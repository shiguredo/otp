/*
 * %CopyrightBegin%
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright Shiguredo Inc. 2026. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * %CopyrightEnd%
 *
 * ----------------------------------------------------------------------
 *  Purpose : io_uring (Linux) completion based I/O backend.
 * ----------------------------------------------------------------------
 *
 * esuio = ESock Uring I/O
 *
 * This is the essio backend where the operations that would block are
 * handed over to io_uring instead of being select:ed, and the result
 * is delivered in a completion message (like the Windows esaio backend):
 *
 *     {'$socket', Socket, completion, {Ref, Result}}
 *
 * Operations are always first tried directly (non-blocking) in the nif
 * call, exactly like essio does. Only when that would block is the
 * operation handed over to io_uring.
 *
 * Rings and threads
 * -----------------
 * There are N rings, each owned by one thread (esuio[i]). That thread
 * is the *only* one that submits to, and reaps from, its ring
 * (IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN). This is
 * important since the completion work of a socket operation (such as
 * the copying of the received data) is run by the submitting task.
 * If the (normal) schedulers submitted, that work would interrupt them.
 * Instead a scheduler puts the operation in the submission queue of the
 * ring and (if the queue was empty) wakes the ring thread with an
 * eventfd (on which the ring thread has a multishot poll).
 *
 * A socket is assigned to a ring (round robin) the first time it is
 * used, and then all its operations are handled by that ring.
 *
 * Operations and the requestors
 * -----------------------------
 * Just like essio, there is at most one operation in progress per
 * direction (reader, writer and acceptor). The current requestor has
 * the operation in its dataP. Other requestors are queued, with their
 * operation (not yet started) in dataP, and they get 'completion' as
 * result. When the current operation completes, the next is started
 * (esock_activate_next_*).
 *
 * An operation that is cancelled (or whose requestor dies) still
 * "owns" its direction until its CQE has been processed. If it
 * actually succeeded, the result (received data or an accepted
 * connection) is put in the stash of the socket, and handed to the next
 * requestor. This way no data is lost, and the order is kept.
 *
 * Lock order: readMtx, writeMtx, (ring) qMtx.
 * The ring thread never holds qMtx when it takes a socket mutex.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef ESOCK_ENABLE
#ifdef ESOCK_HAVE_IO_URING

#ifndef WANT_NONBLOCKING
#define WANT_NONBLOCKING
#endif
#include "sys.h"

#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <poll.h>
#include <errno.h>
#include <string.h>

#include "prim_socket_int.h"
#include "socket_util.h"
#include "socket_io.h"
#include "socket_syncio.h"
#include "socket_uringio.h"
#include "socket_uring.h"


/* =================================================================== *
 *                                                                     *
 *                        Various esuio macros                         *
 *                                                                     *
 * =================================================================== */

/* Global socket debug */
#define SGDBG( proto )            ESOCK_DBG_PRINTF( ctrl.dbg , proto )

#define ESUIO_SQ_ENTRIES       256
#define ESUIO_CQ_ENTRIES      4096

/* user_data of the (multishot) poll on the wakeup eventfd */
#define ESUIO_UD_WAKEUP        ((__u64) 1)

#define sock_errno()           errno
#define sock_recv(s,buf,len,flag)  recv((s),(buf),(len),(flag))
#define sock_recvmsg(s,msghdr,flag) recvmsg((s),(msghdr),(flag))
#define sock_sendmsg(s,msghdr,flag) sendmsg((s),(msghdr),(flag))
#define sock_close(s)          close((s))


/* =================================================================== *
 *                                                                     *
 *                            Local types                              *
 *                                                                     *
 * =================================================================== */

typedef enum {
    ESUIO_OP_RECV = 1,  /* IORING_OP_RECV    - recv                    */
    ESUIO_OP_RECVFROM,  /* IORING_OP_RECVMSG - recvfrom                */
    ESUIO_OP_RECVMSG,   /* IORING_OP_RECVMSG - recvmsg                 */
    ESUIO_OP_SEND,      /* IORING_OP_SENDMSG - send and sendto         */
    ESUIO_OP_SENDMSG,   /* IORING_OP_SENDMSG - sendmsg and sendv       */
    ESUIO_OP_RECVMMSG,  /* IORING_OP_POLL_ADD (in)  - then recvmmsg    */
    ESUIO_OP_SENDMMSG,  /* IORING_OP_POLL_ADD (out) - then sendmmsg    */
    ESUIO_OP_ACCEPT,    /* IORING_OP_ACCEPT                            */
    ESUIO_OP_CONNECT,   /* IORING_OP_CONNECT                           */
    ESUIO_OP_CANCEL     /* IORING_OP_ASYNC_CANCEL                      */
} ESUIOOpTag;

/* Read ops (readMtx) and write ops (writeMtx) */
#define ESUIO_IS_READ_OP(T)                             \
    (((T) == ESUIO_OP_RECV) || ((T) == ESUIO_OP_RECVFROM) ||    \
     ((T) == ESUIO_OP_RECVMSG) || ((T) == ESUIO_OP_RECVMMSG) || \
     ((T) == ESUIO_OP_ACCEPT))
#define ESUIO_IS_WRITE_OP(T)                            \
    (((T) == ESUIO_OP_SEND) || ((T) == ESUIO_OP_SENDMSG) ||     \
     ((T) == ESUIO_OP_SENDMMSG) || ((T) == ESUIO_OP_CONNECT))

/* Maximum number of messages for sendmmsg and recvmmsg (as essio) */
#define ESUIO_MMSG_MAX 1024

/* The data of a send operation (send, sendto, sendmsg and sendv).
 * Always sent with sendmsg (IORING_OP_SENDMSG), msg describes what
 * remains to be sent.
 */
typedef struct {
    struct msghdr msg;
    ESockAddress  addr;
    struct iovec  iov1;       /* send, sendto: the (rest of the) data   */
    ErlNifIOVec*  iovec;      /* sendmsg/sendv (in the env of the op)   */
    char*         ctrlBuf;    /* Owned                                  */
    size_t        size;       /* Total size (of this call)              */
    size_t        written;    /* Written so far (including the nif)     */
    BOOLEAN_T     dataInTail; /* sendmsg/sendv: report {ok, Written}    */
    BOOLEAN_T     isMsg;      /* sendmsg or sendv (not send or sendto)  */
} ESUIOSendData;

/* The (decoded) messages of a sendmmsg.
 */
typedef struct {
    unsigned int    count;      /* Decoded (at most ESUIO_MMSG_MAX)      */
    unsigned int    total;      /* In the list                           */
    struct mmsghdr* hdrs;
    ESockAddress*   addrs;
    ErlNifIOVec**   iovecs;
    char*           pool;       /* The one allocation of all the above   */
    ERL_NIF_TERM    eMsgs;      /* The messages (in the decode env)      */
} ESUIOMMsgData;

typedef struct esuio_op {
    struct esuio_op* nextP;     /* Link in the ring submission queue */
    ESUIOOpTag       tag;
    int              refc;      /* See esuio_op_unref */

    ESockDescriptor* descP;     /* Kept (resource) while in the ring */
    ErlNifEnv*       env;       /* Owns sockRef, ref and data terms  */
    ERL_NIF_TERM     sockRef;
    ERL_NIF_TERM     ref;       /* The operation ref (the handle)    */
    ErlNifPid        caller;
    int              flags;     /* msg flags                         */

    BOOLEAN_T        inRing;    /* Handed over to the ring           */
    BOOLEAN_T        cancelled; /* The caller does not want the result */
    BOOLEAN_T        closing;   /* Cancelled since the socket closes */
    BOOLEAN_T        reportCancel; /* Send the final message anyway  */

    union {
        struct {
            ErlNifBinary  buf;
            ssize_t       len;   /* Requested length (0 = default)   */
            size_t        got;   /* Already received (stream len > 0) */
            ErlNifBinary  ctrl;  /* recvmsg */
            ESockAddress  addr;
            struct msghdr msg;
            struct iovec  iov;
        } recv;

        ESUIOSendData send;

        struct {
            unsigned int  vlen;
            size_t        bufSz;
            size_t        ctrlSz;
        } recvmmsg;

        ESUIOMMsgData sendmmsg;

        struct {
            ESockAddress  addr;
            SOCKLEN_T     addrLen;
        } connect;

        struct {
            struct esuio_op* targetP;  /* NULL: all on the fd */
            BOOLEAN_T        isRead;   /* Counted as a read (or write) op */
        } cancel;
    } data;
} ESUIOOp;


typedef struct {
    unsigned int idx;
    ErlNifTid    tid;
    ESockUring   ring;
    int          efd;           /* Wakeup eventfd */

    ErlNifMutex* qMtx;          /* Protects the following */
    ESUIOOp*     qFirst;
    ESUIOOp*     qLast;
    BOOLEAN_T    stop;

    /* Set (by the ring thread) when it is about to block (waiting for
     * CQEs); whoever clears it (atomic exchange) wakes it (eventfd). */
    int          sleeping;

    /* Thread startup */
    ErlNifMutex* initMtx;
    ErlNifCond*  initCnd;
    BOOLEAN_T    initDone;
    int          initRes;

    /* The (caller) env of the ring thread; cleared after each CQE */
    ErlNifEnv*   env;

    /* Counters (ring thread only) */
    ESockCounter submitted;
    ESockCounter completed;
    ESockCounter wakeups;
} ESUIORing;


typedef struct esuio_stash_elem {
    struct esuio_stash_elem* nextP;
    ESUIOOpTag               tag;   /* The operation that got it */
    ErlNifBinary             data;
    size_t                   offset; /* Already delivered (stream)   */
    ESockAddress             addr;
    SOCKLEN_T                addrLen;
    ErlNifBinary             ctrl;
    size_t                   ctrlLen; /* Used part of ctrl (0 = none) */
    int                      msgFlags;
    int                      fd;      /* ESUIO_OP_ACCEPT: accepted socket */
} ESUIOStashElem;

typedef struct {
    ESUIOStashElem* first;
    ESUIOStashElem* last;
} ESUIOStash;


typedef struct {
    BOOLEAN_T    dbg;
    BOOLEAN_T    sockDbg;
    int          iov_max;

    unsigned int numRings;
    ESUIORing*   rings;
    unsigned int nextRing;      /* Round robin (atomic) */
} ESUIOControl;


/* =================================================================== *
 *                                                                     *
 *                        Function Forwards                            *
 *                                                                     *
 * =================================================================== */

static void* esuio_ring_main(void* arg);
static void  esuio_ring_arm_wakeup(ESUIORing* rP);
static void  esuio_ring_drain_queue(ESUIORing* rP);
static void  esuio_ring_reap(ESUIORing* rP);
static BOOLEAN_T esuio_ring_prep(ESUIORing* rP, ESUIOOp* opP);

static ESUIORing* esuio_ring_of(ESockDescriptor* descP);
static void esuio_submit(ESUIOOp* opP);

static ESUIOOp* esuio_op_alloc(ErlNifEnv*       env,
                               ESockDescriptor* descP,
                               ESUIOOpTag       tag,
                               ERL_NIF_TERM     sockRef,
                               ERL_NIF_TERM     ref);
static void esuio_op_unref(ESUIOOp* opP);
static void esuio_op_hand_over(ESUIOOp* opP);

static void esuio_complete(ESUIOOp* opP, int res);
static void esuio_complete_read(ESUIOOp* opP, int res);
static void esuio_complete_write(ESUIOOp* opP, int res);
static void esuio_complete_cancel(ESUIOOp* opP, int res);
static void esuio_complete_recvmmsg(ESUIOOp* opP, int res);
static void esuio_complete_sendmmsg(ESUIOOp* opP, int res);
static void esuio_complete_accept(ESUIOOp* opP, int res);
static void esuio_complete_connect(ESUIOOp* opP, int res);
static BOOLEAN_T esuio_activate_recvmmsg(ErlNifEnv*       env,
                                         ESockDescriptor* descP,
                                         ERL_NIF_TERM     sockRef,
                                         ESUIOOp*         opP);

static void esuio_send_completion_msg(ESUIOOp*     opP,
                                      ERL_NIF_TERM result);
static void esuio_send_abort_msg(ESUIOOp*     opP,
                                 ERL_NIF_TERM reason);

static void esuio_cancel_op(ESUIOOp* opP, BOOLEAN_T isRead);
static void esuio_cancel_current(ErlNifEnv*       env,
                                 ESockDescriptor* descP,
                                 ESockRequestor*  reqP,
                                 BOOLEAN_T        isRead,
                                 BOOLEAN_T        report);
static void esuio_cancel_all(ESockDescriptor* descP);

static void esuio_maybe_close_done(ESockDescriptor* descP);
static void esuio_close_done(ErlNifEnv* env, ESockDescriptor* descP);

static void esuio_stash_push(ESockDescriptor* descP, ESUIOStashElem* eP);
static ESUIOStashElem* esuio_stash_first(ESockDescriptor* descP);
static ESUIOStashElem* esuio_stash_first_accepted(ESockDescriptor* descP);
static void esuio_stash_drop_first(ESockDescriptor* descP);
static void esuio_stash_free(ESockDescriptor* descP);
static void esuio_stash_elem_free(ESUIOStashElem* eP);
static void esuio_close_scm_rights(unsigned char* ctrl, size_t ctrlLen);


/* =================================================================== *
 *                                                                     *
 *                           Local variables                           *
 *                                                                     *
 * =================================================================== */

static ESUIOControl ctrl = {0};

/* The ring of the current thread (if it is a ring thread) */
static __thread ESUIORing* esuio_self_ring = NULL;


/* ======================================================================== *
 *                              ESUIO Functions                             *
 * ======================================================================== *
 */

/* *******************************************************************
 * esuio_init - Create the rings (and their threads).
 *
 * Returns ESOCK_IO_OK or -errno (the reason why io_uring could not
 * be used, the caller will then fall back to essio).
 */
extern
int esuio_init(unsigned int     numThreads,
               const ESockData* dataP)
{
    unsigned int i;
    int          res = 0;

    ctrl.dbg     = dataP->dbg;
    ctrl.sockDbg = dataP->sockDbg;
    ctrl.iov_max = dataP->iov_max;

    /* We reuse lots of essio functions, and they need their (control)
     * data to be initiated.
     */
    (void) essio_init(numThreads, dataP);

    if (numThreads == 0)
        numThreads = 1;

    ctrl.rings = MALLOC(numThreads * sizeof(ESUIORing));
    ESOCK_ASSERT( ctrl.rings != NULL );
    sys_memzero((char*) ctrl.rings, numThreads * sizeof(ESUIORing));

    for (i = 0; i < numThreads; i++) {
        ESUIORing*       rP = &ctrl.rings[i];
        ErlNifThreadOpts* optsP;
        char             buf[32];

        rP->idx = i;

        if ((rP->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC)) < 0) {
            res = -errno;
            break;
        }

        enif_snprintf(buf, sizeof(buf), "esuio.q[%u]", i);
        rP->qMtx    = MCREATE(buf);
        enif_snprintf(buf, sizeof(buf), "esuio.init[%u]", i);
        rP->initMtx = MCREATE(buf);
        rP->initCnd = enif_cond_create(buf);
        ESOCK_ASSERT( (rP->qMtx != NULL) &&
                      (rP->initMtx != NULL) &&
                      (rP->initCnd != NULL) );

        optsP = enif_thread_opts_create("esuio-opts");
        ESOCK_ASSERT( optsP != NULL );
        enif_snprintf(buf, sizeof(buf), "esuio[%u]", i);
        res = enif_thread_create(buf, &rP->tid, esuio_ring_main, rP, optsP);
        enif_thread_opts_destroy(optsP);
        if (res != 0) {
            res = -res;
            (void) close(rP->efd);
            break;
        }

        /* Wait for the thread to create its ring */
        MLOCK(rP->initMtx);
        while (! rP->initDone)
            enif_cond_wait(rP->initCnd, rP->initMtx);
        res = rP->initRes;
        MUNLOCK(rP->initMtx);

        if (res != 0) {
            (void) enif_thread_join(rP->tid, NULL);
            (void) close(rP->efd);
            break;
        }

        ctrl.numRings++;
    }

    if (res != 0) {
        SGDBG( ("UNIX-ESUIO", "esuio_init -> failed: %d\r\n", res) );
        esuio_finish();
        return res;
    }

    SGDBG( ("UNIX-ESUIO", "esuio_init -> done with %u rings\r\n",
            ctrl.numRings) );

    return ESOCK_IO_OK;
}


/* *******************************************************************
 * esuio_finish - Stop the ring threads.
 *
 * Operations still in progress are left as is (we are halting).
 */
extern
void esuio_finish(void)
{
    unsigned int i;

    for (i = 0; i < ctrl.numRings; i++) {
        ESUIORing* rP  = &ctrl.rings[i];
        uint64_t   one = 1;

        MLOCK(rP->qMtx);
        rP->stop = TRUE;
        MUNLOCK(rP->qMtx);
        (void) !write(rP->efd, &one, sizeof(one));
        (void) enif_thread_join(rP->tid, NULL);
        (void) close(rP->efd);
    }
    ctrl.numRings = 0;
}


/* *******************************************************************
 * esuio_info - Return info "about" this I/O backend.
 */
extern
ERL_NIF_TERM esuio_info(ErlNifEnv* env)
{
    ERL_NIF_TERM info, sctp, counters, cntKeys[3], cntVals[3];
    ERL_NIF_TERM keys[4], vals[4];
    ESockCounter submitted = 0, completed = 0, wakeups = 0;
    unsigned int i;

    /* Only read (without locking) by us - "good enough" */
    for (i = 0; i < ctrl.numRings; i++) {
        submitted += ctrl.rings[i].submitted;
        completed += ctrl.rings[i].completed;
        wakeups   += ctrl.rings[i].wakeups;
    }
    cntKeys[0] = MKA(env, "submitted"); cntVals[0] = MKCNT(env, submitted);
    cntKeys[1] = MKA(env, "completed"); cntVals[1] = MKCNT(env, completed);
    cntKeys[2] = MKA(env, "wakeups");   cntVals[2] = MKCNT(env, wakeups);
    ESOCK_ASSERT( MKMA(env, cntKeys, cntVals, NUM(cntKeys), &counters) );

    /* The (essio) info has the sctp info */
    if (! GET_MAP_VAL(env, essio_info(env), MKA(env, "sctp"), &sctp))
        sctp = esock_atom_undefined;

    keys[0] = esock_atom_name;          vals[0] = MKA(env, "linux_esuio");
    keys[1] = MKA(env, "sctp");         vals[1] = sctp;
    keys[2] = MKA(env, "num_threads");  vals[2] = MKUI(env, ctrl.numRings);
    keys[3] = esock_atom_counters;      vals[3] = counters;
    ESOCK_ASSERT( MKMA(env, keys, vals, NUM(keys), &info) );

    return info;
}



/* ======================================================================== *
 *                           The ring (thread)                              *
 * ======================================================================== *
 */

static
void* esuio_ring_main(void* arg)
{
    /* The opcodes we need */
    static const int ops[] = {
        IORING_OP_POLL_ADD,  IORING_OP_POLL_REMOVE, IORING_OP_ASYNC_CANCEL,
        IORING_OP_RECV,      IORING_OP_RECVMSG,     IORING_OP_SENDMSG,
        IORING_OP_ACCEPT,    IORING_OP_CONNECT
    };
    ESUIORing* rP = (ESUIORing*) arg;
    int        res, missing = 0;

    esuio_self_ring = rP;

    /* The ring must be created by this thread (SINGLE_ISSUER) */
    res = esock_uring_init(&rP->ring, ESUIO_SQ_ENTRIES, ESUIO_CQ_ENTRIES,
                           IORING_SETUP_SINGLE_ISSUER  |
                           IORING_SETUP_DEFER_TASKRUN  |
                           IORING_SETUP_SUBMIT_ALL);
    if (res == 0) {
        if (! (rP->ring.features & IORING_FEAT_NODROP)) {
            res = -ENOTSUP;
        } else {
            res = esock_uring_probe(&rP->ring, ops, NUM(ops), &missing);
        }
        if (res != 0)
            esock_uring_exit(&rP->ring);
    }

    MLOCK(rP->initMtx);
    rP->initRes  = res;
    rP->initDone = TRUE;
    enif_cond_signal(rP->initCnd);
    MUNLOCK(rP->initMtx);

    if (res != 0) {
        if (missing != 0)
            esock_warning_msg("[UNIX-ESUIO] Missing io_uring opcode: %d\r\n",
                              missing);
        return NULL;
    }

    rP->env = esock_alloc_env("esuio-ring");

    esuio_ring_arm_wakeup(rP);

    for (;;) {
        BOOLEAN_T stop, empty;

        esuio_ring_drain_queue(rP);

        /* We are about to block; announce it, and then check (again) that
         * there is nothing in the queue (see esuio_submit). */
        __atomic_store_n(&rP->sleeping, 1, __ATOMIC_SEQ_CST);
        __atomic_thread_fence(__ATOMIC_SEQ_CST);

        MLOCK(rP->qMtx);
        stop  = rP->stop;
        empty = (rP->qFirst == NULL);
        MUNLOCK(rP->qMtx);
        if (stop)
            break;

        if (! empty) {
            (void) __atomic_exchange_n(&rP->sleeping, 0, __ATOMIC_SEQ_CST);
            continue;
        }

        res = esock_uring_submit_and_wait(&rP->ring, 1);

        __atomic_store_n(&rP->sleeping, 0, __ATOMIC_SEQ_CST);

        if ((res < 0) &&
            (res != -EINTR) && (res != -ETIME) &&
            (res != -EBUSY) && (res != -EAGAIN)) {
            esock_error_msg("[UNIX-ESUIO] ring %u: io_uring_enter failed: "
                            "%s (%d)\r\n",
                            rP->idx, erl_errno_id(-res), -res);
        }

        esuio_ring_reap(rP);
    }

    esock_uring_exit(&rP->ring);
    esock_free_env("esuio-ring", rP->env);
    rP->env = NULL;

    return NULL;
}


/* The (multishot) poll on the wakeup eventfd.
 * Its CQE:s have the user_data ESUIO_UD_WAKEUP.
 */
static
void esuio_ring_arm_wakeup(ESUIORing* rP)
{
    struct io_uring_sqe* sqeP;

    if ((sqeP = esock_uring_get_sqe(&rP->ring)) == NULL) {
        (void) esock_uring_submit_and_wait(&rP->ring, 0);
        sqeP = esock_uring_get_sqe(&rP->ring);
        ESOCK_ASSERT( sqeP != NULL );
    }

    sqeP->opcode        = IORING_OP_POLL_ADD;
    sqeP->fd            = rP->efd;
    sqeP->poll32_events = POLLIN;
    sqeP->len           = IORING_POLL_ADD_MULTI;
    sqeP->user_data     = ESUIO_UD_WAKEUP;
}


/* Move (as many as possible) of the queued operations to the SQ.
 */
static
void esuio_ring_drain_queue(ESUIORing* rP)
{
    ESUIOOp *opP, *nextP;

    MLOCK(rP->qMtx);
    opP        = rP->qFirst;
    rP->qFirst = NULL;
    rP->qLast  = NULL;
    MUNLOCK(rP->qMtx);

    while (opP != NULL) {
        nextP       = opP->nextP;
        opP->nextP  = NULL;

        if (! esuio_ring_prep(rP, opP)) {

            /* The SQ is full - submit what we have and try again */

            (void) esock_uring_submit_and_wait(&rP->ring, 0);

            if (! esuio_ring_prep(rP, opP)) {
                ESUIOOp* lastP = opP;

                /* Still full; put the rest back (first) in the queue */
                opP->nextP = nextP;
                while (lastP->nextP != NULL)
                    lastP = lastP->nextP;
                MLOCK(rP->qMtx);
                lastP->nextP = rP->qFirst;
                rP->qFirst   = opP;
                if (rP->qLast == NULL)
                    rP->qLast = lastP;
                MUNLOCK(rP->qMtx);
                return;
            }
        }

        opP = nextP;
    }
}


/* Prepare an SQE for the operation.
 * Returns FALSE if the SQ is full.
 *
 * Note that we read descP->sock without holding any lock. This is safe
 * since the socket is not closed while there are operations in the
 * ring (see esuio_close).
 */
static
BOOLEAN_T esuio_ring_prep(ESUIORing* rP, ESUIOOp* opP)
{
    struct io_uring_sqe* sqeP;

    if ((sqeP = esock_uring_get_sqe(&rP->ring)) == NULL)
        return FALSE;

    sqeP->user_data = (__u64) (uintptr_t) opP;

    switch (opP->tag) {
    case ESUIO_OP_RECV:
        sqeP->opcode    = IORING_OP_RECV;
        sqeP->fd        = opP->descP->sock;
        sqeP->addr      = (__u64) (uintptr_t)
            (opP->data.recv.buf.data + opP->data.recv.got);
        sqeP->len       = opP->data.recv.buf.size - opP->data.recv.got;
        sqeP->msg_flags = opP->flags;
        break;

    case ESUIO_OP_RECVFROM:
    case ESUIO_OP_RECVMSG:
        sqeP->opcode    = IORING_OP_RECVMSG;
        sqeP->fd        = opP->descP->sock;
        sqeP->addr      = (__u64) (uintptr_t) &opP->data.recv.msg;
        sqeP->len       = 1;
        sqeP->msg_flags = opP->flags;
        break;

    case ESUIO_OP_SEND:
    case ESUIO_OP_SENDMSG:
        sqeP->opcode    = IORING_OP_SENDMSG;
        sqeP->fd        = opP->descP->sock;
        sqeP->addr      = (__u64) (uintptr_t) &opP->data.send.msg;
        sqeP->len       = 1;
        sqeP->msg_flags = opP->flags | MSG_NOSIGNAL;
        break;

    case ESUIO_OP_RECVMMSG:
        sqeP->opcode        = IORING_OP_POLL_ADD;
        sqeP->fd            = opP->descP->sock;
        sqeP->poll32_events = POLLIN;
        break;

    case ESUIO_OP_SENDMMSG:
        sqeP->opcode        = IORING_OP_POLL_ADD;
        sqeP->fd            = opP->descP->sock;
        sqeP->poll32_events = POLLOUT;
        break;

    case ESUIO_OP_ACCEPT:
        sqeP->opcode       = IORING_OP_ACCEPT;
        sqeP->fd           = opP->descP->sock;
        sqeP->accept_flags = SOCK_CLOEXEC | SOCK_NONBLOCK;
        break;

    case ESUIO_OP_CONNECT:
        sqeP->opcode    = IORING_OP_CONNECT;
        sqeP->fd        = opP->descP->sock;
        sqeP->addr      = (__u64) (uintptr_t) &opP->data.connect.addr;
        sqeP->off       = opP->data.connect.addrLen;
        break;

    case ESUIO_OP_CANCEL:
        sqeP->opcode    = IORING_OP_ASYNC_CANCEL;
        if (opP->data.cancel.targetP != NULL) {
            sqeP->addr         = (__u64) (uintptr_t) opP->data.cancel.targetP;
        } else {
            sqeP->fd           = opP->descP->sock;
            sqeP->cancel_flags = IORING_ASYNC_CANCEL_FD |
                IORING_ASYNC_CANCEL_ALL;
        }
        break;
    }

    rP->submitted++;

    return TRUE;
}


/* Process all available CQE:s.
 */
static
void esuio_ring_reap(ESUIORing* rP)
{
    struct io_uring_cqe* cqeP;

    while ((cqeP = esock_uring_peek_cqe(&rP->ring)) != NULL) {
        __u64        ud    = cqeP->user_data;
        int          res   = cqeP->res;
        unsigned int flags = cqeP->flags;

        /* Consume it before we handle it (handling may submit) */
        esock_uring_cq_advance(&rP->ring, 1);

        if (ud == ESUIO_UD_WAKEUP) {
            uint64_t v;

            (void) !read(rP->efd, &v, sizeof(v));
            rP->wakeups++;
            if (! (flags & IORING_CQE_F_MORE))
                esuio_ring_arm_wakeup(rP);
        } else {
            rP->completed++;
            esuio_complete((ESUIOOp*) (uintptr_t) ud, res);
        }
    }
}



/* ======================================================================== *
 *                        Operation utility functions                       *
 * ======================================================================== *
 */

/* The ring of the socket (assigned the first time).
 */
static
ESUIORing* esuio_ring_of(ESockDescriptor* descP)
{
    int idx = __atomic_load_n(&descP->uringIdx, __ATOMIC_ACQUIRE);

    if (idx < 0) {
        int expected = -1;
        int newIdx   = (int)
            (__atomic_fetch_add(&ctrl.nextRing, 1, __ATOMIC_RELAXED) %
             ctrl.numRings);

        if (__atomic_compare_exchange_n(&descP->uringIdx, &expected, newIdx,
                                        FALSE,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            idx = newIdx;
        else
            idx = expected;
    }

    return &ctrl.rings[idx];
}


/* Hand the operation over to its ring.
 * If we *are* the ring thread, we prepare the SQE directly,
 * otherwise we put it in the submission queue (and maybe wake the
 * ring thread).
 */
static
void esuio_submit(ESUIOOp* opP)
{
    ESUIORing* rP = esuio_ring_of(opP->descP);

    if (esuio_self_ring == rP) {
        if (esuio_ring_prep(rP, opP))
            return;
    }

    MLOCK(rP->qMtx);
    opP->nextP = NULL;
    if (rP->qLast != NULL)
        rP->qLast->nextP = opP;
    else
        rP->qFirst = opP;
    rP->qLast = opP;
    MUNLOCK(rP->qMtx);

    /* Only wake the ring thread if it is (about to be) blocked; if it is
     * busy it will find the operation (see esuio_ring_main). */
    if (esuio_self_ring != rP) {
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        if (__atomic_exchange_n(&rP->sleeping, 0, __ATOMIC_SEQ_CST)) {
            uint64_t one = 1;

            (void) !write(rP->efd, &one, sizeof(one));
        }
    }
}


static
ESUIOOp* esuio_op_alloc(ErlNifEnv*       env,
                        ESockDescriptor* descP,
                        ESUIOOpTag       tag,
                        ERL_NIF_TERM     sockRef,
                        ERL_NIF_TERM     ref)
{
    ESUIOOp* opP = MALLOC(sizeof(ESUIOOp));

    ESOCK_ASSERT( opP != NULL );
    sys_memzero((char*) opP, sizeof(ESUIOOp));

    opP->tag     = tag;
    opP->refc    = 1;
    opP->descP   = descP;
    opP->env     = esock_alloc_env("esuio-op");
    opP->sockRef = CP_TERM(opP->env, sockRef);
    opP->ref     = CP_TERM(opP->env, ref);
    if ((env == NULL) || (enif_self(env, &opP->caller) == NULL))
        enif_set_pid_undefined(&opP->caller);

    return opP;
}


/* An operation is referenced by its owner (the requestor, or the ring
 * while it is in flight) and by any cancel operation targeting it.
 * The latter makes sure that the memory of an operation is not reused
 * (for another operation) while there is a cancel (by user_data) for it
 * in the ring.
 */
static
void esuio_op_unref(ESUIOOp* opP)
{
    if (__atomic_sub_fetch(&opP->refc, 1, __ATOMIC_ACQ_REL) > 0)
        return;

    switch (opP->tag) {
    case ESUIO_OP_RECV:
    case ESUIO_OP_RECVFROM:
    case ESUIO_OP_RECVMSG:
        if (opP->data.recv.buf.data != NULL)
            FREE_BIN(&opP->data.recv.buf);
        if (opP->data.recv.ctrl.data != NULL)
            FREE_BIN(&opP->data.recv.ctrl);
        break;

    case ESUIO_OP_SEND:
    case ESUIO_OP_SENDMSG:
        if (opP->data.send.ctrlBuf != NULL)
            FREE(opP->data.send.ctrlBuf);
        break;

    case ESUIO_OP_RECVMMSG:
    case ESUIO_OP_ACCEPT:
    case ESUIO_OP_CONNECT:
        break;

    case ESUIO_OP_SENDMMSG:
        /* The I/O vectors are owned by the env */
        if (opP->data.sendmmsg.pool != NULL)
            FREE(opP->data.sendmmsg.pool);
        break;

    case ESUIO_OP_CANCEL:
        if (opP->data.cancel.targetP != NULL)
            esuio_op_unref(opP->data.cancel.targetP);
        break;
    }

    esock_free_env("esuio_op_unref", opP->env);
    FREE(opP);
}


/* Hand the operation over to io_uring.
 * The caller holds the (read or write) mutex of the socket.
 * While in the ring, the operation keeps the socket (resource) alive
 * and it is counted (so that close waits for it).
 */
static
void esuio_op_hand_over(ESUIOOp* opP)
{
    ESockDescriptor* descP = opP->descP;

    ESOCK_ASSERT( ! opP->inRing );

    opP->inRing = TRUE;
    enif_keep_resource(descP);

    if (ESUIO_IS_READ_OP(opP->tag) ||
        ((opP->tag == ESUIO_OP_CANCEL) && opP->data.cancel.isRead))
        descP->uringReadOps++;
    else
        descP->uringWriteOps++;

    esuio_submit(opP);
}


/* The CQE of an operation.
 */
static
void esuio_complete(ESUIOOp* opP, int res)
{
    switch (opP->tag) {
    case ESUIO_OP_RECV:
    case ESUIO_OP_RECVFROM:
    case ESUIO_OP_RECVMSG:
        esuio_complete_read(opP, res);
        break;

    case ESUIO_OP_SEND:
    case ESUIO_OP_SENDMSG:
        esuio_complete_write(opP, res);
        break;

    case ESUIO_OP_RECVMMSG:
        esuio_complete_recvmmsg(opP, res);
        break;

    case ESUIO_OP_SENDMMSG:
        esuio_complete_sendmmsg(opP, res);
        break;

    case ESUIO_OP_ACCEPT:
        esuio_complete_accept(opP, res);
        break;

    case ESUIO_OP_CONNECT:
        esuio_complete_connect(opP, res);
        break;

    case ESUIO_OP_CANCEL:
        esuio_complete_cancel(opP, res);
        break;
    }
}


/* Common "epilogue" of an operation (in the ring) that is done.
 * Called with the socket mutex (of the direction) held.
 * Returns TRUE if the socket is closing and the ring ops of this
 * direction are now drained (the caller should call
 * esuio_maybe_close_done without holding the mutex).
 */
static
BOOLEAN_T esuio_op_done(ESUIOOp* opP, BOOLEAN_T isRead)
{
    ESockDescriptor* descP = opP->descP;
    BOOLEAN_T        drained;

    if (isRead) {
        ESOCK_ASSERT( descP->uringReadOps > 0 );
        descP->uringReadOps--;
        drained = ((descP->uringReadOps == 0) &&
                   IS_CLOSING(descP->readState));
    } else {
        ESOCK_ASSERT( descP->uringWriteOps > 0 );
        descP->uringWriteOps--;
        drained = ((descP->uringWriteOps == 0) &&
                   IS_CLOSING(descP->writeState));
    }
    opP->inRing = FALSE;

    return drained;
}


/* Send {'$socket', Socket, completion, {Ref, Result}} to the caller.
 * The result must have been built in the env of the operation.
 * The env is consumed (after this the op has no env).
 */
static
void esuio_send_completion_msg(ESUIOOp*     opP,
                               ERL_NIF_TERM result)
{
    ERL_NIF_TERM msg;

    if (enif_is_pid_undefined(&opP->caller))
        return;

    msg = esock_mk_socket_msg(opP->env, opP->sockRef,
                              esock_atom_completion,
                              MKT2(opP->env, opP->ref, result));

    (void) esock_send_msg(NULL, &opP->caller, msg, opP->env);

    /* The message send freed the env (and the terms in it) */
    opP->env     = NULL;
    opP->sockRef = esock_atom_undefined;
    opP->ref     = esock_atom_undefined;
    enif_set_pid_undefined(&opP->caller);
}


/* Send {'$socket', Socket, abort, {Ref, Reason}} to the caller.
 * The reason must be an atom or have been built in the env of the
 * operation.
 */
static
void esuio_send_abort_msg(ESUIOOp*     opP,
                          ERL_NIF_TERM reason)
{
    ERL_NIF_TERM msg;

    if (enif_is_pid_undefined(&opP->caller))
        return;

    msg = esock_mk_socket_msg(opP->env, opP->sockRef,
                              esock_atom_abort,
                              MKT2(opP->env, opP->ref, reason));

    (void) esock_send_msg(NULL, &opP->caller, msg, opP->env);

    /* The message send freed the env (and the terms in it) */
    opP->env     = NULL;
    opP->sockRef = esock_atom_undefined;
    opP->ref     = esock_atom_undefined;
    enif_set_pid_undefined(&opP->caller);
}


/* Cancel an operation in the ring (by user_data).
 * The caller holds the mutex of the direction of the operation.
 */
static
void esuio_cancel_op(ESUIOOp* opP, BOOLEAN_T isRead)
{
    ESUIOOp* cancelP;

    ESOCK_ASSERT( opP->inRing );

    cancelP = esuio_op_alloc(NULL, opP->descP, ESUIO_OP_CANCEL,
                             esock_atom_undefined, esock_atom_undefined);
    (void) __atomic_add_fetch(&opP->refc, 1, __ATOMIC_ACQ_REL);
    cancelP->data.cancel.targetP = opP;
    cancelP->data.cancel.isRead  = isRead;

    esuio_op_hand_over(cancelP);
}


/* Cancel all operations (of the socket) in the ring.
 * The caller holds both mutexes (of the socket).
 * The cancel op is counted as a write op (we just need it to be
 * counted, so that the socket is not closed until it is done).
 */
static
void esuio_cancel_all(ESockDescriptor* descP)
{
    ESUIOOp* cancelP;

    cancelP = esuio_op_alloc(NULL, descP, ESUIO_OP_CANCEL,
                             esock_atom_undefined, esock_atom_undefined);
    cancelP->data.cancel.targetP = NULL;
    cancelP->data.cancel.isRead  = FALSE;

    esuio_op_hand_over(cancelP);
}


/* The CQE of a cancel operation.
 * We do not care about the result (the target operation will get its
 * own CQE, whatever happens); we only need to account for it.
 */
static
void esuio_complete_cancel(ESUIOOp* opP, int res)
{
    ESockDescriptor* descP  = opP->descP;
    BOOLEAN_T        isRead = opP->data.cancel.isRead;
    BOOLEAN_T        drained;

    VOID(res);

    if (isRead) {
        MLOCK(descP->readMtx);
        drained = esuio_op_done(opP, TRUE);
        MUNLOCK(descP->readMtx);
    } else {
        MLOCK(descP->writeMtx);
        drained = esuio_op_done(opP, FALSE);
        MUNLOCK(descP->writeMtx);
    }

    if (drained)
        esuio_maybe_close_done(descP);

    enif_release_resource(descP);
    esuio_op_unref(opP);
}



/* ======================================================================== *
 *                                  Receive                                 *
 * ======================================================================== *
 *
 * recv, recvfrom and recvmsg.
 *
 * The result of an operation is exactly what essio would have
 * returned, except that where essio would have returned 'select'
 * (or {select, Bin}), we hand the operation over to io_uring and
 * return 'completion', and the result is later delivered in a
 * completion message.
 *
 * A stream recv with a (non zero) length that only partly succeeds
 * directly (in the nif call) keeps the data it got, and the operation
 * then (in the ring) reads the rest. If that read (in turn) only partly
 * succeeds, the result is {more, Bin} (just like esaio). The (same)
 * caller is then expected to read the rest.
 */

typedef enum {
    ESUIO_RECV_DONE,    /* The reader is done; *resP is the result      */
    ESUIO_RECV_MORE,    /* {more, Bin}; the reader (caller) continues    */
    ESUIO_RECV_ERROR,   /* {error, _}; all readers shall be aborted      */
    ESUIO_RECV_EAGAIN,  /* Would block                                   */
    ESUIO_RECV_PARTIAL  /* Stream with length; the data is kept in buf   */
} ESUIORecvRes;


/* The Reason of {error, Reason} (or the term itself).
 */
static
ERL_NIF_TERM esuio_error_reason(ErlNifEnv* env, ERL_NIF_TERM res)
{
    const ERL_NIF_TERM* tuple;
    int                 arity;

    if (enif_get_tuple(env, res, &arity, &tuple) && (arity == 2))
        return tuple[1];

    return res;
}


/* A buffer of the specified size (may reuse the existing buffer).
 */
static
BOOLEAN_T esuio_recv_alloc_buf(size_t size, ErlNifBinary* bufP)
{
    if (bufP->data == NULL) {
        return ALLOC_BIN(size, bufP);
    } else {
        if (size != bufP->size)
            return REALLOC_BIN(bufP, size);
        else
            return TRUE;
    }
}


/* Create a binary with the first size bytes of the buffer.
 * Either the buffer is handed over (bufP->data is NULL:ed),
 * or the data is copied (and the buffer kept).
 * Same as recv_create_bin in essio.
 */
static
BOOLEAN_T esuio_recv_create_bin(ErlNifBinary* bufP,
                                size_t        size,
                                ErlNifBinary* binP)
{
    if (size >= bufP->size) {
        *binP      = *bufP;
        bufP->data = NULL;
        return TRUE;
    } else if (size >= (bufP->size & ~4095) ||
               size >= (bufP->size >> 1) + (bufP->size >> 2)) {
        *binP      = *bufP;
        bufP->data = NULL;
        return REALLOC_BIN(binP, size);
    } else {
        BOOLEAN_T ret = ALLOC_BIN(size, binP);
        if (ret)
            sys_memcpy(binP->data, bufP->data, size);
        return ret;
    }
}


/* Build the value (the part after 'ok') of a successful read.
 * The data (and ctrl) buffer are consumed.
 */
static
ERL_NIF_TERM esuio_recv_value(ErlNifEnv*       env,
                              ESockDescriptor* descP,
                              ESUIOOpTag       tag,
                              ErlNifBinary*    bufP,
                              size_t           size,
                              ssize_t          read,
                              struct msghdr*   msgP,
                              ErlNifBinary*    ctrlP)
{
    ErlNifBinary bin;
    ERL_NIF_TERM val, eAddr;

    ESOCK_ASSERT( esuio_recv_create_bin(bufP, size, &bin) );

    switch (tag) {
    case ESUIO_OP_RECV:
        val = MKBIN(env, &bin);
        break;

    case ESUIO_OP_RECVFROM:
        esock_encode_sockaddr(env,
                              (ESockAddress*) msgP->msg_name,
                              msgP->msg_namelen,
                              &eAddr);
        val = MKT2(env, eAddr, MKBIN(env, &bin));
        break;

    case ESUIO_OP_RECVMSG:
    default:
        /* The iov (of the msghdr) must describe the data */
        essio_encode_msg(env, descP, read, msgP, &bin, ctrlP, &val);
        ctrlP->data = NULL; // Consumed
        break;
    }

    return val;
}


/* Process the result of a read (recv, recvfrom or recvmsg) call,
 * in the nif (direct) or in the ring (CQE).
 *
 * cEnv    - "caller" env (counters)
 * tEnv    - Env of the result term
 * got     - Data already in the buffer (stream with length)
 * n / err - The result of the read (n < 0 means error err)
 *
 * The counters are updated as essio does.
 */
static
ESUIORecvRes esuio_recv_process(ErlNifEnv*       cEnv,
                                ErlNifEnv*       tEnv,
                                ESockDescriptor* descP,
                                ERL_NIF_TERM     sockRef,
                                ESUIOOpTag       tag,
                                ssize_t          len,
                                ErlNifBinary*    bufP,
                                size_t           got,
                                ssize_t          n,
                                int              err,
                                struct msghdr*   msgP,
                                ErlNifBinary*    ctrlP,
                                ERL_NIF_TERM*    resP)
{
    size_t total;

    if (n < 0) {
        if ((err == EAGAIN) || (err == ERRNO_BLOCK)) {
            /* Like essio, any failure ends the "read more" sequence */
            descP->rNumCnt = 0;
            return (got > 0) ? ESUIO_RECV_PARTIAL : ESUIO_RECV_EAGAIN;
        }
        if (got > 0) {
            /* Deliver what we have; the caller gets the error
             * on the next read */
            n = 0;
            goto more;
        }
        descP->rNumCnt = 0;
        ESOCK_CNT_INC(cEnv, descP, sockRef, esock_atom_read_fails,
                      &descP->readFails, 1);
        *resP = esock_make_error(tEnv, MKA(tEnv, erl_errno_id(err)));
        return ESUIO_RECV_ERROR;
    }

    if ((n == 0) && (descP->type == SOCK_STREAM)) {
        /* End of stream */
        if (got > 0)
            goto more;
        descP->rNumCnt = 0;
        ESOCK_CNT_INC(cEnv, descP, sockRef, esock_atom_read_fails,
                      &descP->readFails, 1);
        *resP = esock_make_error(tEnv, esock_atom_closed);
        return ESUIO_RECV_ERROR;
    }

    total = got + (size_t) n;

    if (tag != ESUIO_OP_RECV) {

        /* recvfrom and recvmsg deliver one message */

        descP->rNumCnt = 0;
        ESOCK_CNT_INC(cEnv, descP, sockRef, esock_atom_read_pkg,
                      &descP->readPkgCnt, 1);
        ESOCK_CNT_INC(cEnv, descP, sockRef, esock_atom_read_byte,
                      &descP->readByteCnt, n);
        if ((ESockCounter) n > descP->readPkgMax)
            descP->readPkgMax = n;

        *resP = esock_make_ok2(tEnv,
                               esuio_recv_value(tEnv, descP, tag,
                                                bufP, total, n,
                                                msgP, ctrlP));
        return ESUIO_RECV_DONE;
    }

    ESOCK_CNT_INC(cEnv, descP, sockRef, esock_atom_read_byte,
                  &descP->readByteCnt, n);
    descP->readPkgMaxCnt += n;

    if (total < bufP->size) {

        /* +++ We did not fill the buffer +++ */

        descP->rNumCnt = 0;
        if (descP->readPkgMaxCnt > descP->readPkgMax)
            descP->readPkgMax = descP->readPkgMaxCnt;
        descP->readPkgMaxCnt = 0;

        if ((descP->type == SOCK_STREAM) && (len > 0)) {
            /* A stream socket with specified read size
             * - more data is needed */
            return ESUIO_RECV_PARTIAL;
        }

        ESOCK_CNT_INC(cEnv, descP, sockRef, esock_atom_read_pkg,
                      &descP->readPkgCnt, 1);
        *resP = esock_make_ok2(tEnv,
                               esuio_recv_value(tEnv, descP, tag,
                                                bufP, total, total,
                                                msgP, ctrlP));
        return ESUIO_RECV_DONE;

    } else {

        /* +++ We filled the buffer +++ */

        if ((len == 0) && (descP->type == SOCK_STREAM)) {
            descP->rNumCnt++;
            if (descP->rNumCnt < descP->rNum) {
                /* {more, Bin} - the caller reads more */
                *resP = MKT2(tEnv, esock_atom_more,
                             esuio_recv_value(tEnv, descP, tag,
                                              bufP, total, total,
                                              msgP, ctrlP));
                return ESUIO_RECV_MORE;
            }
        }

        descP->rNumCnt = 0;
        ESOCK_CNT_INC(cEnv, descP, sockRef, esock_atom_read_pkg,
                      &descP->readPkgCnt, 1);
        if (descP->readPkgMaxCnt > descP->readPkgMax)
            descP->readPkgMax = descP->readPkgMaxCnt;
        descP->readPkgMaxCnt = 0;

        *resP = esock_make_ok2(tEnv,
                               esuio_recv_value(tEnv, descP, tag,
                                                bufP, total, total,
                                                msgP, ctrlP));
        return ESUIO_RECV_DONE;
    }

 more:
    /* Stream with length, we got something, but then end of stream
     * or an error. Deliver what we got (the caller will get the
     * error (again) on the next read).
     */
    ESOCK_CNT_INC(cEnv, descP, sockRef, esock_atom_read_byte,
                  &descP->readByteCnt, n);
    descP->readPkgMaxCnt += n;
    if (descP->readPkgMaxCnt > descP->readPkgMax)
        descP->readPkgMax = descP->readPkgMaxCnt;
    descP->readPkgMaxCnt = 0;
    descP->rNumCnt       = 0;
    total = got + (size_t) n;
    *resP = MKT2(tEnv, esock_atom_more,
                 esuio_recv_value(tEnv, descP, tag,
                                  bufP, total, total, msgP, ctrlP));
    return ESUIO_RECV_MORE;
}


/* Make the caller the current reader, with (in-flight) operation opP
 * (or none).
 */
static
void esuio_reader_set_current(ErlNifEnv*       env,
                              ESockDescriptor* descP,
                              ERL_NIF_TERM     recvRef,
                              ESUIOOp*         opP)
{
    if (descP->currentReaderP == NULL) {
        ESOCK_ASSERT( enif_self(env, &descP->currentReader.pid) != NULL );
        ESOCK_ASSERT( MONP("esuio_reader_set_current -> current reader",
                           env, descP,
                           &descP->currentReader.pid,
                           &descP->currentReader.mon) == 0 );
        ESOCK_ASSERT( descP->currentReader.env == NULL );
        descP->currentReader.env = esock_alloc_env("current-reader");
        descP->currentReaderP    = &descP->currentReader;
    } else {
        /* This is the same process continuing (after {more, Bin}) */
        enif_clear_env(descP->currentReader.env);
    }
    descP->currentReader.ref   = CP_TERM(descP->currentReader.env, recvRef);
    descP->currentReader.dataP = opP;
}


/* The current reader is done; activate the next (if any).
 */
static
void esuio_reader_done(ErlNifEnv*       env,
                       ESockDescriptor* descP,
                       ERL_NIF_TERM     sockRef)
{
    if (descP->currentReaderP == NULL)
        return;

    descP->currentReader.dataP = NULL;

    if (! IS_OPEN(descP->readState)) {
        esock_requestor_release("esuio_reader_done",
                                env, descP, &descP->currentReader);
        descP->currentReaderP = NULL;
        return;
    }

    (void) DEMONP("esuio_reader_done -> current reader",
                  env, descP, &descP->currentReader.mon);

    if (! esock_activate_next_reader(env, descP, sockRef))
        descP->currentReaderP = NULL;
}


/* A fatal read error: The current reader is done, and all the waiting
 * readers are aborted (with the reason).
 * The result for the current reader has already been dealt with.
 */
static
void esuio_reader_error(ErlNifEnv*       env,
                        ESockDescriptor* descP,
                        ERL_NIF_TERM     sockRef,
                        ERL_NIF_TERM     reason)
{
    if (descP->currentReaderP != NULL) {
        descP->currentReader.dataP = NULL;
        esock_requestor_release("esuio_reader_error",
                                env, descP, &descP->currentReader);
        descP->currentReaderP = NULL;
    }

    esock_inform_waiting_procs(env, "reader", descP, sockRef,
                               &descP->readersQ, reason);
}


/* Set up the buffers (msghdr) of a read operation.
 * The data buffer has been set (and may already contain 'got' bytes).
 */
static
void esuio_recv_op_setup(ESockDescriptor* descP, ESUIOOp* opP)
{
    struct msghdr* msgP = &opP->data.recv.msg;

    if (opP->tag == ESUIO_OP_RECV)
        return;

    sys_memzero((char*) msgP, sizeof(struct msghdr));
    sys_memzero((char*) &opP->data.recv.addr, sizeof(ESockAddress));

    opP->data.recv.iov.iov_base = opP->data.recv.buf.data + opP->data.recv.got;
    opP->data.recv.iov.iov_len  = opP->data.recv.buf.size - opP->data.recv.got;
    msgP->msg_name              = &opP->data.recv.addr;
    msgP->msg_namelen           = sizeof(ESockAddress);
    msgP->msg_iov               = &opP->data.recv.iov;
    msgP->msg_iovlen            = 1;
    if (opP->data.recv.ctrl.data != NULL) {
        msgP->msg_control    = opP->data.recv.ctrl.data;
        msgP->msg_controllen = opP->data.recv.ctrl.size;
    }
}


/* Allocate the buffers of a (queued) read operation, and hand it over
 * to io_uring.
 */
static
void esuio_recv_op_start(ESockDescriptor* descP, ESUIOOp* opP)
{
    size_t bufSz = (opP->data.recv.len != 0) ?
        (size_t) opP->data.recv.len : descP->rBufSz;

    if (opP->data.recv.buf.data == NULL) {
        ESOCK_ASSERT( ALLOC_BIN(bufSz, &opP->data.recv.buf) );
        opP->data.recv.got = 0;
    }
    if ((opP->tag == ESUIO_OP_RECVMSG) &&
        (opP->data.recv.ctrl.data == NULL)) {
        size_t ctrlSz = (opP->data.recv.ctrl.size != 0) ?
            opP->data.recv.ctrl.size : descP->rCtrlSz;
        ESOCK_ASSERT( ALLOC_BIN(ctrlSz, &opP->data.recv.ctrl) );
    }
    esuio_recv_op_setup(descP, opP);
    esuio_op_hand_over(opP);
}


/* Queue the caller as a waiting reader (there is a current reader).
 */
static
ERL_NIF_TERM esuio_recv_queue(ErlNifEnv*       env,
                              ESockDescriptor* descP,
                              ERL_NIF_TERM     sockRef,
                              ERL_NIF_TERM     recvRef,
                              ESUIOOpTag       tag,
                              ssize_t          len,
                              ssize_t          ctrlLen,
                              int              flags)
{
    ErlNifPid caller;
    ESUIOOp*  opP;

    ESOCK_ASSERT( enif_self(env, &caller) != NULL );

    if (esock_reader_search4pid(env, descP, &caller)) {
        /* Reader already in queue */
        return esock_raise_invalid(env, esock_atom_state);
    }

    if (COMPARE(recvRef, esock_atom_zero) == 0)
        return esock_atom_timeout;

    opP                    = esuio_op_alloc(env, descP, tag, sockRef, recvRef);
    opP->flags             = flags;
    opP->data.recv.len     = len;
    /* We only remember the (ctrl) size here, the buffer is allocated
     * when the operation is started. */
    opP->data.recv.ctrl.size = (size_t) ctrlLen;

    esock_reader_push(env, descP, caller, recvRef, opP);

    return esock_atom_completion;
}


/* Deliver (directly) from the stash.
 * Returns TRUE if the request was satisfied (*resP is the result).
 * A stream read (with a length) that is not satisfied, puts what it
 * got in the buffer (*gotP), and returns FALSE.
 */
static
BOOLEAN_T esuio_recv_from_stash(ErlNifEnv*       env,
                                ESockDescriptor* descP,
                                ESUIOOpTag       tag,
                                ssize_t          len,
                                ErlNifBinary*    bufP,
                                size_t*          gotP,
                                ERL_NIF_TERM*    resP)
{
    ESUIOStashElem* eP = esuio_stash_first(descP);
    size_t          want, avail, n;

    *gotP = 0;
    if (eP == NULL)
        return FALSE;

    if ((descP->type == SOCK_STREAM) && (tag != ESUIO_OP_RECVMSG)) {

        /* Stream: (just) bytes */

        want = (len != 0) ? (size_t) len : descP->rBufSz;
        ESOCK_ASSERT( esuio_recv_alloc_buf(want, bufP) );

        while ((*gotP < want) && ((eP = esuio_stash_first(descP)) != NULL)) {
            avail = eP->data.size - eP->offset;
            n     = (avail < (want - *gotP)) ? avail : (want - *gotP);
            sys_memcpy(bufP->data + *gotP, eP->data.data + eP->offset, n);
            *gotP     += n;
            eP->offset += n;
            if (eP->offset >= eP->data.size)
                esuio_stash_drop_first(descP);
        }

        if ((len > 0) && (*gotP < want) && (tag == ESUIO_OP_RECV))
            return FALSE;

        descP->readPkgCnt++;
        descP->readByteCnt += *gotP;
        {
            ErlNifBinary bin;
            ESOCK_ASSERT( esuio_recv_create_bin(bufP, *gotP, &bin) );
            if (tag == ESUIO_OP_RECVFROM) {
                *resP = esock_make_ok2(env,
                                       MKT2(env, esock_atom_undefined,
                                            MKBIN(env, &bin)));
            } else {
                *resP = esock_make_ok2(env, MKBIN(env, &bin));
            }
        }
        *gotP = 0;
        return TRUE;

    } else {

        /* A message (datagram, or a recvmsg on a stream) */

        ErlNifBinary   data = eP->data;
        ErlNifBinary   ctrl = eP->ctrl;
        struct msghdr  msg;
        struct iovec   iov;
        size_t         size = data.size;
        ERL_NIF_TERM   val;

        if ((len > 0) && ((size_t) len < size) && (tag != ESUIO_OP_RECVMSG))
            size = len; // Truncated (as the kernel would have)

        sys_memzero((char*) &msg, sizeof(msg));
        iov.iov_base        = data.data;
        iov.iov_len         = data.size;
        msg.msg_name        = &eP->addr;
        msg.msg_namelen     = eP->addrLen;
        msg.msg_iov         = &iov;
        msg.msg_iovlen      = 1;
        msg.msg_control     = (eP->ctrlLen > 0) ? ctrl.data : NULL;
        msg.msg_controllen  = eP->ctrlLen;
        msg.msg_flags       = eP->msgFlags;

        /* The element hands over its buffers */
        eP->data.data = NULL;
        eP->ctrl.data = NULL;
        esuio_stash_drop_first(descP);

        descP->readPkgCnt++;
        descP->readByteCnt += size;

        if (tag == ESUIO_OP_RECVMSG) {
            if (ctrl.data == NULL) {
                /* encode_msg needs a (ctrl) binary */
                ESOCK_ASSERT( ALLOC_BIN(0, &ctrl) );
                msg.msg_controllen = 0;
            }
            val = esuio_recv_value(env, descP, tag, &data, size, size,
                                   &msg, &ctrl);
        } else {
            if (ctrl.data != NULL) {
                /* Not wanted - close any passed fds */
                esuio_close_scm_rights(ctrl.data, eP->ctrlLen);
                FREE_BIN(&ctrl);
            }
            val = esuio_recv_value(env, descP, tag, &data, size, size,
                                   &msg, NULL);
        }
        if (data.data != NULL)
            FREE_BIN(&data);

        *resP = esock_make_ok2(env, val);
        return TRUE;
    }
}


/* recv, recvfrom and recvmsg (the nif part).
 */
static
ERL_NIF_TERM esuio_recv_common(ErlNifEnv*       env,
                               ESockDescriptor* descP,
                               ERL_NIF_TERM     sockRef,
                               ERL_NIF_TERM     recvRef,
                               ESUIOOpTag       tag,
                               ssize_t          len,
                               ssize_t          ctrlLen,
                               int              flags)
{
    ErlNifBinary* bufP;
    ErlNifBinary  ctrl;
    ESockAddress  addr;
    struct msghdr msg;
    struct iovec  iov;
    size_t        bufSz, ctrlSz, got = 0;
    ssize_t       n;
    int           err;
    ERL_NIF_TERM  res;
    ESUIORecvRes  rr;
    ESUIOOp*      opP;

    if (! IS_OPEN(descP->readState))
        return esock_make_error_closed(env);

    /* Accept and Read can not be simultaneous */
    if (descP->currentAcceptorP != NULL)
        return esock_make_error_invalid(env, esock_atom_state);

    /* If there is a current reader, it must be us (continuing after
     * {more, Bin}) - otherwise we are queued. If the current reader
     * has an operation (in the ring), we are also queued (even if it
     * is us; it has then been cancelled).
     */
    if (descP->currentReaderP != NULL) {
        ErlNifPid caller;

        ESOCK_ASSERT( enif_self(env, &caller) != NULL );

        if ((descP->currentReader.dataP != NULL) ||
            (COMPARE_PIDS(&descP->currentReader.pid, &caller) != 0))
            return esuio_recv_queue(env, descP, sockRef, recvRef,
                                    tag, len, ctrlLen, flags);
    }

    bufSz = (len != 0) ? (size_t) len : descP->rBufSz;
    bufP  = &descP->buf;

    /* Data consumed by a cancelled operation goes first */
    if (esuio_stash_first(descP) != NULL) {
        if (esuio_recv_from_stash(env, descP, tag, len, bufP, &got, &res)) {
            esuio_reader_done(env, descP, sockRef);
            return res;
        }
        /* A stream read with only part of the data (in the buffer) */
    }

    ESOCK_ASSERT( esuio_recv_alloc_buf(bufSz, bufP) );

    ESOCK_CNT_INC(env, descP, sockRef,
                  esock_atom_read_tries, &descP->readTries, 1);

    sys_memzero((char*) &msg, sizeof(msg));
    ctrl.data = NULL;
    ctrl.size = 0;

    if (tag == ESUIO_OP_RECV) {
        n = sock_recv(descP->sock, bufP->data + got, bufP->size - got, flags);
    } else {
        sys_memzero((char*) &addr, sizeof(addr));
        iov.iov_base      = bufP->data + got;
        iov.iov_len       = bufP->size - got;
        msg.msg_name      = &addr;
        msg.msg_namelen   = sizeof(addr);
        msg.msg_iov       = &iov;
        msg.msg_iovlen    = 1;
        if (tag == ESUIO_OP_RECVMSG) {
            ctrlSz = (ctrlLen != 0) ? (size_t) ctrlLen : descP->rCtrlSz;
            ESOCK_ASSERT( ALLOC_BIN(ctrlSz, &ctrl) );
            msg.msg_control    = ctrl.data;
            msg.msg_controllen = ctrl.size;
        }
        n = sock_recvmsg(descP->sock, &msg, flags);
    }
    err = ESOCK_IS_ERROR(n) ? sock_errno() : 0;

    rr = esuio_recv_process(env, env, descP, sockRef, tag, len,
                            bufP, got, n, err, &msg, &ctrl, &res);

    switch (rr) {
    case ESUIO_RECV_DONE:
        if (ctrl.data != NULL) FREE_BIN(&ctrl);
        esuio_reader_done(env, descP, sockRef);
        return res;

    case ESUIO_RECV_MORE:
        if (ctrl.data != NULL) FREE_BIN(&ctrl);
        /* We continue as the current reader (without an operation) */
        esuio_reader_set_current(env, descP, recvRef, NULL);
        return res;

    case ESUIO_RECV_ERROR:
        if (ctrl.data != NULL) FREE_BIN(&ctrl);
        esuio_reader_error(env, descP, sockRef, esuio_error_reason(env, res));
        return res;

    case ESUIO_RECV_EAGAIN:
    case ESUIO_RECV_PARTIAL:
    default:
        break;
    }

    /* Would block */

    if ((rr == ESUIO_RECV_PARTIAL) && (n > 0))
        got += n;

    if (COMPARE(recvRef, esock_atom_zero) == 0) {
        /* Polling read */
        if (ctrl.data != NULL) FREE_BIN(&ctrl);
        if (got > 0) {
            ErlNifBinary bin;

            ESOCK_CNT_INC(env, descP, sockRef,
                          esock_atom_read_pkg, &descP->readPkgCnt, 1);
            ESOCK_ASSERT( esuio_recv_create_bin(bufP, got, &bin) );
            esuio_reader_done(env, descP, sockRef);
            return MKT2(env, esock_atom_timeout, MKBIN(env, &bin));
        }
        esuio_reader_done(env, descP, sockRef);
        return esock_atom_timeout;
    }

    if (got > 0) {
        ErlNifBinary bin;
        ERL_NIF_TERM partial;

        /* A stream recv with a length that got only part of it: return
         * that part now ({completion, Bin}), and hand the rest over to
         * io_uring (just like essio returns {select, Bin}). This way the
         * caller always has what it got, even if it then gives up (on a
         * time-out, for instance). */

        if (ctrl.data != NULL) FREE_BIN(&ctrl);
        ESOCK_ASSERT( esuio_recv_create_bin(bufP, got, &bin) );
        partial = MKBIN(env, &bin);

        opP                = esuio_op_alloc(env, descP, tag, sockRef, recvRef);
        opP->flags         = flags;
        opP->data.recv.len = len - (ssize_t) got;
        ESOCK_ASSERT( ALLOC_BIN((size_t) opP->data.recv.len,
                                &opP->data.recv.buf) );
        opP->data.recv.got = 0;
        esuio_recv_op_setup(descP, opP);

        esuio_reader_set_current(env, descP, recvRef, opP);

        esuio_op_hand_over(opP);

        return MKT2(env, esock_atom_completion, partial);
    }

    /* Hand it over to io_uring - the operation takes over the buffers */

    opP                    = esuio_op_alloc(env, descP, tag, sockRef, recvRef);
    opP->flags             = flags;
    opP->data.recv.len     = len;
    opP->data.recv.buf     = *bufP;
    opP->data.recv.got     = got;
    opP->data.recv.ctrl    = ctrl;
    bufP->data             = NULL;
    esuio_recv_op_setup(descP, opP);

    esuio_reader_set_current(env, descP, recvRef, opP);

    esuio_op_hand_over(opP);

    return esock_atom_completion;
}


extern
ERL_NIF_TERM esuio_recv(ErlNifEnv*       env,
                        ESockDescriptor* descP,
                        ERL_NIF_TERM     sockRef,
                        ERL_NIF_TERM     recvRef,
                        ssize_t          len,
                        int              flags)
{
    return esuio_recv_common(env, descP, sockRef, recvRef,
                             ESUIO_OP_RECV, len, 0, flags);
}


extern
ERL_NIF_TERM esuio_recvfrom(ErlNifEnv*       env,
                            ESockDescriptor* descP,
                            ERL_NIF_TERM     sockRef,
                            ERL_NIF_TERM     recvRef,
                            ssize_t          len,
                            int              flags)
{
    return esuio_recv_common(env, descP, sockRef, recvRef,
                             ESUIO_OP_RECVFROM, len, 0, flags);
}


extern
ERL_NIF_TERM esuio_recvmsg(ErlNifEnv*       env,
                           ESockDescriptor* descP,
                           ERL_NIF_TERM     sockRef,
                           ERL_NIF_TERM     recvRef,
                           ssize_t          bufLen,
                           ssize_t          ctrlLen,
                           int              flags)
{
    return esuio_recv_common(env, descP, sockRef, recvRef,
                             ESUIO_OP_RECVMSG, bufLen, ctrlLen, flags);
}


/* Put the (unwanted) result of a successful, but cancelled, read
 * operation in the stash (so that the next reader gets it).
 */
static
void esuio_recv_stash_result(ESockDescriptor* descP,
                             ESUIOOp*         opP,
                             int              res)
{
    ESUIOStashElem* eP;
    size_t          total;

    if ((res < 0) || ((res == 0) && (opP->data.recv.got == 0) &&
                      (descP->type == SOCK_STREAM)))
        return; // Nothing (end of stream is sticky)

    total = opP->data.recv.got + (size_t) res;

    eP = MALLOC(sizeof(ESUIOStashElem));
    ESOCK_ASSERT( eP != NULL );
    sys_memzero((char*) eP, sizeof(ESUIOStashElem));

    eP->tag  = opP->tag;
    eP->fd   = -1;
    eP->data = opP->data.recv.buf;
    opP->data.recv.buf.data = NULL;
    if (total < eP->data.size)
        ESOCK_ASSERT( REALLOC_BIN(&eP->data, total) );

    if (opP->tag != ESUIO_OP_RECV) {
        struct msghdr* msgP = &opP->data.recv.msg;

        eP->addr     = opP->data.recv.addr;
        eP->addrLen  = msgP->msg_namelen;
        eP->msgFlags = msgP->msg_flags;
        if ((opP->tag == ESUIO_OP_RECVMSG) &&
            (msgP->msg_controllen > 0) &&
            (opP->data.recv.ctrl.data != NULL)) {
            eP->ctrl    = opP->data.recv.ctrl;
            eP->ctrlLen = msgP->msg_controllen;
            opP->data.recv.ctrl.data = NULL;
        }
    }

    esuio_stash_push(descP, eP);
}


/* The CQE of a read operation.
 */
static
void esuio_complete_read(ESUIOOp* opP, int res)
{
    ESockDescriptor* descP = opP->descP;
    ErlNifEnv*       env   = esuio_self_ring->env;
    ERL_NIF_TERM     sockRef, result;
    BOOLEAN_T        drained, resubmit = FALSE;
    ESUIORecvRes     rr;
    BOOLEAN_T        isCurrent;

    MLOCK(descP->readMtx);

    sockRef   = enif_make_resource(env, descP);
    isCurrent = ((descP->currentReaderP != NULL) &&
                 (descP->currentReader.dataP == opP));

    if (opP->closing) {

        /* The socket is closing, and the caller has already been
         * told (closed). Just make sure we do not leak any fds. */
        if ((res > 0) && (opP->tag == ESUIO_OP_RECVMSG) &&
            (opP->data.recv.ctrl.data != NULL))
            esuio_close_scm_rights(opP->data.recv.ctrl.data,
                                   opP->data.recv.msg.msg_controllen);

    } else if (opP->cancelled) {

        esuio_recv_stash_result(descP, opP, res);
        if (isCurrent)
            esuio_reader_done(env, descP, sockRef);

    } else {

        rr = esuio_recv_process(env, opP->env, descP, sockRef,
                                opP->tag, opP->data.recv.len,
                                &opP->data.recv.buf, opP->data.recv.got,
                                (res >= 0) ? res : -1,
                                (res < 0) ? -res : 0,
                                &opP->data.recv.msg, &opP->data.recv.ctrl,
                                &result);

        switch (rr) {
        case ESUIO_RECV_DONE:
            esuio_send_completion_msg(opP, result);
            if (isCurrent)
                esuio_reader_done(env, descP, sockRef);
            break;

        case ESUIO_RECV_MORE:
            esuio_send_completion_msg(opP, result);
            if (isCurrent)
                descP->currentReader.dataP = NULL; // Continues
            break;

        case ESUIO_RECV_ERROR:
            {
                ERL_NIF_TERM reason =
                    CP_TERM(env, esuio_error_reason(opP->env, result));

                esuio_send_completion_msg(opP, result);
                esuio_reader_error(env, descP, sockRef, reason);
            }
            break;

        case ESUIO_RECV_EAGAIN:
            resubmit = TRUE;
            break;

        case ESUIO_RECV_PARTIAL:
            if (res < 0) {
                /* Nothing more yet (spurious wakeup) */
                resubmit = TRUE;
            } else {
                size_t total = opP->data.recv.got + (size_t) res;

                /* Only part of it - the caller reads the rest */
                result = MKT2(opP->env, esock_atom_more,
                              esuio_recv_value(opP->env, descP, opP->tag,
                                               &opP->data.recv.buf,
                                               total, total,
                                               &opP->data.recv.msg,
                                               &opP->data.recv.ctrl));
                esuio_send_completion_msg(opP, result);
                if (isCurrent)
                    descP->currentReader.dataP = NULL; // Continues
            }
            break;
        }
    }

    if (resubmit) {
        /* Still in the ring (and counted) */
        esuio_recv_op_setup(descP, opP);
        esuio_submit(opP);
        drained = FALSE;
    } else {
        drained = esuio_op_done(opP, TRUE);
    }

    MUNLOCK(descP->readMtx);

    if (! resubmit) {
        if (drained)
            esuio_maybe_close_done(descP);
        enif_release_resource(descP);
        esuio_op_unref(opP);
    }

    enif_clear_env(env);
}


/* A queued reader has been popped (and is now the current reader).
 */
extern
BOOLEAN_T esuio_activate_reader(ErlNifEnv*       env,
                                ESockDescriptor* descP,
                                ERL_NIF_TERM     sockRef)
{
    ESUIOOp*     opP = (ESUIOOp*) descP->currentReader.dataP;
    ERL_NIF_TERM res;
    size_t       got = 0;

    if (opP->tag == ESUIO_OP_RECVMMSG)
        return esuio_activate_recvmmsg(env, descP, sockRef, opP);

    ESOCK_CNT_INC(env, descP, sockRef,
                  esock_atom_read_tries, &descP->readTries, 1);

    if (esuio_stash_first(descP) != NULL) {
        if (esuio_recv_from_stash(opP->env, descP, opP->tag,
                                  opP->data.recv.len,
                                  &opP->data.recv.buf, &got, &res)) {
            esuio_send_completion_msg(opP, res);
            (void) DEMONP("esuio_activate_reader -> done",
                          env, descP, &descP->currentReader.mon);
            descP->currentReader.dataP = NULL;
            esuio_op_unref(opP);
            return FALSE; // Try the next one
        }
        opP->data.recv.got = got;
    }

    esuio_recv_op_start(descP, opP);

    return TRUE;
}


/* A queued (not started) operation is thrown away.
 */
extern
void esuio_free_queued_op(void* opP)
{
    esuio_op_unref((ESUIOOp*) opP);
}



/* ======================================================================== *
 *                                 The stash                                *
 * ======================================================================== *
 * Data (and connections) consumed by an operation that nobody wanted
 * (anymore). Locked by readMtx.
 */

static
void esuio_stash_push(ESockDescriptor* descP, ESUIOStashElem* eP)
{
    ESUIOStash* stashP = (ESUIOStash*) descP->uringStash;

    if (stashP == NULL) {
        stashP = MALLOC(sizeof(ESUIOStash));
        ESOCK_ASSERT( stashP != NULL );
        stashP->first     = NULL;
        stashP->last      = NULL;
        descP->uringStash = stashP;
    }

    eP->nextP = NULL;
    if (stashP->last != NULL)
        stashP->last->nextP = eP;
    else
        stashP->first = eP;
    stashP->last = eP;
}


/* The first element, if it is (received) data (and not an accepted
 * connection; they are never mixed, since a listen socket does not
 * receive data).
 */
static
ESUIOStashElem* esuio_stash_first(ESockDescriptor* descP)
{
    ESUIOStash* stashP = (ESUIOStash*) descP->uringStash;

    if ((stashP == NULL) || (stashP->first == NULL) ||
        (stashP->first->tag == ESUIO_OP_ACCEPT))
        return NULL;

    return stashP->first;
}


/* The first element, if it is an accepted connection.
 */
static
ESUIOStashElem* esuio_stash_first_accepted(ESockDescriptor* descP)
{
    ESUIOStash* stashP = (ESUIOStash*) descP->uringStash;

    if ((stashP == NULL) || (stashP->first == NULL) ||
        (stashP->first->tag != ESUIO_OP_ACCEPT))
        return NULL;

    return stashP->first;
}


static
void esuio_stash_drop_first(ESockDescriptor* descP)
{
    ESUIOStash*     stashP = (ESUIOStash*) descP->uringStash;
    ESUIOStashElem* eP;

    if ((stashP == NULL) || ((eP = stashP->first) == NULL))
        return;

    stashP->first = eP->nextP;
    if (stashP->first == NULL)
        stashP->last = NULL;

    esuio_stash_elem_free(eP);
}


static
void esuio_stash_elem_free(ESUIOStashElem* eP)
{
    if ((eP->tag == ESUIO_OP_ACCEPT) && (eP->fd >= 0))
        (void) sock_close(eP->fd); // Accepted, but never delivered
    if (eP->data.data != NULL)
        FREE_BIN(&eP->data);
    if (eP->ctrl.data != NULL) {
        /* Never delivered - close any passed fds */
        esuio_close_scm_rights(eP->ctrl.data, eP->ctrlLen);
        FREE_BIN(&eP->ctrl);
    }
    FREE(eP);
}


static
void esuio_stash_free(ESockDescriptor* descP)
{
    ESUIOStash* stashP = (ESUIOStash*) descP->uringStash;

    if (stashP == NULL)
        return;

    while (stashP->first != NULL)
        esuio_stash_drop_first(descP);

    FREE(stashP);
    descP->uringStash = NULL;
}


/* Close the file descriptors passed (SCM_RIGHTS) in a control
 * buffer that will never be delivered.
 */
static
void esuio_close_scm_rights(unsigned char* ctrl, size_t ctrlLen)
{
    struct msghdr   msg;
    struct cmsghdr* cmsgP;

    if ((ctrl == NULL) || (ctrlLen == 0))
        return;

    sys_memzero((char*) &msg, sizeof(msg));
    msg.msg_control    = ctrl;
    msg.msg_controllen = ctrlLen;

    for (cmsgP = CMSG_FIRSTHDR(&msg);
         cmsgP != NULL;
         cmsgP = CMSG_NXTHDR(&msg, cmsgP)) {
        if ((cmsgP->cmsg_level == SOL_SOCKET) &&
            (cmsgP->cmsg_type == SCM_RIGHTS)) {
            int*   fdP = (int*) CMSG_DATA(cmsgP);
            size_t n   = (cmsgP->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            size_t i;

            for (i = 0; i < n; i++)
                (void) close(fdP[i]);
        }
    }
}



/* ======================================================================== *
 *                                   Send                                   *
 * ======================================================================== *
 *
 * send, sendto, sendmsg and sendv.
 *
 * Like essio, we first try to send directly (in the nif). If that
 * would block, or only part of the data (of a stream socket) was sent,
 * the rest is handed over to io_uring. The operation (in the ring)
 * sends *all* of it, and the result (in the completion message) is
 * then 'ok' (or, for sendmsg and sendv when there is more data (in the
 * tail of the I/O vector), {ok, Written}; the caller then sends the
 * rest).
 */


/* Make the caller the current writer, with (in-flight) operation opP
 * (or none).
 */
static
void esuio_writer_set_current(ErlNifEnv*       env,
                              ESockDescriptor* descP,
                              ERL_NIF_TERM     sendRef,
                              ESUIOOp*         opP)
{
    if (descP->currentWriterP == NULL) {
        ESOCK_ASSERT( enif_self(env, &descP->currentWriter.pid) != NULL );
        ESOCK_ASSERT( MONP("esuio_writer_set_current -> current writer",
                           env, descP,
                           &descP->currentWriter.pid,
                           &descP->currentWriter.mon) == 0 );
        ESOCK_ASSERT( descP->currentWriter.env == NULL );
        descP->currentWriter.env = esock_alloc_env("current-writer");
        descP->currentWriterP    = &descP->currentWriter;
    } else {
        enif_clear_env(descP->currentWriter.env);
    }
    descP->currentWriter.ref   = CP_TERM(descP->currentWriter.env, sendRef);
    descP->currentWriter.dataP = opP;
}


/* The current writer is done; activate the next (if any).
 */
static
void esuio_writer_done(ErlNifEnv*       env,
                       ESockDescriptor* descP,
                       ERL_NIF_TERM     sockRef)
{
    if (descP->currentWriterP == NULL)
        return;

    descP->currentWriter.dataP = NULL;

    if (! IS_OPEN(descP->writeState)) {
        esock_requestor_release("esuio_writer_done",
                                env, descP, &descP->currentWriter);
        descP->currentWriterP = NULL;
        return;
    }

    (void) DEMONP("esuio_writer_done -> current writer",
                  env, descP, &descP->currentWriter.mon);

    if (! esock_activate_next_writer(env, descP, sockRef))
        descP->currentWriterP = NULL;
}


/* A fatal write error: The current writer is done, and all the waiting
 * writers are aborted (with the reason).
 */
static
void esuio_writer_error(ErlNifEnv*       env,
                        ESockDescriptor* descP,
                        ERL_NIF_TERM     sockRef,
                        ERL_NIF_TERM     reason)
{
    if (descP->currentWriterP != NULL) {
        descP->currentWriter.dataP = NULL;
        esock_requestor_release("esuio_writer_error",
                                env, descP, &descP->currentWriter);
        descP->currentWriterP = NULL;
    }

    esock_inform_waiting_procs(env, "writer", descP, sockRef,
                               &descP->writersQ, reason);
}


/* Skip n (written) bytes of the msghdr I/O vector.
 */
static
void esuio_send_advance(ESUIOSendData* sdP, size_t n)
{
    struct iovec* iov = sdP->msg.msg_iov;
    size_t        cnt = sdP->msg.msg_iovlen;

    while ((cnt > 0) && ((n > 0) || (iov->iov_len == 0))) {
        if (n >= iov->iov_len) {
            n -= iov->iov_len;
            iov++;
            cnt--;
        } else {
            iov->iov_base = (char*) iov->iov_base + n;
            iov->iov_len -= n;
            n = 0;
        }
    }

    sdP->msg.msg_iov    = iov;
    sdP->msg.msg_iovlen = cnt;
}


/* Decode (the arguments of) a sendmsg or sendv.
 * All terms must be in env; the I/O vector is inspected in iovEnv
 * (NULL means it has to be freed with FREE_IOVEC).
 * eMsg is 'undefined' for sendv.
 */
static
BOOLEAN_T esuio_sendmsg_decode(ErlNifEnv*       env,
                               ErlNifEnv*       iovEnv,
                               ESockDescriptor* descP,
                               ERL_NIF_TERM     eMsg,
                               ERL_NIF_TERM     eIOV,
                               ESUIOSendData*   sdP,
                               ERL_NIF_TERM*    errP)
{
    ERL_NIF_TERM eAddr, eCtrl, tail, h, t;
    ErlNifBinary bin;
    size_t       i, ctrlUsed;

    sys_memzero((char*) sdP, sizeof(ESUIOSendData));
    sdP->isMsg = TRUE;

    if (enif_is_map(env, eMsg) &&
        GET_MAP_VAL(env, eMsg, esock_atom_addr, &eAddr)) {
        sdP->msg.msg_name    = (void*) &sdP->addr;
        sdP->msg.msg_namelen = sizeof(sdP->addr);
        if (! esock_decode_sockaddr(env, eAddr,
                                    &sdP->addr, &sdP->msg.msg_namelen)) {
            *errP = esock_make_invalid(env, esock_atom_addr);
            return FALSE;
        }
    }

    if ((! enif_inspect_iovec(iovEnv, ctrl.iov_max, eIOV, &tail,
                              &sdP->iovec)) ||
        (sdP->iovec == NULL)) {
        sdP->iovec = NULL;
        *errP = esock_make_invalid(env, esock_atom_iov);
        return FALSE;
    }

    if (sdP->iovec->iovcnt > ctrl.iov_max) {
        if (descP->type == SOCK_STREAM) {
            sdP->iovec->iovcnt = ctrl.iov_max;
        } else {
            *errP = esock_make_invalid(env, esock_atom_iov);
            goto failure;
        }
    }

    /* Skip empty binaries in the tail; is there more data? */
    for (;;) {
        if (enif_get_list_cell(env, tail, &h, &t) &&
            enif_inspect_binary(env, h, &bin) &&
            (bin.size == 0)) {
            tail = t;
        } else
            break;
    }
    sdP->dataInTail = (! enif_is_empty_list(env, tail));
    if (sdP->dataInTail && (descP->type != SOCK_STREAM)) {
        /* We can not send the whole packet in one sendmsg() call */
        *errP = esock_make_invalid(env, esock_atom_iov);
        goto failure;
    }

    for (i = 0; i < sdP->iovec->iovcnt; i++) {
        size_t len = sdP->iovec->iov[i].iov_len;

        sdP->size += len;
        if (sdP->size < len) {
            *errP = esock_make_invalid(env, esock_atom_iov);
            goto failure;
        }
    }

    sdP->msg.msg_iov    = sdP->iovec->iov;
    sdP->msg.msg_iovlen = sdP->iovec->iovcnt;

    if (enif_is_map(env, eMsg) &&
        GET_MAP_VAL(env, eMsg, esock_atom_ctrl, &eCtrl)) {
        sdP->ctrlBuf = (char*) MALLOC(descP->wCtrlSz);
        ESOCK_ASSERT( sdP->ctrlBuf != NULL );
        if (! essio_decode_cmsghdrs(env, descP, eCtrl,
                                    sdP->ctrlBuf, descP->wCtrlSz,
                                    &ctrlUsed)) {
            *errP = esock_make_invalid(env, esock_atom_ctrl);
            goto failure;
        }
        sdP->msg.msg_control    = sdP->ctrlBuf;
        sdP->msg.msg_controllen = ctrlUsed;
    }

    return TRUE;

 failure:
    if (iovEnv == NULL)
        FREE_IOVEC( sdP->iovec );
    sdP->iovec = NULL;
    if (sdP->ctrlBuf != NULL) {
        FREE(sdP->ctrlBuf);
        sdP->ctrlBuf = NULL;
    }
    return FALSE;
}


/* The send data of a send or sendto call: what remains of the data.
 * The data term is kept (copied) in the env of the operation, so the
 * data itself is not copied (except for small, heap, binaries).
 */
static
void esuio_send_data_keep(ESUIOOp*       opP,
                          ERL_NIF_TERM   eData,
                          size_t         written,
                          ESockAddress*  toAddrP,
                          SOCKLEN_T      toAddrLen)
{
    ESUIOSendData* sdP = &opP->data.send;
    ErlNifBinary   bin;

    ESOCK_ASSERT( enif_inspect_binary(opP->env,
                                      CP_TERM(opP->env, eData), &bin) );

    sys_memzero((char*) sdP, sizeof(ESUIOSendData));
    sdP->size    = bin.size;
    sdP->written = written;
    sdP->iov1.iov_base  = bin.data + written;
    sdP->iov1.iov_len   = bin.size - written;
    sdP->msg.msg_iov    = &sdP->iov1;
    sdP->msg.msg_iovlen = 1;
    if (toAddrP != NULL) {
        sdP->addr            = *toAddrP;
        sdP->msg.msg_name    = &sdP->addr;
        sdP->msg.msg_namelen = toAddrLen;
    }
}


/* Check the writer (like essio send_check_writer).
 * Returns TRUE if we may send now; otherwise the caller shall be
 * queued (*queueP) or *resP is the result.
 */
static
BOOLEAN_T esuio_send_check_writer(ErlNifEnv*       env,
                                  ESockDescriptor* descP,
                                  BOOLEAN_T*       queueP,
                                  ERL_NIF_TERM*    resP)
{
    ErlNifPid caller;

    *queueP = FALSE;

    if (descP->currentWriterP == NULL)
        return TRUE;

    ESOCK_ASSERT( enif_self(env, &caller) != NULL );

    if ((descP->currentWriter.dataP == NULL) &&
        (COMPARE_PIDS(&descP->currentWriter.pid, &caller) == 0))
        return TRUE; // A continuation (of us)

    if (esock_writer_search4pid(env, descP, &caller)) {
        /* Writer already in queue */
        *resP = esock_raise_invalid(env, esock_atom_state);
        return FALSE;
    }

    *queueP = TRUE;
    return FALSE;
}


/* The result of a direct send (in the nif), like essio
 * send_check_result, except that when we would block (or only part of
 * the data (of a stream) was sent), we hand the rest over to io_uring
 * (*waitP).
 */
static
ERL_NIF_TERM esuio_send_check_result(ErlNifEnv*       env,
                                     ESockDescriptor* descP,
                                     ERL_NIF_TERM     sockRef,
                                     ERL_NIF_TERM     sendRef,
                                     ssize_t          sendResult,
                                     int              err,
                                     size_t           dataSize,
                                     BOOLEAN_T        dataInTail,
                                     BOOLEAN_T*       waitP,
                                     size_t*          writtenP)
{
    size_t written;

    *waitP    = FALSE;
    *writtenP = 0;

    if (ESOCK_IS_ERROR(sendResult)) {
        if ((err == EAGAIN) || (err == EINTR) || (err == ERRNO_BLOCK)) {
            *waitP = TRUE;
            return esock_atom_completion;
        } else {
            ERL_NIF_TERM reason = MKA(env, erl_errno_id(err));

            ESOCK_CNT_INC(env, descP, sockRef,
                          esock_atom_write_fails, &descP->writeFails, 1);
            if (err != EINVAL)
                esuio_writer_error(env, descP, sockRef, reason);
            return esock_make_error(env, reason);
        }
    }

    written   = (size_t) sendResult;
    *writtenP = written;

    ESOCK_CNT_INC(env, descP, sockRef,
                  esock_atom_write_byte, &descP->writeByteCnt, written);
    descP->writePkgMaxCnt += written;

    if (written < dataSize) {

        if (descP->type != SOCK_STREAM) {
            /* Partial write for packet oriented socket
             * - done with packet */
            if (descP->writePkgMaxCnt > descP->writePkgMax)
                descP->writePkgMax = descP->writePkgMaxCnt;
            descP->writePkgMaxCnt = 0;
            ESOCK_CNT_INC(env, descP, sockRef,
                          esock_atom_write_pkg, &descP->writePkgCnt, 1);
            esuio_writer_done(env, descP, sockRef);
            return esock_make_ok2(env, MKI64(env, written));
        }

        /* Stream - the rest is sent by io_uring */
        *waitP = TRUE;
        return esock_atom_completion;
    }

    if (dataInTail) {
        /* We sent all we could, but there is more in the tail;
         * the caller continues (it remains the current writer) */
        esuio_writer_set_current(env, descP, sendRef, NULL);
        return MKT2(env, esock_atom_iov, MKI64(env, written));
    }

    ESOCK_CNT_INC(env, descP, sockRef,
                  esock_atom_write_pkg, &descP->writePkgCnt, 1);
    if (descP->writePkgMaxCnt > descP->writePkgMax)
        descP->writePkgMax = descP->writePkgMaxCnt;
    descP->writePkgMaxCnt = 0;

    esuio_writer_done(env, descP, sockRef);

    return esock_atom_ok;
}


/* Hand a (prepared) send operation over to io_uring, as the current
 * writer.
 */
static
ERL_NIF_TERM esuio_send_wait(ErlNifEnv*       env,
                             ESockDescriptor* descP,
                             ERL_NIF_TERM     sockRef,
                             ERL_NIF_TERM     sendRef,
                             ESUIOOp*         opP)
{
    ESOCK_CNT_INC(env, descP, sockRef,
                  esock_atom_write_waits, &descP->writeWaits, 1);

    esuio_writer_set_current(env, descP, sendRef, opP);
    esuio_op_hand_over(opP);

    return esock_atom_completion;
}


/* send and sendto
 */
static
ERL_NIF_TERM esuio_send_common(ErlNifEnv*       env,
                               ESockDescriptor* descP,
                               ERL_NIF_TERM     sockRef,
                               ERL_NIF_TERM     sendRef,
                               ErlNifBinary*    dataP,
                               ERL_NIF_TERM     eData,
                               int              flags,
                               ESockAddress*    toAddrP,
                               SOCKLEN_T        toAddrLen)
{
    ssize_t      sendResult;
    int          err;
    BOOLEAN_T    queue, wait;
    size_t       written;
    ERL_NIF_TERM res;
    ESUIOOp*     opP;

    if (! IS_OPEN(descP->writeState))
        return esock_make_error_closed(env);

    /* Connect and Write can not be simultaneous */
    if (descP->connectorP != NULL)
        return esock_make_error_invalid(env, esock_atom_state);

    sendResult = (ssize_t) dataP->size;
    if ((size_t) sendResult != dataP->size)
        return esock_make_error_invalid(env, esock_atom_data_size);

    if (! esuio_send_check_writer(env, descP, &queue, &res)) {
        ErlNifPid caller;

        if (! queue)
            return res;

        ESOCK_ASSERT( enif_self(env, &caller) != NULL );
        opP        = esuio_op_alloc(env, descP, ESUIO_OP_SEND,
                                    sockRef, sendRef);
        opP->flags = flags;
        esuio_send_data_keep(opP, eData, 0, toAddrP, toAddrLen);
        esock_writer_push(env, descP, caller, sendRef, opP);
        return esock_atom_completion;
    }

    ESOCK_CNT_INC(env, descP, sockRef,
                  esock_atom_write_tries, &descP->writeTries, 1);

    if (toAddrP != NULL)
        sendResult = sendto(descP->sock, dataP->data, dataP->size, flags,
                            &toAddrP->sa, toAddrLen);
    else
        sendResult = send(descP->sock, dataP->data, dataP->size, flags);
    err = ESOCK_IS_ERROR(sendResult) ? sock_errno() : 0;

    res = esuio_send_check_result(env, descP, sockRef, sendRef,
                                  sendResult, err, dataP->size, FALSE,
                                  &wait, &written);
    if (! wait)
        return res;

    opP        = esuio_op_alloc(env, descP, ESUIO_OP_SEND, sockRef, sendRef);
    opP->flags = flags;
    esuio_send_data_keep(opP, eData, written, toAddrP, toAddrLen);

    return esuio_send_wait(env, descP, sockRef, sendRef, opP);
}


extern
ERL_NIF_TERM esuio_send(ErlNifEnv*       env,
                        ESockDescriptor* descP,
                        ERL_NIF_TERM     sockRef,
                        ERL_NIF_TERM     sendRef,
                        ErlNifBinary*    sndDataP,
                        ERL_NIF_TERM     eData,
                        int              flags)
{
    return esuio_send_common(env, descP, sockRef, sendRef,
                             sndDataP, eData, flags, NULL, 0);
}


extern
ERL_NIF_TERM esuio_sendto(ErlNifEnv*       env,
                          ESockDescriptor* descP,
                          ERL_NIF_TERM     sockRef,
                          ERL_NIF_TERM     sendRef,
                          ErlNifBinary*    dataP,
                          ERL_NIF_TERM     eData,
                          int              flags,
                          ESockAddress*    toAddrP,
                          SOCKLEN_T        toAddrLen)
{
    return esuio_send_common(env, descP, sockRef, sendRef,
                             dataP, eData, flags, toAddrP, toAddrLen);
}


/* Create a sendmsg operation (for sendmsg or sendv); the arguments are
 * decoded (again) in the env of the operation, so that the data is kept
 * alive (without copying it).
 */
static
ESUIOOp* esuio_sendmsg_op(ErlNifEnv*       env,
                          ESockDescriptor* descP,
                          ERL_NIF_TERM     sockRef,
                          ERL_NIF_TERM     sendRef,
                          ERL_NIF_TERM     eMsg,
                          int              flags,
                          ERL_NIF_TERM     eIOV,
                          size_t           written,
                          ERL_NIF_TERM*    errP)
{
    ESUIOOp*     opP = esuio_op_alloc(env, descP, ESUIO_OP_SENDMSG,
                                      sockRef, sendRef);
    ERL_NIF_TERM opMsg = CP_TERM(opP->env, eMsg);
    ERL_NIF_TERM opIOV = CP_TERM(opP->env, eIOV);

    opP->flags = flags;
    if (! esuio_sendmsg_decode(opP->env, opP->env, descP,
                               opMsg, opIOV, &opP->data.send, errP)) {
        *errP = CP_TERM(env, *errP);
        esuio_op_unref(opP);
        return NULL;
    }
    opP->data.send.written = written;
    esuio_send_advance(&opP->data.send, written);

    return opP;
}


/* sendmsg and sendv
 */
static
ERL_NIF_TERM esuio_sendmsg_common(ErlNifEnv*       env,
                                  ESockDescriptor* descP,
                                  ERL_NIF_TERM     sockRef,
                                  ERL_NIF_TERM     sendRef,
                                  ERL_NIF_TERM     eMsg,
                                  int              flags,
                                  ERL_NIF_TERM     eIOV)
{
    ESUIOSendData sd;
    ssize_t       sendResult;
    int           err;
    BOOLEAN_T     queue, wait;
    size_t        written;
    ERL_NIF_TERM  res;
    ESUIOOp*      opP;

    if (! IS_OPEN(descP->writeState))
        return esock_make_error_closed(env);

    /* Connect and Write can not be simultaneous */
    if (descP->connectorP != NULL)
        return esock_make_error_invalid(env, esock_atom_state);

    if (! esuio_send_check_writer(env, descP, &queue, &res)) {
        ErlNifPid caller;

        if (! queue)
            return res;

        ESOCK_ASSERT( enif_self(env, &caller) != NULL );
        if ((opP = esuio_sendmsg_op(env, descP, sockRef, sendRef,
                                    eMsg, flags, eIOV, 0, &res)) == NULL)
            return res;
        esock_writer_push(env, descP, caller, sendRef, opP);
        return esock_atom_completion;
    }

    if (! esuio_sendmsg_decode(env, NULL, descP, eMsg, eIOV, &sd, &res))
        return res;

    ESOCK_CNT_INC(env, descP, sockRef,
                  esock_atom_write_tries, &descP->writeTries, 1);

    sendResult = sock_sendmsg(descP->sock, &sd.msg, flags);
    err        = ESOCK_IS_ERROR(sendResult) ? sock_errno() : 0;

    res = esuio_send_check_result(env, descP, sockRef, sendRef,
                                  sendResult, err, sd.size, sd.dataInTail,
                                  &wait, &written);

    FREE_IOVEC( sd.iovec );
    if (sd.ctrlBuf != NULL)
        FREE(sd.ctrlBuf);

    if (! wait)
        return res;

    if ((opP = esuio_sendmsg_op(env, descP, sockRef, sendRef,
                                eMsg, flags, eIOV, written, &res)) == NULL)
        return res; // Should not happen (we have decoded it once)

    return esuio_send_wait(env, descP, sockRef, sendRef, opP);
}


extern
ERL_NIF_TERM esuio_sendmsg(ErlNifEnv*       env,
                           ESockDescriptor* descP,
                           ERL_NIF_TERM     sockRef,
                           ERL_NIF_TERM     sendRef,
                           ERL_NIF_TERM     eMsg,
                           int              flags,
                           ERL_NIF_TERM     eIOV,
                           const ESockData* dataP)
{
    VOID(dataP);

    return esuio_sendmsg_common(env, descP, sockRef, sendRef,
                                eMsg, flags, eIOV);
}


extern
ERL_NIF_TERM esuio_sendv(ErlNifEnv*       env,
                         ESockDescriptor* descP,
                         ERL_NIF_TERM     sockRef,
                         ERL_NIF_TERM     sendRef,
                         ERL_NIF_TERM     eIOV,
                         const ESockData* dataP)
{
    VOID(dataP);

    return esuio_sendmsg_common(env, descP, sockRef, sendRef,
                                esock_atom_undefined, 0, eIOV);
}


/* The CQE of a write operation.
 */
static
void esuio_complete_write(ESUIOOp* opP, int res)
{
    ESockDescriptor* descP = opP->descP;
    ESUIOSendData*   sdP   = &opP->data.send;
    ErlNifEnv*       env   = esuio_self_ring->env;
    ERL_NIF_TERM     sockRef, result;
    BOOLEAN_T        drained, resubmit = FALSE;
    BOOLEAN_T        isCurrent;

    MLOCK(descP->writeMtx);

    sockRef   = enif_make_resource(env, descP);
    isCurrent = ((descP->currentWriterP != NULL) &&
                 (descP->currentWriter.dataP == opP));

    if (res > 0) {
        sdP->written += res;
        ESOCK_CNT_INC(env, descP, sockRef,
                      esock_atom_write_byte, &descP->writeByteCnt, res);
        descP->writePkgMaxCnt += res;
    }

    if (opP->closing) {

        /* The socket is closing, and the caller has already been told */

    } else if (opP->cancelled) {

        /* The caller cancelled; if it asked for it, tell it how it went.
         * If it actually completed (all was sent), it gets the ordinary
         * completion result, otherwise how much was actually written
         * (including in the nif). */
        if (opP->reportCancel) {
            if (sdP->written >= sdP->size) {
                if (sdP->dataInTail)
                    result = esock_make_ok2(opP->env,
                                            MKUI64(opP->env, sdP->written));
                else
                    result = esock_atom_ok;
                esuio_send_completion_msg(opP, result);
            } else {
                esuio_send_abort_msg(opP,
                                     MKT2(opP->env, esock_atom_cancelled,
                                          MKUI64(opP->env, sdP->written)));
            }
        }
        if (isCurrent)
            esuio_writer_done(env, descP, sockRef);

    } else if (res >= 0) {

        if ((sdP->written < sdP->size) &&
            (descP->type == SOCK_STREAM) &&
            (res > 0)) {

            /* Not all of it yet */
            esuio_send_advance(sdP, res);
            resubmit = TRUE;

        } else {

            ESOCK_CNT_INC(env, descP, sockRef,
                          esock_atom_write_pkg, &descP->writePkgCnt, 1);
            if (descP->writePkgMaxCnt > descP->writePkgMax)
                descP->writePkgMax = descP->writePkgMaxCnt;
            descP->writePkgMaxCnt = 0;

            if (sdP->dataInTail || (sdP->written < sdP->size))
                result = esock_make_ok2(opP->env,
                                        MKUI64(opP->env, sdP->written));
            else
                result = esock_atom_ok;

            esuio_send_completion_msg(opP, result);
            if (isCurrent)
                esuio_writer_done(env, descP, sockRef);
        }

    } else if ((res == -EAGAIN) || (res == -EINTR)) {

        resubmit = TRUE;

    } else {

        ERL_NIF_TERM reason = MKA(env, erl_errno_id(-res));

        ESOCK_CNT_INC(env, descP, sockRef,
                      esock_atom_write_fails, &descP->writeFails, 1);

        esuio_send_completion_msg(opP,
                                  esock_make_error(opP->env,
                                                   CP_TERM(opP->env,
                                                           reason)));
        if (-res != EINVAL)
            esuio_writer_error(env, descP, sockRef, reason);
        else if (isCurrent)
            esuio_writer_done(env, descP, sockRef);
    }

    if (resubmit) {
        esuio_submit(opP);
        drained = FALSE;
    } else {
        drained = esuio_op_done(opP, FALSE);
    }

    MUNLOCK(descP->writeMtx);

    if (! resubmit) {
        if (drained)
            esuio_maybe_close_done(descP);
        enif_release_resource(descP);
        esuio_op_unref(opP);
    }

    enif_clear_env(env);
}


/* A queued writer has been popped (and is now the current writer).
 */
extern
BOOLEAN_T esuio_activate_writer(ErlNifEnv*       env,
                                ESockDescriptor* descP,
                                ERL_NIF_TERM     sockRef)
{
    ESUIOOp* opP = (ESUIOOp*) descP->currentWriter.dataP;

    ESOCK_CNT_INC(env, descP, sockRef,
                  esock_atom_write_tries, &descP->writeTries, 1);
    ESOCK_CNT_INC(env, descP, sockRef,
                  esock_atom_write_waits, &descP->writeWaits, 1);

    esuio_op_hand_over(opP);

    return TRUE;
}



/* ======================================================================== *
 *                            recvmmsg and sendmmsg                         *
 * ======================================================================== *
 *
 * There are no io_uring operations for these, so when they would block,
 * we wait (in the ring) for the socket to become readable (writable),
 * with a poll (IORING_OP_POLL_ADD), and then do the call in the ring
 * thread. Since the poll does not consume (or send) anything, a
 * cancel (or close) can never lose any data.
 *
 * The results are the same as for essio, except that the result of a
 * sendmmsg in a completion message is 'ok' or {ok, RestIOVs}
 * (what socket:sendmmsg/4 returns), rather than what the nif returns.
 */


/* Receive (directly) up to vlen messages.
 * Like essio_recvmmsg.
 */
static
ESUIORecvRes esuio_recvmmsg_do(ErlNifEnv*       cEnv,
                               ErlNifEnv*       tEnv,
                               ESockDescriptor* descP,
                               ERL_NIF_TERM     sockRef,
                               unsigned int     vlen,
                               size_t           bufSz,
                               size_t           ctrlSz,
                               int              flags,
                               ERL_NIF_TERM*    resP)
{
    ESockAddress*   addrs;
    unsigned char*  recvBufs;
    unsigned char*  recvCtrl;
    struct mmsghdr* hdrs;
    struct iovec*   iovs;
    char*           pool;
    ERL_NIF_TERM*   elems;
    size_t          totalBytes = 0;
    unsigned int    i;
    int             n, err;

    {
        size_t addrsSz = vlen * sizeof(ESockAddress);
        size_t hdrsSz  = vlen * sizeof(struct mmsghdr);
        size_t iovsSz  = vlen * sizeof(struct iovec);
        size_t bufsSz  = vlen * bufSz;
        size_t ctrlsSz = vlen * ctrlSz;

        ESOCK_ASSERT( (pool = MALLOC(addrsSz + hdrsSz + iovsSz +
                                     bufsSz + ctrlsSz)) != NULL );
        sys_memzero(pool, addrsSz + hdrsSz + iovsSz);
        addrs    = (ESockAddress*)   pool;
        hdrs     = (struct mmsghdr*) (pool + addrsSz);
        iovs     = (struct iovec*)   (pool + addrsSz + hdrsSz);
        recvBufs = (unsigned char*)  (pool + addrsSz + hdrsSz + iovsSz);
        recvCtrl = (unsigned char*)  (pool + addrsSz + hdrsSz + iovsSz +
                                      bufsSz);
    }

    for (i = 0; i < vlen; i++) {
        iovs[i].iov_base                = recvBufs + (i * bufSz);
        iovs[i].iov_len                 = bufSz;
        hdrs[i].msg_hdr.msg_name        = &addrs[i];
        hdrs[i].msg_hdr.msg_namelen     = sizeof(ESockAddress);
        hdrs[i].msg_hdr.msg_iov         = &iovs[i];
        hdrs[i].msg_hdr.msg_iovlen      = 1;
        hdrs[i].msg_hdr.msg_control     = recvCtrl + (i * ctrlSz);
        hdrs[i].msg_hdr.msg_controllen  = ctrlSz;
    }

    n   = recvmmsg(descP->sock, hdrs, vlen, flags, NULL);
    err = ESOCK_IS_ERROR(n) ? sock_errno() : 0;

    if (n < 0) {
        FREE(pool);
        descP->rNumCnt = 0;
        if ((err == EAGAIN) || (err == ERRNO_BLOCK))
            return ESUIO_RECV_EAGAIN;
        ESOCK_CNT_INC(cEnv, descP, sockRef, esock_atom_read_fails,
                      &descP->readFails, 1);
        *resP = esock_make_error(tEnv, MKA(tEnv, erl_errno_id(err)));
        return ESUIO_RECV_ERROR;
    }

    if (n == 0) {
        FREE(pool);
        *resP = esock_make_ok2(tEnv, MKEL(tEnv));
        return ESUIO_RECV_DONE;
    }

    ESOCK_ASSERT( (elems = MALLOC(n * sizeof(ERL_NIF_TERM))) != NULL );

    for (i = 0; i < (unsigned int) n; i++) {
        ErlNifBinary buf, bin, ctrl;
        size_t       msgLen  = hdrs[i].msg_len;
        size_t       ctrlLen = hdrs[i].msg_hdr.msg_controllen;

        /* With MSG_TRUNC, msg_len may exceed the buffer */
        if (msgLen > bufSz)
            msgLen = bufSz;
        if (ctrlLen > ctrlSz)
            ctrlLen = ctrlSz;

        ESOCK_ASSERT( ALLOC_BIN(msgLen, &buf) );
        sys_memcpy(buf.data, recvBufs + (i * bufSz), msgLen);
        ESOCK_ASSERT( ALLOC_BIN(ctrlSz, &ctrl) );
        sys_memcpy(ctrl.data, recvCtrl + (i * ctrlSz), ctrlLen);
        hdrs[i].msg_hdr.msg_control = ctrl.data;

        /* The iov must describe the data (for the encoding) */
        iovs[i].iov_base = buf.data;
        iovs[i].iov_len  = msgLen;

        ESOCK_ASSERT( esuio_recv_create_bin(&buf, msgLen, &bin) );
        if (buf.data != NULL)
            FREE_BIN(&buf);

        essio_encode_msg(tEnv, descP, msgLen, &hdrs[i].msg_hdr,
                         &bin, &ctrl, &elems[i]);

        totalBytes += msgLen;
        if (msgLen > descP->readPkgMax)
            descP->readPkgMax = msgLen;
    }

    *resP = esock_make_ok2(tEnv, enif_make_list_from_array(tEnv, elems, n));
    FREE(elems);
    FREE(pool);

    descP->rNumCnt = 0;
    ESOCK_CNT_INC(cEnv, descP, sockRef, esock_atom_read_pkg,
                  &descP->readPkgCnt, n);
    ESOCK_CNT_INC(cEnv, descP, sockRef, esock_atom_read_byte,
                  &descP->readByteCnt, totalBytes);

    return ESUIO_RECV_DONE;
}


extern
ERL_NIF_TERM esuio_recvmmsg(ErlNifEnv*       env,
                            ESockDescriptor* descP,
                            ERL_NIF_TERM     sockRef,
                            ERL_NIF_TERM     recvRef,
                            unsigned int     vlen,
                            ssize_t          bufLen,
                            ssize_t          ctrlLen,
                            int              flags)
{
    size_t       bufSz  = (bufLen  != 0 ? (size_t) bufLen  : descP->rBufSz);
    size_t       ctrlSz = (ctrlLen != 0 ? (size_t) ctrlLen : descP->rCtrlSz);
    ERL_NIF_TERM res;
    ESUIOOp*     opP;

    if (! IS_OPEN(descP->readState))
        return esock_make_error_closed(env);

    /* Accept and Read can not be simultaneous */
    if (descP->currentAcceptorP != NULL)
        return esock_make_error_invalid(env, esock_atom_state);

    if (vlen > ESUIO_MMSG_MAX)
        vlen = ESUIO_MMSG_MAX;

    if (descP->currentReaderP != NULL) {
        ErlNifPid caller;

        ESOCK_ASSERT( enif_self(env, &caller) != NULL );

        if ((descP->currentReader.dataP != NULL) ||
            (COMPARE_PIDS(&descP->currentReader.pid, &caller) != 0)) {

            if (esock_reader_search4pid(env, descP, &caller))
                return esock_raise_invalid(env, esock_atom_state);
            if (COMPARE(recvRef, esock_atom_zero) == 0)
                return esock_atom_timeout;

            opP = esuio_op_alloc(env, descP, ESUIO_OP_RECVMMSG,
                                 sockRef, recvRef);
            opP->flags                = flags;
            opP->data.recvmmsg.vlen   = vlen;
            opP->data.recvmmsg.bufSz  = bufSz;
            opP->data.recvmmsg.ctrlSz = ctrlSz;
            esock_reader_push(env, descP, caller, recvRef, opP);
            return esock_atom_completion;
        }
    }

    /* Data consumed by a cancelled operation goes first
     * (one message at a time) */
    if (esuio_stash_first(descP) != NULL) {
        size_t got;

        if (esuio_recv_from_stash(env, descP, ESUIO_OP_RECVMSG, 0,
                                  &descP->buf, &got, &res)) {
            esuio_reader_done(env, descP, sockRef);
            return esock_make_ok2(env,
                                  MKL1(env, esuio_error_reason(env, res)));
        }
    }

    ESOCK_CNT_INC(env, descP, sockRef,
                  esock_atom_read_tries, &descP->readTries, 1);

    switch (esuio_recvmmsg_do(env, env, descP, sockRef,
                              vlen, bufSz, ctrlSz, flags, &res)) {
    case ESUIO_RECV_DONE:
        esuio_reader_done(env, descP, sockRef);
        return res;

    case ESUIO_RECV_ERROR:
        esuio_reader_error(env, descP, sockRef, esuio_error_reason(env, res));
        return res;

    default:
        break;
    }

    /* Would block */

    if (COMPARE(recvRef, esock_atom_zero) == 0) {
        esuio_reader_done(env, descP, sockRef);
        return esock_atom_timeout;
    }

    opP = esuio_op_alloc(env, descP, ESUIO_OP_RECVMMSG, sockRef, recvRef);
    opP->flags                = flags;
    opP->data.recvmmsg.vlen   = vlen;
    opP->data.recvmmsg.bufSz  = bufSz;
    opP->data.recvmmsg.ctrlSz = ctrlSz;

    esuio_reader_set_current(env, descP, recvRef, opP);
    esuio_op_hand_over(opP);

    return esock_atom_completion;
}


/* A queued recvmmsg reader has been popped.
 */
static
BOOLEAN_T esuio_activate_recvmmsg(ErlNifEnv*       env,
                                  ESockDescriptor* descP,
                                  ERL_NIF_TERM     sockRef,
                                  ESUIOOp*         opP)
{
    ESOCK_CNT_INC(env, descP, sockRef,
                  esock_atom_read_tries, &descP->readTries, 1);

    if (esuio_stash_first(descP) != NULL) {
        ErlNifBinary buf = {0};
        ERL_NIF_TERM res;
        size_t       got;

        if (esuio_recv_from_stash(opP->env, descP, ESUIO_OP_RECVMSG, 0,
                                  &buf, &got, &res)) {
            if (buf.data != NULL)
                FREE_BIN(&buf);
            esuio_send_completion_msg(opP,
                                      esock_make_ok2(opP->env,
                                                     MKL1(opP->env,
                                                          esuio_error_reason(opP->env, res))));
            (void) DEMONP("esuio_activate_recvmmsg -> done",
                          env, descP, &descP->currentReader.mon);
            descP->currentReader.dataP = NULL;
            esuio_op_unref(opP);
            return FALSE; // Try the next one
        }
        if (buf.data != NULL)
            FREE_BIN(&buf);
    }

    esuio_op_hand_over(opP);

    return TRUE;
}


/* The CQE of a recvmmsg (poll) operation.
 */
static
void esuio_complete_recvmmsg(ESUIOOp* opP, int res)
{
    ESockDescriptor* descP = opP->descP;
    ErlNifEnv*       env   = esuio_self_ring->env;
    ERL_NIF_TERM     sockRef, result;
    BOOLEAN_T        drained, resubmit = FALSE;
    BOOLEAN_T        isCurrent;

    MLOCK(descP->readMtx);

    sockRef   = enif_make_resource(env, descP);
    isCurrent = ((descP->currentReaderP != NULL) &&
                 (descP->currentReader.dataP == opP));

    if (opP->closing) {

        /* The caller has already been told */

    } else if (opP->cancelled) {

        /* Nothing has been consumed (it was only a poll) */
        if (isCurrent)
            esuio_reader_done(env, descP, sockRef);

    } else {

        /* Readable (or an error, which the call will report) */
        VOID(res);

        ESOCK_CNT_INC(env, descP, sockRef,
                      esock_atom_read_tries, &descP->readTries, 1);

        switch (esuio_recvmmsg_do(env, opP->env, descP, sockRef,
                                  opP->data.recvmmsg.vlen,
                                  opP->data.recvmmsg.bufSz,
                                  opP->data.recvmmsg.ctrlSz,
                                  opP->flags, &result)) {
        case ESUIO_RECV_DONE:
            esuio_send_completion_msg(opP, result);
            if (isCurrent)
                esuio_reader_done(env, descP, sockRef);
            break;

        case ESUIO_RECV_ERROR:
            {
                ERL_NIF_TERM reason =
                    CP_TERM(env, esuio_error_reason(opP->env, result));

                esuio_send_completion_msg(opP, result);
                esuio_reader_error(env, descP, sockRef, reason);
            }
            break;

        default:
            /* Not yet (spurious wakeup) */
            resubmit = TRUE;
            break;
        }
    }

    if (resubmit) {
        esuio_submit(opP);
        drained = FALSE;
    } else {
        drained = esuio_op_done(opP, TRUE);
    }

    MUNLOCK(descP->readMtx);

    if (! resubmit) {
        if (drained)
            esuio_maybe_close_done(descP);
        enif_release_resource(descP);
        esuio_op_unref(opP);
    }

    enif_clear_env(env);
}


/* Decode the messages of a sendmmsg (like essio_sendmmsg).
 * All terms must be in env; the I/O vectors are inspected in iovEnv
 * (NULL means they have to be freed with esuio_sendmmsg_free).
 */
static
void esuio_sendmmsg_free(ESUIOMMsgData* mdP, ErlNifEnv* iovEnv)
{
    unsigned int i;

    if (mdP->pool == NULL)
        return;

    if (iovEnv == NULL) {
        for (i = 0; i < mdP->count; i++) {
            if (mdP->iovecs[i] != NULL)
                FREE_IOVEC( mdP->iovecs[i] );
        }
    }
    FREE(mdP->pool);
    mdP->pool = NULL;
}


static
BOOLEAN_T esuio_sendmmsg_decode(ErlNifEnv*       env,
                                ErlNifEnv*       iovEnv,
                                ESockDescriptor* descP,
                                ERL_NIF_TERM     eMsgs,
                                ESUIOMMsgData*   mdP,
                                ERL_NIF_TERM*    errP)
{
    ERL_NIF_TERM eMsg, eAddr, eCtrl, eIOV, tail, iovTail;
    unsigned int i, count = 0;
    size_t       wCtrlSz = descP->wCtrlSz;
    char*        ctrlData;

    sys_memzero((char*) mdP, sizeof(ESUIOMMsgData));
    mdP->eMsgs = eMsgs;

    tail = eMsgs;
    while (! enif_is_empty_list(env, tail)) {
        if ((! enif_get_list_cell(env, tail, &eMsg, &tail)) ||
            (! IS_MAP(env, eMsg))) {
            *errP = enif_make_badarg(env);
            return FALSE;
        }
        count++;
    }
    mdP->total = count;
    if (count > ESUIO_MMSG_MAX)
        count = ESUIO_MMSG_MAX;
    mdP->count = count;
    if (count == 0)
        return TRUE;

    {
        size_t hdrsSz   = count * sizeof(struct mmsghdr);
        size_t addrsSz  = count * sizeof(ESockAddress);
        size_t iovecsSz = count * sizeof(ErlNifIOVec*);
        size_t ctrlSz   = count * wCtrlSz;

        ESOCK_ASSERT( (mdP->pool = MALLOC(hdrsSz + addrsSz + iovecsSz +
                                          ctrlSz)) != NULL );
        sys_memzero(mdP->pool, hdrsSz + addrsSz + iovecsSz);
        mdP->hdrs   = (struct mmsghdr*) mdP->pool;
        mdP->addrs  = (ESockAddress*)   (mdP->pool + hdrsSz);
        mdP->iovecs = (ErlNifIOVec**)   (mdP->pool + hdrsSz + addrsSz);
        ctrlData    = mdP->pool + hdrsSz + addrsSz + iovecsSz;
    }

    tail = eMsgs;
    for (i = 0; i < count; i++) {
        struct msghdr* hdrP = &mdP->hdrs[i].msg_hdr;

        (void) enif_get_list_cell(env, tail, &eMsg, &tail);

        if (GET_MAP_VAL(env, eMsg, esock_atom_addr, &eAddr)) {
            hdrP->msg_name    = &mdP->addrs[i];
            hdrP->msg_namelen = sizeof(ESockAddress);
            if (! esock_decode_sockaddr(env, eAddr,
                                        &mdP->addrs[i], &hdrP->msg_namelen)) {
                *errP = esock_make_invalid(env, esock_atom_addr);
                goto failure;
            }
        }

        if (! GET_MAP_VAL(env, eMsg, esock_atom_iov, &eIOV)) {
            *errP = enif_make_badarg(env);
            goto failure;
        }
        if (! enif_inspect_iovec(iovEnv, ctrl.iov_max, eIOV, &iovTail,
                                 &mdP->iovecs[i])) {
            mdP->iovecs[i] = NULL;
            *errP = enif_make_badarg(env);
            goto failure;
        }
        if (mdP->iovecs[i]->iovcnt > ctrl.iov_max) {
            *errP = esock_make_invalid(env, esock_atom_iov);
            goto failure;
        }
        hdrP->msg_iov    = mdP->iovecs[i]->iov;
        hdrP->msg_iovlen = mdP->iovecs[i]->iovcnt;

        if (GET_MAP_VAL(env, eMsg, esock_atom_ctrl, &eCtrl)) {
            size_t used;
            char*  ctrlBuf = ctrlData + (i * wCtrlSz);

            if (! essio_decode_cmsghdrs(env, descP, eCtrl,
                                        ctrlBuf, wCtrlSz, &used)) {
                *errP = esock_make_invalid(env, esock_atom_ctrl);
                goto failure;
            }
            hdrP->msg_control    = ctrlBuf;
            hdrP->msg_controllen = used;
        }
    }

    return TRUE;

 failure:
    esuio_sendmmsg_free(mdP, iovEnv);
    return FALSE;
}


/* Skip written bytes of an I/O vector (a list of binaries).
 */
static
ERL_NIF_TERM esuio_iov_rest(ErlNifEnv*   env,
                            ERL_NIF_TERM eIOV,
                            size_t       written)
{
    ERL_NIF_TERM h, t;
    ErlNifBinary bin;

    while ((written > 0) &&
           enif_get_list_cell(env, eIOV, &h, &t) &&
           enif_inspect_binary(env, h, &bin)) {
        if (bin.size <= written) {
            written -= bin.size;
            eIOV     = t;
        } else {
            return MKC(env,
                       enif_make_sub_binary(env, h, written,
                                            bin.size - written),
                       t);
        }
    }

    return eIOV;
}


/* The result of a (successful) sendmmsg call, of sentCount messages.
 * Updates the counters, and returns what essio would have returned
 * (ok | {ok, Partials, SentCount}), or (rest) what socket:sendmmsg/4
 * returns (ok | {ok, RestIOVs}).
 */
static
ERL_NIF_TERM esuio_sendmmsg_result(ErlNifEnv*       cEnv,
                                   ErlNifEnv*       tEnv,
                                   ESockDescriptor* descP,
                                   ERL_NIF_TERM     sockRef,
                                   ESUIOMMsgData*   mdP,
                                   unsigned int     sentCount,
                                   BOOLEAN_T        rest)
{
    ERL_NIF_TERM partials = MKEL(tEnv);
    ERL_NIF_TERM rests    = MKEL(tEnv);
    size_t       written  = 0, maxLen = 0;
    BOOLEAN_T    partial  = FALSE;
    unsigned int i, k;

    for (i = 0; i < sentCount; i++) {
        size_t expected = 0, len = mdP->hdrs[i].msg_len;

        for (k = 0; k < mdP->iovecs[i]->iovcnt; k++)
            expected += mdP->iovecs[i]->iov[k].iov_len;
        written += len;
        if (len > maxLen)
            maxLen = len;
        if (len != expected)
            partial = TRUE;
    }

    ESOCK_CNT_INC(cEnv, descP, sockRef, esock_atom_write_pkg,
                  &descP->writePkgCnt, sentCount);
    ESOCK_CNT_INC(cEnv, descP, sockRef, esock_atom_write_byte,
                  &descP->writeByteCnt, written);
    if (maxLen > descP->writePkgMax)
        descP->writePkgMax = maxLen;

    if ((sentCount == mdP->total) && (! partial))
        return esock_atom_ok;

    if (! rest) {
        for (i = sentCount; i-- > 0; ) {
            size_t expected = 0, len = mdP->hdrs[i].msg_len;

            for (k = 0; k < mdP->iovecs[i]->iovcnt; k++)
                expected += mdP->iovecs[i]->iov[k].iov_len;
            if (len != expected)
                partials = MKC(tEnv,
                               MKT2(tEnv, MKI(tEnv, (int) i),
                                    MKI(tEnv, (int) len)),
                               partials);
        }
        return MKT3(tEnv, esock_atom_ok, partials, MKUI(tEnv, sentCount));
    } else {
        ERL_NIF_TERM  eMsg, eIOV, tail = mdP->eMsgs;
        ERL_NIF_TERM* a;
        unsigned int  n = 0;

        ESOCK_ASSERT( (a = MALLOC(mdP->total * sizeof(ERL_NIF_TERM)))
                      != NULL );
        for (i = 0; i < mdP->total; i++) {
            (void) enif_get_list_cell(tEnv, tail, &eMsg, &tail);
            (void) GET_MAP_VAL(tEnv, eMsg, esock_atom_iov, &eIOV);
            if (i < sentCount) {
                size_t expected = 0, len = mdP->hdrs[i].msg_len;

                for (k = 0; k < mdP->iovecs[i]->iovcnt; k++)
                    expected += mdP->iovecs[i]->iov[k].iov_len;
                if (len != expected)
                    a[n++] = esuio_iov_rest(tEnv, eIOV, len);
            } else {
                a[n++] = eIOV;
            }
        }
        rests = enif_make_list_from_array(tEnv, a, n);
        FREE(a);
        return esock_make_ok2(tEnv, rests);
    }
}


extern
ERL_NIF_TERM esuio_sendmmsg(ErlNifEnv*       env,
                            ESockDescriptor* descP,
                            ERL_NIF_TERM     sockRef,
                            ERL_NIF_TERM     sendRef,
                            ERL_NIF_TERM     eMsgs,
                            int              flags,
                            const ESockData* dataP)
{
    ESUIOMMsgData md;
    BOOLEAN_T     queue;
    ERL_NIF_TERM  res;
    ESUIOOp*      opP;
    int           n, err;

    VOID(dataP);

    if (! IS_OPEN(descP->writeState))
        return esock_make_error_closed(env);

    /* Connect and Write can not be simultaneous */
    if (descP->connectorP != NULL)
        return esock_make_error_invalid(env, esock_atom_state);

    if (! esuio_send_check_writer(env, descP, &queue, &res)) {
        ErlNifPid caller;

        if (! queue)
            return res;

        ESOCK_ASSERT( enif_self(env, &caller) != NULL );
        opP        = esuio_op_alloc(env, descP, ESUIO_OP_SENDMMSG,
                                    sockRef, sendRef);
        opP->flags = flags;
        if (! esuio_sendmmsg_decode(opP->env, opP->env, descP,
                                    CP_TERM(opP->env, eMsgs),
                                    &opP->data.sendmmsg, &res)) {
            res = CP_TERM(env, res);
            esuio_op_unref(opP);
            return res;
        }
        esock_writer_push(env, descP, caller, sendRef, opP);
        return esock_atom_completion;
    }

    if (! esuio_sendmmsg_decode(env, NULL, descP, eMsgs, &md, &res))
        return res;

    if (md.count == 0) {
        esuio_writer_done(env, descP, sockRef);
        return esock_atom_ok;
    }

    ESOCK_CNT_INC(env, descP, sockRef,
                  esock_atom_write_tries, &descP->writeTries, 1);

    n   = sendmmsg(descP->sock, md.hdrs, md.count, flags);
    err = ESOCK_IS_ERROR(n) ? sock_errno() : 0;

    if (n >= 0) {
        res = esuio_sendmmsg_result(env, env, descP, sockRef,
                                    &md, (unsigned int) n, FALSE);
        esuio_sendmmsg_free(&md, NULL);
        esuio_writer_done(env, descP, sockRef);
        return res;
    }

    esuio_sendmmsg_free(&md, NULL);

    if ((err != EAGAIN) && (err != EINTR) && (err != ERRNO_BLOCK)) {
        ERL_NIF_TERM reason = MKA(env, erl_errno_id(err));

        ESOCK_CNT_INC(env, descP, sockRef,
                      esock_atom_write_fails, &descP->writeFails, 1);
        if (err != EINVAL)
            esuio_writer_error(env, descP, sockRef, reason);
        return esock_make_error(env, reason);
    }

    /* Would block - wait (in the ring) until we can send */

    opP        = esuio_op_alloc(env, descP, ESUIO_OP_SENDMMSG,
                                sockRef, sendRef);
    opP->flags = flags;
    if (! esuio_sendmmsg_decode(opP->env, opP->env, descP,
                                CP_TERM(opP->env, eMsgs),
                                &opP->data.sendmmsg, &res)) {
        /* Should not happen (we have decoded it once) */
        res = CP_TERM(env, res);
        esuio_op_unref(opP);
        return res;
    }

    return esuio_send_wait(env, descP, sockRef, sendRef, opP);
}


/* The CQE of a sendmmsg (poll) operation.
 */
static
void esuio_complete_sendmmsg(ESUIOOp* opP, int res)
{
    ESockDescriptor* descP = opP->descP;
    ESUIOMMsgData*   mdP   = &opP->data.sendmmsg;
    ErlNifEnv*       env   = esuio_self_ring->env;
    ERL_NIF_TERM     sockRef, result;
    BOOLEAN_T        drained, resubmit = FALSE;
    BOOLEAN_T        isCurrent;

    VOID(res);

    MLOCK(descP->writeMtx);

    sockRef   = enif_make_resource(env, descP);
    isCurrent = ((descP->currentWriterP != NULL) &&
                 (descP->currentWriter.dataP == opP));

    if (opP->closing) {

        /* The caller has already been told */

    } else if (opP->cancelled) {

        /* Nothing has been sent (it was only a poll) */
        if (isCurrent)
            esuio_writer_done(env, descP, sockRef);

    } else if (mdP->count == 0) {

        esuio_send_completion_msg(opP, esock_atom_ok);
        if (isCurrent)
            esuio_writer_done(env, descP, sockRef);

    } else {
        int n, err;

        ESOCK_CNT_INC(env, descP, sockRef,
                      esock_atom_write_tries, &descP->writeTries, 1);

        n   = sendmmsg(descP->sock, mdP->hdrs, mdP->count,
                       opP->flags | MSG_DONTWAIT);
        err = ESOCK_IS_ERROR(n) ? sock_errno() : 0;

        if (n >= 0) {
            result = esuio_sendmmsg_result(env, opP->env, descP, sockRef,
                                           mdP, (unsigned int) n, TRUE);
            esuio_send_completion_msg(opP, result);
            if (isCurrent)
                esuio_writer_done(env, descP, sockRef);
        } else if ((err == EAGAIN) || (err == EINTR) ||
                   (err == ERRNO_BLOCK)) {
            resubmit = TRUE;
        } else {
            ERL_NIF_TERM reason = MKA(env, erl_errno_id(err));

            ESOCK_CNT_INC(env, descP, sockRef,
                          esock_atom_write_fails, &descP->writeFails, 1);
            esuio_send_completion_msg(opP,
                                      esock_make_error(opP->env,
                                                       CP_TERM(opP->env,
                                                               reason)));
            if (err != EINVAL)
                esuio_writer_error(env, descP, sockRef, reason);
            else if (isCurrent)
                esuio_writer_done(env, descP, sockRef);
        }
    }

    if (resubmit) {
        esuio_submit(opP);
        drained = FALSE;
    } else {
        drained = esuio_op_done(opP, FALSE);
    }

    MUNLOCK(descP->writeMtx);

    if (! resubmit) {
        if (drained)
            esuio_maybe_close_done(descP);
        enif_release_resource(descP);
        esuio_op_unref(opP);
    }

    enif_clear_env(env);
}



/* ======================================================================== *
 *                                  Accept                                  *
 * ======================================================================== *
 *
 * Like essio, we first try to accept directly. If that would block,
 * the accept is handed over to io_uring (IORING_OP_ACCEPT), and the
 * result ({ok, Socket} | {error, Reason}) is delivered in a completion
 * message (like esaio).
 * A connection accepted by an operation that was cancelled (or whose
 * acceptor died) is put in the stash, and given to the next acceptor.
 */

/* The current acceptor is done; activate the next (if any).
 */
static
void esuio_acceptor_done(ErlNifEnv*       env,
                         ESockDescriptor* descP,
                         ERL_NIF_TERM     sockRef)
{
    if (descP->currentAcceptorP == NULL)
        return;

    descP->currentAcceptor.dataP = NULL;

    if (! IS_OPEN(descP->readState)) {
        esock_requestor_release("esuio_acceptor_done",
                                env, descP, &descP->currentAcceptor);
        descP->currentAcceptorP = NULL;
        return;
    }

    (void) DEMONP("esuio_acceptor_done -> current acceptor",
                  env, descP, &descP->currentAcceptor.mon);
    MON_INIT(&descP->currentAcceptor.mon);

    if (! esock_activate_next_acceptor(env, descP, sockRef)) {
        descP->readState       &= ~ESOCK_STATE_ACCEPTING;
        descP->currentAcceptorP = NULL;
    }
}


/* A fatal accept error: The current acceptor is done, and all the
 * waiting acceptors are aborted (with the reason).
 */
static
void esuio_acceptor_error(ErlNifEnv*       env,
                          ESockDescriptor* descP,
                          ERL_NIF_TERM     sockRef,
                          ERL_NIF_TERM     reason)
{
    if (descP->currentAcceptorP != NULL) {
        descP->currentAcceptor.dataP = NULL;
        esock_requestor_release("esuio_acceptor_error",
                                env, descP, &descP->currentAcceptor);
        descP->currentAcceptorP = NULL;
    }
    descP->readState &= ~ESOCK_STATE_ACCEPTING;

    esock_inform_waiting_procs(env, "acceptor", descP, sockRef,
                               &descP->acceptorsQ, reason);
}


/* Take an accepted connection from the stash (or -1).
 */
static
int esuio_stash_take_accepted(ESockDescriptor* descP)
{
    ESUIOStashElem* eP = esuio_stash_first_accepted(descP);
    int             fd;

    if (eP == NULL)
        return -1;

    fd     = eP->fd;
    eP->fd = -1;
    esuio_stash_drop_first(descP);

    return fd;
}


extern
ERL_NIF_TERM esuio_accept(ErlNifEnv*       env,
                          ESockDescriptor* descP,
                          ERL_NIF_TERM     sockRef,
                          ERL_NIF_TERM     accRef)
{
    ErlNifPid    caller;
    SOCKET       accSock;
    ERL_NIF_TERM res;
    ESUIOOp*     opP;
    int          err;

    ESOCK_ASSERT( enif_self(env, &caller) != NULL );

    if (! IS_OPEN(descP->readState))
        return esock_make_error_closed(env);

    /* Accept and Read can not be simultaneous */
    if (descP->currentReaderP != NULL)
        return esock_make_error_invalid(env, esock_atom_state);

    if (descP->currentAcceptorP != NULL) {
        /* There is an accept in progress - wait for our turn */
        if (esock_acceptor_search4pid(env, descP, &caller))
            return esock_raise_invalid(env, esock_atom_state);

        opP = esuio_op_alloc(env, descP, ESUIO_OP_ACCEPT, sockRef, accRef);
        esock_acceptor_push(env, descP, caller, accRef, opP);
        return esock_atom_completion;
    }

    ESOCK_CNT_INC(env, descP, sockRef,
                  esock_atom_acc_tries, &descP->accTries, 1);

    /* A connection accepted by a cancelled operation goes first */
    if ((accSock = esuio_stash_take_accepted(descP)) < 0)
        accSock = accept4(descP->sock, NULL, NULL, SOCK_CLOEXEC);

    if (! ESOCK_IS_ERROR(accSock)) {
        (void) essio_accepted(env, descP, sockRef, accSock, caller, &res);
        return res;
    }

    err = sock_errno();
    if ((err != EAGAIN) && (err != ERRNO_BLOCK)) {
        ESOCK_CNT_INC(env, descP, sockRef,
                      esock_atom_acc_fails, &descP->accFails, 1);
        return esock_make_error_errno(env, err);
    }

    /* Would block - hand it over to io_uring */

    ESOCK_CNT_INC(env, descP, sockRef,
                  esock_atom_acc_waits, &descP->accWaits, 1);

    opP = esuio_op_alloc(env, descP, ESUIO_OP_ACCEPT, sockRef, accRef);

    descP->currentAcceptor.pid = caller;
    ESOCK_ASSERT( MONP("esuio_accept -> current acceptor",
                       env, descP,
                       &descP->currentAcceptor.pid,
                       &descP->currentAcceptor.mon) == 0 );
    ESOCK_ASSERT( descP->currentAcceptor.env == NULL );
    descP->currentAcceptor.env   = esock_alloc_env("current acceptor");
    descP->currentAcceptor.ref   = CP_TERM(descP->currentAcceptor.env,
                                           accRef);
    descP->currentAcceptor.dataP = opP;
    descP->currentAcceptorP      = &descP->currentAcceptor;
    descP->readState            |= ESOCK_STATE_ACCEPTING;

    esuio_op_hand_over(opP);

    return esock_atom_completion;
}


/* The completion result of an accepted connection:
 * {ok, {'$socket', Ref}} (in the env of the operation).
 */
static
ERL_NIF_TERM esuio_accept_result(ErlNifEnv*       env,
                                 ESockDescriptor* descP,
                                 ERL_NIF_TERM     sockRef,
                                 SOCKET           accSock,
                                 ESUIOOp*         opP)
{
    ERL_NIF_TERM res;
    const ERL_NIF_TERM* tuple;
    int                 arity;

    (void) essio_accepted(env, descP, sockRef, accSock, opP->caller, &res);

    /* res = {ok, AccRef} (in env) */
    ESOCK_ASSERT( enif_get_tuple(env, res, &arity, &tuple) && (arity == 2) );

    return esock_make_ok2(opP->env,
                          esock_mk_socket(opP->env,
                                          CP_TERM(opP->env, tuple[1])));
}


/* The CQE of an accept operation.
 */
static
void esuio_complete_accept(ESUIOOp* opP, int res)
{
    ESockDescriptor* descP = opP->descP;
    ErlNifEnv*       env   = esuio_self_ring->env;
    ERL_NIF_TERM     sockRef;
    BOOLEAN_T        drained, resubmit = FALSE;
    BOOLEAN_T        isCurrent;

    MLOCK(descP->readMtx);

    sockRef   = enif_make_resource(env, descP);
    isCurrent = ((descP->currentAcceptorP != NULL) &&
                 (descP->currentAcceptor.dataP == opP));

    if (opP->closing) {

        /* The caller has already been told; nobody wants it */
        if (res >= 0)
            (void) sock_close(res);

    } else if (opP->cancelled) {

        if (res >= 0) {
            ESUIOStashElem* eP = MALLOC(sizeof(ESUIOStashElem));

            ESOCK_ASSERT( eP != NULL );
            sys_memzero((char*) eP, sizeof(ESUIOStashElem));
            eP->tag = ESUIO_OP_ACCEPT;
            eP->fd  = res;
            esuio_stash_push(descP, eP);
        }
        if (isCurrent)
            esuio_acceptor_done(env, descP, sockRef);

    } else if (res >= 0) {

        esuio_send_completion_msg(opP,
                                  esuio_accept_result(env, descP, sockRef,
                                                      res, opP));
        if (isCurrent)
            esuio_acceptor_done(env, descP, sockRef);

    } else if ((res == -EAGAIN) || (res == -EINTR)) {

        resubmit = TRUE;

    } else {

        ERL_NIF_TERM reason = MKA(env, erl_errno_id(-res));

        ESOCK_CNT_INC(env, descP, sockRef,
                      esock_atom_acc_fails, &descP->accFails, 1);
        esuio_send_completion_msg(opP,
                                  esock_make_error(opP->env,
                                                   CP_TERM(opP->env,
                                                           reason)));
        esuio_acceptor_error(env, descP, sockRef, reason);
    }

    if (resubmit) {
        esuio_submit(opP);
        drained = FALSE;
    } else {
        drained = esuio_op_done(opP, TRUE);
    }

    MUNLOCK(descP->readMtx);

    if (! resubmit) {
        if (drained)
            esuio_maybe_close_done(descP);
        enif_release_resource(descP);
        esuio_op_unref(opP);
    }

    enif_clear_env(env);
}


/* A queued acceptor has been popped (and is now the current acceptor).
 */
extern
BOOLEAN_T esuio_activate_acceptor(ErlNifEnv*       env,
                                  ESockDescriptor* descP,
                                  ERL_NIF_TERM     sockRef)
{
    ESUIOOp* opP = (ESUIOOp*) descP->currentAcceptor.dataP;
    int      accSock;

    ESOCK_CNT_INC(env, descP, sockRef,
                  esock_atom_acc_tries, &descP->accTries, 1);

    if ((accSock = esuio_stash_take_accepted(descP)) >= 0) {
        esuio_send_completion_msg(opP,
                                  esuio_accept_result(env, descP, sockRef,
                                                      accSock, opP));
        (void) DEMONP("esuio_activate_acceptor -> done",
                      env, descP, &descP->currentAcceptor.mon);
        MON_INIT(&descP->currentAcceptor.mon);
        descP->currentAcceptor.dataP = NULL;
        esuio_op_unref(opP);
        return FALSE; // Try the next one
    }

    descP->readState |= ESOCK_STATE_ACCEPTING;
    esuio_op_hand_over(opP);

    return TRUE;
}


extern
ERL_NIF_TERM esuio_cancel_accept(ErlNifEnv*       env,
                                 ESockDescriptor* descP,
                                 ERL_NIF_TERM     sockRef,
                                 ERL_NIF_TERM     opRef)
{
    ErlNifPid self;

    VOID(sockRef);

    if (! IS_OPEN(descP->readState))
        return esock_make_error_closed(env);

    if (descP->currentAcceptorP == NULL)
        return esock_atom_not_found;

    ESOCK_ASSERT( enif_self(env, &self) != NULL );

    if ((COMPARE_PIDS(&self, &descP->currentAcceptor.pid) == 0) &&
        (COMPARE(opRef, descP->currentAcceptor.ref) == 0) &&
        (descP->currentAcceptor.dataP != NULL)) {
        /* Whatever it gets, goes to the stash */
        esuio_cancel_current(env, descP, &descP->currentAcceptor,
                             TRUE, FALSE);
        return esock_atom_ok;
    }

    if (esock_acceptor_unqueue(env, descP, &opRef, &self))
        return esock_atom_ok;

    return esock_atom_not_found;
}



/* ======================================================================== *
 *                                 Connect                                  *
 * ======================================================================== *
 *
 * A stream connect is handed over to io_uring (IORING_OP_CONNECT)
 * directly, and the result (ok | {error, Reason}) is delivered in
 * a completion message (like esaio). A datagram connect is done
 * directly (by essio).
 */

extern
ERL_NIF_TERM esuio_connect(ErlNifEnv*       env,
                           ESockDescriptor* descP,
                           ERL_NIF_TERM     sockRef,
                           ERL_NIF_TERM     connRef,
                           ESockAddress*    addrP,
                           SOCKLEN_T        addrLen)
{
    ErlNifPid self;
    ESUIOOp*  opP;

    if ((descP->type != SOCK_STREAM) && (descP->type != SOCK_SEQPACKET))
        return essio_connect(env, descP, sockRef, connRef, addrP, addrLen);

    ESOCK_ASSERT( enif_self(env, &self) != NULL );

    if (! IS_OPEN(descP->writeState))
        return esock_make_error_closed(env);

    /* Connect and Write can not be simultaneous */
    if (descP->currentWriterP != NULL)
        return esock_make_error_invalid(env, esock_atom_state);

    if (descP->connectorP != NULL) {
        /* Connect in progress (the result comes in a completion msg) */
        if (addrP != NULL)
            return esock_make_error(env, esock_atom_already);
        return esock_raise_invalid(env, esock_atom_state);
    }

    /* A connect without an address (to finalize a connect after a
     * select message) is not used with a completion backend */
    if (addrP == NULL)
        return esock_raise_invalid(env, esock_atom_state);

    opP = esuio_op_alloc(env, descP, ESUIO_OP_CONNECT, sockRef, connRef);
    opP->data.connect.addr    = *addrP;
    opP->data.connect.addrLen = addrLen;

    descP->connector.pid = self;
    ESOCK_ASSERT( MONP("esuio_connect -> conn",
                       env, descP,
                       &self, &descP->connector.mon) == 0 );
    descP->connector.env   = esock_alloc_env("connector");
    descP->connector.ref   = CP_TERM(descP->connector.env, connRef);
    descP->connector.dataP = opP;
    descP->connectorP      = &descP->connector;
    descP->writeState     |= ESOCK_STATE_CONNECTING;

    esuio_op_hand_over(opP);

    return esock_atom_completion;
}


/* The connector is done.
 */
static
void esuio_connector_done(ErlNifEnv*       env,
                          ESockDescriptor* descP)
{
    if (descP->connectorP == NULL)
        return;

    descP->connector.dataP = NULL;
    esock_requestor_release("esuio_connector_done",
                            env, descP, &descP->connector);
    descP->connectorP  = NULL;
    descP->writeState &= ~ESOCK_STATE_CONNECTING;
}


/* The CQE of a connect operation.
 */
static
void esuio_complete_connect(ESUIOOp* opP, int res)
{
    ESockDescriptor* descP = opP->descP;
    ErlNifEnv*       env   = esuio_self_ring->env;
    BOOLEAN_T        drained, isCurrent;

    MLOCK(descP->writeMtx);

    isCurrent = ((descP->connectorP != NULL) &&
                 (descP->connector.dataP == opP));

    if (res == 0)
        descP->writeState |= ESOCK_STATE_CONNECTED;

    if (opP->closing) {

        /* The caller has already been told */

    } else if (opP->cancelled) {

        if (isCurrent)
            esuio_connector_done(env, descP);

    } else {

        if (res == 0) {
            esuio_send_completion_msg(opP, esock_atom_ok);
        } else {
            esuio_send_completion_msg(opP,
                                      esock_make_error(opP->env,
                                                       MKA(opP->env,
                                                           erl_errno_id(-res))));
        }
        if (isCurrent)
            esuio_connector_done(env, descP);
    }

    drained = esuio_op_done(opP, FALSE);

    MUNLOCK(descP->writeMtx);

    if (drained)
        esuio_maybe_close_done(descP);
    enif_release_resource(descP);
    esuio_op_unref(opP);

    enif_clear_env(env);
}


extern
ERL_NIF_TERM esuio_cancel_connect(ErlNifEnv*       env,
                                  ESockDescriptor* descP,
                                  ERL_NIF_TERM     opRef)
{
    ErlNifPid self;

    if ((descP->connectorP == NULL) ||
        (descP->connector.dataP == NULL))
        return essio_cancel_connect(env, descP, opRef);

    if (! IS_OPEN(descP->writeState))
        return esock_make_error_closed(env);

    ESOCK_ASSERT( enif_self(env, &self) != NULL );

    if ((COMPARE_PIDS(&self, &descP->connector.pid) != 0) ||
        (COMPARE(opRef, descP->connector.ref) != 0))
        return esock_atom_not_found;

    /* The connector remains until the CQE has been processed */
    esuio_cancel_current(env, descP, &descP->connector, FALSE, FALSE);

    return esock_atom_ok;
}



/* ======================================================================== *
 *                                  Cancel                                  *
 * ======================================================================== *
 */

/* Cancel the current (in the ring) operation of the caller.
 * The operation keeps the direction until its CQE has been processed.
 */
static
void esuio_cancel_current(ErlNifEnv*       env,
                          ESockDescriptor* descP,
                          ESockRequestor*  reqP,
                          BOOLEAN_T        isRead,
                          BOOLEAN_T        report)
{
    ESUIOOp* opP = (ESUIOOp*) reqP->dataP;

    opP->cancelled    = TRUE;
    opP->reportCancel = report;
    if (! report)
        enif_set_pid_undefined(&opP->caller);

    (void) DEMONP("esuio_cancel_current", env, descP, &reqP->mon);
    /* So that no one (not even the caller) is taken for the requestor */
    enif_set_pid_undefined(&reqP->pid);

    esuio_cancel_op(opP, isRead);
}


extern
ERL_NIF_TERM esuio_cancel_recv(ErlNifEnv*       env,
                               ESockDescriptor* descP,
                               ERL_NIF_TERM     sockRef,
                               ERL_NIF_TERM     opRef)
{
    ErlNifPid self;

    if (! IS_OPEN(descP->readState))
        return esock_make_error_closed(env);

    if (descP->currentReaderP == NULL)
        return esock_atom_not_found;

    ESOCK_ASSERT( enif_self(env, &self) != NULL );

    if ((COMPARE_PIDS(&self, &descP->currentReader.pid) == 0) &&
        (COMPARE(opRef, descP->currentReader.ref) == 0)) {

        if (descP->currentReader.dataP != NULL) {
            /* Whatever it gets, goes to the stash */
            esuio_cancel_current(env, descP, &descP->currentReader,
                                 TRUE, FALSE);
        } else {
            esuio_reader_done(env, descP, sockRef);
        }
        return esock_atom_ok;
    }

    if (esock_reader_unqueue(env, descP, &opRef, &self))
        return esock_atom_ok;

    return esock_atom_not_found;
}


/* Note that if the current operation (in the ring) is cancelled,
 * we return 'completion', which means that the caller will get
 * one final message; either a completion message (the operation
 * completed), or an abort message with {cancelled, Written}.
 */
extern
ERL_NIF_TERM esuio_cancel_send(ErlNifEnv*       env,
                               ESockDescriptor* descP,
                               ERL_NIF_TERM     sockRef,
                               ERL_NIF_TERM     opRef)
{
    ErlNifPid self;

    if (! IS_OPEN(descP->writeState))
        return esock_make_error_closed(env);

    if (descP->currentWriterP == NULL)
        return esock_atom_not_found;

    ESOCK_ASSERT( enif_self(env, &self) != NULL );

    if ((COMPARE_PIDS(&self, &descP->currentWriter.pid) == 0) &&
        (COMPARE(opRef, descP->currentWriter.ref) == 0)) {

        if (descP->currentWriter.dataP != NULL) {
            ESUIOOp* opP = (ESUIOOp*) descP->currentWriter.dataP;

            if (opP->tag == ESUIO_OP_SENDMMSG) {
                /* Only waiting (poll), nothing has been sent */
                esuio_cancel_current(env, descP, &descP->currentWriter,
                                     FALSE, FALSE);
                return esock_atom_ok;
            }
            esuio_cancel_current(env, descP, &descP->currentWriter,
                                 FALSE, TRUE);
            return esock_atom_completion;
        } else {
            esuio_writer_done(env, descP, sockRef);
            return esock_atom_ok;
        }
    }

    if (esock_writer_unqueue(env, descP, &opRef, &self))
        return esock_atom_ok;

    return esock_atom_not_found;
}



/* ======================================================================== *
 *                         Close, stop, down and dtor                       *
 * ======================================================================== *
 */

/* The current requestor (with an operation in the ring) when the
 * socket is closed (or the owner dies):
 * The caller is told (closed) now, and the operation is cancelled
 * (by esuio_cancel_all).
 * An operation that has already been cancelled (by the caller) is
 * left alone (its caller may be waiting for its final message).
 */
static
void esuio_stop_current_op(ErlNifEnv*       env,
                           ESockDescriptor* descP,
                           ESockRequestor*  reqP)
{
    ESUIOOp* opP = (ESUIOOp*) reqP->dataP;

    if (! opP->cancelled) {
        opP->closing = TRUE;
        esuio_send_abort_msg(opP, esock_atom_closed);
    }
    reqP->dataP = NULL;
    esock_requestor_release("esuio_stop_current_op", env, descP, reqP);
}


/* Prepare for close - return whether we have to wait (for the select
 * stop and/or the operations in the ring) or not.
 * Both mutexes are held.
 */
static
BOOLEAN_T esuio_do_stop(ErlNifEnv*       env,
                        ESockDescriptor* descP)
{
    BOOLEAN_T    wait = FALSE;
    int          sres = 0;
    ERL_NIF_TERM sockRef;

    sockRef = enif_make_resource(env, descP);

    /* Operations that are still select:ed (accept, connect, sendfile) */
    if (IS_SELECTED(descP)) {
        ESOCK_ASSERT( (sres = esock_select_stop(env,
                                                (ErlNifEvent) descP->sock,
                                                descP)) >= 0 );
        if ((sres & ERL_NIF_SELECT_STOP_SCHEDULED) != 0) {
            descP->uringStopPending = TRUE;
            wait                    = TRUE;
        }
    }

    /* +++++++ Current and waiting Writers +++++++ */

    if (descP->currentWriterP != NULL) {
        if (descP->currentWriter.dataP != NULL) {
            esuio_stop_current_op(env, descP, &descP->currentWriter);
        } else if ((sres & ERL_NIF_SELECT_WRITE_CANCELLED) != 0) {
            esock_stop_handle_current(env, "writer",
                                      descP, sockRef, &descP->currentWriter);
        }
        esock_inform_waiting_procs(env, "writer",
                                   descP, sockRef, &descP->writersQ,
                                   esock_atom_closed);
        descP->currentWriterP = NULL;
    }

    /* +++++++ Connector +++++++ */

    if (descP->connectorP != NULL) {
        if (descP->connector.dataP != NULL) {
            esuio_stop_current_op(env, descP, &descP->connector);
        } else if ((sres & ERL_NIF_SELECT_WRITE_CANCELLED) != 0) {
            esock_stop_handle_current(env, "connector",
                                      descP, sockRef, &descP->connector);
        }
        descP->connectorP = NULL;
    }

    /* +++++++ Current and waiting Readers +++++++ */

    if (descP->currentReaderP != NULL) {
        if (descP->currentReader.dataP != NULL) {
            esuio_stop_current_op(env, descP, &descP->currentReader);
        } else if ((sres & ERL_NIF_SELECT_READ_CANCELLED) != 0) {
            esock_stop_handle_current(env, "reader",
                                      descP, sockRef, &descP->currentReader);
        }
        esock_inform_waiting_procs(env, "reader",
                                   descP, sockRef, &descP->readersQ,
                                   esock_atom_closed);
        descP->currentReaderP = NULL;
    }

    /* +++++++ Current and waiting Acceptors +++++++ */

    if (descP->currentAcceptorP != NULL) {
        if (descP->currentAcceptor.dataP != NULL) {
            esuio_stop_current_op(env, descP, &descP->currentAcceptor);
        } else if ((sres & ERL_NIF_SELECT_READ_CANCELLED) != 0) {
            esock_stop_handle_current(env, "acceptor",
                                      descP, sockRef,
                                      &descP->currentAcceptor);
        }
        esock_inform_waiting_procs(env, "acceptor",
                                   descP, sockRef, &descP->acceptorsQ,
                                   esock_atom_closed);
        descP->currentAcceptorP = NULL;
    }

    /* +++++++ Operations in the ring +++++++ */

    if ((descP->uringReadOps + descP->uringWriteOps) > 0) {
        esuio_cancel_all(descP);
        wait = TRUE;
    }

    return wait;
}


extern
ERL_NIF_TERM esuio_close(ErlNifEnv*       env,
                         ESockDescriptor* descP)
{
    if (! IS_OPEN(descP->readState))
        return esock_make_error_closed(env);

    /* Store the PID of the caller,
     * since we need to inform it when we are done.
     */
    ESOCK_ASSERT( enif_self(env, &descP->closerPid) != NULL );

    /* If the caller is not the owner; monitor the caller,
     * since we should complete this operation even if the caller dies.
     */
    if (COMPARE_PIDS(&descP->closerPid, &descP->ctrlPid) != 0) {
        ESOCK_ASSERT( MONP("esuio_close-check -> closer",
                           env, descP,
                           &descP->closerPid,
                           &descP->closerMon) == 0 );
    }

    descP->readState  |= ESOCK_STATE_CLOSING;
    descP->writeState |= ESOCK_STATE_CLOSING;

    if (esuio_do_stop(env, descP)) {
        /* We have to wait (the close msg will be sent) */
        descP->closeEnv = esock_alloc_env("esuio_close - close-env");
        descP->closeRef = MKREF(descP->closeEnv);

        return esock_make_ok2(env, CP_TERM(env, descP->closeRef));
    } else {
        return esock_atom_ok;
    }
}


extern
ERL_NIF_TERM esuio_fin_close(ErlNifEnv*       env,
                             ESockDescriptor* descP)
{
    if (IS_CLOSING(descP->readState) &&
        (! IS_CLOSED(descP->readState)) &&
        (descP->closeEnv != NULL) &&
        (descP->uringStopPending ||
         ((descP->uringReadOps + descP->uringWriteOps) > 0))) {
        /* We are not done yet */
        return esock_raise_invalid(env, esock_atom_state);
    }

    return essio_fin_close(env, descP);
}


/* Everything is stopped (the select machinery and the ring).
 * Both mutexes are held.
 * Inform the closer, or do an unclean close (like essio_stop).
 */
static
void esuio_close_done(ErlNifEnv* env, ESockDescriptor* descP)
{
    if (! enif_is_pid_undefined(&descP->closerPid)) {

        if (descP->closeEnv != NULL) {
            /* Send message to trigger nif_finalize_close() */
            esock_send_close_msg(env, descP, &descP->closerPid);
            /* Message send frees closeEnv */
            descP->closeEnv = NULL;
            descP->closeRef = esock_atom_undefined;
        }

    } else if (descP->sock != INVALID_SOCKET) {
        int err;

        /* We do not have a closer process
         * - have to do an unclean (non blocking) close */

#ifdef HAVE_SENDFILE
        if (descP->sendfileHandle != INVALID_HANDLE)
            esock_send_sendfile_deferred_close_msg(env, descP);
#endif

        err = esock_close_socket(env, descP, FALSE);

        if (err != 0)
            esock_warning_msg("[UNIX-ESUIO] Failed closing socket without "
                              "closer process: "
                              "\r\n   Controlling Process: %T"
                              "\r\n   Descriptor:          %d"
                              "\r\n   Errno:               %d (%T)"
                              "\r\n",
                              descP->ctrlPid, descP->sock,
                              err, MKA(env, erl_errno_id(err)));
    }
}


/* A direction has been drained (while closing).
 * Called (from the ring thread) without holding any mutex.
 */
static
void esuio_maybe_close_done(ESockDescriptor* descP)
{
    ErlNifEnv* env = esuio_self_ring->env;

    MLOCK(descP->readMtx);
    MLOCK(descP->writeMtx);

    if (IS_CLOSING(descP->readState) &&
        (! IS_CLOSED(descP->readState)) &&
        (descP->uringReadOps == 0) &&
        (descP->uringWriteOps == 0) &&
        (! descP->uringStopPending))
        esuio_close_done(env, descP);

    MUNLOCK(descP->writeMtx);
    MUNLOCK(descP->readMtx);
}


/* The select machinery is done with the socket (both mutexes are held).
 */
extern
void esuio_stop(ErlNifEnv*       env,
                ESockDescriptor* descP)
{
    descP->uringStopPending = FALSE;

    if ((descP->uringReadOps + descP->uringWriteOps) == 0)
        esuio_close_done(env, descP);
    /* else: when the ring is drained (esuio_maybe_close_done) */
}


extern
void esuio_down_ctrl(ErlNifEnv*       env,
                     ESockDescriptor* descP,
                     const ErlNifPid* pidP)
{
    VOID(pidP);

    if (! esuio_do_stop(env, descP)) {
        /* Not waiting for anything
         * - we have to do an unclean (non blocking) socket close here */
        esuio_close_done(env, descP);
    }
}


/* A 'down' has occurred (both mutexes are held).
 */
extern
void esuio_down(ErlNifEnv*           env,
                ESockDescriptor*     descP,
                const ErlNifPid*     pidP,
                const ErlNifMonitor* monP)
{
    if (COMPARE_PIDS(&descP->closerPid, pidP) == 0) {

        /* The closer process went down
         * - it will not call nif_finalize_close
         */

        enif_set_pid_undefined(&descP->closerPid);

        if (MON_EQ(&descP->closerMon, monP)) {
            MON_INIT(&descP->closerMon);
        } else {
            // The owner is the closer so we used its monitor
            ESOCK_ASSERT( MON_EQ(&descP->ctrlMon, monP) );
            MON_INIT(&descP->ctrlMon);
            enif_set_pid_undefined(&descP->ctrlPid);
        }

        if (descP->closeEnv == NULL) {
            /* Nothing to wait for (or we are done waiting)
             * - unclean (non blocking) close */
            esuio_close_done(env, descP);
        } else {
            /* We are waiting - esuio_close_done will close it */
            esock_clear_env("esuio_down - close-env", descP->closeEnv);
            esock_free_env("esuio_down - close-env", descP->closeEnv);
            descP->closeEnv = NULL;
            descP->closeRef = esock_atom_undefined;
        }

    } else if (MON_EQ(&descP->ctrlMon, monP)) {

        MON_INIT(&descP->ctrlMon);
        /* The owner went down */
        enif_set_pid_undefined(&descP->ctrlPid);

        if (IS_OPEN(descP->readState)) {
            descP->readState  |= ESOCK_STATE_CLOSING;
            descP->writeState |= ESOCK_STATE_CLOSING;
            esuio_down_ctrl(env, descP, pidP);
        }

    } else if ((descP->currentReaderP != NULL) &&
               (descP->currentReader.dataP != NULL) &&
               MON_EQ(&descP->currentReader.mon, monP)) {

        /* The current reader (with an operation in the ring) died;
         * whatever the operation gets goes to the stash */
        MON_INIT(&descP->currentReader.mon);
        esuio_cancel_current(env, descP, &descP->currentReader,
                             TRUE, FALSE);

    } else if ((descP->currentWriterP != NULL) &&
               (descP->currentWriter.dataP != NULL) &&
               MON_EQ(&descP->currentWriter.mon, monP)) {

        MON_INIT(&descP->currentWriter.mon);
        esuio_cancel_current(env, descP, &descP->currentWriter,
                             FALSE, FALSE);

    } else if ((descP->currentAcceptorP != NULL) &&
               (descP->currentAcceptor.dataP != NULL) &&
               MON_EQ(&descP->currentAcceptor.mon, monP)) {

        /* An accepted connection goes to the stash */
        MON_INIT(&descP->currentAcceptor.mon);
        esuio_cancel_current(env, descP, &descP->currentAcceptor,
                             TRUE, FALSE);

    } else if ((descP->connectorP != NULL) &&
               (descP->connector.dataP != NULL) &&
               MON_EQ(&descP->connector.mon, monP)) {

        /* Forget about the connect (we may end up connected) */
        MON_INIT(&descP->connector.mon);
        esuio_cancel_current(env, descP, &descP->connector,
                             FALSE, FALSE);

    } else {

        /* The connector, a current requestor without an operation
         * (in the ring), or a waiting requestor */
        essio_down(env, descP, pidP, monP);
    }
}


extern
void esuio_dtor(ErlNifEnv*       env,
                ESockDescriptor* descP)
{
    /* The operations in the ring keep the socket (resource) alive */
    ESOCK_ASSERT( descP->uringReadOps  == 0 );
    ESOCK_ASSERT( descP->uringWriteOps == 0 );

    esuio_stash_free(descP);

    essio_dtor(env, descP);
}

#endif // ESOCK_HAVE_IO_URING
#endif // ESOCK_ENABLE
