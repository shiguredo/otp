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
 *  Purpose : A minimal io_uring ring (raw system calls, no liburing).
 * ----------------------------------------------------------------------
 *
 * Memory ordering (see io_uring(7)):
 *   - The kernel reads the SQ tail, so we publish it with a store-release
 *     (after the SQEs have been written).
 *   - The kernel writes the SQ head, so we read it with a load-acquire.
 *   - The kernel writes the CQ tail, so we read it with a load-acquire
 *     (before reading the CQEs).
 *   - The kernel reads the CQ head, so we publish it with a store-release
 *     (after we are done with the CQEs).
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef ESOCK_HAVE_IO_URING

#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "socket_uring.h"


#define URING_LOAD_ACQ(P)     __atomic_load_n((P), __ATOMIC_ACQUIRE)
#define URING_STORE_REL(P, V) __atomic_store_n((P), (V), __ATOMIC_RELEASE)


static int uring_setup(unsigned int entries, struct io_uring_params* p)
{
    return (int) syscall(__NR_io_uring_setup, entries, p);
}

static int uring_enter(int          fd,
                       unsigned int toSubmit,
                       unsigned int minComplete,
                       unsigned int flags)
{
    return (int) syscall(__NR_io_uring_enter,
                         fd, toSubmit, minComplete, flags, NULL, 0);
}

static int uring_register(int fd, unsigned int op, void* arg, unsigned int n)
{
    return (int) syscall(__NR_io_uring_register, fd, op, arg, n);
}


extern
int esock_uring_init(ESockUring*  ringP,
                     unsigned int sqEntries,
                     unsigned int cqEntries,
                     unsigned int flags)
{
    struct io_uring_params p;
    size_t                 sqSz, cqSz;
    char*                  ring;
    void*                  sqes;
    int                    fd;

    memset(ringP, 0, sizeof(ESockUring));
    ringP->fd = -1;

    memset(&p, 0, sizeof(p));
    p.flags = flags;
    if (cqEntries > 0) {
        p.flags       |= IORING_SETUP_CQSIZE;
        p.cq_entries   = cqEntries;
    }

    if ((fd = uring_setup(sqEntries, &p)) < 0)
        return -errno;

    /* We only support kernels that map the SQ and CQ rings together
     * (5.4 and later). This is always true for the kernels we
     * otherwise require (SINGLE_ISSUER is 6.0). */
    if (! (p.features & IORING_FEAT_SINGLE_MMAP)) {
        (void) close(fd);
        return -ENOTSUP;
    }

    sqSz = p.sq_off.array + p.sq_entries * sizeof(unsigned int);
    cqSz = p.cq_off.cqes  + p.cq_entries * sizeof(struct io_uring_cqe);
    ringP->ringSz = (sqSz > cqSz) ? sqSz : cqSz;

    ring = mmap(NULL, ringP->ringSz,
                PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                fd, IORING_OFF_SQ_RING);
    if (ring == MAP_FAILED) {
        int save_errno = errno;
        (void) close(fd);
        return -save_errno;
    }

    ringP->sqesSz = p.sq_entries * sizeof(struct io_uring_sqe);
    sqes = mmap(NULL, ringP->sqesSz,
                PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                fd, IORING_OFF_SQES);
    if (sqes == MAP_FAILED) {
        int save_errno = errno;
        (void) munmap(ring, ringP->ringSz);
        (void) close(fd);
        return -save_errno;
    }

    ringP->sqesP      = sqes;
    ringP->fd         = fd;
    ringP->features   = p.features;
    ringP->setupFlags = p.flags;
    ringP->ringP      = ring;

    ringP->sqEntries  = p.sq_entries;
    ringP->sqHead     = (unsigned int*) (ring + p.sq_off.head);
    ringP->sqTail     = (unsigned int*) (ring + p.sq_off.tail);
    ringP->sqMask     = (unsigned int*) (ring + p.sq_off.ring_mask);
    ringP->sqArray    = (unsigned int*) (ring + p.sq_off.array);
    ringP->sqes       = (struct io_uring_sqe*) ringP->sqesP;
    ringP->sqLocalTail = *ringP->sqTail;

    ringP->cqEntries  = p.cq_entries;
    ringP->cqHead     = (unsigned int*) (ring + p.cq_off.head);
    ringP->cqTail     = (unsigned int*) (ring + p.cq_off.tail);
    ringP->cqMask     = (unsigned int*) (ring + p.cq_off.ring_mask);
    ringP->cqes       = (struct io_uring_cqe*) (ring + p.cq_off.cqes);

    return 0;
}


extern
void esock_uring_exit(ESockUring* ringP)
{
    if (ringP->sqesP != NULL) {
        (void) munmap(ringP->sqesP, ringP->sqesSz);
        ringP->sqesP = NULL;
    }
    if (ringP->ringP != NULL) {
        (void) munmap(ringP->ringP, ringP->ringSz);
        ringP->ringP = NULL;
    }
    if (ringP->fd >= 0) {
        (void) close(ringP->fd);
        ringP->fd = -1;
    }
}


extern
int esock_uring_probe(ESockUring* ringP,
                      const int*  ops,
                      int         nOps,
                      int*        missingP)
{
    const unsigned int       max = 256;
    struct io_uring_probe*   probeP;
    size_t                   sz;
    int                      i, res = 0;

    sz     = sizeof(struct io_uring_probe) +
        max * sizeof(struct io_uring_probe_op);
    if ((probeP = calloc(1, sz)) == NULL)
        return -ENOMEM;

    if (uring_register(ringP->fd, IORING_REGISTER_PROBE, probeP, max) < 0) {
        res = -errno;
    } else {
        for (i = 0; i < nOps; i++) {
            if ((ops[i] > probeP->last_op) ||
                ! (probeP->ops[ops[i]].flags & IO_URING_OP_SUPPORTED)) {
                *missingP = ops[i];
                res       = -ENOTSUP;
                break;
            }
        }
    }

    free(probeP);

    return res;
}


extern
unsigned int esock_uring_sq_space(ESockUring* ringP)
{
    unsigned int head = URING_LOAD_ACQ(ringP->sqHead);

    return ringP->sqEntries - (ringP->sqLocalTail - head);
}


extern
struct io_uring_sqe* esock_uring_get_sqe(ESockUring* ringP)
{
    struct io_uring_sqe* sqeP;
    unsigned int         idx;

    if (esock_uring_sq_space(ringP) == 0)
        return NULL;

    idx  = ringP->sqLocalTail & *ringP->sqMask;
    sqeP = &ringP->sqes[idx];
    memset(sqeP, 0, sizeof(struct io_uring_sqe));
    ringP->sqArray[idx] = idx;
    ringP->sqLocalTail++;

    return sqeP;
}


extern
int esock_uring_submit_and_wait(ESockUring*  ringP,
                                unsigned int waitNr)
{
    unsigned int toSubmit = ringP->sqLocalTail - *ringP->sqTail;
    unsigned int flags    = 0;
    int          res;

    if (toSubmit > 0)
        URING_STORE_REL(ringP->sqTail, ringP->sqLocalTail);

    /* With IORING_SETUP_DEFER_TASKRUN, pending task work (which is
     * where our socket operations actually complete) is only run when
     * we ask for events, so we always do that when we wait. */
    if (waitNr > 0)
        flags |= IORING_ENTER_GETEVENTS;

    if ((toSubmit == 0) && (waitNr == 0))
        return 0;

    res = uring_enter(ringP->fd, toSubmit, waitNr, flags);
    if (res < 0)
        return -errno;

    return res;
}


extern
struct io_uring_cqe* esock_uring_peek_cqe(ESockUring* ringP)
{
    unsigned int head = *ringP->cqHead;
    unsigned int tail = URING_LOAD_ACQ(ringP->cqTail);

    if (head == tail)
        return NULL;

    return &ringP->cqes[head & *ringP->cqMask];
}


extern
void esock_uring_cq_advance(ESockUring* ringP, unsigned int n)
{
    if (n > 0)
        URING_STORE_REL(ringP->cqHead, *ringP->cqHead + n);
}

#endif // ESOCK_HAVE_IO_URING
