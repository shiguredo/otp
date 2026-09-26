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
 * A ring is owned by *one* thread (it is created with
 * IORING_SETUP_SINGLE_ISSUER), and that thread is the only one
 * that may get SQEs, submit, and reap CQEs. Nothing in here is
 * thread safe.
 *
 */

#ifndef SOCKET_URING_H__
#define SOCKET_URING_H__

#ifdef ESOCK_HAVE_IO_URING

#include <linux/io_uring.h>

typedef struct {
    int                  fd;
    unsigned int         features;
    unsigned int         setupFlags;

    /* Submission queue */
    unsigned int         sqEntries;
    unsigned int*        sqHead;
    unsigned int*        sqTail;
    unsigned int*        sqMask;
    unsigned int*        sqArray;
    struct io_uring_sqe* sqes;
    unsigned int         sqLocalTail; /* Not yet published to the kernel */

    /* Completion queue */
    unsigned int         cqEntries;
    unsigned int*        cqHead;
    unsigned int*        cqTail;
    unsigned int*        cqMask;
    struct io_uring_cqe* cqes;

    /* Mappings (for cleanup) */
    void*                ringP;
    size_t               ringSz;
    void*                sqesP;
    size_t               sqesSz;
} ESockUring;


/* Create a ring. Returns 0 or -errno. */
extern int esock_uring_init(ESockUring*  ringP,
                            unsigned int sqEntries,
                            unsigned int cqEntries,
                            unsigned int flags);
extern void esock_uring_exit(ESockUring* ringP);

/* Check that every opcode in ops is supported.
 * Returns 0, -ENOTSUP (and *missingP) or -errno. */
extern int esock_uring_probe(ESockUring* ringP,
                             const int*  ops,
                             int         nOps,
                             int*        missingP);

/* Get a (zeroed) SQE, or NULL if the submission queue is full. */
extern struct io_uring_sqe* esock_uring_get_sqe(ESockUring* ringP);
extern unsigned int esock_uring_sq_space(ESockUring* ringP);

/* Publish all SQEs gotten so far, submit them and (if waitNr > 0)
 * wait for at least waitNr CQEs.
 * Returns the number of submitted SQEs or -errno.
 * -EINTR and -ETIME are returned as is (the caller decides). */
extern int esock_uring_submit_and_wait(ESockUring*  ringP,
                                       unsigned int waitNr);

/* Get the next CQE (without consuming it), or NULL if there is none. */
extern struct io_uring_cqe* esock_uring_peek_cqe(ESockUring* ringP);
/* Consume n CQEs. */
extern void esock_uring_cq_advance(ESockUring* ringP, unsigned int n);

#endif // ESOCK_HAVE_IO_URING

#endif // SOCKET_URING_H__
