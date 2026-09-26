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
 * This backend is the unix (essio) backend where the operations that
 * would block are handed over to io_uring instead of being select:ed.
 * The result is then delivered to the caller in a completion message,
 * exactly like the Windows (esaio) backend.
 *
 */

#ifndef SOCKET_URINGIO_H__
#define SOCKET_URINGIO_H__

#ifdef ESOCK_HAVE_IO_URING

#include "socket_io.h"

extern int  esuio_init(unsigned int     numThreads,
                       const ESockData* dataP);
extern void esuio_finish(void);
extern ERL_NIF_TERM esuio_info(ErlNifEnv* env);

extern ERL_NIF_TERM esuio_connect(ErlNifEnv*       env,
                                  ESockDescriptor* descP,
                                  ERL_NIF_TERM     sockRef,
                                  ERL_NIF_TERM     connRef,
                                  ESockAddress*    addrP,
                                  SOCKLEN_T        addrLen);
extern ERL_NIF_TERM esuio_accept(ErlNifEnv*       env,
                                 ESockDescriptor* descP,
                                 ERL_NIF_TERM     sockRef,
                                 ERL_NIF_TERM     accRef);

extern ERL_NIF_TERM esuio_send(ErlNifEnv*       env,
                               ESockDescriptor* descP,
                               ERL_NIF_TERM     sockRef,
                               ERL_NIF_TERM     sendRef,
                               ErlNifBinary*    sndDataP,
                               ERL_NIF_TERM     eData,
                               int              flags);
extern ERL_NIF_TERM esuio_sendto(ErlNifEnv*       env,
                                 ESockDescriptor* descP,
                                 ERL_NIF_TERM     sockRef,
                                 ERL_NIF_TERM     sendRef,
                                 ErlNifBinary*    dataP,
                                 ERL_NIF_TERM     eData,
                                 int              flags,
                                 ESockAddress*    toAddrP,
                                 SOCKLEN_T        toAddrLen);
extern ERL_NIF_TERM esuio_sendmsg(ErlNifEnv*       env,
                                  ESockDescriptor* descP,
                                  ERL_NIF_TERM     sockRef,
                                  ERL_NIF_TERM     sendRef,
                                  ERL_NIF_TERM     eMsg,
                                  int              flags,
                                  ERL_NIF_TERM     eIOV,
                                  const ESockData* dataP);
extern ERL_NIF_TERM esuio_sendmmsg(ErlNifEnv*       env,
                                   ESockDescriptor* descP,
                                   ERL_NIF_TERM     sockRef,
                                   ERL_NIF_TERM     sendRef,
                                   ERL_NIF_TERM     eMsgs,
                                   int              flags,
                                   const ESockData* dataP);
extern ERL_NIF_TERM esuio_sendv(ErlNifEnv*       env,
                                ESockDescriptor* descP,
                                ERL_NIF_TERM     sockRef,
                                ERL_NIF_TERM     sendRef,
                                ERL_NIF_TERM     eIOV,
                                const ESockData* dataP);

extern ERL_NIF_TERM esuio_recv(ErlNifEnv*       env,
                               ESockDescriptor* descP,
                               ERL_NIF_TERM     sockRef,
                               ERL_NIF_TERM     recvRef,
                               ssize_t          len,
                               int              flags);
extern ERL_NIF_TERM esuio_recvfrom(ErlNifEnv*       env,
                                   ESockDescriptor* descP,
                                   ERL_NIF_TERM     sockRef,
                                   ERL_NIF_TERM     recvRef,
                                   ssize_t          len,
                                   int              flags);
extern ERL_NIF_TERM esuio_recvmsg(ErlNifEnv*       env,
                                  ESockDescriptor* descP,
                                  ERL_NIF_TERM     sockRef,
                                  ERL_NIF_TERM     recvRef,
                                  ssize_t          bufLen,
                                  ssize_t          ctrlLen,
                                  int              flags);
extern ERL_NIF_TERM esuio_recvmmsg(ErlNifEnv*       env,
                                   ESockDescriptor* descP,
                                   ERL_NIF_TERM     sockRef,
                                   ERL_NIF_TERM     recvRef,
                                   unsigned int     vlen,
                                   ssize_t          bufLen,
                                   ssize_t          ctrlLen,
                                   int              flags);

extern ERL_NIF_TERM esuio_close(ErlNifEnv*       env,
                                ESockDescriptor* descP);
extern ERL_NIF_TERM esuio_fin_close(ErlNifEnv*       env,
                                    ESockDescriptor* descP);

extern ERL_NIF_TERM esuio_cancel_connect(ErlNifEnv*       env,
                                         ESockDescriptor* descP,
                                         ERL_NIF_TERM     opRef);
extern ERL_NIF_TERM esuio_cancel_accept(ErlNifEnv*       env,
                                        ESockDescriptor* descP,
                                        ERL_NIF_TERM     sockRef,
                                        ERL_NIF_TERM     opRef);
extern ERL_NIF_TERM esuio_cancel_send(ErlNifEnv*       env,
                                      ESockDescriptor* descP,
                                      ERL_NIF_TERM     sockRef,
                                      ERL_NIF_TERM     opRef);
extern ERL_NIF_TERM esuio_cancel_recv(ErlNifEnv*       env,
                                      ESockDescriptor* descP,
                                      ERL_NIF_TERM     sockRef,
                                      ERL_NIF_TERM     opRef);

extern void esuio_dtor(ErlNifEnv*       env,
                       ESockDescriptor* descP);
extern void esuio_stop(ErlNifEnv*       env,
                       ESockDescriptor* descP);
extern void esuio_down(ErlNifEnv*           env,
                       ESockDescriptor*     descP,
                       const ErlNifPid*     pidP,
                       const ErlNifMonitor* monP);
extern void esuio_down_ctrl(ErlNifEnv*       env,
                            ESockDescriptor* descP,
                            const ErlNifPid* pidP);


/* Called (by esock_activate_next_[acceptor|writer|reader]) when a
 * queued requestor, that has an esuio operation, has been popped
 * (and made the current requestor).
 * Returns TRUE if the operation is now in progress, and FALSE if it
 * is already done (in which case the next requestor should be tried).
 */
extern BOOLEAN_T esuio_activate_acceptor(ErlNifEnv*       env,
                                         ESockDescriptor* descP,
                                         ERL_NIF_TERM     sockRef);
extern BOOLEAN_T esuio_activate_writer(ErlNifEnv*       env,
                                       ESockDescriptor* descP,
                                       ERL_NIF_TERM     sockRef);
extern BOOLEAN_T esuio_activate_reader(ErlNifEnv*       env,
                                       ESockDescriptor* descP,
                                       ERL_NIF_TERM     sockRef);

/* A requestor queued with an esuio operation is thrown away. */
extern void esuio_free_queued_op(void* opP);

#endif // ESOCK_HAVE_IO_URING

#endif // SOCKET_URINGIO_H__
