/* Copyright (c) 2014, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef UTIL_H_
#define UTIL_H_

#include "dns_private.h"

/**
 * Make a universal socket
 * @param credits host, ip or path to unix socket
 * @param port port (used for network sockets)
 * @param type of socket (SOCK_STREAM or SOCK_DGRAM)
 */
int
rdns_make_client_socket (const char *credits,
						 uint16_t port,
						 int type,
						 struct sockaddr **psockaddr,
						 socklen_t *psocklen);

/**
 * Generate new random DNS id
 * @return dns id
 */
uint16_t rdns_permutor_generate_id (void);


/**
 * Free IO channel
 */
void rdns_ioc_free (struct rdns_io_channel *ioc);

/**
 * Creates a new IO channel
 */
struct rdns_io_channel * rdns_ioc_new (struct rdns_server *srv,
									   struct rdns_resolver *resolver,
									   bool is_tcp);

/**
 * Resets inactive/errored TCP chain as recommended by RFC
 * @param ioc
 */
void rdns_ioc_tcp_reset (struct rdns_io_channel *ioc);

/**
 * Connect TCP IO channel to a server
 * @param ioc
 */
bool rdns_ioc_tcp_connect (struct rdns_io_channel *ioc);

/**
 * Free request
 * @param req
 */
void rdns_request_free (struct rdns_request *req);

/**
 * Removes request from a channel's hash (e.g. if needed to migrate to another channel)
 * @param req
 */
void rdns_request_remove_from_hash (struct rdns_request *req);

/**
 * Creates a new reply
 * @param req
 * @param rcode
 * @return
 */
struct rdns_reply * rdns_make_reply (struct rdns_request *req, enum dns_rcode rcode);
/**
 * Free reply
 * @param rep
 */
void rdns_reply_free (struct rdns_reply *rep);

void rdns_request_unschedule (struct rdns_request *req, bool remove_from_hash);

#endif /* UTIL_H_ */
