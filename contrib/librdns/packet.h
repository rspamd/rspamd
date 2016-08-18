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
#ifndef PACKET_H_
#define PACKET_H_

#include <stdbool.h>
#include <stdint.h>
#include "dns_private.h"

struct rdns_compression_entry;

/**
 * Allocate dns packet suitable to handle up to `namelen` name
 * @param req request
 * @param namelen requested name
 */
void rdns_allocate_packet (struct rdns_request* req, unsigned int namelen);

/**
 * Add basic header to the dns packet
 * @param req
 */
void rdns_make_dns_header (struct rdns_request *req, unsigned int qcount);


/**
 * Add a resource record to the DNS packet
 * @param req request
 * @param name requested name
 * @param type type of resource record
 */
bool rdns_add_rr (struct rdns_request *req, const char *name, unsigned int len,
		enum dns_type type, struct rdns_compression_entry **comp);

/**
 * Add EDNS0 section
 * @param req
 */
bool rdns_add_edns0 (struct rdns_request *req);

#endif /* PACKET_H_ */
