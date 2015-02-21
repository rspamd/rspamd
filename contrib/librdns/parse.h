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
#ifndef PARSE_H_
#define PARSE_H_

#include "dns_private.h"

/**
 * Compare request and reply checking names
 * @param req request object
 * @param in incoming packet
 * @param len length of the incoming packet
 * @return new position in the incoming packet or NULL if request is not equal to reply
 */
uint8_t * rdns_request_reply_cmp (struct rdns_request *req, uint8_t *in, int len);

/**
 * Parse labels in the packet
 * @param in incoming packet
 * @param target target to write the parsed label (out)
 * @param pos output position in the packet (it/out)
 * @param rep dns reply
 * @param remain remaining bytes (in/out)
 * @param make_name create name or just skip to the next label
 * @return true if a label has been successfully parsed
 */
bool rdns_parse_labels (struct rdns_resolver *resolver,
		uint8_t *in, char **target,
		uint8_t **pos, struct rdns_reply *rep,
		int *remain, bool make_name);

/**
 * Parse resource record
 * @param in incoming packet
 * @param elt new reply entry
 * @param pos output position in the packet (it/out)
 * @param rep dns reply
 * @param remain remaining bytes (in/out)
 * @return 1 if rr has been parsed, 0 if rr has been skipped and -1 if there was a parsing error
 */
int rdns_parse_rr (struct rdns_resolver *resolver,
		uint8_t *in, struct rdns_reply_entry *elt, uint8_t **pos,
		struct rdns_reply *rep, int *remain);

#endif /* PARSE_H_ */
