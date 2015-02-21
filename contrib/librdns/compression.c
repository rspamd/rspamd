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

#include "compression.h"
#include "logger.h"

static struct rdns_compression_entry *
rdns_can_compress (const char *pos, struct rdns_compression_entry *comp)
{
	struct rdns_compression_entry *res;

	HASH_FIND_STR (comp, pos, res);

	return res;
}

static unsigned int
rdns_calculate_label_len (const char *pos, const char *end)
{
	const char *p = pos;
	unsigned int res = 0;

	while (p != end) {
		if (*p == '.') {
			break;
		}
		res ++;
		p ++;
	}
	return res;
}

static void
rdns_add_compressed (const char *pos, const char *end,
		struct rdns_compression_entry **comp, int offset)
{
	struct rdns_compression_entry *new;

	assert (offset >= 0);
	new = malloc (sizeof (*new));
	if (new != NULL) {
		new->label = pos;
		new->offset = offset;
		HASH_ADD_KEYPTR (hh, *comp, pos, (end - pos), new);
	}
}

void
rnds_compression_free (struct rdns_compression_entry *comp)
{
	struct rdns_compression_entry *cur, *tmp;

	if (comp) {
		free (comp->hh.tbl->buckets);
		free (comp->hh.tbl);

		HASH_ITER (hh, comp, cur, tmp) {
			free (cur);
		}
	}
}

bool
rdns_write_name_compressed (struct rdns_request *req,
		const char *name, unsigned int namelen,
		struct rdns_compression_entry **comp)
{
	uint8_t *target = req->packet + req->pos;
	const char *pos = name, *end = name + namelen;
	unsigned int remain = req->packet_len - req->pos - 5, label_len;
	struct rdns_compression_entry *head = NULL, *test;
	struct rdns_resolver *resolver = req->resolver;
	uint16_t pointer;

	if (comp != NULL) {
		head = *comp;
	}

	while (pos < end && remain > 0) {
		if (head != NULL) {
			test = rdns_can_compress (pos, head);
			if (test != NULL) {
				if (remain < 2) {
					rdns_info ("no buffer remain for constructing query");
					return false;
				}

				pointer = htons ((uint16_t)test->offset) | DNS_COMPRESSION_BITS;
				memcpy (target, &pointer, sizeof (pointer));
				req->pos += 2;

				return true;
			}
		}


		label_len = rdns_calculate_label_len (pos, end);
		if (label_len == 0) {
			/* We have empty label it is allowed only if pos == end - 1 */
			if (pos == end - 1) {
				break;
			}
			else {
				rdns_err ("double dots in the name requested");
				return false;
			}
		}
		else if (label_len > DNS_D_MAXLABEL) {
			rdns_err ("too large label: %d", (int)label_len);
			return false;
		}

		if (label_len + 1 > remain) {
			rdns_info ("no buffer remain for constructing query, strip %d to %d",
					(int)label_len, (int)remain);
			label_len = remain - 1;
		}

		if (comp != NULL) {
			rdns_add_compressed (pos, end, comp, target - req->packet);
		}
		/* Write label as is */
		*target++ = (uint8_t)label_len;
		memcpy (target, pos, label_len);
		target += label_len;
		pos += label_len + 1;
	}

	/* Termination label */
	*target++ = '\0';
	req->pos = target - req->packet;

	return true;
}
