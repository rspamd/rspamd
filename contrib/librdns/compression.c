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
#include "contrib/mumhash/mum.h"

#define rdns_compression_hash(n) (mum_hash(n.suffix, n.suffix_len, 0xdeadbeef))
#define rdns_compression_equal(n1, n2) ((n1).suffix_len == (n2).suffix_len && \
	(memcmp((n1).suffix, (n2).suffix, (n1).suffix_len) == 0))
__KHASH_IMPL(rdns_compression_hash, kh_inline, struct rdns_compression_name, char, 0, rdns_compression_hash,
		rdns_compression_equal);

static struct rdns_compression_name *
rdns_can_compress (const char *pos, unsigned int len, khash_t(rdns_compression_hash) *comp)
{
	struct rdns_compression_name check;
	khiter_t k;

	if (comp == NULL) {
		return NULL;
	}

	check.suffix_len = len;
	check.suffix = pos;
	k = kh_get(rdns_compression_hash, comp, check);

	if (k != kh_end(comp)) {
		return &kh_key(comp, k);
	}

	return NULL;
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
					 khash_t(rdns_compression_hash) *comp,
					 int offset)
{
	struct rdns_compression_name new_name;
	int r;

	if (comp != NULL) {

		assert (offset >= 0);
		new_name.suffix_len = end - pos;
		new_name.suffix = pos;
		new_name.offset = offset;

		kh_put(rdns_compression_hash, comp, new_name, &r);
	}
}

void
rdns_compression_free (khash_t(rdns_compression_hash) *comp)
{
	if (comp != NULL) {
		kh_destroy(rdns_compression_hash, comp);
	}
}

bool
rdns_write_name_compressed (struct rdns_request *req,
							const char *name, unsigned int namelen,
							khash_t(rdns_compression_hash) **comp)
{
	uint8_t *target = req->packet + req->pos;
	const char *pos = name, *end = name + namelen;
	unsigned int remain = req->packet_len - req->pos - 5, label_len;
	struct rdns_resolver *resolver = req->resolver;
	uint16_t pointer;

	if (comp != NULL && *comp == NULL) {
		*comp = kh_init(rdns_compression_hash);
	}

	while (pos < end && remain > 0) {
		if (comp) {
			struct rdns_compression_name *test = rdns_can_compress(pos, end - pos, *comp);
			if (test != NULL) {
				/* Can compress name */
				if (remain < 2) {
					rdns_info ("no buffer remain for constructing query");
					return false;
				}

				pointer = htons ((uint16_t) test->offset) | DNS_COMPRESSION_BITS;
				memcpy(target, &pointer, sizeof(pointer));
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

		if (comp) {
			rdns_add_compressed(pos, end, *comp, target - req->packet);
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
