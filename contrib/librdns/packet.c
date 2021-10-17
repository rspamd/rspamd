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

#include "rdns.h"
#include "dns_private.h"
#include "punycode.h"
#include "packet.h"
#include "util.h"
#include "logger.h"
#include "compression.h"

void
rdns_allocate_packet (struct rdns_request* req, unsigned int namelen)
{
	namelen += 96 + 2 + 4 + 11; /* EDNS0 RR */
	req->packet = malloc (namelen);
	req->pos = 0;
	req->packet_len = namelen;
}


void
rdns_make_dns_header (struct rdns_request *req, unsigned int qcount)
{
	struct dns_header *header;

	/* Set DNS header values */
	header = (struct dns_header *)req->packet;
	memset (header, 0 , sizeof (struct dns_header));
	header->qid = rdns_permutor_generate_id ();
	header->rd = 1;
	header->qdcount = htons (qcount);
	header->arcount = htons (1);
	req->pos += sizeof (struct dns_header);
	req->id = header->qid;
}

static bool
rdns_maybe_punycode_label (const uint8_t *begin,
		uint8_t const **dot, size_t *label_len)
{
	bool ret = false;
	const uint8_t *p = begin;

	*dot = NULL;

	while (*p) {
		if (*p == '.') {
			*dot = p;
			break;
		}
		else if ((*p) & 0x80) {
			ret = true;
		}
		p ++;
	}

	if (label_len) {
		*label_len = p - begin;
	}

	return ret;
}

bool
rdns_format_dns_name (struct rdns_resolver *resolver, const char *in,
		size_t inlen,
		char **out, size_t *outlen)
{
	const uint8_t *dot;
	const uint8_t *p = in, *end = in + inlen;
	char *o;
	int labels = 0;
	size_t label_len, olen, remain;
	uint32_t *uclabel = NULL;
	size_t punylabel_len, uclabel_len;
	char tmp_label[DNS_D_MAXLABEL];
	bool need_encode = false;

	if (inlen == 0) {
		inlen = strlen (in);
	}

	/* Check for non-ascii characters */
	if (!(resolver->flags & RDNS_RESOLVER_NOIDN)) {
		while (p != end) {
			if (*p >= 0x80) {
				need_encode = true;
			}
			else if (*p == '.') {
				labels++;
			}
			p++;
		}
	}

	if (!need_encode) {
		*out = malloc (inlen + 1);

		if (*out == NULL) {
			return false;
		}

		o = *out;
		memcpy (o, in, inlen);
		o[inlen] = '\0';
		*outlen = inlen;

		return true;
	}

	/* We need to encode */
	p = in;
	/* We allocate 4 times more memory as we cannot guarantee encoding bounds */
	olen = inlen * sizeof (int32_t) + 1 + sizeof ("xn--") * labels;
	*out = malloc (olen + 1);

	if (*out == NULL) {
		return false;
	}

	o = *out;
	remain = olen;

	while (p != end) {
		/* Check label for unicode characters */
		if (rdns_maybe_punycode_label (p, &dot, &label_len)) {
			/* Convert to ucs4 */
			if (rdns_utf8_to_ucs4 (p, label_len, &uclabel, &uclabel_len) == 0) {
				punylabel_len = DNS_D_MAXLABEL;

				rdns_punycode_label_toascii (uclabel, uclabel_len,
						tmp_label, &punylabel_len);
				if (remain >= punylabel_len + 1) {
					memcpy (o, tmp_label, punylabel_len);
					o += punylabel_len;
					*o++ = '.';
					remain -= punylabel_len + 1;
				}
				else {
					rdns_info ("no buffer remain for punycoding query");
					goto err;
				}

				free (uclabel);
				uclabel = NULL;

				if (dot) {
					p = dot + 1;
				}
				else {
					break;
				}
			}
			else {
				break;
			}
		}
		else {
			if (dot) {
				if (label_len > DNS_D_MAXLABEL) {
					rdns_info ("dns name component is longer than 63 bytes, should be stripped");
					label_len = DNS_D_MAXLABEL;
				}
				if (remain < label_len + 1) {
					rdns_info ("no buffer remain for punycoding query");
					goto err;
				}
				if (label_len == 0) {
					/* Two dots in order, skip this */
					rdns_info ("name contains two or more dots in a row, replace it with one dot");
					p = dot + 1;
					continue;
				}
				memcpy (o, p, label_len);
				o += label_len;
				*o++ = '.';
				remain -= label_len + 1;
				p = dot + 1;
			}
			else {
				if (label_len == 0) {
					/* If name is ended with dot */
					break;
				}
				if (label_len > DNS_D_MAXLABEL) {
					rdns_info ("dns name component is longer than 63 bytes, should be stripped");
					label_len = DNS_D_MAXLABEL;
				}
				if (remain < label_len + 1) {
					rdns_info ("no buffer remain for punycoding query");
					goto err;
				}
				memcpy (o, p, label_len);
				o += label_len;
				*o++ = '.';
				remain -= label_len + 1;
				p = dot + 1;
				break;
			}
		}
		if (remain == 0) {
			rdns_info ("no buffer remain for punycoding query");
			goto err;
		}
	}

	*o = '\0';

	*outlen = o - *out;

	return true;

err:
	free (*out);
	*out = NULL;
	free (uclabel);

	return false;
}

#define U16_TO_WIRE_ADVANCE(val, p8) \
	*p8++ = (uint8_t)(((uint16_t)(val)) >> 8); \
	*p8++ = (uint8_t)(((uint16_t)(val)) & 0xFF);

bool
rdns_add_rr (struct rdns_request *req, const char *name, unsigned int len,
		enum dns_type type, struct rdns_compression_entry **comp)
{
	uint8_t *p8;

	if (!rdns_write_name_compressed (req, name, len, comp)) {
		return false;
	}

	p8 = (req->packet + req->pos);
	U16_TO_WIRE_ADVANCE (type, p8);
	U16_TO_WIRE_ADVANCE (DNS_C_IN, p8);
	req->pos += sizeof (uint16_t) * 2;

	return true;
}

bool
rdns_add_edns0 (struct rdns_request *req)
{
	uint8_t *p8;

	p8 = (req->packet + req->pos);
	*p8++ = '\0'; /* Name is root */
	U16_TO_WIRE_ADVANCE (DNS_T_OPT, p8);
	U16_TO_WIRE_ADVANCE (UDP_PACKET_SIZE, p8);
	U16_TO_WIRE_ADVANCE (0, p8);

	if (req->resolver->enable_dnssec) {
		*p8++ = 0x80;
	}
	else {
		*p8++ = 0x00;
	}
	*p8++ = 0;
	/* Length */
	U16_TO_WIRE_ADVANCE (0, p8);

	req->pos += sizeof (uint8_t) + sizeof (uint16_t) * 5;

	return true;
}
