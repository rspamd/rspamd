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
#include "parse.h"
#include "logger.h"

static uint8_t *
rdns_decompress_label (uint8_t *begin, uint16_t *len, uint16_t max)
{
	uint16_t offset = (*len);

	if (offset > max) {
		return NULL;
	}
	*len = *(begin + offset);
	return begin + offset;
}

#define UNCOMPRESS_DNS_OFFSET(p) (((*(p)) ^ DNS_COMPRESSION_BITS) << 8) + *((p) + 1)

uint8_t *
rdns_request_reply_cmp (struct rdns_request *req, uint8_t *in, int len)
{
	uint8_t *p, *c, *l1, *l2;
	uint16_t len1, len2;
	int decompressed = 0;
	struct rdns_resolver *resolver = req->resolver;

	/* QR format:
	 * labels - len:octets
	 * null label - 0
	 * class - 2 octets
	 * type - 2 octets
	 */

	/* In p we would store current position in reply and in c - position in request */
	p = in;
	c = req->packet + req->pos;

	for (;;) {
		/* Get current label */
		len1 = *p;
		len2 = *c;
		if (p - in > len) {
			rdns_info ("invalid dns reply");
			return NULL;
		}
		/* This may be compressed, so we need to decompress it */
		if (len1 & DNS_COMPRESSION_BITS) {
			len1 = UNCOMPRESS_DNS_OFFSET(p);
			l1 = rdns_decompress_label (in, &len1, len);
			if (l1 == NULL) {
				return NULL;
			}
			decompressed ++;
			l1 ++;
			p += 2;
		}
		else {
			l1 = ++p;
			p += len1;
		}
		if (len2 & DNS_COMPRESSION_BITS) {
			len2 = UNCOMPRESS_DNS_OFFSET(c);
			l2 = rdns_decompress_label (c, &len2, len);
			if (l2 == NULL) {
				rdns_info ("invalid DNS pointer, cannot decompress");
				return NULL;
			}
			decompressed ++;
			l2 ++;
			c += 2;
		}
		else {
			l2 = ++c;
			c += len2;
		}
		if (len1 != len2) {
			return NULL;
		}
		if (len1 == 0) {
			break;
		}

		if (memcmp (l1, l2, len1) != 0) {
			return NULL;
		}
		if (decompressed == 2) {
			break;
		}
	}

	/* p now points to the end of QR section */
	/* Compare class and type */
	if (memcmp (p, c, sizeof (uint16_t) * 2) == 0) {
		req->pos = c - req->packet + sizeof (uint16_t) * 2;
		return p + sizeof (uint16_t) * 2;
	}
	return NULL;
}

#define MAX_RECURSION_LEVEL 10

bool
rdns_parse_labels (struct rdns_resolver *resolver,
		uint8_t *in, char **target, uint8_t **pos, struct rdns_reply *rep,
		int *remain, bool make_name)
{
	uint16_t namelen = 0;
	uint8_t *p = *pos, *begin = *pos, *l, *t, *end = *pos + *remain, *new_pos = *pos;
	uint16_t llen;
	int length = *remain, new_remain = *remain;
	int ptrs = 0, labels = 0;
	bool got_compression = false;

	/* First go through labels and calculate name length */
	while (p - begin < length) {
		if (ptrs > MAX_RECURSION_LEVEL) {
			rdns_info ("dns pointers are nested too much");
			return false;
		}
		llen = *p;
		if (llen == 0) {
			if (!got_compression) {
				/* In case of compression we have already decremented the processing position */
				new_remain -= sizeof (uint8_t);
				new_pos += sizeof (uint8_t);
			}
			break;
		}
		else if ((llen & DNS_COMPRESSION_BITS)) {
			if (end - p > 1) {
				ptrs ++;
				llen = UNCOMPRESS_DNS_OFFSET(p);
				l = rdns_decompress_label (in, &llen, end - in);
				if (l == NULL) {
					rdns_info ("invalid DNS pointer");
					return false;
				}
				if (!got_compression) {
					/* Our label processing is finished actually */
					new_remain -= sizeof (uint16_t);
					new_pos += sizeof (uint16_t);
					got_compression = true;
				}
				if (l < in || l > begin + length) {
					rdns_info  ("invalid pointer in DNS packet");
					return false;
				}
				begin = l;
				length = end - begin;
				p = l + *l + 1;
				namelen += *l;
				labels ++;
			}
			else {
				rdns_info ("DNS packet has incomplete compressed label, input length: %d bytes, remain: %d",
						*remain, new_remain);
				return false;
			}
		}
		else {
			namelen += llen;
			p += llen + 1;
			labels ++;
			if (!got_compression) {
				new_remain -= llen + 1;
				new_pos += llen + 1;
			}
		}
	}

	if (!make_name) {
		goto end;
	}
	*target = malloc (namelen + labels + 3);
	t = (uint8_t *)*target;
	p = *pos;
	begin = *pos;
	length = *remain;
	/* Now copy labels to name */
	while (p - begin < length) {
		llen = *p;
		if (llen == 0) {
			break;
		}
		else if (llen & DNS_COMPRESSION_BITS) {
			llen = UNCOMPRESS_DNS_OFFSET(p);
			l = rdns_decompress_label (in, &llen, end - in);

			if (l == NULL) {
				goto end;
			}

			begin = l;
			length = end - begin;
			p = l + *l + 1;
			memcpy (t, l + 1, *l);
			t += *l;
			*t ++ = '.';
		}
		else {
			memcpy (t, p + 1, *p);
			t += *p;
			*t ++ = '.';
			p += *p + 1;
		}
	}
	if (t > (uint8_t *)*target) {
		*(t - 1) = '\0';
	}
	else {
		/* Handle empty labels */
		**target = '\0';
	}
end:
	*remain = new_remain;
	*pos = new_pos;

	return true;
}

#define GET8(x) do {(x) = ((*p)); p += sizeof (uint8_t); *remain -= sizeof (uint8_t); } while(0)
#define GET16(x) do {(x) = ((*p) << 8) + *(p + 1); p += sizeof (uint16_t); *remain -= sizeof (uint16_t); } while(0)
#define GET32(x) do {(x) = ((*p) << 24) + ((*(p + 1)) << 16) + ((*(p + 2)) << 8) + *(p + 3); p += sizeof (uint32_t); *remain -= sizeof (uint32_t); } while(0)
#define SKIP(type) do { p += sizeof(type); *remain -= sizeof(type); } while (0)

int
rdns_parse_rr (struct rdns_resolver *resolver,
		uint8_t *in, struct rdns_reply_entry *elt, uint8_t **pos,
		struct rdns_reply *rep, int *remain)
{
	uint8_t *p = *pos, parts;
	uint16_t type, datalen, txtlen, copied;
	int32_t ttl;
	bool parsed = false;

	/* Skip the whole name */
	if (!rdns_parse_labels (resolver, in, NULL, &p, rep, remain, false)) {
		rdns_info ("bad RR name");
		return -1;
	}
	if (*remain < (int)sizeof (uint16_t) * 6) {
		rdns_info ("stripped dns reply: %d bytes remain; domain %s", *remain,
				rep->requested_name);
		return -1;
	}
	GET16 (type);
	/* Skip class */
	SKIP (uint16_t);
	GET32 (ttl);
	GET16 (datalen);
	elt->type = type;
	/* Now p points to RR data */
	switch (type) {
	case DNS_T_A:
		if (!(datalen & 0x3) && datalen <= *remain) {
			memcpy (&elt->content.a.addr, p, sizeof (struct in_addr));
			p += datalen;
			*remain -= datalen;
			parsed = true;
		}
		else {
			rdns_info ("corrupted A record; domain: %s", rep->requested_name);
			return -1;
		}
		break;
	case DNS_T_AAAA:
		if (datalen == sizeof (struct in6_addr) && datalen <= *remain) {
			memcpy (&elt->content.aaa.addr, p, sizeof (struct in6_addr));
			p += datalen;
			*remain -= datalen;
			parsed = true;
		}
		else {
			rdns_info ("corrupted AAAA record; domain %s", rep->requested_name);
			return -1;
		}
		break;
	case DNS_T_PTR:
		if (! rdns_parse_labels (resolver, in, &elt->content.ptr.name, &p,
				rep, remain, true)) {
			rdns_info ("invalid labels in PTR record; domain %s", rep->requested_name);
			return -1;
		}
		parsed = true;
		break;
	case DNS_T_NS:
		if (! rdns_parse_labels (resolver, in, &elt->content.ns.name, &p,
				rep, remain, true)) {
			rdns_info ("invalid labels in NS record; domain %s", rep->requested_name);
			return -1;
		}
		parsed = true;
		break;
	case DNS_T_SOA:
		if (! rdns_parse_labels (resolver, in, &elt->content.soa.mname, &p,
				rep, remain, true)) {
			rdns_info ("invalid labels in SOA record; domain %s", rep->requested_name);
			return -1;
		}
		if (! rdns_parse_labels (resolver, in, &elt->content.soa.admin, &p,
				rep, remain, true)) {
			rdns_info ("invalid labels in SOA record; domain %s", rep->requested_name);
			return -1;
		}
		if (*remain >= sizeof(int32_t) * 5) {
			GET32 (elt->content.soa.serial);
			GET32 (elt->content.soa.refresh);
			GET32 (elt->content.soa.retry);
			GET32 (elt->content.soa.expire);
			GET32 (elt->content.soa.minimum);
		}
		else {
			rdns_info ("invalid data in SOA record; domain %s", rep->requested_name);
			return -1;
		}
		parsed = true;
		break;
	case DNS_T_MX:
		GET16 (elt->content.mx.priority);
		if (! rdns_parse_labels (resolver, in, &elt->content.mx.name, &p,
				rep, remain, true)) {
			rdns_info ("invalid labels in MX record; domain %s", rep->requested_name);
			return -1;
		}
		parsed = true;
		break;
	case DNS_T_TXT:
	case DNS_T_SPF:
		if (datalen <= *remain) {
			if (datalen > UINT16_MAX / 2) {
				rdns_info ("too large datalen; domain %s", rep->requested_name);
				return -1;
			}
			elt->content.txt.data = malloc(datalen + 1);
			if (elt->content.txt.data == NULL) {
				rdns_err ("failed to allocate %d bytes for TXT record; domain %s",
						(int) datalen + 1, rep->requested_name);
				return -1;
			}
			/* Now we should compose data from parts */
			copied = 0;
			parts = 0;
			while (copied + parts < datalen && *remain > 0) {
				txtlen = *p;
				if (txtlen + copied + parts <= datalen && *remain >= txtlen + 1) {
					parts++;
					memcpy (elt->content.txt.data + copied, p + 1, txtlen);
					copied += txtlen;
					p += txtlen + 1;
					*remain -= txtlen + 1;
				}
				else {

					if (txtlen + copied + parts > datalen) {
						/* Incorrect datalen reported ! */
						rdns_err ("incorrect txtlen (%d) > datalen (%d) reported; domain %s",
								(txtlen + copied + parts), datalen,
								rep->requested_name);
						return -1;
					}

					/* Reported equal to the actual data copied */
					break;
				}
			}
			*(elt->content.txt.data + copied) = '\0';
			parsed = true;
			elt->type = RDNS_REQUEST_TXT;
		}
		else {
			rdns_info ("stripped data in TXT record (%d bytes available, %d requested); "
			  "domain %s", (int)*remain, (int)datalen, rep->requested_name);
			return -1;
		}
		break;
	case DNS_T_SRV:
		if (p - *pos > (int)(*remain - sizeof (uint16_t) * 3)) {
			rdns_info ("stripped dns reply while reading SRV record; domain %s", rep->requested_name);
			return -1;
		}
		GET16 (elt->content.srv.priority);
		GET16 (elt->content.srv.weight);
		GET16 (elt->content.srv.port);
		if (! rdns_parse_labels (resolver, in, &elt->content.srv.target,
				&p, rep, remain, true)) {
			rdns_info ("invalid labels in SRV record; domain %s", rep->requested_name);
			return -1;
		}
		parsed = true;
		break;
	case DNS_T_TLSA:
		if (p - *pos > (int)(*remain - sizeof (uint8_t) * 3) || datalen <= 3) {
			rdns_info ("stripped dns reply while reading TLSA record; domain %s", rep->requested_name);
			return -1;
		}
		if (datalen > UINT16_MAX / 2) {
			rdns_info ("too large datalen; domain %s", rep->requested_name);
			return -1;
		}
		GET8 (elt->content.tlsa.usage);
		GET8 (elt->content.tlsa.selector);
		GET8 (elt->content.tlsa.match_type);
		datalen -= 3;
		elt->content.tlsa.data = malloc (datalen);
		if (elt->content.tlsa.data == NULL) {
			rdns_err ("failed to allocate %d bytes for TLSA record; domain %s",
					(int)datalen + 1, rep->requested_name);
			return -1;
		}
		elt->content.tlsa.datalen = datalen;
		memcpy (elt->content.tlsa.data, p, datalen);
		p += datalen;
		*remain -= datalen;
		parsed = true;
		break;
	case DNS_T_CNAME:
		/* Skip cname records */
		p += datalen;
		*remain -= datalen;
		break;
	default:
		rdns_info ("unexpected RR type: %d; domain %s", type, rep->requested_name);
		p += datalen;
		*remain -= datalen;
		break;
	}
	*pos = p;

	if (parsed) {
		elt->ttl = ttl;
		return 1;
	}
	return 0;
}
