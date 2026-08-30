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

#define MAX_RECURSION_LEVEL 10
/* Maximum length of a name on the wire: DNS_D_MAXNAME plus the root label */
#define DNS_D_MAXNAME_WIRE (DNS_D_MAXNAME + 1)

/*
 * Iterator over a (possibly compressed) DNS name.
 *
 * Two independent limits are enforced. Compression pointer targets may address
 * anything inside the packet, so they are bound to `[pkt, pkt + pkt_len)`. The
 * octets that physically encode the name in the enclosing stream (before the
 * first compression jump) must stay inside `[pkt, pkt + stream_end)`, which lets
 * a caller restrict a name to its RDATA boundary. The amount of work spent on a
 * single name is bounded by both the number of compression pointers followed and
 * the maximum length of a DNS name, so a malicious packet cannot make us loop or
 * accumulate an unbounded name.
 */
struct rdns_name_iter {
	const uint8_t *pkt;
	size_t pkt_len;   /* Bounds compression pointer targets */
	size_t stream_end;/* Bounds the physically encoded octets of the name */
	size_t pos;    /* Current offset in the packet */
	size_t end_pos;/* Offset just after the name in the enclosing stream */
	size_t namelen;/* Wire length of the name decoded so far */
	unsigned int ptrs;
	bool jumped;
	bool finished;
};

static void
rdns_name_iter_init(struct rdns_name_iter *it, const uint8_t *pkt,
					size_t pkt_len, size_t stream_end, size_t pos)
{
	it->pkt = pkt;
	it->pkt_len = pkt_len;
	it->stream_end = stream_end > pkt_len ? pkt_len : stream_end;
	it->pos = pos;
	it->end_pos = pos;
	it->namelen = 0;
	it->ptrs = 0;
	it->jumped = false;
	it->finished = false;
}

/*
 * Read the next label of a name.
 *
 * Returns 1 and fills `off`/`len` (offsets within the packet) when a label has
 * been read, 0 when the name is over and -1 when the name is malformed.
 */
static int
rdns_name_iter_next(struct rdns_name_iter *it, size_t *off, size_t *len)
{
	if (it->finished) {
		return 0;
	}

	for (;;) {
		/*
		 * Until we follow a compression pointer we are reading octets that
		 * belong to the enclosing stream (e.g. the current RDATA); afterwards we
		 * may roam anywhere inside the packet
		 */
		size_t limit = it->jumped ? it->pkt_len : it->stream_end;

		if (it->pos >= limit) {
			return -1;
		}

		uint8_t llen = it->pkt[it->pos];

		if ((llen & DNS_COMPRESSION_BITS) == DNS_COMPRESSION_BITS) {
			/* Compression pointer, it occupies 2 octets in the enclosing stream */
			if (it->pos + 1 >= limit) {
				return -1;
			}

			size_t target = ((size_t) (llen & ~DNS_COMPRESSION_BITS) << 8) +
							it->pkt[it->pos + 1];

			if (target >= it->pkt_len) {
				return -1;
			}

			if (++it->ptrs > MAX_RECURSION_LEVEL) {
				return -1;
			}

			if (!it->jumped) {
				it->end_pos = it->pos + 2;
				it->jumped = true;
			}

			it->pos = target;
			continue;
		}
		else if ((llen & DNS_COMPRESSION_BITS) != 0) {
			/* Reserved label type, we cannot parse it */
			return -1;
		}

		if (llen == 0) {
			/* Root label terminates the name */
			if (!it->jumped) {
				it->end_pos = it->pos + 1;
			}

			it->finished = true;

			return 0;
		}

		if (it->pos + 1 + llen > limit) {
			return -1;
		}

		/*
		 * The pointers limit alone does not bound the total name length, as a
		 * single jump can be followed by an arbitrary long chain of labels
		 */
		if (it->namelen + llen + 1 > DNS_D_MAXNAME_WIRE) {
			return -1;
		}

		it->namelen += llen + 1;
		*off = it->pos + 1;
		*len = llen;
		it->pos += llen + 1;

		if (!it->jumped) {
			it->end_pos = it->pos;
		}

		return 1;
	}
}

uint8_t *
rdns_request_reply_cmp(struct rdns_request *req, uint8_t *in, int len,
					   uint8_t *pos, unsigned int req_len)
{
	struct rdns_name_iter reply_it, req_it;
	size_t reply_off, req_off, reply_llen, req_llen;
	struct rdns_resolver *resolver = req->resolver;
	int r1, r2;

	/* QR format:
	 * labels - len:octets
	 * null label - 0
	 * class - 2 octets
	 * type - 2 octets
	 */

	if (len < 0 || pos < in || (size_t) (pos - in) >= (size_t) len ||
		req_len > req->packet_len || req->pos < 0 ||
		(size_t) req->pos >= (size_t) req_len) {
		rdns_info("invalid dns reply");
		return NULL;
	}

	/* A question is not embedded into any RDATA, so it spans up to the packet end */
	rdns_name_iter_init(&reply_it, in, (size_t) len, (size_t) len,
						(size_t) (pos - in));
	rdns_name_iter_init(&req_it, req->packet, req_len, req_len,
						(size_t) req->pos);

	/* Compare the question name in the reply with the one we have sent */
	for (;;) {
		r1 = rdns_name_iter_next(&reply_it, &reply_off, &reply_llen);
		r2 = rdns_name_iter_next(&req_it, &req_off, &req_llen);

		if (r1 < 0 || r2 < 0) {
			return NULL;
		}

		if (r1 != r2) {
			/* One of the names is longer than another one */
			return NULL;
		}

		if (r1 == 0) {
			break;
		}

		if (reply_llen != req_llen ||
			memcmp(in + reply_off, req->packet + req_off, reply_llen) != 0) {
			return NULL;
		}
	}

	/* Both iterators now point to the end of the QNAME, compare class and type */
	if (reply_it.end_pos + sizeof(uint16_t) * 2 > (size_t) len ||
		req_it.end_pos + sizeof(uint16_t) * 2 > req_len) {
		rdns_info("stripped dns reply: no room for the question type and class");
		return NULL;
	}

	if (memcmp(in + reply_it.end_pos, req->packet + req_it.end_pos,
			   sizeof(uint16_t) * 2) != 0) {
		return NULL;
	}

	req->pos = req_it.end_pos + sizeof(uint16_t) * 2;

	return in + reply_it.end_pos + sizeof(uint16_t) * 2;
}

bool
rdns_parse_labels(struct rdns_resolver *resolver,
				  uint8_t *in, char **target, uint8_t **pos,
				  struct rdns_reply *rep, int *remain, bool make_name,
				  size_t rdata_end)
{
	struct rdns_name_iter it;
	/* A name is bounded, so we can compose it on stack before allocating */
	uint8_t name[DNS_D_MAXNAME_WIRE];
	size_t namelen = 0, off, llen, pkt_len, start, stream_end;
	int r;

	if (*remain <= 0 || *pos < in) {
		return false;
	}

	start = (size_t) (*pos - in);
	pkt_len = start + (size_t) *remain;
	/*
	 * `rdata_end == 0` is used by names that are not embedded into a resource
	 * record (the RR owner name), those are only bound by the packet end
	 */
	stream_end = (rdata_end == 0) ? pkt_len : rdata_end;

	rdns_name_iter_init(&it, in, pkt_len, stream_end, start);

	while ((r = rdns_name_iter_next(&it, &off, &llen)) > 0) {
		if (make_name) {
			/* Cannot happen as the iterator bounds the name length */
			if (namelen + llen + 1 > sizeof(name)) {
				return false;
			}

			memcpy(name + namelen, in + off, llen);
			namelen += llen;
			name[namelen++] = '.';
		}
	}

	if (r < 0) {
		rdns_info("invalid DNS name in the packet");
		return false;
	}

	if (make_name) {
		*target = malloc(namelen > 0 ? namelen : 1);

		if (*target == NULL) {
			rdns_err("failed to allocate %d bytes for a DNS name",
					 (int) (namelen > 0 ? namelen : 1));
			return false;
		}

		if (namelen > 0) {
			memcpy(*target, name, namelen);
			/* Replace the trailing dot with the terminating zero */
			(*target)[namelen - 1] = '\0';
		}
		else {
			/* Handle empty labels */
			**target = '\0';
		}
	}

	*remain = (int) (pkt_len - it.end_pos);
	*pos = in + it.end_pos;

	return true;
}

#define GET8(x) do {(x) = ((*p)); p += sizeof (uint8_t); *remain -= sizeof (uint8_t); } while(0)
#define GET16(x) do {(x) = ((*p) << 8) + *(p + 1); p += sizeof (uint16_t); *remain -= sizeof (uint16_t); } while(0)
#define GET32(x) do {(x) = ((uint32_t) (*p) << 24) + ((uint32_t) (*(p + 1)) << 16) + ((uint32_t) (*(p + 2)) << 8) + *(p + 3); p += sizeof (uint32_t); *remain -= sizeof (uint32_t); } while(0)
#define SKIP(type) do { p += sizeof(type); *remain -= sizeof(type); } while (0)

int
rdns_parse_rr(struct rdns_resolver *resolver,
			  uint8_t *in, struct rdns_reply_entry *elt, uint8_t **pos,
			  struct rdns_reply *rep, int *remain)
{
	uint8_t *p = *pos, *rdata_start;
	uint16_t type, datalen;
	int32_t ttl;
	int rdata_remain;
	size_t rdata_end;
	bool parsed = false;

	/* Skip the whole name */
	if (!rdns_parse_labels(resolver, in, NULL, &p, rep, remain, false, 0)) {
		rdns_info("bad RR name");
		return -1;
	}
	if (*remain < (int) sizeof(uint16_t) * 6) {
		rdns_info("stripped dns reply: %d bytes remain; domain %s", *remain,
				  rep->requested_name);
		return -1;
	}
	GET16(type);
	/* Skip class */
	SKIP(uint16_t);
	GET32(ttl);
	GET16(datalen);
	elt->type = type;

	/* Now p points to RR data */
	rdata_start = p;
	rdata_remain = *remain;

	if ((int) datalen > rdata_remain) {
		rdns_info("stripped dns reply: RR of type %d claims %d bytes of data, "
				  "%d bytes remain; domain %s",
				  (int) type, (int) datalen, rdata_remain, rep->requested_name);
		return -1;
	}

	/*
	 * Absolute offset at which this record's RDATA ends. Names embedded into the
	 * RDATA must be physically encoded before it (compression pointers may still
	 * reference names elsewhere in the packet)
	 */
	rdata_end = (size_t) (rdata_start - in) + datalen;

	switch (type) {
	case DNS_T_A:
		if (datalen != sizeof(struct in_addr)) {
			rdns_info("corrupted A record; domain: %s", rep->requested_name);
			return -1;
		}

		memcpy(&elt->content.a.addr, p, sizeof(struct in_addr));
		parsed = true;
		break;
	case DNS_T_AAAA:
		if (datalen != sizeof(struct in6_addr)) {
			rdns_info("corrupted AAAA record; domain %s", rep->requested_name);
			return -1;
		}

		memcpy(&elt->content.aaa.addr, p, sizeof(struct in6_addr));
		parsed = true;
		break;
	case DNS_T_PTR:
		if (!rdns_parse_labels(resolver, in, &elt->content.ptr.name, &p,
							   rep, remain, true, rdata_end)) {
			rdns_info("invalid labels in PTR record; domain %s", rep->requested_name);
			return -1;
		}
		if ((size_t) (p - in) != rdata_end) {
			rdns_info("PTR record name does not fill its RDATA; domain %s",
					  rep->requested_name);
			free(elt->content.ptr.name);
			return -1;
		}
		parsed = true;
		break;
	case DNS_T_NS:
		if (!rdns_parse_labels(resolver, in, &elt->content.ns.name, &p,
							   rep, remain, true, rdata_end)) {
			rdns_info("invalid labels in NS record; domain %s", rep->requested_name);
			return -1;
		}
		if ((size_t) (p - in) != rdata_end) {
			rdns_info("NS record name does not fill its RDATA; domain %s",
					  rep->requested_name);
			free(elt->content.ns.name);
			return -1;
		}
		parsed = true;
		break;
	case DNS_T_SOA: {
		char *mname = NULL, *admin = NULL;

		if (!rdns_parse_labels(resolver, in, &mname, &p, rep, remain, true,
							   rdata_end)) {
			rdns_info("invalid labels in SOA record; domain %s", rep->requested_name);
			return -1;
		}
		if (!rdns_parse_labels(resolver, in, &admin, &p, rep, remain, true,
							   rdata_end)) {
			rdns_info("invalid labels in SOA record; domain %s", rep->requested_name);
			free(mname);
			return -1;
		}
		/* The two names must be followed by exactly five 32 bit integers */
		if ((size_t) (p - in) + sizeof(uint32_t) * 5 != rdata_end) {
			rdns_info("invalid data in SOA record; domain %s", rep->requested_name);
			free(mname);
			free(admin);
			return -1;
		}

		elt->content.soa.mname = mname;
		elt->content.soa.admin = admin;
		GET32(elt->content.soa.serial);
		GET32(elt->content.soa.refresh);
		GET32(elt->content.soa.retry);
		GET32(elt->content.soa.expire);
		GET32(elt->content.soa.minimum);
		parsed = true;
		break;
	}
	case DNS_T_MX:
		if (datalen < sizeof(uint16_t) + 1) {
			rdns_info("stripped dns reply while reading MX record; domain %s", rep->requested_name);
			return -1;
		}

		GET16(elt->content.mx.priority);
		if (!rdns_parse_labels(resolver, in, &elt->content.mx.name, &p,
							   rep, remain, true, rdata_end)) {
			rdns_info("invalid labels in MX record; domain %s", rep->requested_name);
			return -1;
		}
		if ((size_t) (p - in) != rdata_end) {
			rdns_info("MX record name does not fill its RDATA; domain %s",
					  rep->requested_name);
			free(elt->content.mx.name);
			return -1;
		}
		parsed = true;
		break;
	case DNS_T_TXT:
	case DNS_T_SPF: {
		/*
		 * TXT data is a sequence of length prefixed chunks that we glue
		 * together; all of them must fit into the declared RR data
		 */
		size_t consumed = 0, copied = 0;

		elt->content.txt.data = malloc(datalen + 1);
		if (elt->content.txt.data == NULL) {
			rdns_err("failed to allocate %d bytes for TXT record; domain %s",
					 (int) datalen + 1, rep->requested_name);
			return -1;
		}

		while (consumed < datalen) {
			size_t txtlen = rdata_start[consumed];

			if (consumed + txtlen + 1 > datalen) {
				/* Incorrect datalen reported ! */
				rdns_err("incorrect txtlen (%d) > datalen (%d) reported; domain %s",
						 (int) (consumed + txtlen + 1), (int) datalen,
						 rep->requested_name);
				free(elt->content.txt.data);
				elt->content.txt.data = NULL;

				return -1;
			}

			memcpy(elt->content.txt.data + copied, rdata_start + consumed + 1,
				   txtlen);
			copied += txtlen;
			consumed += txtlen + 1;
		}

		*(elt->content.txt.data + copied) = '\0';
		parsed = true;
		elt->type = RDNS_REQUEST_TXT;
		break;
	}
	case DNS_T_SRV:
		if (datalen < sizeof(uint16_t) * 3 + 1) {
			rdns_info("stripped dns reply while reading SRV record; domain %s", rep->requested_name);
			return -1;
		}

		GET16(elt->content.srv.priority);
		GET16(elt->content.srv.weight);
		GET16(elt->content.srv.port);
		if (!rdns_parse_labels(resolver, in, &elt->content.srv.target,
							   &p, rep, remain, true, rdata_end)) {
			rdns_info("invalid labels in SRV record; domain %s", rep->requested_name);
			return -1;
		}
		if ((size_t) (p - in) != rdata_end) {
			rdns_info("SRV record target does not fill its RDATA; domain %s",
					  rep->requested_name);
			free(elt->content.srv.target);
			return -1;
		}
		parsed = true;
		break;
	case DNS_T_TLSA: {
		uint16_t tlsa_len;

		if (datalen <= sizeof(uint8_t) * 3) {
			rdns_info("stripped dns reply while reading TLSA record; domain %s", rep->requested_name);
			return -1;
		}

		GET8(elt->content.tlsa.usage);
		GET8(elt->content.tlsa.selector);
		GET8(elt->content.tlsa.match_type);
		tlsa_len = datalen - sizeof(uint8_t) * 3;

		elt->content.tlsa.data = malloc(tlsa_len);
		if (elt->content.tlsa.data == NULL) {
			rdns_err("failed to allocate %d bytes for TLSA record; domain %s",
					 (int) tlsa_len, rep->requested_name);
			return -1;
		}

		elt->content.tlsa.datalen = tlsa_len;
		memcpy(elt->content.tlsa.data, p, tlsa_len);
		parsed = true;
		break;
	}
	case DNS_T_CNAME:
		if (!rdns_parse_labels(resolver, in, &elt->content.cname.name, &p,
							   rep, remain, true, rdata_end)) {
			rdns_info("invalid labels in CNAME record; domain %s", rep->requested_name);
			return -1;
		}
		if ((size_t) (p - in) != rdata_end) {
			rdns_info("CNAME record name does not fill its RDATA; domain %s",
					  rep->requested_name);
			free(elt->content.cname.name);
			return -1;
		}
		parsed = true;
		break;
	default:
		rdns_info("unexpected RR type: %d; domain %s", type, rep->requested_name);
		break;
	}

	/*
	 * Names inside RR data are allowed to reference the rest of the packet via
	 * compression, but the encoded record itself must not be longer than the
	 * declared data length. Resync to the end of this RR to make sure that a
	 * bogus RDLENGTH cannot shift the parsing of the records that follow.
	 */
	*pos = rdata_start + datalen;
	*remain = rdata_remain - datalen;

	if (parsed) {
		elt->ttl = ttl;
		return 1;
	}
	return 0;
}
