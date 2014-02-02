/*
 * Copyright (c) 2009-2013, Vsevolod Stakhov
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
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

#include "config.h"
#include "dns.h"
#include "main.h"
#include "utlist.h"
#include "chacha_private.h"
#ifdef HAVE_OPENSSL
#include <openssl/rand.h>
#endif

/* Upstream timeouts */
#define DEFAULT_UPSTREAM_ERROR_TIME 10
#define DEFAULT_UPSTREAM_DEAD_TIME 300
#define DEFAULT_UPSTREAM_MAXERRORS 10

static const unsigned base         = 36;
static const unsigned t_min        = 1;
static const unsigned t_max        = 26;
static const unsigned skew         = 38;
static const unsigned damp         = 700;
static const unsigned initial_n    = 128;
static const unsigned initial_bias = 72;

static const gint dns_port = 53;

#define UDP_PACKET_SIZE 4096

#define DNS_COMPRESSION_BITS 0xC0

static void dns_retransmit_handler (gint fd, short what, void *arg);

/*
 * DNS permutor utilities
 */

#define PERMUTOR_BUF_SIZE 32768
#define PERMUTOR_KSIZE 32
#define PERMUTOR_IVSIZE 8

struct dns_permutor {
	chacha_ctx ctx;
	guchar perm_buf[PERMUTOR_BUF_SIZE];
	guint pos;
};

/**
 * Init chacha20 context
 * @param p
 */
static void
dns_permutor_init (struct dns_permutor *p)
{
	/* Init random key and IV */
	rspamd_random_bytes (p->perm_buf, PERMUTOR_KSIZE + PERMUTOR_IVSIZE);

	/* Setup ctx */
	chacha_keysetup (&p->ctx, p->perm_buf, PERMUTOR_KSIZE * 8, 0);
	chacha_ivsetup (&p->ctx, p->perm_buf + PERMUTOR_KSIZE * 8);

	chacha_encrypt_bytes (&p->ctx, p->perm_buf, p->perm_buf, sizeof (p->perm_buf));

	p->pos = 0;
}

static struct dns_permutor *
dns_permutor_new (memory_pool_t *pool)
{
	struct dns_permutor *new;

	new = memory_pool_alloc0 (pool, sizeof (struct dns_permutor));
	dns_permutor_init (new);

	return new;
}

static guint16
dns_permutor_generate_id (struct dns_permutor *p)
{
	guint16 id;
	if (p->pos + sizeof (guint16) >= sizeof (p->perm_buf)) {
		dns_permutor_init (p);
	}

	memcpy (&id, &p->perm_buf[p->pos], sizeof (guint16));
	p->pos += sizeof (guint16);

	return id;
}

/* Punycode utility */
static guint digit(unsigned n)
{
	return "abcdefghijklmnopqrstuvwxyz0123456789"[n];
}

static guint adapt(guint delta, guint numpoints, gint first)
{
	guint k;

	if (first) {
		delta = delta / damp;
	}
	else {
		delta /= 2;
	}
	delta += delta / numpoints;
	k = 0;
	while (delta > ((base - t_min) * t_max) / 2) {
		delta /= base - t_min;
		k += base;
	}
	return k + (((base - t_min + 1) * delta) / (delta + skew));
}

/**
 * Convert an UCS4 string to a puny-coded DNS label string suitable
 * when combined with delimiters and other labels for DNS lookup.
 *
 * @param in an UCS4 string to convert
 * @param in_len the length of in.
 * @param out the resulting puny-coded string. The string is not NUL
 * terminatied.
 * @param out_len before processing out_len should be the length of
 * the out variable, after processing it will be the length of the out
 * string.
 *
 * @return returns 0 on success, an wind error code otherwise
 * @ingroup wind
 */

gboolean
punycode_label_toascii(const gunichar *in, gsize in_len, gchar *out,
		gsize *out_len)
{
	guint n = initial_n;
	guint delta = 0;
	guint bias = initial_bias;
	guint h = 0;
	guint b;
	guint i;
	guint o = 0;
	guint m;

	for (i = 0; i < in_len; ++i) {
		if (in[i] < 0x80) {
			++h;
			if (o >= *out_len) {
				return FALSE;
			}
			out[o++] = in[i];
		}
	}
	b = h;
	if (b > 0) {
		if (o >= *out_len) {
			return FALSE;
		}
		out[o++] = 0x2D;
	}
	/* is this string punycoded */
	if (h < in_len) {
		if (o + 4 >= *out_len) {
			return FALSE;
		}
		memmove (out + 4, out, o);
		memcpy (out, "xn--", 4);
		o += 4;
	}

	while (h < in_len) {
		m = (guint) -1;
		for (i = 0; i < in_len; ++i) {

			if (in[i] < m && in[i] >= n) {
				m = in[i];
			}
		}
		delta += (m - n) * (h + 1);
		n = m;
		for (i = 0; i < in_len; ++i) {
			if (in[i] < n) {
				++delta;
			}
			else if (in[i] == n) {
				guint q = delta;
				guint k;
				for (k = base;; k += base) {
					guint t;
					if (k <= bias) {
						t = t_min;
					}
					else if (k >= bias + t_max) {
						t = t_max;
					}
					else {
						t = k - bias;
					}
					if (q < t) {
						break;
					}
					if (o >= *out_len) {
						return -1;
					}
					out[o++] = digit (t + ((q - t) % (base - t)));
					q = (q - t) / (base - t);
				}
				if (o >= *out_len) {
					return -1;
				}
				out[o++] = digit (q);
				/* output */
				bias = adapt (delta, h + 1, h == b);
				delta = 0;
				++h;
			}
		}
		++delta;
		++n;
	}

	*out_len = o;
	return TRUE;
}

struct dns_request_key {
	guint16 id;
	guint16 port;
};

/** Message compression */
struct dns_name_table {
	guint8 off;
	guint8 *label;
	guint8 len;
};

static gboolean
try_compress_label (memory_pool_t *pool, guint8 *target, guint8 *start, guint8 len, guint8 *label, GList **table)
{
	GList *cur;
	struct dns_name_table *tbl;
	guint16 pointer;

	cur = *table;
	while (cur) {
		tbl = cur->data;
		if (tbl->len == len) {
			if (memcmp (label, tbl->label, len) == 0) {
				pointer = htons ((guint16)tbl->off | 0xC0);
				memcpy (target, &pointer, sizeof (pointer));
				return TRUE;
			}
		}
		cur = g_list_next (cur);
	}

	/* Insert label to list */
	tbl = memory_pool_alloc (pool, sizeof (struct dns_name_table));
	tbl->off = target - start;
	tbl->label = label;
	tbl->len = len;
	*table = g_list_prepend (*table, tbl);

	return FALSE;
}

/** Packet creating functions */
static void
allocate_packet (struct rspamd_dns_request *req, guint namelen)
{
	namelen += 96 /* header */
		+ 2 /* Trailing label */
		+ 4 /* Resource type */
		+ 11; /* EDNS0 RR */
	req->packet = memory_pool_alloc (req->pool, namelen);
	req->pos = 0;
	req->packet_len = namelen;
}

static void
make_dns_header (struct rspamd_dns_request *req)
{
	struct dns_header *header;
	
	/* Set DNS header values */
	header = (struct dns_header *)req->packet;
	memset (header, 0 , sizeof (struct dns_header));
	header->qid = dns_permutor_generate_id (req->resolver->permutor);
	header->rd = 1;
	header->qdcount = htons (1);
	header->arcount = htons (1);
	req->pos += sizeof (struct dns_header);
	req->id = header->qid;
}

static gboolean
maybe_punycode_label (guint8 *begin, guint8 **res, guint8 **dot, guint *label_len)
{
	gboolean ret = FALSE;
	guint8 *p = begin;

	*dot = NULL;

	while (*p) {
		if (*p == '.') {
			*dot = p;
			break;
		}
		else if ((*p) & 0x80) {
			ret = TRUE;
		}
		p ++;
	}

	if (*p) {
		*res = p - 1;
		*label_len = p - begin;
	}
	else {
		*res = p;
		*label_len = p - begin;
	}

	return ret;
}

static void
format_dns_name (struct rspamd_dns_request *req, const gchar *name, guint namelen)
{
	guint8 *pos = req->packet + req->pos, *end, *dot, *name_pos, *begin;
	guint remain = req->packet_len - req->pos - 5, label_len;
	GList *table = NULL;
	gunichar *uclabel;
	glong uclabel_len;
	gsize punylabel_len;
	guint8 tmp_label[DNS_D_MAXLABEL];

	if (namelen == 0) {
		namelen = strlen (name);
	}
	
	begin = (guint8 *)name;
	end = (guint8 *)name + namelen;
	for (;;) {
		/* Check label for unicode characters */
		if (maybe_punycode_label (begin, &name_pos, &dot, &label_len)) {
			/* Convert to ucs4 */
			uclabel = g_utf8_to_ucs4_fast ((gchar *)begin, label_len, &uclabel_len);
			memory_pool_add_destructor (req->pool, g_free, uclabel);
			punylabel_len = DNS_D_MAXLABEL;

			punycode_label_toascii (uclabel, uclabel_len, (gchar *)tmp_label, &punylabel_len);
			/* Try to compress name */
			if (! try_compress_label (req->pool, pos, req->packet, punylabel_len, tmp_label, &table)) {
				/* Copy punylabel */
				*pos++ = (guint8)punylabel_len;
				memcpy (pos, tmp_label, punylabel_len);
				pos += punylabel_len;
			}
			else {
				pos += 2;
			}
			if (dot) {
				remain -= label_len + 1;
				begin = dot + 1;
			}
			else {
				break;
			}
		}
		else {
			if (dot) {
				if (label_len > DNS_D_MAXLABEL) {
					msg_err ("dns name component is longer than 63 bytes, should be stripped");
					label_len = DNS_D_MAXLABEL;
				}
				if (remain < label_len + 1) {
					label_len = remain - 1;
					msg_err ("no buffer remain for constructing query, strip to %ud", label_len);
				}
				if (label_len == 0) {
					/* Two dots in order, skip this */
					msg_info ("name contains two or more dots in a row, replace it with one dot");
					begin = dot + 1;
					continue;
				}
				/* First try to compress name */
				if (! try_compress_label (req->pool, pos, req->packet, end - begin, begin, &table)) {
					*pos++ = (guint8)label_len;
					memcpy (pos, begin, label_len);
					pos += label_len;
				}
				else {
					pos += 2;
				}
				remain -= label_len + 1;
				begin = dot + 1;
			}
			else {
				if (label_len == 0) {
					/* If name is ended with dot */
					break;
				}
				if (label_len > DNS_D_MAXLABEL) {
					msg_err ("dns name component is longer than 63 bytes, should be stripped");
					label_len = DNS_D_MAXLABEL;
				}
				if (remain < label_len + 1) {
					label_len = remain - 1;
					msg_err ("no buffer remain for constructing query, strip to %ud", label_len);
				}
				*pos++ = (guint8)label_len;
				memcpy (pos, begin, label_len);
				pos += label_len;
				break;
			}
		}
		if (remain == 0) {
			msg_err ("no buffer space available, aborting");
			break;
		}
	}
	/* Termination label */
	*pos = '\0';
	req->pos += pos - (req->packet + req->pos) + 1;
	if (table != NULL) {
		g_list_free (table);
	}
}

static void
make_ptr_req (struct rspamd_dns_request *req, struct in_addr *addr)
{
	gchar                           ipbuf[sizeof("255.255.255.255.in-addr.arpa")];
	guint32                         r;
	guint16                        *p;
	guint8                         *addr_p = (guint8 *)&addr->s_addr;

	r = rspamd_snprintf (ipbuf, sizeof(ipbuf), "%d.%d.%d.%d.in-addr.arpa",
			addr_p[3], addr_p[2], addr_p[1], addr_p[0]);
	allocate_packet (req, r);
	make_dns_header (req);
	format_dns_name (req, ipbuf, r);
	p = (guint16 *)(req->packet + req->pos);
	*p++ = htons (DNS_T_PTR);
	*p = htons (DNS_C_IN);
	req->requested_name = memory_pool_strdup (req->pool, ipbuf);
	req->pos += sizeof (guint16) * 2;
	req->type = DNS_REQUEST_PTR;
}

static void
make_a_req (struct rspamd_dns_request *req, const gchar *name)
{
	guint16 *p;

	allocate_packet (req, strlen (name));
	make_dns_header (req);
	format_dns_name (req, name, 0);
	p = (guint16 *)(req->packet + req->pos);
	*p++ = htons (DNS_T_A);
	*p = htons (DNS_C_IN);
	req->pos += sizeof (guint16) * 2;
	req->type = DNS_REQUEST_A;
	req->requested_name = name;
}

#ifdef HAVE_INET_PTON
static void
make_aaa_req (struct rspamd_dns_request *req, const gchar *name)
{
	guint16 *p;

	allocate_packet (req, strlen (name));
	make_dns_header (req);
	format_dns_name (req, name, 0);
	p = (guint16 *)(req->packet + req->pos);
	*p++ = htons (DNS_T_AAAA);
	*p = htons (DNS_C_IN);
	req->pos += sizeof (guint16) * 2;
	req->type = DNS_REQUEST_AAA;
	req->requested_name = name;
}
#endif

static void
make_txt_req (struct rspamd_dns_request *req, const gchar *name)
{
	guint16 *p;

	allocate_packet (req, strlen (name));
	make_dns_header (req);
	format_dns_name (req, name, 0);
	p = (guint16 *)(req->packet + req->pos);
	*p++ = htons (DNS_T_TXT);
	*p = htons (DNS_C_IN);
	req->pos += sizeof (guint16) * 2;
	req->type = DNS_REQUEST_TXT;
	req->requested_name = name;
}

static void
make_mx_req (struct rspamd_dns_request *req, const gchar *name)
{
	guint16 *p;

	allocate_packet (req, strlen (name));
	make_dns_header (req);
	format_dns_name (req, name, 0);
	p = (guint16 *)(req->packet + req->pos);
	*p++ = htons (DNS_T_MX);
	*p = htons (DNS_C_IN);
	req->pos += sizeof (guint16) * 2;
	req->type = DNS_REQUEST_MX;
	req->requested_name = name;
}

static void
make_srv_req (struct rspamd_dns_request *req, const gchar *service, const gchar *proto, const gchar *name)
{
	guint16 *p;
	guint len;
	gchar *target;

	len = strlen (service) + strlen (proto) + strlen (name) + 5;

	allocate_packet (req, len);
	make_dns_header (req);
	target = memory_pool_alloc (req->pool, len);
	len = rspamd_snprintf (target, len, "_%s._%s.%s", service, proto, name);
	format_dns_name (req, target, len);
	p = (guint16 *)(req->packet + req->pos);
	*p++ = htons (DNS_T_SRV);
	*p = htons (DNS_C_IN);
	req->pos += sizeof (guint16) * 2;
	req->type = DNS_REQUEST_SRV;
	req->requested_name = name;
}

static void
make_spf_req (struct rspamd_dns_request *req, const gchar *name)
{
	guint16 *p;

	allocate_packet (req, strlen (name));
	make_dns_header (req);
	format_dns_name (req, name, 0);
	p = (guint16 *)(req->packet + req->pos);
	*p++ = htons (DNS_T_SPF);
	*p = htons (DNS_C_IN);
	req->pos += sizeof (guint16) * 2;
	req->type = DNS_REQUEST_SPF;
	req->requested_name = name;
}

static void
rspamd_dns_add_edns0 (struct rspamd_dns_request *req)
{
	guint8 *p8;
	guint16 *p16;

	p8 = (guint8 *)(req->packet + req->pos);
	*p8 = '\0'; /* Name is root */
	p16 = (guint16 *)(req->packet + req->pos + 1);
	*p16++ = htons (DNS_T_OPT);
	/* UDP packet length */
	*p16++ = htons (UDP_PACKET_SIZE);
	/* Extended rcode 00 00 */
	*p16++ = 0;
	/* Z 10000000 00000000 to allow dnssec */
	p8 = (guint8 *)p16++;
	/* Not a good time for DNSSEC */
	*p8 = 0x00;
	/* Length */
	*p16 = 0;
	req->pos += sizeof (guint8) + sizeof (guint16) * 5;
}

static gint
send_dns_request (struct rspamd_dns_request *req)
{
	gint r;
	struct rspamd_dns_server *serv = req->io->srv;

	r = send (req->sock, req->packet, req->pos, 0);
	if (r == -1) {
		if (errno == EAGAIN) {
			event_set (&req->io_event, req->sock, EV_WRITE, dns_retransmit_handler, req);
			event_base_set (req->resolver->ev_base, &req->io_event);
			event_add (&req->io_event, &req->tv);
			register_async_event (req->session, (event_finalizer_t)event_del, &req->io_event,
					g_quark_from_static_string ("dns resolver"));
			return 0;
		} 
		else {
			msg_err ("send failed: %s for server %s", strerror (errno), serv->name);
			upstream_fail (&serv->up, req->time);
			return -1;
		}
	}
	else if (r < req->pos) {
		msg_err ("incomplete send over UDP socket, seems to be internal bug");
		event_set (&req->io_event, req->sock, EV_WRITE, dns_retransmit_handler, req);
		event_base_set (req->resolver->ev_base, &req->io_event);
		event_add (&req->io_event, &req->tv);
		register_async_event (req->session, (event_finalizer_t)event_del, &req->io_event,
				g_quark_from_static_string ("dns resolver"));
		return 0;
	}
	
	return 1;
}

static void
dns_fin_cb (gpointer arg)
{
	struct rspamd_dns_request *req = arg;
	
	event_del (&req->timer_event);
	g_hash_table_remove (req->io->requests, &req->id);
}

static guint8 *
decompress_label (guint8 *begin, guint16 *len, guint16 max)
{
	guint16 offset = (*len);

	if (offset > max) {
		msg_info ("invalid DNS compression pointer: %d max is %d", (gint)offset, (gint)max);
		return NULL;
	}
	*len = *(begin + offset);
	return begin + offset;
}

#define UNCOMPRESS_DNS_OFFSET(p) (((*(p)) ^ DNS_COMPRESSION_BITS) << 8) + *((p) + 1)

static guint8 *
dns_request_reply_cmp (struct rspamd_dns_request *req, guint8 *in, gint len)
{
	guint8 *p, *c, *l1, *l2;
	guint16 len1, len2;
	gint decompressed = 0;

	/* QR format:
	 * labels - len:octets
	 * null label - 0
	 * class - 2 octets
	 * type - 2 octets
	 */
	
	/* In p we would store current position in reply and in c - position in request */
	p = in;
	c = req->packet + sizeof (struct dns_header);

	for (;;) {
		/* Get current label */
		len1 = *p;
		len2 = *c;
		if (p - in > len) {
			msg_info ("invalid dns reply");
			return NULL;
		}
		/* This may be compressed, so we need to decompress it */
		if (len1 & DNS_COMPRESSION_BITS) {
			len1 = UNCOMPRESS_DNS_OFFSET(p);
			l1 = decompress_label (in, &len1, len);
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
			len2 = UNCOMPRESS_DNS_OFFSET(p);
			l2 = decompress_label (req->packet, &len2, len);
			if (l2 == NULL) {
				msg_info ("invalid DNS pointer");
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
	if (memcmp (p, c, sizeof (guint16) * 2) == 0) {
		return p + sizeof (guint16) * 2;
	}
	return NULL;
}

#define MAX_RECURSION_LEVEL 10

static gboolean
dns_parse_labels (guint8 *in, gchar **target, guint8 **pos, struct rspamd_dns_reply *rep,
		gint *remain, gboolean make_name)
{
	guint16 namelen = 0;
	guint8 *p = *pos, *begin = *pos, *l, *t, *end = *pos + *remain, *new_pos = *pos;
	guint16 llen;
	gint length = *remain, new_remain = *remain;
	gint ptrs = 0, labels = 0;
	gboolean got_compression = FALSE;

	/* First go through labels and calculate name length */
	while (p - begin < length) {
		if (ptrs > MAX_RECURSION_LEVEL) {
			msg_warn ("dns pointers are nested too much");
			return FALSE;
		}
		llen = *p;
		if (llen == 0) {
			if (!got_compression) {
				/* In case of compression we have already decremented the processing position */
				new_remain -= sizeof (guint8);
				new_pos += sizeof (guint8);
			}
			break;
		}
		else if ((llen & DNS_COMPRESSION_BITS)) {
			if (end - p > 1) {
				ptrs ++;
				llen = UNCOMPRESS_DNS_OFFSET(p);
				l = decompress_label (in, &llen, end - in);
				if (l == NULL) {
					msg_info ("invalid DNS pointer");
					return FALSE;
				}
				if (!got_compression) {
					/* Our label processing is finished actually */
					new_remain -= sizeof (guint16);
					new_pos += sizeof (guint16);
					got_compression = TRUE;
				}
				if (l < in || l > begin + length) {
					msg_warn  ("invalid pointer in DNS packet");
					return FALSE;
				}
				begin = l;
				length = end - begin;
				p = l + *l + 1;
				namelen += *l;
				labels ++;
			}
			else {
				msg_warn ("DNS packet has incomplete compressed label, input length: %d bytes, remain: %d",
						*remain, new_remain);
				return FALSE;
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
	*target = memory_pool_alloc (rep->request->pool, namelen + labels + 3);
	t = (guint8 *)*target;
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
			l = decompress_label (in, &llen, end - in);
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
	*(t - 1) = '\0';
end:
	*remain = new_remain;
	*pos = new_pos;

	return TRUE;
}

#define GET16(x) do {(x) = ((*p) << 8) + *(p + 1); p += sizeof (guint16); *remain -= sizeof (guint16); } while(0)
#define GET32(x) do {(x) = ((*p) << 24) + ((*(p + 1)) << 16) + ((*(p + 2)) << 8) + *(p + 3); p += sizeof (guint32); *remain -= sizeof (guint32); } while(0)

static gint
dns_parse_rr (guint8 *in, union rspamd_reply_element *elt, guint8 **pos, struct rspamd_dns_reply *rep, gint *remain)
{
	guint8 *p = *pos, parts;
	guint16 type, datalen, txtlen, copied;
	gboolean parsed = FALSE;

	/* Skip the whole name */
	if (! dns_parse_labels (in, NULL, &p, rep, remain, FALSE)) {
		msg_info ("bad RR name");
		return -1;
	}
	if (*remain < (gint)sizeof (guint16) * 6) {
		msg_info ("stripped dns reply: %d bytes remain", *remain);
		return -1;
	}
	GET16 (type);
	/* Skip ttl and class */
	p += sizeof (guint16) + sizeof (guint32);
	*remain -= sizeof (guint16) + sizeof (guint32);
	GET16 (datalen);
	/* Now p points to RR data */
	switch (type) {
	case DNS_T_A:
		if (rep->request->type != DNS_REQUEST_A) {
			p += datalen;
		}
		else {
			if (!(datalen & 0x3) && datalen <= *remain) {
				memcpy (&elt->a.addr[0], p, sizeof (struct in_addr));
				p += datalen;
				*remain -= datalen;
				parsed = TRUE;
			}
			else {
				msg_info ("corrupted A record");
				return -1;
			}
		}
		break;
#ifdef HAVE_INET_PTON
	case DNS_T_AAAA:
		if (rep->request->type != DNS_REQUEST_AAA) {
			p += datalen;
			*remain -= datalen;
		}
		else {
			if (datalen == sizeof (struct in6_addr) && datalen <= *remain) {
				memcpy (&elt->aaa.addr, p, sizeof (struct in6_addr));
				p += datalen;
				*remain -= datalen;
				parsed = TRUE;
			}
			else {
				msg_info ("corrupted AAAA record");
				return -1;
			}
		}
		break;
#endif
	case DNS_T_PTR:
		if (rep->request->type != DNS_REQUEST_PTR) {
			p += datalen;
			*remain -= datalen;
		}
		else {
			if (! dns_parse_labels (in, &elt->ptr.name, &p, rep, remain, TRUE)) {
				msg_info ("invalid labels in PTR record");
				return -1;
			}
			parsed = TRUE;
		}
		break;
	case DNS_T_MX:
		if (rep->request->type != DNS_REQUEST_MX) {
			p += datalen;
			*remain -= datalen;
		}
		else {
			GET16 (elt->mx.priority);
			if (! dns_parse_labels (in, &elt->mx.name, &p, rep, remain, TRUE)) {
				msg_info ("invalid labels in MX record");
				return -1;
			}
			parsed = TRUE;
		}
		break;
	case DNS_T_TXT:
		if (rep->request->type != DNS_REQUEST_TXT) {
			p += datalen;
			*remain -= datalen;
		}
		else {
			elt->txt.data = memory_pool_alloc (rep->request->pool, datalen + 1);
			/* Now we should compose data from parts */
			copied = 0;
			parts = 0;
			while (copied + parts < datalen) {
				txtlen = *p;
				if (txtlen + copied + parts <= datalen) {
					parts ++;
					memcpy (elt->txt.data + copied, p + 1, txtlen);
					copied += txtlen;
					p += txtlen + 1;
					*remain -= txtlen + 1;
				}
				else {
					break;
				}
			}
			*(elt->txt.data + copied) = '\0';
			parsed = TRUE;
		}
		break;
	case DNS_T_SPF:
		if (rep->request->type != DNS_REQUEST_SPF) {
			p += datalen;
			*remain -= datalen;
		}
		else {
			copied = 0;
			elt->txt.data = memory_pool_alloc (rep->request->pool, datalen + 1);
			while (copied < datalen) {
				txtlen = *p;
				if (txtlen + copied < datalen) {
					memcpy (elt->txt.data + copied, p + 1, txtlen);
					copied += txtlen;
					p += txtlen + 1;
					*remain -= txtlen + 1;
				}
				else {
					break;
				}
			}
			*(elt->spf.data + copied) = '\0';
			parsed = TRUE;
		}
		break;
	case DNS_T_SRV:
		if (rep->request->type != DNS_REQUEST_SRV) {
			p += datalen;
			*remain -= datalen;
		}
		else {
			if (p - *pos > (gint)(*remain - sizeof (guint16) * 3)) {
				msg_info ("stripped dns reply while reading SRV record");
				return -1;
			}
			GET16 (elt->srv.priority);
			GET16 (elt->srv.weight);
			GET16 (elt->srv.port);
			if (! dns_parse_labels (in, &elt->srv.target, &p, rep, remain, TRUE)) {
				msg_info ("invalid labels in SRV record");
				return -1;
			}
			parsed = TRUE;
		}
		break;
	case DNS_T_CNAME:
		/* Skip cname records */
		p += datalen;
		*remain -= datalen;
		break;
	default:
		msg_debug ("unexpected RR type: %d", type);
		p += datalen;
		*remain -= datalen;
		break;
	}
	*pos = p;

	if (parsed) {
		return 1;
	}
	return 0;
}

static gboolean
dns_parse_reply (gint sock, guint8 *in, gint r, struct rspamd_dns_resolver *resolver,
		struct rspamd_dns_request **req_out, struct rspamd_dns_reply **_rep)
{
	struct dns_header *header = (struct dns_header *)in;
	struct rspamd_dns_request      *req;
	struct rspamd_dns_reply        *rep;
	struct rspamd_dns_io_channel   *ioc;
	union rspamd_reply_element     *elt;
	guint8                         *pos;
	guint16                         id;
	gint                            i, t;
	
	/* First check header fields */
	if (header->qr == 0) {
		msg_info ("got request while waiting for reply");
		return FALSE;
	}

	/* Find io channel */
	if ((ioc = g_hash_table_lookup (resolver->io_channels, GINT_TO_POINTER (sock))) == NULL) {
		msg_err ("io channel is not found for this resolver: %d", sock);
		return FALSE;
	}

	/* Now try to find corresponding request */
	id = header->qid;
	if ((req = g_hash_table_lookup (ioc->requests, &id)) == NULL) {
		/* No such requests found */
		msg_debug ("DNS request with id %d has not been found for IO channel", (gint)id);
		return FALSE;
	}
	*req_out = req;
	/* 
	 * Now we have request and query data is now at the end of header, so compare
	 * request QR section and reply QR section
	 */
	if ((pos = dns_request_reply_cmp (req, in + sizeof (struct dns_header),
			r - sizeof (struct dns_header))) == NULL) {
		msg_debug ("DNS request with id %d is for different query, ignoring", (gint)id);
		return FALSE;
	}
	/*
	 * Now pos is in answer section, so we should extract data and form reply
	 */
	rep = memory_pool_alloc (req->pool, sizeof (struct rspamd_dns_reply));
	rep->request = req;
	rep->type = req->type;
	rep->elements = NULL;
	rep->code = header->rcode;

	if (rep->code == DNS_RC_NOERROR) {
		r -= pos - in;
		/* Extract RR records */
		for (i = 0; i < ntohs (header->ancount); i ++) {
			elt = memory_pool_alloc (req->pool, sizeof (union rspamd_reply_element));
			t = dns_parse_rr (in, elt, &pos, rep, &r);
			if (t == -1) {
				msg_info ("incomplete reply");
				break;
			}
			else if (t == 1) {
				rep->elements = g_list_prepend (rep->elements, elt);
			}
		}
		if (rep->elements) {
			memory_pool_add_destructor (req->pool, (pool_destruct_func)g_list_free, rep->elements);
		}
	}
	
	*_rep = rep;
	return TRUE;
}

static void
dns_throttling_cb (gint fd, short what, void *arg)
{
	struct rspamd_dns_resolver *resolver = arg;

	resolver->throttling = FALSE;
	resolver->errors = 0;
	msg_info ("stop DNS throttling after %d seconds", (int)resolver->throttling_time.tv_sec);
	event_del (&resolver->throttling_event);
}

static void
dns_check_throttling (struct rspamd_dns_resolver *resolver)
{
	if (resolver->errors > resolver->max_errors && !resolver->throttling) {
		msg_info ("starting DNS throttling after %ud errors", resolver->errors);
		/* Init throttling timeout */
		resolver->throttling = TRUE;
		evtimer_set (&resolver->throttling_event, dns_throttling_cb, resolver);
		event_base_set (resolver->ev_base, &resolver->throttling_event);
		event_add (&resolver->throttling_event, &resolver->throttling_time);
	}
}

static void
dns_read_cb (gint fd, short what, void *arg)
{
	struct rspamd_dns_resolver     *resolver = arg;
	struct rspamd_dns_request      *req = NULL;
	gint                            r;
	struct rspamd_dns_reply        *rep;
	guint8                          in[UDP_PACKET_SIZE];

	/* This function is called each time when we have data on one of server's sockets */
	
	/* First read packet from socket */
	r = read (fd, in, sizeof (in));
	if (r > (gint)(sizeof (struct dns_header) + sizeof (struct dns_query))) {
		if (dns_parse_reply (fd, in, r, resolver, &req, &rep)) {
			/* Decrease errors count */
			if (rep->request->resolver->errors > 0) {
				rep->request->resolver->errors --;
			}
			upstream_ok (&rep->request->io->srv->up, rep->request->time);
			rep->request->func (rep, rep->request->arg);
			remove_normal_event (req->session, dns_fin_cb, req);
		}
	}
}

static void
dns_timer_cb (gint fd, short what, void *arg)
{
	struct rspamd_dns_request *req = arg;
	struct rspamd_dns_reply *rep;
	struct rspamd_dns_server *serv;
	gint                            r;
	
	/* Retransmit dns request */
	req->retransmits ++;
	serv = req->io->srv;
	if (req->retransmits >= req->resolver->max_retransmits) {
		msg_err ("maximum number of retransmits expired for resolving %s of type %s",
				req->requested_name, dns_strtype (req->type));
		dns_check_throttling (req->resolver);
		req->resolver->errors ++;
		goto err;
	}

	if (req->sock == -1) {
		goto err;
	}
	/* Add other retransmit event */
	r = send_dns_request (req);
	if (r == -1) {
		goto err;
	}

	msg_debug ("retransmit DNS request with ID %d", (int)req->id);
	evtimer_add (&req->timer_event, &req->tv);

	return;
err:
	msg_debug ("error on retransmitting DNS request with ID %d", (int)req->id);
	rep = memory_pool_alloc0 (req->pool, sizeof (struct rspamd_dns_reply));
	rep->request = req;
	rep->code = DNS_RC_SERVFAIL;
	if (serv) {
		upstream_fail (&serv->up, rep->request->time);
	}
	req->func (rep, req->arg);
	remove_normal_event (req->session, dns_fin_cb, req);
	return;
}

static void
dns_retransmit_handler (gint fd, short what, void *arg)
{
	struct rspamd_dns_request *req = arg;
	struct rspamd_dns_reply *rep;
	struct rspamd_dns_server *serv;
	gint r;

	remove_normal_event (req->session, (event_finalizer_t)event_del, &req->io_event);
	serv = req->io->srv;

	if (what == EV_WRITE) {
		/* Retransmit dns request */
		req->retransmits ++;
		event_del (&req->io_event);
		if (req->retransmits >= req->resolver->max_retransmits) {
			msg_err ("maximum number of retransmits expired for %s", req->requested_name);
			rep = memory_pool_alloc0 (req->pool, sizeof (struct rspamd_dns_reply));
			rep->request = req;
			rep->code = DNS_RC_SERVFAIL;
			upstream_fail (&serv->up, rep->request->time);
			req->resolver->errors ++;
			dns_check_throttling (req->resolver);

			req->func (rep, req->arg);

			return;
		}
		r = send_dns_request (req);
		if (r == -1) {
			rep = memory_pool_alloc0 (req->pool, sizeof (struct rspamd_dns_reply));
			rep->request = req;
			rep->code = DNS_RC_SERVFAIL;
			upstream_fail (&serv->up, rep->request->time);
			req->func (rep, req->arg);

		}
		else if (r == 1) {
			/* Add timer event */
			event_del (&req->timer_event);
			evtimer_set (&req->timer_event, dns_timer_cb, req);
			event_base_set (req->resolver->ev_base, &req->timer_event);
			evtimer_add (&req->timer_event, &req->tv);

			/* Add request to hash table */
			g_hash_table_insert (req->io->requests, &req->id, req);
			register_async_event (req->session, (event_finalizer_t)dns_fin_cb,
					req, g_quark_from_static_string ("dns resolver"));
		}
	}
}

gboolean 
make_dns_request (struct rspamd_dns_resolver *resolver,
		struct rspamd_async_session *session, memory_pool_t *pool, dns_callback_type cb, 
		gpointer ud, enum rspamd_request_type type, ...)
{
	va_list args;
	struct rspamd_dns_request *req;
	struct rspamd_dns_server *serv;
	struct in_addr *addr;
	const gchar *name, *service, *proto;
	gint r;
	const gint max_id_cycles = 32;
	struct dns_header *header;

	/* If no DNS servers defined silently return FALSE */
	if (resolver->servers_num == 0) {
		return FALSE;
	}
	/* Check throttling */
	if (resolver->throttling) {
		return FALSE;
	}

	req = memory_pool_alloc (pool, sizeof (struct rspamd_dns_request));
	req->pool = pool;
	req->session = session;
	req->resolver = resolver;
	req->func = cb;
	req->arg = ud;
	req->type = type;
	
	va_start (args, type);
	switch (type) {
		case DNS_REQUEST_PTR:
			addr = va_arg (args, struct in_addr *);
			make_ptr_req (req, addr);
			break;
		case DNS_REQUEST_MX:
			name = va_arg (args, const gchar *);
			make_mx_req (req, name);
			break;
		case DNS_REQUEST_A:
			name = va_arg (args, const gchar *);
			make_a_req (req, name);
			break;
		case DNS_REQUEST_AAA:
#ifdef HAVE_INET_PTON
			name = va_arg (args, const gchar *);
			make_aaa_req (req, name);
			break;
#else
			msg_err ("your system has no ipv6 support, cannot make aaa request");
			break;
#endif
		case DNS_REQUEST_TXT:
			name = va_arg (args, const gchar *);
			make_txt_req (req, name);
			break;
		case DNS_REQUEST_SPF:
			name = va_arg (args, const gchar *);
			make_spf_req (req, name);
			break;
		case DNS_REQUEST_SRV:
			service = va_arg (args, const gchar *);
			proto = va_arg (args, const gchar *);
			name = va_arg (args, const gchar *);
			make_srv_req (req, service, proto, name);
			break;
	}
	va_end (args);

	/* Add EDNS RR */
	rspamd_dns_add_edns0 (req);

	req->retransmits = 0;
	req->time = time (NULL);
	if (resolver->is_master_slave) {
		serv = (struct rspamd_dns_server *)get_upstream_master_slave (resolver->servers,
				resolver->servers_num, sizeof (struct rspamd_dns_server),
				req->time, DEFAULT_UPSTREAM_ERROR_TIME, DEFAULT_UPSTREAM_DEAD_TIME, DEFAULT_UPSTREAM_MAXERRORS);
	}
	else {
		serv = (struct rspamd_dns_server *)get_upstream_round_robin (resolver->servers,
				resolver->servers_num, sizeof (struct rspamd_dns_server),
				req->time, DEFAULT_UPSTREAM_ERROR_TIME, DEFAULT_UPSTREAM_DEAD_TIME, DEFAULT_UPSTREAM_MAXERRORS);
	}
	if (serv == NULL) {
		msg_err ("cannot find suitable server for request");
		return FALSE;
	}
	
	/* Now select IO channel */

	req->io = serv->cur_io_channel;
	if (req->io == NULL) {
		msg_err ("cannot find suitable io channel for the server %s", serv->name);
		return FALSE;
	}
	serv->cur_io_channel = serv->cur_io_channel->next;
	req->sock = req->io->sock;

	if (req->sock == -1) {
		return FALSE;
	}

	/* Fill timeout */
	msec_to_tv (resolver->request_timeout, &req->tv);
	evtimer_set (&req->timer_event, dns_timer_cb, req);
	event_base_set (req->resolver->ev_base, &req->timer_event);
	
	/* Now send request to server */
	r = send_dns_request (req);

	if (r == 1) {
		/* Add request to hash table */
		r = 0;
		while (g_hash_table_lookup (req->io->requests, &req->id)) {
			/* Check for unique id */
			header = (struct dns_header *)req->packet;
			header->qid = dns_permutor_generate_id (resolver->permutor);
			req->id = header->qid;
			if (++r > max_id_cycles) {
				msg_err ("cannot generate new id for server %s", serv->name);
				return FALSE;
			}
		}
		/* Add timer event */
		evtimer_add (&req->timer_event, &req->tv);
		g_hash_table_insert (req->io->requests, &req->id, req);
		register_async_event (session, (event_finalizer_t)dns_fin_cb, req,
				g_quark_from_static_string ("dns resolver"));
	}
	else if (r == -1) {
		return FALSE;
	}

	return TRUE;
}

#define RESOLV_CONF "/etc/resolv.conf"

static gboolean
parse_resolv_conf (struct rspamd_dns_resolver *resolver)
{
	FILE                           *r;
	gchar                           buf[BUFSIZ], *p, addr_holder[16];
	struct rspamd_dns_server       *new;

	r = fopen (RESOLV_CONF, "r");

	if (r == NULL) {
		msg_err ("cannot open %s: %s", RESOLV_CONF, strerror (errno));
		return FALSE;
	}
	
	while (! feof (r)) {
		if (fgets (buf, sizeof (buf), r)) {
			g_strstrip (buf);
			if (g_ascii_strncasecmp (buf, "nameserver", sizeof ("nameserver") - 1) == 0) {
				p = buf + sizeof ("nameserver");
				while (*p && g_ascii_isspace (*p)) {
					p ++;
				}
				if (! *p) {
					msg_warn ("cannot parse empty nameserver line in resolv.conf");
					continue;
				}
				else {
					if (inet_pton (AF_INET6, p, addr_holder) == 1 ||
							inet_pton (AF_INET, p, addr_holder) == 1) {
						new = &resolver->servers[resolver->servers_num];
						new->name = memory_pool_strdup (resolver->static_pool, p);
						resolver->servers_num ++;
					}
					else {
						msg_warn ("cannot parse ip address of nameserver: %s", p);
						continue;
					}
				}
			}
		}
	}

	fclose (r);
	return TRUE;
}

/* Hashing utilities */
static gboolean
dns_id_equal (gconstpointer v1, gconstpointer v2)
{
	return *((const guint16*) v1) == *((const guint16*) v2);
}

static guint
dns_id_hash (gconstpointer v)
{
	return *(const guint16 *) v;
}


struct rspamd_dns_resolver *
dns_resolver_init (struct event_base *ev_base, struct config_file *cfg)
{
	GList                          *cur;
	struct rspamd_dns_resolver     *new;
	gchar                          *begin, *p, *err, addr_holder[16];
	gint                            priority, i, j;
	struct rspamd_dns_server       *serv;
	struct rspamd_dns_io_channel   *ioc;
	
	new = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct rspamd_dns_resolver));
	new->ev_base = ev_base;
	new->permutor = dns_permutor_new (cfg->cfg_pool);
	new->io_channels = g_hash_table_new (g_direct_hash, g_direct_equal);
	new->static_pool = cfg->cfg_pool;
	new->request_timeout = cfg->dns_timeout;
	new->max_retransmits = cfg->dns_retransmits;
	new->max_errors = cfg->dns_throttling_errors;
	msec_to_tv (cfg->dns_throttling_time, &new->throttling_time);

	if (cfg->nameservers == NULL) {
		/* Parse resolv.conf */
		if (! parse_resolv_conf (new) || new->servers_num == 0) {
			msg_err ("cannot parse resolv.conf and no nameservers defined, so no ways to resolve addresses");
			return new;
		}
	}
	else {
		cur = cfg->nameservers;
		while (cur) {
			begin = cur->data;
			p = strchr (begin, ':');
			if (p != NULL) {
				*p = '\0';
				p ++;
				if (!new->is_master_slave) {
					priority = strtoul (p, &err, 10);
					if (err != NULL && (*err == 'm' || *err == 'M' || *err == 's' || *err == 'S')) {
						new->is_master_slave = TRUE;
					}
					else {
						msg_info ("bad character '%c', must be 'm' or 's' or a numeric priority", *err);
					}
				}
				if (new->is_master_slave) {
					if (*p == 'm' || *p == 'M') {
						priority = 100;
					}
					else if (*p == 's' || *p == 'S') {
						priority = 1;
					}
					else {
						msg_info ("master/slave mode is turned on, and %c character is invalid", *p);
						priority = 0;
					}
				}
			}
			else {
				priority = 0;
			}
			serv = &new->servers[new->servers_num];
			if (inet_pton (AF_INET6, p, addr_holder) == 1 ||
				inet_pton (AF_INET, p, addr_holder) == 1) {
				serv->name = memory_pool_strdup (new->static_pool, begin);
				serv->up.priority = priority;
				new->servers_num ++;
			}
			else {
				msg_warn ("cannot parse ip address of nameserver: %s", p);
				cur = g_list_next (cur);
				continue;
			}

			cur = g_list_next (cur);
		}
		if (new->servers_num == 0) {
			msg_err ("no valid nameservers defined, try to parse resolv.conf");
			if (! parse_resolv_conf (new) || new->servers_num == 0) {
				msg_err ("cannot parse resolv.conf and no nameservers defined, so no ways to resolve addresses");
				return new;
			}
		}

	}
	/* Now init io channels to all servers */
	for (i = 0; i < new->servers_num; i ++) {
		serv = &new->servers[i];
		for (j = 0; j < (gint)cfg->dns_io_per_server; j ++) {
			ioc = memory_pool_alloc (new->static_pool, sizeof (struct rspamd_dns_io_channel));
			ioc->sock = make_universal_socket (serv->name, dns_port, SOCK_DGRAM, TRUE, FALSE, FALSE);
			if (ioc->sock == -1) {
				msg_warn ("cannot create socket to server %s", serv->name);
			}
			else {
				ioc->requests = g_hash_table_new (dns_id_hash, dns_id_equal);
				memory_pool_add_destructor (new->static_pool, (pool_destruct_func)g_hash_table_unref,
						ioc->requests);
				ioc->srv = serv;
				ioc->resolver = new;
				event_set (&ioc->ev, ioc->sock, EV_READ | EV_PERSIST, dns_read_cb, new);
				event_base_set (new->ev_base, &ioc->ev);
				event_add (&ioc->ev, NULL);
				CDL_PREPEND (serv->io_channels, ioc);
				serv->cur_io_channel = ioc;
				g_hash_table_insert (new->io_channels, GINT_TO_POINTER (ioc->sock), ioc);
			}
		}
	}

	return new;
}

static gchar dns_rcodes[16][16] = {
	[DNS_RC_NOERROR]  = "NOERROR",
	[DNS_RC_FORMERR]  = "FORMERR",
	[DNS_RC_SERVFAIL] = "SERVFAIL",
	[DNS_RC_NXDOMAIN] = "NXDOMAIN",
	[DNS_RC_NOTIMP]   = "NOTIMP",
	[DNS_RC_REFUSED]  = "REFUSED",
	[DNS_RC_YXDOMAIN] = "YXDOMAIN",
	[DNS_RC_YXRRSET]  = "YXRRSET",
	[DNS_RC_NXRRSET]  = "NXRRSET",
	[DNS_RC_NOTAUTH]  = "NOTAUTH",
	[DNS_RC_NOTZONE]  = "NOTZONE",
};

const gchar *
dns_strerror (enum dns_rcode rcode)
{
	rcode &= 0xf;
	static gchar numbuf[16];

	if ('\0' == dns_rcodes[rcode][0]) {
		rspamd_snprintf (numbuf, sizeof (numbuf), "UNKNOWN: %d", (gint)rcode);
		return numbuf;
	}
	return dns_rcodes[rcode];
}

static gchar dns_types[7][16] = {
		[DNS_REQUEST_A] = "A request",
		[DNS_REQUEST_PTR] = "PTR request",
		[DNS_REQUEST_MX] = "MX request",
		[DNS_REQUEST_TXT] = "TXT request",
		[DNS_REQUEST_SRV] = "SRV request",
		[DNS_REQUEST_SPF] = "SPF request",
		[DNS_REQUEST_AAA] = "AAA request"
};

const gchar *
dns_strtype (enum rspamd_request_type type)
{
	return dns_types[type];
}
