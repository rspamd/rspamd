/*
 * Copyright (c) 2009, Rambler media
 * Copyright (c) 2008, 2009, 2010  William Ahern
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
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* 
 * Rspamd resolver library is based on code written by William Ahern.
 *
 * The original library can be found at: http://25thandclement.com/~william/projects/dns.c.html
 */

#include "config.h"
#include "dns.h"
#include "main.h"

/* Upstream timeouts */
#define DEFAULT_UPSTREAM_ERROR_TIME 10
#define DEFAULT_UPSTREAM_DEAD_TIME 300
#define DEFAULT_UPSTREAM_MAXERRORS 10

#ifdef HAVE_ARC4RANDOM
#define DNS_RANDOM arc4random
#elif defined HAVE_RANDOM
#define DNS_RANDOM random
#else
#define DNS_RANDOM rand
#endif

/*
 * P E R M U T A T I O N  G E N E R A T O R
 */

#define DNS_K_TEA_BLOCK_SIZE	8
#define DNS_K_TEA_CYCLES	32
#define DNS_K_TEA_MAGIC		0x9E3779B9U

static void dns_retransmit_handler (int fd, short what, void *arg);


static void 
dns_k_tea_init(struct dns_k_tea *tea, uint32_t key[], unsigned cycles) 
{
	memcpy(tea->key, key, sizeof tea->key);

	tea->cycles	= (cycles)? cycles : DNS_K_TEA_CYCLES;
} /* dns_k_tea_init() */


static void 
dns_k_tea_encrypt (struct dns_k_tea *tea, uint32_t v[], uint32_t *w) 
{
	guint32 y, z, sum, n;

	y	= v[0];
	z	= v[1];
	sum	= 0;

	for (n = 0; n < tea->cycles; n++) {
		sum	+= DNS_K_TEA_MAGIC;
		y	+= ((z << 4) + tea->key[0]) ^ (z + sum) ^ ((z >> 5) + tea->key[1]);
		z	+= ((y << 4) + tea->key[2]) ^ (y + sum) ^ ((y >> 5) + tea->key[3]);
	}

	w[0]	= y;
	w[1]	= z;

} /* dns_k_tea_encrypt() */


/*
 * Permutation generator, based on a Luby-Rackoff Feistel construction.
 *
 * Specifically, this is a generic balanced Feistel block cipher using TEA
 * (another block cipher) as the pseudo-random function, F. At best it's as
 * strong as F (TEA), notwithstanding the seeding. F could be AES, SHA-1, or
 * perhaps Bernstein's Salsa20 core; I am naively trying to keep things
 * simple.
 *
 * The generator can create a permutation of any set of numbers, as long as
 * the size of the set is an even power of 2. This limitation arises either
 * out of an inherent property of balanced Feistel constructions, or by my
 * own ignorance. I'll tackle an unbalanced construction after I wrap my
 * head around Schneier and Kelsey's paper.
 *
 * CAVEAT EMPTOR. IANAC.
 */
#define DNS_K_PERMUTOR_ROUNDS	8



static inline unsigned int
dns_k_permutor_powof (unsigned int n) 
{
	unsigned int m, i = 0;

	for (m = 1; m < n; m <<= 1, i++);

	return i;
} /* dns_k_permutor_powof() */

static void 
dns_k_permutor_init (struct dns_k_permutor *p, unsigned low, unsigned high) 
{
	uint32_t key[DNS_K_TEA_KEY_SIZE / sizeof (uint32_t)];
	unsigned width, i;

	p->stepi	= 0;

	p->length	= (high - low) + 1;
	p->limit	= high;

	width		= dns_k_permutor_powof (p->length);
	width		+= width % 2;

	p->shift	= width / 2;
	p->mask		= (1U << p->shift) - 1;
	p->rounds	= DNS_K_PERMUTOR_ROUNDS;

	for (i = 0; i < G_N_ELEMENTS (key); i++) {
		key[i]	= DNS_RANDOM ();
	}

	dns_k_tea_init (&p->tea, key, 0);

} /* dns_k_permutor_init() */


static unsigned 
dns_k_permutor_F (struct dns_k_permutor *p, unsigned k, unsigned x) 
{
	uint32_t in[DNS_K_TEA_BLOCK_SIZE / sizeof (uint32_t)], out[DNS_K_TEA_BLOCK_SIZE / sizeof (uint32_t)];

	memset(in, '\0', sizeof in);

	in[0]	= k;
	in[1]	= x;

	dns_k_tea_encrypt (&p->tea, in, out);

	return p->mask & out[0];
} /* dns_k_permutor_F() */


static unsigned 
dns_k_permutor_E (struct dns_k_permutor *p, unsigned n) 
{
	unsigned l[2], r[2];
	unsigned i;

	i	= 0;
	l[i]	= p->mask & (n >> p->shift);
	r[i]	= p->mask & (n >> 0);

	do {
		l[(i + 1) % 2]	= r[i % 2];
		r[(i + 1) % 2]	= l[i % 2] ^ dns_k_permutor_F(p, i, r[i % 2]);

		i++;
	} while (i < p->rounds - 1);

	return ((l[i % 2] & p->mask) << p->shift) | ((r[i % 2] & p->mask) << 0);
} /* dns_k_permutor_E() */


static unsigned 
dns_k_permutor_D (struct dns_k_permutor *p, unsigned n) 
{
	unsigned l[2], r[2];
	unsigned i;

	i		= p->rounds - 1;
	l[i % 2]	= p->mask & (n >> p->shift);
	r[i % 2]	= p->mask & (n >> 0);

	do {
		i--;

		r[i % 2]	= l[(i + 1) % 2];
		l[i % 2]	= r[(i + 1) % 2] ^ dns_k_permutor_F(p, i, l[(i + 1) % 2]);
	} while (i > 0);

	return ((l[i % 2] & p->mask) << p->shift) | ((r[i % 2] & p->mask) << 0);
} /* dns_k_permutor_D() */


static unsigned 
dns_k_permutor_step(struct dns_k_permutor *p) 
{
	unsigned n;

	do {
		n	= dns_k_permutor_E(p, p->stepi++);
	} while (n >= p->length);

	return n + (p->limit + 1 - p->length);
} /* dns_k_permutor_step() */


/*
 * Simple permutation box. Useful for shuffling rrsets from an iterator.
 * Uses AES s-box to provide good diffusion.
 */
static unsigned short 
dns_k_shuffle16 (unsigned short n, unsigned s) 
{
	static const unsigned char sbox[256] =
	{ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
	  0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
	  0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
	  0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
	  0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
	  0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
	  0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
	  0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
	  0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
	  0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
	  0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
	  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
	  0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
	  0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
	  0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
	  0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
	  0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
	unsigned char a, b;
	unsigned i;

	a = 0xff & (n >> 0);
	b = 0xff & (n >> 8);

	for (i = 0; i < 4; i++) {
		a ^= 0xff & s;
		a = sbox[a] ^ b;
		b = sbox[b] ^ a;
		s >>= 8;
	}

	return ((0xff00 & (a << 8)) | (0x00ff & (b << 0)));
} /* dns_k_shuffle16() */

struct dns_request_key {
	guint16 id;
	guint16 port;
};


struct rspamd_dns_resolver *
dns_resolver_init (void)
{
	struct rspamd_dns_resolver *res;

	res = g_malloc0 (sizeof (struct rspamd_dns_resolver));
	
	res->requests = g_hash_table_new (g_direct_hash, g_direct_equal);
	res->permutor = g_malloc (sizeof (struct dns_k_permutor));
	dns_k_permutor_init (res->permutor, 0, G_MAXUINT16);

	return res;
}

/** Packet creating functions */
static void
allocate_packet (struct rspamd_dns_request *req, guint namelen)
{
	namelen += 96 /* header */
		+ 2 /* Trailing label */
		+ 4; /* Resource type */
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
	header->qid = dns_k_permutor_step (req->resolver->permutor);
	header->rd = 1;
	header->qdcount = 1;
	req->pos += sizeof (struct dns_header);
	req->id = header->qid;
}

static void
format_dns_name (struct rspamd_dns_request *req, const char *name, guint namelen)
{
	guint8 *pos = req->packet + req->pos, *begin, *end;
	guint remain = req->packet_len - req->pos - 5, label_len;

	if (namelen == 0) {
		namelen = strlen (name);
	}
	
	begin = (guint8 *)name;
	for (;;) {
		end = strchr (begin, '.');
		if (end) {
			label_len = end - begin;
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
			remain -= label_len + 1;
			begin = end + 1;
		}
		else {
			end = (guint8 *)name + namelen;
			label_len = end - begin;
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
			remain -= label_len + 1;
			break;
		}
		if (remain == 0) {
			msg_err ("no buffer space available, aborting");
			break;
		}
	}
	/* Termination label */
	*(++pos) = '\0';
	req->pos += pos - (req->packet + req->pos) + 1;
}

static void
make_ptr_req (struct rspamd_dns_request *req, struct in_addr addr)
{
	char ipbuf[sizeof("255.255.255.255.in-addr.arpa")];
	guint32 a = addr.s_addr, r;
	guint16 *p;

	r = rspamd_snprintf (ipbuf, sizeof(ipbuf), "%d.%d.%d.%d.in-addr.arpa",
			(int)(guint8)((a	) & 0xff),
			(int)(guint8)((a>>8 ) & 0xff),
			(int)(guint8)((a>>16) & 0xff),
			(int)(guint8)((a>>24) & 0xff));
	
	allocate_packet (req, r);
	make_dns_header (req);
	format_dns_name (req, ipbuf, r);
	p = (guint16 *)req->packet + req->pos;
	*p++ = htons (DNS_C_IN);
	*p = htons (DNS_T_PTR);
	req->pos += sizeof (guint16) * 2;
}

static void
make_a_req (struct rspamd_dns_request *req, const char *name)
{
	guint16 *p;

	allocate_packet (req, strlen (name));
	make_dns_header (req);
	format_dns_name (req, name, 0);
	p = (guint16 *)req->packet + req->pos;
	*p++ = htons (DNS_C_IN);
	*p = htons (DNS_T_A);
	req->pos += sizeof (guint16) * 2;
}

static void
make_txt_req (struct rspamd_dns_request *req, const char *name)
{
	guint16 *p;

	allocate_packet (req, strlen (name));
	make_dns_header (req);
	format_dns_name (req, name, 0);
	p = (guint16 *)req->packet + req->pos;
	*p++ = htons (DNS_C_IN);
	*p = htons (DNS_T_A);
	req->pos += sizeof (guint16) * 2;
	
}

static void
make_mx_req (struct rspamd_dns_request *req, const char *name)
{
	guint16 *p;

	allocate_packet (req, strlen (name));
	make_dns_header (req);
	format_dns_name (req, name, 0);
	p = (guint16 *)req->packet + req->pos;
	*p++ = htons (DNS_C_IN);
	*p = htons (DNS_T_A);
	req->pos += sizeof (guint16) * 2;
	
}

static int
send_dns_request (struct rspamd_dns_request *req)
{
	gint r;

	r = send (req->sock, req->packet, req->pos, 0);
	if (r == -1) {
		if (errno == EAGAIN) {
			event_set (&req->io_event, req->sock, EV_WRITE, dns_retransmit_handler, req);
			event_add (&req->io_event, &req->tv);
			register_async_event (req->session, (event_finalizer_t)event_del, &req->io_event, FALSE);
			return 0;
		} 
		else {
			msg_err ("send failed: %s for server %s", strerror (errno), req->server->name);
			upstream_fail (&req->server->up, time (NULL));
			return -1;
		}
	}
	else if (r < req->pos) {
		event_set (&req->io_event, req->sock, EV_WRITE, dns_retransmit_handler, req);
		event_add (&req->io_event, &req->tv);
		register_async_event (req->session, (event_finalizer_t)event_del, &req->io_event, FALSE);
		return 0;
	}
	
	return 1;
}

static void
dns_fin_cb (gpointer arg)
{
	struct rspamd_dns_request *req = arg;
	
	/* XXX: call callback if possible */
}

static void
dns_timer_cb (int fd, short what, void *arg)
{
	struct rspamd_dns_request *req = arg;

	
	/* Retransmit dns request */
	req->retransmits ++;
	if (req->retransmits >= req->resolver->max_retransmits) {
		msg_err ("maximum number of retransmits expired");
		event_del (&req->timer_event);
		/* XXX: call user's callback here */
		return;
	}
	/* Select other server */
	req->server = (struct rspamd_dns_server *)get_upstream_round_robin (req->resolver->servers, 
			req->resolver->servers_num, sizeof (struct rspamd_dns_server),
			time (NULL), DEFAULT_UPSTREAM_ERROR_TIME, DEFAULT_UPSTREAM_DEAD_TIME, DEFAULT_UPSTREAM_MAXERRORS);
	if (req->server == NULL) {
		event_del (&req->timer_event);
		/* XXX: call user's callback here */
		return;
	}
	
	if (req->server->sock == -1) {
		req->server->sock = make_udp_socket (&req->server->addr, htons (53), FALSE, TRUE);
	}
	req->sock = req->server->sock;

	if (req->sock == -1) {
		event_del (&req->timer_event);
		/* XXX: call user's callback here */
		return;
	}
	/* Add other retransmit event */

	evtimer_add (&req->timer_event, &req->tv);
}

static void
dns_retransmit_handler (int fd, short what, void *arg)
{
	struct rspamd_dns_request *req = arg;
	gint r;

	if (what == EV_WRITE) {
		/* Retransmit dns request */
		req->retransmits ++;
		if (req->retransmits >= req->resolver->max_retransmits) {
			msg_err ("maximum number of retransmits expired");
			event_del (&req->io_event);
			/* XXX: call user's callback here */
			return;
		}
		r = send_dns_request (req);
		if (r == -1) {
			event_del (&req->io_event);
			/* XXX: call user's callback here */
			upstream_fail (&req->server->up, time (NULL));
		}
		else if (r == 1) {
			/* Add timer event */
			evtimer_set (&req->timer_event, dns_timer_cb, req);
			evtimer_add (&req->timer_event, &req->tv);

			/* Add request to hash table */
			g_hash_table_insert (req->resolver->requests, GUINT_TO_POINTER (req->id), req); 
			register_async_event (req->session, (event_finalizer_t)dns_fin_cb, req, FALSE);
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
	struct in_addr addr;
	const char *name;
	gint r;

	req = memory_pool_alloc (pool, sizeof (struct rspamd_dns_request));
	req->pool = pool;
	req->session = session;
	req->resolver = resolver;
	req->func = cb;
	req->arg = ud;
	
	va_start (args, type);
	switch (type) {
		case DNS_REQUEST_PTR:
			addr = va_arg (args, struct in_addr);
			make_ptr_req (req, addr);
			break;
		case DNS_REQUEST_MX:
			name = va_arg (args, const char *);
			make_mx_req (req, name);
			break;
		case DNS_REQUEST_A:
			name = va_arg (args, const char *);
			make_a_req (req, name);
			break;
		case DNS_REQUEST_TXT:
			name = va_arg (args, const char *);
			make_txt_req (req, name);
			break;
	}
	va_end (args);

	req->retransmits = 0;
	req->server = (struct rspamd_dns_server *)get_upstream_round_robin (resolver->servers, 
			resolver->servers_num, sizeof (struct rspamd_dns_server),
			time (NULL), DEFAULT_UPSTREAM_ERROR_TIME, DEFAULT_UPSTREAM_DEAD_TIME, DEFAULT_UPSTREAM_MAXERRORS);
	if (req->server == NULL) {
		msg_err ("cannot find suitable server for request");
		return FALSE;
	}
	
	if (req->server->sock == -1) {
		req->server->sock = make_udp_socket (&req->server->addr, htons (53), FALSE, TRUE);
	}
	req->sock = req->server->sock;

	if (req->sock == -1) {
		return FALSE;
	}

	/* Fill timeout */
	req->tv.tv_sec = resolver->request_timeout / 1000;
	req->tv.tv_usec = (resolver->request_timeout - req->tv.tv_sec * 1000) * 1000;
	
	/* Now send request to server */
	r = send_dns_request (req);

	if (r == 1) {
		/* Add timer event */
		evtimer_set (&req->timer_event, dns_timer_cb, req);
		evtimer_add (&req->timer_event, &req->tv);

		/* Add request to hash table */
		g_hash_table_insert (resolver->requests, GUINT_TO_POINTER (req->id), req); 
		register_async_event (session, (event_finalizer_t)dns_fin_cb, req, FALSE);
	}
	else if (r == -1) {
		return FALSE;
	}

	return TRUE;
}
