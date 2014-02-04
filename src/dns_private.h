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

#ifndef DNS_PRIVATE_H_
#define DNS_PRIVATE_H_

#include "config.h"

#define MAX_SERVERS 16
/* Upstream timeouts */
#define DEFAULT_UPSTREAM_ERROR_TIME 10
#define DEFAULT_UPSTREAM_DEAD_TIME 300
#define DEFAULT_UPSTREAM_MAXERRORS 10

static const unsigned base = 36;
static const unsigned t_min = 1;
static const unsigned t_max = 26;
static const unsigned skew = 38;
static const unsigned damp = 700;
static const unsigned initial_n = 128;
static const unsigned initial_bias = 72;

static const gint dns_port = 53;

#define UDP_PACKET_SIZE 4096

#define DNS_COMPRESSION_BITS 0xC0

#define DNS_D_MAXLABEL  63      /* + 1 '\0' */
#define DNS_D_MAXNAME   255     /* + 1 '\0' */

#define RESOLV_CONF "/etc/resolv.conf"

/**
 * Represents DNS server
 */
struct rspamd_dns_server {
	struct upstream up; /**< upstream structure                                         */
	gchar *name; /**< name of DNS server                                         */
	struct rspamd_dns_io_channel *io_channels;
	struct rspamd_dns_io_channel *cur_io_channel;
};

/**
 * IO channel for a specific DNS server
 */
struct rspamd_dns_io_channel {
	struct rspamd_dns_server *srv;
	struct rspamd_dns_resolver *resolver;
	gint sock; /**< persistent socket                                          */
	struct event ev;
	GHashTable *requests; /**< requests in flight                                         */
	struct rspamd_dns_io_channel *prev, *next;
};


struct rspamd_dns_resolver {
	struct rspamd_dns_server servers[MAX_SERVERS];
	gint servers_num; /**< number of DNS servers registered           */
	guint request_timeout;
	guint max_retransmits;
	guint max_errors;
	GHashTable *io_channels; /**< hash of io chains indexed by socket        */
	gboolean throttling; /**< dns servers are busy                                       */
	gboolean is_master_slave; /**< if this is true, then select upstreams as master/slave */
	guint errors; /**< resolver errors                                            */
	struct timeval throttling_time; /**< throttling time                                            */
	struct event throttling_event; /**< throttling event                                           */
	struct event_base *ev_base; /**< base for event ops                                         */
};

struct dns_header;
struct dns_query;

/* Internal DNS structs */

struct dns_header {
	guint qid :16;

#if BYTE_ORDER == BIG_ENDIAN
	guint qr:1;
	guint opcode:4;
	guint aa:1;
	guint tc:1;
	guint rd:1;

	guint ra:1;
	guint unused:3;
	guint rcode:4;
#else
	guint rd :1;
	guint tc :1;
	guint aa :1;
	guint opcode :4;
	guint qr :1;

	guint rcode :4;
	guint unused :3;
	guint ra :1;
#endif

	guint qdcount :16;
	guint ancount :16;
	guint nscount :16;
	guint arcount :16;
};

enum dns_section {
	DNS_S_QD = 0x01,
#define DNS_S_QUESTION          DNS_S_QD

	DNS_S_AN = 0x02,
#define DNS_S_ANSWER            DNS_S_AN

	DNS_S_NS = 0x04,
#define DNS_S_AUTHORITY         DNS_S_NS

	DNS_S_AR = 0x08,
#define DNS_S_ADDITIONAL        DNS_S_AR

	DNS_S_ALL = 0x0f
};
/* enum dns_section */

enum dns_opcode {
	DNS_OP_QUERY = 0,
	DNS_OP_IQUERY = 1,
	DNS_OP_STATUS = 2,
	DNS_OP_NOTIFY = 4,
	DNS_OP_UPDATE = 5,
};
/* dns_opcode */

enum dns_class {
	DNS_C_IN = 1,

	DNS_C_ANY = 255
};
/* enum dns_class */

struct dns_query {
	gchar *qname;
	guint qtype :16;
	guint qclass :16;
};

enum dns_type {
	DNS_T_A = 1,
	DNS_T_NS = 2,
	DNS_T_CNAME = 5,
	DNS_T_SOA = 6,
	DNS_T_PTR = 12,
	DNS_T_MX = 15,
	DNS_T_TXT = 16,
	DNS_T_AAAA = 28,
	DNS_T_SRV = 33,
	DNS_T_OPT = 41,
	DNS_T_SSHFP = 44,
	DNS_T_SPF = 99,

	DNS_T_ALL = 255
};
/* enum dns_type */

static const gchar dns_rcodes[16][16] = {
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

static const gchar dns_types[7][16] = {
		[DNS_REQUEST_A] = "A request",
		[DNS_REQUEST_PTR] = "PTR request",
		[DNS_REQUEST_MX] = "MX request",
		[DNS_REQUEST_TXT] = "TXT request",
		[DNS_REQUEST_SRV] = "SRV request",
		[DNS_REQUEST_SPF] = "SPF request",
		[DNS_REQUEST_AAA] = "AAA request"
};

#endif /* DNS_PRIVATE_H_ */
