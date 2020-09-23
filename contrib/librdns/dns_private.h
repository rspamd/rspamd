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
#include "uthash.h"
#include "utlist.h"
#include "rdns.h"
#include "upstream.h"
#include "ref.h"

static const int dns_port = 53;
static const int default_io_cnt = 8;

#define UDP_PACKET_SIZE 4096

#define DNS_COMPRESSION_BITS 0xC0

#define DNS_D_MAXLABEL  63      /* + 1 '\0' */
#define DNS_D_MAXNAME   255     /* + 1 '\0' */

#define RESOLV_CONF "/etc/resolv.conf"

/**
 * Represents DNS server
 */
struct rdns_server {
	char *name;
	unsigned int port;
	unsigned int io_cnt;

	struct rdns_io_channel **io_channels;
	void *ups_elt;
	upstream_entry_t up;
};

enum rdns_request_state {
	RDNS_REQUEST_NEW = 0,
	RDNS_REQUEST_REGISTERED = 1,
	RDNS_REQUEST_WAIT_SEND,
	RDNS_REQUEST_WAIT_REPLY,
	RDNS_REQUEST_REPLIED,
	RDNS_REQUEST_FAKE,
};

struct rdns_request {
	struct rdns_resolver *resolver;
	struct rdns_async_context *async;
	struct rdns_io_channel *io;
	struct rdns_reply *reply;
	enum rdns_request_type type;

	double timeout;
	unsigned int retransmits;

	int id;
	struct rdns_request_name *requested_names;
	unsigned int qcount;
	enum rdns_request_state state;

	uint8_t *packet;
	off_t pos;
	unsigned int packet_len;

	dns_callback_type func;
	void *arg;

	void *async_event;

#if defined(TWEETNACL) || defined(USE_RSPAMD_CRYPTOBOX)
	void *curve_plugin_data;
#endif

	UT_hash_handle hh;
	ref_entry_t ref;
};


/**
 * IO channel for a specific DNS server
 */
struct rdns_io_channel {
	struct rdns_server *srv;
	struct rdns_resolver *resolver;
	struct sockaddr *saddr;
	socklen_t slen;
	int sock; /**< persistent socket                                          */
	bool active;
	bool connected;
	void *async_io; /** async opaque ptr */
	struct rdns_request *requests; /**< requests in flight                                         */
	uint64_t uses;
	ref_entry_t ref;
};

struct rdns_fake_reply_idx {
	enum rdns_request_type type;
	unsigned len;
	char request[0];
};

struct rdns_fake_reply {
	enum dns_rcode rcode;
	struct rdns_reply_entry *result;
	UT_hash_handle hh;
	struct rdns_fake_reply_idx key;
};


struct rdns_resolver {
	struct rdns_server *servers;
	struct rdns_io_channel *io_channels; /**< hash of io chains indexed by socket        */
	struct rdns_async_context *async; /** async callbacks */
	void *periodic; /** periodic event for resolver */
	struct rdns_upstream_context *ups;
	struct rdns_plugin *curve_plugin;
	struct rdns_fake_reply *fake_elts;

#ifdef __GNUC__
	__attribute__((format(printf, 4, 0)))
#endif
	rdns_log_function logger;
	void *log_data;
	enum rdns_log_level log_level;

	uint64_t max_ioc_uses;
	void *refresh_ioc_periodic;

	bool async_binded;
	bool initialized;
	bool enable_dnssec;
	int flags;
	ref_entry_t ref;
};

struct dns_header;
struct dns_query;

/* Internal DNS structs */

struct dns_header {
	unsigned int qid :16;

#if BYTE_ORDER == BIG_ENDIAN
	unsigned int qr:1;
	unsigned int opcode:4;
	unsigned int aa:1;
	unsigned int tc:1;
	unsigned int rd:1;

	unsigned int ra:1;
	unsigned int cd : 1;
	unsigned int ad : 1;
	unsigned int z : 1;
	unsigned int rcode:4;
#else
	unsigned int rd :1;
	unsigned int tc :1;
	unsigned int aa :1;
	unsigned int opcode :4;
	unsigned int qr :1;

	unsigned int rcode :4;
	unsigned int z : 1;
	unsigned int ad : 1;
	unsigned int cd : 1;
	unsigned int ra :1;
#endif

	unsigned int qdcount :16;
	unsigned int ancount :16;
	unsigned int nscount :16;
	unsigned int arcount :16;
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
	char *qname;
	unsigned int qtype :16;
	unsigned int qclass :16;
};

enum dns_type {
	DNS_T_A = RDNS_REQUEST_A,
	DNS_T_NS = RDNS_REQUEST_NS,
	DNS_T_CNAME = 5,
	DNS_T_SOA = RDNS_REQUEST_SOA,
	DNS_T_PTR = RDNS_REQUEST_PTR,
	DNS_T_MX = RDNS_REQUEST_MX,
	DNS_T_TXT = RDNS_REQUEST_TXT,
	DNS_T_AAAA = RDNS_REQUEST_AAAA,
	DNS_T_SRV = RDNS_REQUEST_SRV,
	DNS_T_OPT = 41,
	DNS_T_SSHFP = 44,
	DNS_T_TLSA = RDNS_REQUEST_TLSA,
	DNS_T_SPF = RDNS_REQUEST_SPF,
	DNS_T_ALL = RDNS_REQUEST_ANY
};
/* enum dns_type */

static const char dns_rcodes[][32] = {
	[RDNS_RC_NOERROR]  = "no error",
	[RDNS_RC_FORMERR]  = "query format error",
	[RDNS_RC_SERVFAIL] = "server fail",
	[RDNS_RC_NXDOMAIN] = "no records with this name",
	[RDNS_RC_NOTIMP]   = "not implemented",
	[RDNS_RC_REFUSED]  = "query refused",
	[RDNS_RC_YXDOMAIN] = "YXDOMAIN",
	[RDNS_RC_YXRRSET]  = "YXRRSET",
	[RDNS_RC_NXRRSET]  = "NXRRSET",
	[RDNS_RC_NOTAUTH]  = "not authorized",
	[RDNS_RC_NOTZONE]  = "no such zone",
	[RDNS_RC_TIMEOUT]  = "query timed out",
	[RDNS_RC_NETERR]  = "network error",
	[RDNS_RC_NOREC]  = "requested record is not found"
};

static const char dns_types[][16] = {
	[RDNS_REQUEST_A] = "A request",
	[RDNS_REQUEST_NS] = "NS request",
	[RDNS_REQUEST_PTR] = "PTR request",
	[RDNS_REQUEST_MX] = "MX request",
	[RDNS_REQUEST_TXT] = "TXT request",
	[RDNS_REQUEST_SRV] = "SRV request",
	[RDNS_REQUEST_SPF] = "SPF request",
	[RDNS_REQUEST_AAAA] = "AAAA request",
	[RDNS_REQUEST_TLSA] = "TLSA request",
	[RDNS_REQUEST_ANY] = "ANY request"
};


#endif /* DNS_PRIVATE_H_ */
