/*
 * Copyright (c) 2013, Vsevolod Stakhov
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

#ifndef RSPAMD_DNS_H
#define RSPAMD_DNS_H

#include "config.h"
#include "mem_pool.h"
#include "events.h"
#include "upstream.h"

struct rspamd_dns_reply;
struct config_file;

typedef void (*dns_callback_type) (struct rspamd_dns_reply *reply, gpointer arg);

enum rspamd_request_type {
	DNS_REQUEST_A = 0,
	DNS_REQUEST_PTR,
	DNS_REQUEST_MX,
	DNS_REQUEST_TXT,
	DNS_REQUEST_SRV,
	DNS_REQUEST_SPF,
	DNS_REQUEST_AAA
};

struct rspamd_dns_request {
	memory_pool_t *pool;				/**< pool associated with request			*/
	struct rspamd_dns_resolver *resolver;
	struct rspamd_dns_io_channel *io;
	dns_callback_type func;
	gpointer arg;
	struct event timer_event;
	struct event io_event;
	struct timeval tv;
	guint retransmits;
	guint16 id;
	struct rspamd_async_session *session;
	struct rspamd_dns_reply *reply;
	guint8 *packet;
	const gchar *requested_name;
	off_t pos;
	guint packet_len;
	gint sock;
	enum rspamd_request_type type;
	time_t time;
	struct rspamd_dns_request *next;
};

union rspamd_reply_element_un {
	struct {
		struct in_addr addr;
		guint16 addrcount;
	} a;
#ifdef HAVE_INET_PTON
	struct {
		struct in6_addr addr;
	} aaa;
#endif
	struct {
		gchar *name;
	} ptr;
	struct {
		gchar *name;
		guint16 priority;
	} mx;
	struct {
		gchar *data;
	} txt;
	struct {
		guint16 priority;
		guint16 weight;
		guint16 port;
		gchar *target;
	} srv;
};

struct rspamd_reply_entry {
	union rspamd_reply_element_un content;
	guint16 type;
	guint16 ttl;
	struct rspamd_reply_entry *prev, *next;
};


enum dns_rcode {
	DNS_RC_NOERROR	= 0,
	DNS_RC_FORMERR	= 1,
	DNS_RC_SERVFAIL	= 2,
	DNS_RC_NXDOMAIN	= 3,
	DNS_RC_NOTIMP	= 4,
	DNS_RC_REFUSED	= 5,
	DNS_RC_YXDOMAIN	= 6,
	DNS_RC_YXRRSET	= 7,
	DNS_RC_NXRRSET	= 8,
	DNS_RC_NOTAUTH	= 9,
	DNS_RC_NOTZONE	= 10,
};
	
struct rspamd_dns_reply {
	struct rspamd_dns_request *request;
	enum dns_rcode code;
	struct rspamd_reply_entry *entries;
};


/* Rspamd DNS API */

/**
 * Init DNS resolver, params are obtained from a config file or system file /etc/resolv.conf
 */
struct rspamd_dns_resolver *dns_resolver_init (struct event_base *ev_base, struct config_file *cfg);

/**
 * Make a DNS request
 * @param resolver resolver object
 * @param session async session to register event
 * @param pool memory pool for storage
 * @param cb callback to call on resolve completing
 * @param ud user data for callback
 * @param type request type
 * @param ... string or ip address based on a request type
 * @return TRUE if request was sent.
 */
gboolean make_dns_request (struct rspamd_dns_resolver *resolver, 
		struct rspamd_async_session *session, memory_pool_t *pool, dns_callback_type cb, 
		gpointer ud, enum rspamd_request_type type, ...);

/**
 * Get textual presentation of DNS error code
 */
const gchar *dns_strerror (enum dns_rcode rcode);

/**
 * Get textual presentation of DNS request type
 */
const gchar *dns_strtype (enum rspamd_request_type type);

#endif
