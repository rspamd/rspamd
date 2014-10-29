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
#include "logger.h"
#include "rdns.h"

struct rspamd_dns_resolver {
	struct rdns_resolver *r;
	struct event_base *ev_base;
	gdouble request_timeout;
	guint max_retransmits;
};

/* Rspamd DNS API */

/**
 * Init DNS resolver, params are obtained from a config file or system file /etc/resolv.conf
 */
struct rspamd_dns_resolver * dns_resolver_init (rspamd_logger_t *logger,
	struct event_base *ev_base, struct rspamd_config *cfg);

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
	struct rspamd_async_session *session,
	rspamd_mempool_t *pool,
	dns_callback_type cb,
	gpointer ud,
	enum rdns_request_type type,
	const char *name);

#endif
