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
#include "uthash.h"
#include "rdns_event.h"

struct rspamd_dns_resolver {
	struct rdns_resolver *r;
	struct event_base *ev_base;
	gdouble request_timeout;
	guint max_retransmits;
};

struct rspamd_dns_request_ud {
	struct rspamd_async_session *session;
	dns_callback_type cb;
	gpointer ud;
	struct rdns_request *req;
};

static void
rspamd_dns_fin_cb (gpointer arg)
{
	struct rdns_request *req = arg;
	
	rdns_request_release (req);
}

static void
rspamd_dns_callback (struct rdns_reply *reply, gpointer ud)
{
	struct rspamd_dns_request_ud *reqdata = ud;

	reqdata->cb (reply, reqdata->ud);

	/*
	 * Ref event to avoid double unref by
	 * event removing
	 */
	rdns_request_retain (reply->request);
	remove_normal_event (reqdata->session, rspamd_dns_fin_cb, reqdata->req);
}

gboolean 
make_dns_request (struct rspamd_dns_resolver *resolver,
		struct rspamd_async_session *session, rspamd_mempool_t *pool, dns_callback_type cb,
		gpointer ud, enum rdns_request_type type, const char *name)
{
	struct rdns_request *req;
	struct rspamd_dns_request_ud *reqdata;
	
	reqdata = rspamd_mempool_alloc (pool, sizeof (struct rspamd_dns_request_ud));
	reqdata->session = session;
	reqdata->cb = cb;
	reqdata->ud = ud;

	req = rdns_make_request_full (resolver->r, rspamd_dns_callback, reqdata,
			resolver->request_timeout, resolver->max_retransmits, 1, name, type);

	if (req != NULL) {
		register_async_event (session, (event_finalizer_t)rspamd_dns_fin_cb, req,
				g_quark_from_static_string ("dns resolver"));
		reqdata->req = req;
	}
	else {
		return FALSE;
	}

	return TRUE;
}


struct rspamd_dns_resolver *
dns_resolver_init (rspamd_logger_t *logger, struct event_base *ev_base, struct rspamd_config *cfg)
{
	GList                          *cur;
	struct rspamd_dns_resolver     *new;
	gchar                          *begin, *p, *err;
	gint                            priority;
	
	new = g_slice_alloc0 (sizeof (struct rspamd_dns_resolver));
	new->ev_base = ev_base;
	new->request_timeout = cfg->dns_timeout;
	new->max_retransmits = cfg->dns_retransmits;

	new->r = rdns_resolver_new ();
	rdns_bind_libevent (new->r, new->ev_base);
	rdns_resolver_set_log_level (new->r, cfg->log_level);
	rdns_resolver_set_logger (new->r, (rdns_log_function)rspamd_common_logv, logger);

	if (cfg->nameservers == NULL) {
		/* Parse resolv.conf */
		if (!rdns_resolver_parse_resolv_conf (new->r, "/etc/resolv.conf")) {
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
				priority = strtoul (p, &err, 10);
				if (err != NULL && *err != '\0') {
					msg_info ("bad character '%x', must be 'm' or 's' or a numeric priority", *err);
				}
			}
			else {
				priority = 0;
			}
			if (!rdns_resolver_add_server (new->r, begin, 53, priority, cfg->dns_io_per_server)) {
				msg_warn ("cannot parse ip address of nameserver: %s", begin);
				cur = g_list_next (cur);
				continue;
			}

			cur = g_list_next (cur);
		}

	}

	rdns_resolver_init (new->r);

	return new;
}
