/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "config.h"
#include "dns.h"
#include "rspamd.h"
#include "utlist.h"
#include "uthash.h"
#include "rdns_event.h"

struct rspamd_dns_request_ud {
	struct rspamd_async_session *session;
	dns_callback_type cb;
	gpointer ud;
	rspamd_mempool_t *pool;
	struct rdns_request *req;
};

static void
rspamd_dns_fin_cb (gpointer arg)
{
	struct rspamd_dns_request_ud *reqdata = (struct rspamd_dns_request_ud *)arg;

	rdns_request_release (reqdata->req);
	if (reqdata->pool == NULL) {
		g_slice_free1 (sizeof (struct rspamd_dns_request_ud), reqdata);
	}
}

static void
rspamd_dns_callback (struct rdns_reply *reply, gpointer ud)
{
	struct rspamd_dns_request_ud *reqdata = ud;

	reqdata->cb (reply, reqdata->ud);

	if (reqdata->session) {
		/*
		 * Ref event to avoid double unref by
		 * event removing
		 */
		rdns_request_retain (reply->request);
		rspamd_session_remove_event (reqdata->session, rspamd_dns_fin_cb, reqdata);
	}
	else if (reqdata->pool == NULL) {
		g_slice_free1 (sizeof (struct rspamd_dns_request_ud), reqdata);
	}
}

gboolean
make_dns_request (struct rspamd_dns_resolver *resolver,
	struct rspamd_async_session *session,
	rspamd_mempool_t *pool,
	dns_callback_type cb,
	gpointer ud,
	enum rdns_request_type type,
	const char *name)
{
	struct rdns_request *req;
	struct rspamd_dns_request_ud *reqdata = NULL;

	g_assert (resolver != NULL);

	if (resolver->r == NULL) {
		return FALSE;
	}

	if (pool != NULL) {
		reqdata =
			rspamd_mempool_alloc (pool, sizeof (struct rspamd_dns_request_ud));
	}
	else {
		reqdata = g_slice_alloc (sizeof (struct rspamd_dns_request_ud));
	}
	reqdata->pool = pool;
	reqdata->session = session;
	reqdata->cb = cb;
	reqdata->ud = ud;

	req = rdns_make_request_full (resolver->r, rspamd_dns_callback, reqdata,
			resolver->request_timeout, resolver->max_retransmits, 1, name,
			type);
	reqdata->req = req;

	if (session) {
		if (req != NULL) {
			rspamd_session_add_event (session,
					(event_finalizer_t)rspamd_dns_fin_cb,
					reqdata,
					g_quark_from_static_string ("dns resolver"));
		}
	}

	if (req == NULL) {
		if (pool == NULL) {
			g_slice_free1 (sizeof (struct rspamd_dns_request_ud), reqdata);
		}
		return FALSE;
	}

	return TRUE;
}

gboolean make_dns_request_task (struct rspamd_task *task,
	dns_callback_type cb,
	gpointer ud,
	enum rdns_request_type type,
	const char *name)
{
	gboolean ret;

	if (task->dns_requests >= task->cfg->dns_max_requests) {
		return FALSE;
	}

	ret = make_dns_request (task->resolver, task->s, task->task_pool, cb, ud,
			type, name);

	if (ret) {
		task->dns_requests ++;

		if (task->dns_requests >= task->cfg->dns_max_requests) {
			msg_info_task ("<%s> stop resolving on reaching %ud requests",
					task->message_id, task->dns_requests);
		}
	}

	return ret;
}

static void rspamd_rnds_log_bridge (
		void *log_data,
		enum rdns_log_level level,
		const char *function,
		const char *format,
		va_list args)
{
	rspamd_logger_t *logger = log_data;

	rspamd_common_logv (logger, (GLogLevelFlags)level, "rdns", NULL,
			function, format, args);
}

struct rspamd_dns_resolver *
dns_resolver_init (rspamd_logger_t *logger,
	struct event_base *ev_base,
	struct rspamd_config *cfg)
{
	GList *cur;
	struct rspamd_dns_resolver *new;
	gchar *begin, *p, *err;
	gint priority;

	new = g_slice_alloc0 (sizeof (struct rspamd_dns_resolver));
	new->ev_base = ev_base;
	if (cfg != NULL) {
		new->request_timeout = cfg->dns_timeout;
		new->max_retransmits = cfg->dns_retransmits;
	}
	else {
		new->request_timeout = 1;
		new->max_retransmits = 2;
	}

	new->r = rdns_resolver_new ();
	rdns_bind_libevent (new->r, new->ev_base);

	if (cfg != NULL) {
		rdns_resolver_set_log_level (new->r, cfg->log_level);
	}

	rdns_resolver_set_logger (new->r, rspamd_rnds_log_bridge, logger);

	if (cfg == NULL || cfg->nameservers == NULL) {
		/* Parse resolv.conf */
		if (!rdns_resolver_parse_resolv_conf (new->r, "/etc/resolv.conf")) {
			msg_err_config (
				"cannot parse resolv.conf and no nameservers defined, so no ways to resolve addresses");
			rdns_resolver_release (new->r);
			new->r = NULL;

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
				p++;
				priority = strtoul (p, &err, 10);
				if (err != NULL && *err != '\0') {
					msg_info_config (
						"bad character '%xc', must be 'm' or 's' or a numeric priority",
						*err);
				}
			}
			else {
				priority = 0;
			}
			if (!rdns_resolver_add_server (new->r, begin, 53, priority,
				cfg->dns_io_per_server)) {
				msg_warn_config ("cannot parse ip address of nameserver: %s", begin);
				cur = g_list_next (cur);
				continue;
			}

			cur = g_list_next (cur);
		}

	}

	rdns_resolver_init (new->r);

	return new;
}
