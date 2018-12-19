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

#include <contrib/librdns/rdns.h>
#include <contrib/librdns/dns_private.h>
#include "config.h"
#include "dns.h"
#include "rspamd.h"
#include "utlist.h"
#include "uthash.h"
#include "rdns_event.h"
#include "unix-std.h"

static const gchar *M = "rspamd dns";

static struct rdns_upstream_elt* rspamd_dns_select_upstream (const char *name,
		size_t len, void *ups_data);
static struct rdns_upstream_elt* rspamd_dns_select_upstream_retransmit (
		const char *name,
		size_t len, void *ups_data);
static void rspamd_dns_upstream_ok (struct rdns_upstream_elt *elt,
		void *ups_data);
static void rspamd_dns_upstream_fail (struct rdns_upstream_elt *elt,
		void *ups_data);
static unsigned int rspamd_dns_upstream_count (void *ups_data);

static struct rdns_upstream_context rspamd_ups_ctx = {
		.select = rspamd_dns_select_upstream,
		.select_retransmit = rspamd_dns_select_upstream_retransmit,
		.ok = rspamd_dns_upstream_ok,
		.fail = rspamd_dns_upstream_fail,
		.count = rspamd_dns_upstream_count,
		.data = NULL
};

struct rspamd_dns_request_ud {
	struct rspamd_async_session *session;
	dns_callback_type cb;
	gpointer ud;
	rspamd_mempool_t *pool;
	struct rspamd_task *task;
	struct rspamd_symcache_item *item;
	struct rdns_request *req;
	struct rdns_reply *reply;
};

static void
rspamd_dns_fin_cb (gpointer arg)
{
	struct rspamd_dns_request_ud *reqdata = (struct rspamd_dns_request_ud *)arg;

	if (reqdata->item) {
		rspamd_symcache_set_cur_item (reqdata->task, reqdata->item);
	}

	if (reqdata->reply) {
		reqdata->cb (reqdata->reply, reqdata->ud);
	}
	else {
		struct rdns_reply fake_reply;

		memset (&fake_reply, 0, sizeof (fake_reply));
		fake_reply.code = RDNS_RC_TIMEOUT;
		fake_reply.request = reqdata->req;
		fake_reply.resolver = reqdata->req->resolver;
		fake_reply.requested_name = reqdata->req->requested_names[0].name;

		reqdata->cb (&fake_reply, reqdata->ud);
	}

	rdns_request_release (reqdata->req);

	if (reqdata->item) {
		rspamd_symcache_item_async_dec_check (reqdata->task,
				reqdata->item, M);
	}

	if (reqdata->pool == NULL) {
		g_free (reqdata);
	}
}

static void
rspamd_dns_callback (struct rdns_reply *reply, gpointer ud)
{
	struct rspamd_dns_request_ud *reqdata = ud;

	reqdata->reply = reply;

	if (reqdata->session) {
		/*
		 * Ref event to avoid double unref by
		 * event removing
		 */
		rdns_request_retain (reply->request);
		rspamd_session_remove_event (reqdata->session, rspamd_dns_fin_cb, reqdata);
	}
	else {
		reqdata->cb (reply, reqdata->ud);

		if (reqdata->pool == NULL) {
			g_free (reqdata);
		}
	}
}

struct rspamd_dns_request_ud *
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
		return NULL;
	}

	if (session && rspamd_session_blocked (session)) {
		return NULL;
	}

	if (pool != NULL) {
		reqdata =
			rspamd_mempool_alloc0 (pool, sizeof (struct rspamd_dns_request_ud));
	}
	else {
		reqdata = g_malloc0 (sizeof (struct rspamd_dns_request_ud));
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
					(event_finalizer_t) rspamd_dns_fin_cb,
					reqdata,
					M);
		}
	}

	if (req == NULL) {
		if (pool == NULL) {
			g_free (reqdata);
		}

		return NULL;
	}

	return reqdata;
}

static gboolean
make_dns_request_task_common (struct rspamd_task *task,
	dns_callback_type cb,
	gpointer ud,
	enum rdns_request_type type,
	const char *name,
	gboolean forced)
{
	struct rspamd_dns_request_ud *reqdata;

	if (!forced && task->dns_requests >= task->cfg->dns_max_requests) {
		return FALSE;
	}

	reqdata = make_dns_request (task->resolver, task->s, task->task_pool, cb, ud,
			type, name);

	if (reqdata) {
		task->dns_requests ++;

		reqdata->task = task;
		reqdata->item = rspamd_symcache_get_cur_item (task);

		if (reqdata->item) {
			/* We are inside some session */
			rspamd_symcache_item_async_inc (task, reqdata->item, M);
		}

		if (!forced && task->dns_requests >= task->cfg->dns_max_requests) {
			msg_info_task ("<%s> stop resolving on reaching %ud requests",
					task->message_id, task->dns_requests);
		}

		return TRUE;
	}

	return FALSE;
}

gboolean
make_dns_request_task (struct rspamd_task *task,
	dns_callback_type cb,
	gpointer ud,
	enum rdns_request_type type,
	const char *name)
{
	return make_dns_request_task_common (task, cb, ud, type, name, FALSE);
}

gboolean
make_dns_request_task_forced (struct rspamd_task *task,
	dns_callback_type cb,
	gpointer ud,
	enum rdns_request_type type,
	const char *name)
{
	return make_dns_request_task_common (task, cb, ud, type, name, TRUE);
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

static void
rspamd_dns_server_init (struct upstream *up, guint idx, gpointer ud)
{
	struct rspamd_dns_resolver *r = ud;
	rspamd_inet_addr_t *addr;
	void *serv;
	struct rdns_upstream_elt *elt;

	addr = rspamd_upstream_addr (up);

	if (r->cfg) {
		serv = rdns_resolver_add_server (r->r, rspamd_inet_address_to_string (addr),
				rspamd_inet_address_get_port (addr), 0, r->cfg->dns_io_per_server);
	}
	else {
		serv = rdns_resolver_add_server (r->r, rspamd_inet_address_to_string (addr),
				rspamd_inet_address_get_port (addr), 0, 8);
	}

	g_assert (serv != NULL);

	elt = g_malloc0 (sizeof (*elt));
	elt->server = serv;
	elt->lib_data = up;

	rspamd_upstream_set_data (up, elt);
}

static void
rspamd_dns_server_reorder (struct upstream *up, guint idx, gpointer ud)
{
	struct rspamd_dns_resolver *r = ud;

	rspamd_upstream_set_weight (up, rspamd_upstreams_count (r->ups) - idx + 1);
}

static bool
rspamd_dns_resolv_conf_on_server (struct rdns_resolver *resolver,
		const char *name, unsigned int port,
		int priority, unsigned int io_cnt, void *ud)
{
	struct rspamd_dns_resolver *dns_resolver = ud;
	struct rspamd_config *cfg;
	rspamd_inet_addr_t *addr;
	gint test_fd;

	cfg = dns_resolver->cfg;

	msg_info_config ("parsed nameserver %s from resolv.conf", name);

	/* Try to open a connection */
	if (!rspamd_parse_inet_address (&addr, name, strlen (name))) {
		msg_warn_config ("cannot parse nameserver address %s", name);

		return FALSE;
	}

	rspamd_inet_address_set_port (addr, port);
	test_fd = rspamd_inet_address_connect (addr, SOCK_DGRAM, TRUE);

	if (test_fd == -1) {
		msg_warn_config ("cannot open connection to nameserver at address %s: %s",
				name, strerror (errno));
		rspamd_inet_address_free (addr);

		return FALSE;
	}

	rspamd_inet_address_free (addr);
	close (test_fd);

	return rspamd_upstreams_add_upstream (dns_resolver->ups, name, port,
			RSPAMD_UPSTREAM_PARSE_NAMESERVER,
			NULL);
}

static void
rspamd_dns_resolver_config_ucl (struct rspamd_config *cfg,
								struct rspamd_dns_resolver *dns_resolver,
								const ucl_object_t *dns_section)
{
	const ucl_object_t *fake_replies, *cur;
	ucl_object_iter_t it;

	/* Process fake replies */
	fake_replies = ucl_object_lookup_any (dns_section, "fake_records",
			"fake_replies", NULL);

	if (fake_replies && ucl_object_type (fake_replies) == UCL_ARRAY) {
		it = ucl_object_iterate_new (fake_replies);

		while ((cur = ucl_object_iterate_safe (it, true))) {
			const ucl_object_t *type_obj, *name_obj, *code_obj, *replies_obj;
			enum rdns_request_type rtype = RDNS_REQUEST_A;
			enum dns_rcode rcode = RDNS_RC_NOERROR;
			struct rdns_reply_entry *replies = NULL;
			const gchar *name = NULL;

			if (ucl_object_type (cur) != UCL_OBJECT) {
				continue;
			}

			name_obj = ucl_object_lookup (cur, "name");
			if (name_obj == NULL ||
				(name = ucl_object_tostring (name_obj)) == NULL) {
				msg_err_config ("no name for fake dns reply");
				continue;
			}

			type_obj = ucl_object_lookup (cur, "type");
			if (type_obj) {
				rtype = rdns_type_fromstr (ucl_object_tostring (type_obj));

				if (rtype == RDNS_REQUEST_INVALID) {
					msg_err_config ("invalid type for %s: %s", name,
							ucl_object_tostring (type_obj));
					continue;
				}
			}

			code_obj = ucl_object_lookup_any (cur, "code", "rcode", NULL);
			if (code_obj) {
				rcode = rdns_rcode_fromstr (ucl_object_tostring (code_obj));

				if (rcode == RDNS_RC_INVALID) {
					msg_err_config ("invalid rcode for %s: %s", name,
							ucl_object_tostring (code_obj));
					continue;
				}
			}

			if (rcode == RDNS_RC_NOERROR) {
				/* We want replies to be set for this rcode */
				replies_obj = ucl_object_lookup (cur, "replies");

				if (replies_obj == NULL || ucl_object_type (replies_obj) != UCL_ARRAY) {
					msg_err_config ("invalid replies for fake DNS record %s", name);
					continue;
				}

				ucl_object_iter_t rep_it;
				const ucl_object_t *rep_obj;

				rep_it = ucl_object_iterate_new (replies_obj);

				while ((rep_obj = ucl_object_iterate_safe (rep_it, true))) {
					const gchar *str_rep = ucl_object_tostring (rep_obj);
					struct rdns_reply_entry *rep;
					gchar **svec;

					if (str_rep == NULL) {
						msg_err_config ("invalid reply element for fake DNS record %s",
								name);
						continue;
					}

					rep = calloc (1, sizeof (*rep));
					g_assert (rep != NULL);

					rep->type = rtype;
					rep->ttl = 0;

					switch (rtype) {
					case RDNS_REQUEST_A:
						if (inet_pton (AF_INET, str_rep, &rep->content.a.addr) != 1) {
							msg_err_config ("invalid A reply element for fake "
											"DNS record %s: %s",
									name, str_rep);
							free (rep);
						}
						else {
							DL_APPEND (replies, rep);
						}
						break;
					case RDNS_REQUEST_NS:
						rep->content.ns.name = strdup (str_rep);
						DL_APPEND (replies, rep);
						break;
					case RDNS_REQUEST_PTR:
						rep->content.ptr.name = strdup (str_rep);
						DL_APPEND (replies, rep);
						break;
					case RDNS_REQUEST_MX:
						svec = g_strsplit_set (str_rep, " :", -1);

						if (svec && svec[0] && svec[1]) {
							rep->content.mx.priority = strtoul (svec[0], NULL, 10);
							rep->content.mx.name = strdup (svec[1]);
							DL_APPEND (replies, rep);
						}
						else {
							msg_err_config ("invalid MX reply element for fake "
											"DNS record %s: %s",
									name, str_rep);
							free (rep);
						}

						g_strfreev (svec);
						break;
					case RDNS_REQUEST_TXT:
						rep->content.txt.data = strdup (str_rep);
						DL_APPEND (replies, rep);
						break;
					case RDNS_REQUEST_SOA:
						svec = g_strsplit_set (str_rep, " :", -1);

						/* 7 elements */
						if (svec && svec[0] && svec[1] && svec[2] &&
								svec[3] && svec[4] && svec[5] && svec[6]) {
							rep->content.soa.mname = strdup (svec[0]);
							rep->content.soa.admin = strdup (svec[1]);
							rep->content.soa.serial = strtoul (svec[2], NULL, 10);
							rep->content.soa.refresh = strtol (svec[3], NULL, 10);
							rep->content.soa.retry = strtol (svec[4], NULL, 10);
							rep->content.soa.expire = strtol (svec[5], NULL, 10);
							rep->content.soa.minimum = strtoul (svec[6], NULL, 10);
							DL_APPEND (replies, rep);
						}
						else {
							msg_err_config ("invalid MX reply element for fake "
											"DNS record %s: %s",
									name, str_rep);
							free (rep);
						}

						g_strfreev (svec);
						break;
					case RDNS_REQUEST_AAAA:
						if (inet_pton (AF_INET6, str_rep, &rep->content.aaa.addr) != 1) {
							msg_err_config ("invalid AAAA reply element for fake "
											"DNS record %s: %s",
									name, str_rep);
							free (rep);
						}
						else {
							DL_APPEND (replies, rep);
						}
					case RDNS_REQUEST_SRV:
					default:
						msg_err_config ("invalid or unsupported reply element "
										"for fake DNS record %s(%s): %s",
								name, rdns_str_from_type (rtype), str_rep);
						free (rep);
						break;
					}
				}

				ucl_object_iterate_free (rep_it);

				if (replies) {
					struct rdns_reply_entry *tmp_entry;
					guint i = 0;
					DL_COUNT (replies, tmp_entry, i);

					msg_info_config ("added fake record: %s(%s); %d replies", name,
							rdns_str_from_type (rtype), i);
					rdns_resolver_set_fake_reply (dns_resolver->r,
							name, rtype, rcode, replies);
				}
				else {
					msg_warn_config ("record %s has no replies, not adding",
							name);
				}
			}
			else {
				/* This entry returns some non valid code, no replies are possible */
				replies_obj = ucl_object_lookup (cur, "replies");

				if (replies_obj) {
					msg_warn_config ("replies are set for non-successful return "
					  "code for %s(%s), they will be ignored", name, rdns_str_from_type (rtype));
				}

				rdns_resolver_set_fake_reply (dns_resolver->r,
						name, rtype, rcode, NULL);
			}
		}

		ucl_object_iterate_free (it);
	}
}

struct rspamd_dns_resolver *
dns_resolver_init (rspamd_logger_t *logger,
	struct event_base *ev_base,
	struct rspamd_config *cfg)
{
	struct rspamd_dns_resolver *dns_resolver;

	dns_resolver = g_malloc0 (sizeof (struct rspamd_dns_resolver));
	dns_resolver->ev_base = ev_base;
	if (cfg != NULL) {
		dns_resolver->request_timeout = cfg->dns_timeout;
		dns_resolver->max_retransmits = cfg->dns_retransmits;
	}
	else {
		dns_resolver->request_timeout = 1;
		dns_resolver->max_retransmits = 2;
	}

	dns_resolver->r = rdns_resolver_new ();
	rdns_bind_libevent (dns_resolver->r, dns_resolver->ev_base);

	if (cfg != NULL) {
		rdns_resolver_set_log_level (dns_resolver->r, cfg->log_level);
		dns_resolver->cfg = cfg;
		rdns_resolver_set_dnssec (dns_resolver->r, cfg->enable_dnssec);

		if (cfg->nameservers == NULL) {
			/* Parse resolv.conf */
			dns_resolver->ups = rspamd_upstreams_create (cfg->ups_ctx);
			rspamd_upstreams_set_flags (dns_resolver->ups,
					RSPAMD_UPSTREAM_FLAG_NORESOLVE);
			rspamd_upstreams_set_rotation (dns_resolver->ups,
					RSPAMD_UPSTREAM_MASTER_SLAVE);

			if (!rdns_resolver_parse_resolv_conf_cb (dns_resolver->r,
					"/etc/resolv.conf",
					rspamd_dns_resolv_conf_on_server,
					dns_resolver)) {
				msg_err ("cannot parse resolv.conf and no nameservers defined, "
						"so no ways to resolve addresses");
				rdns_resolver_release (dns_resolver->r);
				dns_resolver->r = NULL;

				return dns_resolver;
			}

			/* Use normal resolv.conf rules */
			rspamd_upstreams_foreach (dns_resolver->ups, rspamd_dns_server_reorder,
					dns_resolver);
		}
		else {
			dns_resolver->ups = rspamd_upstreams_create (cfg->ups_ctx);
			rspamd_upstreams_set_flags (dns_resolver->ups,
					RSPAMD_UPSTREAM_FLAG_NORESOLVE);

			if (!rspamd_upstreams_from_ucl (dns_resolver->ups, cfg->nameservers,
					53, dns_resolver)) {
				msg_err_config ("cannot parse DNS nameservers definitions");
				rdns_resolver_release (dns_resolver->r);
				dns_resolver->r = NULL;

				return dns_resolver;
			}
		}

		rspamd_upstreams_foreach (dns_resolver->ups, rspamd_dns_server_init,
				dns_resolver);
		rdns_resolver_set_upstream_lib (dns_resolver->r, &rspamd_ups_ctx,
				dns_resolver->ups);
		cfg->dns_resolver = dns_resolver;

		if (cfg->rcl_obj) {
			/* Configure additional options */
			const ucl_object_t *opts_section, *dns_section;

			opts_section = ucl_object_lookup (cfg->rcl_obj, "options");

			if (opts_section) {
				dns_section = ucl_object_lookup (opts_section, "dns");

				if (dns_section) {
					rspamd_dns_resolver_config_ucl (cfg, dns_resolver, dns_section);
				}
			}
		}
	}

	rdns_resolver_set_logger (dns_resolver->r, rspamd_rnds_log_bridge, logger);
	rdns_resolver_init (dns_resolver->r);

	return dns_resolver;
}


static struct rdns_upstream_elt*
rspamd_dns_select_upstream (const char *name,
		size_t len, void *ups_data)
{
	struct upstream_list *ups = ups_data;
	struct upstream *up;

	up = rspamd_upstream_get (ups, RSPAMD_UPSTREAM_ROUND_ROBIN, name, len);

	if (up) {
		msg_debug ("select %s", rspamd_upstream_name (up));

		return rspamd_upstream_get_data (up);
	}

	return NULL;
}

static struct rdns_upstream_elt*
rspamd_dns_select_upstream_retransmit (
		const char *name,
		size_t len, void *ups_data)
{
	struct upstream_list *ups = ups_data;
	struct upstream *up;

	up = rspamd_upstream_get_forced (ups, RSPAMD_UPSTREAM_RANDOM, name, len);

	if (up) {
		msg_debug ("select forced %s", rspamd_upstream_name (up));

		return rspamd_upstream_get_data (up);
	}

	return NULL;
}

static void
rspamd_dns_upstream_ok (struct rdns_upstream_elt *elt,
		void *ups_data)
{
	struct upstream *up = elt->lib_data;

	rspamd_upstream_ok (up);
}

static void
rspamd_dns_upstream_fail (struct rdns_upstream_elt *elt,
		void *ups_data)
{
	struct upstream *up = elt->lib_data;

	rspamd_upstream_fail (up, FALSE);
}

static unsigned int
rspamd_dns_upstream_count (void *ups_data)
{
	struct upstream_list *ups = ups_data;

	return rspamd_upstreams_alive (ups);
}
