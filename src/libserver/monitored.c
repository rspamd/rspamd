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

#include "rdns.h"
#include "mem_pool.h"
#include "cfg_file.h"
#include "monitored.h"
#include "cryptobox.h"
#include "logger.h"
#include "radix.h"

static const gdouble default_monitoring_interval = 60.0;
static const guint default_max_errors = 3;

struct rspamd_monitored_methods {
	void * (*monitored_config) (struct rspamd_monitored *m,
			struct rspamd_monitored_ctx *ctx,
			const ucl_object_t *opts);
	void (*monitored_update) (struct rspamd_monitored *m,
			struct rspamd_monitored_ctx *ctx, gpointer ud);
	void (*monitored_dtor) (struct rspamd_monitored *m,
			struct rspamd_monitored_ctx *ctx, gpointer ud);
	gpointer ud;
};

struct rspamd_monitored_ctx {
	struct rspamd_config *cfg;
	struct rdns_resolver *resolver;
	struct event_base *ev_base;
	GPtrArray *elts;
	gdouble monitoring_interval;
	guint max_errors;
	gboolean initialized;
};

struct rspamd_monitored {
	gchar *url;
	gdouble monitoring_interval;
	gdouble offline_time;
	gdouble total_offline_time;
	gdouble latency;
	guint nchecks;
	guint max_errors;
	guint cur_errors;
	gboolean alive;
	enum rspamd_monitored_type type;
	enum rspamd_monitored_flags flags;
	struct rspamd_monitored_ctx *ctx;
	struct rspamd_monitored_methods proc;
	struct event periodic;
	gchar tag[MEMPOOL_UID_LEN];
};

#define msg_err_mon(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
		"map", m->tag, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_mon(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
		"monitored", m->tag, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_mon(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
		"monitored", m->tag, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_mon(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
        "monitored", m->tag, \
        G_STRFUNC, \
        __VA_ARGS__)

static inline void
rspamd_monitored_propagate_error (struct rspamd_monitored *m,
		const gchar *error)
{
	if (m->alive) {
		if (m->cur_errors < m->max_errors) {
			msg_info_mon ("%s on resolving %s, %d retries left",
					error, m->url,  m->max_errors - m->cur_errors);
			m->cur_errors ++;
		}
		else {
			msg_info_mon ("%s on resolving %s, disable object",
					error, m->url);
			m->alive = FALSE;
			m->offline_time = rspamd_get_calendar_ticks ();
		}
	}
}

static inline void
rspamd_monitored_propagate_success (struct rspamd_monitored *m, gdouble lat)
{
	gdouble t;

	m->cur_errors = 0;

	if (!m->alive) {
		t = rspamd_get_calendar_ticks ();
		m->total_offline_time += t - m->offline_time;
		m->alive = TRUE;
		msg_info_mon ("restoring %s after %.1f seconds of downtime, "
				"total downtime: %.1f",
				m->url, t - m->offline_time, m->total_offline_time);
		m->offline_time = 0;
		m->nchecks = 1;
		m->latency = lat;
	}
	else {
		m->latency = (lat + m->latency * m->nchecks) / (m->nchecks + 1);
		m->nchecks ++;
	}
}

static void
rspamd_monitored_periodic (gint fd, short what, gpointer ud)
{
	struct rspamd_monitored *m = ud;
	struct timeval tv;
	gdouble jittered;

	jittered = rspamd_time_jitter (m->monitoring_interval, 0.0);
	double_to_tv (jittered, &tv);

	if (m->proc.monitored_update) {
		m->proc.monitored_update (m, m->ctx, m->proc.ud);
	}

	event_add (&m->periodic, &tv);
}

struct rspamd_dns_monitored_conf {
	enum rdns_request_type rt;
	GString *request;
	radix_compressed_t *expected;
	struct rspamd_monitored *m;
	gint expected_code;
	gdouble check_tm;
};

static void *
rspamd_monitored_dns_conf (struct rspamd_monitored *m,
		struct rspamd_monitored_ctx *ctx,
		const ucl_object_t *opts)
{
	struct rspamd_dns_monitored_conf *conf;
	const ucl_object_t *elt;
	gint rt;
	GString *req = g_string_sized_new (127);

	conf = g_malloc0 (sizeof (*conf));
	conf->rt = RDNS_REQUEST_A;
	conf->m = m;
	conf->expected_code = -1;

	if (opts) {
		elt = ucl_object_lookup (opts, "type");

		if (elt) {
			rt = rdns_type_fromstr (ucl_object_tostring (elt));

			if (rt != -1) {
				conf->rt = rt;
			}
			else {
				msg_err_mon ("invalid resolve type: %s",
						ucl_object_tostring (elt));
			}
		}

		elt = ucl_object_lookup (opts, "prefix");

		if (elt && ucl_object_type (elt) == UCL_STRING) {
			rspamd_printf_gstring (req, "%s.", ucl_object_tostring (elt));
		}

		elt = ucl_object_lookup (opts, "ipnet");

		if (elt) {
			if (ucl_object_type (elt) == UCL_STRING) {
				radix_add_generic_iplist (ucl_object_tostring (elt),
						&conf->expected, FALSE);
			}
			else if (ucl_object_type (elt) == UCL_ARRAY) {
				const ucl_object_t *cur;
				ucl_object_iter_t it = NULL;

				while ((cur = ucl_object_iterate (elt, &it, true)) != NULL) {
					radix_add_generic_iplist (ucl_object_tostring (elt),
							&conf->expected, FALSE);
				}
			}
		}

		elt = ucl_object_lookup (opts, "rcode");
		if (elt) {
			rt = rdns_rcode_fromstr (ucl_object_tostring (elt));

			if (rt != -1) {
				conf->expected_code = rt;
			}
			else {
				msg_err_mon ("invalid resolve rcode: %s",
						ucl_object_tostring (elt));
			}
		}
	}

	rspamd_printf_gstring (req, "%s", m->url);
	conf->request = req;

	return conf;
}

static void
rspamd_monitored_dns_cb (struct rdns_reply *reply, void *arg)
{
	struct rspamd_dns_monitored_conf *conf = arg;
	struct rspamd_monitored *m;
	gdouble lat;

	m = conf->m;
	lat = rspamd_get_calendar_ticks () - conf->check_tm;
	conf->check_tm = 0;
	msg_debug_mon ("dns callback for %s in %.2f: %s", m->url, lat,
			rdns_strerror (reply->code));

	if (reply->code == RDNS_RC_TIMEOUT) {
		rspamd_monitored_propagate_error (m, "timeout");
	}
	else if (reply->code == RDNS_RC_SERVFAIL) {
		rspamd_monitored_propagate_error (m, "servfail");
	}
	else if (reply->code == RDNS_RC_REFUSED) {
		rspamd_monitored_propagate_error (m, "refused");
	}
	else {
		if (conf->expected_code != -1) {
			if (reply->code != conf->expected_code) {
				if (reply->code == RDNS_RC_NOREC &&
						conf->expected_code == RDNS_RC_NXDOMAIN) {
					rspamd_monitored_propagate_success (m, lat);
				}
				else {
					msg_info_mon ("DNS reply returned %s while %s is expected",
							rdns_strerror (reply->code),
							rdns_strerror (conf->expected_code));
					rspamd_monitored_propagate_error (m, "invalid return");
				}
			}
			else {
				rspamd_monitored_propagate_success (m, lat);
			}
		}
		else if (conf->expected) {
			/* We also need to check IP */
			if (reply->code != RDNS_RC_NOERROR) {
				rspamd_monitored_propagate_error (m, "no record");
			}
			else {
				rspamd_inet_addr_t *addr;

				addr = rspamd_inet_address_from_rnds (reply->entries);

				if (!addr) {
					rspamd_monitored_propagate_error (m,
							"unreadable address");
				}
				else if (radix_find_compressed_addr (conf->expected, addr)) {
					msg_info_mon ("bad address %s is returned when monitoring %s",
							rspamd_inet_address_to_string (addr),
							conf->request->str);
					rspamd_monitored_propagate_error (m,
							"invalid address");

					rspamd_inet_address_destroy (addr);
				}
				else {
					rspamd_monitored_propagate_success (m, lat);
					rspamd_inet_address_destroy (addr);
				}
			}
		}
		else {
			rspamd_monitored_propagate_success (m, lat);
		}
	}
}

void
rspamd_monitored_dns_mon (struct rspamd_monitored *m,
		struct rspamd_monitored_ctx *ctx, gpointer ud)
{
	struct rspamd_dns_monitored_conf *conf = ud;

	if (!rdns_make_request_full (ctx->resolver, rspamd_monitored_dns_cb,
			conf, ctx->cfg->dns_timeout, ctx->cfg->dns_retransmits,
			conf->rt, conf->request->str)) {
		msg_info_mon ("cannot make request to resolve %s", conf->request->str);

		m->cur_errors ++;
		rspamd_monitored_propagate_error (m, "failed to make DNS request");
	}
	else {
		conf->check_tm = rspamd_get_calendar_ticks ();
	}
}

void
rspamd_monitored_dns_dtor (struct rspamd_monitored *m,
		struct rspamd_monitored_ctx *ctx, gpointer ud)
{
	struct rspamd_dns_monitored_conf *conf = ud;

	g_string_free (conf->request, TRUE);

	if (conf->expected) {
		radix_destroy_compressed (conf->expected);
	}

	g_free (conf);
}

struct rspamd_monitored_ctx *
rspamd_monitored_ctx_init (void)
{
	struct rspamd_monitored_ctx *ctx;

	ctx = g_slice_alloc0 (sizeof (*ctx));
	ctx->monitoring_interval = default_monitoring_interval;
	ctx->max_errors = default_max_errors;
	ctx->elts = g_ptr_array_new ();

	return ctx;
}


void
rspamd_monitored_ctx_config (struct rspamd_monitored_ctx *ctx,
		struct rspamd_config *cfg,
		struct event_base *ev_base,
		struct rdns_resolver *resolver)
{
	struct rspamd_monitored *m;
	guint i;

	g_assert (ctx != NULL);
	ctx->ev_base = ev_base;
	ctx->resolver = resolver;
	ctx->cfg = cfg;
	ctx->initialized = TRUE;

	/* Start all events */
	for (i = 0; i < ctx->elts->len; i ++) {
		m = g_ptr_array_index (ctx->elts, i);
		rspamd_monitored_start (m);
	}
}


struct rspamd_monitored *
rspamd_monitored_create (struct rspamd_monitored_ctx *ctx,
		const gchar *line,
		enum rspamd_monitored_type type,
		enum rspamd_monitored_flags flags,
		const ucl_object_t *opts)
{
	struct rspamd_monitored *m;
	rspamd_cryptobox_hash_state_t st;
	gchar *cksum_encoded, cksum[rspamd_cryptobox_HASHBYTES];

	g_assert (ctx != NULL);
	g_assert (line != NULL);

	m = g_slice_alloc0 (sizeof (*m));
	m->type = type;
	m->flags = flags;
	m->url = g_strdup (line);
	m->ctx = ctx;
	m->monitoring_interval = ctx->monitoring_interval;
	m->max_errors = ctx->max_errors;
	m->alive = TRUE;

	if (type == RSPAMD_MONITORED_DNS) {
		m->proc.monitored_update = rspamd_monitored_dns_mon;
		m->proc.monitored_config = rspamd_monitored_dns_conf;
		m->proc.monitored_dtor = rspamd_monitored_dns_dtor;
	}
	else {
		g_slice_free1 (sizeof (*m), m);

		return NULL;
	}

	m->proc.ud = m->proc.monitored_config (m, ctx, opts);

	if (m->proc.ud == NULL) {
		g_slice_free1 (sizeof (*m), m);

		return NULL;
	}

	/* Create a persistent tag */
	rspamd_cryptobox_hash_init (&st, NULL, 0);
	rspamd_cryptobox_hash_update (&st, m->url, strlen (m->url));
	rspamd_cryptobox_hash_final (&st, cksum);
	cksum_encoded = rspamd_encode_base32 (cksum, sizeof (cksum));
	rspamd_strlcpy (m->tag, cksum_encoded, sizeof (m->tag));
	g_free (cksum_encoded);

	g_ptr_array_add (ctx->elts, m);

	if (ctx->ev_base) {
		rspamd_monitored_start (m);
	}

	return m;
}

gboolean
rspamd_monitored_alive (struct rspamd_monitored *m)
{
	g_assert (m != NULL);

	return m->alive;
}

gdouble
rspamd_monitored_offline_time (struct rspamd_monitored *m)
{
	g_assert (m != NULL);

	if (m->offline_time > 0) {
		return rspamd_get_calendar_ticks () - m->offline_time;
	}

	return 0;
}

gdouble
rspamd_monitored_total_offline_time (struct rspamd_monitored *m)
{
	g_assert (m != NULL);

	if (m->offline_time > 0) {
		return rspamd_get_calendar_ticks () - m->offline_time + m->total_offline_time;
	}


	return m->total_offline_time;
}

gdouble
rspamd_monitored_latency (struct rspamd_monitored *m)
{
	g_assert (m != NULL);

		return m->latency;
}

void
rspamd_monitored_stop (struct rspamd_monitored *m)
{
	g_assert (m != NULL);

	m->alive = FALSE;
	if (event_get_base (&m->periodic)) {
		event_del (&m->periodic);
	}
}

void
rspamd_monitored_start (struct rspamd_monitored *m)
{
	struct timeval tv;
	gdouble jittered;

	g_assert (m != NULL);
	msg_debug_mon ("started monitored object %s", m->url);
	jittered = rspamd_time_jitter (m->monitoring_interval, 0.0);
	double_to_tv (jittered, &tv);

	if (event_get_base (&m->periodic)) {
		event_del (&m->periodic);
	}

	event_set (&m->periodic, -1, EV_TIMEOUT, rspamd_monitored_periodic, m);
	event_base_set (m->ctx->ev_base, &m->periodic);
	event_add (&m->periodic, &tv);
}

void
rspamd_monitored_ctx_destroy (struct rspamd_monitored_ctx *ctx)
{
	struct rspamd_monitored *m;
	guint i;

	g_assert (ctx != NULL);

	for (i = 0; i < ctx->elts->len; i ++) {
		m = g_ptr_array_index (ctx->elts, i);
		rspamd_monitored_stop (m);
		g_free (m->url);
		m->proc.monitored_dtor (m, m->ctx, m->proc.ud);
		g_slice_free1 (sizeof (*m), m);
	}

	g_ptr_array_free (ctx->elts, TRUE);
	g_slice_free1 (sizeof (*ctx), ctx);
}
