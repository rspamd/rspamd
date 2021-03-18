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
#include "rdns.h"
#include "mem_pool.h"
#include "cfg_file.h"
#include "cryptobox.h"
#include "logger.h"
#include "contrib/uthash/utlist.h"

static const gdouble default_monitoring_interval = 60.0;
static const guint default_max_errors = 2;
static const gdouble default_max_monitored_mult = 32;
static const gdouble default_min_monitored_mult = 0.1;
static const gdouble default_initial_monitored_mult = default_min_monitored_mult;
static const gdouble default_offline_monitored_mult = 8.0;

struct rspamd_monitored_methods {
	void * (*monitored_config) (struct rspamd_monitored *m,
			struct rspamd_monitored_ctx *ctx,
			const ucl_object_t *opts);
	gboolean (*monitored_update) (struct rspamd_monitored *m,
			struct rspamd_monitored_ctx *ctx, gpointer ud);
	void (*monitored_dtor) (struct rspamd_monitored *m,
			struct rspamd_monitored_ctx *ctx, gpointer ud);
	gpointer ud;
};

struct rspamd_monitored_ctx {
	struct rspamd_config *cfg;
	struct rdns_resolver *resolver;
	struct ev_loop *event_loop;
	GPtrArray *elts;
	GHashTable *helts;
	mon_change_cb change_cb;
	gpointer ud;
	gdouble monitoring_interval;
	gdouble max_monitored_mult;
	gdouble min_monitored_mult;
	gdouble initial_monitored_mult;
	gdouble offline_monitored_mult;
	guint max_errors;
	gboolean initialized;
};

struct rspamd_monitored {
	gchar *url;
	gdouble monitoring_mult;
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
	ev_timer periodic;
	gchar tag[RSPAMD_MONITORED_TAG_LEN];
};

#define msg_err_mon(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
		"monitored", m->tag, \
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
#define msg_notice_mon(...)   rspamd_default_log_function (G_LOG_LEVEL_MESSAGE, \
		"monitored", m->tag, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_mon(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_monitored_log_id, "monitored", m->tag, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(monitored)

static inline void
rspamd_monitored_propagate_error (struct rspamd_monitored *m,
		const gchar *error)
{
	if (m->alive) {
		if (m->cur_errors < m->max_errors) {

			m->cur_errors ++;
			/* Reduce timeout */
			rspamd_monitored_stop (m);

			if (m->monitoring_mult > m->ctx->min_monitored_mult) {
				if (m->monitoring_mult < 1.0) {
					m->monitoring_mult = 1.0;
				}
				else {
					m->monitoring_mult /= 2.0;
				}
			}

			msg_debug_mon ("%s on resolving %s, %d retries left; next check in %.2f",
					error, m->url,  m->max_errors - m->cur_errors,
					m->ctx->monitoring_interval * m->monitoring_mult);

			rspamd_monitored_start (m);
		}
		else {
			msg_notice_mon ("%s on resolving %s, disable object",
					error, m->url);
			m->alive = FALSE;
			m->offline_time = rspamd_get_calendar_ticks ();
			rspamd_monitored_stop (m);
			m->monitoring_mult = 2.0;
			rspamd_monitored_start (m);

			if (m->ctx->change_cb) {
				m->ctx->change_cb (m->ctx, m, FALSE, m->ctx->ud);
			}
		}
	}
	else {
		if (m->monitoring_mult < m->ctx->offline_monitored_mult) {
			/* Increase timeout */
			rspamd_monitored_stop (m);
			m->monitoring_mult *= 2.0;
			rspamd_monitored_start (m);
		}
		else {
			rspamd_monitored_stop (m);
			m->monitoring_mult = m->ctx->offline_monitored_mult;
			rspamd_monitored_start (m);
		}
	}
}

static inline void
rspamd_monitored_propagate_success (struct rspamd_monitored *m, gdouble lat)
{
	gdouble t;

	m->cur_errors = 0;

	if (!m->alive) {
		m->monitoring_mult = 1.0;
		t = rspamd_get_calendar_ticks ();
		m->total_offline_time += t - m->offline_time;
		m->alive = TRUE;
		msg_notice_mon ("restoring %s after %.1f seconds of downtime, "
				"total downtime: %.1f",
				m->url, t - m->offline_time, m->total_offline_time);
		m->offline_time = 0;
		m->nchecks = 1;
		m->latency = lat;
		rspamd_monitored_stop (m);
		rspamd_monitored_start (m);

		if (m->ctx->change_cb) {
			m->ctx->change_cb (m->ctx, m, TRUE, m->ctx->ud);
		}
	}
	else {
		/* Increase monitored interval */
		if (m->monitoring_mult < m->ctx->max_monitored_mult) {
			if (m->monitoring_mult < 1.0) {
				/* Upgrade fast from the initial mult */
				m->monitoring_mult = 1.0;
			}
			else {
				m->monitoring_mult *= 2.0;
			}
		}
		else {
			m->monitoring_mult = m->ctx->max_monitored_mult;
		}
		m->latency = (lat + m->latency * m->nchecks) / (m->nchecks + 1);
		m->nchecks ++;
	}
}

static void
rspamd_monitored_periodic (EV_P_ ev_timer *w, int revents)
{
	struct rspamd_monitored *m = (struct rspamd_monitored *)w->data;
	gdouble jittered;
	gboolean ret = FALSE;

	if (m->proc.monitored_update) {
		ret = m->proc.monitored_update (m, m->ctx, m->proc.ud);
	}

	jittered = rspamd_time_jitter (m->ctx->monitoring_interval * m->monitoring_mult,
			0.0);

	if (ret) {
		m->periodic.repeat = jittered;
		ev_timer_again (EV_A_ &m->periodic);
	}
}

struct rspamd_dns_monitored_conf {
	enum rdns_request_type rt;
	GString *request;
	radix_compressed_t *expected;
	struct rspamd_monitored *m;
	gint expected_code;
	gdouble check_tm;
};

static void
rspamd_monitored_dns_random (struct rspamd_monitored *m,
							 struct rspamd_dns_monitored_conf *conf)
{
	gchar random_prefix[32];
	const gchar dns_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
	gint len;

	len = rspamd_random_uint64_fast () % sizeof (random_prefix);

	if (len < 8) {
		len = 8;
	}

	for (guint i = 0; i < len; i ++) {
		guint idx = rspamd_random_uint64_fast () % (sizeof (dns_chars) - 1);
		random_prefix[i] = dns_chars[idx];
	}

	conf->request->len = 0;
	rspamd_printf_gstring (conf->request, "%*.s.%s", len, random_prefix,
			m->url);
}

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

		if (!(m->flags & RSPAMD_MONITORED_RANDOM)) {
			/* Prefix is useless for random monitored */
			elt = ucl_object_lookup (opts, "prefix");

			if (elt && ucl_object_type (elt) == UCL_STRING) {
				rspamd_printf_gstring (req, "%s.", ucl_object_tostring (elt));
			}
		}

		elt = ucl_object_lookup (opts, "ipnet");

		if (elt) {
			if (ucl_object_type (elt) == UCL_STRING) {
				radix_add_generic_iplist (ucl_object_tostring (elt),
						&conf->expected, FALSE, NULL);
			}
			else if (ucl_object_type (elt) == UCL_ARRAY) {
				const ucl_object_t *cur;
				ucl_object_iter_t it = NULL;

				while ((cur = ucl_object_iterate (elt, &it, true)) != NULL) {
					radix_add_generic_iplist (ucl_object_tostring (elt),
							&conf->expected, FALSE, NULL);
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

	if (!(m->flags & RSPAMD_MONITORED_RANDOM)) {
		rspamd_printf_gstring (req, "%s", m->url);
	}

	conf->request = req;

	return conf;
}

static void
rspamd_monitored_dns_cb (struct rdns_reply *reply, void *arg)
{
	struct rspamd_dns_monitored_conf *conf = arg;
	struct rspamd_monitored *m;
	struct rdns_reply_entry *cur;
	gboolean is_special_reply = FALSE;
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
					LL_FOREACH (reply->entries, cur) {
						if (cur->type == RDNS_REQUEST_A) {
							if ((guint32)cur->content.a.addr.s_addr ==
									htonl (INADDR_LOOPBACK)) {
								is_special_reply = TRUE;
							}
						}
					}

					if (is_special_reply) {
						msg_notice_mon ("DNS query blocked on %s "
									  "(127.0.0.1 returned), "
									  "possibly due to high volume",
								m->url);
					}
					else {
						msg_notice_mon ("DNS reply returned '%s' for %s while '%s' "
									  "was expected when querying for '%s'"
									  "(likely DNS spoofing or BL internal issues)",
								rdns_strerror (reply->code),
								m->url,
								rdns_strerror (conf->expected_code),
								conf->request->str);
					}

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
					msg_notice_mon ("bad address %s is returned when monitoring %s",
							rspamd_inet_address_to_string (addr),
							conf->request->str);
					rspamd_monitored_propagate_error (m,
							"invalid address");

					rspamd_inet_address_free (addr);
				}
				else {
					rspamd_monitored_propagate_success (m, lat);
					rspamd_inet_address_free (addr);
				}
			}
		}
		else {
			rspamd_monitored_propagate_success (m, lat);
		}
	}
}

static gboolean
rspamd_monitored_dns_mon (struct rspamd_monitored *m,
		struct rspamd_monitored_ctx *ctx, gpointer ud)
{
	struct rspamd_dns_monitored_conf *conf = ud;

	if (m->flags & RSPAMD_MONITORED_RANDOM) {
		rspamd_monitored_dns_random (m, conf);
	}

	if (!rdns_make_request_full (ctx->resolver, rspamd_monitored_dns_cb,
			conf, ctx->cfg->dns_timeout, ctx->cfg->dns_retransmits,
			1, conf->request->str, conf->rt)) {
		msg_notice_mon ("cannot make request to resolve %s (%s monitored url)",
				conf->request->str, conf->m->url);

		m->cur_errors ++;
		rspamd_monitored_propagate_error (m, "failed to make DNS request");

		return FALSE;
	}
	else {
		conf->check_tm = rspamd_get_calendar_ticks ();
	}

	return TRUE;
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

	ctx = g_malloc0 (sizeof (*ctx));
	ctx->monitoring_interval = default_monitoring_interval;
	ctx->max_errors = default_max_errors;
	ctx->offline_monitored_mult = default_offline_monitored_mult;
	ctx->initial_monitored_mult = default_initial_monitored_mult;
	ctx->max_monitored_mult = default_max_monitored_mult;
	ctx->min_monitored_mult = default_min_monitored_mult;
	ctx->elts = g_ptr_array_new ();
	ctx->helts = g_hash_table_new (g_str_hash, g_str_equal);

	return ctx;
}


void
rspamd_monitored_ctx_config (struct rspamd_monitored_ctx *ctx,
		struct rspamd_config *cfg,
		struct ev_loop *ev_base,
		struct rdns_resolver *resolver,
		mon_change_cb change_cb,
		gpointer ud)
{
	struct rspamd_monitored *m;
	guint i;

	g_assert (ctx != NULL);
	ctx->event_loop = ev_base;
	ctx->resolver = resolver;
	ctx->cfg = cfg;
	ctx->initialized = TRUE;
	ctx->change_cb = change_cb;
	ctx->ud = ud;

	if (cfg->monitored_interval != 0) {
		ctx->monitoring_interval = cfg->monitored_interval;
	}

	/* Start all events */
	for (i = 0; i < ctx->elts->len; i ++) {
		m = g_ptr_array_index (ctx->elts, i);
		m->monitoring_mult = ctx->initial_monitored_mult;
		rspamd_monitored_start (m);
		m->monitoring_mult = 1.0;
	}
}


struct ev_loop *
rspamd_monitored_ctx_get_ev_base (struct rspamd_monitored_ctx *ctx)
{
	return ctx->event_loop;
}


struct rspamd_monitored *
rspamd_monitored_create_ (struct rspamd_monitored_ctx *ctx,
		const gchar *line,
		enum rspamd_monitored_type type,
		enum rspamd_monitored_flags flags,
		const ucl_object_t *opts,
		const gchar *loc)
{
	struct rspamd_monitored *m;
	rspamd_cryptobox_hash_state_t st;
	gchar *cksum_encoded, cksum[rspamd_cryptobox_HASHBYTES];

	g_assert (ctx != NULL);

	m = g_malloc0 (sizeof (*m));
	m->type = type;
	m->flags = flags;

	m->url = g_strdup (line);
	m->ctx = ctx;
	m->monitoring_mult = ctx->initial_monitored_mult;
	m->max_errors = ctx->max_errors;
	m->alive = TRUE;

	if (type == RSPAMD_MONITORED_DNS) {
		m->proc.monitored_update = rspamd_monitored_dns_mon;
		m->proc.monitored_config = rspamd_monitored_dns_conf;
		m->proc.monitored_dtor = rspamd_monitored_dns_dtor;
	}
	else {
		g_free (m);

		return NULL;
	}

	if (opts) {
		const ucl_object_t *rnd_obj;

		rnd_obj = ucl_object_lookup (opts, "random");

		if (rnd_obj && ucl_object_type (rnd_obj) == UCL_BOOLEAN) {
			if (ucl_object_toboolean (rnd_obj)) {
				m->flags |= RSPAMD_MONITORED_RANDOM;
			}
		}
	}

	m->proc.ud = m->proc.monitored_config (m, ctx, opts);

	if (m->proc.ud == NULL) {
		g_free (m);

		return NULL;
	}

	/* Create a persistent tag */
	rspamd_cryptobox_hash_init (&st, NULL, 0);
	rspamd_cryptobox_hash_update (&st, m->url, strlen (m->url));
	rspamd_cryptobox_hash_update (&st, loc, strlen (loc));
	rspamd_cryptobox_hash_final (&st, cksum);
	cksum_encoded = rspamd_encode_base32 (cksum, sizeof (cksum), RSPAMD_BASE32_DEFAULT);
	rspamd_strlcpy (m->tag, cksum_encoded, sizeof (m->tag));

	if (g_hash_table_lookup (ctx->helts, m->tag) != NULL) {
		msg_err ("monitored error: tag collision detected for %s; "
				"url: %s", m->tag, m->url);
	}
	else {
		g_hash_table_insert (ctx->helts, m->tag, m);
	}

	g_free (cksum_encoded);

	g_ptr_array_add (ctx->elts, m);

	if (ctx->event_loop) {
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

gboolean
rspamd_monitored_set_alive (struct rspamd_monitored *m, gboolean alive)
{
	gboolean st;

	g_assert (m != NULL);
	st = m->alive;
	m->alive = alive;

	return st;
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

	ev_timer_stop (m->ctx->event_loop, &m->periodic);
}

void
rspamd_monitored_start (struct rspamd_monitored *m)
{
	gdouble jittered;

	g_assert (m != NULL);
	jittered = rspamd_time_jitter (m->ctx->monitoring_interval * m->monitoring_mult,
			0.0);

	msg_debug_mon ("started monitored object %s in %.2f seconds", m->url, jittered);

	if (ev_can_stop (&m->periodic)) {
		ev_timer_stop (m->ctx->event_loop, &m->periodic);
	}

	m->periodic.data = m;
	ev_timer_init (&m->periodic, rspamd_monitored_periodic, jittered, 0.0);
	ev_timer_start (m->ctx->event_loop, &m->periodic);
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
		m->proc.monitored_dtor (m, m->ctx, m->proc.ud);
		g_free (m->url);
		g_free (m);
	}

	g_ptr_array_free (ctx->elts, TRUE);
	g_hash_table_unref (ctx->helts);
	g_free (ctx);
}

struct rspamd_monitored *
rspamd_monitored_by_tag (struct rspamd_monitored_ctx *ctx,
		guchar tag[RSPAMD_MONITORED_TAG_LEN])
{
	struct rspamd_monitored *res;
	gchar rtag[RSPAMD_MONITORED_TAG_LEN];

	rspamd_strlcpy (rtag, tag, sizeof (rtag));
	res = g_hash_table_lookup (ctx->helts, rtag);

	return res;
}


void
rspamd_monitored_get_tag (struct rspamd_monitored *m,
		guchar tag_out[RSPAMD_MONITORED_TAG_LEN])
{
	g_assert (m != NULL);

	rspamd_strlcpy (tag_out, m->tag, RSPAMD_MONITORED_TAG_LEN);
}