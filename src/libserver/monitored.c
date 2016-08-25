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

static const gdouble default_monitoring_interval = 10.0;
static const guint default_max_errors = 3;

struct rspamd_monitored_methods {
	void * (*monitored_config) (struct rspamd_monitored *m,
			struct rspamd_monitored_ctx *ctx);
	void (*monitored_update) (struct rspamd_monitored *m,
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

static void
rspamd_monitored_periodic (gint fd, short what, gpointer ud)
{
	struct rspamd_monitored *m = ud;
	struct timeval tv;

	double_to_tv (m->monitoring_interval, &tv);

	if (m->proc.monitored_update) {
		m->proc.monitored_update (m, m->ctx, m->proc.ud);
	}

	event_add (&m->periodic, &tv);
}

struct rspamd_dns_monitored_conf {
	void *unused;
};

static void *
rspamd_monitored_dns_conf (struct rspamd_monitored *m,
		struct rspamd_monitored_ctx *ctx)
{
	struct rspamd_dns_monitored_conf *conf;

	conf = g_malloc0 (sizeof (*conf));

	return conf;
}

void
rspamd_monitored_dns_mon (struct rspamd_monitored *m,
		struct rspamd_monitored_ctx *ctx, gpointer ud)
{

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
		enum rspamd_monitored_flags flags)
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
		m->proc.ud = m->proc.monitored_config (m, ctx);

		if (m->proc.ud == NULL) {
			g_slice_free1 (sizeof (*m), m);

			return NULL;
		}
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

	g_assert (m != NULL);
	msg_debug_mon ("started monitored object %s", m->url);
	double_to_tv (m->monitoring_interval, &tv);

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
		g_free (m->proc.ud);
		g_slice_free1 (sizeof (*m), m);
	}

	g_ptr_array_free (ctx->elts, TRUE);
	g_slice_free1 (sizeof (*ctx), ctx);
}
