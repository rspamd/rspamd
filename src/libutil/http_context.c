/*-
 * Copyright 2019 Vsevolod Stakhov
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

#include "http_context.h"
#include "http_private.h"
#include "keypair.h"
#include "keypairs_cache.h"
#include "cfg_file.h"
#include "contrib/libottery/ottery.h"
#include "rspamd.h"

static struct rspamd_http_context *default_ctx = NULL;

static void
rspamd_http_context_client_rotate_ev (gint fd, short what, void *arg)
{
	struct timeval rot_tv;
	struct rspamd_http_context *ctx = arg;
	gpointer kp;

	double_to_tv (ctx->config.client_key_rotate_time, &rot_tv);
	rot_tv.tv_sec += ottery_rand_range (rot_tv.tv_sec);
	event_del (&ctx->client_rotate_ev);
	event_add (&ctx->client_rotate_ev, &rot_tv);

	kp = ctx->client_kp;
	ctx->client_kp = rspamd_keypair_new (RSPAMD_KEYPAIR_KEX,
			RSPAMD_CRYPTOBOX_MODE_25519);
	rspamd_keypair_unref (kp);
}

static struct rspamd_http_context*
rspamd_http_context_new_default (struct rspamd_config *cfg,
								 struct event_base *ev_base)
{
	struct rspamd_http_context *ctx;

	static const int default_kp_size = 1024;
	static const gdouble default_rotate_time = 120;
	static const gchar *default_user_agent = "rspamd-" RSPAMD_VERSION_FULL;

	ctx = g_malloc0 (sizeof (*ctx));
	ctx->config.kp_cache_size_client = default_kp_size;
	ctx->config.kp_cache_size_server = default_kp_size;
	ctx->config.client_key_rotate_time = default_rotate_time;
	ctx->config.user_agent = default_user_agent;

	if (cfg) {
		ctx->ssl_ctx = cfg->libs_ctx->ssl_ctx;
		ctx->ssl_ctx_noverify = cfg->libs_ctx->ssl_ctx_noverify;
	}
	else {
		ctx->ssl_ctx = rspamd_init_ssl_ctx ();
		ctx->ssl_ctx_noverify = rspamd_init_ssl_ctx_noverify ();
	}

	ctx->ev_base = ev_base;

	return ctx;
}

static void
rspamd_http_context_init (struct rspamd_http_context *ctx)
{
	if (ctx->config.kp_cache_size_client > 0) {
		ctx->client_kp_cache = rspamd_keypair_cache_new (ctx->config.kp_cache_size_client);
	}

	if (ctx->config.kp_cache_size_client > 0) {
		ctx->client_kp_cache = rspamd_keypair_cache_new (ctx->config.kp_cache_size_client);
	}

	if (ctx->config.client_key_rotate_time > 0 && ctx->ev_base) {
		struct timeval tv;
		double jittered = rspamd_time_jitter (ctx->config.client_key_rotate_time,
				0);

		double_to_tv (jittered, &tv);
		event_set (&ctx->client_rotate_ev, -1, EV_TIMEOUT,
				rspamd_http_context_client_rotate_ev, ctx);
		event_base_set (ctx->ev_base, &ctx->client_rotate_ev);
		event_add (&ctx->client_rotate_ev, &tv);
	}

	default_ctx = ctx;
}

struct rspamd_http_context*
rspamd_http_context_create (struct rspamd_config *cfg,
							struct event_base *ev_base)
{
	struct rspamd_http_context *ctx;
	const ucl_object_t *http_obj;

	ctx = rspamd_http_context_new_default (cfg, ev_base);
	http_obj = ucl_object_lookup (cfg->rcl_obj, "http");

	if (http_obj) {
		const ucl_object_t *server_obj, *client_obj;

		client_obj = ucl_object_lookup (http_obj, "client");

		if (client_obj) {
			const ucl_object_t *kp_size;

			kp_size = ucl_object_lookup (client_obj, "cache_size");

			if (kp_size) {
				ctx->config.kp_cache_size_client = ucl_object_toint (kp_size);
			}

			const ucl_object_t *rotate_time;

			rotate_time = ucl_object_lookup (client_obj, "rotate_time");

			if (rotate_time) {
				ctx->config.client_key_rotate_time = ucl_object_todouble (rotate_time);
			}

			const ucl_object_t *user_agent;

			user_agent = ucl_object_lookup (client_obj, "user_agent");

			if (user_agent) {
				ctx->config.user_agent = ucl_object_tostring (user_agent);

				if (ctx->config.user_agent && strlen (ctx->config.user_agent) == 0) {
					ctx->config.user_agent = NULL;
				}
			}
		}

		server_obj = ucl_object_lookup (http_obj, "server");

		if (server_obj) {
			const ucl_object_t *kp_size;

			kp_size = ucl_object_lookup (server_obj, "cache_size");

			if (kp_size) {
				ctx->config.kp_cache_size_server = ucl_object_toint (kp_size);
			}
		}
	}

	rspamd_http_context_init (ctx);

	return ctx;
}

void
rspamd_http_context_free (struct rspamd_http_context *ctx)
{
	if (ctx == default_ctx) {
		default_ctx = NULL;
	}

	if (ctx->client_kp_cache) {
		rspamd_keypair_cache_destroy (ctx->client_kp_cache);
	}

	if (ctx->server_kp_cache) {
		rspamd_keypair_cache_destroy (ctx->server_kp_cache);
	}

	g_free (ctx);
}

struct rspamd_http_context*
rspamd_http_context_create_config (struct rspamd_http_context_cfg *cfg,
		struct event_base *ev_base)
{
	struct rspamd_http_context *ctx;

	ctx = rspamd_http_context_new_default (NULL, ev_base);
	memcpy (&ctx->config, cfg, sizeof (*cfg));
	rspamd_http_context_init (ctx);

	return ctx;
}

struct rspamd_http_context*
rspamd_http_context_default (void)
{
	g_assert (default_ctx != NULL);

	return default_ctx;
}