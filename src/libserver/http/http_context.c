/*
 * Copyright 2024 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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
#include "contrib/http-parser/http_parser.h"
#include "ssl_util.h"
#include "rspamd.h"
#include "libev_helper.h"

INIT_LOG_MODULE(http_context)

#define msg_debug_http_context(...) rspamd_conditional_debug_fast(NULL, NULL,                                       \
																  rspamd_http_context_log_id, "http_context", NULL, \
																  G_STRFUNC,                                        \
																  __VA_ARGS__)

static struct rspamd_http_context *default_ctx = NULL;

struct rspamd_http_keepalive_cbdata {
	struct rspamd_http_connection *conn;
	struct rspamd_http_context *ctx;
	GQueue *queue;
	GList *link;
	struct rspamd_io_ev ev;
};

static void
rspamd_http_keepalive_queue_cleanup(GQueue *conns)
{
	GList *cur;

	cur = conns->head;

	while (cur) {
		struct rspamd_http_keepalive_cbdata *cbd;

		cbd = (struct rspamd_http_keepalive_cbdata *) cur->data;
		/* unref call closes fd, so we need to remove ev watcher first! */
		rspamd_ev_watcher_stop(cbd->ctx->event_loop, &cbd->ev);
		rspamd_http_connection_unref(cbd->conn);
		g_free(cbd);

		cur = cur->next;
	}

	g_queue_clear(conns);
}

static void
rspamd_http_context_client_rotate_ev(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct rspamd_http_context *ctx = (struct rspamd_http_context *) w->data;
	gpointer kp;

	w->repeat = rspamd_time_jitter(ctx->config.client_key_rotate_time, 0);
	msg_debug_http_context("rotate local keypair, next rotate in %.0f seconds",
						   w->repeat);

	ev_timer_again(loop, w);

	kp = ctx->client_kp;
	ctx->client_kp = rspamd_keypair_new(RSPAMD_KEYPAIR_KEX);
	rspamd_keypair_unref(kp);
}

static struct rspamd_http_context *
rspamd_http_context_new_default(struct rspamd_config *cfg,
								struct ev_loop *ev_base,
								struct upstream_ctx *ups_ctx)
{
	struct rspamd_http_context *ctx;

	static const int default_kp_size = 1024;
	static const double default_rotate_time = 120;
	static const double default_keepalive_interval = 65;
	static const char *default_user_agent = "rspamd-" RSPAMD_VERSION_FULL;
	static const char *default_server_hdr = "rspamd/" RSPAMD_VERSION_FULL;

	ctx = g_malloc0(sizeof(*ctx));
	ctx->config.kp_cache_size_client = default_kp_size;
	ctx->config.kp_cache_size_server = default_kp_size;
	ctx->config.client_key_rotate_time = default_rotate_time;
	ctx->config.user_agent = default_user_agent;
	ctx->config.keepalive_interval = default_keepalive_interval;
	ctx->config.server_hdr = default_server_hdr;
	ctx->ups_ctx = ups_ctx;

	if (cfg) {
		ctx->ssl_ctx = cfg->libs_ctx->ssl_ctx;
		ctx->ssl_ctx_noverify = cfg->libs_ctx->ssl_ctx_noverify;
	}
	else {
		ctx->ssl_ctx = rspamd_init_ssl_ctx();
		ctx->ssl_ctx_noverify = rspamd_init_ssl_ctx_noverify();
	}

	ctx->event_loop = ev_base;

	ctx->keep_alive_hash = kh_init(rspamd_keep_alive_hash);

	return ctx;
}

static void
rspamd_http_context_parse_proxy(struct rspamd_http_context *ctx,
								const char *name,
								struct upstream_list **pls)
{
	struct http_parser_url u;
	struct upstream_list *uls;

	if (!ctx->ups_ctx) {
		msg_err("cannot parse http_proxy %s - upstreams context is undefined", name);
		return;
	}

	memset(&u, 0, sizeof(u));

	if (http_parser_parse_url(name, strlen(name), 1, &u) == 0) {
		if (!(u.field_set & (1u << UF_HOST)) || u.port == 0) {
			msg_err("cannot parse http(s) proxy %s - invalid host or port", name);

			return;
		}

		uls = rspamd_upstreams_create(ctx->ups_ctx);

		if (!rspamd_upstreams_parse_line_len(uls,
											 name + u.field_data[UF_HOST].off,
											 u.field_data[UF_HOST].len, u.port, NULL)) {
			msg_err("cannot parse http(s) proxy %s - invalid data", name);

			rspamd_upstreams_destroy(uls);
		}
		else {
			*pls = uls;
			msg_info("set http(s) proxy to %s", name);
		}
	}
	else {
		uls = rspamd_upstreams_create(ctx->ups_ctx);

		if (!rspamd_upstreams_parse_line(uls,
										 name, 3128, NULL)) {
			msg_err("cannot parse http(s) proxy %s - invalid data", name);

			rspamd_upstreams_destroy(uls);
		}
		else {
			*pls = uls;
			msg_info("set http(s) proxy to %s", name);
		}
	}
}

static void
rspamd_http_context_init(struct rspamd_http_context *ctx)
{
	if (ctx->config.kp_cache_size_client > 0) {
		ctx->client_kp_cache = rspamd_keypair_cache_new(ctx->config.kp_cache_size_client);
	}

	if (ctx->config.kp_cache_size_server > 0) {
		ctx->server_kp_cache = rspamd_keypair_cache_new(ctx->config.kp_cache_size_server);
	}

	if (ctx->config.client_key_rotate_time > 0 && ctx->event_loop) {
		double jittered = rspamd_time_jitter(ctx->config.client_key_rotate_time,
											 0);

		ev_timer_init(&ctx->client_rotate_ev,
					  rspamd_http_context_client_rotate_ev, jittered, 0);
		ev_timer_start(ctx->event_loop, &ctx->client_rotate_ev);
		ctx->client_rotate_ev.data = ctx;
	}

	if (ctx->config.http_proxy) {
		rspamd_http_context_parse_proxy(ctx, ctx->config.http_proxy,
										&ctx->http_proxies);
	}

	default_ctx = ctx;
}

struct rspamd_http_context *
rspamd_http_context_create(struct rspamd_config *cfg,
						   struct ev_loop *ev_base,
						   struct upstream_ctx *ups_ctx)
{
	struct rspamd_http_context *ctx;
	const ucl_object_t *http_obj;

	ctx = rspamd_http_context_new_default(cfg, ev_base, ups_ctx);
	http_obj = ucl_object_lookup(cfg->cfg_ucl_obj, "http");

	if (http_obj) {
		const ucl_object_t *server_obj, *client_obj;

		client_obj = ucl_object_lookup(http_obj, "client");

		if (client_obj) {
			const ucl_object_t *kp_size;

			kp_size = ucl_object_lookup(client_obj, "cache_size");

			if (kp_size) {
				ctx->config.kp_cache_size_client = ucl_object_toint(kp_size);
			}

			const ucl_object_t *rotate_time;

			rotate_time = ucl_object_lookup(client_obj, "rotate_time");

			if (rotate_time) {
				ctx->config.client_key_rotate_time = ucl_object_todouble(rotate_time);
			}

			const ucl_object_t *user_agent;

			user_agent = ucl_object_lookup(client_obj, "user_agent");

			if (user_agent) {
				ctx->config.user_agent = ucl_object_tostring(user_agent);

				if (ctx->config.user_agent && strlen(ctx->config.user_agent) == 0) {
					ctx->config.user_agent = NULL;
				}
			}

			const ucl_object_t *server_hdr;
			server_hdr = ucl_object_lookup(client_obj, "server_hdr");

			if (server_hdr) {
				ctx->config.server_hdr = ucl_object_tostring(server_hdr);

				if (ctx->config.server_hdr && strlen(ctx->config.server_hdr) == 0) {
					ctx->config.server_hdr = "";
				}
			}

			const ucl_object_t *keepalive_interval;

			keepalive_interval = ucl_object_lookup(client_obj, "keepalive_interval");

			if (keepalive_interval) {
				ctx->config.keepalive_interval = ucl_object_todouble(keepalive_interval);
			}

			const ucl_object_t *http_proxy;
			http_proxy = ucl_object_lookup(client_obj, "http_proxy");

			if (http_proxy) {
				ctx->config.http_proxy = ucl_object_tostring(http_proxy);
			}
		}

		server_obj = ucl_object_lookup(http_obj, "server");

		if (server_obj) {
			const ucl_object_t *kp_size;

			kp_size = ucl_object_lookup(server_obj, "cache_size");

			if (kp_size) {
				ctx->config.kp_cache_size_server = ucl_object_toint(kp_size);
			}
		}
	}

	rspamd_http_context_init(ctx);

	return ctx;
}


void rspamd_http_context_free(struct rspamd_http_context *ctx)
{
	if (ctx == default_ctx) {
		default_ctx = NULL;
	}

	if (ctx->client_kp_cache) {
		rspamd_keypair_cache_destroy(ctx->client_kp_cache);
	}

	if (ctx->server_kp_cache) {
		rspamd_keypair_cache_destroy(ctx->server_kp_cache);
	}

	if (ctx->config.client_key_rotate_time > 0) {
		ev_timer_stop(ctx->event_loop, &ctx->client_rotate_ev);

		if (ctx->client_kp) {
			rspamd_keypair_unref(ctx->client_kp);
		}
	}

	struct rspamd_keepalive_hash_key *hk;

	kh_foreach_key(ctx->keep_alive_hash, hk, {
		msg_debug_http_context("cleanup keepalive elt %s (%s)",
							   rspamd_inet_address_to_string_pretty(hk->addr),
							   hk->host);

		if (hk->host) {
			g_free(hk->host);
		}

		rspamd_inet_address_free(hk->addr);
		rspamd_http_keepalive_queue_cleanup(&hk->conns);
		g_free(hk);
	});

	kh_destroy(rspamd_keep_alive_hash, ctx->keep_alive_hash);

	if (ctx->http_proxies) {
		rspamd_upstreams_destroy(ctx->http_proxies);
	}

	g_free(ctx);
}

struct rspamd_http_context *
rspamd_http_context_create_config(struct rspamd_http_context_cfg *cfg,
								  struct ev_loop *ev_base,
								  struct upstream_ctx *ups_ctx)
{
	struct rspamd_http_context *ctx;

	ctx = rspamd_http_context_new_default(NULL, ev_base, ups_ctx);
	memcpy(&ctx->config, cfg, sizeof(*cfg));
	rspamd_http_context_init(ctx);

	return ctx;
}

struct rspamd_http_context *
rspamd_http_context_default(void)
{
	g_assert(default_ctx != NULL);

	return default_ctx;
}

int32_t
rspamd_keep_alive_key_hash(struct rspamd_keepalive_hash_key *k)
{
	rspamd_cryptobox_fast_hash_state_t hst;

	rspamd_cryptobox_fast_hash_init(&hst, 0);

	if (k->host) {
		rspamd_cryptobox_fast_hash_update(&hst, k->host, strlen(k->host));
	}

	rspamd_cryptobox_fast_hash_update(&hst, &k->port, sizeof(k->port));
	rspamd_cryptobox_fast_hash_update(&hst, &k->is_ssl, sizeof(k->is_ssl));

	return rspamd_cryptobox_fast_hash_final(&hst);
}

bool rspamd_keep_alive_key_equal(struct rspamd_keepalive_hash_key *k1,
								 struct rspamd_keepalive_hash_key *k2)
{
	if (k1->is_ssl != k2->is_ssl) {
		return false;
	}

	if (k1->host && k2->host) {
		if (k1->port == k2->port) {
			return strcmp(k1->host, k2->host) == 0;
		}
	}
	else if (!k1->host && !k2->host) {
		return (k1->port == k2->port);
	}

	/* One has host and another has no host */
	return false;
}

struct rspamd_http_connection *
rspamd_http_context_check_keepalive(struct rspamd_http_context *ctx,
									const rspamd_inet_addr_t *addr,
									const char *host,
									bool is_ssl)
{
	struct rspamd_keepalive_hash_key hk, *phk;
	khiter_t k;

	if (ctx == NULL) {
		ctx = rspamd_http_context_default();
	}

	hk.addr = (rspamd_inet_addr_t *) addr;
	hk.host = (char *) host;
	hk.port = rspamd_inet_address_get_port(addr);
	hk.is_ssl = is_ssl;

	k = kh_get(rspamd_keep_alive_hash, ctx->keep_alive_hash, &hk);

	if (k != kh_end(ctx->keep_alive_hash)) {
		phk = kh_key(ctx->keep_alive_hash, k);
		GQueue *conns = &phk->conns;

		/* Use stack based approach */

		if (g_queue_get_length(conns) > 0) {
			struct rspamd_http_keepalive_cbdata *cbd;
			struct rspamd_http_connection *conn;
			int err;
			socklen_t len = sizeof(int);

			cbd = g_queue_pop_head(conns);
			rspamd_ev_watcher_stop(ctx->event_loop, &cbd->ev);
			conn = cbd->conn;
			g_free(cbd);

			if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1) {
				err = errno;
			}

			if (err != 0) {
				rspamd_http_connection_unref(conn);

				msg_debug_http_context("invalid reused keepalive element %s (%s, ssl=%d); "
									   "%s error; "
									   "%d connections queued",
									   rspamd_inet_address_to_string_pretty(phk->addr),
									   phk->host,
									   (int) phk->is_ssl,
									   g_strerror(err),
									   conns->length);

				return NULL;
			}

			msg_debug_http_context("reused keepalive element %s (%s, ssl=%d), %d connections queued",
								   rspamd_inet_address_to_string_pretty(phk->addr),
								   phk->host,
								   (int) phk->is_ssl,
								   conns->length);

			/* We transfer refcount here! */
			return conn;
		}
		else {
			msg_debug_http_context("found empty keepalive element %s (%s), cannot reuse",
								   rspamd_inet_address_to_string_pretty(phk->addr),
								   phk->host);
		}
	}

	return NULL;
}

const rspamd_inet_addr_t *
rspamd_http_context_has_keepalive(struct rspamd_http_context *ctx,
								  const char *host,
								  unsigned port,
								  bool is_ssl)
{
	struct rspamd_keepalive_hash_key hk, *phk;
	khiter_t k;

	if (ctx == NULL) {
		ctx = rspamd_http_context_default();
	}

	hk.host = (char *) host;
	hk.port = port;
	hk.is_ssl = is_ssl;

	k = kh_get(rspamd_keep_alive_hash, ctx->keep_alive_hash, &hk);

	if (k != kh_end(ctx->keep_alive_hash)) {
		phk = kh_key(ctx->keep_alive_hash, k);
		GQueue *conns = &phk->conns;

		if (g_queue_get_length(conns) > 0) {
			return phk->addr;
		}
	}

	return NULL;
}

void rspamd_http_context_prepare_keepalive(struct rspamd_http_context *ctx,
										   struct rspamd_http_connection *conn,
										   const rspamd_inet_addr_t *addr,
										   const char *host,
										   bool is_ssl)
{
	struct rspamd_keepalive_hash_key hk, *phk;
	khiter_t k;

	hk.addr = (rspamd_inet_addr_t *) addr;
	hk.host = (char *) host;
	hk.is_ssl = is_ssl;
	hk.port = rspamd_inet_address_get_port(addr);

	k = kh_get(rspamd_keep_alive_hash, ctx->keep_alive_hash, &hk);

	if (k != kh_end(ctx->keep_alive_hash)) {
		/* Reuse existing */
		conn->keepalive_hash_key = kh_key(ctx->keep_alive_hash, k);
		msg_debug_http_context("use existing keepalive element %s (%s)",
							   rspamd_inet_address_to_string_pretty(conn->keepalive_hash_key->addr),
							   conn->keepalive_hash_key->host);
	}
	else {
		/* Create new one */
		GQueue empty_init = G_QUEUE_INIT;
		int r;

		phk = g_malloc(sizeof(*phk));
		phk->conns = empty_init;
		phk->host = g_strdup(host);
		phk->is_ssl = is_ssl;
		phk->addr = rspamd_inet_address_copy(addr, NULL);
		phk->port = hk.port;


		kh_put(rspamd_keep_alive_hash, ctx->keep_alive_hash, phk, &r);
		conn->keepalive_hash_key = phk;

		msg_debug_http_context("create new keepalive element %s (%s)",
							   rspamd_inet_address_to_string_pretty(conn->keepalive_hash_key->addr),
							   conn->keepalive_hash_key->host);
	}
}

static void
rspamd_http_keepalive_handler(int fd, short what, gpointer ud)
{
	struct rspamd_http_keepalive_cbdata *cbdata =
		(struct rspamd_http_keepalive_cbdata *) ud; /*
	 * We can get here if a remote side reported something or it has
	 * timed out. In both cases we just terminate keepalive connection.
	 */

	g_queue_delete_link(cbdata->queue, cbdata->link);
	msg_debug_http_context("remove keepalive element %s (%s), %d connections left",
						   rspamd_inet_address_to_string_pretty(cbdata->conn->keepalive_hash_key->addr),
						   cbdata->conn->keepalive_hash_key->host,
						   cbdata->queue->length);
	/* unref call closes fd, so we need to remove ev watcher first! */
	rspamd_ev_watcher_stop(cbdata->ctx->event_loop, &cbdata->ev);
	rspamd_http_connection_unref(cbdata->conn);
	g_free(cbdata);
}

/* Non-static for unit testing */
long rspamd_http_parse_keepalive_timeout(const rspamd_ftok_t *tok)
{
	long timeout = -1;
	goffset pos = rspamd_substring_search(tok->begin,
										  tok->len, "timeout", sizeof("timeout") - 1);

	if (pos != -1) {
		pos += sizeof("timeout") - 1;

		/* Skip spaces and equal sign */
		while (pos < tok->len) {
			if (tok->begin[pos] != '=' && !g_ascii_isspace(tok->begin[pos])) {
				break;
			}
			pos++;
		}

		gsize ndigits = rspamd_memspn(tok->begin + pos, "0123456789", tok->len - pos);
		glong real_timeout;

		if (ndigits > 0) {
			if (rspamd_strtoul(tok->begin + pos, ndigits, &real_timeout)) {
				timeout = real_timeout;
				msg_debug_http_context("got timeout attr %l", timeout);
			}
		}
	}

	return timeout;
}

void rspamd_http_context_push_keepalive(struct rspamd_http_context *ctx,
										struct rspamd_http_connection *conn,
										struct rspamd_http_message *msg,
										struct ev_loop *event_loop)
{
	struct rspamd_http_keepalive_cbdata *cbdata;
	double timeout = ctx->config.keepalive_interval;

	g_assert(conn->keepalive_hash_key != NULL);

	if (msg) {
		const rspamd_ftok_t *tok;
		rspamd_ftok_t cmp;

		tok = rspamd_http_message_find_header(msg, "Connection");

		if (!tok) {
			/* Server has not stated that it can do keep alive */
			conn->finished = TRUE;
			msg_debug_http_context("no Connection header");
			return;
		}

		RSPAMD_FTOK_ASSIGN(&cmp, "keep-alive");

		if (rspamd_ftok_casecmp(&cmp, tok) != 0) {
			conn->finished = TRUE;
			msg_debug_http_context("connection header is not `keep-alive`");
			return;
		}

		/* We can proceed, check timeout */

		tok = rspamd_http_message_find_header(msg, "Keep-Alive");

		if (tok) {
			long maybe_timeout = rspamd_http_parse_keepalive_timeout(tok);

			if (maybe_timeout > 0) {
				timeout = maybe_timeout;
			}
		}
	}

	/* Move connection to the keepalive pool */
	cbdata = g_malloc0(sizeof(*cbdata));

	cbdata->conn = rspamd_http_connection_ref(conn);
	/* Use stack like approach to that would easy reading */
	g_queue_push_head(&conn->keepalive_hash_key->conns, cbdata);
	cbdata->link = conn->keepalive_hash_key->conns.head;

	cbdata->queue = &conn->keepalive_hash_key->conns;
	cbdata->ctx = ctx;
	conn->finished = FALSE;

	rspamd_ev_watcher_init(&cbdata->ev, conn->fd, EV_READ,
						   rspamd_http_keepalive_handler,
						   cbdata);
	rspamd_ev_watcher_start(event_loop, &cbdata->ev, timeout);

	msg_debug_http_context("push keepalive element %s (%s), %d connections queued, %.1f timeout",
						   rspamd_inet_address_to_string_pretty(cbdata->conn->keepalive_hash_key->addr),
						   cbdata->conn->keepalive_hash_key->host,
						   cbdata->queue->length,
						   timeout);
}