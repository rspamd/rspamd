/*
 * Copyright 2025 Vsevolod Stakhov
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

#include "config.h"
#include "libutil/util.h"
#include "libutil/addr.h"
#include "libserver/cfg_file.h"
#include "libserver/cfg_rcl.h"
#include "libserver/dns.h"
#include "libserver/ssl_util.h"
#include "libserver/worker_util.h"
#include "rspamd.h"
#include "lua/lua_common.h"
#include "unix-std.h"

#include "libserver/smtp_proxy/smtp_proxy_session.hxx"

#include <unordered_map>
#include <memory>

/* Log module ID */
INIT_LOG_MODULE(smtp_proxy)

/* Worker function declarations */
extern "C" {
gpointer init_smtp_proxy(struct rspamd_config *cfg);
void start_smtp_proxy(struct rspamd_worker *worker);
}

/* Worker definition */
worker_t smtp_proxy_worker = {
	"smtp_proxy",     /* Name */
	init_smtp_proxy,  /* Init function */
	start_smtp_proxy, /* Start function */
	RSPAMD_WORKER_HAS_SOCKET | RSPAMD_WORKER_KILLABLE,
	RSPAMD_WORKER_SOCKET_TCP, /* TCP socket */
	RSPAMD_WORKER_VER};

/* Session storage */
static std::unordered_map<void *, rspamd::smtp::smtp_proxy_session::ptr> g_sessions;

/* Logging macros */
#define msg_err_ctx(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL,                                                         \
													 "smtp_proxy", ctx->worker ? ctx->worker->srv->cfg->cfg_pool->tag.uid : "???", \
													 RSPAMD_LOG_FUNC, __VA_ARGS__)
#define msg_warn_ctx(...) rspamd_default_log_function(G_LOG_LEVEL_WARNING,                                                          \
													  "smtp_proxy", ctx->worker ? ctx->worker->srv->cfg->cfg_pool->tag.uid : "???", \
													  RSPAMD_LOG_FUNC, __VA_ARGS__)
#define msg_info_ctx(...) rspamd_default_log_function(G_LOG_LEVEL_INFO,                                                             \
													  "smtp_proxy", ctx->worker ? ctx->worker->srv->cfg->cfg_pool->tag.uid : "???", \
													  RSPAMD_LOG_FUNC, __VA_ARGS__)

/**
 * Accept callback for new connections
 */
static void
smtp_proxy_accept_socket(struct ev_loop *loop, ev_io *w, int revents)
{
	auto *worker = static_cast<struct rspamd_worker *>(w->data);
	auto *ctx = static_cast<rspamd::smtp::smtp_proxy_ctx *>(worker->ctx);

	rspamd_inet_addr_t *addr = nullptr;
	int nfd = rspamd_accept_from_socket(w->fd, &addr, nullptr, nullptr);

	if (nfd < 0) {
		if (addr) {
			rspamd_inet_address_free(addr);
		}
		return;
	}

	/* Check connection limits (use worker-level limit if configured) */
	if (ctx->max_connections > 0 &&
		worker->nconns >= ctx->max_connections) {
		msg_info_ctx("connection limit reached (%u), rejecting connection from %s",
					 ctx->max_connections,
					 rspamd_inet_address_to_string(addr));
		close(nfd);
		rspamd_inet_address_free(addr);
		return;
	}

	msg_info_ctx("accepted connection from %s on fd %d",
				 rspamd_inet_address_to_string(addr), nfd);

	/* Create session */
	auto session = rspamd::smtp::smtp_proxy_session::create(ctx, nfd, addr);

	if (!session) {
		msg_err_ctx("failed to create session for %s",
					rspamd_inet_address_to_string(addr));
		close(nfd);
		rspamd_inet_address_free(addr);
		return;
	}

	/* Store session */
	g_sessions[session.get()] = session;
	worker->nconns++;

	/* Start the session */
	session->start();
}

/**
 * Parse precheck configuration
 */
static gboolean
rspamd_smtp_proxy_parse_precheck(rspamd_mempool_t *pool,
								 const ucl_object_t *obj,
								 gpointer ud,
								 struct rspamd_rcl_section *section,
								 GError **err)
{
	auto *ctx = static_cast<rspamd::smtp::smtp_proxy_ctx *>(ud);
	const char *val = ucl_object_tostring(obj);

	if (!val) {
		ctx->precheck_hook = rspamd::smtp::precheck_point::disabled;
		return TRUE;
	}

	if (g_ascii_strcasecmp(val, "connect") == 0) {
		ctx->precheck_hook = rspamd::smtp::precheck_point::on_connect;
	}
	else if (g_ascii_strcasecmp(val, "mail") == 0 ||
			 g_ascii_strcasecmp(val, "after_mail") == 0) {
		ctx->precheck_hook = rspamd::smtp::precheck_point::after_mail;
	}
	else if (g_ascii_strcasecmp(val, "rcpt") == 0 ||
			 g_ascii_strcasecmp(val, "after_first_rcpt") == 0) {
		ctx->precheck_hook = rspamd::smtp::precheck_point::after_first_rcpt;
	}
	else if (g_ascii_strcasecmp(val, "disabled") == 0 ||
			 g_ascii_strcasecmp(val, "none") == 0) {
		ctx->precheck_hook = rspamd::smtp::precheck_point::disabled;
	}
	else {
		g_set_error(err, g_quark_from_static_string("smtp_proxy"), EINVAL,
					"invalid precheck value: %s", val);
		return FALSE;
	}

	return TRUE;
}

/**
 * Parse backend configuration
 */
static gboolean
rspamd_smtp_proxy_parse_backend(rspamd_mempool_t *pool,
								const ucl_object_t *obj,
								gpointer ud,
								struct rspamd_rcl_section *section,
								GError **err)
{
	auto *ctx = static_cast<rspamd::smtp::smtp_proxy_ctx *>(ud);

	if (ucl_object_type(obj) == UCL_STRING) {
		/* Simple format: "host:port" or just "host" */
		const char *val = ucl_object_tostring(obj);
		std::string backend_str(val);

		auto colon_pos = backend_str.find(':');
		if (colon_pos != std::string::npos) {
			ctx->backend_host = backend_str.substr(0, colon_pos);
			ctx->backend_port = static_cast<uint16_t>(
				std::stoul(backend_str.substr(colon_pos + 1)));
		}
		else {
			ctx->backend_host = backend_str;
			ctx->backend_port = 25;
		}
	}
	else if (ucl_object_type(obj) == UCL_OBJECT) {
		/* Complex format with options */
		const ucl_object_t *host = ucl_object_lookup(obj, "host");
		const ucl_object_t *port = ucl_object_lookup(obj, "port");
		const ucl_object_t *ssl = ucl_object_lookup(obj, "ssl");

		if (host) {
			ctx->backend_host = ucl_object_tostring(host);
		}
		if (port) {
			ctx->backend_port = static_cast<uint16_t>(ucl_object_toint(port));
		}
		if (ssl) {
			ctx->backend_ssl = ucl_object_toboolean(ssl);
		}
	}
	else {
		g_set_error(err, g_quark_from_static_string("smtp_proxy"), EINVAL,
					"backend must be a string or object");
		return FALSE;
	}

	return TRUE;
}

/**
 * Initialize worker context
 */
gpointer
init_smtp_proxy(struct rspamd_config *cfg)
{
	auto *ctx = rspamd_mempool_alloc0_type(cfg->cfg_pool,
										   rspamd::smtp::smtp_proxy_ctx);

	/* Initialize with magic and defaults */
	new (ctx) rspamd::smtp::smtp_proxy_ctx();

	GQuark type = g_quark_try_string("smtp_proxy");

	/* Register configuration options */
	rspamd_rcl_register_worker_option(cfg,
									  type,
									  "timeout",
									  rspamd_rcl_parse_struct_time,
									  ctx,
									  G_STRUCT_OFFSET(rspamd::smtp::smtp_proxy_ctx, client_timeout),
									  RSPAMD_CL_FLAG_TIME_FLOAT,
									  "Client connection timeout (default: 300s)");

	rspamd_rcl_register_worker_option(cfg,
									  type,
									  "backend_timeout",
									  rspamd_rcl_parse_struct_time,
									  ctx,
									  G_STRUCT_OFFSET(rspamd::smtp::smtp_proxy_ctx, backend_timeout),
									  RSPAMD_CL_FLAG_TIME_FLOAT,
									  "Backend connection timeout (default: 60s)");

	rspamd_rcl_register_worker_option(cfg,
									  type,
									  "greeting_delay",
									  rspamd_rcl_parse_struct_time,
									  ctx,
									  G_STRUCT_OFFSET(rspamd::smtp::smtp_proxy_ctx, greeting_delay),
									  RSPAMD_CL_FLAG_TIME_FLOAT,
									  "Delay before sending greeting (tarpit)");

	rspamd_rcl_register_worker_option(cfg,
									  type,
									  "max_line_length",
									  rspamd_rcl_parse_struct_integer,
									  ctx,
									  G_STRUCT_OFFSET(rspamd::smtp::smtp_proxy_ctx, max_line_length),
									  RSPAMD_CL_FLAG_INT_SIZE,
									  "Maximum line length (default: 4096)");

	rspamd_rcl_register_worker_option(cfg,
									  type,
									  "max_pipelined",
									  rspamd_rcl_parse_struct_integer,
									  ctx,
									  G_STRUCT_OFFSET(rspamd::smtp::smtp_proxy_ctx, max_outstanding),
									  RSPAMD_CL_FLAG_INT_SIZE,
									  "Maximum pipelined commands (default: 10)");

	rspamd_rcl_register_worker_option(cfg,
									  type,
									  "max_connections",
									  rspamd_rcl_parse_struct_integer,
									  ctx,
									  G_STRUCT_OFFSET(rspamd::smtp::smtp_proxy_ctx, max_connections),
									  RSPAMD_CL_FLAG_INT_SIZE,
									  "Maximum concurrent connections (default: 0 = unlimited)");

	rspamd_rcl_register_worker_option(cfg,
									  type,
									  "starttls",
									  rspamd_rcl_parse_struct_boolean,
									  ctx,
									  G_STRUCT_OFFSET(rspamd::smtp::smtp_proxy_ctx, starttls_enabled),
									  0,
									  "Enable STARTTLS support");

	rspamd_rcl_register_worker_option(cfg,
									  type,
									  "backend",
									  rspamd_smtp_proxy_parse_backend,
									  ctx,
									  0,
									  0,
									  "Backend MTA configuration (host:port or object)");

	rspamd_rcl_register_worker_option(cfg,
									  type,
									  "precheck",
									  rspamd_smtp_proxy_parse_precheck,
									  ctx,
									  0,
									  0,
									  "Precheck hook point: disabled, connect, after_mail, after_first_rcpt");

	return ctx;
}

/**
 * Start worker
 */
__attribute__((noreturn)) void
start_smtp_proxy(struct rspamd_worker *worker)
{
	auto *ctx = static_cast<rspamd::smtp::smtp_proxy_ctx *>(worker->ctx);

	g_assert(rspamd_worker_check_context(worker->ctx, rspamd::smtp::smtp_proxy_ctx::magic));

	ctx->cfg = worker->srv->cfg;
	ctx->worker = worker;
	CFG_REF_RETAIN(ctx->cfg);

	/* Prepare worker */
	ctx->event_loop = rspamd_prepare_worker(worker, "smtp_proxy", smtp_proxy_accept_socket);

	/* Initialize DNS resolver */
	ctx->resolver = rspamd_dns_resolver_init(worker->srv->logger,
											 ctx->event_loop,
											 worker->srv->cfg);

	rspamd_upstreams_library_config(worker->srv->cfg, ctx->cfg->ups_ctx,
									ctx->event_loop, ctx->resolver->r);

	/* Initialize SSL context if STARTTLS is enabled */
	if (ctx->starttls_enabled) {
		ctx->ssl_ctx = rspamd_init_ssl_ctx();
		if (ctx->ssl_ctx) {
			rspamd_ssl_ctx_config(ctx->cfg, ctx->ssl_ctx);
		}
	}

	/* Store Lua state reference */
	ctx->lua_state = static_cast<lua_State *>(ctx->cfg->lua_state);

	/* Create sessions cache */
	ctx->sessions_cache = rspamd_worker_session_cache_new(worker, ctx->event_loop);

	msg_info_ctx("started smtp_proxy worker, backend: %s:%d, starttls: %s",
				 ctx->backend_host.empty() ? "127.0.0.1" : ctx->backend_host.c_str(),
				 ctx->backend_port,
				 ctx->starttls_enabled ? "enabled" : "disabled");

	/* Run Lua postloads */
	rspamd_lua_run_postloads(ctx->lua_state, ctx->cfg, ctx->event_loop, worker);

	/* Main event loop */
	ev_loop(ctx->event_loop, 0);

	/* Cleanup */
	rspamd_worker_block_signals();

	/* Close all sessions */
	g_sessions.clear();

	if (ctx->ssl_ctx) {
		rspamd_ssl_ctx_free(ctx->ssl_ctx);
	}

	CFG_REF_RELEASE(ctx->cfg);
	rspamd_log_close(worker->srv->logger);
	rspamd_unset_crash_handler(worker->srv);

	exit(EXIT_SUCCESS);
}
