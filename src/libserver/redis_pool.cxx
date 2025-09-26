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
#include "contrib/libev/ev.h"
#include "redis_pool.h"
#include "cfg_file.h"
#include "contrib/hiredis/hiredis.h"
#include "contrib/hiredis/async.h"
#include "contrib/hiredis/hiredis_ssl.h"
#include "contrib/hiredis/adapters/libev.h"
#include "cryptobox.h"
#include "logger.h"
#include "contrib/ankerl/unordered_dense.h"

#include <list>
#include <unordered_map>

namespace rspamd {
class redis_pool_elt;
class redis_pool;

#define msg_debug_rpool(...) rspamd_conditional_debug_fast(NULL, NULL,                                        \
														   rspamd_redis_pool_log_id, "redis_pool", conn->tag, \
														   __FUNCTION__,                                      \
														   __VA_ARGS__)

INIT_LOG_MODULE(redis_pool)

enum class rspamd_redis_pool_connection_state : std::uint8_t {
	RSPAMD_REDIS_POOL_CONN_INACTIVE = 0,
	RSPAMD_REDIS_POOL_CONN_ACTIVE,
	RSPAMD_REDIS_POOL_CONN_FINALISING
};

struct redis_pool_connection {
	using redis_pool_connection_ptr = std::unique_ptr<redis_pool_connection>;
	using conn_iter_t = std::list<redis_pool_connection_ptr>::iterator;
	struct redisAsyncContext *ctx;
	redis_pool_elt *elt;
	redis_pool *pool;
	conn_iter_t elt_pos;
	ev_timer timeout;
	char tag[MEMPOOL_UID_LEN];
	rspamd_redis_pool_connection_state state;

	auto schedule_timeout() -> void;
	~redis_pool_connection();

	explicit redis_pool_connection(redis_pool *_pool,
								   redis_pool_elt *_elt,
								   const std::string &db,
								   const std::string &username,
								   const std::string &password,
								   struct redisAsyncContext *_ctx);

private:
	static auto redis_conn_timeout_cb(EV_P_ ev_timer *w, int revents) -> void;
	static auto redis_quit_cb(redisAsyncContext *c, void *r, void *priv) -> void;
	static auto redis_on_disconnect(const struct redisAsyncContext *ac, int status) -> auto;
};


using redis_pool_key_t = std::uint64_t;
class redis_pool;

class redis_pool_elt {
	using redis_pool_connection_ptr = std::unique_ptr<redis_pool_connection>;
	redis_pool *pool;
	/*
	 * These lists owns connections, so if an element is removed from both
	 * lists, it is destructed
	 */
	std::list<redis_pool_connection_ptr> active;
	std::list<redis_pool_connection_ptr> inactive;
	std::list<redis_pool_connection_ptr> terminating;
	std::string ip;
	std::string db;
	std::string username;
	std::string password;
	/* TLS options */
	bool use_tls = false;
	bool no_ssl_verify = false;
	std::string ca_file;
	std::string ca_dir;
	std::string cert_file;
	std::string key_file;
	std::string sni;
	int port;
	redis_pool_key_t key;
	bool is_unix;

public:
	/* Disable copy */
	redis_pool_elt() = delete;
	redis_pool_elt(const redis_pool_elt &) = delete;
	/* Enable move */
	redis_pool_elt(redis_pool_elt &&other) = default;

	explicit redis_pool_elt(redis_pool *_pool,
							const char *_db, const char *_username,
							const char *_password,
							const char *_ip, int _port,
							bool _use_tls = false,
							bool _no_ssl_verify = false,
							const char *_ca_file = nullptr,
							const char *_ca_dir = nullptr,
							const char *_cert_file = nullptr,
							const char *_key_file = nullptr,
							const char *_sni = nullptr)
		: pool(_pool), ip(_ip), port(_port),
		  key(redis_pool_elt::make_key(_db, _username, _password, _ip, _port,
									   _use_tls, _no_ssl_verify,
									   _ca_file, _ca_dir, _cert_file, _key_file, _sni))
	{
		is_unix = ip[0] == '.' || ip[0] == '/';

		if (_db) {
			db = _db;
		}
		if (_username) {
			username = _username;
		}
		if (_password) {
			password = _password;
		}

		use_tls = _use_tls;
		no_ssl_verify = _no_ssl_verify;
		if (_ca_file) ca_file = _ca_file;
		if (_ca_dir) ca_dir = _ca_dir;
		if (_cert_file) cert_file = _cert_file;
		if (_key_file) key_file = _key_file;
		if (_sni) sni = _sni;
	}

	auto new_connection() -> redisAsyncContext *;

	auto release_connection(const redis_pool_connection *conn) -> void
	{
		switch (conn->state) {
		case rspamd_redis_pool_connection_state::RSPAMD_REDIS_POOL_CONN_ACTIVE:
			active.erase(conn->elt_pos);
			break;
		case rspamd_redis_pool_connection_state::RSPAMD_REDIS_POOL_CONN_INACTIVE:
			inactive.erase(conn->elt_pos);
			break;
		case rspamd_redis_pool_connection_state::RSPAMD_REDIS_POOL_CONN_FINALISING:
			terminating.erase(conn->elt_pos);
			break;
		}
	}

	auto move_to_inactive(redis_pool_connection *conn) -> void
	{
		inactive.splice(std::end(inactive), active, conn->elt_pos);
		conn->elt_pos = std::prev(std::end(inactive));
	}

	auto move_to_terminating(redis_pool_connection *conn) -> void
	{
		terminating.splice(std::end(terminating), inactive, conn->elt_pos);
		conn->elt_pos = std::prev(std::end(terminating));
	}

	inline static auto make_key(const char *db, const char *username,
								const char *password, const char *ip, int port,
								bool use_tls = false, bool no_ssl_verify = false,
								const char *ca_file = nullptr, const char *ca_dir = nullptr,
								const char *cert_file = nullptr, const char *key_file = nullptr,
								const char *sni = nullptr) -> redis_pool_key_t
	{
		rspamd_cryptobox_fast_hash_state_t st;

		rspamd_cryptobox_fast_hash_init(&st, rspamd_hash_seed());

		if (db) {
			rspamd_cryptobox_fast_hash_update(&st, db, strlen(db));
		}
		if (username) {
			rspamd_cryptobox_fast_hash_update(&st, username, strlen(username));
		}
		if (password) {
			rspamd_cryptobox_fast_hash_update(&st, password, strlen(password));
		}

		rspamd_cryptobox_fast_hash_update(&st, ip, strlen(ip));
		rspamd_cryptobox_fast_hash_update(&st, &port, sizeof(port));

		/* TLS parameters */
		rspamd_cryptobox_fast_hash_update(&st, &use_tls, sizeof(use_tls));
		rspamd_cryptobox_fast_hash_update(&st, &no_ssl_verify, sizeof(no_ssl_verify));
		if (ca_file) {
			rspamd_cryptobox_fast_hash_update(&st, ca_file, strlen(ca_file));
		}
		if (ca_dir) {
			rspamd_cryptobox_fast_hash_update(&st, ca_dir, strlen(ca_dir));
		}
		if (cert_file) {
			rspamd_cryptobox_fast_hash_update(&st, cert_file, strlen(cert_file));
		}
		if (key_file) {
			rspamd_cryptobox_fast_hash_update(&st, key_file, strlen(key_file));
		}
		if (sni) {
			rspamd_cryptobox_fast_hash_update(&st, sni, strlen(sni));
		}

		return rspamd_cryptobox_fast_hash_final(&st);
	}

	auto num_active() const -> auto
	{
		return active.size();
	}

	~redis_pool_elt()
	{
		rspamd_explicit_memzero(password.data(), password.size());
	}

private:
	auto initiate_tls(redisAsyncContext *ctx) const -> bool
	{
		redisSSLContextError ssl_err = REDIS_SSL_CTX_NONE;
		redisSSLOptions opts{};
		opts.cacert_filename = ca_file.empty() ? nullptr : ca_file.c_str();
		opts.capath = ca_dir.empty() ? nullptr : ca_dir.c_str();
		opts.cert_filename = cert_file.empty() ? nullptr : cert_file.c_str();
		opts.private_key_filename = key_file.empty() ? nullptr : key_file.c_str();
		opts.server_name = sni.empty() ? nullptr : sni.c_str();
		opts.verify_mode = no_ssl_verify ? REDIS_SSL_VERIFY_NONE : REDIS_SSL_VERIFY_PEER;
		auto *ssl_ctx = redisCreateSSLContextWithOptions(&opts, &ssl_err);
		if (!ssl_ctx || redisInitiateSSLWithContext(&ctx->c, ssl_ctx) != REDIS_OK) {
			msg_err("cannot start TLS for redis %s:%d: %s", ip.c_str(), port, ctx->errstr);
			if (ssl_ctx) redisFreeSSLContext(ssl_ctx);
			return false;
		}
		redisFreeSSLContext(ssl_ctx);
		return true;
	}

	auto redis_async_new() -> redisAsyncContext *
	{
		struct redisAsyncContext *ctx;

		if (is_unix) {
			ctx = redisAsyncConnectUnix(ip.c_str());
		}
		else {
			ctx = redisAsyncConnect(ip.c_str(), port);
		}

		if (ctx && ctx->err != REDIS_OK) {
			msg_err("cannot connect to redis %s (port %d): %s", ip.c_str(), port,
					ctx->errstr);
			redisAsyncFree(ctx);

			return nullptr;
		}

		return ctx;
	}
};

class redis_pool final {
	static constexpr const double default_timeout = 10.0;
	static constexpr const unsigned default_max_conns = 100;

	/* We want to have references integrity */
	ankerl::unordered_dense::map<redisAsyncContext *,
								 redis_pool_connection *>
		conns_by_ctx;
	/*
	 * We store a pointer to the element in each connection, so this has to be
	 * a buckets map with pointers/references stability guarantees.
	 */
	std::unordered_map<redis_pool_key_t, redis_pool_elt> elts_by_key;
	bool wanna_die = false; /* Hiredis is 'clever' so we can call ourselves from destructor */
public:
	double timeout = default_timeout;
	unsigned max_conns = default_max_conns;
	struct ev_loop *event_loop;
	struct rspamd_config *cfg;

public:
	explicit redis_pool()
		: event_loop(nullptr), cfg(nullptr)
	{
		conns_by_ctx.reserve(max_conns);
	}

	/* Legacy stuff */
	auto do_config(struct ev_loop *_loop, struct rspamd_config *_cfg) -> void
	{
		event_loop = _loop;
		cfg = _cfg;
	}

	auto new_connection(const char *db, const char *username,
						const char *password, const char *ip, int port) -> redisAsyncContext *;

	auto new_connection_ext(const char *db, const char *username,
							const char *password, const char *ip, int port,
							bool use_tls, bool no_ssl_verify,
							const char *ca_file, const char *ca_dir,
							const char *cert_file, const char *key_file,
							const char *sni) -> redisAsyncContext *;

	auto release_connection(redisAsyncContext *ctx,
							enum rspamd_redis_pool_release_type how) -> void;

	auto unregister_context(redisAsyncContext *ctx) -> void
	{
		conns_by_ctx.erase(ctx);
	}

	auto register_context(redisAsyncContext *ctx, redis_pool_connection *conn)
	{
		conns_by_ctx.emplace(ctx, conn);
	}

	/* Hack to prevent Redis callbacks to be executed */
	auto prepare_to_die() -> void
	{
		wanna_die = true;
	}

	~redis_pool()
	{
	}
};


redis_pool_connection::~redis_pool_connection()
{
	const auto *conn = this; /* For debug */

	if (state == rspamd_redis_pool_connection_state::RSPAMD_REDIS_POOL_CONN_ACTIVE) {
		msg_debug_rpool("active connection destructed: %p", ctx);

		if (ctx) {
			pool->unregister_context(ctx);

			if (!(ctx->c.flags & REDIS_FREEING)) {
				auto *ac = ctx;
				ctx = nullptr;
				ac->onDisconnect = nullptr;
				redisAsyncFree(ac);
			}
		}
	}
	else {
		msg_debug_rpool("inactive connection destructed: %p", ctx);

		ev_timer_stop(pool->event_loop, &timeout);
		if (ctx) {
			pool->unregister_context(ctx);

			if (!(ctx->c.flags & REDIS_FREEING)) {
				auto *ac = ctx;
				/* To prevent on_disconnect here */
				ctx = nullptr;
				ac->onDisconnect = nullptr;
				redisAsyncFree(ac);
			}
		}
	}
}

auto redis_pool_connection::redis_quit_cb(redisAsyncContext *c, void *r, void *priv) -> void
{
	struct redis_pool_connection *conn =
		(struct redis_pool_connection *) priv;

	msg_debug_rpool("quit command reply for the connection %p",
					conn->ctx);
	/*
	 * The connection will be freed by hiredis itself as we are here merely after
	 * quit command has succeeded and we have timer being set already.
	 * The problem is that when this callback is called, our connection is likely
	 * dead, so probably even on_disconnect callback has been already called...
	 *
	 * Hence, the connection might already be freed, so even (conn) pointer may be
	 * inaccessible.
	 *
	 * TODO: Use refcounts to prevent this stuff to happen, the problem is how
	 * to handle Redis timeout on `quit` command in fact... The good thing is that
	 * it will not likely happen.
	 */
}

/*
 * Called for inactive connections that due to be removed
 */
auto redis_pool_connection::redis_conn_timeout_cb(EV_P_ ev_timer *w, int revents) -> void
{
	auto *conn = (struct redis_pool_connection *) w->data;

	g_assert(conn->state != rspamd_redis_pool_connection_state::RSPAMD_REDIS_POOL_CONN_ACTIVE);

	if (conn->state == rspamd_redis_pool_connection_state::RSPAMD_REDIS_POOL_CONN_INACTIVE) {
		msg_debug_rpool("scheduled soft removal of connection %p",
						conn->ctx);
		conn->state = rspamd_redis_pool_connection_state::RSPAMD_REDIS_POOL_CONN_FINALISING;
		ev_timer_again(EV_A_ w);
		redisAsyncCommand(conn->ctx, redis_pool_connection::redis_quit_cb, conn, "QUIT");
		conn->elt->move_to_terminating(conn);
	}
	else {
		/* Finalising by timeout */
		ev_timer_stop(EV_A_ w);
		msg_debug_rpool("final removal of connection %p, refcount: %d",
						conn->ctx);

		/* Erasure of shared pointer will cause it to be removed */
		conn->elt->release_connection(conn);
	}
}

auto redis_pool_connection::redis_on_disconnect(const struct redisAsyncContext *ac, int status) -> auto
{
	auto *conn = (struct redis_pool_connection *) ac->data;

	/*
	 * Here, we know that redis itself will free this connection
	 * so, we need to do something very clever about it
	 */
	if (conn->state != rspamd_redis_pool_connection_state::RSPAMD_REDIS_POOL_CONN_ACTIVE) {
		/* Do nothing for active connections as it is already handled somewhere */
		if (conn->ctx) {
			msg_debug_rpool("inactive connection terminated: %s",
							conn->ctx->errstr);
		}

		/* Erasure of shared pointer will cause it to be removed */
		conn->elt->release_connection(conn);
	}
}

auto redis_pool_connection::schedule_timeout() -> void
{
	const auto *conn = this; /* For debug */
	double real_timeout;
	auto active_elts = elt->num_active();

	if (active_elts > pool->max_conns) {
		real_timeout = pool->timeout / 2.0;
		real_timeout = rspamd_time_jitter(real_timeout, real_timeout / 4.0);
	}
	else {
		real_timeout = pool->timeout;
		real_timeout = rspamd_time_jitter(real_timeout, real_timeout / 2.0);
	}

	msg_debug_rpool("scheduled connection %p cleanup in %.1f seconds",
					ctx, real_timeout);

	timeout.data = this;
	/* Restore in case if these fields have been modified externally */
	ctx->data = this;
	redisAsyncSetDisconnectCallback(ctx, redis_pool_connection::redis_on_disconnect);
	ev_timer_init(&timeout,
				  redis_pool_connection::redis_conn_timeout_cb,
				  real_timeout, real_timeout / 2.0);
	ev_timer_start(pool->event_loop, &timeout);
}


redis_pool_connection::redis_pool_connection(redis_pool *_pool,
											 redis_pool_elt *_elt,
											 const std::string &db,
											 const std::string &username,
											 const std::string &password,
											 struct redisAsyncContext *_ctx)
	: ctx(_ctx), elt(_elt), pool(_pool)
{

	state = rspamd_redis_pool_connection_state::RSPAMD_REDIS_POOL_CONN_ACTIVE;

	pool->register_context(ctx, this);
	ctx->data = this;
	memset(tag, 0, sizeof(tag));
	rspamd_random_hex(tag, sizeof(tag) - 1);

	redisLibevAttach(pool->event_loop, ctx);
	redisAsyncSetDisconnectCallback(ctx, redis_pool_connection::redis_on_disconnect);

	if (!username.empty()) {
		if (!password.empty()) {
			redisAsyncCommand(ctx, nullptr, nullptr,
							  "AUTH %s %s", username.c_str(), password.c_str());
		}
		else {
			msg_warn("Redis requires a password when username is supplied");
		}
	}
	else if (!password.empty()) {
		redisAsyncCommand(ctx, nullptr, nullptr,
						  "AUTH %s", password.c_str());
	}
	if (!db.empty()) {
		redisAsyncCommand(ctx, nullptr, nullptr,
						  "SELECT %s", db.c_str());
	}
}

/* OpenSSL is initialised by core before Redis pool is used */

auto redis_pool_elt::new_connection() -> redisAsyncContext *
{
	if (!inactive.empty()) {
		decltype(inactive)::value_type conn;
		conn.swap(inactive.back());
		inactive.pop_back();

		g_assert(conn->state != rspamd_redis_pool_connection_state::RSPAMD_REDIS_POOL_CONN_ACTIVE);
		if (conn->ctx->err == REDIS_OK) {
			/* Also check SO_ERROR */
			int err;
			socklen_t len = sizeof(int);

			if (getsockopt(conn->ctx->c.fd, SOL_SOCKET, SO_ERROR,
						   (void *) &err, &len) == -1) {
				err = errno;
			}

			if (err != 0) {
				/*
				 * We cannot reuse connection, so we just recursively call
				 * this function one more time
				 */
				msg_debug_rpool("cannot reuse the existing connection to %s:%d: %p; errno=%d",
								ip.c_str(), port, conn->ctx, err);
				return new_connection();
			}
			else {
				/* Reuse connection */
				ev_timer_stop(pool->event_loop, &conn->timeout);
				conn->state = rspamd_redis_pool_connection_state::RSPAMD_REDIS_POOL_CONN_ACTIVE;
				msg_debug_rpool("reused existing connection to %s:%d: %p",
								ip.c_str(), port, conn->ctx);
				active.emplace_front(std::move(conn));
				active.front()->elt_pos = active.begin();

				return active.front()->ctx;
			}
		}
		else {
			auto *nctx = redis_async_new();
			msg_debug_rpool("error in the inactive connection: %s; opened new connection to %s:%d: %p",
							conn->ctx->errstr, ip.c_str(), port, nctx);

			if (nctx) {
				/* If TLS is configured for this element, initiate it now */
				if (use_tls && !is_unix) {
					if (!initiate_tls(nctx)) {
						redisAsyncFree(nctx);
						nctx = nullptr;
					}
				}

				if (nctx) {
					active.emplace_front(std::make_unique<redis_pool_connection>(pool, this,
																				 db.c_str(), username.c_str(), password.c_str(), nctx));
					active.front()->elt_pos = active.begin();
				}
			}

			return nctx;
		}
	}
	else {
		auto *nctx = redis_async_new();

		if (nctx) {
			/* If TLS is configured for this element, initiate it now */
			if (use_tls && !is_unix) {
				if (!initiate_tls(nctx)) {
					redisAsyncFree(nctx);
					nctx = nullptr;
				}
			}

			if (nctx) {
				active.emplace_front(std::make_unique<redis_pool_connection>(pool, this,
																			 db.c_str(), username.c_str(), password.c_str(), nctx));
				active.front()->elt_pos = active.begin();
				auto conn = active.front().get();
				msg_debug_rpool("no inactive connections; opened new connection to %s:%d: %p",
								ip.c_str(), port, nctx);
			}
		}

		return nctx;
	}

	RSPAMD_UNREACHABLE;
}

auto redis_pool::new_connection(const char *db, const char *username,
								const char *password, const char *ip, int port) -> redisAsyncContext *
{

	if (!wanna_die) {
		auto key = redis_pool_elt::make_key(db, username, password, ip, port);
		auto found_elt = elts_by_key.find(key);

		if (found_elt != elts_by_key.end()) {
			auto &elt = found_elt->second;

			return elt.new_connection();
		}
		else {
			/* Need to create a pool */
			auto nelt = elts_by_key.try_emplace(key,
												this, db, username, password, ip, port);

			return nelt.first->second.new_connection();
		}
	}

	return nullptr;
}

auto redis_pool::new_connection_ext(const char *db, const char *username,
									const char *password, const char *ip, int port,
									bool use_tls, bool no_ssl_verify,
									const char *ca_file, const char *ca_dir,
									const char *cert_file, const char *key_file,
									const char *sni) -> redisAsyncContext *
{

	if (!wanna_die) {
		auto key = redis_pool_elt::make_key(db, username, password, ip, port,
											use_tls, no_ssl_verify, ca_file, ca_dir,
											cert_file, key_file, sni);
		auto found_elt = elts_by_key.find(key);

		if (found_elt != elts_by_key.end()) {
			auto &elt = found_elt->second;

			return elt.new_connection();
		}
		else {
			/* Need to create a pool */
			auto nelt = elts_by_key.try_emplace(key,
												this, db, username, password, ip, port,
												use_tls, no_ssl_verify, ca_file, ca_dir,
												cert_file, key_file, sni);

			return nelt.first->second.new_connection();
		}
	}

	return nullptr;
}

auto redis_pool::release_connection(redisAsyncContext *ctx,
									enum rspamd_redis_pool_release_type how) -> void
{
	if (!wanna_die) {
		auto conn_it = conns_by_ctx.find(ctx);
		if (conn_it != conns_by_ctx.end()) {
			auto *conn = conn_it->second;
			g_assert(conn->state == rspamd_redis_pool_connection_state::RSPAMD_REDIS_POOL_CONN_ACTIVE);

			if (ctx->err != REDIS_OK) {
				/* We need to terminate connection forcefully */
				msg_debug_rpool("closed connection %p due to an error", conn->ctx);
			}
			else {
				if (how == RSPAMD_REDIS_RELEASE_DEFAULT) {
					/* Ensure that there are no callbacks attached to this conn */
					if (ctx->replies.head == nullptr && (ctx->c.flags & REDIS_CONNECTED)) {
						/* Just move it to the inactive queue */
						conn->state = rspamd_redis_pool_connection_state::RSPAMD_REDIS_POOL_CONN_INACTIVE;
						conn->elt->move_to_inactive(conn);
						conn->schedule_timeout();
						msg_debug_rpool("mark connection %p inactive", conn->ctx);

						return;
					}
					else {
						msg_debug_rpool("closed connection %p due to callbacks left",
										conn->ctx);
					}
				}
				else {
					if (how == RSPAMD_REDIS_RELEASE_FATAL) {
						msg_debug_rpool("closed connection %p due to an fatal termination",
										conn->ctx);
					}
					else {
						msg_debug_rpool("closed connection %p due to explicit termination",
										conn->ctx);
					}
				}
			}

			conn->elt->release_connection(conn);
		}
		else {
			msg_err("fatal internal error, connection with ctx %p is not found in the Redis pool",
					ctx);
			RSPAMD_UNREACHABLE;
		}
	}
}

}// namespace rspamd

void *
rspamd_redis_pool_init(void)
{
	return new rspamd::redis_pool{};
}

void rspamd_redis_pool_config(void *p,
							  struct rspamd_config *cfg,
							  struct ev_loop *ev_base)
{
	g_assert(p != NULL);
	auto *pool = reinterpret_cast<class rspamd::redis_pool *>(p);

	pool->do_config(ev_base, cfg);
}


struct redisAsyncContext *
rspamd_redis_pool_connect(void *p,
						  const char *db, const char *username,
						  const char *password, const char *ip, int port)
{
	g_assert(p != NULL);
	auto *pool = reinterpret_cast<class rspamd::redis_pool *>(p);

	return pool->new_connection(db, username, password, ip, port);
}


struct redisAsyncContext *
rspamd_redis_pool_connect_ext(void *p,
							  const char *db, const char *username,
							  const char *password, const char *ip, int port,
							  const struct rspamd_redis_tls_opts *tls)
{
	g_assert(p != NULL);
	auto *pool = reinterpret_cast<class rspamd::redis_pool *>(p);

	if (tls && tls->use_tls) {
		return pool->new_connection_ext(db, username, password, ip, port,
										true, tls->no_ssl_verify,
										tls->ca_file, tls->ca_dir,
										tls->cert_file, tls->key_file,
										tls->sni);
	}
	else {
		return pool->new_connection(db, username, password, ip, port);
	}
}


void rspamd_redis_pool_release_connection(void *p,
										  struct redisAsyncContext *ctx, enum rspamd_redis_pool_release_type how)
{
	g_assert(p != NULL);
	g_assert(ctx != NULL);
	auto *pool = reinterpret_cast<class rspamd::redis_pool *>(p);

	pool->release_connection(ctx, how);
}


void rspamd_redis_pool_destroy(void *p)
{
	auto *pool = reinterpret_cast<class rspamd::redis_pool *>(p);

	pool->prepare_to_die();
	delete pool;
}

const char *
rspamd_redis_type_to_string(int type)
{
	const char *ret = "unknown";

	switch (type) {
	case REDIS_REPLY_STRING:
		ret = "string";
		break;
	case REDIS_REPLY_ARRAY:
		ret = "array";
		break;
	case REDIS_REPLY_INTEGER:
		ret = "int";
		break;
	case REDIS_REPLY_STATUS:
		ret = "status";
		break;
	case REDIS_REPLY_NIL:
		ret = "nil";
		break;
	case REDIS_REPLY_ERROR:
		ret = "error";
		break;
	default:
		break;
	}

	return ret;
}
