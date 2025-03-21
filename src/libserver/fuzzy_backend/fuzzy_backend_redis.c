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

#include "config.h"
#include "ref.h"
#include "fuzzy_backend.h"
#include "fuzzy_backend_redis.h"
#include "redis_pool.h"
#include "cryptobox.h"
#include "str_util.h"
#include "upstream.h"
#include "contrib/hiredis/hiredis.h"
#include "contrib/hiredis/async.h"
#include "lua/lua_common.h"

#define REDIS_DEFAULT_PORT 6379
#define REDIS_DEFAULT_OBJECT "fuzzy"
#define REDIS_DEFAULT_TIMEOUT 2.0

#define msg_err_redis_session(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL,                \
															   "fuzzy_redis", session->backend->id, \
															   G_STRFUNC,                           \
															   __VA_ARGS__)
#define msg_warn_redis_session(...) rspamd_default_log_function(G_LOG_LEVEL_WARNING,                 \
																"fuzzy_redis", session->backend->id, \
																G_STRFUNC,                           \
																__VA_ARGS__)
#define msg_info_redis_session(...) rspamd_default_log_function(G_LOG_LEVEL_INFO,                    \
																"fuzzy_redis", session->backend->id, \
																G_STRFUNC,                           \
																__VA_ARGS__)
#define msg_debug_redis_session(...) rspamd_conditional_debug_fast(NULL, NULL,                                                     \
																   rspamd_fuzzy_redis_log_id, "fuzzy_redis", session->backend->id, \
																   G_STRFUNC,                                                      \
																   __VA_ARGS__)

INIT_LOG_MODULE(fuzzy_redis)

struct rspamd_fuzzy_backend_redis {
	lua_State *L;
	const char *redis_object;
	const char *username;
	const char *password;
	const char *dbname;
	char *id;
	struct rspamd_redis_pool *pool;
	double timeout;
	int conf_ref;
	bool terminated;
	ref_entry_t ref;
};

enum rspamd_fuzzy_redis_command {
	RSPAMD_FUZZY_REDIS_COMMAND_COUNT,
	RSPAMD_FUZZY_REDIS_COMMAND_VERSION,
	RSPAMD_FUZZY_REDIS_COMMAND_UPDATES,
	RSPAMD_FUZZY_REDIS_COMMAND_CHECK
};

struct rspamd_fuzzy_redis_session {
	struct rspamd_fuzzy_backend_redis *backend;
	redisAsyncContext *ctx;
	ev_timer timeout;
	const struct rspamd_fuzzy_cmd *cmd;
	struct ev_loop *event_loop;
	float prob;
	gboolean shingles_checked;

	enum rspamd_fuzzy_redis_command command;
	unsigned int nargs;

	unsigned int nadded;
	unsigned int ndeleted;
	unsigned int nextended;
	unsigned int nignored;

	union {
		rspamd_fuzzy_check_cb cb_check;
		rspamd_fuzzy_update_cb cb_update;
		rspamd_fuzzy_version_cb cb_version;
		rspamd_fuzzy_count_cb cb_count;
	} callback;
	void *cbdata;

	char **argv;
	gsize *argv_lens;
	struct upstream *up;
	unsigned char found_digest[rspamd_cryptobox_HASHBYTES];
};

static inline struct upstream_list *
rspamd_redis_get_servers(struct rspamd_fuzzy_backend_redis *ctx,
						 const char *what)
{
	lua_State *L = ctx->L;
	struct upstream_list *res = NULL;

	lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->conf_ref);
	lua_pushstring(L, what);
	lua_gettable(L, -2);

	if (lua_type(L, -1) == LUA_TUSERDATA) {
		res = *((struct upstream_list **) lua_touserdata(L, -1));
	}
	else {
		char outbuf[8192];

		lua_logger_out(L, -2, outbuf, sizeof(outbuf),
							LUA_ESCAPE_UNPRINTABLE);

		msg_err("cannot get %s upstreams for Redis fuzzy storage %s; table content: %s",
				what, ctx->id, outbuf);
	}

	lua_settop(L, 0);

	return res;
}

static inline void
rspamd_fuzzy_redis_session_free_args(struct rspamd_fuzzy_redis_session *session)
{
	unsigned int i;

	if (session->argv) {
		for (i = 0; i < session->nargs; i++) {
			g_free(session->argv[i]);
		}

		g_free(session->argv);
		g_free(session->argv_lens);
	}
}
static void
rspamd_fuzzy_redis_session_dtor(struct rspamd_fuzzy_redis_session *session,
								gboolean is_fatal)
{
	redisAsyncContext *ac;


	if (session->ctx) {
		ac = session->ctx;
		session->ctx = NULL;
		rspamd_redis_pool_release_connection(session->backend->pool,
											 ac,
											 is_fatal ? RSPAMD_REDIS_RELEASE_FATAL : RSPAMD_REDIS_RELEASE_DEFAULT);
	}

	ev_timer_stop(session->event_loop, &session->timeout);
	rspamd_fuzzy_redis_session_free_args(session);

	REF_RELEASE(session->backend);
	rspamd_upstream_unref(session->up);
	g_free(session);
}

static void
rspamd_fuzzy_backend_redis_dtor(struct rspamd_fuzzy_backend_redis *backend)
{
	if (!backend->terminated && backend->conf_ref != -1) {
		luaL_unref(backend->L, LUA_REGISTRYINDEX, backend->conf_ref);
	}

	if (backend->id) {
		g_free(backend->id);
	}

	g_free(backend);
}

void *
rspamd_fuzzy_backend_init_redis(struct rspamd_fuzzy_backend *bk,
								const ucl_object_t *obj, struct rspamd_config *cfg, GError **err)
{
	struct rspamd_fuzzy_backend_redis *backend;
	const ucl_object_t *elt;
	gboolean ret = FALSE;
	unsigned char id_hash[rspamd_cryptobox_HASHBYTES];
	rspamd_cryptobox_hash_state_t st;
	lua_State *L = (lua_State *) cfg->lua_state;
	int conf_ref = -1;

	backend = g_malloc0(sizeof(*backend));

	backend->timeout = REDIS_DEFAULT_TIMEOUT;
	backend->redis_object = REDIS_DEFAULT_OBJECT;
	backend->L = L;

	ret = rspamd_lua_try_load_redis(L, obj, cfg, &conf_ref);

	/* Now try global redis settings */
	if (!ret) {
		elt = ucl_object_lookup(cfg->cfg_ucl_obj, "redis");

		if (elt) {
			const ucl_object_t *specific_obj;

			specific_obj = ucl_object_lookup_any(elt, "fuzzy", "fuzzy_storage",
												 NULL);

			if (specific_obj) {
				ret = rspamd_lua_try_load_redis(L, specific_obj, cfg, &conf_ref);
			}
			else {
				ret = rspamd_lua_try_load_redis(L, elt, cfg, &conf_ref);
			}
		}
	}

	if (!ret) {
		msg_err_config("cannot init redis backend for fuzzy storage");
		g_free(backend);

		return NULL;
	}

	elt = ucl_object_lookup(obj, "prefix");
	if (elt == NULL || ucl_object_type(elt) != UCL_STRING) {
		backend->redis_object = REDIS_DEFAULT_OBJECT;
	}
	else {
		backend->redis_object = ucl_object_tostring(elt);
	}

	backend->conf_ref = conf_ref;

	/* Check some common table values */
	lua_rawgeti(L, LUA_REGISTRYINDEX, conf_ref);

	lua_pushstring(L, "timeout");
	lua_gettable(L, -2);
	if (lua_type(L, -1) == LUA_TNUMBER) {
		backend->timeout = lua_tonumber(L, -1);
	}
	lua_pop(L, 1);

	lua_pushstring(L, "db");
	lua_gettable(L, -2);
	if (lua_type(L, -1) == LUA_TSTRING) {
		backend->dbname = rspamd_mempool_strdup(cfg->cfg_pool,
												lua_tostring(L, -1));
	}
	lua_pop(L, 1);

	lua_pushstring(L, "username");
	lua_gettable(L, -2);
	if (lua_type(L, -1) == LUA_TSTRING) {
		backend->username = rspamd_mempool_strdup(cfg->cfg_pool,
												  lua_tostring(L, -1));
	}
	lua_pop(L, 1);

	lua_pushstring(L, "password");
	lua_gettable(L, -2);
	if (lua_type(L, -1) == LUA_TSTRING) {
		backend->password = rspamd_mempool_strdup(cfg->cfg_pool,
												  lua_tostring(L, -1));
	}
	lua_pop(L, 1);

	lua_settop(L, 0);

	REF_INIT_RETAIN(backend, rspamd_fuzzy_backend_redis_dtor);
	backend->pool = cfg->redis_pool;
	rspamd_cryptobox_hash_init(&st, NULL, 0);
	rspamd_cryptobox_hash_update(&st, backend->redis_object,
								 strlen(backend->redis_object));

	if (backend->dbname) {
		rspamd_cryptobox_hash_update(&st, backend->dbname,
									 strlen(backend->dbname));
	}

	if (backend->username) {
		rspamd_cryptobox_hash_update(&st, backend->username,
									 strlen(backend->username));
	}

	if (backend->password) {
		rspamd_cryptobox_hash_update(&st, backend->password,
									 strlen(backend->password));
	}

	rspamd_cryptobox_hash_final(&st, id_hash);
	backend->id = rspamd_encode_base32(id_hash, sizeof(id_hash), RSPAMD_BASE32_DEFAULT);

	return backend;
}

static void
rspamd_fuzzy_redis_timeout(EV_P_ ev_timer *w, int revents)
{
	struct rspamd_fuzzy_redis_session *session =
		(struct rspamd_fuzzy_redis_session *) w->data;
	redisAsyncContext *ac;
	static char errstr[128];

	if (session->ctx) {
		ac = session->ctx;
		session->ctx = NULL;
		ac->err = REDIS_ERR_IO;
		/* Should be safe as in hiredis it is char[128] */
		rspamd_snprintf(errstr, sizeof(errstr), "%s", strerror(ETIMEDOUT));
		ac->errstr = errstr;

		/* This will cause session closing */
		rspamd_redis_pool_release_connection(session->backend->pool,
											 ac, RSPAMD_REDIS_RELEASE_FATAL);
	}
}

static void rspamd_fuzzy_redis_check_callback(redisAsyncContext *c, gpointer r,
											  gpointer priv);

struct _rspamd_fuzzy_shingles_helper {
	unsigned char digest[64];
	unsigned int found;
};

static int
rspamd_fuzzy_backend_redis_shingles_cmp(const void *a, const void *b)
{
	const struct _rspamd_fuzzy_shingles_helper *sha = a,
											   *shb = b;

	return memcmp(sha->digest, shb->digest, sizeof(sha->digest));
}

static void
rspamd_fuzzy_redis_shingles_callback(redisAsyncContext *c, gpointer r,
									 gpointer priv)
{
	struct rspamd_fuzzy_redis_session *session = priv;
	redisReply *reply = r, *cur;
	struct rspamd_fuzzy_reply rep;
	GString *key;
	struct _rspamd_fuzzy_shingles_helper *shingles, *prev = NULL, *sel = NULL;
	unsigned int i, found = 0, max_found = 0, cur_found = 0;

	ev_timer_stop(session->event_loop, &session->timeout);
	memset(&rep, 0, sizeof(rep));

	if (c->err == 0 && reply != NULL) {
		rspamd_upstream_ok(session->up);

		if (reply->type == REDIS_REPLY_ARRAY &&
			reply->elements == RSPAMD_SHINGLE_SIZE) {
			shingles = g_alloca(sizeof(struct _rspamd_fuzzy_shingles_helper) *
								RSPAMD_SHINGLE_SIZE);

			for (i = 0; i < RSPAMD_SHINGLE_SIZE; i++) {
				cur = reply->element[i];

				if (cur->type == REDIS_REPLY_STRING) {
					shingles[i].found = 1;
					memcpy(shingles[i].digest, cur->str, MIN(64, cur->len));
					found++;
				}
				else {
					memset(shingles[i].digest, 0, sizeof(shingles[i].digest));
					shingles[i].found = 0;
				}
			}

			if (found > RSPAMD_SHINGLE_SIZE / 2) {
				/* Now sort to find the most frequent element */
				qsort(shingles, RSPAMD_SHINGLE_SIZE,
					  sizeof(struct _rspamd_fuzzy_shingles_helper),
					  rspamd_fuzzy_backend_redis_shingles_cmp);

				prev = &shingles[0];

				for (i = 1; i < RSPAMD_SHINGLE_SIZE; i++) {
					if (!shingles[i].found) {
						continue;
					}

					if (memcmp(shingles[i].digest, prev->digest, 64) == 0) {
						cur_found++;

						if (cur_found > max_found) {
							max_found = cur_found;
							sel = &shingles[i];
						}
					}
					else {
						cur_found = 1;
						prev = &shingles[i];
					}
				}

				if (max_found > RSPAMD_SHINGLE_SIZE / 2) {
					session->prob = ((float) max_found) / RSPAMD_SHINGLE_SIZE;
					rep.v1.prob = session->prob;

					g_assert(sel != NULL);

					/* Prepare new check command */
					rspamd_fuzzy_redis_session_free_args(session);
					session->nargs = 5;
					session->argv = g_malloc(sizeof(char *) * session->nargs);
					session->argv_lens = g_malloc(sizeof(gsize) * session->nargs);

					key = g_string_new(session->backend->redis_object);
					g_string_append_len(key, sel->digest, sizeof(sel->digest));
					session->argv[0] = g_strdup("HMGET");
					session->argv_lens[0] = 5;
					session->argv[1] = key->str;
					session->argv_lens[1] = key->len;
					session->argv[2] = g_strdup("V");
					session->argv_lens[2] = 1;
					session->argv[3] = g_strdup("F");
					session->argv_lens[3] = 1;
					session->argv[4] = g_strdup("C");
					session->argv_lens[4] = 1;
					g_string_free(key, FALSE); /* Do not free underlying array */
					memcpy(session->found_digest, sel->digest,
						   sizeof(session->cmd->digest));

					g_assert(session->ctx != NULL);
					if (redisAsyncCommandArgv(session->ctx,
											  rspamd_fuzzy_redis_check_callback,
											  session, session->nargs,
											  (const char **) session->argv,
											  session->argv_lens) != REDIS_OK) {

						if (session->callback.cb_check) {
							memset(&rep, 0, sizeof(rep));
							session->callback.cb_check(&rep, session->cbdata);
						}

						rspamd_fuzzy_redis_session_dtor(session, TRUE);
					}
					else {
						/* Add timeout */
						session->timeout.data = session;
						ev_now_update_if_cheap((struct ev_loop *) session->event_loop);
						ev_timer_init(&session->timeout,
									  rspamd_fuzzy_redis_timeout,
									  session->backend->timeout, 0.0);
						ev_timer_start(session->event_loop, &session->timeout);
					}

					return;
				}
			}
		}
		else if (reply->type == REDIS_REPLY_ERROR) {
			msg_err_redis_session("fuzzy backend redis error: \"%s\"",
								  reply->str);
		}

		if (session->callback.cb_check) {
			session->callback.cb_check(&rep, session->cbdata);
		}
	}
	else {
		if (session->callback.cb_check) {
			session->callback.cb_check(&rep, session->cbdata);
		}

		if (c->errstr) {
			msg_err_redis_session("error getting shingles: %s", c->errstr);
			rspamd_upstream_fail(session->up, FALSE, c->errstr);
		}
	}

	rspamd_fuzzy_redis_session_dtor(session, FALSE);
}

static void
rspamd_fuzzy_backend_check_shingles(struct rspamd_fuzzy_redis_session *session)
{
	struct rspamd_fuzzy_reply rep;
	const struct rspamd_fuzzy_shingle_cmd *shcmd;
	GString *key;
	unsigned int i, init_len;

	rspamd_fuzzy_redis_session_free_args(session);
	/* First of all check digest */
	session->nargs = RSPAMD_SHINGLE_SIZE + 1;
	session->argv = g_malloc(sizeof(char *) * session->nargs);
	session->argv_lens = g_malloc(sizeof(gsize) * session->nargs);
	shcmd = (const struct rspamd_fuzzy_shingle_cmd *) session->cmd;

	session->argv[0] = g_strdup("MGET");
	session->argv_lens[0] = 4;
	init_len = strlen(session->backend->redis_object);

	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i++) {

		key = g_string_sized_new(init_len + 2 + 2 + sizeof("18446744073709551616"));
		rspamd_printf_gstring(key, "%s_%d_%uL", session->backend->redis_object,
							  i, shcmd->sgl.hashes[i]);
		session->argv[i + 1] = key->str;
		session->argv_lens[i + 1] = key->len;
		g_string_free(key, FALSE); /* Do not free underlying array */
	}

	session->shingles_checked = TRUE;

	g_assert(session->ctx != NULL);

	if (redisAsyncCommandArgv(session->ctx, rspamd_fuzzy_redis_shingles_callback,
							  session, session->nargs,
							  (const char **) session->argv, session->argv_lens) != REDIS_OK) {
		msg_err("cannot execute redis command on %s: %s",
				rspamd_inet_address_to_string_pretty(rspamd_upstream_addr_cur(session->up)),
				session->ctx->errstr);

		if (session->callback.cb_check) {
			memset(&rep, 0, sizeof(rep));
			session->callback.cb_check(&rep, session->cbdata);
		}

		rspamd_fuzzy_redis_session_dtor(session, TRUE);
	}
	else {
		/* Add timeout */
		session->timeout.data = session;
		ev_now_update_if_cheap((struct ev_loop *) session->event_loop);
		ev_timer_init(&session->timeout,
					  rspamd_fuzzy_redis_timeout,
					  session->backend->timeout, 0.0);
		ev_timer_start(session->event_loop, &session->timeout);
	}
}

static void
rspamd_fuzzy_redis_check_callback(redisAsyncContext *c, gpointer r,
								  gpointer priv)
{
	struct rspamd_fuzzy_redis_session *session = priv;
	redisReply *reply = r, *cur;
	struct rspamd_fuzzy_reply rep;
	gulong value;
	unsigned int found_elts = 0;

	ev_timer_stop(session->event_loop, &session->timeout);
	memset(&rep, 0, sizeof(rep));

	if (c->err == 0 && reply != NULL) {
		rspamd_upstream_ok(session->up);

		if (reply->type == REDIS_REPLY_ARRAY && reply->elements >= 2) {
			cur = reply->element[0];

			if (cur->type == REDIS_REPLY_STRING) {
				value = strtoul(cur->str, NULL, 10);
				rep.v1.value = value;
				found_elts++;
			}

			cur = reply->element[1];

			if (cur->type == REDIS_REPLY_STRING) {
				value = strtoul(cur->str, NULL, 10);
				rep.v1.flag = value;
				found_elts++;
			}

			if (found_elts >= 2) {
				rep.v1.prob = session->prob;
				memcpy(rep.digest, session->found_digest, sizeof(rep.digest));
			}

			rep.ts = 0;

			if (reply->elements > 2) {
				cur = reply->element[2];

				if (cur->type == REDIS_REPLY_STRING) {
					rep.ts = strtoul(cur->str, NULL, 10);
				}
			}
		}
		else if (reply->type == REDIS_REPLY_ERROR) {
			msg_err_redis_session("fuzzy backend redis error: \"%s\"",
								  reply->str);
		}

		if (found_elts < 2) {
			if (session->cmd->shingles_count > 0 && !session->shingles_checked) {
				/* We also need to check all shingles here */
				rspamd_fuzzy_backend_check_shingles(session);
				/* Do not free session */
				return;
			}
			else {
				if (session->callback.cb_check) {
					session->callback.cb_check(&rep, session->cbdata);
				}
			}
		}
		else {
			if (session->callback.cb_check) {
				session->callback.cb_check(&rep, session->cbdata);
			}
		}
	}
	else {
		if (session->callback.cb_check) {
			session->callback.cb_check(&rep, session->cbdata);
		}

		if (c->errstr) {
			msg_err_redis_session("error getting hashes on %s: %s",
								  rspamd_inet_address_to_string_pretty(rspamd_upstream_addr_cur(session->up)),
								  c->errstr);
			rspamd_upstream_fail(session->up, FALSE, c->errstr);
		}
	}

	rspamd_fuzzy_redis_session_dtor(session, FALSE);
}

void rspamd_fuzzy_backend_check_redis(struct rspamd_fuzzy_backend *bk,
									  const struct rspamd_fuzzy_cmd *cmd,
									  rspamd_fuzzy_check_cb cb, void *ud,
									  void *subr_ud)
{
	struct rspamd_fuzzy_backend_redis *backend = subr_ud;
	struct rspamd_fuzzy_redis_session *session;
	struct upstream *up;
	struct upstream_list *ups;
	rspamd_inet_addr_t *addr;
	struct rspamd_fuzzy_reply rep;
	GString *key;

	g_assert(backend != NULL);

	ups = rspamd_redis_get_servers(backend, "read_servers");
	if (!ups) {
		if (cb) {
			memset(&rep, 0, sizeof(rep));
			cb(&rep, ud);
		}

		return;
	}

	session = g_malloc0(sizeof(*session));
	session->backend = backend;
	REF_RETAIN(session->backend);

	session->callback.cb_check = cb;
	session->cbdata = ud;
	session->command = RSPAMD_FUZZY_REDIS_COMMAND_CHECK;
	session->cmd = cmd;
	session->prob = 1.0;
	memcpy(rep.digest, session->cmd->digest, sizeof(rep.digest));
	memcpy(session->found_digest, session->cmd->digest, sizeof(rep.digest));
	session->event_loop = rspamd_fuzzy_backend_event_base(bk);

	/* First of all check digest */
	session->nargs = 5;
	session->argv = g_malloc(sizeof(char *) * session->nargs);
	session->argv_lens = g_malloc(sizeof(gsize) * session->nargs);

	key = g_string_new(backend->redis_object);
	g_string_append_len(key, cmd->digest, sizeof(cmd->digest));
	session->argv[0] = g_strdup("HMGET");
	session->argv_lens[0] = 5;
	session->argv[1] = key->str;
	session->argv_lens[1] = key->len;
	session->argv[2] = g_strdup("V");
	session->argv_lens[2] = 1;
	session->argv[3] = g_strdup("F");
	session->argv_lens[3] = 1;
	session->argv[4] = g_strdup("C");
	session->argv_lens[4] = 1;
	g_string_free(key, FALSE); /* Do not free underlying array */

	up = rspamd_upstream_get(ups,
							 RSPAMD_UPSTREAM_ROUND_ROBIN,
							 NULL,
							 0);

	session->up = rspamd_upstream_ref(up);
	addr = rspamd_upstream_addr_next(up);
	g_assert(addr != NULL);
	session->ctx = rspamd_redis_pool_connect(backend->pool,
											 backend->dbname,
											 backend->username, backend->password,
											 rspamd_inet_address_to_string(addr),
											 rspamd_inet_address_get_port(addr));

	if (session->ctx == NULL) {
		rspamd_upstream_fail(up, TRUE, strerror(errno));
		rspamd_fuzzy_redis_session_dtor(session, TRUE);

		if (cb) {
			memset(&rep, 0, sizeof(rep));
			cb(&rep, ud);
		}
	}
	else {
		if (redisAsyncCommandArgv(session->ctx, rspamd_fuzzy_redis_check_callback,
								  session, session->nargs,
								  (const char **) session->argv, session->argv_lens) != REDIS_OK) {
			rspamd_fuzzy_redis_session_dtor(session, TRUE);

			if (cb) {
				memset(&rep, 0, sizeof(rep));
				cb(&rep, ud);
			}
		}
		else {
			/* Add timeout */
			session->timeout.data = session;
			ev_now_update_if_cheap((struct ev_loop *) session->event_loop);
			ev_timer_init(&session->timeout,
						  rspamd_fuzzy_redis_timeout,
						  session->backend->timeout, 0.0);
			ev_timer_start(session->event_loop, &session->timeout);
		}
	}
}

static void
rspamd_fuzzy_redis_count_callback(redisAsyncContext *c, gpointer r,
								  gpointer priv)
{
	struct rspamd_fuzzy_redis_session *session = priv;
	redisReply *reply = r;
	gulong nelts;

	ev_timer_stop(session->event_loop, &session->timeout);

	if (c->err == 0 && reply != NULL) {
		rspamd_upstream_ok(session->up);

		if (reply->type == REDIS_REPLY_INTEGER) {
			if (session->callback.cb_count) {
				session->callback.cb_count(reply->integer, session->cbdata);
			}
		}
		else if (reply->type == REDIS_REPLY_STRING) {
			nelts = strtoul(reply->str, NULL, 10);

			if (session->callback.cb_count) {
				session->callback.cb_count(nelts, session->cbdata);
			}
		}
		else {
			if (reply->type == REDIS_REPLY_ERROR) {
				msg_err_redis_session("fuzzy backend redis error: \"%s\"",
									  reply->str);
			}
			if (session->callback.cb_count) {
				session->callback.cb_count(0, session->cbdata);
			}
		}
	}
	else {
		if (session->callback.cb_count) {
			session->callback.cb_count(0, session->cbdata);
		}

		if (c->errstr) {
			msg_err_redis_session("error getting count on %s: %s",
								  rspamd_inet_address_to_string_pretty(rspamd_upstream_addr_cur(session->up)),
								  c->errstr);
			rspamd_upstream_fail(session->up, FALSE, c->errstr);
		}
	}

	rspamd_fuzzy_redis_session_dtor(session, FALSE);
}

void rspamd_fuzzy_backend_count_redis(struct rspamd_fuzzy_backend *bk,
									  rspamd_fuzzy_count_cb cb, void *ud,
									  void *subr_ud)
{
	struct rspamd_fuzzy_backend_redis *backend = subr_ud;
	struct rspamd_fuzzy_redis_session *session;
	struct upstream *up;
	struct upstream_list *ups;
	rspamd_inet_addr_t *addr;
	GString *key;

	g_assert(backend != NULL);

	ups = rspamd_redis_get_servers(backend, "read_servers");
	if (!ups) {
		if (cb) {
			cb(0, ud);
		}

		return;
	}

	session = g_malloc0(sizeof(*session));
	session->backend = backend;
	REF_RETAIN(session->backend);

	session->callback.cb_count = cb;
	session->cbdata = ud;
	session->command = RSPAMD_FUZZY_REDIS_COMMAND_COUNT;
	session->event_loop = rspamd_fuzzy_backend_event_base(bk);

	session->nargs = 2;
	session->argv = g_malloc(sizeof(char *) * 2);
	session->argv_lens = g_malloc(sizeof(gsize) * 2);
	key = g_string_new(backend->redis_object);
	g_string_append(key, "_count");
	session->argv[0] = g_strdup("GET");
	session->argv_lens[0] = 3;
	session->argv[1] = key->str;
	session->argv_lens[1] = key->len;
	g_string_free(key, FALSE); /* Do not free underlying array */

	up = rspamd_upstream_get(ups,
							 RSPAMD_UPSTREAM_ROUND_ROBIN,
							 NULL,
							 0);

	session->up = rspamd_upstream_ref(up);
	addr = rspamd_upstream_addr_next(up);
	g_assert(addr != NULL);
	session->ctx = rspamd_redis_pool_connect(backend->pool,
											 backend->dbname,
											 backend->username, backend->password,
											 rspamd_inet_address_to_string(addr),
											 rspamd_inet_address_get_port(addr));

	if (session->ctx == NULL) {
		rspamd_upstream_fail(up, TRUE, strerror(errno));
		rspamd_fuzzy_redis_session_dtor(session, TRUE);

		if (cb) {
			cb(0, ud);
		}
	}
	else {
		if (redisAsyncCommandArgv(session->ctx, rspamd_fuzzy_redis_count_callback,
								  session, session->nargs,
								  (const char **) session->argv, session->argv_lens) != REDIS_OK) {
			rspamd_fuzzy_redis_session_dtor(session, TRUE);

			if (cb) {
				cb(0, ud);
			}
		}
		else {
			/* Add timeout */
			session->timeout.data = session;
			ev_now_update_if_cheap((struct ev_loop *) session->event_loop);
			ev_timer_init(&session->timeout,
						  rspamd_fuzzy_redis_timeout,
						  session->backend->timeout, 0.0);
			ev_timer_start(session->event_loop, &session->timeout);
		}
	}
}

static void
rspamd_fuzzy_redis_version_callback(redisAsyncContext *c, gpointer r,
									gpointer priv)
{
	struct rspamd_fuzzy_redis_session *session = priv;
	redisReply *reply = r;
	gulong nelts;

	ev_timer_stop(session->event_loop, &session->timeout);

	if (c->err == 0 && reply != NULL) {
		rspamd_upstream_ok(session->up);

		if (reply->type == REDIS_REPLY_INTEGER) {
			if (session->callback.cb_version) {
				session->callback.cb_version(reply->integer, session->cbdata);
			}
		}
		else if (reply->type == REDIS_REPLY_STRING) {
			nelts = strtoul(reply->str, NULL, 10);

			if (session->callback.cb_version) {
				session->callback.cb_version(nelts, session->cbdata);
			}
		}
		else {
			if (reply->type == REDIS_REPLY_ERROR) {
				msg_err_redis_session("fuzzy backend redis error: \"%s\"",
									  reply->str);
			}
			if (session->callback.cb_version) {
				session->callback.cb_version(0, session->cbdata);
			}
		}
	}
	else {
		if (session->callback.cb_version) {
			session->callback.cb_version(0, session->cbdata);
		}

		if (c->errstr) {
			msg_err_redis_session("error getting version on %s: %s",
								  rspamd_inet_address_to_string_pretty(rspamd_upstream_addr_cur(session->up)),
								  c->errstr);
			rspamd_upstream_fail(session->up, FALSE, c->errstr);
		}
	}

	rspamd_fuzzy_redis_session_dtor(session, FALSE);
}

void rspamd_fuzzy_backend_version_redis(struct rspamd_fuzzy_backend *bk,
										const char *src,
										rspamd_fuzzy_version_cb cb, void *ud,
										void *subr_ud)
{
	struct rspamd_fuzzy_backend_redis *backend = subr_ud;
	struct rspamd_fuzzy_redis_session *session;
	struct upstream *up;
	struct upstream_list *ups;
	rspamd_inet_addr_t *addr;
	GString *key;

	g_assert(backend != NULL);

	ups = rspamd_redis_get_servers(backend, "read_servers");
	if (!ups) {
		if (cb) {
			cb(0, ud);
		}

		return;
	}

	session = g_malloc0(sizeof(*session));
	session->backend = backend;
	REF_RETAIN(session->backend);

	session->callback.cb_version = cb;
	session->cbdata = ud;
	session->command = RSPAMD_FUZZY_REDIS_COMMAND_VERSION;
	session->event_loop = rspamd_fuzzy_backend_event_base(bk);

	session->nargs = 2;
	session->argv = g_malloc(sizeof(char *) * 2);
	session->argv_lens = g_malloc(sizeof(gsize) * 2);
	key = g_string_new(backend->redis_object);
	g_string_append(key, src);
	session->argv[0] = g_strdup("GET");
	session->argv_lens[0] = 3;
	session->argv[1] = key->str;
	session->argv_lens[1] = key->len;
	g_string_free(key, FALSE); /* Do not free underlying array */

	up = rspamd_upstream_get(ups,
							 RSPAMD_UPSTREAM_ROUND_ROBIN,
							 NULL,
							 0);

	session->up = rspamd_upstream_ref(up);
	addr = rspamd_upstream_addr_next(up);
	g_assert(addr != NULL);
	session->ctx = rspamd_redis_pool_connect(backend->pool,
											 backend->dbname,
											 backend->username, backend->password,
											 rspamd_inet_address_to_string(addr),
											 rspamd_inet_address_get_port(addr));

	if (session->ctx == NULL) {
		rspamd_upstream_fail(up, FALSE, strerror(errno));
		rspamd_fuzzy_redis_session_dtor(session, TRUE);

		if (cb) {
			cb(0, ud);
		}
	}
	else {
		if (redisAsyncCommandArgv(session->ctx, rspamd_fuzzy_redis_version_callback,
								  session, session->nargs,
								  (const char **) session->argv, session->argv_lens) != REDIS_OK) {
			rspamd_fuzzy_redis_session_dtor(session, TRUE);

			if (cb) {
				cb(0, ud);
			}
		}
		else {
			/* Add timeout */
			session->timeout.data = session;
			ev_now_update_if_cheap((struct ev_loop *) session->event_loop);
			ev_timer_init(&session->timeout,
						  rspamd_fuzzy_redis_timeout,
						  session->backend->timeout, 0.0);
			ev_timer_start(session->event_loop, &session->timeout);
		}
	}
}

const char *
rspamd_fuzzy_backend_id_redis(struct rspamd_fuzzy_backend *bk,
							  void *subr_ud)
{
	struct rspamd_fuzzy_backend_redis *backend = subr_ud;
	g_assert(backend != NULL);

	return backend->id;
}

void rspamd_fuzzy_backend_expire_redis(struct rspamd_fuzzy_backend *bk,
									   void *subr_ud)
{
	struct rspamd_fuzzy_backend_redis *backend = subr_ud;

	g_assert(backend != NULL);
}

static gboolean
rspamd_fuzzy_update_append_command(struct rspamd_fuzzy_backend *bk,
								   struct rspamd_fuzzy_redis_session *session,
								   struct fuzzy_peer_cmd *io_cmd, unsigned int *shift)
{
	GString *key, *value;
	unsigned int cur_shift = *shift;
	unsigned int i, klen;
	struct rspamd_fuzzy_cmd *cmd;

	if (io_cmd->is_shingle) {
		cmd = &io_cmd->cmd.shingle.basic;
	}
	else {
		cmd = &io_cmd->cmd.normal;
	}

	if (cmd->cmd == FUZZY_WRITE) {
		/*
		 * For each normal hash addition we do 5 redis commands:
		 * HSET <key> F <flag>
		 * HSETNX <key> C <time>
		 * HINCRBY <key> V <weight>
		 * EXPIRE <key> <expire>
		 * Where <key> is <prefix> || <digest>
		 */

		/* HSET */
		klen = strlen(session->backend->redis_object) +
			   sizeof(cmd->digest) + 1;
		key = g_string_sized_new(klen);
		g_string_append(key, session->backend->redis_object);
		g_string_append_len(key, cmd->digest, sizeof(cmd->digest));
		value = g_string_sized_new(sizeof("4294967296"));
		rspamd_printf_gstring(value, "%d", cmd->flag);

		if (cmd->version & RSPAMD_FUZZY_FLAG_WEAK) {
			session->argv[cur_shift] = g_strdup("HSETNX");
			session->argv_lens[cur_shift++] = sizeof("HSETNX") - 1;
		}
		else {
			session->argv[cur_shift] = g_strdup("HSET");
			session->argv_lens[cur_shift++] = sizeof("HSET") - 1;
		}

		session->argv[cur_shift] = key->str;
		session->argv_lens[cur_shift++] = key->len;
		session->argv[cur_shift] = g_strdup("F");
		session->argv_lens[cur_shift++] = sizeof("F") - 1;
		session->argv[cur_shift] = value->str;
		session->argv_lens[cur_shift++] = value->len;
		g_string_free(key, FALSE);
		g_string_free(value, FALSE);

		if (redisAsyncCommandArgv(session->ctx, NULL, NULL,
								  4,
								  (const char **) &session->argv[cur_shift - 4],
								  &session->argv_lens[cur_shift - 4]) != REDIS_OK) {

			return FALSE;
		}

		/* HSETNX */
		klen = strlen(session->backend->redis_object) +
			   sizeof(cmd->digest) + 1;
		key = g_string_sized_new(klen);
		g_string_append(key, session->backend->redis_object);
		g_string_append_len(key, cmd->digest, sizeof(cmd->digest));
		value = g_string_sized_new(sizeof("18446744073709551616"));
		rspamd_printf_gstring(value, "%L", (int64_t) rspamd_get_calendar_ticks());
		session->argv[cur_shift] = g_strdup("HSETNX");
		session->argv_lens[cur_shift++] = sizeof("HSETNX") - 1;
		session->argv[cur_shift] = key->str;
		session->argv_lens[cur_shift++] = key->len;
		session->argv[cur_shift] = g_strdup("C");
		session->argv_lens[cur_shift++] = sizeof("C") - 1;
		session->argv[cur_shift] = value->str;
		session->argv_lens[cur_shift++] = value->len;
		g_string_free(key, FALSE);
		g_string_free(value, FALSE);

		if (redisAsyncCommandArgv(session->ctx, NULL, NULL,
								  4,
								  (const char **) &session->argv[cur_shift - 4],
								  &session->argv_lens[cur_shift - 4]) != REDIS_OK) {

			return FALSE;
		}

		/* HINCRBY */
		key = g_string_sized_new(klen);
		g_string_append(key, session->backend->redis_object);
		g_string_append_len(key, cmd->digest, sizeof(cmd->digest));
		value = g_string_sized_new(sizeof("4294967296"));
		rspamd_printf_gstring(value, "%d", cmd->value);
		session->argv[cur_shift] = g_strdup("HINCRBY");
		session->argv_lens[cur_shift++] = sizeof("HINCRBY") - 1;
		session->argv[cur_shift] = key->str;
		session->argv_lens[cur_shift++] = key->len;
		session->argv[cur_shift] = g_strdup("V");
		session->argv_lens[cur_shift++] = sizeof("V") - 1;
		session->argv[cur_shift] = value->str;
		session->argv_lens[cur_shift++] = value->len;
		g_string_free(key, FALSE);
		g_string_free(value, FALSE);

		if (redisAsyncCommandArgv(session->ctx, NULL, NULL,
								  4,
								  (const char **) &session->argv[cur_shift - 4],
								  &session->argv_lens[cur_shift - 4]) != REDIS_OK) {

			return FALSE;
		}

		/* EXPIRE */
		key = g_string_sized_new(klen);
		g_string_append(key, session->backend->redis_object);
		g_string_append_len(key, cmd->digest, sizeof(cmd->digest));
		value = g_string_sized_new(sizeof("4294967296"));
		rspamd_printf_gstring(value, "%d",
							  (int) rspamd_fuzzy_backend_get_expire(bk));
		session->argv[cur_shift] = g_strdup("EXPIRE");
		session->argv_lens[cur_shift++] = sizeof("EXPIRE") - 1;
		session->argv[cur_shift] = key->str;
		session->argv_lens[cur_shift++] = key->len;
		session->argv[cur_shift] = value->str;
		session->argv_lens[cur_shift++] = value->len;
		g_string_free(key, FALSE);
		g_string_free(value, FALSE);

		if (redisAsyncCommandArgv(session->ctx, NULL, NULL,
								  3,
								  (const char **) &session->argv[cur_shift - 3],
								  &session->argv_lens[cur_shift - 3]) != REDIS_OK) {

			return FALSE;
		}

		/* INCR */
		key = g_string_sized_new(klen);
		g_string_append(key, session->backend->redis_object);
		g_string_append(key, "_count");
		session->argv[cur_shift] = g_strdup("INCR");
		session->argv_lens[cur_shift++] = sizeof("INCR") - 1;
		session->argv[cur_shift] = key->str;
		session->argv_lens[cur_shift++] = key->len;
		g_string_free(key, FALSE);

		if (redisAsyncCommandArgv(session->ctx, NULL, NULL,
								  2,
								  (const char **) &session->argv[cur_shift - 2],
								  &session->argv_lens[cur_shift - 2]) != REDIS_OK) {

			return FALSE;
		}
	}
	else if (cmd->cmd == FUZZY_DEL) {
		/* DEL */
		klen = strlen(session->backend->redis_object) +
			   sizeof(cmd->digest) + 1;

		key = g_string_sized_new(klen);
		g_string_append(key, session->backend->redis_object);
		g_string_append_len(key, cmd->digest, sizeof(cmd->digest));
		session->argv[cur_shift] = g_strdup("DEL");
		session->argv_lens[cur_shift++] = sizeof("DEL") - 1;
		session->argv[cur_shift] = key->str;
		session->argv_lens[cur_shift++] = key->len;
		g_string_free(key, FALSE);

		if (redisAsyncCommandArgv(session->ctx, NULL, NULL,
								  2,
								  (const char **) &session->argv[cur_shift - 2],
								  &session->argv_lens[cur_shift - 2]) != REDIS_OK) {

			return FALSE;
		}

		/* DECR */
		key = g_string_sized_new(klen);
		g_string_append(key, session->backend->redis_object);
		g_string_append(key, "_count");
		session->argv[cur_shift] = g_strdup("DECR");
		session->argv_lens[cur_shift++] = sizeof("DECR") - 1;
		session->argv[cur_shift] = key->str;
		session->argv_lens[cur_shift++] = key->len;
		g_string_free(key, FALSE);

		if (redisAsyncCommandArgv(session->ctx, NULL, NULL,
								  2,
								  (const char **) &session->argv[cur_shift - 2],
								  &session->argv_lens[cur_shift - 2]) != REDIS_OK) {

			return FALSE;
		}
	}
	else if (cmd->cmd == FUZZY_REFRESH) {
		/*
		 * Issue refresh command by just EXPIRE command
		 * EXPIRE <key> <expire>
		 * Where <key> is <prefix> || <digest>
		 */

		klen = strlen(session->backend->redis_object) +
			   sizeof(cmd->digest) + 1;

		/* EXPIRE */
		key = g_string_sized_new(klen);
		g_string_append(key, session->backend->redis_object);
		g_string_append_len(key, cmd->digest, sizeof(cmd->digest));
		value = g_string_sized_new(sizeof("4294967296"));
		rspamd_printf_gstring(value, "%d",
							  (int) rspamd_fuzzy_backend_get_expire(bk));
		session->argv[cur_shift] = g_strdup("EXPIRE");
		session->argv_lens[cur_shift++] = sizeof("EXPIRE") - 1;
		session->argv[cur_shift] = key->str;
		session->argv_lens[cur_shift++] = key->len;
		session->argv[cur_shift] = value->str;
		session->argv_lens[cur_shift++] = value->len;
		g_string_free(key, FALSE);
		g_string_free(value, FALSE);

		if (redisAsyncCommandArgv(session->ctx, NULL, NULL,
								  3,
								  (const char **) &session->argv[cur_shift - 3],
								  &session->argv_lens[cur_shift - 3]) != REDIS_OK) {

			return FALSE;
		}
	}
	else if (cmd->cmd == FUZZY_DUP) {
		/* Ignore */
	}
	else {
		g_assert_not_reached();
	}

	if (io_cmd->is_shingle) {
		if (cmd->cmd == FUZZY_WRITE) {
			klen = strlen(session->backend->redis_object) +
				   64 + 1;

			for (i = 0; i < RSPAMD_SHINGLE_SIZE; i++) {
				unsigned char *hval;
				/*
				 * For each command with shingles we additionally emit 32 commands:
				 * SETEX <prefix>_<number>_<value> <expire> <digest>
				 */

				/* SETEX */
				key = g_string_sized_new(klen);
				rspamd_printf_gstring(key, "%s_%d_%uL",
									  session->backend->redis_object,
									  i,
									  io_cmd->cmd.shingle.sgl.hashes[i]);
				value = g_string_sized_new(sizeof("4294967296"));
				rspamd_printf_gstring(value, "%d",
									  (int) rspamd_fuzzy_backend_get_expire(bk));
				hval = g_malloc(sizeof(io_cmd->cmd.shingle.basic.digest));
				memcpy(hval, io_cmd->cmd.shingle.basic.digest,
					   sizeof(io_cmd->cmd.shingle.basic.digest));
				session->argv[cur_shift] = g_strdup("SETEX");
				session->argv_lens[cur_shift++] = sizeof("SETEX") - 1;
				session->argv[cur_shift] = key->str;
				session->argv_lens[cur_shift++] = key->len;
				session->argv[cur_shift] = value->str;
				session->argv_lens[cur_shift++] = value->len;
				session->argv[cur_shift] = hval;
				session->argv_lens[cur_shift++] = sizeof(io_cmd->cmd.shingle.basic.digest);
				g_string_free(key, FALSE);
				g_string_free(value, FALSE);

				if (redisAsyncCommandArgv(session->ctx, NULL, NULL,
										  4,
										  (const char **) &session->argv[cur_shift - 4],
										  &session->argv_lens[cur_shift - 4]) != REDIS_OK) {

					return FALSE;
				}
			}
		}
		else if (cmd->cmd == FUZZY_DEL) {
			klen = strlen(session->backend->redis_object) +
				   64 + 1;

			for (i = 0; i < RSPAMD_SHINGLE_SIZE; i++) {
				key = g_string_sized_new(klen);
				rspamd_printf_gstring(key, "%s_%d_%uL",
									  session->backend->redis_object,
									  i,
									  io_cmd->cmd.shingle.sgl.hashes[i]);
				session->argv[cur_shift] = g_strdup("DEL");
				session->argv_lens[cur_shift++] = sizeof("DEL") - 1;
				session->argv[cur_shift] = key->str;
				session->argv_lens[cur_shift++] = key->len;
				g_string_free(key, FALSE);

				if (redisAsyncCommandArgv(session->ctx, NULL, NULL,
										  2,
										  (const char **) &session->argv[cur_shift - 2],
										  &session->argv_lens[cur_shift - 2]) != REDIS_OK) {

					return FALSE;
				}
			}
		}
		else if (cmd->cmd == FUZZY_REFRESH) {
			klen = strlen(session->backend->redis_object) +
				   64 + 1;

			for (i = 0; i < RSPAMD_SHINGLE_SIZE; i++) {
				/*
				 * For each command with shingles we additionally emit 32 commands:
				 * EXPIRE <prefix>_<number>_<value> <expire>
				 */

				/* Expire */
				key = g_string_sized_new(klen);
				rspamd_printf_gstring(key, "%s_%d_%uL",
									  session->backend->redis_object,
									  i,
									  io_cmd->cmd.shingle.sgl.hashes[i]);
				value = g_string_sized_new(sizeof("18446744073709551616"));
				rspamd_printf_gstring(value, "%d",
									  (int) rspamd_fuzzy_backend_get_expire(bk));
				session->argv[cur_shift] = g_strdup("EXPIRE");
				session->argv_lens[cur_shift++] = sizeof("EXPIRE") - 1;
				session->argv[cur_shift] = key->str;
				session->argv_lens[cur_shift++] = key->len;
				session->argv[cur_shift] = value->str;
				session->argv_lens[cur_shift++] = value->len;
				g_string_free(key, FALSE);
				g_string_free(value, FALSE);

				if (redisAsyncCommandArgv(session->ctx, NULL, NULL,
										  3,
										  (const char **) &session->argv[cur_shift - 3],
										  &session->argv_lens[cur_shift - 3]) != REDIS_OK) {

					return FALSE;
				}
			}
		}
		else if (cmd->cmd == FUZZY_DUP) {
			/* Ignore */
		}
		else {
			g_assert_not_reached();
		}
	}

	*shift = cur_shift;

	return TRUE;
}

static void
rspamd_fuzzy_redis_update_callback(redisAsyncContext *c, gpointer r,
								   gpointer priv)
{
	struct rspamd_fuzzy_redis_session *session = priv;
	redisReply *reply = r;

	ev_timer_stop(session->event_loop, &session->timeout);

	if (c->err == 0 && reply != NULL) {
		rspamd_upstream_ok(session->up);

		if (reply->type == REDIS_REPLY_ARRAY) {
			/* TODO: check all replies somehow */
			if (session->callback.cb_update) {
				session->callback.cb_update(TRUE,
											session->nadded,
											session->ndeleted,
											session->nextended,
											session->nignored,
											session->cbdata);
			}
		}
		else {
			if (reply->type == REDIS_REPLY_ERROR) {
				msg_err_redis_session("fuzzy backend redis error: \"%s\"",
									  reply->str);
			}
			if (session->callback.cb_update) {
				session->callback.cb_update(FALSE, 0, 0, 0, 0, session->cbdata);
			}
		}
	}
	else {
		if (session->callback.cb_update) {
			session->callback.cb_update(FALSE, 0, 0, 0, 0, session->cbdata);
		}

		if (c->errstr) {
			msg_err_redis_session("error sending update to redis %s: %s",
								  rspamd_inet_address_to_string_pretty(rspamd_upstream_addr_cur(session->up)),
								  c->errstr);
			rspamd_upstream_fail(session->up, FALSE, c->errstr);
		}
	}

	rspamd_fuzzy_redis_session_dtor(session, FALSE);
}

void rspamd_fuzzy_backend_update_redis(struct rspamd_fuzzy_backend *bk,
									   GArray *updates, const char *src,
									   rspamd_fuzzy_update_cb cb, void *ud,
									   void *subr_ud)
{
	struct rspamd_fuzzy_backend_redis *backend = subr_ud;
	struct rspamd_fuzzy_redis_session *session;
	struct upstream *up;
	struct upstream_list *ups;
	rspamd_inet_addr_t *addr;
	unsigned int i;
	GString *key;
	struct fuzzy_peer_cmd *io_cmd;
	struct rspamd_fuzzy_cmd *cmd = NULL;
	unsigned int nargs, cur_shift;

	g_assert(backend != NULL);

	ups = rspamd_redis_get_servers(backend, "write_servers");
	if (!ups) {
		if (cb) {
			cb(FALSE, 0, 0, 0, 0, ud);
		}

		return;
	}

	session = g_malloc0(sizeof(*session));
	session->backend = backend;
	REF_RETAIN(session->backend);

	/*
	 * For each normal hash addition we do 3 redis commands:
	 * HSET <key> F <flag> **OR** HSETNX <key> F <flag> when flag is weak
	 * HINCRBY <key> V <weight>
	 * EXPIRE <key> <expire>
	 * INCR <prefix||fuzzy_count>
	 *
	 * Where <key> is <prefix> || <digest>
	 *
	 * For each command with shingles we additionally emit 32 commands:
	 * SETEX <prefix>_<number>_<value> <expire> <digest>
	 *
	 * For each delete command we emit:
	 * DEL <key>
	 *
	 * For each delete command with shingles we emit also 32 commands:
	 * DEL <prefix>_<number>_<value>
	 * DECR <prefix||fuzzy_count>
	 */

	nargs = 4;

	for (i = 0; i < updates->len; i++) {
		io_cmd = &g_array_index(updates, struct fuzzy_peer_cmd, i);

		if (io_cmd->is_shingle) {
			cmd = &io_cmd->cmd.shingle.basic;
		}
		else {
			cmd = &io_cmd->cmd.normal;
		}

		if (cmd->cmd == FUZZY_WRITE) {
			nargs += 17;
			session->nadded++;

			if (io_cmd->is_shingle) {
				nargs += RSPAMD_SHINGLE_SIZE * 4;
			}
		}
		else if (cmd->cmd == FUZZY_DEL) {
			nargs += 4;
			session->ndeleted++;

			if (io_cmd->is_shingle) {
				nargs += RSPAMD_SHINGLE_SIZE * 2;
			}
		}
		else if (cmd->cmd == FUZZY_REFRESH) {
			nargs += 3;
			session->nextended++;

			if (io_cmd->is_shingle) {
				nargs += RSPAMD_SHINGLE_SIZE * 3;
			}
		}
		else {
			session->nignored++;
		}
	}

	/* Now we need to create a new request */
	session->callback.cb_update = cb;
	session->cbdata = ud;
	session->command = RSPAMD_FUZZY_REDIS_COMMAND_UPDATES;
	session->cmd = cmd;
	session->prob = 1.0f;
	session->event_loop = rspamd_fuzzy_backend_event_base(bk);

	/* First of all check digest */
	session->nargs = nargs;
	session->argv = g_malloc0(sizeof(char *) * session->nargs);
	session->argv_lens = g_malloc0(sizeof(gsize) * session->nargs);

	up = rspamd_upstream_get(ups,
							 RSPAMD_UPSTREAM_MASTER_SLAVE,
							 NULL,
							 0);

	session->up = rspamd_upstream_ref(up);
	addr = rspamd_upstream_addr_next(up);
	g_assert(addr != NULL);
	session->ctx = rspamd_redis_pool_connect(backend->pool,
											 backend->dbname,
											 backend->username, backend->password,
											 rspamd_inet_address_to_string(addr),
											 rspamd_inet_address_get_port(addr));

	if (session->ctx == NULL) {
		rspamd_upstream_fail(up, TRUE, strerror(errno));
		rspamd_fuzzy_redis_session_dtor(session, TRUE);

		if (cb) {
			cb(FALSE, 0, 0, 0, 0, ud);
		}
	}
	else {
		/* Start with MULTI command */
		session->argv[0] = g_strdup("MULTI");
		session->argv_lens[0] = 5;

		if (redisAsyncCommandArgv(session->ctx, NULL, NULL,
								  1,
								  (const char **) session->argv,
								  session->argv_lens) != REDIS_OK) {

			if (cb) {
				cb(FALSE, 0, 0, 0, 0, ud);
			}
			rspamd_fuzzy_redis_session_dtor(session, TRUE);

			return;
		}

		/* Now split the rest of commands in packs and emit them command by command */
		cur_shift = 1;

		for (i = 0; i < updates->len; i++) {
			io_cmd = &g_array_index(updates, struct fuzzy_peer_cmd, i);

			if (!rspamd_fuzzy_update_append_command(bk, session, io_cmd,
													&cur_shift)) {
				if (cb) {
					cb(FALSE, 0, 0, 0, 0, ud);
				}
				rspamd_fuzzy_redis_session_dtor(session, TRUE);

				return;
			}
		}

		/* Now INCR command for the source */
		key = g_string_new(backend->redis_object);
		g_string_append(key, src);
		session->argv[cur_shift] = g_strdup("INCR");
		session->argv_lens[cur_shift++] = 4;
		session->argv[cur_shift] = key->str;
		session->argv_lens[cur_shift++] = key->len;
		g_string_free(key, FALSE);

		if (redisAsyncCommandArgv(session->ctx, NULL, NULL,
								  2,
								  (const char **) &session->argv[cur_shift - 2],
								  &session->argv_lens[cur_shift - 2]) != REDIS_OK) {

			if (cb) {
				cb(FALSE, 0, 0, 0, 0, ud);
			}
			rspamd_fuzzy_redis_session_dtor(session, TRUE);

			return;
		}

		/* Finally we call EXEC with a specific callback */
		session->argv[cur_shift] = g_strdup("EXEC");
		session->argv_lens[cur_shift] = 4;

		if (redisAsyncCommandArgv(session->ctx,
								  rspamd_fuzzy_redis_update_callback, session,
								  1,
								  (const char **) &session->argv[cur_shift],
								  &session->argv_lens[cur_shift]) != REDIS_OK) {

			if (cb) {
				cb(FALSE, 0, 0, 0, 0, ud);
			}
			rspamd_fuzzy_redis_session_dtor(session, TRUE);

			return;
		}
		else {
			/* Add timeout */
			session->timeout.data = session;
			ev_now_update_if_cheap((struct ev_loop *) session->event_loop);
			ev_timer_init(&session->timeout,
						  rspamd_fuzzy_redis_timeout,
						  session->backend->timeout, 0.0);
			ev_timer_start(session->event_loop, &session->timeout);
		}
	}
}

void rspamd_fuzzy_backend_close_redis(struct rspamd_fuzzy_backend *bk,
									  void *subr_ud)
{
	struct rspamd_fuzzy_backend_redis *backend = subr_ud;

	g_assert(backend != NULL);

	/*
	 * XXX: we leak lua registry element there to avoid crashing
	 * due to chicken-egg problem between lua state termination and
	 * redis pool termination.
	 * Here, we assume that redis pool is destroyed AFTER lua_state,
	 * so all connections pending will release references but due to
	 * `terminated` hack they will not try to access Lua stuff
	 * This is enabled merely if we have connections pending (e.g. refcount > 1)
	 */
	if (backend->ref.refcount > 1) {
		backend->terminated = true;
	}
	REF_RELEASE(backend);
}
