/*
 * Copyright 2026 Vsevolod Stakhov
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
	int cbref_update; /* Lua functor ref for updates */
	bool terminated;
	ref_entry_t ref;
};

enum rspamd_fuzzy_redis_command {
	RSPAMD_FUZZY_REDIS_COMMAND_COUNT,
	RSPAMD_FUZZY_REDIS_COMMAND_VERSION,
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

	union {
		rspamd_fuzzy_check_cb cb_check;
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
	if (!backend->terminated) {
		if (backend->conf_ref != -1) {
			luaL_unref(backend->L, LUA_REGISTRYINDEX, backend->conf_ref);
		}
		if (backend->cbref_update != -1) {
			luaL_unref(backend->L, LUA_REGISTRYINDEX, backend->cbref_update);
		}
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
	backend->cbref_update = -1;
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

	/* Load Lua update functor following the Bayes pattern */
	lua_pushcfunction(L, &rspamd_lua_traceback);
	int err_idx = lua_gettop(L);

	if (!rspamd_lua_require_function(L, "lua_fuzzy_redis", "lua_fuzzy_redis_init")) {
		msg_err_config("cannot require lua_fuzzy_redis.lua_fuzzy_redis_init");
		lua_settop(L, err_idx - 1);
		/* Non-fatal: CHECK/COUNT/VERSION still work, only UPDATE is disabled */
	}
	else {
		/* Push redis params table (same as conf_ref) */
		lua_rawgeti(L, LUA_REGISTRYINDEX, conf_ref);

		if (lua_pcall(L, 1, 1, err_idx) != 0) {
			msg_err_config("call to lua_fuzzy_redis_init failed: %s",
						   lua_tostring(L, -1));
			lua_settop(L, err_idx - 1);
		}
		else if (lua_isfunction(L, -1)) {
			backend->cbref_update = luaL_ref(L, LUA_REGISTRYINDEX);
			lua_settop(L, err_idx - 1);
		}
		else {
			msg_err_config("lua_fuzzy_redis_init returned non-function");
			lua_settop(L, err_idx - 1);
		}
	}

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
	struct rspamd_fuzzy_multiflag_result mf_result;
	GString *key;
	struct _rspamd_fuzzy_shingles_helper *shingles, *prev = NULL, *sel = NULL;
	unsigned int i, found = 0, max_found = 0, cur_found = 0;

	ev_timer_stop(session->event_loop, &session->timeout);
	memset(&mf_result, 0, sizeof(mf_result));

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

					g_assert(sel != NULL);

					/* Prepare new check command — use HGETALL for multi-flag */
					rspamd_fuzzy_redis_session_free_args(session);
					session->nargs = 2;
					session->argv = g_malloc(sizeof(char *) * session->nargs);
					session->argv_lens = g_malloc(sizeof(gsize) * session->nargs);

					key = g_string_new(session->backend->redis_object);
					g_string_append_len(key, sel->digest, sizeof(sel->digest));
					session->argv[0] = g_strdup("HGETALL");
					session->argv_lens[0] = 7;
					session->argv[1] = key->str;
					session->argv_lens[1] = key->len;
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
							session->callback.cb_check(&mf_result, session->cbdata);
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
			session->callback.cb_check(&mf_result, session->cbdata);
		}
	}
	else {
		if (session->callback.cb_check) {
			session->callback.cb_check(&mf_result, session->cbdata);
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
	struct rspamd_fuzzy_multiflag_result mf_result;
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
			memset(&mf_result, 0, sizeof(mf_result));
			session->callback.cb_check(&mf_result, session->cbdata);
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
	redisReply *reply = r, *cur_key, *cur_val;
	struct rspamd_fuzzy_multiflag_result mf_result;
	gulong value;
	gboolean found_primary = FALSE;

	ev_timer_stop(session->event_loop, &session->timeout);
	memset(&mf_result, 0, sizeof(mf_result));

	if (c->err == 0 && reply != NULL) {
		rspamd_upstream_ok(session->up);

		if (reply->type == REDIS_REPLY_ARRAY && reply->elements >= 2) {
			/*
			 * HGETALL returns key-value pairs: [k1, v1, k2, v2, ...]
			 * Parse V/F/C (primary) and V1/F1, V2/F2, ..., V7/F7 (extra flags)
			 */
			int32_t primary_value = 0;
			uint32_t primary_flag = 0;
			uint32_t ts = 0;
			gboolean have_v = FALSE, have_f = FALSE;

			/* Temporary storage for extra flag slots */
			int32_t extra_values[RSPAMD_FUZZY_MAX_EXTRA_FLAGS];
			uint32_t extra_flags[RSPAMD_FUZZY_MAX_EXTRA_FLAGS];
			gboolean extra_have_v[RSPAMD_FUZZY_MAX_EXTRA_FLAGS];
			gboolean extra_have_f[RSPAMD_FUZZY_MAX_EXTRA_FLAGS];

			memset(extra_have_v, 0, sizeof(extra_have_v));
			memset(extra_have_f, 0, sizeof(extra_have_f));
			memset(extra_values, 0, sizeof(extra_values));
			memset(extra_flags, 0, sizeof(extra_flags));

			for (gsize i = 0; i + 1 < reply->elements; i += 2) {
				cur_key = reply->element[i];
				cur_val = reply->element[i + 1];

				if (cur_key->type != REDIS_REPLY_STRING || cur_val->type != REDIS_REPLY_STRING) {
					continue;
				}

				if (cur_key->len == 1) {
					switch (cur_key->str[0]) {
					case 'V':
						primary_value = strtol(cur_val->str, NULL, 10);
						have_v = TRUE;
						break;
					case 'F':
						primary_flag = strtoul(cur_val->str, NULL, 10);
						have_f = TRUE;
						break;
					case 'C':
						ts = strtoul(cur_val->str, NULL, 10);
						break;
					default:
						break;
					}
				}
				else if (cur_key->len == 2 && cur_key->str[0] >= 'A') {
					/* Extra flag fields: V1..V7, F1..F7 */
					int slot = cur_key->str[1] - '1';
					if (slot >= 0 && slot < RSPAMD_FUZZY_MAX_EXTRA_FLAGS) {
						if (cur_key->str[0] == 'V') {
							extra_values[slot] = strtol(cur_val->str, NULL, 10);
							extra_have_v[slot] = TRUE;
						}
						else if (cur_key->str[0] == 'F') {
							extra_flags[slot] = strtoul(cur_val->str, NULL, 10);
							extra_have_f[slot] = TRUE;
						}
					}
				}
			}

			if (have_v && have_f) {
				found_primary = TRUE;
				mf_result.rep.v1.value = primary_value;
				mf_result.rep.v1.flag = primary_flag;
				mf_result.rep.v1.prob = session->prob;
				mf_result.rep.ts = ts;
				memcpy(mf_result.rep.digest, session->found_digest,
					   sizeof(mf_result.rep.digest));

				/* Collect extra flags */
				for (int j = 0; j < RSPAMD_FUZZY_MAX_EXTRA_FLAGS; j++) {
					if (extra_have_v[j] && extra_have_f[j]) {
						int idx = mf_result.n_extra_flags;
						mf_result.extra_flags[idx].value = extra_values[j];
						mf_result.extra_flags[idx].flag = extra_flags[j];
						mf_result.n_extra_flags++;
					}
				}
			}
		}
		else if (reply->type == REDIS_REPLY_ERROR) {
			msg_err_redis_session("fuzzy backend redis error: \"%s\"",
								  reply->str);
		}

		if (!found_primary) {
			if (session->cmd->shingles_count > 0 && !session->shingles_checked) {
				/* We also need to check all shingles here */
				rspamd_fuzzy_backend_check_shingles(session);
				/* Do not free session */
				return;
			}
			else {
				if (session->callback.cb_check) {
					session->callback.cb_check(&mf_result, session->cbdata);
				}
			}
		}
		else {
			if (session->callback.cb_check) {
				session->callback.cb_check(&mf_result, session->cbdata);
			}
		}
	}
	else {
		if (session->callback.cb_check) {
			session->callback.cb_check(&mf_result, session->cbdata);
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
	struct rspamd_fuzzy_multiflag_result mf_result;
	GString *key;

	g_assert(backend != NULL);

	ups = rspamd_redis_get_servers(backend, "read_servers");
	if (!ups) {
		if (cb) {
			memset(&mf_result, 0, sizeof(mf_result));
			cb(&mf_result, ud);
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
	memcpy(session->found_digest, session->cmd->digest, sizeof(session->found_digest));
	session->event_loop = rspamd_fuzzy_backend_event_base(bk);

	/* First of all check digest — use HGETALL to get all flags */
	session->nargs = 2;
	session->argv = g_malloc(sizeof(char *) * session->nargs);
	session->argv_lens = g_malloc(sizeof(gsize) * session->nargs);

	key = g_string_new(backend->redis_object);
	g_string_append_len(key, cmd->digest, sizeof(cmd->digest));
	session->argv[0] = g_strdup("HGETALL");
	session->argv_lens[0] = 7;
	session->argv[1] = key->str;
	session->argv_lens[1] = key->len;
	g_string_free(key, FALSE); /* Do not free underlying array */

	up = rspamd_upstream_get(ups,
							 RSPAMD_UPSTREAM_ROUND_ROBIN,
							 NULL,
							 0);

	if (up == NULL) {
		rspamd_fuzzy_redis_session_dtor(session, TRUE);
		if (cb) {
			memset(&mf_result, 0, sizeof(mf_result));
			cb(&mf_result, ud);
		}
		return;
	}

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
			memset(&mf_result, 0, sizeof(mf_result));
			cb(&mf_result, ud);
		}
	}
	else {
		if (redisAsyncCommandArgv(session->ctx, rspamd_fuzzy_redis_check_callback,
								  session, session->nargs,
								  (const char **) session->argv, session->argv_lens) != REDIS_OK) {
			rspamd_fuzzy_redis_session_dtor(session, TRUE);

			if (cb) {
				memset(&mf_result, 0, sizeof(mf_result));
				cb(&mf_result, ud);
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

	if (up == NULL) {
		rspamd_fuzzy_redis_session_dtor(session, TRUE);
		if (cb) {
			cb(0, ud);
		}
		return;
	}

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

	if (up == NULL) {
		rspamd_fuzzy_redis_session_dtor(session, TRUE);
		if (cb) {
			cb(0, ud);
		}
		return;
	}

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

/*
 * Callback data for Lua-based fuzzy update.
 * Stored as lightuserdata upvalue in the C closure passed to Lua.
 */
struct rspamd_fuzzy_lua_update_cbdata {
	rspamd_fuzzy_update_cb cb;
	void *ud;
	struct rspamd_fuzzy_backend_redis *backend;
	unsigned int nadded;
	unsigned int ndeleted;
	unsigned int nextended;
	unsigned int nignored;
};

/*
 * C closure called from Lua when all fuzzy update operations complete.
 * Lua calls this as: callback(success_boolean)
 * Upvalue 1: lightuserdata -> struct rspamd_fuzzy_lua_update_cbdata
 */
static int
rspamd_fuzzy_redis_lua_update_cb(lua_State *L)
{
	struct rspamd_fuzzy_lua_update_cbdata *cbdata =
		(struct rspamd_fuzzy_lua_update_cbdata *) lua_touserdata(L, lua_upvalueindex(1));

	if (cbdata == NULL) {
		return 0;
	}

	gboolean success = lua_toboolean(L, 1);

	if (cbdata->cb) {
		cbdata->cb(success,
				   cbdata->nadded,
				   cbdata->ndeleted,
				   cbdata->nextended,
				   cbdata->nignored,
				   cbdata->ud);
	}

	REF_RELEASE(cbdata->backend);
	g_free(cbdata);

	return 0;
}

void rspamd_fuzzy_backend_update_redis(struct rspamd_fuzzy_backend *bk,
									   GArray *updates, const char *src,
									   rspamd_fuzzy_update_cb cb, void *ud,
									   void *subr_ud)
{
	struct rspamd_fuzzy_backend_redis *backend = subr_ud;
	lua_State *L = backend->L;
	unsigned int i;
	struct fuzzy_peer_cmd *io_cmd;
	struct rspamd_fuzzy_cmd *cmd;
	unsigned int nadded = 0, ndeleted = 0, nextended = 0, nignored = 0;

	g_assert(backend != NULL);

	if (backend->cbref_update == -1) {
		msg_err("fuzzy redis update functor not initialized");
		if (cb) {
			cb(FALSE, 0, 0, 0, 0, ud);
		}
		return;
	}

	/* Count stats upfront */
	for (i = 0; i < updates->len; i++) {
		io_cmd = &g_array_index(updates, struct fuzzy_peer_cmd, i);

		if (io_cmd->is_shingle) {
			cmd = &io_cmd->cmd.shingle.basic;
		}
		else {
			cmd = &io_cmd->cmd.normal;
		}

		if (cmd->cmd == FUZZY_WRITE) {
			nadded++;
		}
		else if (cmd->cmd == FUZZY_DEL) {
			ndeleted++;
		}
		else if (cmd->cmd == FUZZY_REFRESH) {
			nextended++;
		}
		else {
			nignored++;
		}
	}

	lua_pushcfunction(L, &rspamd_lua_traceback);
	int err_idx = lua_gettop(L);

	/* Push the update functor */
	lua_rawgeti(L, LUA_REGISTRYINDEX, backend->cbref_update);

	/* Arg 1: ev_base */
	struct ev_loop **pev = lua_newuserdata(L, sizeof(struct ev_loop *));
	*pev = rspamd_fuzzy_backend_event_base(bk);
	rspamd_lua_setclass(L, rspamd_ev_base_classname, -1);

	/* Arg 2: prefix */
	lua_pushstring(L, backend->redis_object);

	/* Arg 3: updates table */
	lua_createtable(L, updates->len, 0);
	for (i = 0; i < updates->len; i++) {
		io_cmd = &g_array_index(updates, struct fuzzy_peer_cmd, i);

		if (io_cmd->is_shingle) {
			cmd = &io_cmd->cmd.shingle.basic;
		}
		else {
			cmd = &io_cmd->cmd.normal;
		}

		lua_createtable(L, 0, 6);

		/* op */
		if (cmd->cmd == FUZZY_WRITE) {
			lua_pushstring(L, "add");
		}
		else if (cmd->cmd == FUZZY_DEL) {
			lua_pushstring(L, "del");
		}
		else if (cmd->cmd == FUZZY_REFRESH) {
			lua_pushstring(L, "refresh");
		}
		else {
			lua_pushstring(L, "dup");
		}
		lua_setfield(L, -2, "op");

		/* digest (raw bytes) */
		lua_pushlstring(L, (const char *) cmd->digest, sizeof(cmd->digest));
		lua_setfield(L, -2, "digest");

		/* flag */
		lua_pushinteger(L, cmd->flag);
		lua_setfield(L, -2, "flag");

		/* value */
		lua_pushinteger(L, cmd->value);
		lua_setfield(L, -2, "value");

		/* is_weak */
		lua_pushinteger(L, (cmd->version & RSPAMD_FUZZY_FLAG_WEAK) ? 1 : 0);
		lua_setfield(L, -2, "is_weak");

		/* timestamp */
		lua_pushinteger(L, (lua_Integer) rspamd_get_calendar_ticks());
		lua_setfield(L, -2, "timestamp");

		/* shingle_keys (array of strings, only for shingle commands) */
		if (io_cmd->is_shingle) {
			unsigned int j;
			lua_createtable(L, RSPAMD_SHINGLE_SIZE, 0);
			for (j = 0; j < RSPAMD_SHINGLE_SIZE; j++) {
				GString *sk = g_string_sized_new(64);
				rspamd_printf_gstring(sk, "%s_%d_%uL",
									  backend->redis_object,
									  j,
									  io_cmd->cmd.shingle.sgl.hashes[j]);
				lua_pushlstring(L, sk->str, sk->len);
				lua_rawseti(L, -2, j + 1);
				g_string_free(sk, TRUE);
			}
			lua_setfield(L, -2, "shingle_keys");
		}

		lua_rawseti(L, -2, i + 1);
	}

	/* Arg 4: src */
	lua_pushstring(L, src);

	/* Arg 5: expire */
	lua_pushnumber(L, rspamd_fuzzy_backend_get_expire(bk));

	/* Arg 6: callback (C closure with cbdata as lightuserdata upvalue) */
	struct rspamd_fuzzy_lua_update_cbdata *cbdata;
	cbdata = g_malloc(sizeof(*cbdata));
	cbdata->cb = cb;
	cbdata->ud = ud;
	cbdata->backend = backend;
	cbdata->nadded = nadded;
	cbdata->ndeleted = ndeleted;
	cbdata->nextended = nextended;
	cbdata->nignored = nignored;
	REF_RETAIN(backend);
	lua_pushlightuserdata(L, cbdata);
	lua_pushcclosure(L, &rspamd_fuzzy_redis_lua_update_cb, 1);

	if (lua_pcall(L, 6, 0, err_idx) != 0) {
		msg_err("call to fuzzy redis update functor failed: %s",
				lua_tostring(L, -1));

		if (cb) {
			cb(FALSE, 0, 0, 0, 0, ud);
		}

		REF_RELEASE(backend);
		g_free(cbdata);
	}

	lua_settop(L, err_idx - 1);
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
