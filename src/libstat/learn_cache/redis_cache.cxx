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
// Include early to avoid `extern "C"` issues
#include "lua/lua_common.h"
#include "learn_cache.h"
#include "rspamd.h"
#include "stat_api.h"
#include "stat_internal.h"
#include "cryptobox.h"
#include "ucl.h"
#include "libmime/message.h"

#include <memory>

struct rspamd_redis_cache_ctx {
	lua_State *L;
	struct rspamd_statfile_config *stcf;
	int check_ref = -1;
	int learn_ref = -1;

	rspamd_redis_cache_ctx() = delete;
	explicit rspamd_redis_cache_ctx(lua_State *L)
		: L(L)
	{
	}

	~rspamd_redis_cache_ctx()
	{
		if (check_ref != -1) {
			luaL_unref(L, LUA_REGISTRYINDEX, check_ref);
		}

		if (learn_ref != -1) {
			luaL_unref(L, LUA_REGISTRYINDEX, learn_ref);
		}
	}
};

static void
rspamd_stat_cache_redis_generate_id(struct rspamd_task *task)
{
	rspamd_cryptobox_hash_state_t st;
	rspamd_cryptobox_hash_init(&st, nullptr, 0);

	const auto *user = (const char *) rspamd_mempool_get_variable(task->task_pool, "stat_user");
	/* Use dedicated hash space for per users cache */
	if (user != nullptr) {
		rspamd_cryptobox_hash_update(&st, (const unsigned char *) user, strlen(user));
	}

	for (auto i = 0; i < task->tokens->len; i++) {
		const auto *tok = (rspamd_token_t *) g_ptr_array_index(task->tokens, i);
		rspamd_cryptobox_hash_update(&st, (const unsigned char *) &tok->data,
									 sizeof(tok->data));
	}

	guchar out[rspamd_cryptobox_HASHBYTES];
	rspamd_cryptobox_hash_final(&st, out);

	auto *b32out = rspamd_mempool_alloc_array_type(task->task_pool,
												   sizeof(out) * 8 / 5 + 3, char);
	auto out_sz = rspamd_encode_base32_buf(out, sizeof(out), b32out,
										   sizeof(out) * 8 / 5 + 2, RSPAMD_BASE32_DEFAULT);

	if (out_sz > 0) {
		/* Zero terminate */
		b32out[out_sz] = '\0';
		rspamd_mempool_set_variable(task->task_pool, "words_hash", b32out, nullptr);
	}
}

gpointer
rspamd_stat_cache_redis_init(struct rspamd_stat_ctx *ctx,
							 struct rspamd_config *cfg,
							 struct rspamd_statfile *st,
							 const ucl_object_t *cf)
{
	std::unique_ptr<rspamd_redis_cache_ctx> cache_ctx = std::make_unique<rspamd_redis_cache_ctx>(RSPAMD_LUA_CFG_STATE(cfg));

	auto *L = RSPAMD_LUA_CFG_STATE(cfg);
	lua_settop(L, 0);

	lua_pushcfunction(L, &rspamd_lua_traceback);
	auto err_idx = lua_gettop(L);

	/* Obtain function */
	if (!rspamd_lua_require_function(L, "lua_bayes_redis", "lua_bayes_init_cache")) {
		msg_err_config("cannot require lua_bayes_redis.lua_bayes_init_cache");
		lua_settop(L, err_idx - 1);

		return nullptr;
	}

	/* Push arguments */
	ucl_object_push_lua(L, st->classifier->cfg->opts, false);
	ucl_object_push_lua(L, st->stcf->opts, false);

	if (lua_pcall(L, 2, 2, err_idx) != 0) {
		msg_err("call to lua_bayes_init_cache "
				"script failed: %s",
				lua_tostring(L, -1));
		lua_settop(L, err_idx - 1);

		return nullptr;
	}

	/*
	 * Results are in the stack:
	 * top - 1 - check function (idx = -2)
	 * top - learn function (idx = -1)
	 */
	lua_pushvalue(L, -2);
	cache_ctx->check_ref = luaL_ref(L, LUA_REGISTRYINDEX);

	lua_pushvalue(L, -1);
	cache_ctx->learn_ref = luaL_ref(L, LUA_REGISTRYINDEX);

	lua_settop(L, err_idx - 1);

	return (gpointer) cache_ctx.release();
}

gpointer
rspamd_stat_cache_redis_runtime(struct rspamd_task *task,
								gpointer c, gboolean learn)
{
	auto *ctx = (struct rspamd_redis_cache_ctx *) c;

	if (task->tokens == nullptr || task->tokens->len == 0) {
		return nullptr;
	}

	if (!learn) {
		/* On check, we produce words_hash variable, on learn it is guaranteed to be set */
		rspamd_stat_cache_redis_generate_id(task);
	}

	return (void *) ctx;
}

static gint
rspamd_stat_cache_checked(lua_State *L)
{
	auto *task = lua_check_task(L, 1);
	auto res = lua_toboolean(L, 2);

	if (res) {
		auto val = lua_tointeger(L, 3);

		if ((val > 0 && (task->flags & RSPAMD_TASK_FLAG_LEARN_SPAM)) ||
			(val <= 0 && (task->flags & RSPAMD_TASK_FLAG_LEARN_HAM))) {
			/* Already learned */
			msg_info_task("<%s> has been already "
						  "learned as %s, ignore it",
						  MESSAGE_FIELD(task, message_id),
						  (task->flags & RSPAMD_TASK_FLAG_LEARN_SPAM) ? "spam" : "ham");
			task->flags |= RSPAMD_TASK_FLAG_ALREADY_LEARNED;
		}
		else if (val != 0) {
			/* Unlearn flag */
			task->flags |= RSPAMD_TASK_FLAG_UNLEARN;
		}
	}

	/* Ignore errors for now, as we can do nothing about them at the moment */

	return 0;
}

gint rspamd_stat_cache_redis_check(struct rspamd_task *task,
								   gboolean is_spam,
								   gpointer runtime)
{
	auto *ctx = (struct rspamd_redis_cache_ctx *) runtime;
	auto *h = (char *) rspamd_mempool_get_variable(task->task_pool, "words_hash");

	if (h == nullptr) {
		return RSPAMD_LEARN_IGNORE;
	}

	auto *L = ctx->L;

	lua_pushcfunction(L, &rspamd_lua_traceback);
	gint err_idx = lua_gettop(L);

	/* Function arguments */
	lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->check_ref);
	rspamd_lua_task_push(L, task);
	lua_pushstring(L, h);

	lua_pushcclosure(L, &rspamd_stat_cache_checked, 0);

	if (lua_pcall(L, 3, 0, err_idx) != 0) {
		msg_err_task("call to redis failed: %s", lua_tostring(L, -1));
		lua_settop(L, err_idx - 1);
		return RSPAMD_LEARN_IGNORE;
	}

	/* We need to return OK every time */
	return RSPAMD_LEARN_OK;
}

gint rspamd_stat_cache_redis_learn(struct rspamd_task *task,
								   gboolean is_spam,
								   gpointer runtime)
{
	auto *ctx = (struct rspamd_redis_cache_ctx *) runtime;

	if (rspamd_session_blocked(task->s)) {
		return RSPAMD_LEARN_IGNORE;
	}

	auto *h = (char *) rspamd_mempool_get_variable(task->task_pool, "words_hash");
	g_assert(h != nullptr);
	auto *L = ctx->L;

	lua_pushcfunction(L, &rspamd_lua_traceback);
	gint err_idx = lua_gettop(L);

	/* Function arguments */
	lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->learn_ref);
	rspamd_lua_task_push(L, task);
	lua_pushstring(L, h);
	lua_pushboolean(L, is_spam);

	if (lua_pcall(L, 3, 0, err_idx) != 0) {
		msg_err_task("call to redis failed: %s", lua_tostring(L, -1));
		lua_settop(L, err_idx - 1);
		return RSPAMD_LEARN_IGNORE;
	}

	/* We need to return OK every time */
	return RSPAMD_LEARN_OK;
}

void rspamd_stat_cache_redis_close(gpointer c)
{
	auto *ctx = (struct rspamd_redis_cache_ctx *) c;
	delete ctx;
}
