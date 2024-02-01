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
#include "lua/lua_common.h"
#include "rspamd.h"
#include "stat_internal.h"
#include "upstream.h"
#include "libserver/mempool_vars_internal.h"
#include "fmt/core.h"

#include "libutil/cxx/error.hxx"

#include <string>
#include <cstdint>
#include <vector>
#include <optional>

#define msg_debug_stat_redis(...) rspamd_conditional_debug_fast(nullptr, nullptr,                                                 \
																rspamd_stat_redis_log_id, "stat_redis", task->task_pool->tag.uid, \
																RSPAMD_LOG_FUNC,                                                  \
																__VA_ARGS__)

INIT_LOG_MODULE(stat_redis)

#define REDIS_CTX(p) (reinterpret_cast<struct redis_stat_ctx *>(p))
#define REDIS_RUNTIME(p) (reinterpret_cast<struct redis_stat_runtime<float> *>(p))
#define REDIS_DEFAULT_OBJECT "%s%l"
#define REDIS_DEFAULT_USERS_OBJECT "%s%l%r"
#define REDIS_DEFAULT_TIMEOUT 0.5
#define REDIS_STAT_TIMEOUT 30
#define REDIS_MAX_USERS 1000

struct redis_stat_ctx {
	lua_State *L;
	struct rspamd_statfile_config *stcf;
	const char *redis_object = REDIS_DEFAULT_OBJECT;
	bool enable_users = false;
	bool store_tokens = false;
	bool enable_signatures = false;
	int cbref_user = -1;

	int cbref_classify = -1;
	int cbref_learn = -1;

	ucl_object_t *cur_stat = nullptr;

	explicit redis_stat_ctx(lua_State *_L)
		: L(_L)
	{
	}

	~redis_stat_ctx()
	{
		if (cbref_user != -1) {
			luaL_unref(L, LUA_REGISTRYINDEX, cbref_user);
		}

		if (cbref_classify != -1) {
			luaL_unref(L, LUA_REGISTRYINDEX, cbref_classify);
		}

		if (cbref_learn != -1) {
			luaL_unref(L, LUA_REGISTRYINDEX, cbref_learn);
		}
	}
};


template<class T, std::enable_if_t<std::is_convertible_v<T, float>, bool> = true>
struct redis_stat_runtime {
	struct redis_stat_ctx *ctx;
	struct rspamd_task *task;
	struct rspamd_statfile_config *stcf;
	GPtrArray *tokens = nullptr;
	const char *redis_object_expanded;
	std::uint64_t learned = 0;
	int id;
	std::vector<std::pair<int, T>> *results = nullptr;
	bool need_redis_call = true;
	std::optional<rspamd::util::error> err;

	using result_type = std::vector<std::pair<int, T>>;

private:
	/* Called on connection termination */
	static void rt_dtor(gpointer data)
	{
		auto *rt = REDIS_RUNTIME(data);

		delete rt;
	}

	/* Avoid occasional deletion */
	~redis_stat_runtime()
	{
		if (tokens) {
			g_ptr_array_unref(tokens);
		}

		delete results;
	}

public:
	explicit redis_stat_runtime(struct redis_stat_ctx *_ctx, struct rspamd_task *_task, const char *_redis_object_expanded)
		: ctx(_ctx), task(_task), stcf(_ctx->stcf), redis_object_expanded(_redis_object_expanded)
	{
		rspamd_mempool_add_destructor(task->task_pool, redis_stat_runtime<T>::rt_dtor, this);
	}

	static auto maybe_recover_from_mempool(struct rspamd_task *task, const char *redis_object_expanded,
										   bool is_spam) -> std::optional<redis_stat_runtime<T> *>
	{
		auto var_name = fmt::format("{}_{}", redis_object_expanded, is_spam ? "S" : "H");
		auto *res = rspamd_mempool_get_variable(task->task_pool, var_name.c_str());

		if (res) {
			msg_debug_bayes("recovered runtime from mempool at %s", var_name.c_str());
			return reinterpret_cast<redis_stat_runtime<T> *>(res);
		}
		else {
			msg_debug_bayes("no runtime at %s", var_name.c_str());
			return std::nullopt;
		}
	}

	void set_results(std::vector<std::pair<int, T>> *results)
	{
		this->results = results;
	}

	/* Propagate results from internal representation to the tokens array */
	auto process_tokens(GPtrArray *tokens) const -> bool
	{
		rspamd_token_t *tok;

		if (!results) {
			return false;
		}

		for (auto [idx, val]: *results) {
			tok = (rspamd_token_t *) g_ptr_array_index(tokens, idx - 1);
			tok->values[id] = val;
		}

		return true;
	}

	auto save_in_mempool(bool is_spam) const
	{
		auto var_name = fmt::format("{}_{}", redis_object_expanded, is_spam ? "S" : "H");
		/* We do not set destructor for the variable, as it should be already added on creation */
		rspamd_mempool_set_variable(task->task_pool, var_name.c_str(), (gpointer) this, nullptr);
		msg_debug_bayes("saved runtime in mempool at %s", var_name.c_str());
	}
};

#define GET_TASK_ELT(task, elt) (task == nullptr ? nullptr : (task)->elt)

static const gchar *M = "redis statistics";

static GQuark
rspamd_redis_stat_quark(void)
{
	return g_quark_from_static_string(M);
}

/*
 * Non-static for lua unit testing
 */
gsize rspamd_redis_expand_object(const gchar *pattern,
								 struct redis_stat_ctx *ctx,
								 struct rspamd_task *task,
								 gchar **target)
{
	gsize tlen = 0;
	const gchar *p = pattern, *elt;
	gchar *d, *end;
	enum {
		just_char,
		percent_char,
		mod_char
	} state = just_char;
	struct rspamd_statfile_config *stcf;
	lua_State *L = nullptr;
	struct rspamd_task **ptask;
	const gchar *rcpt = nullptr;
	gint err_idx;

	g_assert(ctx != nullptr);
	g_assert(task != nullptr);
	stcf = ctx->stcf;

	L = RSPAMD_LUA_CFG_STATE(task->cfg);
	g_assert(L != nullptr);

	if (ctx->enable_users) {
		if (ctx->cbref_user == -1) {
			rcpt = rspamd_task_get_principal_recipient(task);
		}
		else {
			/* Execute lua function to get userdata */
			lua_pushcfunction(L, &rspamd_lua_traceback);
			err_idx = lua_gettop(L);

			lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->cbref_user);
			ptask = (struct rspamd_task **) lua_newuserdata(L, sizeof(struct rspamd_task *));
			*ptask = task;
			rspamd_lua_setclass(L, "rspamd{task}", -1);

			if (lua_pcall(L, 1, 1, err_idx) != 0) {
				msg_err_task("call to user extraction script failed: %s",
							 lua_tostring(L, -1));
			}
			else {
				rcpt = rspamd_mempool_strdup(task->task_pool, lua_tostring(L, -1));
			}

			/* Result + error function */
			lua_settop(L, err_idx - 1);
		}

		if (rcpt) {
			rspamd_mempool_set_variable(task->task_pool, "stat_user",
										(gpointer) rcpt, nullptr);
		}
	}

	/* Length calculation */
	while (*p) {
		switch (state) {
		case just_char:
			if (*p == '%') {
				state = percent_char;
			}
			else {
				tlen++;
			}
			p++;
			break;
		case percent_char:
			switch (*p) {
			case '%':
				tlen++;
				state = just_char;
				break;
			case 'u':
				elt = GET_TASK_ELT(task, auth_user);
				if (elt) {
					tlen += strlen(elt);
				}
				break;
			case 'r':

				if (rcpt == nullptr) {
					elt = rspamd_task_get_principal_recipient(task);
				}
				else {
					elt = rcpt;
				}

				if (elt) {
					tlen += strlen(elt);
				}
				break;
			case 'l':
				if (stcf->label) {
					tlen += strlen(stcf->label);
				}
				/* Label miss is OK */
				break;
			case 's':
				tlen += sizeof("RS") - 1;
				break;
			default:
				state = just_char;
				tlen++;
				break;
			}

			if (state == percent_char) {
				state = mod_char;
			}
			p++;
			break;

		case mod_char:
			switch (*p) {
			case 'd':
				p++;
				state = just_char;
				break;
			default:
				state = just_char;
				break;
			}
			break;
		}
	}


	if (target == nullptr) {
		return -1;
	}

	*target = (gchar *) rspamd_mempool_alloc(task->task_pool, tlen + 1);
	d = *target;
	end = d + tlen + 1;
	d[tlen] = '\0';
	p = pattern;
	state = just_char;

	/* Expand string */
	while (*p && d < end) {
		switch (state) {
		case just_char:
			if (*p == '%') {
				state = percent_char;
			}
			else {
				*d++ = *p;
			}
			p++;
			break;
		case percent_char:
			switch (*p) {
			case '%':
				*d++ = *p;
				state = just_char;
				break;
			case 'u':
				elt = GET_TASK_ELT(task, auth_user);
				if (elt) {
					d += rspamd_strlcpy(d, elt, end - d);
				}
				break;
			case 'r':
				if (rcpt == nullptr) {
					elt = rspamd_task_get_principal_recipient(task);
				}
				else {
					elt = rcpt;
				}

				if (elt) {
					d += rspamd_strlcpy(d, elt, end - d);
				}
				break;
			case 'l':
				if (stcf->label) {
					d += rspamd_strlcpy(d, stcf->label, end - d);
				}
				break;
			case 's':
				d += rspamd_strlcpy(d, "RS", end - d);
				break;
			default:
				state = just_char;
				*d++ = *p;
				break;
			}

			if (state == percent_char) {
				state = mod_char;
			}
			p++;
			break;

		case mod_char:
			switch (*p) {
			case 'd':
				/* TODO: not supported yet */
				p++;
				state = just_char;
				break;
			default:
				state = just_char;
				break;
			}
			break;
		}
	}

	return tlen;
}

static int
rspamd_redis_stat_cb(lua_State *L)
{
	const auto *cookie = lua_tostring(L, lua_upvalueindex(1));
	auto *cfg = lua_check_config(L, 1);
	auto *backend = REDIS_CTX(rspamd_mempool_get_variable(cfg->cfg_pool, cookie));

	if (backend == nullptr) {
		msg_err("internal error: cookie %s is not found", cookie);

		return 0;
	}

	auto *cur_obj = ucl_object_lua_import(L, 2);
	msg_debug_bayes_cfg("got stat object for %s", backend->stcf->symbol);
	/* Enrich with some default values that are meaningless for redis */
	ucl_object_insert_key(cur_obj,
						  ucl_object_typed_new(UCL_INT), "used", 0, false);
	ucl_object_insert_key(cur_obj,
						  ucl_object_typed_new(UCL_INT), "total", 0, false);
	ucl_object_insert_key(cur_obj,
						  ucl_object_typed_new(UCL_INT), "size", 0, false);
	ucl_object_insert_key(cur_obj,
						  ucl_object_fromstring(backend->stcf->symbol),
						  "symbol", 0, false);
	ucl_object_insert_key(cur_obj, ucl_object_fromstring("redis"),
						  "type", 0, false);
	ucl_object_insert_key(cur_obj, ucl_object_fromint(0),
						  "languages", 0, false);

	if (backend->cur_stat) {
		ucl_object_unref(backend->cur_stat);
	}

	backend->cur_stat = cur_obj;

	return 0;
}

static void
rspamd_redis_parse_classifier_opts(struct redis_stat_ctx *backend,
								   const ucl_object_t *statfile_obj,
								   const ucl_object_t *classifier_obj,
								   struct rspamd_config *cfg)
{
	const gchar *lua_script;
	const ucl_object_t *elt, *users_enabled;
	auto *L = RSPAMD_LUA_CFG_STATE(cfg);

	users_enabled = ucl_object_lookup_any(classifier_obj, "per_user",
										  "users_enabled", nullptr);

	if (users_enabled != nullptr) {
		if (ucl_object_type(users_enabled) == UCL_BOOLEAN) {
			backend->enable_users = ucl_object_toboolean(users_enabled);
			backend->cbref_user = -1;
		}
		else if (ucl_object_type(users_enabled) == UCL_STRING) {
			lua_script = ucl_object_tostring(users_enabled);

			if (luaL_dostring(L, lua_script) != 0) {
				msg_err_config("cannot execute lua script for users "
							   "extraction: %s",
							   lua_tostring(L, -1));
			}
			else {
				if (lua_type(L, -1) == LUA_TFUNCTION) {
					backend->enable_users = TRUE;
					backend->cbref_user = luaL_ref(L,
												   LUA_REGISTRYINDEX);
				}
				else {
					msg_err_config("lua script must return "
								   "function(task) and not %s",
								   lua_typename(L, lua_type(L, -1)));
				}
			}
		}
	}
	else {
		backend->enable_users = FALSE;
		backend->cbref_user = -1;
	}

	elt = ucl_object_lookup(classifier_obj, "prefix");
	if (elt == nullptr || ucl_object_type(elt) != UCL_STRING) {
		/* Default non-users statistics */
		if (backend->enable_users || backend->cbref_user != -1) {
			backend->redis_object = REDIS_DEFAULT_USERS_OBJECT;
		}
		else {
			backend->redis_object = REDIS_DEFAULT_OBJECT;
		}
	}
	else {
		/* XXX: sanity check */
		backend->redis_object = ucl_object_tostring(elt);
	}

	elt = ucl_object_lookup(classifier_obj, "store_tokens");
	if (elt) {
		backend->store_tokens = ucl_object_toboolean(elt);
	}
	else {
		backend->store_tokens = FALSE;
	}

	elt = ucl_object_lookup(classifier_obj, "signatures");
	if (elt) {
		backend->enable_signatures = ucl_object_toboolean(elt);
	}
	else {
		backend->enable_signatures = FALSE;
	}
}

gpointer
rspamd_redis_init(struct rspamd_stat_ctx *ctx,
				  struct rspamd_config *cfg, struct rspamd_statfile *st)
{
	auto *L = RSPAMD_LUA_CFG_STATE(cfg);

	auto backend = std::make_unique<struct redis_stat_ctx>(L);
	lua_settop(L, 0);

	rspamd_redis_parse_classifier_opts(backend.get(), st->stcf->opts, st->classifier->cfg->opts, cfg);

	st->stcf->clcf->flags |= RSPAMD_FLAG_CLASSIFIER_INCREMENTING_BACKEND;
	backend->stcf = st->stcf;

	lua_pushcfunction(L, &rspamd_lua_traceback);
	auto err_idx = lua_gettop(L);

	/* Obtain function */
	if (!rspamd_lua_require_function(L, "lua_bayes_redis", "lua_bayes_init_statfile")) {
		msg_err_config("cannot require lua_bayes_redis.lua_bayes_init_statfile");
		lua_settop(L, err_idx - 1);

		return nullptr;
	}

	/* Push arguments */
	ucl_object_push_lua(L, st->classifier->cfg->opts, false);
	ucl_object_push_lua(L, st->stcf->opts, false);
	lua_pushstring(L, backend->stcf->symbol);
	lua_pushboolean(L, backend->stcf->is_spam);

	/* Push event loop if there is one available (e.g. we are not in rspamadm mode) */
	if (ctx->event_loop) {
		auto **pev_base = (struct ev_loop **) lua_newuserdata(L, sizeof(struct ev_loop *));
		*pev_base = ctx->event_loop;
		rspamd_lua_setclass(L, "rspamd{ev_base}", -1);
	}
	else {
		lua_pushnil(L);
	}

	/* Store backend in random cookie */
	char *cookie = (char *) rspamd_mempool_alloc(cfg->cfg_pool, 16);
	rspamd_random_hex(cookie, 16);
	cookie[15] = '\0';
	rspamd_mempool_set_variable(cfg->cfg_pool, cookie, backend.get(), nullptr);
	/* Callback + 1 upvalue */
	lua_pushstring(L, cookie);
	lua_pushcclosure(L, &rspamd_redis_stat_cb, 1);

	if (lua_pcall(L, 6, 2, err_idx) != 0) {
		msg_err("call to lua_bayes_init_classifier "
				"script failed: %s",
				lua_tostring(L, -1));
		lua_settop(L, err_idx - 1);

		return nullptr;
	}

	/* Results are in the stack:
	 * top - 1 - classifier function (idx = -2)
	 * top - learn function (idx = -1)
	 */

	lua_pushvalue(L, -2);
	backend->cbref_classify = luaL_ref(L, LUA_REGISTRYINDEX);

	lua_pushvalue(L, -1);
	backend->cbref_learn = luaL_ref(L, LUA_REGISTRYINDEX);

	lua_settop(L, err_idx - 1);

	return backend.release();
}

gpointer
rspamd_redis_runtime(struct rspamd_task *task,
					 struct rspamd_statfile_config *stcf,
					 gboolean learn, gpointer c, gint _id)
{
	struct redis_stat_ctx *ctx = REDIS_CTX(c);
	char *object_expanded = nullptr;

	g_assert(ctx != nullptr);
	g_assert(stcf != nullptr);

	if (rspamd_redis_expand_object(ctx->redis_object, ctx, task,
								   &object_expanded) == 0) {
		msg_err_task("expansion for %s failed for symbol %s "
					 "(maybe learning per user classifier with no user or recipient)",
					 learn ? "learning" : "classifying",
					 stcf->symbol);
		return nullptr;
	}

	/* Look for the cached results */
	if (!learn) {
		auto maybe_existing = redis_stat_runtime<float>::maybe_recover_from_mempool(task,
																					object_expanded, stcf->is_spam);

		if (maybe_existing) {
			auto *rt = maybe_existing.value();
			/* Update stcf and ctx to correspond to what we have been asked */
			rt->stcf = stcf;
			rt->ctx = ctx;
			return rt;
		}
	}

	/* No cached result (or learn), create new one */
	auto *rt = new redis_stat_runtime<float>(ctx, task, object_expanded);

	if (!learn) {
		/*
		 * For check, we also need to create the opposite class runtime to avoid
		 * double call for Redis scripts.
		 * This runtime will be filled later.
		 */
		auto maybe_opposite_rt = redis_stat_runtime<float>::maybe_recover_from_mempool(task,
																					   object_expanded,
																					   !stcf->is_spam);

		if (!maybe_opposite_rt) {
			auto *opposite_rt = new redis_stat_runtime<float>(ctx, task, object_expanded);
			opposite_rt->save_in_mempool(!stcf->is_spam);
			opposite_rt->need_redis_call = false;
		}
	}

	rt->save_in_mempool(stcf->is_spam);

	return rt;
}

void rspamd_redis_close(gpointer p)
{
	struct redis_stat_ctx *ctx = REDIS_CTX(p);
	delete ctx;
}

static constexpr auto
msgpack_emit_str(const std::string_view st, char *out) -> std::size_t
{
	auto len = st.size();
	constexpr const unsigned char fix_mask = 0xA0, l8_ch = 0xd9, l16_ch = 0xda, l32_ch = 0xdb;
	auto blen = 0;
	if (len <= 0x1F) {
		blen = 1;
		out[0] = (len | fix_mask) & 0xff;
	}
	else if (len <= 0xff) {
		blen = 2;
		out[0] = l8_ch;
		out[1] = len & 0xff;
	}
	else if (len <= 0xffff) {
		uint16_t bl = GUINT16_TO_BE(len);

		blen = 3;
		out[0] = l16_ch;
		memcpy(&out[1], &bl, sizeof(bl));
	}
	else {
		uint32_t bl = GUINT32_TO_BE(len);

		blen = 5;
		out[0] = l32_ch;
		memcpy(&out[1], &bl, sizeof(bl));
	}

	memcpy(&out[blen], st.data(), st.size());

	return blen + len;
}

static constexpr auto
msgpack_str_len(std::size_t len) -> std::size_t
{
	if (len <= 0x1F) {
		return 1 + len;
	}
	else if (len <= 0xff) {
		return 2 + len;
	}
	else if (len <= 0xffff) {
		return 3 + len;
	}
	else {
		return 4 + len;
	}
}

/*
 * Serialise stat tokens to message pack
 */
static char *
rspamd_redis_serialize_tokens(struct rspamd_task *task, const gchar *prefix, GPtrArray *tokens, gsize *ser_len)
{
	/* Each token is int64_t that requires 10 bytes (2 int32_t) + 4 bytes array len + 1 byte array magic */
	char max_int64_str[] = "18446744073709551615";
	auto prefix_len = strlen(prefix);
	std::size_t req_len = 5;
	rspamd_token_t *tok;

	/* Calculate required length */
	req_len += tokens->len * (msgpack_str_len(sizeof(max_int64_str) + prefix_len) + 1);

	auto *buf = (gchar *) rspamd_mempool_alloc(task->task_pool, req_len);
	auto *p = buf;

	/* Array */
	*p++ = (gchar) 0xdd;
	/* Length in big-endian (4 bytes) */
	*p++ = (gchar) ((tokens->len >> 24) & 0xff);
	*p++ = (gchar) ((tokens->len >> 16) & 0xff);
	*p++ = (gchar) ((tokens->len >> 8) & 0xff);
	*p++ = (gchar) (tokens->len & 0xff);


	int i;
	auto numbuf_len = sizeof(max_int64_str) + prefix_len + 1;
	auto *numbuf = (char *) g_alloca(numbuf_len);

	PTR_ARRAY_FOREACH(tokens, i, tok)
	{
		std::size_t r = rspamd_snprintf(numbuf, numbuf_len, "%s_%uL", prefix, tok->data);
		auto shift = msgpack_emit_str({numbuf, r}, p);
		p += shift;
	}

	*ser_len = p - buf;

	return buf;
}

static char *
rspamd_redis_serialize_text_tokens(struct rspamd_task *task, GPtrArray *tokens, gsize *ser_len)
{
	rspamd_token_t *tok;
	auto req_len = 5; /* Messagepack array prefix */
	int i;

	/*
	 * First we need to determine the requested length
	 */
	PTR_ARRAY_FOREACH(tokens, i, tok)
	{
		if (tok->t1 && tok->t2) {
			/* Two tokens */
			req_len += msgpack_str_len(tok->t1->stemmed.len) + msgpack_str_len(tok->t2->stemmed.len);
		}
		else if (tok->t1) {
			req_len += msgpack_str_len(tok->t1->stemmed.len);
			req_len += 1; /* null */
		}
		else {
			req_len += 2; /* 2 nulls */
		}
	}

	auto *buf = (gchar *) rspamd_mempool_alloc(task->task_pool, req_len);
	auto *p = buf;

	/* Array */
	std::uint32_t nlen = tokens->len * 2;
	nlen = GUINT32_TO_BE(nlen);
	*p++ = (gchar) 0xdd;
	/* Length in big-endian (4 bytes) */
	memcpy(p, &nlen, sizeof(nlen));
	p += sizeof(nlen);

	PTR_ARRAY_FOREACH(tokens, i, tok)
	{
		if (tok->t1 && tok->t2) {
			auto step = msgpack_emit_str({tok->t1->stemmed.begin, tok->t1->stemmed.len}, p);
			p += step;
			step = msgpack_emit_str({tok->t2->stemmed.begin, tok->t2->stemmed.len}, p);
			p += step;
		}
		else if (tok->t1) {
			auto step = msgpack_emit_str({tok->t1->stemmed.begin, tok->t1->stemmed.len}, p);
			p += step;
			*p++ = 0xc0;
		}
		else {
			*p++ = 0xc0;
			*p++ = 0xc0;
		}
	}

	*ser_len = p - buf;

	return buf;
}

static gint
rspamd_redis_classified(lua_State *L)
{
	const auto *cookie = lua_tostring(L, lua_upvalueindex(1));
	auto *task = lua_check_task(L, 1);
	auto *rt = REDIS_RUNTIME(rspamd_mempool_get_variable(task->task_pool, cookie));

	if (rt == nullptr) {
		msg_err_task("internal error: cannot find runtime for cookie %s", cookie);

		return 0;
	}

	bool result = lua_toboolean(L, 2);

	if (result) {
		/* Indexes:
		 * 3 - learned_ham (int)
		 * 4 - learned_spam (int)
		 * 5 - ham_tokens (pair<int, int>)
		 * 6 - spam_tokens (pair<int, int>)
		 */

		/*
		 * We need to fill our runtime AND the opposite runtime
		 */
		auto filler_func = [](redis_stat_runtime<float> *rt, lua_State *L, unsigned learned, int tokens_pos) {
			rt->learned = learned;
			redis_stat_runtime<float>::result_type *res;

			res = new redis_stat_runtime<float>::result_type();

			for (lua_pushnil(L); lua_next(L, tokens_pos); lua_pop(L, 1)) {
				lua_rawgeti(L, -1, 1);
				auto idx = lua_tointeger(L, -1);
				lua_pop(L, 1);

				lua_rawgeti(L, -1, 2);
				auto value = lua_tonumber(L, -1);
				lua_pop(L, 1);

				res->emplace_back(idx, value);
			}

			rt->set_results(res);
		};

		auto opposite_rt_maybe = redis_stat_runtime<float>::maybe_recover_from_mempool(task,
																					   rt->redis_object_expanded,
																					   !rt->stcf->is_spam);

		if (!opposite_rt_maybe) {
			msg_err_task("internal error: cannot find opposite runtime for cookie %s", cookie);

			return 0;
		}

		if (rt->stcf->is_spam) {
			filler_func(rt, L, lua_tointeger(L, 4), 6);
			filler_func(opposite_rt_maybe.value(), L, lua_tointeger(L, 3), 5);
		}
		else {
			filler_func(rt, L, lua_tointeger(L, 3), 5);
			filler_func(opposite_rt_maybe.value(), L, lua_tointeger(L, 4), 6);
		}

		/* Mark task as being processed */
		task->flags |= RSPAMD_TASK_FLAG_HAS_SPAM_TOKENS | RSPAMD_TASK_FLAG_HAS_HAM_TOKENS;

		/* Process all tokens */
		g_assert(rt->tokens != nullptr);
		rt->process_tokens(rt->tokens);
		opposite_rt_maybe.value()->process_tokens(rt->tokens);
	}
	else {
		/* Error message is on index 3 */
		const auto *err_msg = lua_tostring(L, 3);
		rt->err = rspamd::util::error(err_msg, 500);
		msg_err_task("cannot classify task: %s",
					 err_msg);
	}

	return 0;
}

gboolean
rspamd_redis_process_tokens(struct rspamd_task *task,
							GPtrArray *tokens,
							gint id, gpointer p)
{
	auto *rt = REDIS_RUNTIME(p);
	auto *L = rt->ctx->L;

	if (rspamd_session_blocked(task->s)) {
		return FALSE;
	}

	if (tokens == nullptr || tokens->len == 0) {
		return FALSE;
	}

	if (!rt->need_redis_call) {
		/* No need to do anything, as it is already done in the opposite class processing */
		/* However, we need to store id as it is needed for further tokens processing */
		rt->id = id;
		rt->tokens = g_ptr_array_ref(tokens);

		return TRUE;
	}

	gsize tokens_len;
	gchar *tokens_buf = rspamd_redis_serialize_tokens(task, rt->redis_object_expanded, tokens, &tokens_len);
	rt->id = id;

	lua_pushcfunction(L, &rspamd_lua_traceback);
	gint err_idx = lua_gettop(L);

	/* Function arguments */
	lua_rawgeti(L, LUA_REGISTRYINDEX, rt->ctx->cbref_classify);
	rspamd_lua_task_push(L, task);
	lua_pushstring(L, rt->redis_object_expanded);
	lua_pushinteger(L, id);
	lua_pushboolean(L, rt->stcf->is_spam);
	lua_new_text(L, tokens_buf, tokens_len, false);

	/* Store rt in random cookie */
	char *cookie = (char *) rspamd_mempool_alloc(task->task_pool, 16);
	rspamd_random_hex(cookie, 16);
	cookie[15] = '\0';
	rspamd_mempool_set_variable(task->task_pool, cookie, rt, nullptr);
	/* Callback */
	lua_pushstring(L, cookie);
	lua_pushcclosure(L, &rspamd_redis_classified, 1);

	if (lua_pcall(L, 6, 0, err_idx) != 0) {
		msg_err_task("call to redis failed: %s", lua_tostring(L, -1));
		lua_settop(L, err_idx - 1);
		return FALSE;
	}

	rt->tokens = g_ptr_array_ref(tokens);

	lua_settop(L, err_idx - 1);
	return TRUE;
}

gboolean
rspamd_redis_finalize_process(struct rspamd_task *task, gpointer runtime,
							  gpointer ctx)
{
	auto *rt = REDIS_RUNTIME(runtime);

	return !rt->err.has_value();
}


static gint
rspamd_redis_learned(lua_State *L)
{
	const auto *cookie = lua_tostring(L, lua_upvalueindex(1));
	auto *task = lua_check_task(L, 1);
	auto *rt = REDIS_RUNTIME(rspamd_mempool_get_variable(task->task_pool, cookie));

	if (rt == nullptr) {
		msg_err_task("internal error: cannot find runtime for cookie %s", cookie);

		return 0;
	}

	bool result = lua_toboolean(L, 2);

	if (result) {
		/* TODO: write it */
	}
	else {
		/* Error message is on index 3 */
		const auto *err_msg = lua_tostring(L, 3);
		rt->err = rspamd::util::error(err_msg, 500);
		msg_err_task("cannot learn task: %s", err_msg);
	}

	return 0;
}

gboolean
rspamd_redis_learn_tokens(struct rspamd_task *task,
						  GPtrArray *tokens,
						  gint id, gpointer p)
{
	auto *rt = REDIS_RUNTIME(p);
	auto *L = rt->ctx->L;

	if (rspamd_session_blocked(task->s)) {
		return FALSE;
	}

	if (tokens == nullptr || tokens->len == 0) {
		return FALSE;
	}

	gsize tokens_len;
	gchar *tokens_buf = rspamd_redis_serialize_tokens(task, rt->redis_object_expanded, tokens, &tokens_len);

	rt->id = id;

	gsize text_tokens_len = 0;
	gchar *text_tokens_buf = nullptr;

	if (rt->ctx->store_tokens) {
		text_tokens_buf = rspamd_redis_serialize_text_tokens(task, tokens, &text_tokens_len);
	}

	lua_pushcfunction(L, &rspamd_lua_traceback);
	gint err_idx = lua_gettop(L);
	auto nargs = 8;

	/* Function arguments */
	lua_rawgeti(L, LUA_REGISTRYINDEX, rt->ctx->cbref_learn);
	rspamd_lua_task_push(L, task);
	lua_pushstring(L, rt->redis_object_expanded);
	lua_pushinteger(L, id);
	lua_pushboolean(L, rt->stcf->is_spam);
	lua_pushstring(L, rt->stcf->symbol);

	/* Detect unlearn */
	auto *tok = (rspamd_token_t *) g_ptr_array_index(task->tokens, 0);

	if (tok->values[id] > 0) {
		lua_pushboolean(L, FALSE);// Learn
	}
	else {
		lua_pushboolean(L, TRUE);// Unlearn
	}
	lua_new_text(L, tokens_buf, tokens_len, false);

	/* Store rt in random cookie */
	char *cookie = (char *) rspamd_mempool_alloc(task->task_pool, 16);
	rspamd_random_hex(cookie, 16);
	cookie[15] = '\0';
	rspamd_mempool_set_variable(task->task_pool, cookie, rt, nullptr);
	/* Callback */
	lua_pushstring(L, cookie);
	lua_pushcclosure(L, &rspamd_redis_learned, 1);

	if (text_tokens_len) {
		nargs = 9;
		lua_new_text(L, text_tokens_buf, text_tokens_len, false);
	}

	if (lua_pcall(L, nargs, 0, err_idx) != 0) {
		msg_err_task("call to script failed: %s", lua_tostring(L, -1));
		lua_settop(L, err_idx - 1);
		return FALSE;
	}

	rt->tokens = g_ptr_array_ref(tokens);

	lua_settop(L, err_idx - 1);
	return TRUE;
}


gboolean
rspamd_redis_finalize_learn(struct rspamd_task *task, gpointer runtime,
							gpointer ctx, GError **err)
{
	auto *rt = REDIS_RUNTIME(runtime);

	if (rt->err.has_value()) {
		rt->err->into_g_error_set(rspamd_redis_stat_quark(), err);

		return FALSE;
	}

	return TRUE;
}

gulong
rspamd_redis_total_learns(struct rspamd_task *task, gpointer runtime,
						  gpointer ctx)
{
	auto *rt = REDIS_RUNTIME(runtime);

	return rt->learned;
}

gulong
rspamd_redis_inc_learns(struct rspamd_task *task, gpointer runtime,
						gpointer ctx)
{
	auto *rt = REDIS_RUNTIME(runtime);

	/* XXX: may cause races */
	return rt->learned + 1;
}

gulong
rspamd_redis_dec_learns(struct rspamd_task *task, gpointer runtime,
						gpointer ctx)
{
	auto *rt = REDIS_RUNTIME(runtime);

	/* XXX: may cause races */
	return rt->learned + 1;
}

gulong
rspamd_redis_learns(struct rspamd_task *task, gpointer runtime,
					gpointer ctx)
{
	auto *rt = REDIS_RUNTIME(runtime);

	return rt->learned;
}

ucl_object_t *
rspamd_redis_get_stat(gpointer runtime,
					  gpointer ctx)
{
	auto *rt = REDIS_RUNTIME(runtime);

	return ucl_object_ref(rt->ctx->cur_stat);
}

gpointer
rspamd_redis_load_tokenizer_config(gpointer runtime,
								   gsize *len)
{
	return nullptr;
}
