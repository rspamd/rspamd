/* Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "lua_common.h"
#include "task.h"
#include "main.h"
#include "cfg_rcl.h"
#include "tokenizers/tokenizers.h"

/***
 * @function util.create_event_base()
 * Creates new event base for processing asynchronous events
 * @return {ev_base} new event processing base
 */
LUA_FUNCTION_DEF (util, create_event_base);
/***
 * @function util.load_rspamd_config(filename)
 * Load rspamd config from the specified file
 * @return {confg} new configuration object suitable for access
 */
LUA_FUNCTION_DEF (util, load_rspamd_config);
/***
 * @function util.config_from_ucl(any)
 * Load rspamd config from ucl reperesented by any lua table
 * @return {confg} new configuration object suitable for access
 */
LUA_FUNCTION_DEF (util, config_from_ucl);
/***
 * @function util.encode_base64(input[, str_len])
 * Encodes data in base64 breaking lines if needed
 * @param {text or string} input input data
 * @param {number} str_len optional size of lines or 0 if split is not needed
 * @return {rspamd_text} encoded data chunk
 */
LUA_FUNCTION_DEF (util, encode_base64);
/***
 * @function util.decode_base64(input)
 * Decodes data from base64 ignoring whitespace characters
 * @param {text or string} input data to decode; if `rspamd{text}` is used then the string is modified **in-place**
 * @return {rspamd_text} decoded data chunk
 */
LUA_FUNCTION_DEF (util, decode_base64);
/***
 * @function util.tokenize_text(input[, exceptions])
 * Create tokens from a text using optional exceptions list
 * @param {text/string} input input data
 * @param {table} exceptions, a table of pairs containing <start_pos,lenght> of exceptions in the input
 * @return {table/strings} list of strings representing words in the text
 */
LUA_FUNCTION_DEF (util, tokenize_text);
LUA_FUNCTION_DEF (util, process_message);

static const struct luaL_reg utillib_f[] = {
	LUA_INTERFACE_DEF (util, create_event_base),
	LUA_INTERFACE_DEF (util, load_rspamd_config),
	LUA_INTERFACE_DEF (util, config_from_ucl),
	LUA_INTERFACE_DEF (util, process_message),
	LUA_INTERFACE_DEF (util, encode_base64),
	LUA_INTERFACE_DEF (util, decode_base64),
	LUA_INTERFACE_DEF (util, tokenize_text),
	{NULL, NULL}
};

static gint
lua_util_create_event_base (lua_State *L)
{
	struct event_base **pev_base;

	pev_base = lua_newuserdata (L, sizeof (struct event_base *));
	rspamd_lua_setclass (L, "rspamd{ev_base}", -1);
	*pev_base = event_init ();

	return 1;
}

static gint
lua_util_load_rspamd_config (lua_State *L)
{
	struct rspamd_config *cfg, **pcfg;
	const gchar *cfg_name;

	cfg_name = luaL_checkstring (L, 1);

	if (cfg_name) {
		cfg = g_malloc0 (sizeof (struct rspamd_config));
		rspamd_init_cfg (cfg, FALSE);

		if (rspamd_config_read (cfg, cfg_name, NULL, NULL, NULL)) {
			msg_err ("cannot load config from %s", cfg_name);
			lua_pushnil (L);
		}
		else {
			rspamd_config_post_load (cfg);
			init_symbols_cache (cfg->cfg_pool, cfg->cache, cfg, NULL, TRUE);
			pcfg = lua_newuserdata (L, sizeof (struct rspamd_config *));
			rspamd_lua_setclass (L, "rspamd{config}", -1);
			*pcfg = cfg;
		}
	}

	return 1;
}

static gint
lua_util_config_from_ucl (lua_State *L)
{
	struct rspamd_config *cfg, **pcfg;
	struct rspamd_rcl_section *top;
	GError *err = NULL;
	ucl_object_t *obj;

	obj = ucl_object_lua_import (L, 1);

	if (obj) {
		cfg = g_malloc0 (sizeof (struct rspamd_config));
		rspamd_init_cfg (cfg, FALSE);
		cfg->lua_state = L;
		cfg->rcl_obj = obj;
		top = rspamd_rcl_config_init ();

		if (!rspamd_rcl_parse (top, cfg, cfg->cfg_pool, cfg->rcl_obj, &err)) {
			msg_err ("rcl parse error: %s", err->message);
			ucl_object_unref (obj);
			lua_pushnil (L);
		}
		else {
			rspamd_config_post_load (cfg);
			init_symbols_cache (cfg->cfg_pool, cfg->cache, cfg, NULL, TRUE);
			pcfg = lua_newuserdata (L, sizeof (struct rspamd_config *));
			rspamd_lua_setclass (L, "rspamd{config}", -1);
			*pcfg = cfg;
		}
	}

	return 1;
}

static gboolean
lua_util_task_fin (struct rspamd_task *task, void *ud)
{
	ucl_object_t **target = ud;

	*target = rspamd_protocol_write_ucl (task, NULL);
	rdns_resolver_release (task->resolver->r);

	return TRUE;
}

static gint
lua_util_process_message (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *message;
	gsize mlen;
	struct rspamd_task *task;
	struct event_base *base;
	ucl_object_t *res = NULL;

	message = luaL_checklstring (L, 2, &mlen);

	if (cfg != NULL && message != NULL) {
		base = event_init ();
		rspamd_init_filters (cfg, FALSE);
		task = rspamd_task_new (NULL);
		task->cfg = cfg;
		task->ev_base = base;
		task->msg.start = rspamd_mempool_alloc (task->task_pool, mlen + 1);
		rspamd_strlcpy ((gpointer)task->msg.start, message, mlen + 1);
		task->msg.len = mlen;
		task->fin_callback = lua_util_task_fin;
		task->fin_arg = &res;
		task->resolver = dns_resolver_init (NULL, base, cfg);
		task->s = new_async_session (task->task_pool, rspamd_task_fin,
					rspamd_task_restore, rspamd_task_free_hard, task);

		if (rspamd_task_process (task, NULL, message, mlen, TRUE)) {
			event_base_loop (base, 0);

			if (res != NULL) {
				ucl_object_push_lua (L, res, true);

				ucl_object_unref (res);
			}
			else {
				ucl_object_push_lua (L, rspamd_protocol_write_ucl (task, NULL),
						true);
				rdns_resolver_release (task->resolver->r);
				rspamd_task_free_hard (task);
			}
		}
		else {
			lua_pushnil (L);
		}

		event_base_free (base);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_util_encode_base64 (lua_State *L)
{
	struct rspamd_lua_text *t;
	const gchar *s = NULL;
	gchar *out;
	gsize inlen, outlen;
	guint str_lim = 0;

	if (lua_type (L, 1) == LUA_TSTRING) {
		s = luaL_checklstring (L, 1, &inlen);
	}
	else if (lua_type (L, 1) == LUA_TUSERDATA) {
		t = lua_check_text (L, 1);

		if (t != NULL) {
			s = t->start;
			inlen = t->len;
		}
	}

	if (lua_gettop (L) > 1) {
		str_lim = luaL_checknumber (L, 2);
	}

	if (s == NULL) {
		lua_pushnil (L);
	}
	else {
		out = rspamd_encode_base64 (s, inlen, str_lim, &outlen);

		if (out != NULL) {
			t = lua_newuserdata (L, sizeof (*t));
			rspamd_lua_setclass (L, "rspamd{text}", -1);
			t->start = out;
			t->len = outlen;
			/* Need destruction */
			t->own = TRUE;
		}
		else {
			lua_pushnil (L);
		}
	}

	return 1;
}

static gint
lua_util_decode_base64 (lua_State *L)
{
	struct rspamd_lua_text *t;
	const gchar *s = NULL;
	gsize inlen, outlen;
	gboolean zero_copy = FALSE, grab_own = FALSE;
	gint state = 0;
	guint save = 0;

	if (lua_type (L, 1) == LUA_TSTRING) {
		s = luaL_checklstring (L, 1, &inlen);
	}
	else if (lua_type (L, 1) == LUA_TUSERDATA) {
		t = lua_check_text (L, 1);

		if (t != NULL) {
			s = t->start;
			inlen = t->len;
			zero_copy = TRUE;
			if (t->own) {
				t->own = FALSE;
				grab_own = TRUE;
			}
		}
	}

	if (s != NULL) {
		if (zero_copy) {
			/* Decode in place */
			outlen = g_base64_decode_step (s, inlen, (guchar *)s, &state, &save);
			t = lua_newuserdata (L, sizeof (*t));
			rspamd_lua_setclass (L, "rspamd{text}", -1);
			t->start = s;
			t->len = outlen;
			t->own = grab_own;
		}
		else {
			t = lua_newuserdata (L, sizeof (*t));
			rspamd_lua_setclass (L, "rspamd{text}", -1);
			t->len = (inlen / 4) * 3 + 3;
			t->start = g_malloc (t->len);
			outlen = g_base64_decode_step (s, inlen, (guchar *)t->start,
					&state, &save);
			t->len = outlen;
			t->own = TRUE;
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_util_tokenize_text (lua_State *L)
{
	const gchar *in = NULL;
	gsize len, pos, ex_len, i;
	GList *exceptions = NULL, *cur;
	struct rspamd_lua_text *t;
	struct process_exception *ex;
	GArray *res;
	rspamd_fstring_t *w;
	gboolean compat = FALSE;

	if (lua_type (L, 1) == LUA_TSTRING) {
		in = luaL_checklstring (L, 1, &len);
	}
	else if (lua_type (L, 1) == LUA_TTABLE) {
		t = lua_check_text (L, 1);

		if (t) {
			in = t->start;
			len = t->len;
		}
	}

	if (in == NULL) {
		lua_pushnil (L);
		return 1;
	}

	if (lua_gettop (L) > 1 && lua_type (L, 2) == LUA_TTABLE) {
		lua_pushvalue (L, 2);
		lua_pushnil (L);

		while (lua_next (L, -2) != 0) {
			if (lua_type (L, -1) == LUA_TTABLE) {
				lua_rawgeti (L, -1, 1);
				pos = luaL_checknumber (L, -1);
				lua_pop (L, 1);
				lua_rawgeti (L, -1, 2);
				ex_len = luaL_checknumber (L, -1);
				lua_pop (L, 1);

				if (ex_len > 0) {
					ex = g_slice_alloc (sizeof (*ex));
					ex->pos = pos;
					ex->len = ex_len;
					exceptions = g_list_prepend (exceptions, ex);
				}
			}
			lua_pop (L, 1);
		}

		lua_pop (L, 1);
	}

	if (lua_gettop (L) > 2 && lua_type (L, 3) == LUA_TBOOLEAN) {
		compat = lua_toboolean (L, 3);
	}

	if (exceptions) {
		exceptions = g_list_reverse (exceptions);
	}

	res = rspamd_tokenize_text ((gchar *)in, len, TRUE, 0, exceptions, compat);

	if (res == NULL) {
		lua_pushnil (L);
	}
	else {
		lua_newtable (L);

		for (i = 0; i < res->len; i ++) {
			w = &g_array_index (res, rspamd_fstring_t, i);
			lua_pushlstring (L, w->begin, w->len);
			lua_rawseti (L, -2, i + 1);
		}
	}

	cur = exceptions;
	while (cur) {
		ex = cur->data;
		g_slice_free1 (sizeof (*ex), ex);
		cur = g_list_next (cur);
	}

	g_list_free (exceptions);

	return 1;
}

static gint
lua_load_util (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, utillib_f);

	return 1;
}

void
luaopen_util (lua_State * L)
{
	rspamd_lua_add_preload (L, "rspamd_util", lua_load_util);
}
