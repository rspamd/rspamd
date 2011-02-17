/*
 * Copyright (c) 2009, Rambler media
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include "lua_common.h"
#include "../message.h"
#include "../expressions.h"
#include "../protocol.h"
#include "../filter.h"
#include "../dns.h"
#include "../util.h"
#include "../images.h"
#include "../cfg_file.h"
#include "../statfile.h"
#include "../tokenizers/tokenizers.h"
#include "../classifiers/classifiers.h"
#include "../binlog.h"
#include "../statfile_sync.h"

extern stat_file_t* get_statfile_by_symbol (statfile_pool_t *pool, struct classifier_config *ccf,
		const gchar *symbol, struct statfile **st, gboolean try_create);

/* Task methods */
LUA_FUNCTION_DEF (task, get_message);
LUA_FUNCTION_DEF (task, insert_result);
LUA_FUNCTION_DEF (task, get_urls);
LUA_FUNCTION_DEF (task, get_emails);
LUA_FUNCTION_DEF (task, get_text_parts);
LUA_FUNCTION_DEF (task, get_raw_headers);
LUA_FUNCTION_DEF (task, get_received_headers);
LUA_FUNCTION_DEF (task, resolve_dns_a);
LUA_FUNCTION_DEF (task, resolve_dns_ptr);
LUA_FUNCTION_DEF (task, resolve_dns_txt);
LUA_FUNCTION_DEF (task, call_rspamd_function);
LUA_FUNCTION_DEF (task, get_recipients);
LUA_FUNCTION_DEF (task, get_from);
LUA_FUNCTION_DEF (task, get_from_ip);
LUA_FUNCTION_DEF (task, get_from_ip_num);
LUA_FUNCTION_DEF (task, get_client_ip_num);
LUA_FUNCTION_DEF (task, get_helo);
LUA_FUNCTION_DEF (task, get_images);
LUA_FUNCTION_DEF (task, get_symbol);
LUA_FUNCTION_DEF (task, get_metric_score);
LUA_FUNCTION_DEF (task, get_metric_action);
LUA_FUNCTION_DEF (task, learn_statfile);

static const struct luaL_reg    tasklib_m[] = {
	LUA_INTERFACE_DEF (task, get_message),
	LUA_INTERFACE_DEF (task, insert_result),
	LUA_INTERFACE_DEF (task, get_urls),
	LUA_INTERFACE_DEF (task, get_emails),
	LUA_INTERFACE_DEF (task, get_text_parts),
	LUA_INTERFACE_DEF (task, get_raw_headers),
	LUA_INTERFACE_DEF (task, get_received_headers),
	LUA_INTERFACE_DEF (task, resolve_dns_a),
	LUA_INTERFACE_DEF (task, resolve_dns_ptr),
	LUA_INTERFACE_DEF (task, resolve_dns_txt),
	LUA_INTERFACE_DEF (task, call_rspamd_function),
	LUA_INTERFACE_DEF (task, get_recipients),
	LUA_INTERFACE_DEF (task, get_from),
	LUA_INTERFACE_DEF (task, get_from_ip),
	LUA_INTERFACE_DEF (task, get_from_ip_num),
	LUA_INTERFACE_DEF (task, get_client_ip_num),
	LUA_INTERFACE_DEF (task, get_helo),
	LUA_INTERFACE_DEF (task, get_images),
	LUA_INTERFACE_DEF (task, get_symbol),
	LUA_INTERFACE_DEF (task, get_metric_score),
	LUA_INTERFACE_DEF (task, get_metric_action),
	LUA_INTERFACE_DEF (task, learn_statfile),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

/* Textpart methods */
LUA_FUNCTION_DEF (textpart, get_content);
LUA_FUNCTION_DEF (textpart, is_empty);
LUA_FUNCTION_DEF (textpart, is_html);
LUA_FUNCTION_DEF (textpart, get_fuzzy);

static const struct luaL_reg    textpartlib_m[] = {
	LUA_INTERFACE_DEF (textpart, get_content),
	LUA_INTERFACE_DEF (textpart, is_empty),
	LUA_INTERFACE_DEF (textpart, is_html),
	LUA_INTERFACE_DEF (textpart, get_fuzzy),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

/* Image methods */
LUA_FUNCTION_DEF (image, get_width);
LUA_FUNCTION_DEF (image, get_height);
LUA_FUNCTION_DEF (image, get_type);
LUA_FUNCTION_DEF (image, get_filename);
LUA_FUNCTION_DEF (image, get_size);

static const struct luaL_reg    imagelib_m[] = {
	LUA_INTERFACE_DEF (image, get_width),
	LUA_INTERFACE_DEF (image, get_height),
	LUA_INTERFACE_DEF (image, get_type),
	LUA_INTERFACE_DEF (image, get_filename),
	LUA_INTERFACE_DEF (image, get_size),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

/* URL methods */
LUA_FUNCTION_DEF (url, get_host);
LUA_FUNCTION_DEF (url, get_user);
LUA_FUNCTION_DEF (url, get_path);
LUA_FUNCTION_DEF (url, get_text);
LUA_FUNCTION_DEF (url, is_phished);
LUA_FUNCTION_DEF (url, get_phished);

static const struct luaL_reg    urllib_m[] = {
	LUA_INTERFACE_DEF (url, get_host),
	LUA_INTERFACE_DEF (url, get_user),
	LUA_INTERFACE_DEF (url, get_path),
	LUA_INTERFACE_DEF (url, get_text),
	LUA_INTERFACE_DEF (url, is_phished),
	LUA_INTERFACE_DEF (url, get_phished),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

/* Utility functions */
static struct worker_task      *
lua_check_task (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{task}");
	luaL_argcheck (L, ud != NULL, 1, "'task' expected");
	return *((struct worker_task **)ud);
}

static struct mime_text_part   *
lua_check_textpart (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{textpart}");
	luaL_argcheck (L, ud != NULL, 1, "'textpart' expected");
	return *((struct mime_text_part **)ud);
}

static struct rspamd_image      *
lua_check_image (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{image}");
	luaL_argcheck (L, ud != NULL, 1, "'image' expected");
	return *((struct rspamd_image **)ud);
}

static struct uri      *
lua_check_url (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{url}");
	luaL_argcheck (L, ud != NULL, 1, "'url' expected");
	return *((struct uri **)ud);
}

/*** Task interface	***/
static int
lua_task_get_message (lua_State * L)
{
	GMimeMessage                  **pmsg;
	struct worker_task             *task = lua_check_task (L);

	if (task != NULL) {
		/* XXX write handler for message object */
		pmsg = lua_newuserdata (L, sizeof (GMimeMessage *));
		lua_setclass (L, "rspamd{message}", -1);
		*pmsg = task->message;
	}
	return 1;
}

static gint
lua_task_insert_result (lua_State * L)
{
	struct worker_task             *task = lua_check_task (L);
	const gchar                     *symbol_name, *param;
	double                          flag;
	GList                          *params = NULL;
	gint                            i, top;

	if (task != NULL) {
		symbol_name = memory_pool_strdup (task->task_pool, luaL_checkstring (L, 2));
		flag = luaL_checknumber (L, 3);
		top = lua_gettop (L);
		/* Get additional options */
		for (i = 4; i <= top; i++) {
			param = luaL_checkstring (L, i);
			params = g_list_prepend (params, memory_pool_strdup (task->task_pool, param));
		}

		insert_result (task, symbol_name, flag, params);
	}
	return 1;
}

static gint
lua_task_get_urls (lua_State * L)
{
	gint                            i = 1;
	struct worker_task             *task = lua_check_task (L);
	GList                          *cur;
	struct uri                    **purl;

	if (task) {
		cur = task->urls;
		if (cur != NULL) {
			lua_newtable (L);
			while (cur) {
				purl = lua_newuserdata (L, sizeof (struct uri *));
				lua_setclass (L, "rspamd{url}", -1);
				*purl = cur->data;
				lua_rawseti (L, -2, i++);
				cur = g_list_next (cur);
			}
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

static gint
lua_task_get_emails (lua_State * L)
{
	gint                            i = 1;
	struct worker_task             *task = lua_check_task (L);
	GList                          *cur;
	struct uri                    **purl;

	if (task) {
		cur = task->emails;
		if (cur != NULL) {
			lua_newtable (L);
			while (cur) {
				purl = lua_newuserdata (L, sizeof (struct uri *));
				lua_setclass (L, "rspamd{url}", -1);
				*purl = cur->data;
				lua_rawseti (L, -2, i++);
				cur = g_list_next (cur);
			}
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

static gint
lua_task_get_text_parts (lua_State * L)
{
	gint                            i = 1;
	struct worker_task             *task = lua_check_task (L);
	GList                          *cur;
	struct mime_text_part          *part, **ppart;

	if (task != NULL) {
		lua_newtable (L);
		cur = task->text_parts;
		while (cur) {
			part = cur->data;
			ppart = lua_newuserdata (L, sizeof (struct mime_text_part *));
			*ppart = part;
			lua_setclass (L, "rspamd{textpart}", -1);
			/* Make it array */
			lua_rawseti (L, -2, i++);
			cur = g_list_next (cur);
		}
		return 1;
	}
	lua_pushnil (L);
	return 1;
}

static gint
lua_task_get_raw_headers (lua_State * L)
{
	struct worker_task             *task = lua_check_task (L);

	if (task) {
		lua_pushstring (L, task->raw_headers);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_task_get_received_headers (lua_State * L)
{
	struct worker_task             *task = lua_check_task (L);
	GList                          *cur;
	struct received_header         *rh;
	gint                            i = 1;

	if (task) {
		lua_newtable (L);
		cur = g_list_first (task->received);
		while (cur) {
			rh = cur->data;
			if (rh->is_error || G_UNLIKELY(
					rh->from_ip == NULL &&
					rh->real_ip == NULL &&
					rh->real_hostname == NULL &&
					rh->by_hostname == NULL)) {
				cur = g_list_next (cur);
				continue;
			}
			lua_newtable (L);
			lua_set_table_index (L, "from_hostname", rh->from_hostname);
			lua_set_table_index (L, "from_ip", rh->from_ip);
			lua_set_table_index (L, "real_hostname", rh->real_hostname);
			lua_set_table_index (L, "real_ip", rh->real_ip);
			lua_set_table_index (L, "by_hostname", rh->by_hostname);
			lua_rawseti (L, -2, i++);
			cur = g_list_next (cur);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

struct lua_dns_callback_data {
	lua_State                      *L;
	struct worker_task             *task;
	const gchar                    *callback;
	const gchar                    *to_resolve;
	gint                            cbtype;
	union {
		gpointer                    string;
		gboolean                    boolean;
		gdouble                     number;
	}                               cbdata;
};

static void
lua_dns_callback (struct rspamd_dns_reply *reply, gpointer arg)
{
	struct lua_dns_callback_data   *cd = arg;
	gint                            i = 0;
	struct in_addr                  ina;
	struct worker_task            **ptask;
	union rspamd_reply_element     *elt;
	GList                          *cur;

	lua_getglobal (cd->L, cd->callback);
	ptask = lua_newuserdata (cd->L, sizeof (struct worker_task *));
	lua_setclass (cd->L, "rspamd{task}", -1);

	*ptask = cd->task;
	lua_pushstring (cd->L, cd->to_resolve);

	if (reply->code == DNS_RC_NOERROR) {
		if (reply->type == DNS_REQUEST_A) {

			lua_newtable (cd->L);
			cur = reply->elements;
			while (cur) {
				elt = cur->data;
				memcpy (&ina, elt->a.addr, sizeof (in_addr_t));
				/* Actually this copy memory, so using of inet_ntoa is valid */
				lua_pushstring (cd->L, inet_ntoa (ina));
				lua_rawseti (cd->L, -2, ++i);
				cur = g_list_next (cur);
			}
			lua_pushnil (cd->L);
		}
		else if (reply->type == DNS_REQUEST_A) {
			lua_newtable (cd->L);
			cur = reply->elements;
			while (cur) {
				elt = cur->data;
				lua_pushstring (cd->L, elt->ptr.name);
				lua_rawseti (cd->L, -2, ++i);
				cur = g_list_next (cur);
			}
			lua_pushnil (cd->L);

		}
		else if (reply->type == DNS_REQUEST_TXT) {
			lua_newtable (cd->L);
			cur = reply->elements;
			while (cur) {
				elt = cur->data;
				lua_pushstring (cd->L, elt->txt.data);
				lua_rawseti (cd->L, -2, ++i);
				cur = g_list_next (cur);
			}
			lua_pushnil (cd->L);

		}
		else {
			lua_pushnil (cd->L);
			lua_pushstring (cd->L, "Unknown reply type");
		}
	}
	else {
		lua_pushnil (cd->L);
		lua_pushstring (cd->L, dns_strerror (reply->code));
	}

	switch (cd->cbtype) {
	case LUA_TBOOLEAN:
		lua_pushboolean (cd->L, cd->cbdata.boolean);
		break;
	case LUA_TNUMBER:
		lua_pushnumber (cd->L, cd->cbdata.number);
		break;
	case LUA_TSTRING:
		lua_pushstring (cd->L, cd->cbdata.string);
		break;
	default:
		lua_pushnil (cd->L);
		break;
	}

	if (lua_pcall (cd->L, 5, 0, 0) != 0) {
		msg_info ("call to %s failed: %s", cd->callback, lua_tostring (cd->L, -1));
	}

	cd->task->save.saved--;
	if (cd->task->save.saved == 0) {
		/* Call other filters */
		cd->task->save.saved = 1;
		process_filters (cd->task);
	}
}

static gint
lua_task_resolve_dns_a (lua_State * L)
{
	struct worker_task             *task = lua_check_task (L);
	struct lua_dns_callback_data   *cd;

	if (task) {
		cd = memory_pool_alloc (task->task_pool, sizeof (struct lua_dns_callback_data));
		cd->task = task;
		cd->L = L;
		cd->to_resolve = memory_pool_strdup (task->task_pool, luaL_checkstring (L, 2));
		cd->callback = memory_pool_strdup (task->task_pool, luaL_checkstring (L, 3));
		cd->cbtype = lua_type (L, 4);
		if (cd->cbtype != LUA_TNONE && cd->cbtype != LUA_TNIL) {
			switch (cd->cbtype) {
			case LUA_TBOOLEAN:
				cd->cbdata.boolean = lua_toboolean (L, 4);
				break;
			case LUA_TNUMBER:
				cd->cbdata.number = lua_tonumber (L, 4);
				break;
			case LUA_TSTRING:
				cd->cbdata.string = memory_pool_strdup (task->task_pool, lua_tostring (L, 4));
				break;
			default:
				msg_warn ("cannot handle type %s as callback data", lua_typename (L, cd->cbtype));
				cd->cbtype = LUA_TNONE;
				break;
			}
		}

		if (!cd->to_resolve || !cd->callback) {
			msg_info ("invalid parameters passed to function");
			return 0;
		}
		if (make_dns_request (task->resolver, task->s, task->task_pool, lua_dns_callback, (void *)cd, DNS_REQUEST_A, cd->to_resolve)) {
			task->save.saved++;
		}
	}
	return 0;
}

static gint
lua_task_resolve_dns_txt (lua_State * L)
{
	struct worker_task             *task = lua_check_task (L);
	struct lua_dns_callback_data   *cd;

	if (task) {
		cd = memory_pool_alloc (task->task_pool, sizeof (struct lua_dns_callback_data));
		cd->task = task;
		cd->L = L;
		cd->to_resolve = memory_pool_strdup (task->task_pool, luaL_checkstring (L, 2));
		cd->callback = memory_pool_strdup (task->task_pool, luaL_checkstring (L, 3));
		cd->cbtype = lua_type (L, 4);
		if (cd->cbtype != LUA_TNONE && cd->cbtype != LUA_TNIL) {
			switch (cd->cbtype) {
			case LUA_TBOOLEAN:
				cd->cbdata.boolean = lua_toboolean (L, 4);
				break;
			case LUA_TNUMBER:
				cd->cbdata.number = lua_tonumber (L, 4);
				break;
			case LUA_TSTRING:
				cd->cbdata.string = memory_pool_strdup (task->task_pool, lua_tostring (L, 4));
				break;
			default:
				msg_warn ("cannot handle type %s as callback data", lua_typename (L, cd->cbtype));
				cd->cbtype = LUA_TNONE;
				break;
			}
		}
		if (!cd->to_resolve || !cd->callback) {
			msg_info ("invalid parameters passed to function");
			return 0;
		}
		if (make_dns_request (task->resolver, task->s, task->task_pool, lua_dns_callback, (void *)cd, DNS_REQUEST_TXT, cd->to_resolve)) {
			task->save.saved++;
		}
	}
	return 0;
}

static gint
lua_task_resolve_dns_ptr (lua_State * L)
{
	struct worker_task             *task = lua_check_task (L);
	struct lua_dns_callback_data   *cd;
	struct in_addr                 *ina;

	if (task) {
		cd = memory_pool_alloc (task->task_pool, sizeof (struct lua_dns_callback_data));
		cd->task = task;
		cd->L = L;
		cd->to_resolve = memory_pool_strdup (task->task_pool, luaL_checkstring (L, 2));
		cd->callback = memory_pool_strdup (task->task_pool, luaL_checkstring (L, 3));
		cd->cbtype = lua_type (L, 4);
		if (cd->cbtype != LUA_TNONE && cd->cbtype != LUA_TNIL) {
			switch (cd->cbtype) {
			case LUA_TBOOLEAN:
				cd->cbdata.boolean = lua_toboolean (L, 4);
				break;
			case LUA_TNUMBER:
				cd->cbdata.number = lua_tonumber (L, 4);
				break;
			case LUA_TSTRING:
				cd->cbdata.string = memory_pool_strdup (task->task_pool, lua_tostring (L, 4));
				break;
			default:
				msg_warn ("cannot handle type %s as callback data", lua_typename (L, cd->cbtype));
				cd->cbtype = LUA_TNONE;
				break;
			}
		}
		ina = memory_pool_alloc (task->task_pool, sizeof (struct in_addr));
		if (!cd->to_resolve || !cd->callback || !inet_aton (cd->to_resolve, ina)) {
			msg_info ("invalid parameters passed to function");
			return 0;
		}
		if (make_dns_request (task->resolver, task->s, task->task_pool, lua_dns_callback, (void *)cd, DNS_REQUEST_PTR, ina)) {
			task->save.saved++;
		}
	}
	return 0;
}

static gint
lua_task_call_rspamd_function (lua_State * L)
{
	struct worker_task             *task = lua_check_task (L);
	struct expression_function      f;
	gint                            i, top;
	gboolean                        res;
	gchar                           *arg;

	if (task) {
		f.name = (gchar *)luaL_checkstring (L, 2);
		if (f.name) {
			f.args = NULL;
			top = lua_gettop (L);
			/* Get arguments after function name */
			for (i = 3; i <= top; i++) {
				arg = (gchar *)luaL_checkstring (L, i);
				if (arg != NULL) {
					f.args = g_list_prepend (f.args, arg);
				}
			}
			res = call_expression_function (&f, task);
			lua_pushboolean (L, res);
			if (f.args) {
				g_list_free (f.args);
			}

			return 1;
		}
	}

	lua_pushnil (L);

	return 1;

}

static gint
lua_task_get_recipients (lua_State *L)
{
	struct worker_task             *task = lua_check_task (L);
	gint                            i = 1;
	GList                          *cur;

	if (task) {
		cur = task->rcpt;
		if (cur != NULL) {
			lua_newtable (L);
			while (cur) {
				lua_pushstring (L, (gchar *)cur->data);
				lua_rawseti (L, -2, i++);
				cur = g_list_next (cur);
			}
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

static gint
lua_task_get_from (lua_State *L)
{
	struct worker_task             *task = lua_check_task (L);
	
	if (task) {
		if (task->from != NULL) {
			lua_pushstring (L, (gchar *)task->from);
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

static gint
lua_task_get_from_ip (lua_State *L)
{
	struct worker_task             *task = lua_check_task (L);
	
	if (task) {
		if (task->from_addr.s_addr != INADDR_NONE && task->from_addr.s_addr != INADDR_ANY) {
			lua_pushstring (L, inet_ntoa (task->from_addr));
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

static gint
lua_task_get_from_ip_num (lua_State *L)
{
	struct worker_task             *task = lua_check_task (L);
	
	if (task) {
		if (task->from_addr.s_addr != INADDR_NONE && task->from_addr.s_addr != INADDR_ANY) {
			lua_pushinteger (L, ntohl (task->from_addr.s_addr));
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

static gint
lua_task_get_client_ip_num (lua_State *L)
{
	struct worker_task             *task = lua_check_task (L);
	
	if (task) {
		if (task->client_addr.s_addr != INADDR_NONE && task->client_addr.s_addr != INADDR_ANY) {
			lua_pushinteger (L, ntohl (task->client_addr.s_addr));
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

static gint
lua_task_get_helo (lua_State *L)
{
	struct worker_task             *task = lua_check_task (L);
	
	if (task) {
		if (task->helo != NULL) {
			lua_pushstring (L, (gchar *)task->helo);
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

static gint
lua_task_get_images (lua_State *L)
{
	struct worker_task             *task = lua_check_task (L);
	gint                            i = 1;
	GList                          *cur;
	struct rspamd_image           **pimg;

	if (task) {
		cur = task->images;
		if (cur != NULL) {
			lua_newtable (L);
			while (cur) {
				pimg = lua_newuserdata (L, sizeof (struct rspamd_image *));
				lua_setclass (L, "rspamd{image}", -1);
				*pimg = cur->data;
				lua_rawseti (L, -2, i++);
				cur = g_list_next (cur);
			}
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

static inline gboolean
lua_push_symbol_result (lua_State *L, struct worker_task *task, struct metric *metric, const gchar *symbol)
{
	struct metric_result           *metric_res;
	struct symbol                  *s;
	gint                            j;
	GList                          *opt;

	metric_res = g_hash_table_lookup (task->results, metric->name);
	if (metric_res) {
		if ((s = g_hash_table_lookup (metric_res->symbols, symbol)) != NULL) {
			j = 0;
			lua_newtable (L);
			lua_pushstring (L, "metric");
			lua_pushstring (L, metric->name);
			lua_settable (L, -3);
			lua_pushstring (L, "score");
			lua_pushnumber (L, s->score);
			lua_settable (L, -3);
			if (s->options) {
				opt = s->options;
				lua_pushstring (L, "options");
				lua_newtable (L);
				while (opt) {
					lua_pushstring (L, opt->data);
					lua_rawseti (L, -2, j++);
					opt = g_list_next (opt);
				}
				lua_settable (L, -3);
			}

			return TRUE;
		}
	}

	return FALSE;
}

static gint
lua_task_get_symbol (lua_State *L)
{
	struct worker_task             *task = lua_check_task (L);
	const gchar                     *symbol;
	struct metric                  *metric;
	GList                          *cur = NULL, *metric_list;
	gboolean                        found = FALSE;
	gint                            i = 1;

	symbol = luaL_checkstring (L, 2);

	if (task && symbol) {
		metric_list = g_hash_table_lookup (task->cfg->metrics_symbols, symbol);
		if (metric_list) {
			lua_newtable (L);
			cur = metric_list;
		}
		else {
			metric = task->cfg->default_metric;
		}

		if (!cur && metric) {
			if ((found = lua_push_symbol_result (L, task, metric, symbol))) {
				lua_newtable (L);
				lua_rawseti (L, -2, i++);
			}
		}
		else {
			while (cur) {
				metric = cur->data;
				if (lua_push_symbol_result (L, task, metric, symbol)) {
					lua_rawseti (L, -2, i++);
					found = TRUE;
				}
				cur = g_list_next (cur);
			}
		}
	}

	if (!found) {
		lua_pushnil (L);
	}
	return 1;
}

static gint
lua_task_learn_statfile (lua_State *L)
{
	struct worker_task             *task = lua_check_task (L);
	const gchar                     *symbol;
	struct classifier_config       *cl;
	GTree                          *tokens;
	struct statfile                *st;
	stat_file_t                    *statfile;
	struct classifier_ctx          *ctx;

	symbol = luaL_checkstring (L, 2);

	if (task && symbol) {
		cl = g_hash_table_lookup (task->cfg->classifiers_symbols, symbol);
		if (cl == NULL) {
			msg_warn ("classifier for symbol %s is not found", symbol);
			lua_pushboolean (L, FALSE);
			return 1;
		}
		ctx = cl->classifier->init_func (task->task_pool, cl);
		if ((tokens = g_hash_table_lookup (task->tokens, cl->tokenizer)) == NULL) {
			msg_warn ("no tokens found learn failed!");
			lua_pushboolean (L, FALSE);
			return 1;
		}
		statfile = get_statfile_by_symbol (task->worker->srv->statfile_pool, ctx->cfg,
								symbol, &st, TRUE);

		if (statfile == NULL) {
			msg_warn ("opening statfile failed!");
			lua_pushboolean (L, FALSE);
			return 1;
		}

		cl->classifier->learn_func (ctx, task->worker->srv->statfile_pool, symbol, tokens, TRUE, NULL, 1., NULL);
		maybe_write_binlog (ctx->cfg, st, statfile, tokens);
		lua_pushboolean (L, TRUE);
	}

	return 1;
}

static gint
lua_task_get_metric_score (lua_State *L)
{
	struct worker_task             *task = lua_check_task (L);
	const gchar                     *metric_name;
	struct metric_result           *metric_res;

	metric_name = luaL_checkstring (L, 2);

	if (task && metric_name) {
		if ((metric_res = g_hash_table_lookup (task->results, metric_name)) != NULL) {
			lua_newtable (L);
			lua_pushnumber (L, metric_res->score);
			lua_rawseti (L, -2, 1);
			lua_pushnumber (L, metric_res->metric->required_score);
			lua_rawseti (L, -2, 2);
			lua_pushnumber (L, metric_res->metric->reject_score);
			lua_rawseti (L, -2, 3);
		}
		else {
			lua_pushnil (L);
		}
		return 1;
	}

	return 0;
}

static gint
lua_task_get_metric_action (lua_State *L)
{
	struct worker_task             *task = lua_check_task (L);
	const gchar                     *metric_name;
	struct metric_result           *metric_res;
	enum rspamd_metric_action       action;

	metric_name = luaL_checkstring (L, 2);

	if (task && metric_name) {
		if ((metric_res = g_hash_table_lookup (task->results, metric_name)) != NULL) {
			action = check_metric_action (metric_res->score, metric_res->metric->required_score, metric_res->metric);
			lua_pushstring (L, str_action_metric (action));
		}
		else {
			lua_pushnil (L);
		}
		return 1;
	}

	return 0;
}

/**** Textpart implementation *****/

static gint
lua_textpart_get_content (lua_State * L)
{
	struct mime_text_part          *part = lua_check_textpart (L);

	if (part == NULL || part->is_empty) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushlstring (L, part->content->data, part->content->len);

	return 1;
}

static gint
lua_textpart_is_empty (lua_State * L)
{
	struct mime_text_part          *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushboolean (L, part->is_empty);

	return 1;
}

static gint
lua_textpart_is_html (lua_State * L)
{
	struct mime_text_part          *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushboolean (L, part->is_html);

	return 1;
}

static gint
lua_textpart_get_fuzzy (lua_State * L)
{
	struct mime_text_part          *part = lua_check_textpart (L);

	if (part == NULL || part->is_empty) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushlstring (L, part->fuzzy->hash_pipe, sizeof (part->fuzzy->hash_pipe));
	return 1;
}

/* Image functions */
static gint
lua_image_get_width (lua_State *L)
{
	struct rspamd_image             *img = lua_check_image (L);

	if (img != NULL) {
		lua_pushnumber (L, img->width);
	}
	else {
		lua_pushnumber (L, 0);
	}
	return 1;
}

static gint
lua_image_get_height (lua_State *L)
{
	struct rspamd_image             *img = lua_check_image (L);

	if (img != NULL) {
		lua_pushnumber (L, img->height);
	}
	else {
		lua_pushnumber (L, 0);
	}

	return 1;
}

static gint
lua_image_get_type (lua_State *L)
{
	struct rspamd_image             *img = lua_check_image (L);

	if (img != NULL) {
		lua_pushstring (L, image_type_str (img->type));
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_image_get_size (lua_State *L)
{
	struct rspamd_image             *img = lua_check_image (L);

	if (img != NULL) {
		lua_pushinteger (L, img->data->len);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_image_get_filename (lua_State *L)
{
	struct rspamd_image             *img = lua_check_image (L);

	if (img != NULL && img->filename != NULL) {
		lua_pushstring (L, img->filename);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/* URL part */
static gint
lua_url_get_host (lua_State *L)
{
	struct uri                      *url = lua_check_url (L);

	if (url != NULL) {
		lua_pushlstring (L, url->host, url->hostlen);
	}
	else {
		lua_pushnil (L);
	}
	return 1;
}

static gint
lua_url_get_user (lua_State *L)
{
	struct uri                      *url = lua_check_url (L);

	if (url != NULL) {
		lua_pushlstring (L, url->user, url->userlen);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_url_get_path (lua_State *L)
{
	struct uri                      *url = lua_check_url (L);

	if (url != NULL) {
		lua_pushlstring (L, url->data, url->datalen);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_url_get_text (lua_State *L)
{
	struct uri                      *url = lua_check_url (L);

	if (url != NULL) {
		lua_pushstring (L, struri (url));
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_url_is_phished (lua_State *L)
{
	struct uri                      *url = lua_check_url (L);

	if (url != NULL) {
		lua_pushboolean (L, url->is_phished);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_url_get_phished (lua_State *L)
{
	struct uri                    **purl, *url = lua_check_url (L);

	if (url) {
		if (url->is_phished && url->phished_url != NULL) {
			purl = lua_newuserdata (L, sizeof (struct uri *));
			lua_setclass (L, "rspamd{url}", -1);
			*purl = url->phished_url;

			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

/* Init part */
gint
luaopen_task (lua_State * L)
{
	lua_newclass (L, "rspamd{task}", tasklib_m);
	luaL_openlib (L, "rspamd_task", null_reg, 0);

	return 1;
}

gint
luaopen_textpart (lua_State * L)
{
	lua_newclass (L, "rspamd{textpart}", textpartlib_m);
	luaL_openlib (L, "rspamd_textpart", null_reg, 0);

	return 1;
}

gint
luaopen_image (lua_State * L)
{
	lua_newclass (L, "rspamd{image}", imagelib_m);
	luaL_openlib (L, "rspamd_image", null_reg, 0);

	return 1;
}

gint
luaopen_url (lua_State * L)
{
	lua_newclass (L, "rspamd{url}", urllib_m);
	luaL_openlib (L, "rspamd_url", null_reg, 0);

	return 1;
}
