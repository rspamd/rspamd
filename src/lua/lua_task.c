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
#include <evdns.h>

/* Task methods */
LUA_FUNCTION_DEF(task, get_message);
LUA_FUNCTION_DEF(task, insert_result);
LUA_FUNCTION_DEF(task, get_urls);
LUA_FUNCTION_DEF(task, get_text_parts);
LUA_FUNCTION_DEF(task, get_raw_headers);
LUA_FUNCTION_DEF(task, get_received_headers);
LUA_FUNCTION_DEF(task, resolve_dns_a);
LUA_FUNCTION_DEF(task, resolve_dns_ptr);

static const struct luaL_reg tasklib_m[] = {
	LUA_INTERFACE_DEF(task, get_message),
	LUA_INTERFACE_DEF(task, insert_result),
	LUA_INTERFACE_DEF(task, get_urls),
	LUA_INTERFACE_DEF(task, get_text_parts),
    LUA_INTERFACE_DEF(task, get_raw_headers),
    LUA_INTERFACE_DEF(task, get_received_headers),
	LUA_INTERFACE_DEF(task, resolve_dns_a),
	LUA_INTERFACE_DEF(task, resolve_dns_ptr),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

/* Textpart methods */
LUA_FUNCTION_DEF(textpart, get_content);
LUA_FUNCTION_DEF(textpart, is_empty);
LUA_FUNCTION_DEF(textpart, is_html);
LUA_FUNCTION_DEF(textpart, get_fuzzy);

static const struct luaL_reg textpartlib_m[] = {
	LUA_INTERFACE_DEF(textpart, get_content),
	LUA_INTERFACE_DEF(textpart, is_empty),
	LUA_INTERFACE_DEF(textpart, is_html),
	LUA_INTERFACE_DEF(textpart, get_fuzzy),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

/* Utility functions */
static struct worker_task *
lua_check_task (lua_State *L) 
{
	void *ud = luaL_checkudata (L, 1, "rspamd{task}");
	luaL_argcheck (L, ud != NULL, 1, "'task' expected");
	return *((struct worker_task **)ud);
}

static struct mime_text_part *
lua_check_textpart (lua_State *L)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{textpart}");
	luaL_argcheck (L, ud != NULL, 1, "'textpart' expected");
	return *((struct mime_text_part **)ud);
}

/*** Task interface	***/
static int
lua_task_get_message (lua_State *L)
{
	GMimeMessage **pmsg;
	struct worker_task *task = lua_check_task (L);

	if (task != NULL) {
		/* XXX write handler for message object */
		pmsg = lua_newuserdata (L, sizeof (GMimeMessage *));
		lua_setclass (L, "rspamd{message}", -1);
		*pmsg = task->message;
	}
	return 1;
}

static int 
lua_task_insert_result (lua_State *L)
{
	struct worker_task *task = lua_check_task (L);
	const char *metric_name, *symbol_name;
	double flag;

	if (task != NULL) {
		metric_name = luaL_checkstring (L, 2);
		symbol_name = luaL_checkstring (L, 3);
		flag = luaL_checknumber (L, 4);
		insert_result (task, metric_name, symbol_name, flag, NULL);
	}
	return 1;
}

static int 
lua_task_get_urls (lua_State *L)
{
    int i = 1;
	struct worker_task *task = lua_check_task (L);
	GList *cur;
	struct uri *url;

	if (task != NULL) {
        lua_newtable (L);
		cur = g_list_first (task->urls);
		while (cur) {
			url = cur->data;
			lua_pushstring (L, struri (url));
            lua_rawseti(L, -2, i++);
			cur = g_list_next (cur);
		}
	}

	return 1;
}

static int
lua_task_get_text_parts (lua_State *L)
{
    int i = 1;
	struct worker_task *task = lua_check_task (L);
	GList *cur;
	struct mime_text_part *part, **ppart;

	if (task != NULL) {
        lua_newtable (L);
		cur = task->text_parts;
		while (cur) {
			part = cur->data;
			ppart = lua_newuserdata (L, sizeof (struct mime_text_part *));
			*ppart = part;
			lua_setclass (L, "rspamd{textpart}", -1);
            /* Make it array */
            lua_rawseti(L, -2, i++);
			cur = g_list_next (cur);
		}
        return 1;
	}
	lua_pushnil (L);
	return 1;
}

static int
lua_task_get_raw_headers (lua_State *L)
{
	struct worker_task *task = lua_check_task (L);

    if (task) {
		lua_pushstring (L, task->raw_headers);
    }
	else {
		lua_pushnil (L);
	}

    return 1;
}

static int
lua_task_get_received_headers (lua_State *L)
{
	struct worker_task *task = lua_check_task (L);
	GList *cur;
	struct received_header *rh;
	int i = 1;

    if (task) {
		lua_newtable (L);
		cur = g_list_first (task->received);
		while (cur) {
			rh = cur->data;
			lua_newtable (L);
			lua_set_table_index (L, "from_hostname", rh->from_hostname);
			lua_set_table_index (L, "from_ip", rh->from_ip);
			lua_set_table_index (L, "real_hostname", rh->real_hostname);
			lua_set_table_index (L, "real_ip", rh->real_ip);
			lua_set_table_index (L, "by_hostname", rh->by_hostname);
			lua_rawseti(L, -2, i++);
			cur = g_list_next (cur);
		}
    }
	else {
		lua_pushnil (L);
	}
	
	return 1;
}

struct lua_dns_callback_data {
	lua_State *L;
	struct worker_task *task;
	const char *callback;
	const char *to_resolve;
};

static void 
lua_dns_callback (int result, char type, int count, int ttl, void *addresses, void *arg)
{
	struct lua_dns_callback_data *cd = arg;
	int i;
	struct in_addr ina;
	struct worker_task **ptask;

	lua_getglobal (cd->L, cd->callback);
	ptask = lua_newuserdata (cd->L, sizeof (struct worker_task *));
	lua_setclass (cd->L, "rspamd{task}", -1);

	*ptask = cd->task;
	lua_pushstring (cd->L, cd->to_resolve);

	if (result == DNS_ERR_NONE) {
		if (type == DNS_IPv4_A) {

			lua_newtable (cd->L);
			for (i = 1; i <= count; i ++) {
				memcpy (&ina.s_addr, ((in_addr_t *)addresses) + i - 1, sizeof (in_addr_t));
				/* Actually this copy memory, so using of inet_ntoa is valid */
				lua_pushstring (cd->L, inet_ntoa (ina));
				lua_rawseti (cd->L, -2, i);
			}
			lua_pushnil (cd->L);
		}
		else if (type == DNS_PTR) {
			lua_newtable (cd->L);
			for (i = 1; i <= count; i ++) {
				lua_pushstring (cd->L, ((char **)addresses)[i - 1]);
				lua_rawseti (cd->L, -2, i);
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
		lua_pushstring (cd->L, evdns_err_to_string (result));
	}

	if (lua_pcall (cd->L, 4, 0, 0) != 0) {
		msg_info ("lua_dns_callback: call to %s failed: %s", cd->callback, lua_tostring (cd->L, -1));
	}

	cd->task->save.saved --;
	if (cd->task->save.saved == 0) {
		/* Call other filters */
		cd->task->save.saved = 1;
		process_filters (cd->task);
	}

}

static int
lua_task_resolve_dns_a (lua_State *L)
{
	struct worker_task *task = lua_check_task (L);
	struct lua_dns_callback_data *cd;

	if (task) {
		cd = memory_pool_alloc (task->task_pool, sizeof (struct lua_dns_callback_data));
		cd->task = task;
		cd->L = L;
		cd->to_resolve = memory_pool_strdup (task->task_pool, luaL_checkstring (L, 2));
		cd->callback = memory_pool_strdup (task->task_pool, luaL_checkstring (L, 3));
		if (!cd->to_resolve || !cd->callback) {
			msg_info ("lua_task_resolve_dns_a: invalid parameters passed to function");
			return 0;
		}
		if (evdns_resolve_ipv4 (cd->to_resolve, DNS_QUERY_NO_SEARCH, lua_dns_callback, (void *)cd) == 0) {
			task->save.saved ++;
        }
	}
	return 0;
}

static int
lua_task_resolve_dns_ptr (lua_State *L)
{
	struct worker_task *task = lua_check_task (L);
	struct lua_dns_callback_data *cd;
	struct in_addr *ina;

	if (task) {
		cd = memory_pool_alloc (task->task_pool, sizeof (struct lua_dns_callback_data));
		cd->task = task;
		cd->L = L;
		cd->to_resolve = memory_pool_strdup (task->task_pool, luaL_checkstring (L, 2));
		cd->callback = memory_pool_strdup (task->task_pool, luaL_checkstring (L, 3));
		ina = memory_pool_alloc (task->task_pool, sizeof (struct in_addr));
		if (!cd->to_resolve || !cd->callback || !inet_aton (cd->to_resolve, ina)) {
			msg_info ("lua_task_resolve_dns_a: invalid parameters passed to function");
			return 0;
		}
		if (evdns_resolve_reverse (ina, DNS_QUERY_NO_SEARCH, lua_dns_callback, (void *)cd) == 0) {
			task->save.saved ++;
        }
	}
	return 0;
}


/**** Textpart implementation *****/

static int
lua_textpart_get_content (lua_State *L)
{
	struct mime_text_part *part = lua_check_textpart (L);

	if (part == NULL || part->is_empty) {
		lua_pushnil (L);
		return 1;
	}
	
	lua_pushlstring (L, part->content->data, part->content->len);

	return 1;
}

static int
lua_textpart_is_empty (lua_State *L)
{
	struct mime_text_part *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushboolean (L, part->is_empty);

	return 1;
}

static int
lua_textpart_is_html (lua_State *L)
{
	struct mime_text_part *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushboolean (L, part->is_html);

	return 1;
}

static int
lua_textpart_get_fuzzy (lua_State *L)
{
	struct mime_text_part *part = lua_check_textpart (L);

	if (part == NULL || part->is_empty) {
		lua_pushnil (L);
		return 1;
	}
	
	lua_pushlstring (L, part->fuzzy->hash_pipe, sizeof (part->fuzzy->hash_pipe));
	return 1;
}


/* Init part */
int
luaopen_task (lua_State *L)
{
	lua_newclass (L, "rspamd{task}", tasklib_m);
	luaL_openlib (L, "rspamd_task", null_reg, 0);
    
	return 1;
}

int
luaopen_textpart (lua_State *L)
{
	lua_newclass (L, "rspamd{textpart}", textpartlib_m);
	luaL_openlib (L, "rspamd_textpart", null_reg, 0);
    
	return 1;
}

