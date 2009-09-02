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

/* Task methods */
LUA_FUNCTION_DEF(task, get_message);
LUA_FUNCTION_DEF(task, insert_result);
LUA_FUNCTION_DEF(task, get_urls);
LUA_FUNCTION_DEF(task, get_text_parts);

static const struct luaL_reg tasklib_m[] = {
	LUA_INTERFACE_DEF(task, get_message),
	LUA_INTERFACE_DEF(task, insert_result),
	LUA_INTERFACE_DEF(task, get_urls),
	LUA_INTERFACE_DEF(task, get_text_parts),
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
	{NULL, NULL}
};

/* Utility functions */
static struct worker_task *
lua_check_task (lua_State *L) 
{
	void *ud = luaL_checkudata (L, 1, "Rspamd.task");
	luaL_argcheck (L, ud != NULL, 1, "'task' expected");
	return *((struct worker_task **)ud);
}

static struct mime_text_part *
lua_check_textpart (lua_State *L)
{
	void *ud = luaL_checkudata (L, 1, "Rspamd.textpart");
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
		lua_setclass (L, "Rspamd.message", -1);
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
	struct worker_task *task = lua_check_task (L);
	GList *cur;
	struct uri *url;

	if (task != NULL) {
		cur = g_list_first (task->urls);
		while (cur) {
			url = cur->data;
			lua_pushstring (L, struri (url));
			cur = g_list_next (cur);
		}
	}

	return 1;
}

static int
lua_task_get_text_parts (lua_State *L)
{

	struct worker_task *task = lua_check_task (L);
	GList *cur;
	struct mime_text_part *part, **ppart;

	if (task != NULL) {
		cur = task->text_parts;
		while (cur) {
			part = cur->data;
			ppart = lua_newuserdata (L, sizeof (struct mime_text_part *));
			lua_setclass (L, "Rspamd.textpart", -1);
			*ppart = part;
			cur = g_list_next (cur);
		}
	}
	lua_pushnil (L);
	return 1;
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
	lua_newclass (L, "Rspamd.task", tasklib_m);
	luaL_openlib (L, "task", tasklib_m, 0);
    
	return 1;
}

int
luaopen_textpart (lua_State *L)
{
	lua_newclass (L, "Rspamd.textpart", textpartlib_m);
	luaL_openlib (L, "textpart", textpartlib_m, 0);
    
	return 1;
}

