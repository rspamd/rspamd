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

/* Task methods */
LUA_FUNCTION_DEF(task, get_message);
LUA_FUNCTION_DEF(task, insert_result);
LUA_FUNCTION_DEF(task, get_urls);

static const struct luaL_reg tasklib_m[] = {
	LUA_INTERFACE_DEF(task, get_message),
	LUA_INTERFACE_DEF(task, insert_result),
	LUA_INTERFACE_DEF(task, get_urls),
	{NULL, NULL}
};

static struct worker_task *
lua_check_task (lua_State *L) 
{
	void *ud = luaL_checkudata (L, 1, "Rspamd.task");
	luaL_argcheck (L, ud != NULL, 1, "'task' expected");
	return (struct worker_task *)ud;
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


int
luaopen_task (lua_State *L)
{
	lua_newclass (L, "Rspamd.task", tasklib_m);
	luaL_openlib (L, "task", tasklib_m, 0);
    
	return 1;
}

