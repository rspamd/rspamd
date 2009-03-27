/*
 * Copyright (c) 2009, Rambler media
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
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

#include "config.h"
#include "url.h"
#include "main.h"
#include "lua-rspamd.h"
#include "cfg_file.h"

/* Lua module init function */
#define MODULE_INIT_FUNC "module_init"

lua_State *L = NULL;

static int lua_task_get_message (lua_State *L);
static int lua_task_insert_result (lua_State *L);
static int lua_task_get_urls (lua_State *L);

/* Task methods */
static const struct luaL_reg tasklib_m[] = {
	{"get_message", lua_task_get_message},
	{"insert_result", lua_task_insert_result},
	{"get_urls", lua_task_get_urls},
	{NULL, NULL},
};

static struct worker_task *
lua_check_task (lua_State *L) 
{
	void *ud = luaL_checkudata (L, 1, "Rspamd.task");
	luaL_argcheck (L, ud != NULL, 1, "'task' expected");
	return (struct worker_task *)ud;
}

static int
lua_task_get_message (lua_State *L)
{
	struct worker_task *task = lua_check_task (L);
	if (task != NULL) {
		/* XXX write handler for message object */
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
	struct uri *url;

	if (task != NULL) {
		TAILQ_FOREACH (url, &task->urls, next) {	
			lua_pushstring (L, struri (url));	
		}
	}
	return 1;
}

static int
luaopen_task (lua_State *L)
{
	luaL_newmetatable(L, "Rspamd.task");
    
	lua_pushstring(L, "__index");
	lua_pushvalue(L, -2);  /* pushes the metatable */
	lua_settable(L, -3);  /* metatable.__index = metatable */
    
	luaL_openlib(L, NULL, tasklib_m, 0);
    
	return 1;
}

void
init_lua_filters (struct config_file *cfg)
{
	struct perl_module *module;
	char *init_func;
	size_t funclen;

	L = lua_open ();
	luaL_openlibs (L);
	
	LIST_FOREACH (module, &cfg->perl_modules, next) {
		if (module->path) {
			luaL_loadfile (L, module->path);

			/* Call module init function */
			funclen = strlen (module->path) + sizeof ("::") + sizeof (MODULE_INIT_FUNC) - 1;
			init_func = g_malloc (funclen);
			snprintf (init_func, funclen, "%s::%s", module->path, MODULE_INIT_FUNC);
			lua_getglobal (L, init_func);
			lua_pushlightuserdata (L, cfg);
			/* do the call (1 arguments, 1 result) */
			if (lua_pcall (L, 1, 1, 0) != 0) {
				msg_info ("lua_init_filters: call to %s failed", init_func);
			}
		}
	}
	luaopen_task (L);
}


int
lua_call_header_filter (const char *function, struct worker_task *task)
{
	int result;

	lua_getglobal (L, function);
	lua_pushlightuserdata (L, task);
	
	if (lua_pcall (L, 1, 1, 0) != 0) {
		msg_info ("lua_init_filters: call to %s failed", function);
	}

	/* retrieve result */
	if (!lua_isnumber (L, -1)) {
		msg_info ("lua_call_header_filter: function %s must return a number", function);
	}
	result = lua_tonumber (L, -1);
	lua_pop (L, 1);  /* pop returned value */
	return result;
}

int
lua_call_mime_filter (const char *function, struct worker_task *task)
{
	int result;

	lua_getglobal (L, function);
	lua_pushlightuserdata (L, task);
	
	if (lua_pcall (L, 1, 1, 0) != 0) {
		msg_info ("lua_init_filters: call to %s failed", function);
	}

	/* retrieve result */
	if (!lua_isnumber (L, -1)) {
		msg_info ("lua_call_header_filter: function %s must return a number", function);
	}
	result = lua_tonumber (L, -1);
	lua_pop (L, 1);  /* pop returned value */
	return result;
}

int
lua_call_message_filter (const char *function, struct worker_task *task)
{
	int result;

	lua_getglobal (L, function);
	lua_pushlightuserdata (L, task);
	
	if (lua_pcall (L, 1, 1, 0) != 0) {
		msg_info ("lua_init_filters: call to %s failed", function);
	}

	/* retrieve result */
	if (!lua_isnumber (L, -1)) {
		msg_info ("lua_call_header_filter: function %s must return a number", function);
	}
	result = lua_tonumber (L, -1);
	lua_pop (L, 1);  /* pop returned value */
	return result;
}

int
lua_call_url_filter (const char *function, struct worker_task *task)
{
	int result;

	lua_getglobal (L, function);
	lua_pushlightuserdata (L, task);
	
	if (lua_pcall (L, 1, 1, 0) != 0) {
		msg_info ("lua_init_filters: call to %s failed", function);
	}

	/* retrieve result */
	if (!lua_isnumber (L, -1)) {
		msg_info ("lua_call_header_filter: function %s must return a number", function);
	}
	result = lua_tonumber (L, -1);
	lua_pop (L, 1);  /* pop returned value */
	return result;
}

int
lua_call_chain_filter (const char *function, struct worker_task *task, int *marks, unsigned int number)
{
	int result, i;

	lua_getglobal (L, function);

	for (i = 0; i < number; i ++) {
		lua_pushnumber (L, marks[i]);
	}
	if (lua_pcall (L, number, 1, 0) != 0) {
		msg_info ("lua_init_filters: call to %s failed", function);
	}

	/* retrieve result */
	if (!lua_isnumber (L, -1)) {
		msg_info ("lua_call_header_filter: function %s must return a number", function);
	}
	result = lua_tonumber (L, -1);
	lua_pop (L, 1);  /* pop returned value */
	return result;
}

