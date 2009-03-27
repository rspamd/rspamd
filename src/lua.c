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

