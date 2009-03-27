#ifndef RSPAMD_LUA_H
#define RSPAMD_LUA_H

#include "config.h"
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

struct uri;
struct worker_task;
struct config_file;

void init_lua_filters (struct config_file *cfg);

int lua_call_header_filter (const char *function, struct worker_task *task);
int lua_call_mime_filter (const char *function, struct worker_task *task);
int lua_call_message_filter (const char *function, struct worker_task *task);
int lua_call_url_filter (const char *function, struct worker_task *task);
int lua_call_chain_filter (const char *function, struct worker_task *task, int *marks, unsigned int number);

#endif
