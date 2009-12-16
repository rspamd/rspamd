#ifndef RSPAMD_LUA_H
#define RSPAMD_LUA_H

#include "../config.h"
#ifdef WITH_LUA

#include "../main.h"
#include "../cfg_file.h"
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

/* Interface definitions */
#define LUA_FUNCTION_DEF(class, name) static int lua_##class##_##name(lua_State *L)
#define LUA_INTERFACE_DEF(class, name) { #name, lua_##class##_##name }

extern const luaL_reg null_reg[];

void lua_newclass (lua_State *L, const char *classname, const struct luaL_reg *func);
void lua_setclass (lua_State *L, const char *classname, int objidx);
void lua_set_table_index (lua_State *L, const char *index, const char *value);
int lua_class_tostring (lua_State *L);
int luaopen_message (lua_State *L);
int luaopen_task (lua_State *L);
int luaopen_config (lua_State *L);
int luaopen_metric (lua_State *L);
int luaopen_radix (lua_State *L);
int luaopen_hash_table (lua_State *L);
int luaopen_textpart (lua_State *L);
int luaopen_classifier (lua_State *L);
int luaopen_statfile (lua_State * L);
void init_lua_filters (struct config_file *cfg);

int lua_call_filter (const char *function, struct worker_task *task);
int lua_call_chain_filter (const char *function, struct worker_task *task, int *marks, unsigned int number);
double lua_consolidation_func (struct worker_task *task, const char *metric_name, const char *function_name);
void add_luabuf (const char *line);

GList *call_classifier_pre_callbacks (struct classifier_config *ccf, struct worker_task *task);
double call_classifier_post_callbacks (struct classifier_config *ccf, struct worker_task *task, double in);

#endif /* WITH_LUA */
#endif /* RSPAMD_LUA_H */
