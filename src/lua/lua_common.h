#ifndef RSPAMD_LUA_H
#define RSPAMD_LUA_H

#include "config.h"
#ifdef WITH_LUA

#include "main.h"
#include "cfg_file.h"
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

/* Interface definitions */
#define LUA_FUNCTION_DEF(class, name) static gint lua_##class##_##name(lua_State *L)
#define LUA_INTERFACE_DEF(class, name) { #name, lua_##class##_##name }

extern const luaL_reg null_reg[];

#define RSPAMD_LUA_API_VERSION 8

/* Common utility functions */
void lua_newclass (lua_State *L, const gchar *classname, const struct luaL_reg *func);
void lua_setclass (lua_State *L, const gchar *classname, gint objidx);
void lua_set_table_index (lua_State *L, const gchar *index, const gchar *value);
gint lua_class_tostring (lua_State *L);
gint luaopen_message (lua_State *L);
gint luaopen_task (lua_State *L);
gint luaopen_config (lua_State *L);
gint luaopen_metric (lua_State *L);
gint luaopen_radix (lua_State *L);
gint luaopen_hash_table (lua_State *L);
gint luaopen_trie (lua_State * L);
gint luaopen_textpart (lua_State *L);
gint luaopen_image (lua_State *L);
gint luaopen_url (lua_State *L);
gint luaopen_classifier (lua_State *L);
gint luaopen_statfile (lua_State * L);
gint luaopen_glib_regexp (lua_State *L);
gint luaopen_cdb (lua_State *L);
gint luaopen_xmlrpc (lua_State * L);
gint luaopen_http (lua_State * L);
gint luaopen_redis (lua_State * L);
void init_lua (struct config_file *cfg);
gboolean init_lua_filters (struct config_file *cfg);

/* Filters functions */
gint lua_call_filter (const gchar *function, struct worker_task *task);
gint lua_call_chain_filter (const gchar *function, struct worker_task *task, gint *marks, guint number);
double lua_consolidation_func (struct worker_task *task, const gchar *metric_name, const gchar *function_name);
gboolean lua_call_expression_func (const gchar *module, const gchar *symbol, struct worker_task *task, GList *args, gboolean *res);
void lua_call_post_filters (struct worker_task *task);
void add_luabuf (const gchar *line);

/* Classify functions */
GList *call_classifier_pre_callbacks (struct classifier_config *ccf, struct worker_task *task, gboolean is_learn, gboolean is_spam);
double call_classifier_post_callbacks (struct classifier_config *ccf, struct worker_task *task, double in);

double lua_normalizer_func (struct config_file *cfg, long double score, void *params);

/* Config file functions */
void lua_post_load_config (struct config_file *cfg);
void lua_process_element (struct config_file *cfg, const gchar *name, struct module_opt *opt, gint idx);
gboolean lua_handle_param (struct worker_task *task, gchar *mname, gchar *optname, 
							enum lua_var_type expected_type, gpointer *res);
gboolean lua_check_condition (struct config_file *cfg, const gchar *condition);
void lua_dumpstack (lua_State *L);


#endif /* WITH_LUA */
#endif /* RSPAMD_LUA_H */
