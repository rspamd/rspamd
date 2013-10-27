#ifndef RSPAMD_LUA_H
#define RSPAMD_LUA_H

#include "config.h"
#ifdef WITH_LUA

#include "main.h"
#include "cfg_file.h"
#include "ucl.h"
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#ifndef lua_open
#define lua_open()	luaL_newstate()
#endif

#ifndef luaL_reg
#define luaL_reg	luaL_Reg
#endif

#if LUA_VERSION_NUM > 501
static inline void
luaL_register (lua_State *L, const gchar *name, const struct luaL_reg *methods)
{
    lua_newtable (L);
    luaL_setfuncs (L, methods, 0);
    if (name != NULL) {
    	lua_pushvalue (L, -1);
    	lua_setglobal (L, name);
    }
}
#endif

/* Interface definitions */
#define LUA_FUNCTION_DEF(class, name) static gint lua_##class##_##name(lua_State *L)
#define LUA_INTERFACE_DEF(class, name) { #name, lua_##class##_##name }

extern const luaL_reg null_reg[];

#define RSPAMD_LUA_API_VERSION 12

/* Locked lua state with mutex */
struct lua_locked_state {
	lua_State *L;
	rspamd_mutex_t *m;
};

/* Common utility functions */

/**
 * Create and register new class
 */
void lua_newclass (lua_State *L, const gchar *classname, const struct luaL_reg *methods);

/**
 * Create and register new class with static methods
 */
void lua_newclass_full (lua_State *L, const gchar *classname, const gchar *static_name, const struct luaL_reg *methods, const struct luaL_reg *func);

/**
 * Set class name for object at @param objidx position
 */
void lua_setclass (lua_State *L, const gchar *classname, gint objidx);

/**
 * Set index of table to value (like t['index'] = value)
 */
void lua_set_table_index (lua_State *L, const gchar *index, const gchar *value);

/**
 * Get string value of index in a table (return t['index'])
 */
const gchar * lua_get_table_index_str (lua_State *L, const gchar *index);

/**
 * Convert classname to string
 */
gint lua_class_tostring (lua_State *L);

/**
 * Check whether the argument at specified index is of the specified class
 */
gpointer lua_check_class (lua_State *L, gint index, const gchar *name);

/**
 * Initialize lua and bindings
 */
lua_State* init_lua (struct config_file *cfg);

/**
 * Load and initialize lua plugins
 */
gboolean init_lua_filters (struct config_file *cfg);

/**
 * Initialize new locked lua_State structure
 */
struct lua_locked_state* init_lua_locked (struct config_file *cfg);
/**
 * Free locked state structure
 */
void free_lua_locked (struct lua_locked_state *st);

/**
 * Push an rcl object to lua
 * @param L lua state
 * @param obj object to push
 */
gint lua_rcl_obj_push (lua_State *L, ucl_object_t *obj, gboolean allow_array);

/**
 * Extract rcl object from lua object
 * @param L
 * @return
 */
ucl_object_t * lua_rcl_obj_get (lua_State *L, gint idx);

/**
 * Open libraries functions
 */
gint luaopen_message (lua_State *L);
gint luaopen_task (lua_State *L);
gint luaopen_config (lua_State *L);
gint luaopen_metric (lua_State *L);
gint luaopen_radix (lua_State *L);
gint luaopen_hash_table (lua_State *L);
gint luaopen_trie (lua_State * L);
gint luaopen_textpart (lua_State *L);
gint luaopen_mimepart (lua_State *L);
gint luaopen_image (lua_State *L);
gint luaopen_url (lua_State *L);
gint luaopen_classifier (lua_State *L);
gint luaopen_statfile (lua_State * L);
gint luaopen_glib_regexp (lua_State *L);
gint luaopen_cdb (lua_State *L);
gint luaopen_xmlrpc (lua_State * L);
gint luaopen_http (lua_State * L);
gint luaopen_redis (lua_State * L);
gint luaopen_upstream (lua_State * L);
gint luaopen_mempool (lua_State * L);
gint luaopen_session (lua_State * L);
gint luaopen_io_dispatcher (lua_State * L);
gint luaopen_dns_resolver (lua_State * L);
gint luaopen_rsa (lua_State * L);

gint lua_call_filter (const gchar *function, struct worker_task *task);
gint lua_call_chain_filter (const gchar *function, struct worker_task *task, gint *marks, guint number);
double lua_consolidation_func (struct worker_task *task, const gchar *metric_name, const gchar *function_name);
gboolean lua_call_expression_func (gpointer lua_data, struct worker_task *task, GList *args, gboolean *res);
void lua_call_post_filters (struct worker_task *task);
void lua_call_pre_filters (struct worker_task *task);
void add_luabuf (const gchar *line);

/* Classify functions */
GList *call_classifier_pre_callbacks (struct classifier_config *ccf, struct worker_task *task, gboolean is_learn, gboolean is_spam, lua_State *L);
double call_classifier_post_callbacks (struct classifier_config *ccf, struct worker_task *task, double in, lua_State *L);

double lua_normalizer_func (struct config_file *cfg, long double score, void *params);

/* Config file functions */
void lua_post_load_config (struct config_file *cfg);
void lua_process_element (struct config_file *cfg, const gchar *name,
		const gchar *module_name, struct module_opt *opt, gint idx, gboolean allow_meta);
gboolean lua_handle_param (struct worker_task *task, gchar *mname, gchar *optname, 
							enum lua_var_type expected_type, gpointer *res);
gboolean lua_check_condition (struct config_file *cfg, const gchar *condition);
void lua_dumpstack (lua_State *L);

struct memory_pool_s *lua_check_mempool (lua_State * L);


#endif /* WITH_LUA */
#endif /* RSPAMD_LUA_H */
