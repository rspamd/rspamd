#ifndef RSPAMD_LUA_H
#define RSPAMD_LUA_H

#include "config.h"
#ifdef WITH_LUA

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "rspamd.h"
#include "ucl.h"
#include "lua_ucl.h"

#ifndef lua_open
#define lua_open()  luaL_newstate ()
#endif

#ifndef luaL_reg
#define luaL_reg    luaL_Reg
#endif

#define LUA_ENUM(L, name, val) \
	lua_pushlstring (L, # name, sizeof(# name) - 1); \
	lua_pushnumber (L, val); \
	lua_settable (L, -3);

#if LUA_VERSION_NUM > 501 && !defined LUA_COMPAT_MODULE
static inline void
luaL_register (lua_State *L, const gchar *name, const struct luaL_reg *methods)
{
	if (name != NULL) {
		lua_newtable (L);
	}
	luaL_setfuncs (L, methods, 0);
	if (name != NULL) {
		lua_pushvalue (L, -1);
		lua_setglobal (L, name);
	}
}
#endif

/* Interface definitions */
#define LUA_FUNCTION_DEF(class, name) static gint lua_ ## class ## _ ## name ( \
		lua_State * L)
#define LUA_PUBLIC_FUNCTION_DEF(class, name) gint lua_ ## class ## _ ## name ( \
		lua_State * L)
#define LUA_INTERFACE_DEF(class, name) { # name, lua_ ## class ## _ ## name }

extern const luaL_reg null_reg[];

#define RSPAMD_LUA_API_VERSION 12

/* Locked lua state with mutex */
struct lua_locked_state {
	lua_State *L;
	rspamd_mutex_t *m;
};

/**
 * Lua IP address structure
 */
struct rspamd_lua_ip {
	rspamd_inet_addr_t *addr;
};

#define RSPAMD_TEXT_FLAG_OWN (1 << 0)
#define RSPAMD_TEXT_FLAG_MMAPED (1 << 1)
struct rspamd_lua_text {
	const gchar *start;
	guint len;
	guint flags;
};

struct rspamd_lua_url {
	struct rspamd_url *url;
};

struct rspamd_lua_regexp {
	rspamd_regexp_t *re;
	gchar *module;
	gchar *re_pattern;
	gsize match_limit;
	gint re_flags;
};

struct rspamd_map;
struct lua_map_callback_data;
struct radix_tree_compressed;
struct rspamd_mime_header;

enum rspamd_lua_map_type {
	RSPAMD_LUA_MAP_RADIX = 0,
	RSPAMD_LUA_MAP_SET,
	RSPAMD_LUA_MAP_HASH,
	RSPAMD_LUA_MAP_REGEXP,
	RSPAMD_LUA_MAP_REGEXP_MULTIPLE,
	RSPAMD_LUA_MAP_CALLBACK
};

struct rspamd_lua_map {
	struct rspamd_map *map;
	enum rspamd_lua_map_type type;
	guint flags;

	union {
		struct radix_tree_compressed *radix;
		GHashTable *hash;
		struct lua_map_callback_data *cbdata;
		struct rspamd_regexp_map *re_map;
	} data;
};

/* Common utility functions */

/**
 * Create and register new class
 */
void rspamd_lua_new_class (lua_State *L,
	const gchar *classname,
	const struct luaL_reg *methods);

/**
 * Create and register new class with static methods
 */
void rspamd_lua_new_class_full (lua_State *L,
	const gchar *classname,
	const gchar *static_name,
	const struct luaL_reg *methods,
	const struct luaL_reg *func);

/**
 * Set class name for object at @param objidx position
 */
void rspamd_lua_setclass (lua_State *L, const gchar *classname, gint objidx);

/**
 * Set index of table to value (like t['index'] = value)
 */
void rspamd_lua_table_set (lua_State *L, const gchar *index, const gchar *value);

/**
 * Get string value of index in a table (return t['index'])
 */
const gchar * rspamd_lua_table_get (lua_State *L, const gchar *index);

/**
 * Convert classname to string
 */
gint rspamd_lua_class_tostring (lua_State *L);

/**
 * Check whether the argument at specified index is of the specified class
 */
gpointer rspamd_lua_check_class (lua_State *L, gint index, const gchar *name);

/**
 * Initialize lua and bindings
 */
lua_State *rspamd_lua_init (void);

/**
 * Load and initialize lua plugins
 */
gboolean
rspamd_init_lua_filters (struct rspamd_config *cfg, gboolean force_load,
		GHashTable *vars);

/**
 * Initialize new locked lua_State structure
 */
struct lua_locked_state * rspamd_init_lua_locked (struct rspamd_config *cfg);
/**
 * Free locked state structure
 */
void rspamd_free_lua_locked (struct lua_locked_state *st);

/**
 * Push lua ip address
 */
void rspamd_lua_ip_push (lua_State *L, rspamd_inet_addr_t *addr);

/**
 * Push rspamd task structure to lua
 */
void rspamd_lua_task_push (lua_State *L, struct rspamd_task *task);

/**
 * Return lua ip structure at the specified address
 */
struct rspamd_lua_ip * lua_check_ip (lua_State * L, gint pos);

struct rspamd_lua_text * lua_check_text (lua_State * L, gint pos);


gint rspamd_lua_push_header (lua_State *L,
		struct rspamd_mime_header *h,
		gboolean full,
		gboolean raw);
/**
 * Push specific header to lua
 */
gint rspamd_lua_push_header_array (lua_State *L,
		GPtrArray *hdrs,
		gboolean full,
		gboolean raw);

/**
 * Check for task at the specified position
 */
struct rspamd_task *lua_check_task (lua_State * L, gint pos);
struct rspamd_task *lua_check_task_maybe (lua_State * L, gint pos);

struct rspamd_lua_map *lua_check_map (lua_State * L, gint pos);

/**
 * Push ip address from a string (nil is pushed if a string cannot be converted)
 */
void rspamd_lua_ip_push_fromstring (lua_State *L, const gchar *ip_str);

/**
 * Create type error
 */
int rspamd_lua_typerror (lua_State *L, int narg, const char *tname);
/**
 * Open libraries functions
 */

/**
 * Add preload function
 */
void rspamd_lua_add_preload (lua_State *L, const gchar *name, lua_CFunction func);

void luaopen_task (lua_State *L);
void luaopen_config (lua_State *L);
void luaopen_metric (lua_State *L);
void luaopen_map (lua_State *L);
void luaopen_trie (lua_State * L);
void luaopen_textpart (lua_State *L);
void luaopen_mimepart (lua_State *L);
void luaopen_image (lua_State *L);
void luaopen_url (lua_State *L);
void luaopen_classifier (lua_State *L);
void luaopen_statfile (lua_State * L);
void luaopen_regexp (lua_State *L);
void luaopen_cdb (lua_State *L);
void luaopen_xmlrpc (lua_State * L);
void luaopen_http (lua_State * L);
void luaopen_redis (lua_State * L);
void luaopen_upstream (lua_State * L);
void luaopen_mempool (lua_State * L);
void luaopen_dns_resolver (lua_State * L);
void luaopen_rsa (lua_State * L);
void luaopen_ip (lua_State * L);
void luaopen_expression (lua_State * L);
void luaopen_logger (lua_State * L);
void luaopen_text (lua_State *L);
void luaopen_util (lua_State * L);
void luaopen_tcp (lua_State * L);
void luaopen_html (lua_State * L);
void luaopen_fann (lua_State *L);
void luaopen_sqlite3 (lua_State *L);
void luaopen_cryptobox (lua_State *L);

void rspamd_lua_dostring (const gchar *line);

double rspamd_lua_normalize (struct rspamd_config *cfg,
	long double score,
	void *params);

/* Config file functions */
void rspamd_lua_post_load_config (struct rspamd_config *cfg);
gboolean rspamd_lua_handle_param (struct rspamd_task *task,
	gchar *mname,
	gchar *optname,
	enum lua_var_type expected_type,
	gpointer *res);
gboolean rspamd_lua_check_condition (struct rspamd_config *cfg,
	const gchar *condition);
void rspamd_lua_dumpstack (lua_State *L);

/* Set lua path according to the configuration */
void rspamd_lua_set_path (lua_State *L, struct rspamd_config *cfg,
		GHashTable *vars);

struct memory_pool_s * rspamd_lua_check_mempool (lua_State * L, gint pos);
struct rspamd_config * lua_check_config (lua_State * L, gint pos);
struct rspamd_async_session* lua_check_session (lua_State * L, gint pos);
struct event_base* lua_check_ev_base (lua_State * L, gint pos);

/**
 * Extract an arguments from lua table according to format string. Supported arguments are:
 * [*]key=S|I|N|B|V|U{a-z};[key=...]
 * - S - const char *
 * - I - gint64_t
 * - N - double
 * - B - boolean
 * - V - size_t + const char *
 * - U{classname} - userdata of the following class (stored in gpointer)
 * - F - function
 * - O - ucl_object_t *
 *
 * If any of keys is prefixed with `*` then it is treated as required argument
 * @param L lua state
 * @param pos at which pos start extraction
 * @param err error pointer
 * @param extraction_pattern static pattern
 * @return TRUE if a table has been parsed
 */
gboolean rspamd_lua_parse_table_arguments (lua_State *L, gint pos,
		GError **err, const gchar *extraction_pattern, ...);


gint rspamd_lua_traceback (lua_State *L);

/**
 * Returns size of table at position `tbl_pos`
 */
guint rspamd_lua_table_size (lua_State *L, gint tbl_pos);

void lua_push_emails_address_list (lua_State *L, GPtrArray *addrs);

/**
 * Log lua object to string
 * @param L
 * @param pos
 * @param outbuf
 * @param len
 * @return
 */
gsize lua_logger_out_type (lua_State *L, gint pos, gchar *outbuf,
		gsize len);

/**
 * Safely checks userdata to match specified class
 * @param L
 * @param pos
 * @param classname
 */
void *rspamd_lua_check_udata (lua_State *L, gint pos, const gchar *classname);

/**
 * Safely checks userdata to match specified class
 * @param L
 * @param pos
 * @param classname
 */
void *rspamd_lua_check_udata_maybe (lua_State *L, gint pos, const gchar *classname);

/**
 * Call finishing script with the specified task
 * @param L
 * @param sc
 * @param task
 */
void lua_call_finish_script (lua_State *L, struct
		rspamd_config_post_load_script *sc,
		struct rspamd_task *task);

/**
 * Run post-load operations
 * @param L
 * @param cfg
 * @param ev_base
 */
gboolean rspamd_lua_run_postloads (lua_State *L, struct rspamd_config *cfg,
		struct event_base *ev_base, struct rspamd_worker *w);

/**
 * Adds new destructor for a local function for specific pool
 * @param L
 * @param pool
 * @param ref
 */
void rspamd_lua_add_ref_dtor (lua_State *L, rspamd_mempool_t *pool,
		gint ref);

#endif /* WITH_LUA */
#endif /* RSPAMD_LUA_H */
