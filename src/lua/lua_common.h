/*
 * Copyright 2025 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RSPAMD_LUA_H
#define RSPAMD_LUA_H

#include "config.h"


/* Lua headers do not have __cplusplus guards... */
#ifdef __cplusplus
extern "C" {
#endif

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#ifdef WITH_LUAJIT
#include <luajit.h>
#endif

#ifdef __cplusplus
}
#endif
#include <stdbool.h>


#include "rspamd.h"
#include "ucl.h"
#include "lua_ucl.h"
#include "lua_classnames.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef lua_open
#define lua_open() luaL_newstate()
#endif

#ifndef luaL_reg
#define luaL_reg luaL_Reg
#endif

#define LUA_ENUM(L, name, val)                    \
	lua_pushlstring(L, #name, sizeof(#name) - 1); \
	lua_pushinteger(L, val);                      \
	lua_settable(L, -3);

#if LUA_VERSION_NUM > 501 && !defined LUA_COMPAT_MODULE
static inline void
luaL_register(lua_State *L, const char *name, const struct luaL_reg *methods)
{
	if (name != NULL) {
		lua_newtable(L);
	}
	luaL_setfuncs(L, methods, 0);
	if (name != NULL) {
		lua_pushvalue(L, -1);
		lua_setglobal(L, name);
	}
}
#endif

#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM == 501

/* Special hack to work with moonjit of specific version */
#if !defined(MOONJIT_VERSION) && (!defined(LUAJIT_VERSION_NUM) || LUAJIT_VERSION_NUM != 20200)
static inline int lua_absindex(lua_State *L, int i)
{
	if (i < 0 && i > LUA_REGISTRYINDEX)
		i += lua_gettop(L) + 1;
	return i;
}
#endif

#endif

/* Interface definitions */
#define LUA_FUNCTION_DEF(class, name) static int lua_##class##_##name(lua_State *L)
#define LUA_PUBLIC_FUNCTION_DEF(class, name) int lua_##class##_##name(lua_State *L)
#define LUA_INTERFACE_DEF(class, name) \
	{                                  \
		#name, lua_##class##_##name}

extern const luaL_reg null_reg[];

#define RSPAMD_LUA_CFG_STATE(cfg) ((lua_State *) ((cfg)->lua_state))
/**
* Lua IP address structure
*/
struct rspamd_lua_ip {
	rspamd_inet_addr_t *addr;
};

#define RSPAMD_TEXT_FLAG_OWN (1u << 0u)
#define RSPAMD_TEXT_FLAG_MMAPED (1u << 1u)
#define RSPAMD_TEXT_FLAG_WIPE (1u << 2u)
#define RSPAMD_TEXT_FLAG_SYSMALLOC (1u << 3u)
#define RSPAMD_TEXT_FLAG_FAKE (1u << 4u)
#define RSPAMD_TEXT_FLAG_BINARY (1u << 5u)
struct rspamd_lua_text {
	const char *start;
	unsigned int len;
	unsigned int flags;
};

struct rspamd_lua_url {
	struct rspamd_url *url;
};

struct rspamd_lua_regexp {
	rspamd_regexp_t *re;
	char *module;
	char *re_pattern;
	int re_flags;
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
	RSPAMD_LUA_MAP_CALLBACK,
	RSPAMD_LUA_MAP_CDB,
	RSPAMD_LUA_MAP_UNKNOWN,
};

struct rspamd_lua_map {
	struct rspamd_map *map;
	enum rspamd_lua_map_type type;
	unsigned int flags;

	union {
		struct rspamd_radix_map_helper *radix;
		struct rspamd_hash_map_helper *hash;
		struct rspamd_regexp_map_helper *re_map;
		struct rspamd_cdb_map_helper *cdb_map;
		struct lua_map_callback_data *cbdata;
	} data;
};

struct rspamd_lua_upstream {
	struct upstream *up;
	int upref;
};

/* Common utility functions */

/**
* Create and register new class
*/
void rspamd_lua_new_class(lua_State *L,
						  const char *classname,
						  const struct luaL_reg *methods);

/**
* Set class name for object at @param objidx position
* @param L
 * @param classname **MUST BE STATIC**, direct address is used for comparisons!
*/
void rspamd_lua_setclass(lua_State *L, const char *classname, int objidx);

/**
* Pushes the metatable for specific class on top of the stack
* @param L
* @param classname
*/
void rspamd_lua_class_metatable(lua_State *L, const char *classname);

/**
* Adds a new field to the class (metatable) identified by `classname`
* @param L
* @param classname
* @param meth
*/
void rspamd_lua_add_metamethod(lua_State *L, const char *classname,
							   luaL_Reg *meth);

/**
* Set index of table to value (like t['index'] = value)
*/
void rspamd_lua_table_set(lua_State *L, const char *index, const char *value);

/**
* Get string value of index in a table (return t['index'])
*/
const char *rspamd_lua_table_get(lua_State *L, const char *index);

/**
* Convert classname to string
*/
int rspamd_lua_class_tostring(lua_State *L);

/**
* Check whether the argument at specified index is of the specified class
*/
gpointer rspamd_lua_check_class(lua_State *L, int index, const char *name);

/**
* Initialize lua and bindings
*/
lua_State *rspamd_lua_init(bool wipe_mem);

/**
 * Close lua_state and free remainders
 * @param L
 */
void rspamd_lua_close(lua_State *L);

void rspamd_lua_start_gc(struct rspamd_config *cfg);

/**
* Sets field in a global variable
* @param L
* @param global_name
* @param field_name
* @param new_elt
*/
void rspamd_plugins_table_push_elt(lua_State *L, const char *field_name,
								   const char *new_elt);

/**
* Load and initialize lua plugins
*/
gboolean
rspamd_init_lua_filters(struct rspamd_config *cfg, bool force_load, bool strict);


/**
* Push lua ip address
*/
void rspamd_lua_ip_push(lua_State *L, rspamd_inet_addr_t *addr);

/**
* Push rspamd task structure to lua
*/
void rspamd_lua_task_push(lua_State *L, struct rspamd_task *task);

/**
* Return lua ip structure at the specified address
*/
struct rspamd_lua_ip *lua_check_ip(lua_State *L, int pos);

struct rspamd_lua_text *lua_check_text(lua_State *L, int pos);
/**
* Checks for a text or a string. In case of string a pointer to static structure is returned.
* So it should not be reused or placed to Lua stack anyhow!
* However, you can use this function up to 4 times and have distinct static structures
* @param L
* @param pos
* @return
*/
struct rspamd_lua_text *lua_check_text_or_string(lua_State *L, int pos);
/**
 * Create new text object
 * @param L
 * @param start
 * @param len
 * @param own
 * @return
 */
struct rspamd_lua_text *lua_new_text(lua_State *L, const char *start,
									 gsize len, gboolean allocate_memory);
/**
 * Create new text object from task pool if allocation is needed
 * @param task
 * @param L
 * @param start
 * @param len
 * @param own
 * @return
 */
struct rspamd_lua_text *lua_new_text_task(lua_State *L, struct rspamd_task *task,
										  const char *start, gsize len, gboolean own);
/**
 * Checks if a text has binary characters (non ascii and non-utf8 characters)
 * @param t
 * @return
 */
bool lua_is_text_binary(struct rspamd_lua_text *t);

struct rspamd_lua_regexp *lua_check_regexp(lua_State *L, int pos);

struct rspamd_lua_upstream *lua_check_upstream(lua_State *L, int pos);

enum rspamd_lua_task_header_type {
	RSPAMD_TASK_HEADER_PUSH_SIMPLE = 0,
	RSPAMD_TASK_HEADER_PUSH_RAW,
	RSPAMD_TASK_HEADER_PUSH_FULL,
	RSPAMD_TASK_HEADER_PUSH_COUNT,
	RSPAMD_TASK_HEADER_PUSH_HAS,
};

int rspamd_lua_push_header(lua_State *L,
						   struct rspamd_mime_header *h,
						   enum rspamd_lua_task_header_type how);

/**
* Push specific header to lua
*/
int rspamd_lua_push_header_array(lua_State *L,
								 const char *name,
								 struct rspamd_mime_header *rh,
								 enum rspamd_lua_task_header_type how,
								 gboolean strong);

/**
* Check for task at the specified position
*/
struct rspamd_task *lua_check_task(lua_State *L, int pos);

struct rspamd_task *lua_check_task_maybe(lua_State *L, int pos);

struct rspamd_lua_map *lua_check_map(lua_State *L, int pos);

/**
* Push ip address from a string (nil is pushed if a string cannot be converted)
*/
void rspamd_lua_ip_push_fromstring(lua_State *L, const char *ip_str);

/**
* Create type error
*/
int rspamd_lua_typerror(lua_State *L, int narg, const char *tname);
/**
* Open libraries functions
*/

/**
* Add preload function
*/
void rspamd_lua_add_preload(lua_State *L, const char *name, lua_CFunction func);

void luaopen_task(lua_State *L);

void luaopen_config(lua_State *L);

void luaopen_map(lua_State *L);

void luaopen_trie(lua_State *L);

void luaopen_textpart(lua_State *L);

void luaopen_mimepart(lua_State *L);

void luaopen_image(lua_State *L);

void luaopen_url(lua_State *L);

void luaopen_classifier(lua_State *L);

void luaopen_statfile(lua_State *L);

void luaopen_regexp(lua_State *L);

void luaopen_cdb(lua_State *L);

void luaopen_xmlrpc(lua_State *L);

void luaopen_http(lua_State *L);

void luaopen_redis(lua_State *L);

void luaopen_upstream(lua_State *L);

void luaopen_mempool(lua_State *L);

void luaopen_dns_resolver(lua_State *L);

void luaopen_rsa(lua_State *L);

void luaopen_ip(lua_State *L);

void luaopen_expression(lua_State *L);

void luaopen_logger(lua_State *L);

void luaopen_text(lua_State *L);

void luaopen_util(lua_State *L);

void luaopen_tcp(lua_State *L);

void luaopen_html(lua_State *L);

void luaopen_sqlite3(lua_State *L);

void luaopen_cryptobox(lua_State *L);

void luaopen_dns(lua_State *L);

void luaopen_udp(lua_State *L);

void luaopen_worker(lua_State *L);

void luaopen_kann(lua_State *L);

void luaopen_spf(lua_State *L);

void luaopen_tensor(lua_State *L);

void luaopen_parsers(lua_State *L);

void luaopen_shingle(lua_State *L);

void rspamd_lua_dostring(const char *line);

double rspamd_lua_normalize(struct rspamd_config *cfg,
							long double score,
							void *params);

/* Config file functions */
void rspamd_lua_post_load_config(struct rspamd_config *cfg);

void rspamd_lua_dumpstack(lua_State *L);

/* Set lua path according to the configuration */
void rspamd_lua_set_path(lua_State *L, const ucl_object_t *cfg_obj,
						 GHashTable *vars);

/* Set some lua globals */
gboolean rspamd_lua_set_env(lua_State *L, GHashTable *vars, char **lua_env,
							GError **err);

void rspamd_lua_set_globals(struct rspamd_config *cfg, lua_State *L);

struct memory_pool_s *rspamd_lua_check_mempool(lua_State *L, int pos);

struct rspamd_config *lua_check_config(lua_State *L, int pos);

struct rspamd_async_session *lua_check_session(lua_State *L, int pos);

struct ev_loop *lua_check_ev_base(lua_State *L, int pos);

struct rspamd_dns_resolver *lua_check_dns_resolver(lua_State *L, int pos);

struct rspamd_lua_url *lua_check_url(lua_State *L, int pos);

/**
 * Creates a new shingle object from the existing shingle
 */
struct rspamd_shingle;
void lua_newshingle(lua_State *L, const void *sh);

enum rspamd_lua_parse_arguments_flags {
	RSPAMD_LUA_PARSE_ARGUMENTS_DEFAULT = 0,
	RSPAMD_LUA_PARSE_ARGUMENTS_IGNORE_MISSING,
};

/**
* Extract an arguments from lua table according to format string. Supported arguments are:
* [*]key=S|I|N|B|V|U{a-z};[key=...]
* - S - const char *
* - I - int64_t_t
* - i - int32_t
* - N - double
* - B - gboolean
* - V - size_t + const char *
* - U{classname} - userdata of the following class (stored in gpointer)
* - F - function
* - O - ucl_object_t *
* - D - same as N but argument is set to NAN not to 0.0
* - u{classname} - userdata of the following class (stored directly)
*
* If any of keys is prefixed with `*` then it is treated as required argument
* @param L lua state
* @param pos at which pos start extraction
* @param err error pointer
* @param how extraction type (IGNORE_MISSING means that default values will not be set)
* @param extraction_pattern static pattern
* @return TRUE if a table has been parsed
*/
gboolean rspamd_lua_parse_table_arguments(lua_State *L, int pos,
										  GError **err,
										  enum rspamd_lua_parse_arguments_flags how,
										  const char *extraction_pattern, ...);


int rspamd_lua_traceback(lua_State *L);

/**
* Returns stack trace as a string. Caller should clear memory.
* @param L
* @return
*/
void rspamd_lua_get_traceback_string(lua_State *L, luaL_Buffer *buf);

/**
* Returns size of table at position `tbl_pos`
*/
unsigned int rspamd_lua_table_size(lua_State *L, int tbl_pos);

void lua_push_emails_address_list(lua_State *L, GPtrArray *addrs, int flags);


#define TRACE_POINTS 6

struct lua_logger_trace {
	int cur_level;
	gconstpointer traces[TRACE_POINTS];
};

enum lua_logger_escape_type {
	LUA_ESCAPE_NONE = (0u),
	LUA_ESCAPE_UNPRINTABLE = (1u << 0u),
	LUA_ESCAPE_NEWLINES = (1u << 1u),
	LUA_ESCAPE_8BIT = (1u << 2u),
};

#define LUA_ESCAPE_LOG (LUA_ESCAPE_UNPRINTABLE | LUA_ESCAPE_NEWLINES)
#define LUA_ESCAPE_ALL (LUA_ESCAPE_UNPRINTABLE | LUA_ESCAPE_NEWLINES | LUA_ESCAPE_8BIT)

/**
* Log lua object to string
* @param L
* @param pos
* @param outbuf
* @param len
* @param trace
* @return
*/
gsize lua_logger_out_type(lua_State *L, int pos, char *outbuf,
						  gsize len, struct lua_logger_trace *trace,
						  enum lua_logger_escape_type esc_type);

/**
* Log lua object to string
* @param L
* @param pos
* @param outbuf
* @param len
* @return
*/
gsize lua_logger_out(lua_State *L, int pos, char *outbuf, gsize len,
						  enum lua_logger_escape_type esc_type);

/**
* Safely checks userdata to match specified class
* @param L
* @param pos
* @param classname **MUST BE STATIC**, direct address is used for comparisons!
*/
void *rspamd_lua_check_udata(lua_State *L, int pos, const char *classname);

#define RSPAMD_LUA_CHECK_UDATA_PTR_OR_RETURN(L, pos, classname, type, dest)                                        \
	do {                                                                                                           \
		type **_maybe_ptr = (type **) rspamd_lua_check_udata((L), (pos), (classname));                             \
		if (_maybe_ptr == NULL) {                                                                                  \
			return luaL_error(L, "%s: invalid arguments; pos = %d; expected = %s", G_STRFUNC, (pos), (classname)); \
		}                                                                                                          \
		(dest) = *(_maybe_ptr);                                                                                    \
	} while (0)

/**
* Safely checks userdata to match specified class
* @param L
* @param pos
* @param classname **MUST BE STATIC**, direct address is used for comparisons!
*/
void *rspamd_lua_check_udata_maybe(lua_State *L, int pos, const char *classname);

/**
* Call finishing script with the specified task
* @param sc
* @param task
*/
void lua_call_finish_script(struct rspamd_config_cfg_lua_script *sc,
							struct rspamd_task *task);

/**
* Run post-load operations
* @param L
* @param cfg
* @param ev_base
*/
void rspamd_lua_run_postloads(lua_State *L, struct rspamd_config *cfg,
							  struct ev_loop *ev_base, struct rspamd_worker *w);

void rspamd_lua_run_config_post_init(lua_State *L, struct rspamd_config *cfg);

void rspamd_lua_run_config_unload(lua_State *L, struct rspamd_config *cfg);

/**
* Adds new destructor for a local function for specific pool
* @param L
* @param pool
* @param ref
*/
void rspamd_lua_add_ref_dtor(lua_State *L, rspamd_mempool_t *pool,
							 int ref);

/**
 * Returns a lua reference from a function like string, e.g. `return function(...) end`
 * @param L
 * @param str
 * @return
 */
int rspamd_lua_function_ref_from_str(lua_State *L, const char *str, gsize slen,
									 const char *modname, GError **err);

/**
* Tries to load some module using `require` and get some method from it
* @param L
* @param modname
* @param funcname
* @return TRUE if function exists in that module, the function is pushed in stack, otherwise stack is unchanged and FALSE is returned
*/
gboolean rspamd_lua_require_function(lua_State *L, const char *modname,
									 const char *funcname);

/**
* Tries to load redis server definition from ucl object specified
* @param L
* @param obj
* @param cfg
* @return
*/
gboolean rspamd_lua_try_load_redis(lua_State *L, const ucl_object_t *obj,
								   struct rspamd_config *cfg, int *ref_id);

struct rspamd_stat_token_s;

/**
* Pushes a single word into Lua
* @param L
* @param word
*/
void rspamd_lua_push_full_word(lua_State *L, struct rspamd_stat_token_s *word);

enum rspamd_lua_words_type {
	RSPAMD_LUA_WORDS_STEM = 0,
	RSPAMD_LUA_WORDS_NORM,
	RSPAMD_LUA_WORDS_RAW,
	RSPAMD_LUA_WORDS_FULL,
	RSPAMD_LUA_WORDS_MAX
};

/**
* Pushes words (rspamd_stat_token_t) to Lua
* @param L
* @param words
* @param how
*/
int rspamd_lua_push_words(lua_State *L, GArray *words,
						  enum rspamd_lua_words_type how);

/**
* Returns newly allocated name for caller module name
* @param L
* @return
*/
char *rspamd_lua_get_module_name(lua_State *L);

/**
* Call Lua function in a universal way. Arguments string:
* - i - lua_integer, argument - int64_t
* - n - lua_number, argument - double
* - s - lua_string, argument - const char * (zero terminated)
* - l - lua_lstring, argument - (size_t + const char *) pair
* - u - lua_userdata, argument - (const char * + void *) - classname + pointer
* - b - lua_boolean, argument - gboolean (not bool due to varargs promotion)
* - f - lua_function, argument - int - position of the function on stack (not lua_registry)
* - t - lua_text, argument - int - position of the lua_text on stack (not lua_registry)
* @param L lua state
* @param cbref LUA_REGISTRY reference (if it is -1 then a function on top of the stack is called - it must be removed by caller manually)
* @param strloc where this function is called from
* @param nret number of results (or LUA_MULTRET)
* @param args arguments format string
* @param err error to promote
* @param ... arguments
* @return true of pcall returned 0, false + err otherwise
*/
bool rspamd_lua_universal_pcall(lua_State *L, int cbref, const char *strloc,
								int nret, const char *args, GError **err, ...);

/**
 * Returns true if lua is initialised
 * @return
 */
bool rspamd_lua_is_initialised(void);

/**
* Wrapper for lua_geti from lua 5.3
* @param L
* @param index
* @param i
* @return
*/
#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM <= 502
int rspamd_lua_geti(lua_State *L, int index, int i);
#else
#define rspamd_lua_geti lua_geti
#endif

/* Paths defs */
#define RSPAMD_CONFDIR_INDEX "CONFDIR"
#define RSPAMD_LOCAL_CONFDIR_INDEX "LOCAL_CONFDIR"
#define RSPAMD_RUNDIR_INDEX "RUNDIR"
#define RSPAMD_DBDIR_INDEX "DBDIR"
#define RSPAMD_LOGDIR_INDEX "LOGDIR"
#define RSPAMD_PLUGINSDIR_INDEX "PLUGINSDIR"
#define RSPAMD_SHAREDIR_INDEX "SHAREDIR"
#define RSPAMD_RULESDIR_INDEX "RULESDIR"
#define RSPAMD_LUALIBDIR_INDEX "LUALIBDIR"
#define RSPAMD_WWWDIR_INDEX "WWWDIR"
#define RSPAMD_PREFIX_INDEX "PREFIX"
#define RSPAMD_VERSION_INDEX "VERSION"

#ifdef WITH_LUA_TRACE
extern ucl_object_t *lua_traces;
#define LUA_TRACE_POINT                                                            \
	do {                                                                           \
		ucl_object_t *func_obj;                                                    \
		if (lua_traces == NULL) { lua_traces = ucl_object_typed_new(UCL_OBJECT); } \
		func_obj = (ucl_object_t *) ucl_object_lookup(lua_traces, G_STRFUNC);      \
		if (func_obj == NULL) {                                                    \
			func_obj = ucl_object_typed_new(UCL_INT);                              \
			ucl_object_insert_key(lua_traces, func_obj, G_STRFUNC, 0, false);      \
		}                                                                          \
		func_obj->value.iv++;                                                      \
	} while (0)
#else
#define LUA_TRACE_POINT \
	do {                \
	} while (0)
#endif

#ifdef __cplusplus
}
#endif

#endif /* RSPAMD_LUA_H */
