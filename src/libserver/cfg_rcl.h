/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef CFG_RCL_H_
#define CFG_RCL_H_

#include "config.h"
#include "cfg_file.h"
#include "ucl.h"
#include "mem_pool.h"

#define CFG_RCL_ERROR cfg_rcl_error_quark ()
static inline GQuark
cfg_rcl_error_quark (void)
{
	return g_quark_from_static_string ("cfg-rcl-error-quark");
}

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_rcl_section;
struct rspamd_config;
struct rspamd_rcl_default_handler_data;

enum rspamd_rcl_flag {
	RSPAMD_CL_FLAG_TIME_FLOAT = 0x1 << 0,
	RSPAMD_CL_FLAG_TIME_TIMEVAL = 0x1 << 1,
	RSPAMD_CL_FLAG_TIME_TIMESPEC = 0x1 << 2,
	RSPAMD_CL_FLAG_TIME_INTEGER = 0x1 << 3,
	RSPAMD_CL_FLAG_TIME_UINT_32 = 0x1 << 4,
	RSPAMD_CL_FLAG_INT_16 = 0x1 << 5,
	RSPAMD_CL_FLAG_INT_32 = 0x1 << 6,
	RSPAMD_CL_FLAG_INT_64 = 0x1 << 7,
	RSPAMD_CL_FLAG_UINT = 0x1 << 8,
	RSPAMD_CL_FLAG_INT_SIZE = 0x1 << 9,
	RSPAMD_CL_FLAG_STRING_PATH = 0x1 << 10,
	RSPAMD_CL_FLAG_BOOLEAN_INVERSE = 0x1 << 11,
	RSPAMD_CL_FLAG_STRING_LIST_HASH = 0x1 << 12,
	RSPAMD_CL_FLAG_MULTIPLE = 0x1 << 13,
	RSPAMD_CL_FLAG_SIGNKEY = 0x1 << 14,
	RSPAMD_CL_FLAG_NISTKEY = 0x1 << 15,
};

struct rspamd_rcl_struct_parser {
	struct rspamd_config *cfg;
	gpointer user_struct;
	goffset offset;
	enum rspamd_rcl_flag flags;
};


/**
 * Common handler type
 * @param cfg configuration
 * @param obj object to parse
 * @param ud user data (depends on section)
 * @param err error object
 * @return TRUE if a section has been parsed
 */
typedef gboolean (*rspamd_rcl_handler_t) (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	const gchar *key,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err);

typedef gboolean (*rspamd_rcl_default_handler_t) (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err);

/**
 * A handler type that is called at the end of section parsing
 * @param cfg configuration
 * @param ud user data
 */
typedef void (*rspamd_rcl_section_fin_t)(rspamd_mempool_t *pool, gpointer ud);

/**
 * Add a default handler for a section
 * @param section section pointer
 * @param name name of param
 * @param handler handler of param
 * @param offset offset in a structure
 * @param flags flags for the parser
 * @return newly created structure
 */
struct rspamd_rcl_default_handler_data *rspamd_rcl_add_default_handler (
		struct rspamd_rcl_section *section,
		const gchar *name,
		rspamd_rcl_default_handler_t handler,
		goffset offset,
		gint flags,
		const gchar *doc_string);

/**
 * Add new section to the configuration
 * @param top top section
 * @param name the name of the section
 * @param key_attr name of the attribute that should be used as key attribute
 * @param handler handler function for all attributes
 * @param type type of object handled by a handler
 * @param required whether at least one of these sections is required
 * @param strict_type turn on strict check for types for this section
 * @return newly created structure
 */
struct rspamd_rcl_section *rspamd_rcl_add_section (
		struct rspamd_rcl_section **top,
		const gchar *name, const gchar *key_attr,
		rspamd_rcl_handler_t handler,
		enum ucl_type type, gboolean required, gboolean strict_type);

struct rspamd_rcl_section *rspamd_rcl_add_section_doc (
		struct rspamd_rcl_section **top,
		const gchar *name, const gchar *key_attr,
		rspamd_rcl_handler_t handler,
		enum ucl_type type, gboolean required,
		gboolean strict_type,
		ucl_object_t *doc_target,
		const gchar *doc_string);

/**
 * Init common sections known to rspamd
 * @return top section
 */
struct rspamd_rcl_section * rspamd_rcl_config_init (struct rspamd_config *cfg,
		GHashTable *skip_sections);

/**
 * Get a section specified by path, it understand paths separated by '/' character
 * @param top top section
 * @param path '/' divided path
 * @return
 */
struct rspamd_rcl_section * rspamd_rcl_config_get_section (
	struct rspamd_rcl_section *top,
	const char *path);

/**
 * Parse configuration
 * @param top top section
 * @param cfg rspamd configuration
 * @param ptr pointer to the target
 * @param pool pool object
 * @param obj ucl object to parse
 * @param err error pointer
 * @return
 */
gboolean rspamd_rcl_parse (struct rspamd_rcl_section *top,
		struct rspamd_config *cfg,
		gpointer ptr, rspamd_mempool_t *pool,
		const ucl_object_t *obj, GError **err);


/**
 * Parse default structure for a section
 * @param section section
 * @param cfg config file
 * @param obj object to parse
 * @param ptr ptr to pass
 * @param err error ptr
 * @return TRUE if the object has been parsed
 */
gboolean rspamd_rcl_section_parse_defaults (struct rspamd_config *cfg,
		struct rspamd_rcl_section *section,
		rspamd_mempool_t *pool, const ucl_object_t *obj, gpointer ptr,
		GError **err);
/**
 * Here is a section of common handlers that accepts rcl_struct_parser
 * which itself contains a struct pointer and the offset of a member in a
 * specific structure
 */

/**
 * Parse a string field of a structure
 * @param cfg config pointer
 * @param obj object to parse
 * @param ud struct_parser structure
 * @param section the current section
 * @param err error pointer
 * @return TRUE if a string value has been successfully parsed
 */
gboolean rspamd_rcl_parse_struct_string (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err);

/**
 * Parse an integer field of a structure
 * @param cfg config pointer
 * @param obj object to parse
 * @param ud struct_parser structure
 * @param section the current section
 * @param err error pointer
 * @return TRUE if a value has been successfully parsed
 */
gboolean rspamd_rcl_parse_struct_integer (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err);


/**
 * Parse a float field of a structure
 * @param cfg config pointer
 * @param obj object to parse
 * @param ud struct_parser structure
 * @param section the current section
 * @param err error pointer
 * @return TRUE if a value has been successfully parsed
 */
gboolean rspamd_rcl_parse_struct_double (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err);

/**
 * Parse a time field of a structure
 * @param cfg config pointer
 * @param obj object to parse
 * @param ud struct_parser structure (flags mean the exact structure used)
 * @param section the current section
 * @param err error pointer
 * @return TRUE if a value has been successfully parsed
 */
gboolean rspamd_rcl_parse_struct_time (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err);

/**
 * Parse a string list field of a structure presented by a GList* object
 * @param cfg config pointer
 * @param obj object to parse
 * @param ud struct_parser structure (flags mean the exact structure used)
 * @param section the current section
 * @param err error pointer
 * @return TRUE if a value has been successfully parsed
 */
gboolean rspamd_rcl_parse_struct_string_list (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err);

/**
 * Parse a boolean field of a structure
 * @param cfg config pointer
 * @param obj object to parse
 * @param ud struct_parser structure (flags mean the exact structure used)
 * @param section the current section
 * @param err error pointer
 * @return TRUE if a value has been successfully parsed
 */
gboolean rspamd_rcl_parse_struct_boolean (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err);

/**
 * Parse a keypair field of a structure
 * @param cfg config pointer
 * @param obj object to parse
 * @param ud struct_parser structure (flags mean the exact structure used)
 * @param section the current section
 * @param err error pointer
 * @return TRUE if a value has been successfully parsed
 */
gboolean rspamd_rcl_parse_struct_keypair (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err);

/**
 * Parse a pubkey field of a structure
 * @param cfg config pointer
 * @param obj object to parse
 * @param ud struct_parser structure (flags mean the exact structure used)
 * @param section the current section
 * @param err error pointer
 * @return TRUE if a value has been successfully parsed
 */
gboolean rspamd_rcl_parse_struct_pubkey (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err);

/**
 * Parse a inet addr field of a structure
 * @param cfg config pointer
 * @param obj object to parse
 * @param ud struct_parser structure (flags mean the exact structure used)
 * @param section the current section
 * @param err error pointer
 * @return TRUE if a value has been successfully parsed
 */
gboolean rspamd_rcl_parse_struct_addr (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err);

/**
 * Parse a gmime inet address field of a structure
 * @param cfg config pointer
 * @param obj object to parse
 * @param ud struct_parser structure (flags mean the exact structure used)
 * @param section the current section
 * @param err error pointer
 * @return TRUE if a value has been successfully parsed
 */
gboolean rspamd_rcl_parse_struct_mime_addr (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err);

/**
 * Parse a raw ucl object
 * @param cfg config pointer
 * @param obj object to parse
 * @param ud struct_parser structure (flags mean the exact structure used)
 * @param section the current section
 * @param err error pointer
 * @return TRUE if a value has been successfully parsed
 */
gboolean rspamd_rcl_parse_struct_ucl (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err);


/**
 * Utility functions
 */

/**
 * Register new parser for a worker type of an option with the specified name
 * @param cfg config structure
 * @param type type of worker (GQuark)
 * @param name name of option
 * @param handler handler of option
 * @param target opaque target structure
 * @param offset offset inside a structure
 */
void rspamd_rcl_register_worker_option (struct rspamd_config *cfg,
		GQuark type,
		const gchar *name,
		rspamd_rcl_default_handler_t handler,
		gpointer target,
		glong offset,
		gint flags,
		const gchar *doc_string);

/**
 * Register a default parser for a worker
 * @param cfg config structure
 * @param type type of worker (GQuark)
 * @param func handler function
 * @param ud userdata for handler function
 */
void rspamd_rcl_register_worker_parser (struct rspamd_config *cfg, gint type,
	gboolean (*func)(ucl_object_t *, gpointer), gpointer ud);

/**
 * Adds new documentation object to the configuration
 * @param doc_target target object where to insert documentation (top object is used if this is NULL)
 * @param doc_object documentation object to insert
 */
ucl_object_t *rspamd_rcl_add_doc_obj (ucl_object_t *doc_target,
		const char *doc_string,
		const char *doc_name,
		ucl_type_t type,
		rspamd_rcl_default_handler_t handler,
		gint flags,
		const char *default_value,
		gboolean required);

/**
 * Adds new documentation option specified by path `doc_path` that should be
 * split by dots
 */
ucl_object_t *rspamd_rcl_add_doc_by_path (struct rspamd_config *cfg,
		const gchar *doc_path,
		const char *doc_string,
		const char *doc_name,
		ucl_type_t type,
		rspamd_rcl_default_handler_t handler,
		gint flags,
		const char *default_value,
		gboolean required);


/**
 * Parses example and adds documentation according to the example:
 *
 * ```
 * section {
 *   param1 = value; # explanation
 *   param2 = value; # explanation
 * }
 * ```
 *
 * will produce the following documentation strings:
 * section ->
 *   section.param1 : explanation
 *   section.param2 : explanation
 *
 * @param cfg
 * @param root_path
 * @param example_data
 * @param example_len
 * @return
 */
ucl_object_t *rspamd_rcl_add_doc_by_example (struct rspamd_config *cfg,
		const gchar *root_path,
		const gchar *doc_string,
		const gchar *doc_name,
		const gchar *example_data, gsize example_len);

/**
 * Add lua modules path
 * @param cfg
 * @param path
 * @param err
 * @return
 */
gboolean rspamd_rcl_add_lua_plugins_path (struct rspamd_config *cfg,
		const gchar *path,
		gboolean main_path,
		GHashTable *modules_seen,
		GError **err);


/**
 * Calls for an external lua function to apply potential config transformations
 * if needed. This function can change the cfg->rcl_obj.
 *
 * Example of transformation function:
 *
 * function(obj)
 *   if obj.something == 'foo' then
 *     obj.something = "bla"
 *     return true, obj
 *   end
 *
 *   return false, nil
 * end
 *
 * If function returns 'false' then rcl_obj is not touched. Otherwise,
 * it is changed, then rcl_obj is imported from lua. Old config is dereferenced.
 * @param cfg
 */
void rspamd_rcl_maybe_apply_lua_transform (struct rspamd_config *cfg);
void rspamd_rcl_section_free (gpointer p);

void rspamd_config_calculate_cksum (struct rspamd_config *cfg);

/*
 * Read configuration file
 */
gboolean rspamd_config_parse_ucl (struct rspamd_config *cfg,
								  const gchar *filename,
								  GHashTable *vars,
								  ucl_include_trace_func_t inc_trace,
								  void *trace_data,
								  gboolean skip_jinja,
								  GError **err);
gboolean rspamd_config_read (struct rspamd_config *cfg,
							 const gchar *filename,
							 rspamd_rcl_section_fin_t logger_fin,
							 gpointer logger_ud,
							 GHashTable *vars,
							 gboolean skip_jinja,
							 gchar **lua_env);

#ifdef  __cplusplus
}
#endif

#endif /* CFG_RCL_H_ */
