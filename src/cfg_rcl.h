/* Copyright (c) 2013, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef CFG_RCL_H_
#define CFG_RCL_H_

#include "config.h"
#include "ucl/include/ucl.h"
#include "uthash.h"

#define CFG_RCL_ERROR cfg_rcl_error_quark ()
static inline GQuark
cfg_rcl_error_quark (void)
{
	return g_quark_from_static_string ("cfg-rcl-error-quark");
}

struct rspamd_rcl_section;
struct config_file;

struct rspamd_rcl_struct_parser {
	gpointer user_struct;
	goffset offset;
	enum {
		RSPAMD_CL_FLAG_TIME_FLOAT = 0x1 << 0,
		RSPAMD_CL_FLAG_TIME_TIMEVAL = 0x1 << 1,
		RSPAMD_CL_FLAG_TIME_TIMESPEC = 0x1 << 2,
		RSPAMD_CL_FLAG_TIME_INTEGER = 0x1 << 3,
		RSPAMD_CL_FLAG_TIME_UINT_32 = 0x1 << 4,
		RSPAMD_CL_FLAG_INT_16 = 0x1 << 5,
		RSPAMD_CL_FLAG_INT_32 = 0x1 << 6,
		RSPAMD_CL_FLAG_INT_64 = 0x1 << 7,
		RSPAMD_CL_FLAG_INT_SIZE = 0x1 << 8,
		RSPAMD_CL_FLAG_STRING_PATH = 0x1 << 9
	} flags;
};

/**
 * Common handler type
 * @param cfg configuration
 * @param obj object to parse
 * @param ud user data (depends on section)
 * @param err error object
 * @return TRUE if a section has been parsed
 */
typedef gboolean (*rspamd_rcl_handler_t) (struct config_file *cfg, ucl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err);

/**
 * A handler type that is called at the end of section parsing
 * @param cfg configuration
 * @param ud user data
 */
typedef void (*rspamd_rcl_section_fin_t)(struct config_file *cfg, gpointer ud);

struct rspamd_rcl_default_handler_data {
	struct rspamd_rcl_struct_parser pd;
	const gchar *key;
	rspamd_rcl_handler_t handler;
	UT_hash_handle hh;
};

struct rspamd_rcl_section {
	const gchar *name;					/**< name of section */
	rspamd_rcl_handler_t handler;		/**< handler of section attributes */
	enum ucl_type type;			/**< type of attribute */
	gboolean required;					/**< whether this param is required */
	gboolean strict_type;				/**< whether we need strict type */
	UT_hash_handle hh;					/** hash handle */
	struct rspamd_rcl_section *subsections; /**< hash table of subsections */
	struct rspamd_rcl_default_handler_data *default_parser; /**< generic parsing fields */
	rspamd_rcl_section_fin_t fin; /** called at the end of section parsing */
	gpointer fin_ud;
};

/**
 * Init common sections known to rspamd
 * @return top section
 */
struct rspamd_rcl_section* rspamd_rcl_config_init (void);

/**
 * Get a section specified by path, it understand paths separated by '/' character
 * @param top top section
 * @param path '/' divided path
 * @return
 */
struct rspamd_rcl_section *rspamd_rcl_config_get_section (struct rspamd_rcl_section *top,
		const char *path);

/**
 * Read RCL configuration and parse it to a config file
 * @param top top section
 * @param cfg target configuration
 * @param obj object to handle
 * @return TRUE if an object can be parsed
 */
gboolean rspamd_read_rcl_config (struct rspamd_rcl_section *top,
		struct config_file *cfg, ucl_object_t *obj, GError **err);


/**
 * Parse default structure for a section
 * @param section section
 * @param cfg config file
 * @param obj object to parse
 * @param ptr ptr to pass
 * @param err error ptr
 * @return TRUE if the object has been parsed
 */
gboolean rspamd_rcl_section_parse_defaults (struct rspamd_rcl_section *section,
		struct config_file *cfg, ucl_object_t *obj, gpointer ptr,
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
gboolean rspamd_rcl_parse_struct_string (struct config_file *cfg, ucl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err);

/**
 * Parse an integer field of a structure
 * @param cfg config pointer
 * @param obj object to parse
 * @param ud struct_parser structure
 * @param section the current section
 * @param err error pointer
 * @return TRUE if a value has been successfully parsed
 */
gboolean rspamd_rcl_parse_struct_integer (struct config_file *cfg, ucl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err);


/**
 * Parse a float field of a structure
 * @param cfg config pointer
 * @param obj object to parse
 * @param ud struct_parser structure
 * @param section the current section
 * @param err error pointer
 * @return TRUE if a value has been successfully parsed
 */
gboolean rspamd_rcl_parse_struct_double (struct config_file *cfg, ucl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err);

/**
 * Parse a time field of a structure
 * @param cfg config pointer
 * @param obj object to parse
 * @param ud struct_parser structure (flags mean the exact structure used)
 * @param section the current section
 * @param err error pointer
 * @return TRUE if a value has been successfully parsed
 */
gboolean rspamd_rcl_parse_struct_time (struct config_file *cfg, ucl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err);

/**
 * Parse a string list field of a structure presented by a GList* object
 * @param cfg config pointer
 * @param obj object to parse
 * @param ud struct_parser structure (flags mean the exact structure used)
 * @param section the current section
 * @param err error pointer
 * @return TRUE if a value has been successfully parsed
 */
gboolean rspamd_rcl_parse_struct_string_list (struct config_file *cfg, ucl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err);

/**
 * Parse a boolean field of a structure
 * @param cfg config pointer
 * @param obj object to parse
 * @param ud struct_parser structure (flags mean the exact structure used)
 * @param section the current section
 * @param err error pointer
 * @return TRUE if a value has been successfully parsed
 */
gboolean rspamd_rcl_parse_struct_boolean (struct config_file *cfg, ucl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err);

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
void rspamd_rcl_register_worker_option (struct config_file *cfg, gint type, const gchar *name,
		rspamd_rcl_handler_t handler, gpointer target, gsize offset, gint flags);

/**
 * Regiester a default parser for a worker
 * @param cfg config structure
 * @param type type of worker (GQuark)
 * @param func handler function
 * @param ud userdata for handler function
 */
void rspamd_rcl_register_worker_parser (struct config_file *cfg, gint type,
		gboolean (*func)(ucl_object_t *, gpointer), gpointer ud);
#endif /* CFG_RCL_H_ */
