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

#ifndef RCL_H_
#define RCL_H_

#include "config.h"
#include "uthash.h"

/**
 * @file rcl.h
 * RCL is an rspamd configuration language, which is a form of
 * JSON with less strict rules that make it more comfortable for
 * using as a configuration language
 */

enum rspamd_cl_error {
	RSPAMD_CL_EOK = 0,
	RSPAMD_CL_ESYNTAX,
	RSPAMD_CL_EIO,
	RSPAMD_CL_ESTATE,
	RSPAMD_CL_ENESTED,
	RSPAMD_CL_EMACRO,
	RSPAMD_CL_ERECURSION,
	RSPAMD_CL_EINTERNAL,
	RSPAMD_CL_ESSL
};

enum rspamd_cl_type {
	RSPAMD_CL_OBJECT = 0,
	RSPAMD_CL_ARRAY,
	RSPAMD_CL_INT,
	RSPAMD_CL_FLOAT,
	RSPAMD_CL_STRING,
	RSPAMD_CL_BOOLEAN,
	RSPAMD_CL_TIME
};

enum rspamd_cl_emitter {
	RSPAMD_CL_EMIT_JSON = 0,
	RSPAMD_CL_EMIT_JSON_COMPACT,
	RSPAMD_CL_EMIT_CONFIG
};

enum rspamd_cl_flags {
	RSPAMD_CL_FLAG_KEY_LOWERCASE = 0x1
};

typedef struct rspamd_cl_object_s {
	gchar *key;								/**< the key of an object */
	union {
		gint64 iv;							/**< int value of an object */
		gchar *sv;							/**< string value of an object */
		gdouble dv;							/**< double value of an object */
		struct rspamd_cl_object_s *ov;		/**< array or hash 			*/
	} value;
	enum rspamd_cl_type type;				/**< real type				*/
	gint ref;								/**< reference count		*/
	struct rspamd_cl_object_s *next;		/**< array handle			*/
	UT_hash_handle hh;						/**< hash handle			*/
} rspamd_cl_object_t;

/**
 * Converts an object to double value
 * @param obj CL object
 * @param target target double variable
 * @return TRUE if conversion was successful
 */
static inline gboolean
rspamd_cl_obj_todouble_safe (rspamd_cl_object_t *obj, gdouble *target)
{
	if (obj == NULL) {
		return FALSE;
	}
	switch (obj->type) {
	case RSPAMD_CL_INT:
		*target = obj->value.iv; /* Probaly could cause overflow */
		break;
	case RSPAMD_CL_FLOAT:
	case RSPAMD_CL_TIME:
		*target = obj->value.dv;
		break;
	default:
		return FALSE;
	}

	return TRUE;
}

/**
 * Unsafe version of \ref rspamd_cl_obj_todouble_safe
 * @param obj CL object
 * @return double value
 */
static inline gdouble
rspamd_cl_obj_todouble (rspamd_cl_object_t *obj)
{
	gdouble result = 0.;

	rspamd_cl_obj_todouble_safe (obj, &result);
	return result;
}

/**
 * Converts an object to integer value
 * @param obj CL object
 * @param target target integer variable
 * @return TRUE if conversion was successful
 */
static inline gboolean
rspamd_cl_obj_toint_safe (rspamd_cl_object_t *obj, gint64 *target)
{
	if (obj == NULL) {
		return FALSE;
	}
	switch (obj->type) {
	case RSPAMD_CL_INT:
		*target = obj->value.iv;
		break;
	case RSPAMD_CL_FLOAT:
	case RSPAMD_CL_TIME:
		*target = obj->value.dv; /* Loosing of decimal points */
		break;
	default:
		return FALSE;
	}

	return TRUE;
}

/**
 * Unsafe version of \ref rspamd_cl_obj_toint_safe
 * @param obj CL object
 * @return int value
 */
static inline gint64
rspamd_cl_obj_toint (rspamd_cl_object_t *obj)
{
	gint64 result = 0;

	rspamd_cl_obj_toint_safe (obj, &result);
	return result;
}

/**
 * Converts an object to boolean value
 * @param obj CL object
 * @param target target boolean variable
 * @return TRUE if conversion was successful
 */
static inline gboolean
rspamd_cl_obj_toboolean_safe (rspamd_cl_object_t *obj, gboolean *target)
{
	if (obj == NULL) {
		return FALSE;
	}
	switch (obj->type) {
	case RSPAMD_CL_BOOLEAN:
		*target = (obj->value.iv == TRUE);
		break;
	default:
		return FALSE;
	}

	return TRUE;
}

/**
 * Unsafe version of \ref rspamd_cl_obj_toboolean_safe
 * @param obj CL object
 * @return boolean value
 */
static inline gboolean
rspamd_cl_obj_toboolean (rspamd_cl_object_t *obj)
{
	gboolean result = FALSE;

	rspamd_cl_obj_toboolean_safe (obj, &result);
	return result;
}

/**
 * Converts an object to string value
 * @param obj CL object
 * @param target target string variable, no need to free value
 * @return TRUE if conversion was successful
 */
static inline gboolean
rspamd_cl_obj_tostring_safe (rspamd_cl_object_t *obj, const gchar **target)
{
	if (obj == NULL) {
		return FALSE;
	}
	switch (obj->type) {
	case RSPAMD_CL_STRING:
		*target = obj->value.sv;
		break;
	default:
		return FALSE;
	}

	return TRUE;
}

/**
 * Unsafe version of \ref rspamd_cl_obj_tostring_safe
 * @param obj CL object
 * @return string value
 */
static inline const gchar *
rspamd_cl_obj_tostring (rspamd_cl_object_t *obj)
{
	const gchar *result = NULL;

	rspamd_cl_obj_tostring_safe (obj, &result);
	return result;
}

/**
 * Return object identified by a key in the specified object
 * @param obj object to get a key from (must be of type RSPAMD_CL_OBJECT)
 * @param key key to search
 * @return object matched the specified key or NULL if key is not found
 */
static inline rspamd_cl_object_t *
rspamd_cl_obj_get_key (rspamd_cl_object_t *obj, const gchar *key)
{
	gsize keylen;
	rspamd_cl_object_t *ret;

	if (obj == NULL || obj->type != RSPAMD_CL_OBJECT || key == NULL) {
		return NULL;
	}

	keylen = strlen (key);
	HASH_FIND(hh, obj->value.ov, key, keylen, ret);

	return ret;
}

/**
 * Macro handler for a parser
 * @param data the content of macro
 * @param len the length of content
 * @param ud opaque user data
 * @param err error pointer
 * @return TRUE if macro has been parsed
 */
typedef gboolean (*rspamd_cl_macro_handler) (const guchar *data, gsize len, gpointer ud, GError **err);

/* Opaque parser */
struct rspamd_cl_parser;

/**
 * Creates new parser object
 * @param pool pool to allocate memory from
 * @return new parser object
 */
struct rspamd_cl_parser* rspamd_cl_parser_new (gint flags);

/**
 * Register new handler for a macro
 * @param parser parser object
 * @param macro macro name (without leading dot)
 * @param handler handler (it is called immediately after macro is parsed)
 * @param ud opaque user data for a handler
 */
void rspamd_cl_parser_register_macro (struct rspamd_cl_parser *parser, const gchar *macro,
		rspamd_cl_macro_handler handler, gpointer ud);

/**
 * Load new chunk to a parser
 * @param parser parser structure
 * @param data the pointer to the beginning of a chunk
 * @param len the length of a chunk
 * @param err if *err is NULL it is set to parser error
 * @return TRUE if chunk has been added and FALSE in case of error
 */
gboolean rspamd_cl_parser_add_chunk (struct rspamd_cl_parser *parser, const guchar *data,
		gsize len, GError **err);

/**
 * Load and add data from a file
 * @param parser parser structure
 * @param filename the name of file
 * @param err if *err is NULL it is set to parser error
 * @return TRUE if chunk has been added and FALSE in case of error
 */
gboolean rspamd_cl_parser_add_file (struct rspamd_cl_parser *parser, const gchar *filename,
		GError **err);

/**
 * Get a top object for a parser
 * @param parser parser structure
 * @param err if *err is NULL it is set to parser error
 * @return top parser object or NULL
 */
rspamd_cl_object_t* rspamd_cl_parser_get_object (struct rspamd_cl_parser *parser, GError **err);

/**
 * Free cl parser object
 * @param parser parser object
 */
void rspamd_cl_parser_free (struct rspamd_cl_parser *parser);

/**
 * Free cl object
 * @param obj cl object to free
 */
void rspamd_cl_obj_free (rspamd_cl_object_t *obj);

/**
 * Icrease reference count for an object
 * @param obj object to ref
 */
static inline rspamd_cl_object_t *
rspamd_cl_obj_ref (rspamd_cl_object_t *obj) {
	obj->ref ++;
	return obj;
}

/**
 * Decrease reference count for an object
 * @param obj object to unref
 */
static inline void
rspamd_cl_obj_unref (rspamd_cl_object_t *obj) {
	if (--obj->ref <= 0) {
		rspamd_cl_obj_free (obj);
	}
}

/**
 * Emit object to a string
 * @param obj object
 * @param emit_type if type is RSPAMD_CL_EMIT_JSON then emit json, if type is
 * RSPAMD_CL_EMIT_CONFIG then emit config like object
 * @return dump of an object (must be freed after using) or NULL in case of error
 */
guchar *rspamd_cl_object_emit (rspamd_cl_object_t *obj, enum rspamd_cl_emitter emit_type);

/**
 * Add new public key to parser for signatures check
 * @param parser parser object
 * @param key PEM representation of a key
 * @param len length of the key
 * @param err if *err is NULL it is set to parser error
 * @return TRUE if a key has been successfully added
 */
gboolean rspamd_cl_pubkey_add (struct rspamd_cl_parser *parser, const guchar *key, gsize len, GError **err);

#endif /* RCL_H_ */
