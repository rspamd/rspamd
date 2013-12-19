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

#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include "config.h"

/**
 * @file rcl.h
 * RCL is an rspamd configuration language, which is a form of
 * JSON with less strict rules that make it more comfortable for
 * using as a configuration language
 */

/**
 * XXX: Poorly named API functions, need to replace them with the appropriate
 * named function. All API functions *must* use naming ucl_object_*. Usage of
 * ucl_obj* should be avoided.
 */
#define ucl_object_todouble_safe ucl_obj_todouble_safe
#define ucl_object_todouble ucl_obj_todouble
#define ucl_object_tostring ucl_obj_tostring
#define ucl_object_tostring_safe ucl_obj_tostring_safe
#define ucl_object_tolstring ucl_obj_tolstring
#define ucl_object_tolstring_safe ucl_obj_tolstring_safe
#define ucl_object_toint ucl_obj_toint
#define ucl_object_toint_safe ucl_obj_toint_safe
#define ucl_object_toboolean ucl_obj_toboolean
#define ucl_object_toboolean_safe ucl_obj_toboolean_safe
#define ucl_object_find_key ucl_obj_get_key
#define ucl_object_find_keyl ucl_obj_get_keyl
#define ucl_object_unref ucl_obj_unref
#define ucl_object_ref ucl_obj_ref
#define ucl_object_free ucl_obj_free

/**
 * Memory allocation utilities
 * UCL_ALLOC(size) - allocate memory for UCL
 * UCL_FREE(size, ptr) - free memory of specified size at ptr
 * Default: malloc and free
 */
#ifndef UCL_ALLOC
#define UCL_ALLOC(size) malloc(size)
#endif
#ifndef UCL_FREE
#define UCL_FREE(size, ptr) free(ptr)
#endif

#if    __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
#define UCL_WARN_UNUSED_RESULT               \
  __attribute__((warn_unused_result))
#else
#define UCL_WARN_UNUSED_RESULT
#endif

enum ucl_error {
	UCL_EOK = 0,   //!< UCL_EOK
	UCL_ESYNTAX,   //!< UCL_ESYNTAX
	UCL_EIO,       //!< UCL_EIO
	UCL_ESTATE,    //!< UCL_ESTATE
	UCL_ENESTED,   //!< UCL_ENESTED
	UCL_EMACRO,    //!< UCL_EMACRO
	UCL_ERECURSION,//!< UCL_ERECURSION
	UCL_EINTERNAL, //!< UCL_EINTERNAL
	UCL_ESSL       //!< UCL_ESSL
};

/**
 * Object types
 */
enum ucl_type {
	UCL_OBJECT = 0,//!< UCL_OBJECT
	UCL_ARRAY,     //!< UCL_ARRAY
	UCL_INT,       //!< UCL_INT
	UCL_FLOAT,     //!< UCL_FLOAT
	UCL_STRING,    //!< UCL_STRING
	UCL_BOOLEAN,   //!< UCL_BOOLEAN
	UCL_TIME,      //!< UCL_TIME
	UCL_USERDATA,  //!< UCL_USERDATA
	UCL_NULL       //!< UCL_NULL
};

/**
 * Emitting types
 */
enum ucl_emitter {
	UCL_EMIT_JSON = 0,    //!< UCL_EMIT_JSON
	UCL_EMIT_JSON_COMPACT,//!< UCL_EMIT_JSON_COMPACT
	UCL_EMIT_CONFIG,      //!< UCL_EMIT_CONFIG
	UCL_EMIT_YAML         //!< UCL_EMIT_YAML
};

/**
 * Parsing flags
 */
enum ucl_parser_flags {
	UCL_PARSER_KEY_LOWERCASE = 0x1,//!< UCL_FLAG_KEY_LOWERCASE
	UCL_PARSER_ZEROCOPY = 0x2      //!< UCL_FLAG_ZEROCOPY
};

/**
 * String conversion flags
 */
enum ucl_string_flags {
	UCL_STRING_ESCAPE = 0x1,  /**< UCL_STRING_ESCAPE perform JSON escape */
	UCL_STRING_TRIM = 0x2,    /**< UCL_STRING_TRIM trim leading and trailing whitespaces */
	UCL_STRING_PARSE_BOOLEAN = 0x4,    /**< UCL_STRING_PARSE_BOOLEAN parse passed string and detect boolean */
	UCL_STRING_PARSE_INT = 0x8,    /**< UCL_STRING_PARSE_INT parse passed string and detect integer number */
	UCL_STRING_PARSE_DOUBLE = 0x10,    /**< UCL_STRING_PARSE_DOUBLE parse passed string and detect integer or float number */
	UCL_STRING_PARSE_NUMBER =  UCL_STRING_PARSE_INT|UCL_STRING_PARSE_DOUBLE ,  /**<
									UCL_STRING_PARSE_NUMBER parse passed string and detect number */
	UCL_STRING_PARSE =  UCL_STRING_PARSE_BOOLEAN|UCL_STRING_PARSE_NUMBER,   /**<
									UCL_STRING_PARSE parse passed string (and detect booleans and numbers) */
	UCL_STRING_PARSE_BYTES = 0x20  /**< Treat numbers as bytes */
};

/**
 * Basic flags for an object
 */
enum ucl_object_flags {
	UCL_OBJECT_ALLOCATED_KEY = 1, //!< UCL_OBJECT_ALLOCATED_KEY
	UCL_OBJECT_ALLOCATED_VALUE = 2, //!< UCL_OBJECT_ALLOCATED_VALUE
	UCL_OBJECT_NEED_KEY_ESCAPE = 4 //!< UCL_OBJECT_NEED_KEY_ESCAPE
};

/**
 * UCL object
 */
typedef struct ucl_object_s {
	union {
		int64_t iv;							/**< int value of an object */
		const char *sv;					/**< string value of an object */
		double dv;							/**< double value of an object */
		struct ucl_object_s *av;			/**< array					*/
		void *ov;							/**< object					*/
		void* ud;							/**< opaque user data		*/
	} value;
	const char *key;						/**< key of an object		*/
	struct ucl_object_s *next;				/**< array handle			*/
	struct ucl_object_s *prev;				/**< array handle			*/
	unsigned char* trash_stack[2];			/**< pointer to allocated chunks */
	unsigned keylen;						/**< lenght of a key		*/
	unsigned len;							/**< size of an object		*/
	enum ucl_type type;						/**< real type				*/
	uint16_t ref;							/**< reference count		*/
	uint16_t flags;							/**< object flags			*/
} ucl_object_t;


/**
 * Copy and return a key of an object, returned key is zero-terminated
 * @param obj CL object
 * @return zero terminated key
 */
char* ucl_copy_key_trash (ucl_object_t *obj);

/**
 * Copy and return a string value of an object, returned key is zero-terminated
 * @param obj CL object
 * @return zero terminated string representation of object value
 */
char* ucl_copy_value_trash (ucl_object_t *obj);

/**
 * Creates a new object
 * @return new object
 */
static inline ucl_object_t* ucl_object_new (void) UCL_WARN_UNUSED_RESULT;
static inline ucl_object_t *
ucl_object_new (void)
{
	ucl_object_t *new;
	new = malloc (sizeof (ucl_object_t));
	if (new != NULL) {
		memset (new, 0, sizeof (ucl_object_t));
		new->ref = 1;
		new->type = UCL_NULL;
	}
	return new;
}

/**
 * Create new object with type specified
 * @param type type of a new object
 * @return new object
 */
static inline ucl_object_t* ucl_object_typed_new (unsigned int type) UCL_WARN_UNUSED_RESULT;
static inline ucl_object_t *
ucl_object_typed_new (unsigned int type)
{
	ucl_object_t *new;
	new = malloc (sizeof (ucl_object_t));
	if (new != NULL) {
		memset (new, 0, sizeof (ucl_object_t));
		new->ref = 1;
		new->type = (type <= UCL_NULL ? type : UCL_NULL);
	}
	return new;
}

/**
 * Convert any string to an ucl object making the specified transformations
 * @param str fixed size or NULL terminated string
 * @param len length (if len is zero, than str is treated as NULL terminated)
 * @param flags conversion flags
 * @return new object
 */
ucl_object_t * ucl_object_fromstring_common (const char *str, size_t len,
		enum ucl_string_flags flags) UCL_WARN_UNUSED_RESULT;

/**
 * Create a UCL object from the specified string
 * @param str NULL terminated string, will be json escaped
 * @return new object
 */
static inline ucl_object_t *
ucl_object_fromstring (const char *str)
{
	return ucl_object_fromstring_common (str, 0, UCL_STRING_ESCAPE);
}

/**
 * Create a UCL object from the specified string
 * @param str fixed size string, will be json escaped
 * @param len length of a string
 * @return new object
 */
static inline ucl_object_t *
ucl_object_fromlstring (const char *str, size_t len)
{
	return ucl_object_fromstring_common (str, len, UCL_STRING_ESCAPE);
}

/**
 * Create an object from an integer number
 * @param iv number
 * @return new object
 */
static inline ucl_object_t *
ucl_object_fromint (int64_t iv)
{
	ucl_object_t *obj;

	obj = ucl_object_new ();
	if (obj != NULL) {
		obj->type = UCL_INT;
		obj->value.iv = iv;
	}

	return obj;
}

/**
 * Create an object from a float number
 * @param dv number
 * @return new object
 */
static inline ucl_object_t *
ucl_object_fromdouble (double dv)
{
	ucl_object_t *obj;

	obj = ucl_object_new ();
	if (obj != NULL) {
		obj->type = UCL_FLOAT;
		obj->value.dv = dv;
	}

	return obj;
}

/**
 * Create an object from a boolean
 * @param bv bool value
 * @return new object
 */
static inline ucl_object_t *
ucl_object_frombool (bool bv)
{
	ucl_object_t *obj;

	obj = ucl_object_new ();
	if (obj != NULL) {
		obj->type = UCL_BOOLEAN;
		obj->value.iv = bv;
	}

	return obj;
}

/**
 * Insert a object 'elt' to the hash 'top' and associate it with key 'key'
 * @param top destination object (will be created automatically if top is NULL)
 * @param elt element to insert (must NOT be NULL)
 * @param key key to associate with this object (either const or preallocated)
 * @param keylen length of the key (or 0 for NULL terminated keys)
 * @param copy_key make an internal copy of key
 * @return new value of top object
 */
ucl_object_t* ucl_object_insert_key (ucl_object_t *top, ucl_object_t *elt,
		const char *key, size_t keylen, bool copy_key) UCL_WARN_UNUSED_RESULT;

/**
 * Insert a object 'elt' to the hash 'top' and associate it with key 'key', if the specified key exist,
 * try to merge its content
 * @param top destination object (will be created automatically if top is NULL)
 * @param elt element to insert (must NOT be NULL)
 * @param key key to associate with this object (either const or preallocated)
 * @param keylen length of the key (or 0 for NULL terminated keys)
 * @param copy_key make an internal copy of key
 * @return new value of top object
 */
ucl_object_t* ucl_object_insert_key_merged (ucl_object_t *top, ucl_object_t *elt,
		const char *key, size_t keylen, bool copy_key) UCL_WARN_UNUSED_RESULT;

/**
 * Append an element to the array object
 * @param top destination object (will be created automatically if top is NULL)
 * @param eltelement to append (must NOT be NULL)
 * @return new value of top object
 */
static inline ucl_object_t * ucl_array_append (ucl_object_t *top,
		ucl_object_t *elt) UCL_WARN_UNUSED_RESULT;
static inline ucl_object_t *
ucl_array_append (ucl_object_t *top, ucl_object_t *elt)
{
	ucl_object_t *head;

	if (elt == NULL) {
		return NULL;
	}

	if (top == NULL) {
		top = ucl_object_new ();
		top->type = UCL_ARRAY;
		top->value.av = elt;
		elt->next = NULL;
		elt->prev = elt;
	}
	else {
		head = top->value.av;
		elt->prev = head->prev;
		head->prev->next = elt;
		head->prev = elt;
		elt->next = NULL;
	}

	return top;
}

/**
 * Append a element to another element forming an implicit array
 * @param head head to append (may be NULL)
 * @param elt new element
 * @return new head if applicable
 */
static inline ucl_object_t * ucl_elt_append (ucl_object_t *head,
		ucl_object_t *elt) UCL_WARN_UNUSED_RESULT;
static inline ucl_object_t *
ucl_elt_append (ucl_object_t *head, ucl_object_t *elt)
{

	if (head == NULL) {
		elt->next = NULL;
		elt->prev = elt;
		head = elt;
	}
	else {
		elt->prev = head->prev;
		head->prev->next = elt;
		head->prev = elt;
		elt->next = NULL;
	}

	return head;
}

/**
 * Converts an object to double value
 * @param obj CL object
 * @param target target double variable
 * @return true if conversion was successful
 */
static inline bool
ucl_obj_todouble_safe (ucl_object_t *obj, double *target)
{
	if (obj == NULL) {
		return false;
	}
	switch (obj->type) {
	case UCL_INT:
		*target = obj->value.iv; /* Probaly could cause overflow */
		break;
	case UCL_FLOAT:
	case UCL_TIME:
		*target = obj->value.dv;
		break;
	default:
		return false;
	}

	return true;
}

/**
 * Unsafe version of \ref ucl_obj_todouble_safe
 * @param obj CL object
 * @return double value
 */
static inline double
ucl_obj_todouble (ucl_object_t *obj)
{
	double result = 0.;

	ucl_object_todouble_safe (obj, &result);
	return result;
}

/**
 * Converts an object to integer value
 * @param obj CL object
 * @param target target integer variable
 * @return true if conversion was successful
 */
static inline bool
ucl_obj_toint_safe (ucl_object_t *obj, int64_t *target)
{
	if (obj == NULL) {
		return false;
	}
	switch (obj->type) {
	case UCL_INT:
		*target = obj->value.iv;
		break;
	case UCL_FLOAT:
	case UCL_TIME:
		*target = obj->value.dv; /* Loosing of decimal points */
		break;
	default:
		return false;
	}

	return true;
}

/**
 * Unsafe version of \ref ucl_obj_toint_safe
 * @param obj CL object
 * @return int value
 */
static inline int64_t
ucl_obj_toint (ucl_object_t *obj)
{
	int64_t result = 0;

	ucl_object_toint_safe (obj, &result);
	return result;
}

/**
 * Converts an object to boolean value
 * @param obj CL object
 * @param target target boolean variable
 * @return true if conversion was successful
 */
static inline bool
ucl_obj_toboolean_safe (ucl_object_t *obj, bool *target)
{
	if (obj == NULL) {
		return false;
	}
	switch (obj->type) {
	case UCL_BOOLEAN:
		*target = (obj->value.iv == true);
		break;
	default:
		return false;
	}

	return true;
}

/**
 * Unsafe version of \ref ucl_obj_toboolean_safe
 * @param obj CL object
 * @return boolean value
 */
static inline bool
ucl_obj_toboolean (ucl_object_t *obj)
{
	bool result = false;

	ucl_object_toboolean_safe (obj, &result);
	return result;
}

/**
 * Converts an object to string value
 * @param obj CL object
 * @param target target string variable, no need to free value
 * @return true if conversion was successful
 */
static inline bool
ucl_obj_tostring_safe (ucl_object_t *obj, const char **target)
{
	if (obj == NULL) {
		return false;
	}

	switch (obj->type) {
	case UCL_STRING:
		*target = ucl_copy_value_trash (obj);
		break;
	default:
		return false;
	}

	return true;
}

/**
 * Unsafe version of \ref ucl_obj_tostring_safe
 * @param obj CL object
 * @return string value
 */
static inline const char *
ucl_obj_tostring (ucl_object_t *obj)
{
	const char *result = NULL;

	ucl_object_tostring_safe (obj, &result);
	return result;
}

/**
 * Convert any object to a string in JSON notation if needed
 * @param obj CL object
 * @return string value
 */
static inline const char *
ucl_object_tostring_forced (ucl_object_t *obj)
{
	return ucl_copy_value_trash (obj);
}

/**
 * Return string as char * and len, string may be not zero terminated, more efficient that tostring as it
 * allows zero-copy
 * @param obj CL object
 * @param target target string variable, no need to free value
 * @param tlen target length
 * @return true if conversion was successful
 */
static inline bool
ucl_obj_tolstring_safe (ucl_object_t *obj, const char **target, size_t *tlen)
{
	if (obj == NULL) {
		return false;
	}
	switch (obj->type) {
	case UCL_STRING:
		*target = obj->value.sv;
		*tlen = obj->len;
		break;
	default:
		return false;
	}

	return true;
}

/**
 * Unsafe version of \ref ucl_obj_tolstring_safe
 * @param obj CL object
 * @return string value
 */
static inline const char *
ucl_obj_tolstring (ucl_object_t *obj, size_t *tlen)
{
	const char *result = NULL;

	ucl_object_tolstring_safe (obj, &result, tlen);
	return result;
}

/**
 * Return object identified by a key in the specified object
 * @param obj object to get a key from (must be of type UCL_OBJECT)
 * @param key key to search
 * @return object matched the specified key or NULL if key is not found
 */
ucl_object_t * ucl_obj_get_key (ucl_object_t *obj, const char *key);

/**
 * Return object identified by a fixed size key in the specified object
 * @param obj object to get a key from (must be of type UCL_OBJECT)
 * @param key key to search
 * @param klen length of a key
 * @return object matched the specified key or NULL if key is not found
 */
ucl_object_t *ucl_obj_get_keyl (ucl_object_t *obj, const char *key, size_t klen);

/**
 * Returns a key of an object as a NULL terminated string
 * @param obj CL object
 * @return key or NULL if there is no key
 */
static inline const char *
ucl_object_key (ucl_object_t *obj)
{
	return ucl_copy_key_trash (obj);
}

/**
 * Returns a key of an object as a fixed size string (may be more efficient)
 * @param obj CL object
 * @param len target key length
 * @return key pointer
 */
static inline const char *
ucl_object_keyl (ucl_object_t *obj, size_t *len)
{
	*len = obj->keylen;
	return obj->key;
}

/**
 * Macro handler for a parser
 * @param data the content of macro
 * @param len the length of content
 * @param ud opaque user data
 * @param err error pointer
 * @return true if macro has been parsed
 */
typedef bool (*ucl_macro_handler) (const unsigned char *data, size_t len, void* ud);

/* Opaque parser */
struct ucl_parser;

/**
 * Creates new parser object
 * @param pool pool to allocate memory from
 * @return new parser object
 */
struct ucl_parser* ucl_parser_new (int flags);

/**
 * Register new handler for a macro
 * @param parser parser object
 * @param macro macro name (without leading dot)
 * @param handler handler (it is called immediately after macro is parsed)
 * @param ud opaque user data for a handler
 */
void ucl_parser_register_macro (struct ucl_parser *parser, const char *macro,
		ucl_macro_handler handler, void* ud);

/**
 * Register new parser variable
 * @param parser parser object
 * @param var variable name
 * @param value variable value
 */
void ucl_parser_register_variable (struct ucl_parser *parser, const char *var,
		const char *value);

/**
 * Load new chunk to a parser
 * @param parser parser structure
 * @param data the pointer to the beginning of a chunk
 * @param len the length of a chunk
 * @param err if *err is NULL it is set to parser error
 * @return true if chunk has been added and false in case of error
 */
bool ucl_parser_add_chunk (struct ucl_parser *parser, const unsigned char *data, size_t len);

/**
 * Load and add data from a file
 * @param parser parser structure
 * @param filename the name of file
 * @param err if *err is NULL it is set to parser error
 * @return true if chunk has been added and false in case of error
 */
bool ucl_parser_add_file (struct ucl_parser *parser, const char *filename);

/**
 * Get a top object for a parser
 * @param parser parser structure
 * @param err if *err is NULL it is set to parser error
 * @return top parser object or NULL
 */
ucl_object_t* ucl_parser_get_object (struct ucl_parser *parser);

/**
 * Get the error string if failing
 * @param parser parser object
 */
const char *ucl_parser_get_error(struct ucl_parser *parser);
/**
 * Free cl parser object
 * @param parser parser object
 */
void ucl_parser_free (struct ucl_parser *parser);

/**
 * Free cl object
 * @param obj cl object to free
 */
void ucl_obj_free (ucl_object_t *obj);

/**
 * Icrease reference count for an object
 * @param obj object to ref
 */
static inline ucl_object_t *
ucl_obj_ref (ucl_object_t *obj) {
	obj->ref ++;
	return obj;
}

/**
 * Decrease reference count for an object
 * @param obj object to unref
 */
static inline void
ucl_obj_unref (ucl_object_t *obj) {
	if (--obj->ref <= 0) {
		ucl_obj_free (obj);
	}
}

/**
 * Emit object to a string
 * @param obj object
 * @param emit_type if type is UCL_EMIT_JSON then emit json, if type is
 * UCL_EMIT_CONFIG then emit config like object
 * @return dump of an object (must be freed after using) or NULL in case of error
 */
unsigned char *ucl_object_emit (ucl_object_t *obj, enum ucl_emitter emit_type);

/**
 * Add new public key to parser for signatures check
 * @param parser parser object
 * @param key PEM representation of a key
 * @param len length of the key
 * @param err if *err is NULL it is set to parser error
 * @return true if a key has been successfully added
 */
bool ucl_pubkey_add (struct ucl_parser *parser, const unsigned char *key, size_t len);

/**
 * Set FILENAME and CURDIR variables in parser
 * @param parser parser object
 * @param filename filename to set or NULL to set FILENAME to "undef" and CURDIR to getcwd()
 * @param need_expand perform realpath() if this variable is true and filename is not NULL
 * @return true if variables has been set
 */
bool ucl_parser_set_filevars (struct ucl_parser *parser, const char *filename,
		bool need_expand);

typedef void* ucl_object_iter_t;

/**
 * Get next key from an object
 * @param obj object to iterate
 * @param iter opaque iterator, must be set to NULL on the first call:
 * ucl_object_iter_t it = NULL;
 * while ((cur = ucl_iterate_object (obj, &it)) != NULL) ...
 * @return the next object or NULL
 */
ucl_object_t* ucl_iterate_object (ucl_object_t *obj, ucl_object_iter_t *iter, bool expand_values);

#endif /* RCL_H_ */
