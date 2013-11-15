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

#include <float.h>
#include <math.h>
#include "ucl.h"
#include "ucl_internal.h"
#include "ucl_chartable.h"

/**
 * @file rcl_emitter.c
 * Serialise RCL object to the RCL format
 */


static void ucl_obj_write_json (ucl_object_t *obj, UT_string *buf, unsigned int tabs, bool start_tabs, bool compact);
static void ucl_elt_write_rcl (ucl_object_t *obj, UT_string *buf, unsigned int tabs,
		bool start_tabs, bool is_top, bool expand_array);
static void ucl_elt_write_yaml (ucl_object_t *obj, UT_string *buf, unsigned int tabs,
		bool start_tabs, bool compact, bool expand_array);

/**
 * Add tabulation to the output buffer
 * @param buf target buffer
 * @param tabs number of tabs to add
 */
static inline void
ucl_add_tabs (UT_string *buf, unsigned int tabs, bool compact)
{
	char *p;
	unsigned int i;

	if (!compact) {
		while (buf->n - buf->i <= tabs * 4) {
			utstring_reserve (buf, buf->n * 2);
		}
		p = &buf->d[buf->i];
		for (i = 0; i < tabs; i ++) {
			memset (&p[i * 4], ' ', 4);
		}
		buf->i += i * 4;
		buf->d[buf->i] = '\0';
	}
}

/**
 * Serialise string
 * @param str string to emit
 * @param buf target buffer
 */
static void
ucl_elt_string_write_json (const char *str, size_t size, UT_string *buf)
{
	const char *p = str, *c = str;
	size_t len = 0;

	utstring_append_c (buf, '"');
	while (size) {
		if (ucl_test_character (*p, UCL_CHARACTER_JSON_UNSAFE)) {
			if (len > 0) {
				utstring_append_len (buf, c, len);
			}
			switch (*p) {
			case '\n':
				utstring_append_len (buf, "\\n", 2);
				break;
			case '\r':
				utstring_append_len (buf, "\\r", 2);
				break;
			case '\b':
				utstring_append_len (buf, "\\b", 2);
				break;
			case '\t':
				utstring_append_len (buf, "\\t", 2);
				break;
			case '\f':
				utstring_append_len (buf, "\\f", 2);
				break;
			case '\\':
				utstring_append_len (buf, "\\\\", 2);
				break;
			case '"':
				utstring_append_len (buf, "\\\"", 2);
				break;
			}
			len = 0;
			c = ++p;
		}
		else {
			p ++;
			len ++;
		}
		size --;
	}
	if (len > 0) {
		utstring_append_len (buf, c, len);
	}
	utstring_append_c (buf, '"');
}

static inline void
ucl_print_float (UT_string *buf, double val)
{
	if (val == (double)(int)val) {
		utstring_printf (buf, "%.1lf", val);
	}
	else if (fabs (val - (double)(int)val) < 0.0000001) {
		/* Write at maximum precision */
		utstring_printf (buf, "%.*lg", DBL_DIG, val);
	}
	else {
		utstring_printf (buf, "%lf", val);
	}
}

/**
 * Write a single object to the buffer
 * @param obj object to write
 * @param buf target buffer
 */
static void
ucl_elt_obj_write_json (ucl_object_t *obj, UT_string *buf, unsigned int tabs, bool start_tabs, bool compact)
{
	ucl_object_t *cur;
	ucl_hash_iter_t it = NULL;

	if (start_tabs) {
		ucl_add_tabs (buf, tabs, compact);
	}
	if (compact) {
		utstring_append_c (buf, '{');
	}
	else {
		utstring_append_len (buf, "{\n", 2);
	}
	while ((cur = ucl_hash_iterate (obj->value.ov, &it))) {
		ucl_add_tabs (buf, tabs + 1, compact);
		if (cur->keylen > 0) {
			ucl_elt_string_write_json (cur->key, cur->keylen, buf);
		}
		else {
			utstring_append_len (buf, "null", 4);
		}
		if (compact) {
			utstring_append_c (buf, ':');
		}
		else {
			utstring_append_len (buf, ": ", 2);
		}
		ucl_obj_write_json (cur, buf, tabs + 1, false, compact);
		if (ucl_hash_iter_has_next (it)) {
			if (compact) {
				utstring_append_c (buf, ',');
			}
			else {
				utstring_append_len (buf, ",\n", 2);
			}
		}
		else if (!compact) {
			utstring_append_c (buf, '\n');
		}
	}
	ucl_add_tabs (buf, tabs, compact);
	utstring_append_c (buf, '}');
}

/**
 * Write a single array to the buffer
 * @param obj array to write
 * @param buf target buffer
 */
static void
ucl_elt_array_write_json (ucl_object_t *obj, UT_string *buf, unsigned int tabs, bool start_tabs, bool compact)
{
	ucl_object_t *cur = obj;

	if (start_tabs) {
		ucl_add_tabs (buf, tabs, compact);
	}
	if (compact) {
		utstring_append_c (buf, '[');
	}
	else {
		utstring_append_len (buf, "[\n", 2);
	}
	while (cur) {
		ucl_elt_write_json (cur, buf, tabs + 1, true, compact);
		if (cur->next != NULL) {
			if (compact) {
				utstring_append_c (buf, ',');
			}
			else {
				utstring_append_len (buf, ",\n", 2);
			}
		}
		else if (!compact) {
			utstring_append_c (buf, '\n');
		}
		cur = cur->next;
	}
	ucl_add_tabs (buf, tabs, compact);
	utstring_append_c (buf, ']');
}

/**
 * Emit a single element
 * @param obj object
 * @param buf buffer
 */
void
ucl_elt_write_json (ucl_object_t *obj, UT_string *buf, unsigned int tabs, bool start_tabs, bool compact)
{
	switch (obj->type) {
	case UCL_INT:
		if (start_tabs) {
			ucl_add_tabs (buf, tabs, compact);
		}
		utstring_printf (buf, "%jd", (intmax_t)ucl_object_toint (obj));
		break;
	case UCL_FLOAT:
	case UCL_TIME:
		if (start_tabs) {
			ucl_add_tabs (buf, tabs, compact);
		}
		ucl_print_float (buf, ucl_object_todouble (obj));
		break;
	case UCL_BOOLEAN:
		if (start_tabs) {
			ucl_add_tabs (buf, tabs, compact);
		}
		utstring_printf (buf, "%s", ucl_object_toboolean (obj) ? "true" : "false");
		break;
	case UCL_STRING:
		if (start_tabs) {
			ucl_add_tabs (buf, tabs, compact);
		}
		ucl_elt_string_write_json (obj->value.sv, obj->len, buf);
		break;
	case UCL_OBJECT:
		ucl_elt_obj_write_json (obj, buf, tabs, start_tabs, compact);
		break;
	case UCL_ARRAY:
		ucl_elt_array_write_json (obj->value.av, buf, tabs, start_tabs, compact);
		break;
	case UCL_USERDATA:
		break;
	}
}

/**
 * Write a single object to the buffer
 * @param obj object
 * @param buf target buffer
 */
static void
ucl_obj_write_json (ucl_object_t *obj, UT_string *buf, unsigned int tabs, bool start_tabs, bool compact)
{
	ucl_object_t *cur;
	bool is_array = (obj->next != NULL);

	if (is_array) {
		/* This is an array actually */
		if (start_tabs) {
			ucl_add_tabs (buf, tabs, compact);
		}

		if (compact) {
			utstring_append_c (buf, '[');
		}
		else {
			utstring_append_len (buf, "[\n", 2);
		}
		cur = obj;
		while (cur != NULL) {
			ucl_elt_write_json (cur, buf, tabs + 1, true, compact);
			if (cur->next) {
				utstring_append_c (buf, ',');
			}
			if (!compact) {
				utstring_append_c (buf, '\n');
			}
			cur = cur->next;
		}
		ucl_add_tabs (buf, tabs, compact);
		utstring_append_c (buf, ']');
	}
	else {
		ucl_elt_write_json (obj, buf, tabs, start_tabs, compact);
	}

}

/**
 * Emit an object to json
 * @param obj object
 * @return json output (should be freed after using)
 */
static UT_string *
ucl_object_emit_json (ucl_object_t *obj, bool compact)
{
	UT_string *buf;

	/* Allocate large enough buffer */
	utstring_new (buf);

	ucl_obj_write_json (obj, buf, 0, false, compact);

	return buf;
}

/**
 * Write a single object to the buffer
 * @param obj object to write
 * @param buf target buffer
 */
static void
ucl_elt_obj_write_rcl (ucl_object_t *obj, UT_string *buf, unsigned int tabs, bool start_tabs, bool is_top)
{
	ucl_object_t *cur, *cur_obj;
	ucl_hash_iter_t it = NULL;

	if (start_tabs) {
		ucl_add_tabs (buf, tabs, is_top);
	}
	if (!is_top) {
		utstring_append_len (buf, "{\n", 2);
	}

	while ((cur = ucl_hash_iterate (obj->value.ov, &it))) {
		LL_FOREACH (cur, cur_obj) {
			ucl_add_tabs (buf, tabs + 1, is_top);
			if (cur_obj->flags & UCL_OBJECT_NEED_KEY_ESCAPE) {
				ucl_elt_string_write_json (cur_obj->key, cur_obj->keylen, buf);
			}
			else {
				utstring_append_len (buf, cur_obj->key, cur_obj->keylen);
			}
			if (cur_obj->type != UCL_OBJECT && cur_obj->type != UCL_ARRAY) {
				utstring_append_len (buf, " = ", 3);
			}
			else {
				utstring_append_c (buf, ' ');
			}
			ucl_elt_write_rcl (cur_obj, buf, is_top ? tabs : tabs + 1, false, false, false);
			if (cur_obj->type != UCL_OBJECT && cur_obj->type != UCL_ARRAY) {
				utstring_append_len (buf, ";\n", 2);
			}
			else {
				utstring_append_c (buf, '\n');
			}
		}
	}

	ucl_add_tabs (buf, tabs, is_top);
	if (!is_top) {
		utstring_append_c (buf, '}');
	}
}

/**
 * Write a single array to the buffer
 * @param obj array to write
 * @param buf target buffer
 */
static void
ucl_elt_array_write_rcl (ucl_object_t *obj, UT_string *buf, unsigned int tabs, bool start_tabs, bool is_top)
{
	ucl_object_t *cur = obj;

	if (start_tabs) {
		ucl_add_tabs (buf, tabs, false);
	}

	utstring_append_len (buf, "[\n", 2);
	while (cur) {
		ucl_elt_write_rcl (cur, buf, tabs + 1, true, false, false);
		utstring_append_len (buf, ",\n", 2);
		cur = cur->next;
	}
	ucl_add_tabs (buf, tabs, false);
	utstring_append_c (buf, ']');
}

/**
 * Emit a single element
 * @param obj object
 * @param buf buffer
 */
static void
ucl_elt_write_rcl (ucl_object_t *obj, UT_string *buf, unsigned int tabs,
		bool start_tabs, bool is_top, bool expand_array)
{
	if (expand_array && obj->next != NULL) {
		ucl_elt_array_write_rcl (obj, buf, tabs, start_tabs, is_top);
	}
	else {
		switch (obj->type) {
		case UCL_INT:
			if (start_tabs) {
				ucl_add_tabs (buf, tabs, false);
			}
			utstring_printf (buf, "%jd", (intmax_t)ucl_object_toint (obj));
			break;
		case UCL_FLOAT:
		case UCL_TIME:
			if (start_tabs) {
				ucl_add_tabs (buf, tabs, false);
			}
			ucl_print_float (buf, ucl_object_todouble (obj));
			break;
		case UCL_BOOLEAN:
			if (start_tabs) {
				ucl_add_tabs (buf, tabs, false);
			}
			utstring_printf (buf, "%s", ucl_object_toboolean (obj) ? "true" : "false");
			break;
		case UCL_STRING:
			if (start_tabs) {
				ucl_add_tabs (buf, tabs, false);
			}
			ucl_elt_string_write_json (obj->value.sv, obj->len, buf);
			break;
		case UCL_OBJECT:
			ucl_elt_obj_write_rcl (obj, buf, tabs, start_tabs, is_top);
			break;
		case UCL_ARRAY:
			ucl_elt_array_write_rcl (obj->value.av, buf, tabs, start_tabs, is_top);
			break;
		case UCL_USERDATA:
			break;
		}
	}
}

/**
 * Emit an object to rcl
 * @param obj object
 * @return rcl output (should be freed after using)
 */
static UT_string *
ucl_object_emit_rcl (ucl_object_t *obj)
{
	UT_string *buf;

	/* Allocate large enough buffer */
	utstring_new (buf);

	ucl_elt_write_rcl (obj, buf, 0, false, true, true);

	return buf;
}


/**
 * Write a single object to the buffer
 * @param obj object to write
 * @param buf target buffer
 */
static void
ucl_elt_obj_write_yaml (ucl_object_t *obj, UT_string *buf, unsigned int tabs, bool start_tabs, bool is_top)
{
	ucl_object_t *cur;
	ucl_hash_iter_t it = NULL;

	if (start_tabs) {
		ucl_add_tabs (buf, tabs, is_top);
	}
	if (!is_top) {
		utstring_append_len (buf, ": {\n", 4);
	}

	while ((cur = ucl_hash_iterate (obj->value.ov, &it))) {
		ucl_add_tabs (buf, tabs + 1, is_top);
		if (cur->flags & UCL_OBJECT_NEED_KEY_ESCAPE) {
			ucl_elt_string_write_json (cur->key, cur->keylen, buf);
		}
		else {
			utstring_append_len (buf, cur->key, cur->keylen);
		}
		if (cur->type != UCL_OBJECT && cur->type != UCL_ARRAY) {
			utstring_append_len (buf, " : ", 3);
		}
		else {
			utstring_append_c (buf, ' ');
		}
		ucl_elt_write_yaml (cur, buf, is_top ? tabs : tabs + 1, false, false, true);
		if (cur->type != UCL_OBJECT && cur->type != UCL_ARRAY) {
			if (!is_top) {
				utstring_append_len (buf, ",\n", 2);
			}
			else {
				utstring_append_c (buf, '\n');
			}
		}
		else {
			utstring_append_c (buf, '\n');
		}
	}

	ucl_add_tabs (buf, tabs, is_top);
	if (!is_top) {
		utstring_append_c (buf, '}');
	}
}

/**
 * Write a single array to the buffer
 * @param obj array to write
 * @param buf target buffer
 */
static void
ucl_elt_array_write_yaml (ucl_object_t *obj, UT_string *buf, unsigned int tabs, bool start_tabs, bool is_top)
{
	ucl_object_t *cur = obj;

	if (start_tabs) {
		ucl_add_tabs (buf, tabs, false);
	}

	utstring_append_len (buf, "[\n", 2);
	while (cur) {
		ucl_elt_write_yaml (cur, buf, tabs + 1, true, false, false);
		utstring_append_len (buf, ",\n", 2);
		cur = cur->next;
	}
	ucl_add_tabs (buf, tabs, false);
	utstring_append_c (buf, ']');
}

/**
 * Emit a single element
 * @param obj object
 * @param buf buffer
 */
static void
ucl_elt_write_yaml (ucl_object_t *obj, UT_string *buf, unsigned int tabs,
		bool start_tabs, bool is_top, bool expand_array)
{
	if (expand_array && obj->next != NULL) {
		ucl_elt_array_write_yaml (obj, buf, tabs, start_tabs, is_top);
		}
	else {
		switch (obj->type) {
		case UCL_INT:
			if (start_tabs) {
				ucl_add_tabs (buf, tabs, false);
			}
			utstring_printf (buf, "%jd", (intmax_t)ucl_object_toint (obj));
			break;
		case UCL_FLOAT:
		case UCL_TIME:
			if (start_tabs) {
				ucl_add_tabs (buf, tabs, false);
			}
			ucl_print_float (buf, ucl_object_todouble (obj));
			break;
		case UCL_BOOLEAN:
			if (start_tabs) {
				ucl_add_tabs (buf, tabs, false);
			}
			utstring_printf (buf, "%s", ucl_object_toboolean (obj) ? "true" : "false");
			break;
		case UCL_STRING:
			if (start_tabs) {
				ucl_add_tabs (buf, tabs, false);
			}
			ucl_elt_string_write_json (obj->value.sv, obj->len, buf);
			break;
		case UCL_OBJECT:
			ucl_elt_obj_write_yaml (obj, buf, tabs, start_tabs, is_top);
			break;
		case UCL_ARRAY:
			ucl_elt_array_write_yaml (obj->value.av, buf, tabs, start_tabs, is_top);
			break;
		case UCL_USERDATA:
			break;
		}
	}
}

/**
 * Emit an object to rcl
 * @param obj object
 * @return rcl output (should be freed after using)
 */
static UT_string *
ucl_object_emit_yaml (ucl_object_t *obj)
{
	UT_string *buf;

	/* Allocate large enough buffer */
	utstring_new (buf);

	ucl_elt_write_yaml (obj, buf, 0, false, true, true);

	return buf;
}

unsigned char *
ucl_object_emit (ucl_object_t *obj, enum ucl_emitter emit_type)
{
	UT_string *buf = NULL;
	unsigned char *res = NULL;

	if (obj == NULL) {
		return NULL;
	}

	if (emit_type == UCL_EMIT_JSON) {
		buf = ucl_object_emit_json (obj, false);
	}
	else if (emit_type == UCL_EMIT_JSON_COMPACT) {
		buf = ucl_object_emit_json (obj, true);
	}
	else if (emit_type == UCL_EMIT_YAML) {
		buf = ucl_object_emit_yaml (obj);
	}
	else {
		buf = ucl_object_emit_rcl (obj);
	}

	if (buf != NULL) {
		res = utstring_body (buf);
		free (buf);
	}

	return res;
}
