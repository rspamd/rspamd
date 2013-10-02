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

#include "config.h"
#include "rcl.h"
#include "rcl_internal.h"

/**
 * @file rcl_emitter.c
 * Serialise RCL object to the RCL format
 */


static void rspamd_cl_elt_write_json (rspamd_cl_object_t *obj, GString *buf, guint tabs, gboolean start_tabs, gboolean compact);
static void rspamd_cl_obj_write_json (rspamd_cl_object_t *obj, GString *buf, guint tabs, gboolean start_tabs, gboolean compact);
static void rspamd_cl_elt_write_rcl (rspamd_cl_object_t *obj, GString *buf, guint tabs, gboolean start_tabs, gboolean is_top);

/**
 * Add tabulation to the output buffer
 * @param buf target buffer
 * @param tabs number of tabs to add
 */
static inline void
rspamd_cl_add_tabs (GString *buf, guint tabs, gboolean compact)
{
	while (!compact && tabs--) {
		g_string_append_len (buf, "    ", 4);
	}
}

/**
 * Serialise string
 * @param str string to emit
 * @param buf target buffer
 */
static void
rspamd_cl_elt_string_write_json (const gchar *str, GString *buf)
{
	const gchar *p = str;

	g_string_append_c (buf, '"');
	while (*p != '\0') {
		switch (*p) {
		case '\n':
			g_string_append_len (buf, "\\n", 2);
			break;
		case '\r':
			g_string_append_len (buf, "\\r", 2);
			break;
		case '\b':
			g_string_append_len (buf, "\\b", 2);
			break;
		case '\t':
			g_string_append_len (buf, "\\t", 2);
			break;
		case '\f':
			g_string_append_len (buf, "\\f", 2);
			break;
		case '\\':
			g_string_append_len (buf, "\\\\", 2);
			break;
		case '"':
			g_string_append_len (buf, "\\\"", 2);
			break;
		default:
			g_string_append_c (buf, *p);
			break;
		}
		p ++;
	}
	g_string_append_c (buf, '"');
}

/**
 * Write a single object to the buffer
 * @param obj object to write
 * @param buf target buffer
 */
static void
rspamd_cl_elt_obj_write_json (rspamd_cl_object_t *obj, GString *buf, guint tabs, gboolean start_tabs, gboolean compact)
{
	rspamd_cl_object_t *cur, *tmp;

	if (start_tabs) {
		rspamd_cl_add_tabs (buf, tabs, compact);
	}
	if (compact) {
		g_string_append_c (buf, '{');
	}
	else {
		g_string_append_len (buf, "{\n", 2);
	}
	HASH_ITER (hh, obj, cur, tmp) {
		rspamd_cl_add_tabs (buf, tabs + 1, compact);
		rspamd_cl_elt_string_write_json (cur->key, buf);
		if (compact) {
			g_string_append_c (buf, ':');
		}
		else {
			g_string_append_len (buf, ": ", 2);
		}
		rspamd_cl_obj_write_json (cur, buf, tabs + 1, FALSE, compact);
		if (cur->hh.next != NULL) {
			if (compact) {
				g_string_append_c (buf, ',');
			}
			else {
				g_string_append_len (buf, ",\n", 2);
			}
		}
		else if (!compact) {
			g_string_append_c (buf, '\n');
		}
	}
	rspamd_cl_add_tabs (buf, tabs, compact);
	g_string_append_c (buf, '}');
}

/**
 * Write a single array to the buffer
 * @param obj array to write
 * @param buf target buffer
 */
static void
rspamd_cl_elt_array_write_json (rspamd_cl_object_t *obj, GString *buf, guint tabs, gboolean start_tabs, gboolean compact)
{
	rspamd_cl_object_t *cur = obj;

	if (start_tabs) {
		rspamd_cl_add_tabs (buf, tabs, compact);
	}
	if (compact) {
		g_string_append_c (buf, '[');
	}
	else {
		g_string_append_len (buf, "[\n", 2);
	}
	while (cur) {
		rspamd_cl_elt_write_json (cur, buf, tabs + 1, TRUE, compact);
		if (cur->next != NULL) {
			if (compact) {
				g_string_append_c (buf, ',');
			}
			else {
				g_string_append_len (buf, ",\n", 2);
			}
		}
		else if (!compact) {
			g_string_append_c (buf, '\n');
		}
		cur = cur->next;
	}
	rspamd_cl_add_tabs (buf, tabs, compact);
	g_string_append_c (buf, ']');
}

/**
 * Emit a single element
 * @param obj object
 * @param buf buffer
 */
static void
rspamd_cl_elt_write_json (rspamd_cl_object_t *obj, GString *buf, guint tabs, gboolean start_tabs, gboolean compact)
{
	switch (obj->type) {
	case RSPAMD_CL_INT:
		if (start_tabs) {
			rspamd_cl_add_tabs (buf, tabs, compact);
		}
		g_string_append_printf (buf, "%ld", (long int)rspamd_cl_obj_toint (obj));
		break;
	case RSPAMD_CL_FLOAT:
		if (start_tabs) {
			rspamd_cl_add_tabs (buf, tabs, compact);
		}
		g_string_append_printf (buf, "%lf", rspamd_cl_obj_todouble (obj));
		break;
	case RSPAMD_CL_TIME:
		if (start_tabs) {
			rspamd_cl_add_tabs (buf, tabs, compact);
		}
		g_string_append_printf (buf, "%lf", rspamd_cl_obj_todouble (obj));
		break;
	case RSPAMD_CL_BOOLEAN:
		if (start_tabs) {
			rspamd_cl_add_tabs (buf, tabs, compact);
		}
		g_string_append_printf (buf, "%s", rspamd_cl_obj_toboolean (obj) ? "true" : "false");
		break;
	case RSPAMD_CL_STRING:
		if (start_tabs) {
			rspamd_cl_add_tabs (buf, tabs, compact);
		}
		rspamd_cl_elt_string_write_json (rspamd_cl_obj_tostring (obj), buf);
		break;
	case RSPAMD_CL_OBJECT:
		rspamd_cl_elt_obj_write_json (obj->value.ov, buf, tabs, start_tabs, compact);
		break;
	case RSPAMD_CL_ARRAY:
		rspamd_cl_elt_array_write_json (obj->value.ov, buf, tabs, start_tabs, compact);
		break;
	case RSPAMD_CL_USERDATA:
		break;
	}
}

/**
 * Write a single object to the buffer
 * @param obj object
 * @param buf target buffer
 */
static void
rspamd_cl_obj_write_json (rspamd_cl_object_t *obj, GString *buf, guint tabs, gboolean start_tabs, gboolean compact)
{
	rspamd_cl_object_t *cur;
	gboolean is_array = (obj->next != NULL);

	if (is_array) {
		/* This is an array actually */
		if (start_tabs) {
			rspamd_cl_add_tabs (buf, tabs, compact);
		}

		if (compact) {
			g_string_append_c (buf, '[');
		}
		else {
			g_string_append_len (buf, "[\n", 2);
		}
		cur = obj;
		while (cur != NULL) {
			rspamd_cl_elt_write_json (cur, buf, tabs + 1, TRUE, compact);
			if (cur->next) {
				g_string_append_c (buf, ',');
			}
			if (!compact) {
				g_string_append_c (buf, '\n');
			}
			cur = cur->next;
		}
		rspamd_cl_add_tabs (buf, tabs, compact);
		g_string_append_c (buf, ']');
	}
	else {
		rspamd_cl_elt_write_json (obj, buf, tabs, start_tabs, compact);
	}

}

/**
 * Emit an object to json
 * @param obj object
 * @return json output (should be freed after using)
 */
static guchar *
rspamd_cl_object_emit_json (rspamd_cl_object_t *obj, gboolean compact)
{
	GString *buf;
	guchar *res;

	/* Allocate large enough buffer */
	buf = g_string_sized_new (BUFSIZ);

	rspamd_cl_obj_write_json (obj, buf, 0, FALSE, compact);

	res = buf->str;
	g_string_free (buf, FALSE);

	return res;
}

/**
 * Write a single object to the buffer
 * @param obj object to write
 * @param buf target buffer
 */
static void
rspamd_cl_elt_obj_write_rcl (rspamd_cl_object_t *obj, GString *buf, guint tabs, gboolean start_tabs, gboolean is_top)
{
	rspamd_cl_object_t *cur, *tmp;

	if (start_tabs) {
		rspamd_cl_add_tabs (buf, tabs, is_top);
	}
	if (!is_top) {
		g_string_append_len (buf, "{\n", 2);
	}

	while (obj) {
		HASH_ITER (hh, obj, cur, tmp) {
			rspamd_cl_add_tabs (buf, tabs + 1, is_top);
			g_string_append (buf, cur->key);
			if (cur->type != RSPAMD_CL_OBJECT && cur->type != RSPAMD_CL_ARRAY) {
				g_string_append_len (buf, " = ", 3);
			}
			else {
				g_string_append_c (buf, ' ');
			}
			rspamd_cl_elt_write_rcl (cur, buf, is_top ? tabs : tabs + 1, FALSE, FALSE);
			if (cur->type != RSPAMD_CL_OBJECT && cur->type != RSPAMD_CL_ARRAY) {
				g_string_append_len (buf, ";\n", 2);
			}
			else {
				g_string_append_c (buf, '\n');
			}
		}
		obj = obj->next;
	}
	rspamd_cl_add_tabs (buf, tabs, is_top);
	if (!is_top) {
		g_string_append_c (buf, '}');
	}
}

/**
 * Write a single array to the buffer
 * @param obj array to write
 * @param buf target buffer
 */
static void
rspamd_cl_elt_array_write_rcl (rspamd_cl_object_t *obj, GString *buf, guint tabs, gboolean start_tabs, gboolean is_top)
{
	rspamd_cl_object_t *cur = obj;

	if (start_tabs) {
		rspamd_cl_add_tabs (buf, tabs, FALSE);
	}

	g_string_append_len (buf, "[\n", 2);
	while (cur) {
		rspamd_cl_elt_write_rcl (cur, buf, tabs + 1, TRUE, FALSE);
		g_string_append_len (buf, ",\n", 2);
		cur = cur->next;
	}
	rspamd_cl_add_tabs (buf, tabs, FALSE);
	g_string_append_c (buf, ']');
}

/**
 * Emit a single element
 * @param obj object
 * @param buf buffer
 */
static void
rspamd_cl_elt_write_rcl (rspamd_cl_object_t *obj, GString *buf, guint tabs, gboolean start_tabs, gboolean is_top)
{
	switch (obj->type) {
	case RSPAMD_CL_INT:
		if (start_tabs) {
			rspamd_cl_add_tabs (buf, tabs, FALSE);
		}
		g_string_append_printf (buf, "%ld", (long int)rspamd_cl_obj_toint (obj));
		break;
	case RSPAMD_CL_FLOAT:
		if (start_tabs) {
			rspamd_cl_add_tabs (buf, tabs, FALSE);
		}
		g_string_append_printf (buf, "%.4lf", rspamd_cl_obj_todouble (obj));
		break;
	case RSPAMD_CL_TIME:
		if (start_tabs) {
			rspamd_cl_add_tabs (buf, tabs, FALSE);
		}
		g_string_append_printf (buf, "%.4lf", rspamd_cl_obj_todouble (obj));
		break;
	case RSPAMD_CL_BOOLEAN:
		if (start_tabs) {
			rspamd_cl_add_tabs (buf, tabs, FALSE);
		}
		g_string_append_printf (buf, "%s", rspamd_cl_obj_toboolean (obj) ? "true" : "false");
		break;
	case RSPAMD_CL_STRING:
		if (start_tabs) {
			rspamd_cl_add_tabs (buf, tabs, FALSE);
		}
		rspamd_cl_elt_string_write_json (rspamd_cl_obj_tostring (obj), buf);
		break;
	case RSPAMD_CL_OBJECT:
		rspamd_cl_elt_obj_write_rcl (obj->value.ov, buf, tabs, start_tabs, is_top);
		break;
	case RSPAMD_CL_ARRAY:
		rspamd_cl_elt_array_write_rcl (obj->value.ov, buf, tabs, start_tabs, is_top);
		break;
	case RSPAMD_CL_USERDATA:
		break;
	}
}

/**
 * Emit an object to rcl
 * @param obj object
 * @return rcl output (should be freed after using)
 */
static guchar *
rspamd_cl_object_emit_rcl (rspamd_cl_object_t *obj)
{
	GString *buf;
	guchar *res;

	/* Allocate large enough buffer */
	buf = g_string_sized_new (BUFSIZ);

	rspamd_cl_elt_write_rcl (obj, buf, 0, FALSE, TRUE);

	res = buf->str;
	g_string_free (buf, FALSE);

	return res;
}

guchar *
rspamd_cl_object_emit (rspamd_cl_object_t *obj, enum rspamd_cl_emitter emit_type)
{
	if (emit_type == RSPAMD_CL_EMIT_JSON) {
		return rspamd_cl_object_emit_json (obj, FALSE);
	}
	else if (emit_type == RSPAMD_CL_EMIT_JSON_COMPACT) {
		return rspamd_cl_object_emit_json (obj, TRUE);
	}
	else {
		return rspamd_cl_object_emit_rcl (obj);
	}

	return NULL;
}
