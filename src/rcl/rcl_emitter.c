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


static void rspamd_cl_elt_write_json (rspamd_cl_object_t *obj, GString *buf, guint tabs, gboolean start_tabs);
static void rspamd_cl_obj_write_json (rspamd_cl_object_t *obj, GString *buf, guint tabs, gboolean start_tabs);

/**
 * Add tabulation to the output buffer
 * @param buf target buffer
 * @param tabs number of tabs to add
 */
static inline void
rspamd_cl_add_tabs (GString *buf, guint tabs)
{
	while (tabs--) {
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
rspamd_cl_elt_obj_write_json (rspamd_cl_object_t *obj, GString *buf, guint tabs, gboolean start_tabs)
{
	rspamd_cl_object_t *cur, *tmp;

	if (start_tabs) {
		rspamd_cl_add_tabs (buf, tabs);
	}
	g_string_append_len (buf, "{\n", 2);
	HASH_ITER (hh, obj, cur, tmp) {
		rspamd_cl_add_tabs (buf, tabs + 1);
		rspamd_cl_elt_string_write_json (cur->key, buf);
		g_string_append_len (buf, ": ", 2);
		rspamd_cl_obj_write_json (cur, buf, tabs + 1, FALSE);
		if (cur->hh.next != NULL) {
			g_string_append_len (buf, ",\n", 2);
		}
		else {
			g_string_append_c (buf, '\n');
		}
	}
	rspamd_cl_add_tabs (buf, tabs);
	g_string_append_c (buf, '}');
}

/**
 * Write a single array to the buffer
 * @param obj array to write
 * @param buf target buffer
 */
static void
rspamd_cl_elt_array_write_json (rspamd_cl_object_t *obj, GString *buf, guint tabs, gboolean start_tabs)
{
	rspamd_cl_object_t *cur = obj;

	if (start_tabs) {
		rspamd_cl_add_tabs (buf, tabs);
	}
	g_string_append_len (buf, "[\n", 2);
	while (cur) {
		rspamd_cl_elt_write_json (cur, buf, tabs + 1, TRUE);
		if (cur->next != NULL) {
			g_string_append_len (buf, ",\n", 2);
		}
		else {
			g_string_append_c (buf, '\n');
		}
		cur = cur->next;
	}
	rspamd_cl_add_tabs (buf, tabs);
	g_string_append_c (buf, ']');
}

/**
 * Emit a single element
 * @param obj object
 * @param buf buffer
 */
static void
rspamd_cl_elt_write_json (rspamd_cl_object_t *obj, GString *buf, guint tabs, gboolean start_tabs)
{
	switch (obj->type) {
	case RSPAMD_CL_INT:
		if (start_tabs) {
			rspamd_cl_add_tabs (buf, tabs);
		}
		g_string_append_printf (buf, "%ld", (long int)rspamd_cl_obj_toint (obj));
		break;
	case RSPAMD_CL_FLOAT:
		if (start_tabs) {
			rspamd_cl_add_tabs (buf, tabs);
		}
		g_string_append_printf (buf, "%lf", rspamd_cl_obj_todouble (obj));
		break;
	case RSPAMD_CL_TIME:
		if (start_tabs) {
			rspamd_cl_add_tabs (buf, tabs);
		}
		g_string_append_printf (buf, "%lf", rspamd_cl_obj_todouble (obj));
		break;
	case RSPAMD_CL_BOOLEAN:
		if (start_tabs) {
			rspamd_cl_add_tabs (buf, tabs);
		}
		g_string_append_printf (buf, "%s", rspamd_cl_obj_toboolean (obj) ? "true" : "false");
		break;
	case RSPAMD_CL_STRING:
		if (start_tabs) {
			rspamd_cl_add_tabs (buf, tabs);
		}
		rspamd_cl_elt_string_write_json (rspamd_cl_obj_tostring (obj), buf);
		break;
	case RSPAMD_CL_OBJECT:
		rspamd_cl_elt_obj_write_json (obj->value.ov, buf, tabs, start_tabs);
		break;
	case RSPAMD_CL_ARRAY:
		rspamd_cl_elt_array_write_json (obj->value.ov, buf, tabs, start_tabs);
		break;
	}
}

/**
 * Write a single object to the buffer
 * @param obj object
 * @param buf target buffer
 */
static void
rspamd_cl_obj_write_json (rspamd_cl_object_t *obj, GString *buf, guint tabs, gboolean start_tabs)
{
	rspamd_cl_object_t *cur;
	gboolean is_array = (obj->next != NULL);

	if (is_array) {
		/* This is an array actually */
		if (start_tabs) {
			rspamd_cl_add_tabs (buf, tabs);
		}
		g_string_append_len (buf, "[\n", 2);
		cur = obj;
		while (cur != NULL) {
			rspamd_cl_elt_write_json (cur, buf, tabs + 1, TRUE);
			if (cur->next) {
				g_string_append_c (buf, ',');
			}
			g_string_append_c (buf, '\n');
			cur = cur->next;
		}
		rspamd_cl_add_tabs (buf, tabs);
		g_string_append_c (buf, ']');
	}
	else {
		rspamd_cl_elt_write_json (obj, buf, tabs, start_tabs);
	}

}

/**
 * Emit an object to json
 * @param obj object
 * @return json output (should be freed after using)
 */
static guchar *
rspamd_cl_object_emit_json (rspamd_cl_object_t *obj)
{
	GString *buf;
	guchar *res;

	/* Allocate large enough buffer */
	buf = g_string_sized_new (BUFSIZ);

	rspamd_cl_obj_write_json (obj, buf, 0, FALSE);

	res = buf->str;
	g_string_free (buf, FALSE);

	return res;
}

guchar *
rspamd_cl_object_emit (rspamd_cl_object_t *obj, enum rspamd_cl_emitter emit_type)
{
	if (emit_type == RSPAMD_CL_EMIT_JSON) {
		return rspamd_cl_object_emit_json (obj);
	}

	return NULL;
}
