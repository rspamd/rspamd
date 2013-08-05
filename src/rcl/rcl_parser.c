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
 * @file rcl_parser.c
 * The implementation of rcl parser
 */

/**
 * Create a new object
 * @return new object
 */
static inline rspamd_cl_object_t *
rspamd_cl_object_new (void)
{
	return g_slice_alloc0 (sizeof (rspamd_cl_object_t));
}

/**
 * Move up to len characters
 * @param parser
 * @param begin
 * @param len
 * @return new position in chunk
 */
static inline const guchar *
rspamd_cl_chunk_getc (struct rspamd_cl_parser *parser, const guchar *begin, gsize len)
{
	while (len > 0) {
		len --;
		if (*begin == '\n') {
			parser->line ++;
			parser->column = 0;
		}
		else {
			parser->column ++;
		}
		begin ++;
	}
	return begin;
}

static gboolean
rspamd_cl_check_open_comment (struct rspamd_cl_parser *parser, const guchar **begin, gsize *len)
{
	const guchar *p = *begin;

	if (*p == '#') {
		if (parser->state != RSPAMD_RCL_STATE_SCOMMENT &&
				parser->state != RSPAMD_RCL_STATE_MCOMMENT) {
			parser->prev_state = parser->state;
			parser->state = RSPAMD_RCL_STATE_SCOMMENT;
			*begin = rspamd_cl_chunk_getc (parser, *begin, 1);
			(*len) --;
			return TRUE;
		}
	}
	else if (*p == '/' && *len >= 2) {
		if (*p == '/' && parser->state != RSPAMD_RCL_STATE_SCOMMENT &&
				parser->state != RSPAMD_RCL_STATE_MCOMMENT) {
			parser->prev_state = parser->state;
			parser->state = RSPAMD_RCL_STATE_SCOMMENT;
			*begin = rspamd_cl_chunk_getc (parser, *begin, 2);
			(*len) -= 2;
			return TRUE;
		}
		else if (*p == '*') {
			/* Multiline comment */
			if (parser->state == RSPAMD_RCL_STATE_SCOMMENT) {
				/* Immediately finish single line comment and start multiline one */
				parser->state = RSPAMD_RCL_STATE_MCOMMENT;
				parser->comments_nested ++;
			}
			else if (parser->state == RSPAMD_RCL_STATE_MCOMMENT) {
				parser->comments_nested ++;
			}
			else {
				parser->prev_state = parser->state;
				parser->state = RSPAMD_RCL_STATE_SCOMMENT;
			}
			*begin = rspamd_cl_chunk_getc (parser, *begin, 2);
			(*len) -= 2;
		}
	}

	return FALSE;
}

/**
 * Handle include macro
 * @param data include data
 * @param len length of data
 * @param ud user data
 * @param err error ptr
 * @return
 */
static gboolean
rspamd_cl_include_handler (const guchar *data, gsize len, gpointer ud, GError **err)
{
	return TRUE;
}

/**
 * Handle includes macro
 * @param data include data
 * @param len length of data
 * @param ud user data
 * @param err error ptr
 * @return
 */
static gboolean
rspamd_cl_includes_handler (const guchar *data, gsize len, gpointer ud, GError **err)
{
	return TRUE;
}

static const guchar *
rspamd_cl_skip_spaces (struct rspamd_cl_parser *parser, const guchar *data, gsize *len)
{
	const guchar *p, *end;

	p = data;
	end = data + *len;

	if (parser->state == RSPAMD_RCL_STATE_KEY) {
		/* Skip any space character */
		while (p < end) {
			if (!g_ascii_isspace (*p)) {
				break;
			}
			p = rspamd_cl_chunk_getc (parser, p, 1);
			(*len) --;
		}
	}
	else {
		while (p < end) {
			if (!g_ascii_isspace (*p) || *p == '\n' || *p == '\r') {
				break;
			}
			p = rspamd_cl_chunk_getc (parser, p, 1);
			(*len) --;
		}
	}

	return p;
}

static gboolean
rspamd_cl_parse_key (struct rspamd_cl_parser *parser, const guchar **data,
		gsize *len, GError **err)
{
	const guchar *p, *c = NULL, *end;


	p = *data;
	end = p + *len;

	while (p < end) {
		/*
		 * A key must start with alpha and end with space character
		 */
		if (*p == '.') {
			/* It is macro actually */
			p = rspamd_cl_chunk_getc (parser, p, 1);
			len --;
			parser->state = RSPAMD_RCL_STATE_MACRO_NAME;
			*data = p;
			return TRUE;
		}
		else if (c == NULL) {
			if (g_ascii_isalpha (*p)) {
				/* The first symbol */
				c = p;
				p = rspamd_cl_chunk_getc (parser, p, 1);
				(*len) --;
			}
			else if (*p == '"') {
				/* JSON style key */
				c = p + 1;
				p = rspamd_cl_chunk_getc (parser, p, 2);
				(*len) -= 2;
			}
			else {
				/* Invalid identifier */
				parser->state = RSPAMD_RCL_STATE_ERROR;
				g_set_error (err, RCL_ERROR, RSPAMD_CL_ESYNTAX, "key must start with a letter, "
						"line %d, pos: %d", parser->line, parser->column);
				return FALSE;
			}
		}
		else {
			if (g_ascii_isalnum (*p)) {
				p = rspamd_cl_chunk_getc (parser, p, 1);
				(*len) --;
			}
			else if (*p == ' ' || *p == '\t') {
				p = rspamd_cl_skip_spaces (parser, p, len);
			}
		}
	}
	*data = p;

	return TRUE;
}

/**
 * Handle the main states of rcl parser
 * @param parser parser structure
 * @param data the pointer to the beginning of a chunk
 * @param len the length of a chunk
 * @param err if *err is NULL it is set to parser error
 * @return TRUE if chunk has been parsed and FALSE in case of error
 */
static gboolean
rspamd_cl_state_machine (struct rspamd_cl_parser *parser, const guchar *data,
		gsize len, GError **err)
{
	const guchar *p, *end;
	rspamd_cl_object_t *obj;

	p = data;
	end = p + len;
	while (p < end) {
		switch (parser->state) {
		case RSPAMD_RCL_STATE_INIT:
			/*
			 * At the init state we can either go to the parse array or object
			 * if we got [ or { correspondingly or can just treat new data as
			 * a key of newly created object
			 */
			if (!rspamd_cl_check_open_comment (parser, &p, &len)) {
				obj = rspamd_cl_object_new ();
				if (*p == '[') {
					parser->state = RSPAMD_RCL_STATE_ARRAY;
					obj->type = RSPAMD_CL_ARRAY;
					p = rspamd_cl_chunk_getc (parser, p, 1);
					len --;
				}
				else {
					parser->state = RSPAMD_RCL_STATE_KEY;
					obj->type = RSPAMD_CL_OBJECT;
					if (*p == '{') {
						p = rspamd_cl_chunk_getc (parser, p, 1);
						len --;
					}
				}
				parser->cur_obj = obj;
				parser->top_obj = obj;
				p = rspamd_cl_skip_spaces (parser, p, &len);
			}
			break;
		case RSPAMD_RCL_STATE_KEY:
			if (!rspamd_cl_parse_key (parser, &p, &len, err)) {
				return FALSE;
			}
			break;
		default:
			/* TODO: add all states */
			return FALSE;
		}
	}

	return TRUE;
}

struct rspamd_cl_parser*
rspamd_cl_parser_new (void)
{
	struct rspamd_cl_parser *new;

	new = g_slice_alloc0 (sizeof (struct rspamd_cl_parser));

	new->line = 1;
	rspamd_cl_parser_register_macro (new, "include", rspamd_cl_include_handler, new);
	rspamd_cl_parser_register_macro (new, "includes", rspamd_cl_includes_handler, new);

	return new;
}


void
rspamd_cl_parser_register_macro (struct rspamd_cl_parser *parser, const gchar *macro,
		rspamd_cl_macro_handler handler, gpointer ud)
{
	struct rspamd_cl_macro *new;

	new = g_slice_alloc0 (sizeof (struct rspamd_cl_macro));
	new->handler = handler;
	new->name = g_strdup (macro);
	new->ud = ud;
	HASH_ADD_KEYPTR (hh, parser->macroes, new->name, strlen (new->name), new);
}

gboolean
rspamd_cl_parser_add_chunk (struct rspamd_cl_parser *parser, const guchar *data,
		gsize len, GError **err)
{
	if (parser->state != RSPAMD_RCL_STATE_ERROR) {
		return rspamd_cl_state_machine (parser, data, len, err);
	}

	g_set_error (err, RCL_ERROR, RSPAMD_CL_ESTATE, "a parser is in an invalid state");

	return FALSE;
}
