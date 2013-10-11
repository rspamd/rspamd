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
#include "rcl_chartable.h"
#include "util.h"

/**
 * @file rcl_parser.c
 * The implementation of rcl parser
 */

/**
 * Move up to len characters
 * @param parser
 * @param begin
 * @param len
 * @return new position in chunk
 */
static inline void
rspamd_cl_chunk_skipc (struct rspamd_cl_chunk *chunk, guchar c)
{
	if (c == '\n') {
		chunk->line ++;
		chunk->column = 0;
	}
	else {
		chunk->column ++;
	}

	chunk->pos ++;
	chunk->remain --;
}

static inline gboolean
rcl_test_character (guchar c, gint type_flags)
{
	return (rcl_chartable[c] & type_flags) != 0;
}

static inline void
rspamd_cl_set_err (struct rspamd_cl_chunk *chunk, gint code, const char *str, GError **err)
{
	g_set_error (err, RCL_ERROR, code, "error on line %d at column %d: '%s', character: '%c'",
			chunk->line, chunk->column, str, *chunk->pos);
}

static gboolean
rspamd_cl_skip_comments (struct rspamd_cl_parser *parser, GError **err)
{
	struct rspamd_cl_chunk *chunk = parser->chunks;
	const guchar *p;
	gint comments_nested = 0;

	p = chunk->pos;

start:
	if (*p == '#') {
		if (parser->state != RSPAMD_RCL_STATE_SCOMMENT &&
				parser->state != RSPAMD_RCL_STATE_MCOMMENT) {
			while (p < chunk->end) {
				if (*p == '\n') {
					rspamd_cl_chunk_skipc (chunk, *++p);
					/* Check comments again */
					goto start;
				}
				rspamd_cl_chunk_skipc (chunk, *++p);
			}
		}
	}
	else if (*p == '/' && chunk->remain >= 2) {
		if (p[1] == '/' && parser->state != RSPAMD_RCL_STATE_SCOMMENT &&
				parser->state != RSPAMD_RCL_STATE_MCOMMENT) {
			rspamd_cl_chunk_skipc (chunk, *++p);
			chunk->pos = p;
			while (p < chunk->end) {
				if (*p == '\n') {
					rspamd_cl_chunk_skipc (chunk, *++p);
					goto start;
				}
				rspamd_cl_chunk_skipc (chunk, *++p);
			}
		}
		else if (p[1] == '*') {
			rspamd_cl_chunk_skipc (chunk, *++p);
			comments_nested ++;
			rspamd_cl_chunk_skipc (chunk, *++p);

			while (p < chunk->end) {
				if (*p == '*') {
					rspamd_cl_chunk_skipc (chunk, *++p);
					if (*p == '/') {
						comments_nested --;
						if (comments_nested == 0) {
							rspamd_cl_chunk_skipc (chunk, *++p);
							goto start;
						}
					}
					rspamd_cl_chunk_skipc (chunk, *++p);
				}
				else if (p[0] == '/' && chunk->remain >= 2 && p[1] == '*') {
					comments_nested ++;
					rspamd_cl_chunk_skipc (chunk, *++p);
					rspamd_cl_chunk_skipc (chunk, *++p);
					continue;
				}
				rspamd_cl_chunk_skipc (chunk, *++p);
			}
			if (comments_nested != 0) {
				rspamd_cl_set_err (chunk, RSPAMD_CL_ENESTED, "comments nesting is invalid", err);
				return FALSE;
			}
		}
	}

	return TRUE;
}

/**
 * Return multiplier for a character
 * @param c multiplier character
 * @param is_bytes if TRUE use 1024 multiplier
 * @return multiplier
 */
static inline gulong
rspamd_cl_lex_num_multiplier (const guchar c, gboolean is_bytes) {
	const struct {
		char c;
		glong mult_normal;
		glong mult_bytes;
	} multipliers[] = {
			{'m', 1000 * 1000, 1024 * 1024},
			{'k', 1000, 1024},
			{'g', 1000 * 1000 * 1000, 1024 * 1024 * 1024}
	};
	gint i;

	for (i = 0; i < 3; i ++) {
		if (g_ascii_tolower (c) == multipliers[i].c) {
			if (is_bytes) {
				return multipliers[i].mult_bytes;
			}
			return multipliers[i].mult_normal;
		}
	}

	return 1;
}


/**
 * Return multiplier for time scaling
 * @param c
 * @return
 */
static inline gdouble
rspamd_cl_lex_time_multiplier (const guchar c) {
	const struct {
		char c;
		gdouble mult;
	} multipliers[] = {
			{'m', 60},
			{'h', 60 * 60},
			{'d', 60 * 60 * 24},
			{'w', 60 * 60 * 24 * 7},
			{'y', 60 * 60 * 24 * 7 * 365}
	};
	gint i;

	for (i = 0; i < 5; i ++) {
		if (g_ascii_tolower (c) == multipliers[i].c) {
			return multipliers[i].mult;
		}
	}

	return 1;
}

/**
 * Return TRUE if a character is a end of an atom
 * @param c
 * @return
 */
static inline gboolean
rspamd_cl_lex_is_atom_end (const guchar c)
{
	return rcl_test_character (c, RCL_CHARACTER_VALUE_END);
}

static inline gboolean
rspamd_cl_lex_is_comment (const guchar c1, const guchar c2)
{
	if (c1 == '/') {
		if (c2 == '/' || c2 == '*') {
			return TRUE;
		}
	}
	else if (c1 == '#') {
		return TRUE;
	}
	return FALSE;
}

/**
 * Parse possible number
 * @param parser
 * @param chunk
 * @param err
 * @return TRUE if a number has been parsed
 */
static gboolean
rspamd_cl_lex_number (struct rspamd_cl_parser *parser,
		struct rspamd_cl_chunk *chunk, rspamd_cl_object_t *obj, GError **err)
{
	const guchar *p = chunk->pos, *c = chunk->pos;
	gchar *endptr;
	gboolean got_dot = FALSE, got_exp = FALSE, need_double = FALSE, is_date = FALSE;
	gdouble dv;
	gint64 lv;

	if (*p == '-') {
		rspamd_cl_chunk_skipc (chunk, *p);
		p ++;
	}
	while (p < chunk->end) {
		if (g_ascii_isdigit (*p)) {
			rspamd_cl_chunk_skipc (chunk, *p);
			p ++;
		}
		else {
			if (p == c) {
				/* Empty digits sequence, not a number */
				return FALSE;
			}
			else if (*p == '.') {
				if (got_dot) {
					/* Double dots, not a number */
					return FALSE;
				}
				else {
					got_dot = TRUE;
					need_double = TRUE;
				}
			}
			else if (*p == 'e' || *p == 'E') {
				if (got_exp) {
					/* Double exp, not a number */
					return FALSE;
				}
				else {
					got_exp = TRUE;
					need_double = TRUE;
					rspamd_cl_chunk_skipc (chunk, *p);
					p ++;
					if (p >= chunk->end) {
						return FALSE;
					}
					if (!g_ascii_isdigit (*p) && *p != '+' && *p == '-') {
						/* Wrong exponent sign */
						return FALSE;
					}
				}
			}
			else {
				/* Got the end of the number, need to check */
				break;
			}
		}
	}

	errno = 0;
	if (need_double) {
		dv = strtod (c, &endptr);
	}
	else {
		lv = strtoimax (c, &endptr, 10);
	}
	if (errno == ERANGE) {
		rspamd_cl_set_err (chunk, RSPAMD_CL_ESYNTAX, "numeric value is out of range", err);
		parser->prev_state = parser->state;
		parser->state = RSPAMD_RCL_STATE_ERROR;
		return FALSE;
	}

	/* Now check endptr */
	if (endptr == NULL || rspamd_cl_lex_is_atom_end (*endptr) || *endptr == '\0') {
		chunk->pos = endptr;
		goto set_obj;
	}

	if ((guchar *)endptr < chunk->end) {
		p = endptr;
		chunk->pos = p;
		switch (*p) {
		case 'm':
		case 'M':
		case 'g':
		case 'G':
		case 'k':
		case 'K':
			if (chunk->end - p > 2) {
				if (p[1] == 's' || p[1] == 'S') {
					/* Milliseconds */
					if (!need_double) {
						need_double = TRUE;
						dv = lv;
					}
					is_date = TRUE;
					if (p[0] == 'm' || p[0] == 'M') {
						dv /= 1000.;
					}
					else {
						dv *= rspamd_cl_lex_num_multiplier (*p, FALSE);
					}
					rspamd_cl_chunk_skipc (chunk, *p);
					rspamd_cl_chunk_skipc (chunk, *p);
					p += 2;
					goto set_obj;
				}
				else if (p[1] == 'b' || p[1] == 'B') {
					/* Megabytes */
					if (need_double) {
						need_double = FALSE;
						lv = dv;
					}
					lv *= rspamd_cl_lex_num_multiplier (*p, TRUE);
					rspamd_cl_chunk_skipc (chunk, *p);
					rspamd_cl_chunk_skipc (chunk, *p);
					p += 2;
					goto set_obj;
				}
				else if (rspamd_cl_lex_is_atom_end (p[1])) {
					if (need_double) {
						dv *= rspamd_cl_lex_num_multiplier (*p, FALSE);
					}
					else {
						lv *= rspamd_cl_lex_num_multiplier (*p, FALSE);
					}
					rspamd_cl_chunk_skipc (chunk, *p);
					p ++;
					goto set_obj;
				}
				else if (chunk->end - p >= 3) {
					if (g_ascii_tolower (p[0]) == 'm' &&
							g_ascii_tolower (p[1]) == 'i' &&
							g_ascii_tolower (p[2]) == 'n') {
						/* Minutes */
						if (!need_double) {
							need_double = TRUE;
							dv = lv;
						}
						is_date = TRUE;
						dv *= 60.;
						rspamd_cl_chunk_skipc (chunk, *p);
						rspamd_cl_chunk_skipc (chunk, *p);
						rspamd_cl_chunk_skipc (chunk, *p);
						p += 3;
						goto set_obj;
					}
				}
			}
			else {
				if (need_double) {
					dv *= rspamd_cl_lex_num_multiplier (*p, FALSE);
				}
				else {
					lv *= rspamd_cl_lex_num_multiplier (*p, FALSE);
				}
				rspamd_cl_chunk_skipc (chunk, *p);
				p ++;
				goto set_obj;
			}
			break;
		case 'S':
		case 's':
			if (p == chunk->end - 1 || rspamd_cl_lex_is_atom_end (*++p)) {
				if (!need_double) {
					need_double = TRUE;
					dv = lv;
				}
				rspamd_cl_chunk_skipc (chunk, *p);
				is_date = TRUE;
				goto set_obj;
			}
			break;
		case 'h':
		case 'H':
		case 'd':
		case 'D':
		case 'w':
		case 'W':
		case 'Y':
		case 'y':
			if (p == chunk->end - 1 || rspamd_cl_lex_is_atom_end (p[1])) {
				if (!need_double) {
					need_double = TRUE;
					dv = lv;
				}
				is_date = TRUE;
				dv *= rspamd_cl_lex_time_multiplier (*p);
				rspamd_cl_chunk_skipc (chunk, *p);
				p ++;
				goto set_obj;
			}
			break;
		}
	}

	chunk->pos = c;
	return FALSE;

set_obj:
	if (need_double || is_date) {
		if (!is_date) {
			obj->type = RSPAMD_CL_FLOAT;
		}
		else {
			obj->type = RSPAMD_CL_TIME;
		}
		obj->value.dv = dv;
	}
	else {
		obj->type = RSPAMD_CL_INT;
		obj->value.iv = lv;
	}
	chunk->pos = p;
	return TRUE;
}

/**
 * Parse quoted string with possible escapes
 * @param parser
 * @param chunk
 * @param err
 * @return TRUE if a string has been parsed
 */
static gboolean
rspamd_cl_lex_json_string (struct rspamd_cl_parser *parser,
		struct rspamd_cl_chunk *chunk, GError **err)
{
	const guchar *p = chunk->pos;
	guchar c;
	gint i;

	while (p < chunk->end) {
		c = *p;
		if (c < 0x1F) {
			/* Unmasked control character */
			if (c == '\n') {
				rspamd_cl_set_err (chunk, RSPAMD_CL_ESYNTAX, "unexpected newline", err);
			}
			else {
				rspamd_cl_set_err (chunk, RSPAMD_CL_ESYNTAX, "unexpected control character", err);
			}
			return FALSE;
		}
		if (c == '\\') {
			rspamd_cl_chunk_skipc (chunk, *p);
			p ++;
			c = *p;
			if (p >= chunk->end) {
				rspamd_cl_set_err (chunk, RSPAMD_CL_ESYNTAX, "unfinished escape character", err);
				return FALSE;
			}
			if (*p == 'u') {
				rspamd_cl_chunk_skipc (chunk, *p);
				p ++;
				for (i = 0; i < 4 && p < chunk->end; i ++) {
					if (!g_ascii_isxdigit (*p)) {
						rspamd_cl_set_err (chunk, RSPAMD_CL_ESYNTAX, "invalid utf escape", err);
						return FALSE;
					}
					rspamd_cl_chunk_skipc (chunk, *p);
					p ++;
				}
				if (p >= chunk->end) {
					rspamd_cl_set_err (chunk, RSPAMD_CL_ESYNTAX, "unfinished escape character", err);
					return FALSE;
				}
			}
			else if (c == '"' || c == '\\' || c == '/' || c == 'b' ||
					c == 'f' || c == 'n' || c == 'r' || c == 't') {
				rspamd_cl_chunk_skipc (chunk, *p);
				p ++;
			}
			else {
				rspamd_cl_set_err (chunk, RSPAMD_CL_ESYNTAX, "invalid escape character", err);
				return FALSE;
			}
			continue;
		}
		else if (c == '"') {
			rspamd_cl_chunk_skipc (chunk, *p);
			p ++;
			return TRUE;
		}
		rspamd_cl_chunk_skipc (chunk, *p);
		p ++;
	}

	return FALSE;
}

/**
 * Parse a key in an object
 * @param parser
 * @param chunk
 * @param err
 * @return TRUE if a key has been parsed
 */
static gboolean
rspamd_cl_parse_key (struct rspamd_cl_parser *parser,
		struct rspamd_cl_chunk *chunk, GError **err)
{
	const guchar *p, *c = NULL, *end;
	gboolean got_quote = FALSE, got_eq = FALSE, got_semicolon = FALSE;
	rspamd_cl_object_t *nobj, *tobj, *container;

	p = chunk->pos;

	while (p < chunk->end) {
		/*
		 * A key must start with alpha and end with space character
		 */
		if (*p == '.') {
			/* It is macro actually */
			rspamd_cl_chunk_skipc (chunk, *p);
			parser->prev_state = parser->state;
			parser->state = RSPAMD_RCL_STATE_MACRO_NAME;
			return TRUE;
		}
		else if (c == NULL) {
			if (rcl_test_character (*p, RCL_CHARACTER_KEY_START)) {
				/* The first symbol */
				c = p;
				rspamd_cl_chunk_skipc (chunk, *p);
				p ++;
			}
			else if (*p == '"') {
				/* JSON style key */
				c = p + 1;
				got_quote = TRUE;
				rspamd_cl_chunk_skipc (chunk, *p);
				p ++;
			}
			else {
				/* Invalid identifier */
				rspamd_cl_set_err (chunk, RSPAMD_CL_ESYNTAX, "key must begin with a letter", err);
				return FALSE;
			}
		}
		else {
			/* Parse the body of a key */
			if (!got_quote) {
				if (rcl_test_character (*p, RCL_CHARACTER_KEY)) {
					rspamd_cl_chunk_skipc (chunk, *p);
					p ++;
				}
				else if (*p == ' ' || *p == '\t' || *p == ':' || *p == '=') {
					end = p;
					break;
				}
				else {
					rspamd_cl_set_err (chunk, RSPAMD_CL_ESYNTAX, "invalid character in a key", err);
					return FALSE;
				}
			}
			else {
				/* We need to parse json like quoted string */
				if (!rspamd_cl_lex_json_string (parser, chunk, err)) {
					return FALSE;
				}
				end = chunk->pos - 1;
				p = chunk->pos;
				break;
			}
		}
	}

	if (p >= chunk->end) {
		rspamd_cl_set_err (chunk, RSPAMD_CL_ESYNTAX, "unfinished key", err);
		return FALSE;
	}

	/* We are now at the end of the key, need to parse the rest */
	while (p < chunk->end) {
		if (g_ascii_isspace (*p)) {
			rspamd_cl_chunk_skipc (chunk, *p);
			p ++;
		}
		else if (*p == '=') {
			if (!got_eq && !got_semicolon) {
				rspamd_cl_chunk_skipc (chunk, *p);
				p ++;
				got_eq = TRUE;
			}
			else {
				rspamd_cl_set_err (chunk, RSPAMD_CL_ESYNTAX, "unexpected '=' character", err);
				return FALSE;
			}
		}
		else if (*p == ':') {
			if (!got_eq && !got_semicolon) {
				rspamd_cl_chunk_skipc (chunk, *p);
				p ++;
				got_semicolon = TRUE;
			}
			else {
				rspamd_cl_set_err (chunk, RSPAMD_CL_ESYNTAX, "unexpected ':' character", err);
				return FALSE;
			}
		}
		else if (rspamd_cl_lex_is_comment (p[0], p[1])) {
			/* Check for comment */
			if (!rspamd_cl_skip_comments (parser, err)) {
				return FALSE;
			}
			p = chunk->pos;
		}
		else {
			/* Start value */
			break;
		}
	}

	if (p >= chunk->end) {
		rspamd_cl_set_err (chunk, RSPAMD_CL_ESYNTAX, "unfinished key", err);
		return FALSE;
	}

	/* Create a new object */
	nobj = rspamd_cl_object_new ();
	nobj->key = g_malloc (end - c + 1);
	if (parser->flags & RSPAMD_CL_FLAG_KEY_LOWERCASE) {
		rspamd_strlcpy_tolower (nobj->key, c, end - c + 1);
	}
	else {
		rspamd_strlcpy (nobj->key, c, end - c + 1);
	}

	if (got_quote) {
		rspamd_cl_unescape_json_string (nobj->key);
	}

	container = parser->stack->obj->value.ov;
	HASH_FIND_STR (container, nobj->key, tobj);
	if (tobj != NULL) {
		/* Just insert a new object as the next element */
		LL_PREPEND (tobj, nobj);
		HASH_DELETE (hh, container, tobj);
	}

	HASH_ADD_KEYPTR (hh, container, nobj->key, strlen (nobj->key), nobj);
	parser->stack->obj->value.ov = container;

	parser->cur_obj = nobj;

	return TRUE;
}

/**
 * Parse a cl string
 * @param parser
 * @param chunk
 * @param err
 * @return TRUE if a key has been parsed
 */
static gboolean
rspamd_cl_parse_string_value (struct rspamd_cl_parser *parser,
		struct rspamd_cl_chunk *chunk, GError **err)
{
	const guchar *p;

	p = chunk->pos;

	while (p < chunk->end) {
		if (rspamd_cl_lex_is_atom_end (*p) || rspamd_cl_lex_is_comment (p[0], p[1])) {
			break;
		}
		rspamd_cl_chunk_skipc (chunk, *p);
		p ++;
	}

	if (p >= chunk->end) {
		rspamd_cl_set_err (chunk, RSPAMD_CL_ESYNTAX, "unfinished value", err);
		return FALSE;
	}

	return TRUE;
}

/**
 * Check whether a given string contains a boolean value
 * @param obj object to set
 * @param start start of a string
 * @param len length of a string
 * @return TRUE if a string is a boolean value
 */
static inline gboolean
rspamd_cl_maybe_parse_boolean (rspamd_cl_object_t *obj, const guchar *start, gsize len)
{
	const guchar *p = start;
	gboolean ret = FALSE, val = FALSE;

	if (len == 5) {
		if (g_ascii_tolower (p[0]) == 'f' && g_ascii_strncasecmp (p, "false", 5) == 0) {
			ret = TRUE;
			val = FALSE;
		}
	}
	else if (len == 4) {
		if (g_ascii_tolower (p[0]) == 't' && g_ascii_strncasecmp (p, "true", 4) == 0) {
			ret = TRUE;
			val = TRUE;
		}
	}
	else if (len == 3) {
		if (g_ascii_tolower (p[0]) == 'y' && g_ascii_strncasecmp (p, "yes", 3) == 0) {
			ret = TRUE;
			val = TRUE;
		}
		if (g_ascii_tolower (p[0]) == 'o' && g_ascii_strncasecmp (p, "off", 3) == 0) {
			ret = TRUE;
			val = FALSE;
		}
	}
	else if (len == 2) {
		if (g_ascii_tolower (p[0]) == 'n' && g_ascii_strncasecmp (p, "no", 2) == 0) {
			ret = TRUE;
			val = FALSE;
		}
		else if (g_ascii_tolower (p[0]) == 'o' && g_ascii_strncasecmp (p, "on", 2) == 0) {
			ret = TRUE;
			val = TRUE;
		}
	}

	if (ret) {
		obj->type = RSPAMD_CL_BOOLEAN;
		obj->value.iv = val;
	}

	return ret;
}

/**
 * Handle value data
 * @param parser
 * @param chunk
 * @param err
 * @return
 */
static gboolean
rspamd_cl_parse_value (struct rspamd_cl_parser *parser, struct rspamd_cl_chunk *chunk, GError **err)
{
	const guchar *p, *c;
	struct rspamd_cl_stack *st;
	rspamd_cl_object_t *obj = NULL;
	guint stripped_spaces;

	p = chunk->pos;

	while (p < chunk->end) {
		if (obj == NULL) {
			if (parser->stack->obj->type == RSPAMD_CL_ARRAY) {
				/* Object must be allocated */
				obj = rspamd_cl_object_new ();
				parser->cur_obj = obj;
				LL_PREPEND (parser->stack->obj->value.ov, parser->cur_obj);
			}
			else {
				/* Object has been already allocated */
				obj = parser->cur_obj;
			}
		}
		c = p;
		switch (*p) {
		case '"':
			rspamd_cl_chunk_skipc (chunk, *p);
			p ++;
			if (!rspamd_cl_lex_json_string (parser, chunk, err)) {
				return FALSE;
			}
			obj->value.sv = g_malloc (chunk->pos - c - 1);
			rspamd_strlcpy (obj->value.sv, c + 1, chunk->pos - c - 1);
			rspamd_cl_unescape_json_string (obj->value.sv);
			obj->type = RSPAMD_CL_STRING;
			parser->state = RSPAMD_RCL_STATE_AFTER_VALUE;
			p = chunk->pos;
			return TRUE;
			break;
		case '{':
			/* We have a new object */
			obj->type = RSPAMD_CL_OBJECT;

			parser->state = RSPAMD_RCL_STATE_KEY;
			st = g_slice_alloc0 (sizeof (struct rspamd_cl_stack));
			st->obj = obj;
			LL_PREPEND (parser->stack, st);
			parser->cur_obj = obj;

			rspamd_cl_chunk_skipc (chunk, *p);
			p ++;
			return TRUE;
			break;
		case '[':
			/* We have a new array */
			obj = parser->cur_obj;
			obj->type = RSPAMD_CL_ARRAY;

			parser->state = RSPAMD_RCL_STATE_VALUE;
			st = g_slice_alloc0 (sizeof (struct rspamd_cl_stack));
			st->obj = obj;
			LL_PREPEND (parser->stack, st);
			parser->cur_obj = obj;

			rspamd_cl_chunk_skipc (chunk, *p);
			p ++;
			return TRUE;
			break;
		default:
			/* Skip any spaces and comments */
			if (g_ascii_isspace (*p) ||
					rspamd_cl_lex_is_comment (p[0], p[1])) {
				while (p < chunk->end && g_ascii_isspace (*p)) {
					rspamd_cl_chunk_skipc (chunk, *p);
					p ++;
				}
				if (!rspamd_cl_skip_comments (parser, err)) {
					return FALSE;
				}
				p = chunk->pos;
				continue;
			}
			/* Parse atom */
			if (rcl_test_character (*p, RCL_CHARACTER_VALUE_DIGIT_START)) {
				if (!rspamd_cl_lex_number (parser, chunk, obj, err)) {
					if (parser->state == RSPAMD_RCL_STATE_ERROR) {
						return FALSE;
					}
					if (!rspamd_cl_parse_string_value (parser, chunk, err)) {
						return FALSE;
					}
					if (!rspamd_cl_maybe_parse_boolean (obj, c, chunk->pos - c)) {
						/* Cut trailing spaces */
						stripped_spaces = 0;
						while (g_ascii_isspace (*(chunk->pos - 1 - stripped_spaces))) {
							stripped_spaces ++;
						}
						obj->value.sv = g_malloc (chunk->pos - c + 1 - stripped_spaces);
						rspamd_strlcpy (obj->value.sv, c, chunk->pos - c + 1 - stripped_spaces);
						rspamd_cl_unescape_json_string (obj->value.sv);
						obj->type = RSPAMD_CL_STRING;
					}
					parser->state = RSPAMD_RCL_STATE_AFTER_VALUE;
					return TRUE;
				}
				else {
					parser->state = RSPAMD_RCL_STATE_AFTER_VALUE;
					return TRUE;
				}
			}
			else {
				if (!rspamd_cl_parse_string_value (parser, chunk, err)) {
					return FALSE;
				}
				if (!rspamd_cl_maybe_parse_boolean (obj, c, chunk->pos - c)) {
					obj->value.sv = g_malloc (chunk->pos - c + 1);
					rspamd_strlcpy (obj->value.sv, c, chunk->pos - c + 1);
					rspamd_cl_unescape_json_string (obj->value.sv);
					obj->type = RSPAMD_CL_STRING;
				}
				parser->state = RSPAMD_RCL_STATE_AFTER_VALUE;
				return TRUE;
			}
			p = chunk->pos;
			break;
		}
	}

	return TRUE;
}

/**
 * Handle after value data
 * @param parser
 * @param chunk
 * @param err
 * @return
 */
static gboolean
rspamd_cl_parse_after_value (struct rspamd_cl_parser *parser, struct rspamd_cl_chunk *chunk, GError **err)
{
	const guchar *p;
	gboolean got_sep = FALSE, got_comma = FALSE, got_semicolon = FALSE;
	struct rspamd_cl_stack *st;

	p = chunk->pos;

	while (p < chunk->end) {
		if (*p == ' ' || *p == '\t') {
			/* Skip whitespaces */
			rspamd_cl_chunk_skipc (chunk, *p);
			p ++;
		}
		else if (rspamd_cl_lex_is_comment (p[0], p[1])) {
			/* Skip comment */
			if (!rspamd_cl_skip_comments (parser, err)) {
				return FALSE;
			}
			/* Treat comment as a separator */
			got_sep = TRUE;
			p = chunk->pos;
		}
		else if (*p == ',') {
			/* Got a separator */
			got_sep = TRUE;
			if (got_comma || got_semicolon) {
				rspamd_cl_set_err (chunk, RSPAMD_CL_ESYNTAX, "unexpected comma detected", err);
				return FALSE;
			}
			got_comma = TRUE;
			rspamd_cl_chunk_skipc (chunk, *p);
			p ++;
		}
		else if (*p == ';') {
			/* Got a separator */
			got_sep = TRUE;
			if (got_comma || got_semicolon) {
				rspamd_cl_set_err (chunk, RSPAMD_CL_ESYNTAX, "unexpected semicolon detected", err);
				return FALSE;
			}
			got_semicolon = TRUE;
			rspamd_cl_chunk_skipc (chunk, *p);
			p ++;
		}
		else if (*p == '\n') {
			got_sep = TRUE;
			rspamd_cl_chunk_skipc (chunk, *p);
			p ++;
		}
		else if (*p == '}' || *p == ']') {
			if (parser->stack == NULL) {
				rspamd_cl_set_err (chunk, RSPAMD_CL_ESYNTAX, "unexpected } detected", err);
				return FALSE;
			}
			if ((*p == '}' && parser->stack->obj->type == RSPAMD_CL_OBJECT) ||
					(*p == ']' && parser->stack->obj->type == RSPAMD_CL_ARRAY)) {
				/* Pop object from a stack */

				st = parser->stack;
				parser->stack = st->next;
				g_slice_free1 (sizeof (struct rspamd_cl_stack), st);
			}
			else {
				rspamd_cl_set_err (chunk, RSPAMD_CL_ESYNTAX, "unexpected terminating symbol detected", err);
				return FALSE;
			}

			if (parser->stack == NULL) {
				/* Ignore everything after a top object */
				return TRUE;
			}
			else {
				rspamd_cl_chunk_skipc (chunk, *p);
				p ++;
			}
			got_sep = TRUE;
		}
		else {
			/* Anything else */
			if (!got_sep) {
				rspamd_cl_set_err (chunk, RSPAMD_CL_ESYNTAX, "delimiter is missing", err);
				return FALSE;
			}
			return TRUE;
		}
	}

	return TRUE;
}

/**
 * Handle macro data
 * @param parser
 * @param chunk
 * @param err
 * @return
 */
static gboolean
rspamd_cl_parse_macro_value (struct rspamd_cl_parser *parser,
		struct rspamd_cl_chunk *chunk, struct rspamd_cl_macro *macro,
		guchar const **macro_start, gsize *macro_len, GError **err)
{
	const guchar *p, *c;

	p = chunk->pos;

	switch (*p) {
	case '"':
		/* We have macro value encoded in quotes */
		c = p;
		rspamd_cl_chunk_skipc (chunk, *p);
		p ++;
		if (!rspamd_cl_lex_json_string (parser, chunk, err)) {
			return FALSE;
		}

		*macro_start = c + 1;
		*macro_len = chunk->pos - c - 2;
		p = chunk->pos;
		break;
	case '{':
		/* We got a multiline macro body */
		rspamd_cl_chunk_skipc (chunk, *p);
		p ++;
		/* Skip spaces at the beginning */
		while (p < chunk->end) {
			if (g_ascii_isspace (*p)) {
				rspamd_cl_chunk_skipc (chunk, *p);
				p ++;
			}
			else {
				break;
			}
		}
		c = p;
		while (p < chunk->end) {
			if (*p == '}') {
				break;
			}
			rspamd_cl_chunk_skipc (chunk, *p);
			p ++;
		}
		*macro_start = c;
		*macro_len = p - c;
		rspamd_cl_chunk_skipc (chunk, *p);
		p ++;
		break;
	default:
		/* Macro is not enclosed in quotes or braces */
		c = p;
		while (p < chunk->end) {
			if (rspamd_cl_lex_is_atom_end (*p)) {
				break;
			}
			rspamd_cl_chunk_skipc (chunk, *p);
			p ++;
		}
		*macro_start = c;
		*macro_len = p - c;
		break;
	}

	/* We are at the end of a macro */
	/* Skip ';' and space characters and return to previous state */
	while (p < chunk->end) {
		if (!g_ascii_isspace (*p) && *p != ';') {
			break;
		}
		rspamd_cl_chunk_skipc (chunk, *p);
		p ++;
	}
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
rspamd_cl_state_machine (struct rspamd_cl_parser *parser, GError **err)
{
	rspamd_cl_object_t *obj;
	struct rspamd_cl_chunk *chunk = parser->chunks;
	struct rspamd_cl_stack *st;
	const guchar *p, *c, *macro_start = NULL;
	gsize macro_len = 0;
	struct rspamd_cl_macro *macro = NULL;

	p = chunk->pos;
	while (chunk->pos < chunk->end) {
		switch (parser->state) {
		case RSPAMD_RCL_STATE_INIT:
			/*
			 * At the init state we can either go to the parse array or object
			 * if we got [ or { correspondingly or can just treat new data as
			 * a key of newly created object
			 */
			if (!rspamd_cl_skip_comments (parser, err)) {
				parser->prev_state = parser->state;
				parser->state = RSPAMD_RCL_STATE_ERROR;
				return FALSE;
			}
			else {
				p = chunk->pos;
				obj = rspamd_cl_object_new ();
				if (*p == '[') {
					parser->state = RSPAMD_RCL_STATE_VALUE;
					obj->type = RSPAMD_CL_ARRAY;
					rspamd_cl_chunk_skipc (chunk, *p);
					p ++;
				}
				else {
					parser->state = RSPAMD_RCL_STATE_KEY;
					obj->type = RSPAMD_CL_OBJECT;
					if (*p == '{') {
						rspamd_cl_chunk_skipc (chunk, *p);
						p ++;
					}
				};
				parser->cur_obj = obj;
				parser->top_obj = obj;
				st = g_slice_alloc0 (sizeof (struct rspamd_cl_stack));
				st->obj = obj;
				LL_PREPEND (parser->stack, st);
			}
			break;
		case RSPAMD_RCL_STATE_KEY:
			/* Skip any spaces */
			while (p < chunk->end && g_ascii_isspace (*p)) {
				rspamd_cl_chunk_skipc (chunk, *p);
				p ++;
			}
			if (*p == '}') {
				/* We have the end of an object */
				parser->state = RSPAMD_RCL_STATE_AFTER_VALUE;
				continue;
			}
			if (!rspamd_cl_parse_key (parser, chunk, err)) {
				parser->prev_state = parser->state;
				parser->state = RSPAMD_RCL_STATE_ERROR;
				return FALSE;
			}
			if (parser->state != RSPAMD_RCL_STATE_MACRO_NAME) {
				parser->state = RSPAMD_RCL_STATE_VALUE;
			}
			else {
				c = chunk->pos;
			}
			p = chunk->pos;
			break;
		case RSPAMD_RCL_STATE_VALUE:
			/* We need to check what we do have */
			if (!rspamd_cl_parse_value (parser, chunk, err)) {
				parser->prev_state = parser->state;
				parser->state = RSPAMD_RCL_STATE_ERROR;
				return FALSE;
			}
			/* State is set in rspamd_cl_parse_value call */
			p = chunk->pos;
			break;
		case RSPAMD_RCL_STATE_AFTER_VALUE:
			if (!rspamd_cl_parse_after_value (parser, chunk, err)) {
				parser->prev_state = parser->state;
				parser->state = RSPAMD_RCL_STATE_ERROR;
				return FALSE;
			}
			if (parser->stack != NULL) {
				if (parser->stack->obj->type == RSPAMD_CL_OBJECT) {
					parser->state = RSPAMD_RCL_STATE_KEY;
				}
				else {
					/* Array */
					parser->state = RSPAMD_RCL_STATE_VALUE;
				}
			}
			else {
				/* Skip everything at the end */
				return TRUE;
			}
			p = chunk->pos;
			break;
		case RSPAMD_RCL_STATE_MACRO_NAME:
			if (!g_ascii_isspace (*p)) {
				rspamd_cl_chunk_skipc (chunk, *p);
				p ++;
			}
			else if (p - c > 0) {
				/* We got macro name */
				HASH_FIND (hh, parser->macroes, c, p - c, macro);
				if (macro == NULL) {
					rspamd_cl_set_err (chunk, RSPAMD_CL_EMACRO, "unknown macro", err);
					parser->state = RSPAMD_RCL_STATE_ERROR;
					return FALSE;
				}
				/* Now we need to skip all spaces */
				while (p < chunk->end) {
					if (!g_ascii_isspace (*p)) {
						if (rspamd_cl_lex_is_comment (p[0], p[1])) {
							/* Skip comment */
							if (!rspamd_cl_skip_comments (parser, err)) {
								return FALSE;
							}
							p = chunk->pos;
						}
						break;
					}
					rspamd_cl_chunk_skipc (chunk, *p);
					p ++;
				}
				parser->state = RSPAMD_RCL_STATE_MACRO;
			}
			break;
		case RSPAMD_RCL_STATE_MACRO:
			if (!rspamd_cl_parse_macro_value (parser, chunk, macro,
					&macro_start, &macro_len, err)) {
				parser->prev_state = parser->state;
				parser->state = RSPAMD_RCL_STATE_ERROR;
				return FALSE;
			}
			parser->state = parser->prev_state;
			if (!macro->handler (macro_start, macro_len, macro->ud, err)) {
				return FALSE;
			}
			p = chunk->pos;
			break;
		default:
			/* TODO: add all states */
			return FALSE;
		}
	}

	return TRUE;
}

struct rspamd_cl_parser*
rspamd_cl_parser_new (gint flags)
{
	struct rspamd_cl_parser *new;

	new = g_slice_alloc0 (sizeof (struct rspamd_cl_parser));

	rspamd_cl_parser_register_macro (new, "include", rspamd_cl_include_handler, new);
	rspamd_cl_parser_register_macro (new, "includes", rspamd_cl_includes_handler, new);

	new->flags = flags;

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
	struct rspamd_cl_chunk *chunk;

	if (parser->state != RSPAMD_RCL_STATE_ERROR) {
		chunk = g_slice_alloc (sizeof (struct rspamd_cl_chunk));
		chunk->begin = data;
		chunk->remain = len;
		chunk->pos = chunk->begin;
		chunk->end = chunk->begin + len;
		chunk->line = 1;
		chunk->column = 0;
		LL_PREPEND (parser->chunks, chunk);
		parser->recursion ++;
		if (parser->recursion > RCL_MAX_RECURSION) {
			g_set_error (err, RCL_ERROR, RSPAMD_CL_ERECURSION, "maximum include nesting limit is reached: %d",
					parser->recursion);
			return FALSE;
		}
		return rspamd_cl_state_machine (parser, err);
	}

	g_set_error (err, RCL_ERROR, RSPAMD_CL_ESTATE, "a parser is in an invalid state");

	return FALSE;
}
