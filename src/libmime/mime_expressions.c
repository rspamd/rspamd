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
#include <contrib/libucl/ucl.h>
#include "config.h"
#include "util.h"
#include "cfg_file.h"
#include "rspamd.h"
#include "message.h"
#include "mime_expressions.h"
#include "libserver/html/html.h"
#include "lua/lua_common.h"
#include "utlist.h"

gboolean rspamd_compare_encoding (struct rspamd_task *task,
								  GArray * args,
								  void *unused);
gboolean rspamd_header_exists (struct rspamd_task *task,
							   GArray * args,
							   void *unused);
gboolean rspamd_parts_distance (struct rspamd_task *task,
								GArray * args,
								void *unused);
gboolean rspamd_recipients_distance (struct rspamd_task *task,
									 GArray * args,
									 void *unused);
gboolean rspamd_has_only_html_part (struct rspamd_task *task,
									GArray * args,
									void *unused);
gboolean rspamd_is_recipients_sorted (struct rspamd_task *task,
									  GArray * args,
									  void *unused);
gboolean rspamd_compare_transfer_encoding (struct rspamd_task *task,
										   GArray * args,
										   void *unused);
gboolean rspamd_is_html_balanced (struct rspamd_task *task,
								  GArray * args,
								  void *unused);
gboolean rspamd_has_html_tag (struct rspamd_task *task,
							  GArray * args,
							  void *unused);
gboolean rspamd_has_fake_html (struct rspamd_task *task,
							   GArray * args,
							   void *unused);
static gboolean rspamd_raw_header_exists (struct rspamd_task *task,
										  GArray * args,
										  void *unused);
static gboolean rspamd_check_smtp_data (struct rspamd_task *task,
										GArray * args,
										void *unused);
static gboolean rspamd_content_type_is_type (struct rspamd_task * task,
											 GArray * args,
											 void *unused);
static gboolean rspamd_content_type_is_subtype (struct rspamd_task *task,
												GArray * args,
												void *unused);
static gboolean rspamd_content_type_has_param (struct rspamd_task * task,
											   GArray * args,
											   void *unused);
static gboolean rspamd_content_type_compare_param (struct rspamd_task * task,
												   GArray * args,
												   void *unused);
static gboolean rspamd_has_content_part (struct rspamd_task *task,
										 GArray * args,
										 void *unused);
static gboolean rspamd_has_content_part_len (struct rspamd_task *task,
											 GArray * args,
											 void *unused);
static gboolean rspamd_is_empty_body (struct rspamd_task *task,
									  GArray * args,
									  void *unused);
static gboolean rspamd_has_flag_expr (struct rspamd_task *task,
									  GArray * args,
									  void *unused);
static gboolean rspamd_has_symbol_expr (struct rspamd_task *task,
									  GArray * args,
									  void *unused);

static rspamd_expression_atom_t * rspamd_mime_expr_parse (const gchar *line, gsize len,
		rspamd_mempool_t *pool, gpointer ud, GError **err);
static gdouble rspamd_mime_expr_process (void *ud, rspamd_expression_atom_t *atom);
static gint rspamd_mime_expr_priority (rspamd_expression_atom_t *atom);
static void rspamd_mime_expr_destroy (rspamd_expression_atom_t *atom);

/**
 * Regexp structure
 */
struct rspamd_regexp_atom {
	enum rspamd_re_type type;                       /**< regexp type										*/
	gchar *regexp_text;                             /**< regexp text representation							*/
	rspamd_regexp_t *regexp;                        /**< regexp structure									*/
	union {
		const gchar *header;                        /**< header name for header regexps						*/
		const gchar *selector;                      /**< selector name for lua selector regexp				*/
	} extra;
	gboolean is_test;                               /**< true if this expression must be tested				*/
	gboolean is_strong;                             /**< true if headers search must be case sensitive		*/
	gboolean is_multiple;                           /**< true if we need to match all inclusions of atom	*/
};

/**
 * Rspamd expression function
 */
struct rspamd_function_atom {
	gchar *name;	/**< name of function								*/
	GArray *args;	/**< its args										*/
};

enum rspamd_mime_atom_type {
	MIME_ATOM_REGEXP = 0,
	MIME_ATOM_INTERNAL_FUNCTION,
	MIME_ATOM_LUA_FUNCTION,
	MIME_ATOM_LOCAL_LUA_FUNCTION, /* New style */
};

struct rspamd_mime_atom {
	gchar *str;
	union {
		struct rspamd_regexp_atom *re;
		struct rspamd_function_atom *func;
		const gchar *lua_function;
		gint lua_cbref;
	} d;
	enum rspamd_mime_atom_type type;
};

/*
 * List of internal functions of rspamd
 * Sorted by name to use bsearch
 */
static struct _fl {
	const gchar *name;
	rspamd_internal_func_t func;
	void *user_data;
} rspamd_functions_list[] = {
		{"check_smtp_data", rspamd_check_smtp_data, NULL},
		{"compare_encoding", rspamd_compare_encoding, NULL},
		{"compare_parts_distance", rspamd_parts_distance, NULL},
		{"compare_recipients_distance", rspamd_recipients_distance, NULL},
		{"compare_transfer_encoding", rspamd_compare_transfer_encoding, NULL},
		{"content_type_compare_param", rspamd_content_type_compare_param, NULL},
		{"content_type_has_param", rspamd_content_type_has_param, NULL},
		{"content_type_is_subtype", rspamd_content_type_is_subtype, NULL},
		{"content_type_is_type", rspamd_content_type_is_type, NULL},
		{"has_content_part", rspamd_has_content_part, NULL},
		{"has_content_part_len", rspamd_has_content_part_len, NULL},
		{"has_fake_html", rspamd_has_fake_html, NULL},
		{"has_flag", rspamd_has_flag_expr, NULL},
		{"has_html_tag", rspamd_has_html_tag, NULL},
		{"has_only_html_part", rspamd_has_only_html_part, NULL},
		{"has_symbol", rspamd_has_symbol_expr, NULL},
		{"header_exists", rspamd_header_exists, NULL},
		{"is_empty_body", rspamd_is_empty_body, NULL},
		{"is_html_balanced", rspamd_is_html_balanced, NULL},
		{"is_recipients_sorted", rspamd_is_recipients_sorted, NULL},
		{"raw_header_exists", rspamd_raw_header_exists, NULL},
};

const struct rspamd_atom_subr mime_expr_subr = {
	.parse = rspamd_mime_expr_parse,
	.process = rspamd_mime_expr_process,
	.priority = rspamd_mime_expr_priority,
	.destroy = rspamd_mime_expr_destroy
};

static struct _fl *list_ptr = &rspamd_functions_list[0];
static guint32 functions_number = sizeof (rspamd_functions_list) /
	sizeof (struct _fl);
static gboolean list_allocated = FALSE;

/* Bsearch routine */
static gint
fl_cmp (const void *s1, const void *s2)
{
	struct _fl *fl1 = (struct _fl *)s1;
	struct _fl *fl2 = (struct _fl *)s2;
	return strcmp (fl1->name, fl2->name);
}

static GQuark
rspamd_mime_expr_quark (void)
{
	return g_quark_from_static_string ("mime-expressions");
}

#define TYPE_CHECK(str, type, len) (sizeof(type) - 1 == (len) && rspamd_lc_cmp((str), (type), (len)) == 0)
static gboolean
rspamd_parse_long_option (const gchar *start, gsize len,
		struct rspamd_regexp_atom *a)
{
	gboolean ret = FALSE;

	if (TYPE_CHECK (start, "body", len)) {
		ret = TRUE;
		a->type = RSPAMD_RE_BODY;
	}
	else if (TYPE_CHECK (start, "part", len) ||
			TYPE_CHECK (start, "mime", len)) {
		ret = TRUE;
		a->type = RSPAMD_RE_MIME;
	}
	else if (TYPE_CHECK (start, "raw_part", len) ||
			TYPE_CHECK (start, "raw_mime", len) ||
			TYPE_CHECK (start, "mime_raw", len)) {
		ret = TRUE;
		a->type = RSPAMD_RE_RAWMIME;
	}
	else if (TYPE_CHECK (start, "header", len)) {
		ret = TRUE;
		a->type = RSPAMD_RE_HEADER;
	}
	else if (TYPE_CHECK (start, "mime_header", len) ||
			TYPE_CHECK (start, "header_mime", len)) {
		ret = TRUE;
		a->type = RSPAMD_RE_MIMEHEADER;
	}
	else if (TYPE_CHECK (start, "raw_header", len) ||
			TYPE_CHECK (start, "header_raw", len)) {
		ret = TRUE;
		a->type = RSPAMD_RE_RAWHEADER;
	}
	else if (TYPE_CHECK (start, "all_header", len) ||
			TYPE_CHECK (start, "header_all", len) ||
			TYPE_CHECK (start, "all_headers", len)) {
		ret = TRUE;
		a->type = RSPAMD_RE_ALLHEADER;
	}
	else if (TYPE_CHECK (start, "url", len)) {
		ret = TRUE;
		a->type = RSPAMD_RE_URL;
	}
	else if (TYPE_CHECK (start, "email", len)) {
		ret = TRUE;
		a->type = RSPAMD_RE_EMAIL;
	}
	else if (TYPE_CHECK (start, "sa_body", len)) {
		ret = TRUE;
		a->type = RSPAMD_RE_SABODY;
	}
	else if (TYPE_CHECK (start, "sa_raw_body", len) ||
			TYPE_CHECK (start, "sa_body_raw", len)) {
		ret = TRUE;
		a->type = RSPAMD_RE_SARAWBODY;
	}
	else if (TYPE_CHECK (start, "words", len)) {
		ret = TRUE;
		a->type = RSPAMD_RE_WORDS;
	}
	else if (TYPE_CHECK (start, "raw_words", len)) {
		ret = TRUE;
		a->type = RSPAMD_RE_RAWWORDS;
	}
	else if (TYPE_CHECK (start, "stem_words", len)) {
		ret = TRUE;
		a->type = RSPAMD_RE_STEMWORDS;
	}
	else if (TYPE_CHECK (start, "selector", len)) {
		ret = TRUE;
		a->type = RSPAMD_RE_SELECTOR;
	}

	return ret;
}

/*
 * Rspamd regexp utility functions
 */
static struct rspamd_regexp_atom *
rspamd_mime_expr_parse_regexp_atom (rspamd_mempool_t * pool, const gchar *line,
		struct rspamd_config *cfg)
{
	const gchar *begin, *end, *p, *src, *start, *brace;
	gchar *dbegin, *dend, *extra = NULL;
	struct rspamd_regexp_atom *result;
	GError *err = NULL;
	GString *re_flags;

	if (line == NULL) {
		msg_err_pool ("cannot parse NULL line");
		return NULL;
	}

	src = line;
	result = rspamd_mempool_alloc0 (pool, sizeof (struct rspamd_regexp_atom));
	/* Skip whitespaces */
	while (g_ascii_isspace (*line)) {
		line++;
	}
	if (*line == '\0') {
		msg_warn_pool ("got empty regexp");
		return NULL;
	}

	result->type = RSPAMD_RE_MAX;

	start = line;
	/* First try to find header name */
	begin = strchr (line, '/');
	if (begin != NULL) {
		p = begin;
		end = NULL;
		while (p != line) {
			if (*p == '=') {
				end = p;
				break;
			}
			p--;
		}

		if (end) {
			extra = rspamd_mempool_alloc (pool, end - line + 1);
			rspamd_strlcpy (extra, line, end - line + 1);
			line = end;
		}
	}
	else {
		extra = rspamd_mempool_strdup (pool, line);
		result->type = RSPAMD_RE_MAX;
		line = start;
	}
	/* Find begin of regexp */
	while (*line && *line != '/') {
		line++;
	}
	if (*line != '\0') {
		begin = line + 1;
	}
	else if (extra == NULL) {
		/* Assume that line without // is just a header name */
		extra = rspamd_mempool_strdup (pool, line);
		result->type = RSPAMD_RE_HEADER;
		return result;
	}
	else {
		/* We got header name earlier but have not found // expression, so it is invalid regexp */
		msg_warn_pool (
			"got no header name (eg. header=) but without corresponding regexp, %s",
			src);
		return NULL;
	}
	/* Find end */
	end = begin;
	while (*end && (*end != '/' || *(end - 1) == '\\')) {
		end++;
	}
	if (end == begin || *end != '/') {
		msg_warn_pool ("no trailing / in regexp %s", src);
		return NULL;
	}
	/* Parse flags */
	p = end + 1;
	re_flags = g_string_sized_new (32);

	while (p != NULL) {
		switch (*p) {
		case 'i':
		case 'm':
		case 's':
		case 'x':
		case 'u':
		case 'O':
		case 'r':
		case 'L':
			/* Handled by rspamd_regexp_t */
			g_string_append_c (re_flags, *p);
			p++;
			break;
		case 'o':
			p++;
			break;
		/* Type flags */
		case 'H':
			result->type = RSPAMD_RE_HEADER;
			p++;
			break;
		case 'R':
			result->type = RSPAMD_RE_ALLHEADER;
			p++;
			break;
		case 'B':
			result->type = RSPAMD_RE_MIMEHEADER;
			p++;
			break;
		case 'C':
			result->type = RSPAMD_RE_SABODY;
			p++;
			break;
		case 'D':
			result->type = RSPAMD_RE_SARAWBODY;
			p++;
			break;
		case 'M':
			result->type = RSPAMD_RE_BODY;
			p++;
			break;
		case 'P':
			result->type = RSPAMD_RE_MIME;
			p++;
			break;
		case 'Q':
			result->type = RSPAMD_RE_RAWMIME;
			p++;
			break;
		case 'U':
			result->type = RSPAMD_RE_URL;
			p++;
			break;
		case 'X':
			result->type = RSPAMD_RE_RAWHEADER;
			p++;
			break;
		case '$':
			result->type = RSPAMD_RE_SELECTOR;
			p++;
			break;
		case '{':
			/* Long definition */
			if ((brace = strchr (p + 1, '}')) != NULL) {
				if (!rspamd_parse_long_option (p + 1, brace - (p + 1), result)) {
					msg_warn_pool ("invalid long regexp type: %*s in '%s'",
							(int)(brace - (p + 1)), p + 1, src);
					p = NULL;
				}
				else {
					p = brace + 1;
				}
			}
			else {
				p = NULL;
			}
			break;
		/* Other flags */
		case 'T':
			result->is_test = TRUE;
			p++;
			break;
		case 'S':
			result->is_strong = TRUE;
			p++;
			break;
		case 'A':
			result->is_multiple = TRUE;
			p++;
			break;
		/* Stop flags parsing */
		default:
			p = NULL;
			break;
		}
	}

	if (result->type >= RSPAMD_RE_MAX) {
		if (extra) {
			/* Assume header regexp */
			result->extra.header = extra;
			result->type = RSPAMD_RE_HEADER;
		}
		else {
			msg_err_pool ("could not read regexp: %s, unknown type", src);
			return NULL;
		}
	}

	if ((result->type == RSPAMD_RE_HEADER ||
			result->type == RSPAMD_RE_RAWHEADER ||
			result->type == RSPAMD_RE_MIMEHEADER)) {
		if (extra == NULL) {
			msg_err_pool ("header regexp: '%s' has no header part", src);
			return NULL;
		}
		else {
			result->extra.header = extra;
		}
	}

	if (result->type == RSPAMD_RE_SELECTOR) {
		if (extra == NULL) {
			msg_err_pool ("selector regexp: '%s' has no selector part", src);
			return NULL;
		}
		else {
			result->extra.selector = extra;
		}
	}


	result->regexp_text = rspamd_mempool_strdup (pool, start);
	dbegin = result->regexp_text + (begin - start);
	dend = result->regexp_text + (end - start);
	*dend = '\0';

	result->regexp = rspamd_regexp_new (dbegin, re_flags->str,
			&err);

	g_string_free (re_flags, TRUE);

	if (result->regexp == NULL || err != NULL) {
		msg_warn_pool ("could not read regexp: %s while reading regexp %e",
				src, err);

		if (err) {
			g_error_free (err);
		}

		return NULL;
	}

	if (result->is_multiple) {
		rspamd_regexp_set_maxhits (result->regexp, 0);
	}
	else {
		rspamd_regexp_set_maxhits (result->regexp, 1);
	}

	rspamd_regexp_set_ud (result->regexp, result);

	*dend = '/';

	return result;
}

struct rspamd_function_atom *
rspamd_mime_expr_parse_function_atom (rspamd_mempool_t *pool, const gchar *input)
{
	const gchar *obrace, *ebrace, *p, *c;
	gchar t, *databuf;
	guint len;
	struct rspamd_function_atom *res;
	struct expression_argument arg;
	GError *err = NULL;
	enum {
		start_read_argument = 0,
		in_string,
		in_regexp,
		got_backslash,
		got_comma
	} state, prev_state = 0;

	obrace = strchr (input, '(');
	ebrace = strrchr (input, ')');

	g_assert (obrace != NULL && ebrace != NULL);

	res = rspamd_mempool_alloc0 (pool, sizeof (*res));
	res->name = rspamd_mempool_alloc (pool, obrace - input + 1);
	rspamd_strlcpy (res->name, input, obrace - input + 1);
	res->args = g_array_new (FALSE, FALSE, sizeof (struct expression_argument));

	p = obrace + 1;
	c = p;
	state = start_read_argument;

	/* Read arguments */
	while (p <= ebrace) {
		t = *p;
		switch (state) {
		case start_read_argument:
			if (t == '/') {
				state = in_regexp;
				c = p;
			}
			else if (!g_ascii_isspace (t)) {
				state = in_string;

				if (t == '\'' || t == '\"') {
					c = p + 1;
				}
				else {
					c = p;
				}
			}
			p ++;
			break;
		case in_regexp:
			if (t == '\\') {
				state = got_backslash;
				prev_state = in_regexp;
			}
			else if (t == ',' || p == ebrace) {
				len = p - c + 1;
				databuf = rspamd_mempool_alloc (pool, len);
				rspamd_strlcpy (databuf, c, len);
				arg.type = EXPRESSION_ARGUMENT_REGEXP;
				arg.data = rspamd_regexp_cache_create (NULL, databuf, NULL, &err);

				if (arg.data == NULL) {
					/* Fallback to string */
					msg_warn ("cannot parse slashed argument %s as regexp: %s",
							databuf, err->message);
					g_error_free (err);
					arg.type = EXPRESSION_ARGUMENT_NORMAL;
					arg.data = databuf;
				}

				g_array_append_val (res->args, arg);
				state = got_comma;
			}
			p ++;
			break;
		case in_string:
			if (t == '\\') {
				state = got_backslash;
				prev_state = in_string;
			}
			else if (t == ',' || p == ebrace) {
				if (*(p - 1) == '\'' || *(p - 1) == '\"') {
					len = p - c;
				}
				else {
					len = p - c + 1;
				}

				databuf = rspamd_mempool_alloc (pool, len);
				rspamd_strlcpy (databuf, c, len);
				arg.type = EXPRESSION_ARGUMENT_NORMAL;
				arg.data = databuf;
				g_array_append_val (res->args, arg);
				state = got_comma;
			}
			p ++;
			break;
		case got_backslash:
			state = prev_state;
			p ++;
			break;
		case got_comma:
			state = start_read_argument;
			break;
		}
	}

	return res;
}

static rspamd_expression_atom_t *
rspamd_mime_expr_parse (const gchar *line, gsize len,
		rspamd_mempool_t *pool, gpointer ud, GError **err)
{
	rspamd_expression_atom_t *a = NULL;
	struct rspamd_mime_atom *mime_atom = NULL;
	const gchar *p, *end, *c = NULL;
	struct rspamd_mime_expr_ud *real_ud = (struct rspamd_mime_expr_ud *)ud;
	struct rspamd_config *cfg;
	rspamd_regexp_t *own_re;
	gchar t;
	gint type = MIME_ATOM_REGEXP, obraces = 0, ebraces = 0;
	enum {
		in_header = 0,
		got_slash,
		in_regexp,
		got_backslash,
		got_second_slash,
		in_flags,
		in_flags_brace,
		got_obrace,
		in_function,
		in_local_function,
		got_ebrace,
		end_atom,
		bad_atom
	} state = 0, prev_state = 0;

	p = line;
	end = p + len;
	cfg = real_ud->cfg;

	while (p < end) {
		t = *p;

		switch (state) {
		case in_header:
			if (t == '/') {
				/* Regexp */
				state = got_slash;
			}
			else if (t == '(') {
				/* Function */
				state = got_obrace;
			}
			else if (!g_ascii_isalnum (t) && t != '_' && t != '-' && t != '=') {
				if (t == ':') {
					if (p - line == 3 && memcmp (line, "lua", 3) == 0) {
						type = MIME_ATOM_LOCAL_LUA_FUNCTION;
						state = in_local_function;
						c = p + 1;
					}
				}
				else {
					/* Likely lua function, identified by just a string */
					type = MIME_ATOM_LUA_FUNCTION;
					state = end_atom;
					/* Do not increase p */
					continue;
				}
			}
			else if (g_ascii_isspace (t)) {
				state = bad_atom;
			}
			p ++;
			break;
		case got_slash:
			state = in_regexp;
			break;
		case in_regexp:
			if (t == '\\') {
				state = got_backslash;
				prev_state = in_regexp;
			}
			else if (t == '/') {
				state = got_second_slash;
			}
			p ++;
			break;
		case got_second_slash:
			state = in_flags;
			break;
		case in_flags:
			if (t == '{') {
				state = in_flags_brace;
				p ++;
			}
			else if (!g_ascii_isalpha (t) && t != '$') {
				state = end_atom;
			}
			else {
				p ++;
			}
			break;
		case in_flags_brace:
			if (t == '}') {
				state = in_flags;
			}
			p ++;
			break;
		case got_backslash:
			state = prev_state;
			p ++;
			break;
		case got_obrace:
			state = in_function;
			type = MIME_ATOM_INTERNAL_FUNCTION;
			obraces ++;
			break;
		case in_function:
			if (t == '\\') {
				state = got_backslash;
				prev_state = in_function;
			}
			else if (t == '(') {
				obraces ++;
			}
			else if (t == ')') {
				ebraces ++;
				if (ebraces == obraces) {
					state = got_ebrace;
				}
			}
			p ++;
			break;
		case in_local_function:
			if (!(g_ascii_isalnum (t) || t == '-' || t == '_')) {
				g_assert (c != NULL);
				state = end_atom;
			}
			else {
				p++;
			}
			break;
		case got_ebrace:
			state = end_atom;
			break;
		case bad_atom:
			g_set_error (err, rspamd_mime_expr_quark(), 100, "cannot parse"
					" mime atom '%s' when reading symbol '%c' at offset %d, "
					"near %*.s", line, t, (gint)(p - line),
					(gint)MIN (end - p, 10), p);
			return NULL;
		case end_atom:
			goto set;
		}
	}
set:

	if (p - line == 0 || (state != got_ebrace && state != got_second_slash &&
			state != in_flags && state != end_atom)) {
		g_set_error (err, rspamd_mime_expr_quark(), 200, "incomplete or empty"
				" mime atom");
		return NULL;
	}

	mime_atom = rspamd_mempool_alloc (pool, sizeof (*mime_atom));
	mime_atom->type = type;
	mime_atom->str = rspamd_mempool_alloc (pool, p - line + 1);
	rspamd_strlcpy (mime_atom->str, line, p - line + 1);

	if (type == MIME_ATOM_REGEXP) {
		mime_atom->d.re = rspamd_mime_expr_parse_regexp_atom (pool,
				mime_atom->str, cfg);
		if (mime_atom->d.re == NULL) {
			g_set_error (err, rspamd_mime_expr_quark(), 200,
					"cannot parse regexp '%s'",
					mime_atom->str);
			goto err;
		}
		else {
			gint lua_cbref = -1;

			/* Check regexp condition */
			if (real_ud->conf_obj != NULL) {
				const ucl_object_t *re_conditions = ucl_object_lookup (real_ud->conf_obj,
						"re_conditions");

				if (re_conditions != NULL) {
					if (ucl_object_type (re_conditions) != UCL_OBJECT) {
						g_set_error (err, rspamd_mime_expr_quark (), 320,
								"re_conditions is not a table for '%s'",
								mime_atom->str);
						goto err;
					}

					const ucl_object_t *function_obj = ucl_object_lookup (re_conditions,
							mime_atom->str);

					if (function_obj != NULL) {
						if (ucl_object_type (function_obj) != UCL_USERDATA) {
							g_set_error (err, rspamd_mime_expr_quark (), 320,
									"condition for '%s' is invalid, must be function",
									mime_atom->str);
							goto err;
						}

						struct ucl_lua_funcdata *fd = function_obj->value.ud;

						lua_cbref = fd->idx;
					}
				}
			}

			if (lua_cbref != -1) {
				msg_info_config ("added condition for regexp %s", mime_atom->str);
			}

			/* Register new item in the cache */
			if (mime_atom->d.re->type == RSPAMD_RE_HEADER ||
					mime_atom->d.re->type == RSPAMD_RE_RAWHEADER ||
					mime_atom->d.re->type == RSPAMD_RE_MIMEHEADER) {

				if (mime_atom->d.re->extra.header != NULL) {
					own_re = mime_atom->d.re->regexp;
					mime_atom->d.re->regexp = rspamd_re_cache_add (cfg->re_cache,
							mime_atom->d.re->regexp,
							mime_atom->d.re->type,
							mime_atom->d.re->extra.header,
							strlen (mime_atom->d.re->extra.header) + 1,
							lua_cbref);
					/* Pass ownership to the cache */
					rspamd_regexp_unref (own_re);
				}
				else {
					/* We have header regexp, but no header name is detected */
					g_set_error (err,
							rspamd_mime_expr_quark (),
							200,
							"no header name in header regexp: '%s'",
							mime_atom->str);
					rspamd_regexp_unref (mime_atom->d.re->regexp);
					goto err;
				}

			}
			else if (mime_atom->d.re->type == RSPAMD_RE_SELECTOR) {
				if (mime_atom->d.re->extra.selector != NULL) {
					own_re = mime_atom->d.re->regexp;
					mime_atom->d.re->regexp = rspamd_re_cache_add (cfg->re_cache,
							mime_atom->d.re->regexp,
							mime_atom->d.re->type,
							mime_atom->d.re->extra.selector,
							strlen (mime_atom->d.re->extra.selector) + 1,
							lua_cbref);
					/* Pass ownership to the cache */
					rspamd_regexp_unref (own_re);
				}
				else {
					/* We have selector regexp, but no selector name is detected */
					g_set_error (err,
							rspamd_mime_expr_quark (),
							200,
							"no selector name in selector regexp: '%s'",
							mime_atom->str);
					rspamd_regexp_unref (mime_atom->d.re->regexp);
					goto err;
				}
			}
			else {
				own_re = mime_atom->d.re->regexp;
				mime_atom->d.re->regexp = rspamd_re_cache_add (cfg->re_cache,
						mime_atom->d.re->regexp,
						mime_atom->d.re->type,
						NULL,
						0,
						lua_cbref);
				/* Pass ownership to the cache */
				rspamd_regexp_unref (own_re);
			}
		}
	}
	else if (type == MIME_ATOM_LUA_FUNCTION) {
		mime_atom->d.lua_function = mime_atom->str;

		lua_getglobal (cfg->lua_state, mime_atom->str);

		if (lua_type (cfg->lua_state, -1) != LUA_TFUNCTION) {
			g_set_error (err, rspamd_mime_expr_quark(), 200,
					"no such lua function '%s'",
					mime_atom->str);
			lua_pop (cfg->lua_state, 1);

			goto err;
		}

		lua_pop (cfg->lua_state, 1);
	}
	else if (type == MIME_ATOM_LOCAL_LUA_FUNCTION) {
		/* p pointer is set to the start of Lua function name */

		if (real_ud->conf_obj == NULL) {
			g_set_error (err, rspamd_mime_expr_quark(), 300,
					"no config object for '%s'",
					mime_atom->str);
			goto err;
		}

		const ucl_object_t *functions = ucl_object_lookup (real_ud->conf_obj,
				"functions");

		if (functions == NULL) {
			g_set_error (err, rspamd_mime_expr_quark(), 310,
					"no functions defined for '%s'",
					mime_atom->str);
			goto err;
		}

		if (ucl_object_type (functions) != UCL_OBJECT) {
			g_set_error (err, rspamd_mime_expr_quark(), 320,
					"functions is not a table for '%s'",
					mime_atom->str);
			goto err;
		}

		const ucl_object_t *function_obj;

		function_obj = ucl_object_lookup_len (functions, c,
				p - c);

		if (function_obj == NULL) {
			g_set_error (err, rspamd_mime_expr_quark(), 320,
					"function %*.s is not found for '%s'",
					(int)(p - c), c, mime_atom->str);
			goto err;
		}

		if (ucl_object_type (function_obj) != UCL_USERDATA) {
			g_set_error (err, rspamd_mime_expr_quark(), 320,
					"function %*.s has invalid type for '%s'",
					(int)(p - c), c, mime_atom->str);
			goto err;
		}

		struct ucl_lua_funcdata *fd = function_obj->value.ud;

		mime_atom->d.lua_cbref = fd->idx;
	}
	else {
		mime_atom->d.func = rspamd_mime_expr_parse_function_atom (pool,
				mime_atom->str);
		if (mime_atom->d.func == NULL) {
			g_set_error (err, rspamd_mime_expr_quark(), 200,
					"cannot parse function '%s'",
					mime_atom->str);
			goto err;
		}
	}

	a = rspamd_mempool_alloc0 (pool, sizeof (*a));
	a->len = p - line;
	a->priority = 0;
	a->data = mime_atom;

	return a;

err:

	return NULL;
}

static gint
rspamd_mime_expr_process_regexp (struct rspamd_regexp_atom *re,
		struct rspamd_task *task)
{
	gint ret;

	if (re == NULL) {
		msg_info_task ("invalid regexp passed");
		return 0;
	}

	if (re->type == RSPAMD_RE_HEADER || re->type == RSPAMD_RE_RAWHEADER) {
		ret = rspamd_re_cache_process (task,
				re->regexp,
				re->type,
				re->extra.header,
				strlen (re->extra.header),
				re->is_strong);
	}
	else if (re->type == RSPAMD_RE_SELECTOR) {
		ret = rspamd_re_cache_process (task,
				re->regexp,
				re->type,
				re->extra.selector,
				strlen (re->extra.selector),
				re->is_strong);
	}
	else {
		ret = rspamd_re_cache_process (task,
				re->regexp,
				re->type,
				NULL,
				0,
				re->is_strong);
	}

	if (re->is_test) {
		msg_info_task ("test %s regexp '%s' returned %d",
				rspamd_re_cache_type_to_string (re->type),
				re->regexp_text, ret);
	}

	return ret;
}


static gint
rspamd_mime_expr_priority (rspamd_expression_atom_t *atom)
{
	struct rspamd_mime_atom *mime_atom = atom->data;
	gint ret = 0;

	switch (mime_atom->type) {
	case MIME_ATOM_INTERNAL_FUNCTION:
		/* Prioritize internal functions slightly */
		ret = RSPAMD_EXPRESSION_MAX_PRIORITY - RSPAMD_EXPRESSION_MAX_PRIORITY / 8;
		break;
	case MIME_ATOM_LUA_FUNCTION:
	case MIME_ATOM_LOCAL_LUA_FUNCTION:
		ret = RSPAMD_EXPRESSION_MAX_PRIORITY - RSPAMD_EXPRESSION_MAX_PRIORITY / 4;
		break;
	case MIME_ATOM_REGEXP:
		switch (mime_atom->d.re->type) {
		case RSPAMD_RE_HEADER:
		case RSPAMD_RE_RAWHEADER:
			ret = RSPAMD_EXPRESSION_MAX_PRIORITY - RSPAMD_EXPRESSION_MAX_PRIORITY / 16;
			break;
		case RSPAMD_RE_URL:
		case RSPAMD_RE_EMAIL:
			ret = RSPAMD_EXPRESSION_MAX_PRIORITY - RSPAMD_EXPRESSION_MAX_PRIORITY / 8;
			break;
		case RSPAMD_RE_SELECTOR:
			ret = RSPAMD_EXPRESSION_MAX_PRIORITY - RSPAMD_EXPRESSION_MAX_PRIORITY / 8;
			break;
		case RSPAMD_RE_MIME:
		case RSPAMD_RE_RAWMIME:
			ret = RSPAMD_EXPRESSION_MAX_PRIORITY - RSPAMD_EXPRESSION_MAX_PRIORITY / 2;
			break;
		case RSPAMD_RE_WORDS:
		case RSPAMD_RE_RAWWORDS:
		case RSPAMD_RE_STEMWORDS:
		default:
			/* For expensive regexps */
			ret = 0;
			break;
		}
	}

	return ret;
}

static void
rspamd_mime_expr_destroy (rspamd_expression_atom_t *atom)
{
	struct rspamd_mime_atom *mime_atom = atom->data;

	if (mime_atom) {
		if (mime_atom->type == MIME_ATOM_INTERNAL_FUNCTION) {
			/* Need to cleanup arguments */
			g_array_free (mime_atom->d.func->args, TRUE);
		}
	}
}

static gboolean
rspamd_mime_expr_process_function (struct rspamd_function_atom * func,
	struct rspamd_task * task,
	lua_State *L)
{
	struct _fl *selected, key;

	key.name = func->name;

	selected = bsearch (&key,
			list_ptr,
			functions_number,
			sizeof (struct _fl),
			fl_cmp);
	if (selected == NULL) {
		/* Try to check lua function */
		return FALSE;
	}

	return selected->func (task, func->args, selected->user_data);
}

static gdouble
rspamd_mime_expr_process (void *ud, rspamd_expression_atom_t *atom)
{
	struct rspamd_task *task = (struct rspamd_task *)ud;
	struct rspamd_mime_atom *mime_atom;
	lua_State *L;
	gdouble ret = 0;

	g_assert (task != NULL);
	g_assert (atom != NULL);

	mime_atom = atom->data;

	if (mime_atom->type == MIME_ATOM_REGEXP) {
		ret = rspamd_mime_expr_process_regexp (mime_atom->d.re, task);
	}
	else if (mime_atom->type == MIME_ATOM_LUA_FUNCTION) {
		L = task->cfg->lua_state;
		lua_getglobal (L, mime_atom->d.lua_function);
		rspamd_lua_task_push (L, task);

		if (lua_pcall (L, 1, 1, 0) != 0) {
			msg_info_task ("lua call to global function '%s' for atom '%s' failed: %s",
				mime_atom->d.lua_function,
				mime_atom->str,
				lua_tostring (L, -1));
			lua_pop (L, 1);
		}
		else {
			if (lua_type (L, -1) == LUA_TBOOLEAN) {
				ret = lua_toboolean (L, -1);
			}
			else if (lua_type (L, -1) == LUA_TNUMBER) {
				ret = lua_tonumber (L, 1);
			}
			else {
				msg_err_task ("%s returned wrong return type: %s",
						mime_atom->str, lua_typename (L, lua_type (L, -1)));
			}
			/* Remove result */
			lua_pop (L, 1);
		}
	}
	else if (mime_atom->type == MIME_ATOM_LOCAL_LUA_FUNCTION) {
		gint err_idx;

		L = task->cfg->lua_state;
		lua_pushcfunction (L, &rspamd_lua_traceback);
		err_idx = lua_gettop (L);

		lua_rawgeti (L, LUA_REGISTRYINDEX, mime_atom->d.lua_cbref);
		rspamd_lua_task_push (L, task);

		if (lua_pcall (L, 1, 1, err_idx) != 0) {
			msg_info_task ("lua call to local function for atom '%s' failed: %s",
					mime_atom->str,
					lua_tostring (L, -1));
		}
		else {
			if (lua_type (L, -1) == LUA_TBOOLEAN) {
				ret = lua_toboolean (L, -1);
			}
			else if (lua_type (L, -1) == LUA_TNUMBER) {
				ret = lua_tonumber (L, 1);
			}
			else {
				msg_err_task ("%s returned wrong return type: %s",
						mime_atom->str, lua_typename (L, lua_type (L, -1)));
			}
		}

		lua_settop (L, 0);
	}
	else {
		ret = rspamd_mime_expr_process_function (mime_atom->d.func, task,
				task->cfg->lua_state);
	}

	return ret;
}

void
register_expression_function (const gchar *name,
	rspamd_internal_func_t func,
	void *user_data)
{
	static struct _fl *new;

	functions_number++;

	new = g_new (struct _fl, functions_number);
	memcpy (new, list_ptr, (functions_number - 1) * sizeof (struct _fl));
	if (list_allocated) {
		g_free (list_ptr);
	}

	list_allocated = TRUE;
	new[functions_number - 1].name = name;
	new[functions_number - 1].func = func;
	new[functions_number - 1].user_data = user_data;
	qsort (new, functions_number, sizeof (struct _fl), fl_cmp);
	list_ptr = new;
}

gboolean
rspamd_compare_encoding (struct rspamd_task *task, GArray * args, void *unused)
{
	struct expression_argument *arg;

	if (args == NULL || task == NULL) {
		return FALSE;
	}

	arg = &g_array_index (args, struct expression_argument, 0);
	if (!arg || arg->type != EXPRESSION_ARGUMENT_NORMAL) {
		msg_warn_task ("invalid argument to function is passed");
		return FALSE;
	}

	/* XXX: really write this function */
	return TRUE;
}

gboolean
rspamd_header_exists (struct rspamd_task * task, GArray * args, void *unused)
{
	struct expression_argument *arg;
	struct rspamd_mime_header *rh;

	if (args == NULL || task == NULL) {
		return FALSE;
	}

	arg = &g_array_index (args, struct expression_argument, 0);
	if (!arg || arg->type != EXPRESSION_ARGUMENT_NORMAL) {
		msg_warn_task ("invalid argument to function is passed");
		return FALSE;
	}

	rh = rspamd_message_get_header_array(task,
			(gchar *) arg->data, FALSE);

	debug_task ("try to get header %s: %d", (gchar *)arg->data,
			(rh != NULL));

	if (rh) {
		return TRUE;
	}

	return FALSE;
}


/*
 * This function is designed to find difference between text/html and text/plain parts
 * It takes one argument: difference threshold, if we have two text parts, compare
 * its hashes and check for threshold, if value is greater than threshold, return TRUE
 * and return FALSE otherwise.
 */
gboolean
rspamd_parts_distance (struct rspamd_task * task, GArray * args, void *unused)
{
	gint threshold, threshold2 = -1;
	struct expression_argument *arg;
	gdouble *pdiff, diff;

	if (args == NULL || args->len == 0) {
		debug_task ("no threshold is specified, assume it 100");
		threshold = 100;
	}
	else {
		errno = 0;
		arg = &g_array_index (args, struct expression_argument, 0);
		if (!arg || arg->type != EXPRESSION_ARGUMENT_NORMAL) {
			msg_warn_task ("invalid argument to function is passed");
			return FALSE;
		}

		threshold = strtoul ((gchar *)arg->data, NULL, 10);
		if (errno != 0) {
			msg_info_task ("bad numeric value for threshold \"%s\", assume it 100",
				(gchar *)arg->data);
			threshold = 100;
		}
		if (args->len >= 2) {
			arg = &g_array_index (args, struct expression_argument, 1);
			if (!arg || arg->type != EXPRESSION_ARGUMENT_NORMAL) {
				msg_warn_task ("invalid argument to function is passed");
				return FALSE;
			}

			errno = 0;
			threshold2 = strtoul ((gchar *)arg->data, NULL, 10);
			if (errno != 0) {
				msg_info_task ("bad numeric value for threshold \"%s\", ignore it",
					(gchar *)arg->data);
				threshold2 = -1;
			}
		}
	}

	if ((pdiff =
		rspamd_mempool_get_variable (task->task_pool,
		"parts_distance")) != NULL) {
		diff = (1.0 - (*pdiff)) * 100.0;

		if (diff != -1) {
			if (threshold2 > 0) {
				if (diff >= MIN (threshold, threshold2) &&
					diff < MAX (threshold, threshold2)) {

					return TRUE;
				}
			}
			else {
				if (diff <= threshold) {
					return TRUE;
				}
			}
			return FALSE;
		}
		else {
			return FALSE;
		}
	}

	return FALSE;
}

struct addr_list {
	const gchar *name;
	guint namelen;
	const gchar *addr;
	guint addrlen;
};

static gint
addr_list_cmp_func (const void *a, const void *b)
{
	const struct addr_list *addra = (struct addr_list *)a,
			*addrb = (struct addr_list *)b;

	if (addra->addrlen != addrb->addrlen) {
		return addra->addrlen - addrb->addrlen;
	}

	return memcmp (addra->addr, addrb->addr, addra->addrlen);
}

#define COMPARE_RCPT_LEN 3
#define MIN_RCPT_TO_COMPARE 7

gboolean
rspamd_recipients_distance (struct rspamd_task *task, GArray * args,
	void *unused)
{
	struct expression_argument *arg;
	struct rspamd_email_address *cur;
	double threshold;
	struct addr_list *ar;
	gint num, i, hits = 0;

	if (args == NULL) {
		msg_warn_task ("no parameters to function");
		return FALSE;
	}

	arg = &g_array_index (args, struct expression_argument, 0);
	if (!arg || arg->type != EXPRESSION_ARGUMENT_NORMAL) {
		msg_warn_task ("invalid argument to function is passed");
		return FALSE;
	}

	errno = 0;
	threshold = strtod ((gchar *)arg->data, NULL);

	if (errno != 0) {
		msg_warn_task ("invalid numeric value '%s': %s",
			(gchar *)arg->data,
			strerror (errno));
		return FALSE;
	}

	if (!MESSAGE_FIELD (task, rcpt_mime)) {
		return FALSE;
	}

	num = MESSAGE_FIELD (task, rcpt_mime)->len;

	if (num < MIN_RCPT_TO_COMPARE) {
		return FALSE;
	}

	ar = rspamd_mempool_alloc0 (task->task_pool, num * sizeof (struct addr_list));

	/* Fill array */
	num = 0;
	PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, rcpt_mime), i, cur) {
		if (cur->addr_len > COMPARE_RCPT_LEN) {
			ar[num].name = cur->addr;
			ar[num].namelen = cur->addr_len;
			ar[num].addr = cur->domain;
			ar[num].addrlen = cur->domain_len;
			num ++;
		}
	}

	qsort (ar, num, sizeof (*ar), addr_list_cmp_func);

	/* Cycle all elements in array */
	for (i = 0; i < num; i++) {
		if (i < num - 1) {
			if (ar[i].namelen == ar[i + 1].namelen) {
				if (rspamd_lc_cmp (ar[i].name, ar[i + 1].name, COMPARE_RCPT_LEN) == 0) {
					hits++;
				}
			}
		}
	}

	if ((hits * num / 2.) / (double)num >= threshold) {
		return TRUE;
	}

	return FALSE;
}

gboolean
rspamd_has_only_html_part (struct rspamd_task * task, GArray * args,
	void *unused)
{
	struct rspamd_mime_text_part *p;
	guint i, cnt_html = 0, cnt_txt = 0;

	PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, text_parts), i, p) {
		p = g_ptr_array_index (MESSAGE_FIELD (task, text_parts), 0);

		if (!IS_TEXT_PART_ATTACHMENT (p)) {
			if (IS_TEXT_PART_HTML (p)) {
				cnt_html++;
			}
			else {
				cnt_txt++;
			}
		}
	}

	return (cnt_html > 0 && cnt_txt == 0);
}

static gboolean
is_recipient_list_sorted (GPtrArray *ar)
{
	struct rspamd_email_address *addr;
	gboolean res = TRUE;
	rspamd_ftok_t cur, prev;
	gint i;

	/* Do not check to short address lists */
	if (ar == NULL || ar->len < MIN_RCPT_TO_COMPARE) {
		return FALSE;
	}

	prev.len = 0;
	prev.begin = NULL;

	PTR_ARRAY_FOREACH (ar, i, addr) {
		cur.begin = addr->addr;
		cur.len = addr->addr_len;

		if (prev.len != 0) {
			if (rspamd_ftok_casecmp (&cur, &prev) <= 0) {
				res = FALSE;
				break;
			}
		}

		prev = cur;
	}

	return res;
}

gboolean
rspamd_is_recipients_sorted (struct rspamd_task * task,
	GArray * args,
	void *unused)
{
	/* Check all types of addresses */

	if (MESSAGE_FIELD (task, rcpt_mime)) {
		return is_recipient_list_sorted (MESSAGE_FIELD (task, rcpt_mime));
	}

	return FALSE;
}

gboolean
rspamd_compare_transfer_encoding (struct rspamd_task * task,
	GArray * args,
	void *unused)
{
	struct expression_argument *arg;
	guint i;
	struct rspamd_mime_part *part;
	enum rspamd_cte cte;

	if (args == NULL) {
		msg_warn_task ("no parameters to function");
		return FALSE;
	}

	arg = &g_array_index (args, struct expression_argument, 0);
	if (!arg || arg->type != EXPRESSION_ARGUMENT_NORMAL) {
		msg_warn_task ("invalid argument to function is passed");
		return FALSE;
	}

	cte = rspamd_cte_from_string (arg->data);

	if (cte == RSPAMD_CTE_UNKNOWN) {
		msg_warn_task ("unknown cte: %s", arg->data);
		return FALSE;
	}

	PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, parts), i, part) {
		if (IS_PART_TEXT (part)) {
			if (part->cte == cte) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

gboolean
rspamd_is_html_balanced (struct rspamd_task * task, GArray * args, void *unused)
{
	/* Totally broken but seems to be never used */
	return TRUE;
}

gboolean
rspamd_has_html_tag (struct rspamd_task * task, GArray * args, void *unused)
{
	struct rspamd_mime_text_part *p;
	struct expression_argument *arg;
	guint i;
	gboolean res = FALSE;

	if (args == NULL) {
		msg_warn_task ("no parameters to function");
		return FALSE;
	}

	arg = &g_array_index (args, struct expression_argument, 0);
	if (!arg || arg->type != EXPRESSION_ARGUMENT_NORMAL) {
		msg_warn_task ("invalid argument to function is passed");
		return FALSE;
	}

	PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, text_parts), i, p) {
		if (IS_TEXT_PART_HTML (p) && p->html) {
			res = rspamd_html_tag_seen (p->html, arg->data);
		}

		if (res) {
			break;
		}
	}

	return res;

}

gboolean
rspamd_has_fake_html (struct rspamd_task * task, GArray * args, void *unused)
{
	struct rspamd_mime_text_part *p;
	guint i;
	gboolean res = FALSE;

	PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, text_parts), i, p) {
		if (IS_TEXT_PART_HTML (p) && (rspamd_html_get_tags_count(p->html) < 2)) {
			res = TRUE;
		}

		if (res) {
			break;
		}
	}

	return res;

}

static gboolean
rspamd_raw_header_exists (struct rspamd_task *task, GArray * args, void *unused)
{
	struct expression_argument *arg;

	if (args == NULL || task == NULL) {
		return FALSE;
	}

	arg = &g_array_index (args, struct expression_argument, 0);
	if (!arg || arg->type != EXPRESSION_ARGUMENT_NORMAL) {
		msg_warn_task ("invalid argument to function is passed");
		return FALSE;
	}

	return rspamd_message_get_header_array(task, arg->data, FALSE) != NULL;
}

static gboolean
match_smtp_data (struct rspamd_task *task,
	struct expression_argument *arg,
	const gchar *what, gsize len)
{
	rspamd_regexp_t *re;
	gint r = 0;

	if (arg->type == EXPRESSION_ARGUMENT_REGEXP) {
		/* This is a regexp */
		re = arg->data;
		if (re == NULL) {
			msg_warn_task ("cannot compile regexp for function");
			return FALSE;
		}


		if (len > 0) {
			r = rspamd_regexp_search (re, what, len, NULL, NULL, FALSE, NULL);
		}

		return r;
	}
	else if (arg->type == EXPRESSION_ARGUMENT_NORMAL &&
			g_ascii_strncasecmp (arg->data, what, len) == 0) {
		return TRUE;
	}

	return FALSE;
}

static gboolean
rspamd_check_smtp_data (struct rspamd_task *task, GArray * args, void *unused)
{
	struct expression_argument *arg;
	struct rspamd_email_address *addr = NULL;
	GPtrArray *rcpts = NULL;
	const gchar *type, *str = NULL;
	guint i;

	if (args == NULL) {
		msg_warn_task ("no parameters to function");
		return FALSE;
	}

	arg = &g_array_index (args, struct expression_argument, 0);

	if (!arg || !arg->data || arg->type != EXPRESSION_ARGUMENT_NORMAL) {
		msg_warn_task ("no parameters to function");
		return FALSE;
	}
	else {
		type = arg->data;
		switch (*type) {
		case 'f':
		case 'F':
			if (g_ascii_strcasecmp (type, "from") == 0) {
				addr = rspamd_task_get_sender (task);
			}
			else {
				msg_warn_task ("bad argument to function: %s", type);
				return FALSE;
			}
			break;
		case 'h':
		case 'H':
			if (g_ascii_strcasecmp (type, "helo") == 0) {
				str = task->helo;
			}
			else {
				msg_warn_task ("bad argument to function: %s", type);
				return FALSE;
			}
			break;
		case 'u':
		case 'U':
			if (g_ascii_strcasecmp (type, "user") == 0) {
				str = task->user;
			}
			else {
				msg_warn_task ("bad argument to function: %s", type);
				return FALSE;
			}
			break;
		case 's':
		case 'S':
			if (g_ascii_strcasecmp (type, "subject") == 0) {
				str = MESSAGE_FIELD (task, subject);
			}
			else {
				msg_warn_task ("bad argument to function: %s", type);
				return FALSE;
			}
			break;
		case 'r':
		case 'R':
			if (g_ascii_strcasecmp (type, "rcpt") == 0) {
				rcpts = task->rcpt_envelope;
			}
			else {
				msg_warn_task ("bad argument to function: %s", type);
				return FALSE;
			}
			break;
		default:
			msg_warn_task ("bad argument to function: %s", type);
			return FALSE;
		}
	}

	if (str == NULL && addr == NULL && rcpts == NULL) {
		/* Not enough data so regexp would NOT be found anyway */
		return FALSE;
	}

	/* We would process only one more argument, others are ignored */
	if (args->len >= 2) {
		arg = &g_array_index (args, struct expression_argument, 1);

		if (arg) {
			if (str != NULL) {
				return match_smtp_data (task, arg, str, strlen (str));
			}
			else if (addr != NULL && addr->addr) {
				return match_smtp_data (task, arg, addr->addr, addr->addr_len);
			}
			else {
				if (rcpts != NULL) {
					for (i = 0; i < rcpts->len; i ++) {
						addr = g_ptr_array_index (rcpts, i);

						if (addr && addr->addr &&
							match_smtp_data (task, arg,
								addr->addr, addr->addr_len)) {
							return TRUE;
						}
					}
				}
			}
		}
	}

	return FALSE;
}

static inline gboolean
rspamd_check_ct_attr (const gchar *begin, gsize len,
		struct expression_argument *arg_pattern)
{
	rspamd_regexp_t *re;
	gboolean r = FALSE;

	if (arg_pattern->type == EXPRESSION_ARGUMENT_REGEXP) {
		re = arg_pattern->data;

		if (len > 0) {
			r = rspamd_regexp_search (re,
					begin, len,
					NULL, NULL, FALSE, NULL);
		}

		if (r) {
			return TRUE;
		}
	}
	else {
		/* Just do strcasecmp */
		gsize plen = strlen (arg_pattern->data);

		if (plen == len &&
			g_ascii_strncasecmp (arg_pattern->data, begin, len) == 0) {
			return TRUE;
		}
	}

	return FALSE;
}

static gboolean
rspamd_content_type_compare_param (struct rspamd_task * task,
	GArray * args,
	void *unused)
{

	struct expression_argument *arg, *arg1, *arg_pattern;
	gboolean recursive = FALSE;
	struct rspamd_mime_part *cur_part;
	guint i;
	rspamd_ftok_t srch;
	struct rspamd_content_type_param *found = NULL, *cur;
	const gchar *param_name;

	if (args == NULL || args->len < 2) {
		msg_warn_task ("no parameters to function");
		return FALSE;
	}

	arg = &g_array_index (args, struct expression_argument, 0);
	g_assert (arg->type == EXPRESSION_ARGUMENT_NORMAL);
	param_name = arg->data;
	arg_pattern = &g_array_index (args, struct expression_argument, 1);

	PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, parts), i, cur_part) {
		if (args->len >= 3) {
			arg1 = &g_array_index (args, struct expression_argument, 2);
			if (g_ascii_strncasecmp (arg1->data, "true",
					sizeof ("true") - 1) == 0) {
				recursive = TRUE;
			}
		}
		else {
			/*
			 * If user did not specify argument, let's assume that he wants
			 * recursive search if mime part is multipart/mixed
			 */
			if (IS_PART_MULTIPART (cur_part)) {
				recursive = TRUE;
			}
		}

		rspamd_ftok_t lit;
		RSPAMD_FTOK_FROM_STR (&srch, param_name);
		RSPAMD_FTOK_FROM_STR (&lit, "charset");

		if (rspamd_ftok_equal (&srch, &lit)) {
			if (rspamd_check_ct_attr (cur_part->ct->charset.begin,
					cur_part->ct->charset.len, arg_pattern)) {
				return TRUE;
			}
		}

		RSPAMD_FTOK_FROM_STR (&lit, "boundary");
		if (rspamd_ftok_equal (&srch, &lit)) {
			if (rspamd_check_ct_attr (cur_part->ct->orig_boundary.begin,
					cur_part->ct->orig_boundary.len, arg_pattern)) {
				return TRUE;
			}
		}

		if (cur_part->ct->attrs) {
			found = g_hash_table_lookup (cur_part->ct->attrs, &srch);

			if (found) {
				DL_FOREACH (found, cur) {
					if (rspamd_check_ct_attr (cur->value.begin,
							cur->value.len, arg_pattern)) {
						return TRUE;
					}
				}
			}
		}

		if (!recursive) {
			break;
		}
	}

	return FALSE;
}

static gboolean
rspamd_content_type_has_param (struct rspamd_task * task,
	GArray * args,
	void *unused)
{
	struct expression_argument *arg, *arg1;
	gboolean recursive = FALSE;
	struct rspamd_mime_part *cur_part;
	guint i;
	rspamd_ftok_t srch;
	struct rspamd_content_type_param *found = NULL;
	const gchar *param_name;

	if (args == NULL || args->len < 1) {
		msg_warn_task ("no parameters to function");
		return FALSE;
	}

	arg = &g_array_index (args, struct expression_argument, 0);
	g_assert (arg->type == EXPRESSION_ARGUMENT_NORMAL);
	param_name = arg->data;

	PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, parts), i, cur_part) {
		if (args->len >= 2) {
			arg1 = &g_array_index (args, struct expression_argument, 1);
			if (g_ascii_strncasecmp (arg1->data, "true",
					sizeof ("true") - 1) == 0) {
				recursive = TRUE;
			}
		}
		else {
			/*
			 * If user did not specify argument, let's assume that he wants
			 * recursive search if mime part is multipart/mixed
			 */
			if (IS_PART_MULTIPART (cur_part)) {
				recursive = TRUE;
			}
		}


		rspamd_ftok_t lit;
		RSPAMD_FTOK_FROM_STR (&srch, param_name);
		RSPAMD_FTOK_FROM_STR (&lit, "charset");

		if (rspamd_ftok_equal (&srch, &lit)) {
			if (cur_part->ct->charset.len > 0) {
				return TRUE;
			}
		}

		RSPAMD_FTOK_FROM_STR (&lit, "boundary");
		if (rspamd_ftok_equal (&srch, &lit)) {
			if (cur_part->ct->boundary.len > 0) {
				return TRUE;
			}
		}

		if (cur_part->ct->attrs) {
			found = g_hash_table_lookup (cur_part->ct->attrs, &srch);

			if (found) {
				return TRUE;
			}
		}

		if (!recursive) {
			break;
		}
	}

	return FALSE;
}

static gboolean
rspamd_content_type_check (struct rspamd_task *task,
	GArray * args,
	gboolean check_subtype)
{
	rspamd_ftok_t *param_data, srch;
	rspamd_regexp_t *re;
	struct expression_argument *arg1, *arg_pattern;
	struct rspamd_content_type *ct;
	gint r = 0;
	guint i;
	gboolean recursive = FALSE;
	struct rspamd_mime_part *cur_part;

	if (args == NULL || args->len < 1) {
		msg_warn_task ("no parameters to function");
		return FALSE;
	}

	arg_pattern = &g_array_index (args, struct expression_argument, 0);

	PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, parts), i, cur_part) {
		ct = cur_part->ct;

		if (args->len >= 2) {
			arg1 = &g_array_index (args, struct expression_argument, 1);
			if (g_ascii_strncasecmp (arg1->data, "true",
					sizeof ("true") - 1) == 0) {
				recursive = TRUE;
			}
		}
		else {
			/*
			 * If user did not specify argument, let's assume that he wants
			 * recursive search if mime part is multipart/mixed
			 */
			if (IS_PART_MULTIPART (cur_part)) {
				recursive = TRUE;
			}
		}

		if (check_subtype) {
			param_data = &ct->subtype;
		}
		else {
			param_data = &ct->type;
		}

		if (arg_pattern->type == EXPRESSION_ARGUMENT_REGEXP) {
			re = arg_pattern->data;

			if (param_data->len > 0) {
				r = rspamd_regexp_search (re, param_data->begin, param_data->len,
						NULL, NULL, FALSE, NULL);
			}

			if (r) {
				return TRUE;
			}
		}
		else {
			/* Just do strcasecmp */
			srch.begin = arg_pattern->data;
			srch.len = strlen (arg_pattern->data);

			if (rspamd_ftok_casecmp (param_data, &srch) == 0) {
				return TRUE;
			}
		}

		/* Get next part */
		if (!recursive) {
			break;
		}
	}

	return FALSE;
}

static gboolean
rspamd_content_type_is_type (struct rspamd_task * task,
	GArray * args,
	void *unused)
{
	return rspamd_content_type_check (task, args, FALSE);
}

static gboolean
rspamd_content_type_is_subtype (struct rspamd_task * task,
	GArray * args,
	void *unused)
{
	return rspamd_content_type_check (task, args, TRUE);
}

static gboolean
compare_subtype (struct rspamd_task *task, struct rspamd_content_type *ct,
	struct expression_argument *subtype)
{
	rspamd_regexp_t *re;
	rspamd_ftok_t srch;
	gint r = 0;

	if (subtype == NULL || ct == NULL) {
		msg_warn_task ("invalid parameters passed");
		return FALSE;
	}
	if (subtype->type == EXPRESSION_ARGUMENT_REGEXP) {
		re = subtype->data;

		if (ct->subtype.len > 0) {
			r = rspamd_regexp_search (re, ct->subtype.begin, ct->subtype.len,
					NULL, NULL, FALSE, NULL);
		}
	}
	else {
		srch.begin = subtype->data;
		srch.len = strlen (subtype->data);

		/* Just do strcasecmp */
		if (rspamd_ftok_casecmp (&ct->subtype, &srch) == 0) {
			return TRUE;
		}
	}

	return r;
}

static gboolean
compare_len (struct rspamd_mime_part *part, guint min, guint max)
{
	if (min == 0 && max == 0) {
		return TRUE;
	}

	if (min == 0) {
		return part->parsed_data.len <= max;
	}
	else if (max == 0) {
		return part->parsed_data.len >= min;
	}
	else {
		return part->parsed_data.len >= min && part->parsed_data.len <= max;
	}
}

static gboolean
common_has_content_part (struct rspamd_task * task,
	struct expression_argument *param_type,
	struct expression_argument *param_subtype,
	gint min_len,
	gint max_len)
{
	rspamd_regexp_t *re;
	struct rspamd_mime_part *part;
	struct rspamd_content_type *ct;
	rspamd_ftok_t srch;
	gint r = 0;
	guint i;

	PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, parts), i, part) {
		ct = part->ct;

		if (ct == NULL) {
			continue;
		}

		if (param_type->type == EXPRESSION_ARGUMENT_REGEXP) {
			re = param_type->data;

			if (ct->type.len > 0) {
				r = rspamd_regexp_search (re, ct->type.begin, ct->type.len,
						NULL, NULL, FALSE, NULL);
			}

			/* Also check subtype and length of the part */
			if (r && param_subtype) {
				r = compare_len (part, min_len, max_len) &&
						compare_subtype (task, ct, param_subtype);

				return r;
			}
		}
		else {
			/* Just do strcasecmp */
			srch.begin = param_type->data;
			srch.len = strlen (param_type->data);

			if (rspamd_ftok_casecmp (&ct->type, &srch) == 0) {
				if (param_subtype) {
					if (compare_subtype (task, ct, param_subtype)) {
						if (compare_len (part, min_len, max_len)) {
							return TRUE;
						}
					}
				}
				else {
					if (compare_len (part, min_len, max_len)) {
						return TRUE;
					}
				}
			}
		}
	}

	return FALSE;
}

static gboolean
rspamd_has_content_part (struct rspamd_task * task, GArray * args, void *unused)
{
	struct expression_argument *param_type = NULL, *param_subtype = NULL;

	if (args == NULL) {
		msg_warn_task ("no parameters to function");
		return FALSE;
	}

	param_type = &g_array_index (args, struct expression_argument, 0);
	if (args->len >= 2) {
		param_subtype = &g_array_index (args, struct expression_argument, 1);
	}

	return common_has_content_part (task, param_type, param_subtype, 0, 0);
}

static gboolean
rspamd_has_content_part_len (struct rspamd_task * task,
	GArray * args,
	void *unused)
{
	struct expression_argument *param_type = NULL, *param_subtype = NULL;
	gint min = 0, max = 0;
	struct expression_argument *arg;

	if (args == NULL) {
		msg_warn_task ("no parameters to function");
		return FALSE;
	}

	param_type = &g_array_index (args, struct expression_argument, 0);

	if (args->len >= 2) {
		param_subtype = &g_array_index (args, struct expression_argument, 1);

		if (args->len >= 3) {
			arg = &g_array_index (args, struct expression_argument, 2);
			errno = 0;
			min = strtoul (arg->data, NULL, 10);
			g_assert (arg->type == EXPRESSION_ARGUMENT_NORMAL);

			if (errno != 0) {
				msg_warn_task ("invalid numeric value '%s': %s",
					(gchar *)arg->data,
					strerror (errno));
				return FALSE;
			}

			if (args->len >= 4) {
				arg = &g_array_index (args, struct expression_argument, 3);
				g_assert (arg->type == EXPRESSION_ARGUMENT_NORMAL);
				max = strtoul (arg->data, NULL, 10);

				if (errno != 0) {
					msg_warn_task ("invalid numeric value '%s': %s",
						(gchar *)arg->data,
						strerror (errno));
					return FALSE;
				}
			}
		}
	}

	return common_has_content_part (task, param_type, param_subtype, min, max);
}

static gboolean
rspamd_is_empty_body (struct rspamd_task *task,
		GArray * args,
		void *unused)
{
	struct rspamd_mime_part *part;
	guint i;

	PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, parts), i, part) {
		if (part->parsed_data.len > 0) {
			return FALSE;
		}
	}

	return TRUE;
}

#define TASK_FLAG_READ(flag) do { \
	result = !!(task->flags & (flag)); \
} while(0)

#define TASK_GET_FLAG(flag, strname, macro) do { \
	if (!found && strcmp ((flag), strname) == 0) { \
		TASK_FLAG_READ((macro)); \
		found = TRUE; \
	} \
} while(0)

#define TASK_PROTOCOL_FLAG_READ(flag) do { \
	result = !!(task->protocol_flags & (flag)); \
} while(0)

#define TASK_GET_PROTOCOL_FLAG(flag, strname, macro) do { \
	if (!found && strcmp ((flag), strname) == 0) { \
		TASK_PROTOCOL_FLAG_READ((macro)); \
		found = TRUE; \
	} \
} while(0)


static gboolean
rspamd_has_flag_expr (struct rspamd_task *task,
					  GArray * args,
					  void *unused)
{
	gboolean found = FALSE, result = FALSE;
	struct expression_argument *flag_arg;
	const gchar *flag_str;

	if (args == NULL) {
		msg_warn_task ("no parameters to function");
		return FALSE;
	}

	flag_arg = &g_array_index (args, struct expression_argument, 0);

	if (flag_arg->type != EXPRESSION_ARGUMENT_NORMAL) {
		msg_warn_task ("invalid parameter to function");
		return FALSE;
	}

	flag_str = (const gchar *)flag_arg->data;

	TASK_GET_FLAG (flag_str, "pass_all", RSPAMD_TASK_FLAG_PASS_ALL);
	TASK_GET_FLAG (flag_str, "no_log", RSPAMD_TASK_FLAG_NO_LOG);
	TASK_GET_FLAG (flag_str, "no_stat", RSPAMD_TASK_FLAG_NO_STAT);
	TASK_GET_FLAG (flag_str, "skip", RSPAMD_TASK_FLAG_SKIP);
	TASK_GET_PROTOCOL_FLAG (flag_str, "extended_urls",
			RSPAMD_TASK_PROTOCOL_FLAG_EXT_URLS);
	TASK_GET_FLAG (flag_str, "learn_spam", RSPAMD_TASK_FLAG_LEARN_SPAM);
	TASK_GET_FLAG (flag_str, "learn_ham", RSPAMD_TASK_FLAG_LEARN_HAM);
	TASK_GET_FLAG (flag_str, "greylisted", RSPAMD_TASK_FLAG_GREYLISTED);
	TASK_GET_FLAG (flag_str, "broken_headers",
			RSPAMD_TASK_FLAG_BROKEN_HEADERS);
	TASK_GET_FLAG (flag_str, "skip_process",
			RSPAMD_TASK_FLAG_SKIP_PROCESS);
	TASK_GET_PROTOCOL_FLAG (flag_str, "milter",
			RSPAMD_TASK_PROTOCOL_FLAG_MILTER);
	TASK_GET_FLAG (flag_str, "bad_unicode",
			RSPAMD_TASK_FLAG_BAD_UNICODE);

	if (!found) {
		msg_warn_task ("invalid flag name %s", flag_str);
		return FALSE;
	}

	return result;
}

static gboolean
rspamd_has_symbol_expr (struct rspamd_task *task,
					  GArray * args,
					  void *unused)
{
	struct expression_argument *sym_arg;
	const gchar *symbol_str;

	if (args == NULL) {
		msg_warn_task ("no parameters to function");
		return FALSE;
	}

	sym_arg = &g_array_index (args, struct expression_argument, 0);

	if (sym_arg->type != EXPRESSION_ARGUMENT_NORMAL) {
		msg_warn_task ("invalid parameter to function");
		return FALSE;
	}

	symbol_str = (const gchar *)sym_arg->data;

	if (rspamd_task_find_symbol_result (task, symbol_str, NULL)) {
		return TRUE;
	}

	return FALSE;
}
