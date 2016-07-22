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
#include "config.h"
#include "util.h"
#include "cfg_file.h"
#include "rspamd.h"
#include "message.h"
#include "mime_expressions.h"
#include "html.h"
#include "email_addr.h"
#include "lua/lua_common.h"

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

static rspamd_expression_atom_t * rspamd_mime_expr_parse (const gchar *line, gsize len,
		rspamd_mempool_t *pool, gpointer ud, GError **err);
static gint rspamd_mime_expr_process (gpointer input, rspamd_expression_atom_t *atom);
static gint rspamd_mime_expr_priority (rspamd_expression_atom_t *atom);
static void rspamd_mime_expr_destroy (rspamd_expression_atom_t *atom);

/**
 * Regexp structure
 */
struct rspamd_regexp_atom {
	enum rspamd_re_type type;                       /**< regexp type										*/
	gchar *regexp_text;                             /**< regexp text representation							*/
	rspamd_regexp_t *regexp;                        /**< regexp structure									*/
	gchar *header;                                  /**< header name for header regexps						*/
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
	MIME_ATOM_LUA_FUNCTION
};

struct rspamd_mime_atom {
	gchar *str;
	union {
		struct rspamd_regexp_atom *re;
		struct rspamd_function_atom *func;
		const gchar *lua_function;
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
	{"has_html_tag", rspamd_has_html_tag, NULL},
	{"has_only_html_part", rspamd_has_only_html_part, NULL},
	{"header_exists", rspamd_header_exists, NULL},
	{"is_html_balanced", rspamd_is_html_balanced, NULL},
	{"is_recipients_sorted", rspamd_is_recipients_sorted, NULL},
	{"raw_header_exists", rspamd_raw_header_exists, NULL}
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

static gboolean
rspamd_parse_long_option (const gchar *start, gsize len,
		struct rspamd_regexp_atom *a)
{
	gboolean ret = FALSE;

	if (rspamd_lc_cmp (start, "body", len) == 0) {
		ret = TRUE;
		a->type = RSPAMD_RE_BODY;
	}
	else if (rspamd_lc_cmp (start, "part", len) == 0) {
		ret = TRUE;
		a->type = RSPAMD_RE_MIME;
	}
	else if (rspamd_lc_cmp (start, "raw_part", len) == 0) {
		ret = TRUE;
		a->type = RSPAMD_RE_RAWMIME;
	}
	else if (rspamd_lc_cmp (start, "header", len) == 0) {
		ret = TRUE;
		a->type = RSPAMD_RE_HEADER;
	}
	else if (rspamd_lc_cmp (start, "mime_header", len) == 0) {
		ret = TRUE;
		a->type = RSPAMD_RE_MIMEHEADER;
	}
	else if (rspamd_lc_cmp (start, "raw_header", len) == 0) {
		ret = TRUE;
		a->type = RSPAMD_RE_RAWHEADER;
	}
	else if (rspamd_lc_cmp (start, "all_header", len) == 0) {
		ret = TRUE;
		a->type = RSPAMD_RE_ALLHEADER;
	}
	else if (rspamd_lc_cmp (start, "url", len) == 0) {
		ret = TRUE;
		a->type = RSPAMD_RE_URL;
	}
	else if (rspamd_lc_cmp (start, "sa_body", len) == 0) {
		ret = TRUE;
		a->type = RSPAMD_RE_SABODY;
	}
	else if (rspamd_lc_cmp (start, "sa_raw_body", len) == 0) {
		ret = TRUE;
		a->type = RSPAMD_RE_SARAWBODY;
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
	gchar *dbegin, *dend;
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
			result->header = rspamd_mempool_alloc (pool, end - line + 1);
			rspamd_strlcpy (result->header, line, end - line + 1);
			result->type = RSPAMD_RE_HEADER;
			line = end;
		}
	}
	else {
		result->header = rspamd_mempool_strdup (pool, line);
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
	else if (result->header == NULL) {
		/* Assume that line without // is just a header name */
		result->header = rspamd_mempool_strdup (pool, line);
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
			result->type = RSPAMD_RE_RAWHEADER;
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
		msg_err_pool ("could not read regexp: %s, unknown type", src);
		return NULL;
	}

	if ((result->type == RSPAMD_RE_HEADER ||
			result->type == RSPAMD_RE_RAWHEADER ||
			result->type == RSPAMD_RE_MIMEHEADER) &&
			result->header == NULL) {
		msg_err_pool ("header regexp: '%s' has no header part", src);
		return NULL;
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
rspamd_mime_expr_parse_function_atom (const gchar *input)
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

	res = g_slice_alloc0 (sizeof (*res));
	res->name = g_malloc (obrace - input + 1);
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
				databuf = g_malloc (len);
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
				else {
					g_free (databuf);
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

				databuf = g_malloc (len);
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
	const gchar *p, *end;
	struct rspamd_config *cfg = ud;
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
		got_ebrace,
		end_atom,
		bad_atom
	} state = 0, prev_state = 0;

	p = line;
	end = p + len;

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
				/* Likely lua function, identified by just a string */
				type = MIME_ATOM_LUA_FUNCTION;
				state = end_atom;
				/* Do not increase p */
				continue;
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
			else if (!g_ascii_isalpha (t)) {
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

	mime_atom = g_slice_alloc (sizeof (*mime_atom));
	mime_atom->type = type;
	mime_atom->str = g_malloc (p - line + 1);
	rspamd_strlcpy (mime_atom->str, line, p - line + 1);

	if (type == MIME_ATOM_REGEXP) {
		mime_atom->d.re = rspamd_mime_expr_parse_regexp_atom (pool,
				mime_atom->str, cfg);
		if (mime_atom->d.re == NULL) {
			g_set_error (err, rspamd_mime_expr_quark(), 200, "cannot parse regexp '%s'",
					mime_atom->str);
			goto err;
		}
		else {
			/* Register new item in the cache */
			if (mime_atom->d.re->type == RSPAMD_RE_HEADER ||
					mime_atom->d.re->type == RSPAMD_RE_RAWHEADER ||
					mime_atom->d.re->type == RSPAMD_RE_MIMEHEADER) {

				if (mime_atom->d.re->header != NULL) {
					own_re = mime_atom->d.re->regexp;
					mime_atom->d.re->regexp = rspamd_re_cache_add (cfg->re_cache,
							mime_atom->d.re->regexp,
							mime_atom->d.re->type,
							mime_atom->d.re->header,
							strlen (mime_atom->d.re->header) + 1);
					/* Pass ownership to the cache */
					rspamd_regexp_unref (own_re);
				}
				else {
					/* We have header regexp, but no header name is detected */
					g_set_error (err,
							rspamd_mime_expr_quark (),
							200,
							"no header name in /H regexp: '%s'",
							mime_atom->str);
					goto err;
				}
			}
			else {
				own_re = mime_atom->d.re->regexp;
				mime_atom->d.re->regexp = rspamd_re_cache_add (cfg->re_cache,
						mime_atom->d.re->regexp,
						mime_atom->d.re->type,
						NULL,
						0);
				/* Pass ownership to the cache */
				rspamd_regexp_unref (own_re);
			}
		}
	}
	else if (type == MIME_ATOM_LUA_FUNCTION) {
		mime_atom->d.lua_function = mime_atom->str;

		lua_getglobal (cfg->lua_state, mime_atom->str);

		if (lua_type (cfg->lua_state, -1) != LUA_TFUNCTION) {
			g_set_error (err, rspamd_mime_expr_quark(), 200, "no such lua function '%s'",
					mime_atom->str);
			lua_pop (cfg->lua_state, 1);

			goto err;
		}
		lua_pop (cfg->lua_state, 1);
	}
	else {
		mime_atom->d.func = rspamd_mime_expr_parse_function_atom (mime_atom->str);
		if (mime_atom->d.func == NULL) {
			g_set_error (err, rspamd_mime_expr_quark(), 200, "cannot parse function '%s'",
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
	g_free (mime_atom->str);
	g_slice_free1 (sizeof (*mime_atom), mime_atom);

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
				task->re_rt,
				re->regexp,
				re->type,
				re->header,
				strlen (re->header),
				re->is_strong);
	}
	else {
		ret = rspamd_re_cache_process (task,
				task->re_rt,
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
		ret = 50;
		break;
	case MIME_ATOM_LUA_FUNCTION:
		ret = 50;
		break;
	case MIME_ATOM_REGEXP:
		switch (mime_atom->d.re->type) {
		case RSPAMD_RE_HEADER:
		case RSPAMD_RE_RAWHEADER:
			ret = 100;
			break;
		case RSPAMD_RE_URL:
			ret = 90;
			break;
		case RSPAMD_RE_MIME:
		case RSPAMD_RE_RAWMIME:
			ret = 10;
			break;
		default:
			/* For message regexp */
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
	guint i;
	struct expression_argument *arg;

	if (mime_atom) {
		if (mime_atom->type == MIME_ATOM_INTERNAL_FUNCTION) {
			/* Need to cleanup arguments */
			for (i = 0; i < mime_atom->d.func->args->len; i ++) {
				arg = &g_array_index (mime_atom->d.func->args,
						struct expression_argument, i);

				if (arg->type == EXPRESSION_ARGUMENT_NORMAL) {
					g_free (arg->data);
				}
			}
			g_array_free (mime_atom->d.func->args, TRUE);
		}
		/* XXX: regexp shouldn't be special */
		g_slice_free1 (sizeof (*mime_atom), mime_atom);
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

static gint
rspamd_mime_expr_process (gpointer input, rspamd_expression_atom_t *atom)
{
	struct rspamd_task *task = input;
	struct rspamd_mime_atom *mime_atom;
	lua_State *L;
	gint ret = 0;

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
	GList *headerlist;

	if (args == NULL || task == NULL) {
		return FALSE;
	}

	arg = &g_array_index (args, struct expression_argument, 0);
	if (!arg || arg->type != EXPRESSION_ARGUMENT_NORMAL) {
		msg_warn_task ("invalid argument to function is passed");
		return FALSE;
	}

	debug_task ("try to get header %s", (gchar *)arg->data);
	headerlist = rspamd_message_get_header (task,
			(gchar *)arg->data,
			FALSE);
	if (headerlist) {
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
	const gchar *addr;
};

#define COMPARE_RCPT_LEN 3
#define MIN_RCPT_TO_COMPARE 7

gboolean
rspamd_recipients_distance (struct rspamd_task *task, GArray * args,
	void *unused)
{
	struct expression_argument *arg;
	InternetAddressList *cur;
	double threshold;
	struct addr_list *ar;
	gchar *c;
	gint num, i, j, hits = 0, total = 0;

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

	if (!task->rcpt_mime) {
		return FALSE;
	}

	num = internet_address_list_length (task->rcpt_mime);

	if (num < MIN_RCPT_TO_COMPARE) {
		return FALSE;
	}
	ar =
		rspamd_mempool_alloc0 (task->task_pool, num *
			sizeof (struct addr_list));

	/* Fill array */
	cur = task->rcpt_mime;
#ifdef GMIME24
	for (i = 0; i < num; i++) {
		InternetAddress *iaelt =
			internet_address_list_get_address(cur, i);
		InternetAddressMailbox *iamb =
			INTERNET_ADDRESS_IS_MAILBOX(iaelt) ?
			INTERNET_ADDRESS_MAILBOX (iaelt) : NULL;
		if (iamb) {
			ar[i].name = internet_address_mailbox_get_addr (iamb);
			if (ar[i].name != NULL && (c = strchr (ar[i].name, '@')) != NULL) {
				ar[i].addr = c + 1;
			}
		}
	}
#else
	InternetAddress *addr;
	i = 0;
	while (cur) {
		addr = internet_address_list_get_address (cur);
		if (addr && internet_address_get_type (addr) == INTERNET_ADDRESS_NAME) {
			ar[i].name = rspamd_mempool_strdup (task->task_pool,
					internet_address_get_addr (addr));
			if (ar[i].name != NULL && (c = strchr (ar[i].name, '@')) != NULL) {
				*c = '\0';
				ar[i].addr = c + 1;
			}
			cur = internet_address_list_next (cur);
			i++;
		}
		else {
			cur = internet_address_list_next (cur);
		}
	}
#endif

	/* Cycle all elements in array */
	for (i = 0; i < num; i++) {
		for (j = i + 1; j < num; j++) {
			if (ar[i].name && ar[j].name &&
				g_ascii_strncasecmp (ar[i].name, ar[j].name,
				COMPARE_RCPT_LEN) == 0) {
				/* Common name part */
				hits++;
			}
#if 0
			/* XXX: when we have a typical mail that is headed towards
			 * several users within the same domain, then this rule
			 * leads to a false-positive.
			 * We actually need to match host against tld, but this is currently
			 * too expensive.
			 *
			 * TODO: think about normal representation of InternetAddress shit
			 */
			else if (ar[i].addr && ar[j].addr &&
				g_ascii_strcasecmp (ar[i].addr, ar[j].addr) == 0) {
				/* Common address part, but different name */
				hits++;
			}
#endif
			total++;
		}
	}

	if ((double)(hits * num / 2.) / (double)total >= threshold) {
		return TRUE;
	}

	return FALSE;
}

gboolean
rspamd_has_only_html_part (struct rspamd_task * task, GArray * args,
	void *unused)
{
	struct rspamd_mime_text_part *p;
	gboolean res = FALSE;

	if (task->text_parts->len == 1) {
		p = g_ptr_array_index (task->text_parts, 0);

		if (IS_PART_HTML (p)) {
			res = TRUE;
		}
		else {
			res = FALSE;
		}
	}

	return res;
}

static gboolean
is_recipient_list_sorted (const InternetAddressList * ia)
{
	const InternetAddressList *cur;
	InternetAddress *addr;
	InternetAddressMailbox *addr_mb;
	gboolean res = TRUE;
	struct addr_list current = { NULL, NULL }, previous = {
		NULL, NULL
	};
#ifdef GMIME24
	gint num, i;
#endif

	/* Do not check to short address lists */
	if (internet_address_list_length ((InternetAddressList *)ia) <
		MIN_RCPT_TO_COMPARE) {
		return FALSE;
	}
#ifdef GMIME24
	num = internet_address_list_length ((InternetAddressList *)ia);
	cur = ia;
	for (i = 0; i < num; i++) {
		addr =
			internet_address_list_get_address ((InternetAddressList *)cur, i);
		if (INTERNET_ADDRESS_IS_MAILBOX (addr)) {
			addr_mb = INTERNET_ADDRESS_MAILBOX (addr);
			current.addr = (gchar *) internet_address_mailbox_get_addr (addr_mb);
		}

		if (previous.addr != NULL) {
			if (current.addr &&
				g_ascii_strcasecmp (current.addr, previous.addr) <= 0) {
				res = FALSE;
				break;
			}
		}
		previous.addr = current.addr;
	}
#else
	cur = ia;
	while (cur) {
		addr = internet_address_list_get_address (cur);
		if (internet_address_get_type (addr) == INTERNET_ADDRESS_NAME) {
			current.addr = internet_address_get_addr (addr);
			if (previous.addr != NULL) {
				if (current.addr &&
					g_ascii_strcasecmp (current.addr, previous.addr) < 0) {
					res = FALSE;
					break;
				}
			}
			previous.addr = current.addr;
		}
		cur = internet_address_list_next (cur);
	}
#endif

	return res;
}

gboolean
rspamd_is_recipients_sorted (struct rspamd_task * task,
	GArray * args,
	void *unused)
{
	/* Check all types of addresses */
	if (is_recipient_list_sorted (g_mime_message_get_recipients (task->message,
		GMIME_RECIPIENT_TYPE_TO)) == TRUE) {
		return TRUE;
	}
	if (is_recipient_list_sorted (g_mime_message_get_recipients (task->message,
		GMIME_RECIPIENT_TYPE_BCC)) == TRUE) {
		return TRUE;
	}
	if (is_recipient_list_sorted (g_mime_message_get_recipients (task->message,
		GMIME_RECIPIENT_TYPE_CC)) == TRUE) {
		return TRUE;
	}

	return FALSE;
}

gboolean
rspamd_compare_transfer_encoding (struct rspamd_task * task,
	GArray * args,
	void *unused)
{
	GPtrArray *headerlist;
	struct expression_argument *arg;
	guint i;
	struct raw_header *rh;
	static const char *hname = "Content-Transfer-Encoding";

	if (args == NULL) {
		msg_warn_task ("no parameters to function");
		return FALSE;
	}

	arg = &g_array_index (args, struct expression_argument, 0);
	if (!arg || arg->type != EXPRESSION_ARGUMENT_NORMAL) {
		msg_warn_task ("invalid argument to function is passed");
		return FALSE;
	}

	headerlist = rspamd_message_get_header_array (task, hname, FALSE);

	if (headerlist) {
		for (i = 0; i < headerlist->len; i ++) {
			rh = g_ptr_array_index (headerlist, i);

			if (rh->decoded == NULL) {
				continue;
			}

			if (g_ascii_strcasecmp (rh->decoded, arg->data) == 0) {
				return TRUE;
			}
		}
	}

	/*
	 * In fact, we need to check 'Content-Transfer-Encoding' for each part
	 * as gmime has 'strange' assumptions
	 */
	headerlist = rspamd_message_get_mime_header_array (task,
			arg->data,
			FALSE);

	if (headerlist) {
		for (i = 0; i < headerlist->len; i ++) {
			rh = g_ptr_array_index (headerlist, i);

			if (rh->decoded == NULL) {
				continue;
			}

			if (g_ascii_strcasecmp (rh->decoded, arg->data) == 0) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

gboolean
rspamd_is_html_balanced (struct rspamd_task * task, GArray * args, void *unused)
{
	struct rspamd_mime_text_part *p;
	guint i;
	gboolean res = TRUE;

	for (i = 0; i < task->text_parts->len; i ++) {

		p = g_ptr_array_index (task->text_parts, i);
		if (!IS_PART_EMPTY (p) && IS_PART_HTML (p)) {
			if (p->flags & RSPAMD_MIME_TEXT_PART_FLAG_BALANCED) {
				res = TRUE;
			}
			else {
				res = FALSE;
				break;
			}
		}
	}

	return res;

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

	for (i = 0; i < task->text_parts->len; i ++) {
		p = g_ptr_array_index (task->text_parts, i);

		if (!IS_PART_EMPTY (p) && IS_PART_HTML (p) && p->html) {
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

	for (i = 0; i < task->text_parts->len; i ++) {
		p = g_ptr_array_index (task->text_parts, i);

		if (!IS_PART_EMPTY (p) && IS_PART_HTML (p) && p->html->html_tags == NULL) {
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

	return g_hash_table_lookup (task->raw_headers, arg->data) != NULL;
}

static gboolean
match_smtp_data (struct rspamd_task *task,
	struct expression_argument *arg,
	const gchar *what, gsize len)
{
	rspamd_regexp_t *re;
	gint r;

	if (arg->type == EXPRESSION_ARGUMENT_REGEXP) {
		/* This is a regexp */
		re = arg->data;
		if (re == NULL) {
			msg_warn_task ("cannot compile regexp for function");
			return FALSE;
		}


		r = rspamd_regexp_search (re, what, len, NULL, NULL, FALSE, NULL);

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
				str = task->subject;
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

static gboolean
rspamd_content_type_compare_param (struct rspamd_task * task,
	GArray * args,
	void *unused)
{
	const gchar *param_name;
	const gchar *param_data;
	rspamd_regexp_t *re;
	struct expression_argument *arg, *arg1, *arg_pattern;
	GMimeObject *part;
	GMimeContentType *ct;
	gint r;
	guint i;
	gboolean recursive = FALSE;
	struct rspamd_mime_part *cur_part;

	if (args == NULL || args->len < 2) {
		msg_warn_task ("no parameters to function");
		return FALSE;
	}

	arg = &g_array_index (args, struct expression_argument, 0);
	g_assert (arg->type == EXPRESSION_ARGUMENT_NORMAL);
	param_name = arg->data;
	arg_pattern = &g_array_index (args, struct expression_argument, 1);

	for (i = 0; i < task->parts->len; i ++) {
		cur_part = g_ptr_array_index (task->parts, i);
		part = cur_part->mime;
		ct = (GMimeContentType *)g_mime_object_get_content_type (part);

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
			if (g_mime_content_type_is_type (ct, "multipart", "*")) {
				recursive = TRUE;
			}
		}
#ifndef GMIME24
		g_object_unref (part);
#endif

		if ((param_data =
				g_mime_content_type_get_parameter ((GMimeContentType *)ct,
						param_name)) != NULL) {
			if (arg_pattern->type == EXPRESSION_ARGUMENT_REGEXP) {
				re = arg_pattern->data;
				r = rspamd_regexp_search (re, param_data, 0,
							NULL, NULL, FALSE, NULL);

				if (r) {
					return TRUE;
				}
			}
			else {
				/* Just do strcasecmp */
				if (g_ascii_strcasecmp (param_data, arg_pattern->data) == 0) {
					return TRUE;
				}
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
rspamd_content_type_has_param (struct rspamd_task * task,
	GArray * args,
	void *unused)
{
	gchar *param_name;
	const gchar *param_data;
	struct expression_argument *arg, *arg1;
	GMimeObject *part;
	GMimeContentType *ct;
	gboolean recursive = FALSE, result = FALSE;
	guint i;
	struct rspamd_mime_part *cur_part;

	if (args == NULL || args->len < 1) {
		msg_warn_task ("no parameters to function");
		return FALSE;
	}

	arg = &g_array_index (args, struct expression_argument, 0);
	g_assert (arg->type == EXPRESSION_ARGUMENT_NORMAL);
	param_name = arg->data;

	for (i = 0; i < task->parts->len; i ++) {
		cur_part = g_ptr_array_index (task->parts, i);
		part = cur_part->mime;
		ct = (GMimeContentType *)g_mime_object_get_content_type (part);

		if (args->len >= 2) {
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
			if (g_mime_content_type_is_type (ct, "multipart", "*")) {
				recursive = TRUE;
			}
		}

#ifndef GMIME24
		g_object_unref (part);
#endif
		if ((param_data =
				g_mime_content_type_get_parameter ((GMimeContentType *)ct,
						param_name)) != NULL) {
			return TRUE;
		}
		/* Get next part */
		if (!recursive) {
			break;
		}
	}

	return result;
}

static gboolean
rspamd_content_type_check (struct rspamd_task *task,
	GArray * args,
	gboolean check_subtype)
{
	const gchar *param_data;
	rspamd_regexp_t *re;
	struct expression_argument *arg1, *arg_pattern;
	GMimeObject *part;
	GMimeContentType *ct;
	gint r;
	guint i;
	gboolean recursive = FALSE;
	struct rspamd_mime_part *cur_part;

	if (args == NULL || args->len < 1) {
		msg_warn_task ("no parameters to function");
		return FALSE;
	}

	arg_pattern = &g_array_index (args, struct expression_argument, 0);

	for (i = 0; i < task->parts->len; i ++) {
		cur_part = g_ptr_array_index (task->parts, i);
		part = cur_part->mime;
		ct = (GMimeContentType *)g_mime_object_get_content_type (part);

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
			if (g_mime_content_type_is_type (ct, "multipart", "*")) {
				recursive = TRUE;
			}
		}

#ifndef GMIME24
		g_object_unref (part);
#endif
		if (check_subtype) {
			param_data = ct->subtype;
		}
		else {
			param_data = ct->type;
		}

		if (arg_pattern->type == EXPRESSION_ARGUMENT_REGEXP) {
			re = arg_pattern->data;
			r = rspamd_regexp_search (re, param_data, 0,
					NULL, NULL, FALSE, NULL);

			if (r) {
				return TRUE;
			}
		}
		else {
			/* Just do strcasecmp */
			if (g_ascii_strcasecmp (param_data, arg_pattern->data) == 0) {
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
compare_subtype (struct rspamd_task *task, GMimeContentType * ct,
	struct expression_argument *subtype)
{
	rspamd_regexp_t *re;
	gint r = 0;

	if (subtype == NULL || ct == NULL) {
		msg_warn_task ("invalid parameters passed");
		return FALSE;
	}
	if (subtype->type == EXPRESSION_ARGUMENT_REGEXP) {
		re = subtype->data;
		r = rspamd_regexp_search (re, ct->subtype, 0,
				NULL, NULL, FALSE, NULL);
	}
	else {
		/* Just do strcasecmp */
		if (ct->subtype && g_ascii_strcasecmp (ct->subtype, subtype->data) == 0) {
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
		return part->content->len <= max;
	}
	else if (max == 0) {
		return part->content->len >= min;
	}
	else {
		return part->content->len >= min && part->content->len <= max;
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
	GMimeContentType *ct;
	gint r;
	guint i;

	for (i = 0; i < task->parts->len; i ++) {
		part = g_ptr_array_index (task->parts, i);
		ct = part->type;

		if (ct == NULL) {
			continue;
		}

		if (param_type->type == EXPRESSION_ARGUMENT_REGEXP) {
			re = param_type->data;

			r = rspamd_regexp_search (re, ct->type, 0,
					NULL, NULL, FALSE, NULL);
			/* Also check subtype and length of the part */
			if (r && param_subtype) {
				r = compare_len (part, min_len, max_len) &&
						compare_subtype (task, ct, param_subtype);

				return r;
			}
		}
		else {
			/* Just do strcasecmp */
			if (ct->type && g_ascii_strcasecmp (ct->type, param_type->data) == 0) {
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
