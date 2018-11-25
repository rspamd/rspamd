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

/*
 * Copyright (C) 2002-2015 Igor Sysoev
 * Copyright (C) 2011-2015 Nginx, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
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
#include "url.h"
#include "util.h"
#include "rspamd.h"
#include "message.h"
#include "multipattern.h"
#include "contrib/uthash/utlist.h"
#include <unicode/utf8.h>
#include <unicode/uchar.h>

typedef struct url_match_s {
	const gchar *m_begin;
	gsize m_len;
	const gchar *pattern;
	const gchar *prefix;
	const gchar *newline_pos;
	const gchar *prev_newline_pos;
	gboolean add_prefix;
	gchar st;
} url_match_t;

#define URL_FLAG_NOHTML (1 << 0)
#define URL_FLAG_TLD_MATCH (1 << 1)
#define URL_FLAG_STAR_MATCH (1 << 2)
#define URL_FLAG_REGEXP (1 << 3)

struct url_callback_data;

static const struct {
	enum rspamd_url_protocol proto;
	const gchar *name;
	gsize len;
} rspamd_url_protocols[] = {
		{
				.proto = PROTOCOL_FILE,
				.name = "file",
				.len = 4
		},
		{
				.proto = PROTOCOL_FTP,
				.name = "ftp",
				.len = 3
		},
		{
				.proto = PROTOCOL_HTTP,
				.name = "http",
				.len = 4
		},
		{
				.proto = PROTOCOL_HTTPS,
				.name = "https",
				.len = 5
		},
		{
				.proto = PROTOCOL_MAILTO,
				.name = "mailto",
				.len = 6
		},
		{
				.proto = PROTOCOL_UNKNOWN,
				.name = NULL,
				.len = 0
		}
};
struct url_matcher {
	const gchar *pattern;
	const gchar *prefix;

	gboolean (*start) (struct url_callback_data *cb,
			const gchar *pos,
			url_match_t *match);

	gboolean (*end) (struct url_callback_data *cb,
			const gchar *pos,
			url_match_t *match);

	gint flags;
	gsize patlen;
};

static gboolean url_file_start (struct url_callback_data *cb,
		const gchar *pos,
		url_match_t *match);

static gboolean url_file_end (struct url_callback_data *cb,
		const gchar *pos,
		url_match_t *match);

static gboolean url_web_start (struct url_callback_data *cb,
		const gchar *pos,
		url_match_t *match);

static gboolean url_web_end (struct url_callback_data *cb,
		const gchar *pos,
		url_match_t *match);

static gboolean url_tld_start (struct url_callback_data *cb,
		const gchar *pos,
		url_match_t *match);

static gboolean url_tld_end (struct url_callback_data *cb,
		const gchar *pos,
		url_match_t *match);

static gboolean url_email_start (struct url_callback_data *cb,
		const gchar *pos,
		url_match_t *match);

static gboolean url_email_end (struct url_callback_data *cb,
		const gchar *pos,
		url_match_t *match);

struct url_matcher static_matchers[] = {
		/* Common prefixes */
		{"file://",   "",          url_file_start,  url_file_end,
				0, 0},
		{"file:\\\\",   "",        url_file_start,  url_file_end,
				0, 0},
		{"ftp://",    "",          url_web_start,   url_web_end,
				0, 0},
		{"ftp:\\\\",    "",        url_web_start,   url_web_end,
				0, 0},
		{"sftp://",   "",          url_web_start,   url_web_end,
				0, 0},
		{"http:",   "",            url_web_start,   url_web_end,
				0, 0},
		{"https:",   "",           url_web_start,   url_web_end,
				0, 0},
		{"news://",   "",          url_web_start,   url_web_end,
				0, 0},
		{"nntp://",   "",          url_web_start,   url_web_end,
				0, 0},
		{"telnet://", "",          url_web_start,   url_web_end,
				0, 0},
		{"webcal://", "",          url_web_start,   url_web_end,
				0, 0},
		{"mailto:",   "",          url_email_start, url_email_end,
				0, 0},
		{"callto://", "",          url_web_start,   url_web_end,
				0, 0},
		{"h323:",     "",          url_web_start,   url_web_end,
				0, 0},
		{"sip:",      "",          url_web_start,   url_web_end,
				0, 0},
		{"www.",      "http://",   url_web_start,   url_web_end,
				0, 0},
		{"ftp.",      "ftp://",    url_web_start,   url_web_end,
				URL_FLAG_NOHTML, 0},
		/* Likely emails */
		{"@",         "mailto://", url_email_start, url_email_end,
				URL_FLAG_NOHTML, 0}
};

struct url_callback_data {
	const gchar *begin;
	gchar *url_str;
	rspamd_mempool_t *pool;
	gint len;
	gboolean is_html;
	gboolean prefix_added;
	guint newline_idx;
	GPtrArray *newlines;
	const gchar *start;
	const gchar *fin;
	const gchar *end;
	const gchar *last_at;
	url_insert_function func;
	void *funcd;
};

struct url_match_scanner {
	GArray *matchers;
	struct rspamd_multipattern *search_trie;
};

struct url_match_scanner *url_scanner = NULL;

enum {
	IS_LWSP = (1 << 0),
	IS_DOMAIN = (1 << 1),
	IS_URLSAFE = (1 << 2),
	IS_MAILSAFE = (1 << 3),
	IS_DOMAIN_END = (1 << 4)
};

static const unsigned int url_scanner_table[256] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, IS_LWSP, IS_LWSP, IS_LWSP, IS_LWSP, IS_LWSP, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, IS_LWSP /*   */,
		IS_MAILSAFE /* ! */, IS_URLSAFE|IS_DOMAIN_END|IS_MAILSAFE /* " */,
		IS_MAILSAFE /* # */, IS_MAILSAFE /* $ */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* % */, 0 /* & */, IS_MAILSAFE /* ' */,
		0 /* ( */, 0 /* ) */, IS_MAILSAFE /* * */,
		IS_MAILSAFE /* + */, IS_MAILSAFE /* , */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* - */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* . */, IS_DOMAIN_END|IS_MAILSAFE /* / */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* 0 */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* 1 */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* 2 */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* 3 */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* 4 */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* 5 */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* 6 */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* 7 */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* 8 */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* 9 */, IS_DOMAIN_END /* : */,
		0 /* ; */, IS_URLSAFE|IS_DOMAIN_END /* < */, 0 /* = */,
		IS_URLSAFE|IS_DOMAIN_END /* > */, IS_DOMAIN_END /* ? */, 0 /* @ */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* A */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* B */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* C */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* D */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* E */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* F */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* G */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* H */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* I */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* J */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* K */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* L */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* M */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* N */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* O */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* P */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* Q */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* R */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* S */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* T */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* U */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* V */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* W */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* X */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* Y */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* Z */, 0 /* [ */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* \ */, 0 /* ] */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* ^ */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* _ */,
		IS_URLSAFE|IS_DOMAIN_END /* ` */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* a */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* b */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* c */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* d */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* e */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* f */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* g */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* h */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* i */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* j */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* k */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* l */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* m */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* n */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* o */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* p */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* q */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* r */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* s */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* t */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* u */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* v */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* w */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* x */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* y */,
		IS_URLSAFE|IS_DOMAIN|IS_MAILSAFE /* z */,
		IS_URLSAFE|IS_DOMAIN_END|IS_MAILSAFE /* { */,
		IS_URLSAFE|IS_DOMAIN_END|IS_MAILSAFE /* | */,
		IS_URLSAFE|IS_DOMAIN_END|IS_MAILSAFE /* } */,
		IS_URLSAFE|IS_DOMAIN_END|IS_MAILSAFE /* ~ */, 0, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN, IS_URLSAFE|IS_DOMAIN,
		IS_URLSAFE|IS_DOMAIN
};

#define is_lwsp(x) ((url_scanner_table[(guchar)(x)] & IS_LWSP) != 0)
#define is_mailsafe(x) ((url_scanner_table[(guchar)(x)] & (IS_MAILSAFE)) != 0)
#define is_domain(x) ((url_scanner_table[(guchar)(x)] & IS_DOMAIN) != 0)
#define is_urlsafe(x) ((url_scanner_table[(guchar)(x)] & (IS_URLSAFE)) != 0)

const gchar *
rspamd_url_strerror (enum uri_errno err)
{
	switch (err) {
		case URI_ERRNO_OK:
			return "Parsing went well";
		case URI_ERRNO_EMPTY:
			return "The URI string was empty";
		case URI_ERRNO_INVALID_PROTOCOL:
			return "No protocol was found";
		case URI_ERRNO_BAD_FORMAT:
			return "Bad URL format";
		case URI_ERRNO_BAD_ENCODING:
			return "Invalid symbols encoded";
		case URI_ERRNO_INVALID_PORT:
			return "Port number is bad";
		case URI_ERRNO_TLD_MISSING:
			return "TLD part is not detected";
		case URI_ERRNO_HOST_MISSING:
			return "Host part is missing";
	}

	return NULL;
}

static void
rspamd_url_parse_tld_file (const gchar *fname,
		struct url_match_scanner *scanner)
{
	FILE *f;
	struct url_matcher m;
	gchar *linebuf = NULL, *p;
	gsize buflen = 0;
	gssize r;
	gint flags;

	f = fopen (fname, "r");

	if (f == NULL) {
		msg_err ("cannot open TLD file %s: %s", fname, strerror (errno));
		return;
	}

	m.end = url_tld_end;
	m.start = url_tld_start;
	m.prefix = "http://";

	while ((r = getline (&linebuf, &buflen, f)) > 0) {
		if (linebuf[0] == '/' || g_ascii_isspace (linebuf[0])) {
			/* Skip comment or empty line */
			continue;
		}

		g_strchomp (linebuf);

		/* TODO: add support for ! patterns */
		if (linebuf[0] == '!') {
			msg_debug ("skip '!' patterns from parsing for now: %s", linebuf);
			continue;
		}

		flags = URL_FLAG_NOHTML | URL_FLAG_TLD_MATCH;

#ifndef WITH_HYPERSCAN
		if (linebuf[0] == '*') {
			flags |= URL_FLAG_STAR_MATCH;
			p = strchr (linebuf, '.');

			if (p == NULL) {
				msg_err ("got bad star line, skip it: %s", linebuf);
				continue;
			}
			p++;
		}
		else {
			p = linebuf;
		}
#else
		p = linebuf;
#endif

		m.flags = flags;
		rspamd_multipattern_add_pattern (url_scanner->search_trie, p,
				RSPAMD_MULTIPATTERN_TLD | RSPAMD_MULTIPATTERN_ICASE);
		m.pattern = rspamd_multipattern_get_pattern (url_scanner->search_trie,
				rspamd_multipattern_get_npatterns (url_scanner->search_trie) - 1);
		m.patlen = strlen (m.pattern);
		g_array_append_val (url_scanner->matchers, m);
	}

	free (linebuf);
	fclose (f);
}

static void
rspamd_url_add_static_matchers (struct url_match_scanner *sc)
{
	gint n = G_N_ELEMENTS (static_matchers), i;

	for (i = 0; i < n; i++) {
		if (static_matchers[i].flags & URL_FLAG_REGEXP) {
			rspamd_multipattern_add_pattern (url_scanner->search_trie,
					static_matchers[i].pattern,
					RSPAMD_MULTIPATTERN_ICASE|RSPAMD_MULTIPATTERN_UTF8|
							RSPAMD_MULTIPATTERN_RE);
		}
		else {
			rspamd_multipattern_add_pattern (url_scanner->search_trie,
					static_matchers[i].pattern,
					RSPAMD_MULTIPATTERN_ICASE|RSPAMD_MULTIPATTERN_UTF8);
		}

		static_matchers[i].patlen = strlen (static_matchers[i].pattern);
	}

	g_array_append_vals (sc->matchers, static_matchers, n);
}

void
rspamd_url_deinit (void)
{
	if (url_scanner != NULL) {
		rspamd_multipattern_destroy (url_scanner->search_trie);
		g_array_free (url_scanner->matchers, TRUE);
		g_free (url_scanner);

		url_scanner = NULL;
	}
}

void
rspamd_url_init (const gchar *tld_file)
{
	GError *err = NULL;

	if (url_scanner != NULL) {
		rspamd_url_deinit ();
	}

	url_scanner = g_malloc (sizeof (struct url_match_scanner));

	if (tld_file) {
		/* Reserve larger multipattern */
		url_scanner->matchers = g_array_sized_new (FALSE, TRUE,
				sizeof (struct url_matcher), 13000);
		url_scanner->search_trie = rspamd_multipattern_create_sized (13000,
				RSPAMD_MULTIPATTERN_TLD | RSPAMD_MULTIPATTERN_ICASE);
	}
	else {
		url_scanner->matchers = g_array_sized_new (FALSE, TRUE,
				sizeof (struct url_matcher), 128);
		url_scanner->search_trie = rspamd_multipattern_create_sized (128,
				RSPAMD_MULTIPATTERN_TLD | RSPAMD_MULTIPATTERN_ICASE);
	}

	rspamd_url_add_static_matchers (url_scanner);

	if (tld_file != NULL) {
		rspamd_url_parse_tld_file (tld_file, url_scanner);
	}

	if (!rspamd_multipattern_compile (url_scanner->search_trie, &err)) {
		msg_err ("cannot compile tld patterns, url matching will be "
				 "broken completely: %e", err);
		g_error_free (err);
	}

	msg_debug ("initialized trie of %ud elements",
			url_scanner->matchers->len);
}

#define SET_U(u, field) do {                                                \
    if ((u) != NULL) {                                                        \
        (u)->field_set |= 1 << (field);                                        \
        (u)->field_data[(field)].len = p - c;                                \
        (u)->field_data[(field)].off = c - str;                                \
    }                                                                        \
} while (0)

static gboolean
is_url_start (gchar c)
{
	if (c == '(' ||
			c == '{' ||
			c == '[' ||
			c == '<' ||
			c == '\'') {
		return TRUE;
	}

	return FALSE;
}

static gboolean
is_url_end (gchar c)
{
	if (c == ')' ||
			c == '}' ||
			c == ']' ||
			c == '>' ||
			c == '\'') {
		return TRUE;
	}

	return FALSE;
}

static gint
rspamd_mailto_parse (struct http_parser_url *u, const gchar *str, gsize len,
		gchar const **end, gboolean strict, guint *flags)
{
	const gchar *p = str, *c = str, *last = str + len;
	gchar t;
	gint ret = 1;
	enum {
		parse_mailto,
		parse_slash,
		parse_slash_slash,
		parse_semicolon,
		parse_prefix_question,
		parse_destination,
		parse_equal,
		parse_user,
		parse_at,
		parse_domain,
		parse_suffix_question,
		parse_query
	} st = parse_mailto;

	if (u != NULL) {
		memset (u, 0, sizeof (*u));
	}

	while (p < last) {
		t = *p;

		switch (st) {
			case parse_mailto:
				if (t == ':') {
					st = parse_semicolon;
					SET_U (u, UF_SCHEMA);
				}
				p++;
				break;
			case parse_semicolon:
				if (t == '/' || t == '\\') {
					st = parse_slash;
					p++;
				}
				else {
					*flags |= RSPAMD_URL_FLAG_MISSINGSLASHES;
					st = parse_slash_slash;
				}
				break;
			case parse_slash:
				if (t == '/' || t == '\\') {
					st = parse_slash_slash;
				}
				else {
					goto out;
				}
				p++;
				break;
			case parse_slash_slash:
				if (t == '?') {
					st = parse_prefix_question;
					p++;
				}
				else if (t != '/' && t != '\\') {
					c = p;
					st = parse_user;
				}
				else {
					/* Skip multiple slashes */
					p++;
				}
				break;
			case parse_prefix_question:
				if (t == 't') {
					/* XXX: accept only to= */
					st = parse_destination;
				}
				else {
					goto out;
				}
				break;
			case parse_destination:
				if (t == '=') {
					st = parse_equal;
				}
				p++;
				break;
			case parse_equal:
				c = p;
				st = parse_user;
				break;
			case parse_user:
				if (t == '@') {
					if (p - c == 0) {
						goto out;
					}
					SET_U (u, UF_USERINFO);
					st = parse_at;
				}
				else if (!is_mailsafe (t)) {
					goto out;
				}
				p++;
				break;
			case parse_at:
				c = p;
				st = parse_domain;
				break;
			case parse_domain:
				if (t == '?') {
					SET_U (u, UF_HOST);
					st = parse_suffix_question;
				}
				else if (!is_domain (t) && t != '.' && t != '_') {
					goto out;
				}
				p++;
				break;
			case parse_suffix_question:
				c = p;
				st = parse_query;
				break;
			case parse_query:
				if (!is_mailsafe (t)) {
					goto out;
				}
				p++;
				break;
		}
	}

	if (st == parse_domain) {
		if (p - c != 0) {
			SET_U (u, UF_HOST);
			ret = 0;
		}
	}
	else if (st == parse_query) {
		if (p - c > 0) {
			SET_U (u, UF_QUERY);
		}

		ret = 0;
	}

	out:
	if (end != NULL) {
		*end = p;
	}

	if (!strict) {
		return 0;
	}

	return ret;
}

static gint
rspamd_web_parse (struct http_parser_url *u, const gchar *str, gsize len,
		gchar const **end, gboolean strict, guint *flags)
{
	const gchar *p = str, *c = str, *last = str + len, *slash = NULL,
			*password_start = NULL, *user_start = NULL;
	gchar t;
	UChar32 uc;
	glong pt;
	gint ret = 1;
	gboolean user_seen = FALSE;
	enum {
		parse_protocol,
		parse_slash,
		parse_slash_slash,
		parse_semicolon,
		parse_user,
		parse_at,
		parse_multiple_at,
		parse_password_start,
		parse_password,
		parse_domain,
		parse_ipv6,
		parse_port_password,
		parse_port,
		parse_suffix_slash,
		parse_path,
		parse_query,
		parse_part
	} st = parse_protocol;

	if (u != NULL) {
		memset (u, 0, sizeof (*u));
	}

	while (p < last) {
		t = *p;

		switch (st) {
			case parse_protocol:
				if (t == ':') {
					st = parse_semicolon;
					SET_U (u, UF_SCHEMA);
				}
				else if (!g_ascii_isalnum (t) && t != '+' && t != '-') {
					if (!strict && p > c) {
						/* We might have some domain, but no protocol */
						st = parse_domain;
						p = c;
						slash = c;
						break;
					}
					else {
						goto out;
					}
				}
				p++;
				break;
			case parse_semicolon:
				if (t == '/' || t == '\\') {
					st = parse_slash;
					p++;
				}
				else {
					st = parse_slash_slash;
					*(flags) |= RSPAMD_URL_FLAG_MISSINGSLASHES;
				}
				break;
			case parse_slash:
				if (t == '/' || t == '\\') {
					st = parse_slash_slash;
				}
				else {
					goto out;
				}
				p++;
				break;
			case parse_slash_slash:

				if (t != '/' && t != '\\') {
					c = p;
					st = parse_domain;
					slash = p;

					if (*p == '[') {
						st = parse_ipv6;
						p++;
						c = p;
					}
				}
				else {
					/* Skip multiple slashes */
					p++;
				}
				break;
			case parse_ipv6:
				if (t == ']') {
					if (p - c == 0) {
						goto out;
					}
					SET_U (u, UF_HOST);
					p++;

					if (*p == ':') {
						st = parse_port;
						c = p + 1;
					}
					else if (*p == '/') {
						st = parse_path;
						c = p + 1;
					}
					else if (p != last) {
						goto out;
					}
				}
				else if (!g_ascii_isxdigit (t) && t != ':' && t != '.') {
					goto out;
				}
				p++;
				break;
			case parse_user:
				if (t == ':') {
					if (p - c == 0) {
						goto out;
					}
					user_start = c;
					st = parse_password_start;
				}
				else if (t == '@') {
					/* No password */
					if (p - c == 0) {
						/* We have multiple at in fact */
						st = parse_multiple_at;
						user_seen = TRUE;
						*flags |= RSPAMD_URL_FLAG_OBSCURED;

						continue;
					}

					SET_U (u, UF_USERINFO);
					*flags |= RSPAMD_URL_FLAG_HAS_USER;
					st = parse_at;
				}
				else if (!g_ascii_isgraph (t)) {
					goto out;
				}
				p++;
				break;
			case parse_multiple_at:
				if (t != '@') {
					if (p - c == 0) {
						goto out;
					}

					/* For now, we ignore all that stuff as it is bogus */
					SET_U (u, UF_USERINFO);
					st = parse_at;
				}
				else {
					p ++;
				}
				break;
			case parse_password_start:
				if (t == '@') {
					/* Empty password */
					SET_U (u, UF_USERINFO);
					if (u != NULL && u->field_data[UF_USERINFO].len > 0) {
						/* Eat semicolon */
						u->field_data[UF_USERINFO].len--;
					}
					*flags |= RSPAMD_URL_FLAG_HAS_USER;
					st = parse_at;
				}
				else {
					c = p;
					password_start = p;
					st = parse_password;
				}
				p++;
				break;
			case parse_password:
				if (t == '@') {
					/* XXX: password is not stored */
					if (u != NULL) {
						if (u->field_data[UF_USERINFO].len == 0
								&& password_start
								&& user_start && password_start > user_start + 1) {
							*flags |= RSPAMD_URL_FLAG_HAS_USER;
							u->field_set |= 1u << (UF_USERINFO);
							u->field_data[UF_USERINFO].len =
									password_start - user_start - 1;
							u->field_data[UF_USERINFO].off =
									user_start - str;
						}

					}
					st = parse_at;
				}
				else if (!g_ascii_isgraph (t)) {
					goto out;
				}
				p++;
				break;
			case parse_at:
				c = p;

				if (t == '@') {
					*flags |= RSPAMD_URL_FLAG_OBSCURED;
					p ++;
				}
				else if (t == '[') {
					st = parse_ipv6;
					p++;
					c = p;
				}
				else {
					st = parse_domain;
				}
				break;
			case parse_domain:
				if (t == '/' || t == ':' || t == '?' || t == '#') {
					if (p - c == 0) {
						goto out;
					}
					if (t == '/') {
						SET_U (u, UF_HOST);
						st = parse_suffix_slash;
					}
					else if (t == '?') {
						SET_U (u, UF_HOST);
						st = parse_query;
						c = p + 1;
					}
					else if (t == '#') {
						SET_U (u, UF_HOST);
						st = parse_part;
						c = p + 1;
					}
					else if (!user_seen) {
						/*
						 * Here we can have both port and password, hence we need
						 * to apply some heuristic here
						 */
						st = parse_port_password;
					}
					else {
						/*
						 * We can go only for parsing port here
						 */
						SET_U (u, UF_HOST);
						st = parse_port;
						c = p + 1;
					}
					p++;
				}
				else {
					if (is_url_end (t)) {
						goto set;
					}
					else if (*p == '@' && !user_seen) {
						/* We need to fallback and test user */
						p = slash;
						user_seen = TRUE;
						st = parse_user;
					}
					else if (*p != '.' && *p != '-' && *p != '_' && *p != '%') {
						if (*p & 0x80) {
							*flags |= RSPAMD_URL_FLAG_IDN;
							guint i = 0;

							U8_NEXT (p, i, last - p, uc);

							if (uc < 0) {
								/* Bad utf8 */
								goto out;
							}

							if (!u_isalnum (uc)) {
								/* Bad symbol */
								if (strict) {
									goto out;
								}
								else {
									goto set;
								}
							}

							p = p + i;
						}
						else if (is_urlsafe (*p)) {
							p ++;
						}
						else {
							if (strict) {
								goto out;
							}
							else {
								goto set;
							}
						}
					}
					else {
						p++;
					}
				}
				break;
			case parse_port_password:
				if (g_ascii_isdigit (t)) {
					const gchar *tmp = p;

					while (tmp < last) {
						if (!g_ascii_isdigit (*tmp)) {
							if (*tmp == '/' || *tmp == '#' || *tmp == '?' ||
									is_url_end (*tmp) || g_ascii_isspace (*tmp)) {
								/* Port + something */
								st = parse_port;
								c = slash;
								p--;
								SET_U (u, UF_HOST);
								p++;
								c = p;
								break;
							}
							else {
								/* Not a port, bad character at the end */
								break;
							}
						}
						tmp ++;
					}

					if (tmp == last) {
						/* Host + port only */
						st = parse_port;
						c = slash;
						p--;
						SET_U (u, UF_HOST);
						p++;
						c = p;
					}

					if (st != parse_port) {
						/* Fallback to user:password */
						p = slash;
						c = slash;
						user_seen = TRUE;
						st = parse_user;
					}
				}
				else {
					/* Rewind back */
					p = slash;
					c = slash;
					user_seen = TRUE;
					st = parse_user;
				}
				break;
			case parse_port:
				if (t == '/') {
					pt = strtoul (c, NULL, 10);
					if (pt == 0 || pt > 65535) {
						goto out;
					}
					if (u != NULL) {
						u->port = pt;
						*flags |= RSPAMD_URL_FLAG_HAS_PORT;
					}
					st = parse_suffix_slash;
				}
				else if (t == '?') {
					pt = strtoul (c, NULL, 10);
					if (pt == 0 || pt > 65535) {
						goto out;
					}
					if (u != NULL) {
						u->port = pt;
						*flags |= RSPAMD_URL_FLAG_HAS_PORT;
					}

					c = p + 1;
					st = parse_query;
				}
				else if (t == '#') {
					pt = strtoul (c, NULL, 10);
					if (pt == 0 || pt > 65535) {
						goto out;
					}
					if (u != NULL) {
						u->port = pt;
						*flags |= RSPAMD_URL_FLAG_HAS_PORT;
					}

					c = p + 1;
					st = parse_part;
				}
				else if (is_url_end (t)) {
					goto set;
				}
				else if (!g_ascii_isdigit (t)) {
					if (strict || !g_ascii_isspace (t)) {
						goto out;
					}
					else {
						goto set;
					}
				}
				p++;
				break;
			case parse_suffix_slash:
				if (t != '/') {
					c = p;
					st = parse_path;
				}
				else {
					/* Skip extra slashes */
					p++;
				}
				break;
			case parse_path:
				if (t == '?') {
					if (p - c != 0) {
						SET_U (u, UF_PATH);
					}
					c = p + 1;
					st = parse_query;
				}
				else if (is_url_end (t)) {
					goto set;
				}
				else if (is_lwsp (t)) {
					if (strict) {
						if (g_ascii_isspace (t)) {
							goto set;
						}
						goto out;
					}
					else {
						goto set;
					}
				}
				p++;
				break;
			case parse_query:
				if (t == '#') {
					if (p - c != 0) {
						SET_U (u, UF_QUERY);
					}
					c = p + 1;
					st = parse_part;
				}
				else if (is_url_end (t)) {
					goto set;
				}
				else if (is_lwsp (t)) {
					if (strict) {
						if (g_ascii_isspace (t)) {
							goto set;
						}
						goto out;
					}
					else {
						goto set;
					}
				}
				p++;
				break;
			case parse_part:
				if (is_url_end (t)) {
					goto set;
				}
				else if (is_lwsp (t)) {
					if (strict) {
						if (g_ascii_isspace (t)) {
							goto set;
						}
						goto out;
					}
					else {
						goto set;
					}
				}
				p++;
				break;
		}
	}

	set:
	/* Parse remaining */
	switch (st) {
		case parse_domain:
			if (p - c == 0) {
				goto out;
			}
			SET_U (u, UF_HOST);
			ret = 0;

			break;
		case parse_port:
			pt = strtoul (c, NULL, 10);
			if (pt == 0 || pt > 65535) {
				goto out;
			}
			if (u != NULL) {
				u->port = pt;
			}

			ret = 0;
			break;
		case parse_suffix_slash:
			/* Url ends with '/' */
			ret = 0;
			break;
		case parse_path:
			if (p - c > 0) {
				SET_U (u, UF_PATH);
			}
			ret = 0;
			break;
		case parse_query:
			if (p - c > 0) {
				SET_U (u, UF_QUERY);
			}
			ret = 0;
			break;
		case parse_part:
			if (p - c > 0) {
				SET_U (u, UF_FRAGMENT);
			}
			ret = 0;
			break;
		case parse_ipv6:
			if (t != ']') {
				ret = 1;
			}
			else {
				/* e.g. http://[::] */
				ret = 0;
			}
			break;
		default:
			/* Error state */
			ret = 1;
			break;
	}
	out:
	if (end != NULL) {
		*end = p;
	}

	return ret;
}

#undef SET_U

static gint
rspamd_tld_trie_callback (struct rspamd_multipattern *mp,
		guint strnum,
		gint match_start,
		gint match_pos,
		const gchar *text,
		gsize len,
		void *context)
{
	struct url_matcher *matcher;
	const gchar *start, *pos, *p;
	struct rspamd_url *url = context;
	gint ndots = 1;

	matcher = &g_array_index (url_scanner->matchers, struct url_matcher,
			strnum);

	if (matcher->flags & URL_FLAG_STAR_MATCH) {
		/* Skip one more tld component */
		ndots = 2;
	}

	pos = text + match_start;
	p = pos - 1;
	start = url->host;

	if (*pos != '.' || match_pos != (gint) url->hostlen) {
		/* Something weird has been found */
		if (match_pos == (gint) url->hostlen - 1) {
			pos = url->host + match_pos;
			if (*pos == '.') {
				/* This is dot at the end of domain */
				url->hostlen--;
			}
			else {
				return 0;
			}
		}
		else {
			return 0;
		}
	}

	/* Now we need to find top level domain */
	pos = start;
	while (p >= start && ndots > 0) {
		if (*p == '.') {
			ndots--;
			pos = p + 1;
		}

		p--;
	}

	if ((ndots == 0 || p == start - 1) &&
			url->tldlen < url->host + url->hostlen - pos) {
		url->tld = (gchar *) pos;
		url->tldlen = url->host + url->hostlen - pos;
	}

	return 0;
}

static gboolean
rspamd_url_is_ip (struct rspamd_url *uri, rspamd_mempool_t *pool)
{
	const gchar *p, *end, *c;
	gchar buf[INET6_ADDRSTRLEN + 1], *errstr;
	struct in_addr in4;
	struct in6_addr in6;
	gboolean ret = FALSE, check_num = TRUE;
	guint32 n, dots, t = 0, i = 0, shift, nshift;

	p = uri->host;
	end = p + uri->hostlen;

	if (*p == '[' && *(end - 1) == ']') {
		p++;
		end--;
	}

	while (*(end - 1) == '.' && end > p) {
		end--;
	}

	if (end - p > (gint) sizeof (buf) - 1) {
		return FALSE;
	}

	rspamd_strlcpy (buf, p, end - p + 1);

	if (inet_pton (AF_INET, buf, &in4) == 1) {
		uri->host = rspamd_mempool_alloc (pool, INET_ADDRSTRLEN + 1);
		memset (uri->host, 0, INET_ADDRSTRLEN + 1);
		inet_ntop (AF_INET, &in4, uri->host, INET_ADDRSTRLEN);
		uri->hostlen = strlen (uri->host);
		uri->tld = uri->host;
		uri->tldlen = uri->hostlen;
		uri->flags |= RSPAMD_URL_FLAG_NUMERIC;
		ret = TRUE;
	}
	else if (inet_pton (AF_INET6, buf, &in6) == 1) {
		uri->host = rspamd_mempool_alloc (pool, INET6_ADDRSTRLEN + 1);
		memset (uri->host, 0, INET6_ADDRSTRLEN + 1);
		inet_ntop (AF_INET6, &in6, uri->host, INET6_ADDRSTRLEN);
		uri->hostlen = strlen (uri->host);
		uri->tld = uri->host;
		uri->tldlen = uri->hostlen;
		uri->flags |= RSPAMD_URL_FLAG_NUMERIC;
		ret = TRUE;
	}
	else {
		/* Try also numeric notation */
		c = p;
		n = 0;
		dots = 0;
		shift = 0;

		while (p <= end && check_num) {
			if (shift < 32 &&
				((*p == '.' && dots < 3) || (p == end && dots <= 3))) {
				if (p - c + 1 >= (gint) sizeof (buf)) {
					msg_err_pool ("invalid numeric url %*.s...: too long",
							INET6_ADDRSTRLEN, c);
					return FALSE;
				}

				rspamd_strlcpy (buf, c, p - c + 1);
				c = p + 1;

				if (p < end && *p == '.') {
					dots++;
				}

				t = strtoul (buf, &errstr, 0);

				if (errstr == NULL || *errstr == '\0') {

					/*
					 * Even if we have zero, we need to shift by 1 octet
					 */
					nshift = (t == 0 ? shift + 8 : shift);

					/*
					 * Here we count number of octets encoded in this element
					 */
					for (i = 0; i < 4; i++) {
						if ((t >> (8 * i)) > 0) {
							nshift += 8;
						}
						else {
							break;
						}
					}
					/*
					 * Here we need to find the proper shift of the previous
					 * components, so we check possible cases:
					 * 1) 1 octet - just use it applying shift
					 * 2) 2 octets - convert to big endian 16 bit number
					 * 3) 3 octets - convert to big endian 24 bit number
					 * 4) 4 octets - convert to big endian 32 bit number
					 */
					switch (i) {
						case 4:
							t = GUINT32_TO_BE (t);
							break;
						case 3:
							t = (GUINT32_TO_BE (t & 0xFFFFFFU)) >> 8;
							break;
						case 2:
							t = GUINT16_TO_BE (t & 0xFFFFU);
							break;
						default:
							t = t & 0xFF;
							break;
					}

					if (p != end) {
						n |= t << shift;

						shift = nshift;
					}
				}
				else {
					check_num = FALSE;
				}
			}

			p++;
		}

		/* The last component should be last according to url normalization:
		 * 192.168.1 -> 192.168.0.1
		 * 192 -> 0.0.0.192
		 * 192.168 -> 192.0.0.168
		 */
		shift = 8 * (4 - i);
		n |= t << shift;

		if (check_num && dots <= 4) {
			memcpy (&in4, &n, sizeof (in4));
			uri->host = rspamd_mempool_alloc (pool, INET_ADDRSTRLEN + 1);
			memset (uri->host, 0, INET_ADDRSTRLEN + 1);
			inet_ntop (AF_INET, &in4, uri->host, INET_ADDRSTRLEN);
			uri->hostlen = strlen (uri->host);
			uri->tld = uri->host;
			uri->tldlen = uri->hostlen;
			uri->flags |= RSPAMD_URL_FLAG_NUMERIC|RSPAMD_URL_FLAG_OBSCURED;
			ret = TRUE;
		}
	}

	return ret;
}

static void
rspamd_url_shift (struct rspamd_url *uri, gsize nlen,
		enum http_parser_url_fields field)
{
	guint old_shift, shift = 0;

	/* Shift remaining data */
	switch (field) {
	case UF_SCHEMA:
		if (nlen >= uri->protocollen) {
			return;
		}
		else {
			shift = uri->protocollen - nlen;
		}

		old_shift = uri->protocollen;
		uri->protocollen -= shift;
		memmove (uri->string + uri->protocollen, uri->string + old_shift,
				uri->urllen - uri->protocollen);
		uri->urllen -= shift;
		uri->flags |= RSPAMD_URL_FLAG_SCHEMAENCODED;
		break;
	case UF_HOST:
		if (nlen >= uri->hostlen) {
			return;
		}
		else {
			shift = uri->hostlen - nlen;
		}

		old_shift = uri->hostlen;
		uri->hostlen -= shift;
		memmove (uri->host + uri->hostlen, uri->host + old_shift,
				uri->datalen + uri->querylen + uri->fragmentlen);
		uri->urllen -= shift;
		uri->flags |= RSPAMD_URL_FLAG_HOSTENCODED;
		break;
	case UF_PATH:
		if (nlen >= uri->datalen) {
			return;
		}
		else {
			shift = uri->datalen - nlen;
		}

		old_shift = uri->datalen;
		uri->datalen -= shift;
		memmove (uri->data + uri->datalen, uri->data + old_shift,
				uri->querylen + uri->fragmentlen);
		uri->urllen -= shift;
		uri->flags |= RSPAMD_URL_FLAG_PATHENCODED;
		break;
	case UF_QUERY:
		if (nlen >= uri->querylen) {
			return;
		}
		else {
			shift = uri->querylen - nlen;
		}

		old_shift = uri->querylen;
		uri->querylen -= shift;
		memmove (uri->query + uri->querylen, uri->query + old_shift,
				uri->fragmentlen);
		uri->urllen -= shift;
		uri->flags |= RSPAMD_URL_FLAG_QUERYENCODED;
		break;
	case UF_FRAGMENT:
		if (nlen >= uri->fragmentlen) {
			return;
		}
		else {
			shift = uri->fragmentlen - nlen;
		}

		uri->fragmentlen -= shift;
		uri->urllen -= shift;
		break;
	default:
		break;
	}

	/* Now adjust lengths and offsets */
	switch (field) {
	case UF_SCHEMA:
		if (uri->userlen > 0) {
			uri->user -= shift;
		}
		if (uri->hostlen > 0) {
			uri->host -= shift;
		}
		/* Go forward */
	case UF_HOST:
		if (uri->datalen > 0) {
			uri->data -= shift;
		}
		/* Go forward */
	case UF_PATH:
		if (uri->querylen > 0) {
			uri->query -= shift;
		}
		/* Go forward */
	case UF_QUERY:
		if (uri->fragmentlen > 0) {
			uri->fragment -= shift;
		}
		/* Go forward */
	case UF_FRAGMENT:
	default:
		break;
	}
}

enum uri_errno
rspamd_url_parse (struct rspamd_url *uri, gchar *uristring, gsize len,
		rspamd_mempool_t *pool)
{
	struct http_parser_url u;
	gchar *p, *comp;
	const gchar *end;
	guint i, complen, ret, flags = 0;
	guint unquoted_len = 0;

	memset (uri, 0, sizeof (*uri));
	memset (&u, 0, sizeof (u));
	uri->count = 1;

	if (*uristring == '\0') {
		return URI_ERRNO_EMPTY;
	}

	p = uristring;

	if (len > sizeof ("mailto:") - 1) {
		/* For mailto: urls we also need to add slashes to make it a valid URL */
		if (g_ascii_strncasecmp (p, "mailto:", sizeof ("mailto:") - 1) == 0) {
			ret = rspamd_mailto_parse (&u, uristring, len, &end, TRUE, &flags);
		}
		else {
			ret = rspamd_web_parse (&u, uristring, len, &end, TRUE, &flags);
		}
	}
	else {
		ret = rspamd_web_parse (&u, uristring, len, &end, TRUE, &flags);
	}

	if (ret != 0) {
		return URI_ERRNO_BAD_FORMAT;
	}

	if (end > uristring && (guint) (end - uristring) != len) {
		len = end - uristring;
	}

	uri->raw = p;
	uri->rawlen = len;

	if (flags & RSPAMD_URL_FLAG_MISSINGSLASHES) {
		len += 2;
		uri->string = rspamd_mempool_alloc (pool, len + 1);
		memcpy (uri->string, p, u.field_data[UF_SCHEMA].len);
		memcpy (uri->string + u.field_data[UF_SCHEMA].len, "://", 3);
		rspamd_strlcpy (uri->string + u.field_data[UF_SCHEMA].len + 3,
			p + u.field_data[UF_SCHEMA].len + 1,
				len - 2 - u.field_data[UF_SCHEMA].len);
		/* Compensate slashes added */
		for (i = UF_SCHEMA + 1; i < UF_MAX; i++) {
			if (u.field_set & (1 << i)) {
				u.field_data[i].off += 2;
			}
		}
	}
	else {
		uri->string = rspamd_mempool_alloc (pool, len + 1);
		rspamd_strlcpy (uri->string, p, len + 1);
	}

	uri->urllen = len;

	for (i = 0; i < UF_MAX; i++) {
		if (u.field_set & (1 << i)) {
			comp = uri->string + u.field_data[i].off;
			complen = u.field_data[i].len;

			switch (i) {
			case UF_SCHEMA:
				uri->protocollen = u.field_data[i].len;
				break;
			case UF_HOST:
				uri->host = comp;
				uri->hostlen = complen;
				break;
			case UF_PATH:
				uri->data = comp;
				uri->datalen = complen;
				break;
			case UF_QUERY:
				uri->query = comp;
				uri->querylen = complen;
				break;
			case UF_FRAGMENT:
				uri->fragment = comp;
				uri->fragmentlen = complen;
				break;
			case UF_USERINFO:
				uri->user = comp;
				uri->userlen = complen;
				break;
			default:
				break;
			}
		}
	}

	uri->port = u.port;
	uri->flags = flags;

	if (!uri->hostlen) {
		return URI_ERRNO_HOST_MISSING;
	}

	/* Now decode url symbols */
	unquoted_len = rspamd_url_decode (uri->string,
			uri->string,
			uri->protocollen);
	rspamd_url_shift (uri, unquoted_len, UF_SCHEMA);
	unquoted_len = rspamd_url_decode (uri->host, uri->host, uri->hostlen);
	if (rspamd_normalise_unicode_inplace (pool, uri->host, &unquoted_len)) {
		uri->flags |= RSPAMD_URL_FLAG_UNNORMALISED;
	}
	rspamd_url_shift (uri, unquoted_len, UF_HOST);

	if (uri->datalen) {
		unquoted_len = rspamd_url_decode (uri->data, uri->data, uri->datalen);
		if (rspamd_normalise_unicode_inplace (pool, uri->data, &unquoted_len)) {
			uri->flags |= RSPAMD_URL_FLAG_UNNORMALISED;
		}
		rspamd_url_shift (uri, unquoted_len, UF_PATH);
		/* We now normalize path */
		rspamd_http_normalize_path_inplace (uri->data, uri->datalen, &unquoted_len);
		rspamd_url_shift (uri, unquoted_len, UF_PATH);
	}
	if (uri->querylen) {
		unquoted_len = rspamd_url_decode (uri->query,
				uri->query,
				uri->querylen);
		if (rspamd_normalise_unicode_inplace (pool, uri->query, &unquoted_len)) {
			uri->flags |= RSPAMD_URL_FLAG_UNNORMALISED;
		}
		rspamd_url_shift (uri, unquoted_len, UF_QUERY);
	}
	if (uri->fragmentlen) {
		unquoted_len = rspamd_url_decode (uri->fragment,
				uri->fragment,
				uri->fragmentlen);
		if (rspamd_normalise_unicode_inplace (pool, uri->fragment, &unquoted_len)) {
			uri->flags |= RSPAMD_URL_FLAG_UNNORMALISED;
		}
		rspamd_url_shift (uri, unquoted_len, UF_FRAGMENT);
	}

	rspamd_str_lc (uri->string, uri->protocollen);
	rspamd_str_lc_utf8 (uri->host, uri->hostlen);

	uri->protocol = PROTOCOL_UNKNOWN;

	for (i = 0; i < G_N_ELEMENTS (rspamd_url_protocols); i++) {
		if (uri->protocollen == rspamd_url_protocols[i].len) {
			if (memcmp (uri->string, rspamd_url_protocols[i].name, uri->protocollen) ==
				0) {
				uri->protocol = i;
				break;
			}
		}
	}

	/* Find TLD part */
	rspamd_multipattern_lookup (url_scanner->search_trie,
				uri->host, uri->hostlen,
				rspamd_tld_trie_callback, uri, NULL);

	if (uri->tldlen == 0) {
		/* Ignore URL's without TLD if it is not a numeric URL */
		if (!rspamd_url_is_ip (uri, pool)) {
			return URI_ERRNO_TLD_MISSING;
		}
	}

	if (uri->protocol == PROTOCOL_UNKNOWN) {
		return URI_ERRNO_INVALID_PROTOCOL;
	}

	return URI_ERRNO_OK;
}

struct tld_trie_cbdata {
	const gchar *begin;
	gsize len;
	rspamd_ftok_t *out;
};

static gint
rspamd_tld_trie_find_callback (struct rspamd_multipattern *mp,
		guint strnum,
		gint match_start,
		gint match_pos,
		const gchar *text,
		gsize len,
		void *context)
{
	struct url_matcher *matcher;
	const gchar *start, *pos, *p;
	struct tld_trie_cbdata *cbdata = context;
	gint ndots = 1;

	matcher = &g_array_index (url_scanner->matchers, struct url_matcher,
			strnum);

	if (matcher->flags & URL_FLAG_STAR_MATCH) {
		/* Skip one more tld component */
		ndots = 2;
	}

	pos = text + match_start;
	p = pos - 1;
	start = text;

	if (*pos != '.' || match_pos != (gint)cbdata->len) {
		/* Something weird has been found */
		if (match_pos != (gint)cbdata->len - 1) {
			/* Search more */
			return 0;
		}
	}

	/* Now we need to find top level domain */
	pos = start;

	while (p >= start && ndots > 0) {
		if (*p == '.') {
			ndots--;
			pos = p + 1;
		}

		p--;
	}

	if (ndots == 0 || p == start - 1) {
		if (cbdata->begin + cbdata->len - pos > cbdata->out->len) {
			cbdata->out->begin = pos;
			cbdata->out->len = cbdata->begin + cbdata->len - pos;
		}
	}

	return 0;
}

gboolean
rspamd_url_find_tld (const gchar *in, gsize inlen, rspamd_ftok_t *out)
{
	struct tld_trie_cbdata cbdata;

	g_assert (in != NULL);
	g_assert (out != NULL);
	g_assert (url_scanner != NULL);

	cbdata.begin = in;
	cbdata.len = inlen;
	cbdata.out = out;
	out->len = 0;

	rspamd_multipattern_lookup (url_scanner->search_trie, in, inlen,
			rspamd_tld_trie_find_callback, &cbdata, NULL);

	if (out->len > 0) {
		return TRUE;
	}

	return FALSE;
}

static const gchar url_braces[] = {
		'(', ')',
		'{', '}',
		'[', ']',
		'<', '>',
		'|', '|',
		'\'', '\''
};


static gboolean
url_file_start (struct url_callback_data *cb,
		const gchar *pos,
		url_match_t *match)
{
	match->m_begin = pos;

	if (pos > cb->begin - 1) {
		match->st = *(pos - 1);
	}
	else {
		match->st = '\0';
	}

	return TRUE;
}

static gboolean
url_file_end (struct url_callback_data *cb,
		const gchar *pos,
		url_match_t *match)
{
	const gchar *p;
	gchar stop;
	guint i;

	p = pos + strlen (match->pattern);
	stop = *p;
	if (*p == '/') {
		p++;
	}

	for (i = 0; i < G_N_ELEMENTS (url_braces) / 2; i += 2) {
		if (*p == url_braces[i]) {
			stop = url_braces[i + 1];
			break;
		}
	}

	while (p < cb->end && *p != stop && is_urlsafe (*p)) {
		p++;
	}

	if (p == cb->begin) {
		return FALSE;
	}
	match->m_len = p - match->m_begin;

	return TRUE;

}

static gboolean
url_tld_start (struct url_callback_data *cb,
		const gchar *pos,
		url_match_t *match)
{
	const gchar *p = pos;

	/* Try to find the start of the url by finding any non-urlsafe character or whitespace/punctuation */
	while (p >= cb->begin) {
		if (!is_domain (*p) || g_ascii_isspace (*p) || is_url_start (*p) ||
				p == match->prev_newline_pos) {
			if (!is_url_start (*p) && !g_ascii_isspace (*p) &&
					p != match->prev_newline_pos) {
				return FALSE;
			}

			if (p != match->prev_newline_pos) {
				match->st = *p;

				p++;
			}
			else {
				match->st = '\n';
			}

			if (!g_ascii_isalnum (*p)) {
				/* Urls cannot start with strange symbols */
				return FALSE;
			}

			match->m_begin = p;
			return TRUE;
		}
		else if (p == cb->begin && p != pos) {
			match->st = '\0';
			match->m_begin = p;

			return TRUE;
		}
		else if (*p == '.') {
			if (p == cb->begin) {
				/* Urls cannot start with a dot */
				return FALSE;
			}
			if (!g_ascii_isalnum (p[1])) {
				/* Wrong we have an invalid character after dot */
				return FALSE;
			}
		}
		else if (*p == '/') {
			/* Urls cannot contain '/' in their body */
			return FALSE;
		}

		p--;
	}

	return FALSE;
}

static gboolean
url_tld_end (struct url_callback_data *cb,
		const gchar *pos,
		url_match_t *match)
{
	const gchar *p;
	gboolean ret = FALSE;

	p = pos + match->m_len;

	if (p == cb->end) {
		match->m_len = p - match->m_begin;
		return TRUE;
	}
	else if (*p == '/' || *p == ':' || is_url_end (*p) || is_lwsp (*p) ||
			(match->st != '<' && p == match->newline_pos)) {
		/* Parse arguments, ports by normal way by url default function */
		p = match->m_begin;
		/* Check common prefix */
		if (g_ascii_strncasecmp (p, "http://", sizeof ("http://") - 1) == 0) {
			ret = url_web_end (cb,
					match->m_begin + sizeof ("http://") - 1,
					match);
		}
		else {
			ret = url_web_end (cb, match->m_begin, match);
		}

	}
	else if (*p == '.') {
		p++;
		if (p < cb->end) {
			if (g_ascii_isspace (*p) || *p == '/' ||
				*p == '?' || *p == ':') {
				ret = url_web_end (cb, match->m_begin, match);
			}
		}
	}

	if (ret) {
		/* Check sanity of match found */
		if (match->m_begin + match->m_len <= pos) {
			return FALSE;
		}
	}

	return ret;
}

static gboolean
url_web_start (struct url_callback_data *cb,
		const gchar *pos,
		url_match_t *match)
{
	/* Check what we have found */
	if (pos > cb->begin &&
		(g_ascii_strncasecmp (pos, "www", 3) == 0 ||
		 g_ascii_strncasecmp (pos, "ftp", 3) == 0)) {

		if (!(is_url_start (*(pos - 1)) ||
				g_ascii_isspace (*(pos - 1)) ||
				pos - 1 == match->prev_newline_pos ||
				(*(pos - 1) & 0x80))) { /* Chinese trick */
			return FALSE;
		}
	}

	if (*pos == '.') {
		/* Urls cannot start with . */
		return FALSE;
	}

	if (pos > cb->begin) {
		match->st = *(pos - 1);
	}
	else {
		match->st = '\0';
	}

	match->m_begin = pos;

	return TRUE;
}

static gboolean
url_web_end (struct url_callback_data *cb,
		const gchar *pos,
		url_match_t *match)
{
	const gchar *last = NULL;
	gint len = cb->end - pos;
	guint flags = 0;

	if (match->newline_pos && match->st != '<') {
		/* We should also limit our match end to the newline */
		len = MIN (len, match->newline_pos - pos);
	}

	if (rspamd_web_parse (NULL, pos, len, &last, FALSE, &flags) != 0) {
		return FALSE;
	}

	if (last < cb->end && (*last == '>' && last != match->newline_pos)) {
		/* We need to ensure that url also starts with '>' */
		if (match->st != '<') {
			return FALSE;
		}
	}

	match->m_len = (last - pos);

	return TRUE;
}


static gboolean
url_email_start (struct url_callback_data *cb,
		const gchar *pos,
		url_match_t *match)
{
	if (!match->prefix || match->prefix[0] == '\0') {
		/* We have mailto:// at the beginning */
		match->m_begin = pos;

	}
	else {
		/* Just '@' */

		/* Check if this match is a part of the previous mailto: email */
		if (cb->last_at != NULL && cb->last_at == pos) {
			cb->last_at = NULL;
			return FALSE;
		}
		else if (pos == cb->begin) {
			/* Just @ at the start of input */
			return FALSE;
		}
	}

	if (pos >= cb->begin + 1) {
		match->st = *(pos - 1);
	}
	else {
		match->st = '\0';
	}

	return TRUE;
}

static gboolean
url_email_end (struct url_callback_data *cb,
		const gchar *pos,
		url_match_t *match)
{
	const gchar *last = NULL;
	struct http_parser_url u;
	gint len = cb->end - pos;
	guint flags = 0;

	if (match->newline_pos && match->st != '<') {
		/* We should also limit our match end to the newline */
		len = MIN (len, match->newline_pos - pos);
	}

	if (!match->prefix || match->prefix[0] == '\0') {
		/* We have mailto:// at the beginning */
		if (rspamd_mailto_parse (&u, pos, len, &last, FALSE, &flags) != 0) {
			return FALSE;
		}

		if (!(u.field_set & (1 << UF_USERINFO))) {
			return FALSE;
		}

		cb->last_at = match->m_begin + u.field_data[UF_USERINFO].off +
				u.field_data[UF_USERINFO].len;

		g_assert (*cb->last_at == '@');
		match->m_len = (last - pos);

		return TRUE;
	}
	else {
		const gchar *c, *p;
		/*
		 * Here we have just '@', so we need to find both start and end of the
		 * pattern
		 */
		g_assert (*pos == '@');

		if (pos >= cb->end - 2 || pos <= cb->begin + 1) {
			/* Boundary violation */
			return FALSE;
		}

		if (!g_ascii_isalnum (pos[1]) || !g_ascii_isalnum (*(pos - 1))) {
			return FALSE;
		}

		c = pos - 1;
		while (c > cb->begin) {
			if (!is_mailsafe (*c)) {
				break;
			}
			if (c == match->prev_newline_pos) {
				break;
			}

			c --;
		}
		/* Rewind to the first alphanumeric character */
		while (c < pos && !g_ascii_isalnum (*c)) {
			c ++;
		}

		/* Find the end of email */
		p = pos + 1;
		while (p < cb->end && is_domain (*p)) {
			if (p == match->newline_pos) {
				break;
			}

			p ++;
		}

		/* Rewind it again to avoid bad emails to be detected */
		while (p > pos && p < cb->end && !g_ascii_isalnum (*p)) {
			p --;
		}

		if (p < cb->end && g_ascii_isalnum (*p) &&
				(match->newline_pos == NULL || p < match->newline_pos)) {
			p ++;
		}

		if (p > c) {
			match->m_begin = c;
			match->m_len = p - c;
			return TRUE;
		}
	}

	return FALSE;
}

static gboolean
rspamd_url_trie_is_match (struct url_matcher *matcher, const gchar *pos,
		const gchar *end, const gchar *newline_pos)
{
	if (matcher->flags & URL_FLAG_TLD_MATCH) {
		/* Immediately check pos for valid chars */
		if (pos < end) {
			if (pos != newline_pos && !g_ascii_isspace (*pos)
					&& *pos != '/' && *pos != '?' &&
					*pos != ':' && !is_url_end (*pos)) {
				if (*pos == '.') {
					/* We allow . at the end of the domain however */
					pos++;
					if (pos < end) {
						if (!g_ascii_isspace (*pos) && *pos != '/' &&
								*pos != '?' && *pos != ':' && !is_url_end (*pos)) {
							return FALSE;
						}
					}
				}
				else {
					return FALSE;
				}
			}
		}
	}

	return TRUE;
}

static gint
rspamd_url_trie_callback (struct rspamd_multipattern *mp,
		guint strnum,
		gint match_start,
		gint match_pos,
		const gchar *text,
		gsize len,
		void *context)
{
	struct url_matcher *matcher;
	url_match_t m;
	const gchar *pos, *newline_pos = NULL;
	struct url_callback_data *cb = context;

	matcher = &g_array_index (url_scanner->matchers, struct url_matcher,
			strnum);

	if ((matcher->flags & URL_FLAG_NOHTML) && cb->is_html) {
		/* Do not try to match non-html like urls in html texts */
		return 0;
	}

	pos = text + match_pos;
	memset (&m, 0, sizeof (m));
	m.m_begin = text + match_start;
	m.m_len = match_pos - match_start;

	if (cb->newlines && cb->newlines->len > 0) {
		newline_pos = g_ptr_array_index (cb->newlines, cb->newline_idx);

		while (pos > newline_pos && cb->newline_idx < cb->newlines->len) {
			cb->newline_idx ++;
			newline_pos = g_ptr_array_index (cb->newlines, cb->newline_idx);
		}

		if (pos > newline_pos) {
			newline_pos = NULL;
		}

		if (cb->newline_idx > 0) {
			m.prev_newline_pos = g_ptr_array_index (cb->newlines,
					cb->newline_idx - 1);
		}
	}

	if (!rspamd_url_trie_is_match (matcher, pos, cb->end, newline_pos)) {
		return 0;
	}

	m.pattern = matcher->pattern;
	m.prefix = matcher->prefix;
	m.add_prefix = FALSE;
	m.newline_pos = newline_pos;
	pos = cb->begin + match_start;

	if (matcher->start (cb, pos, &m) &&
			matcher->end (cb, pos, &m)) {
		if (m.add_prefix || matcher->prefix[0] != '\0') {
			cb->len = m.m_len + strlen (matcher->prefix);
			cb->url_str = rspamd_mempool_alloc (cb->pool, cb->len + 1);
			cb->len = rspamd_snprintf (cb->url_str,
					cb->len + 1,
					"%s%*s",
					m.prefix,
					(gint)m.m_len,
					m.m_begin);
			cb->prefix_added = TRUE;
		}
		else {
			cb->url_str = rspamd_mempool_alloc (cb->pool, m.m_len + 1);
			rspamd_strlcpy (cb->url_str, m.m_begin, m.m_len + 1);
		}

		cb->start = m.m_begin;
		cb->fin = m.m_begin + m.m_len;

		return 1;
	}
	else {
		cb->url_str = NULL;
	}

	/* Continue search */
	return 0;
}

gboolean
rspamd_url_find (rspamd_mempool_t *pool, const gchar *begin, gsize len,
		gchar **url_str, gboolean is_html, goffset *url_pos,
		gboolean *prefix_added)
{
	struct url_callback_data cb;
	gint ret;

	memset (&cb, 0, sizeof (cb));
	cb.begin = begin;
	cb.end = begin + len;
	cb.is_html = is_html;
	cb.pool = pool;

	ret = rspamd_multipattern_lookup (url_scanner->search_trie, begin, len,
			rspamd_url_trie_callback, &cb, NULL);

	if (ret) {
		if (url_str) {
			*url_str = cb.url_str;
		}

		if (url_pos) {
			*url_pos = cb.start - begin;
		}

		if (prefix_added) {
			*prefix_added = cb.prefix_added;
		}

		return TRUE;
	}

	return FALSE;
}

static gint
rspamd_url_trie_generic_callback_common (struct rspamd_multipattern *mp,
		guint strnum,
		gint match_start,
		gint match_pos,
		const gchar *text,
		gsize len,
		void *context,
		gboolean multiple)
{
	struct rspamd_url *url;
	struct url_matcher *matcher;
	url_match_t m;
	const gchar *pos, *newline_pos = NULL;
	struct url_callback_data *cb = context;
	gint rc;
	rspamd_mempool_t *pool;

	matcher = &g_array_index (url_scanner->matchers, struct url_matcher,
			strnum);
	pool = cb->pool;

	if ((matcher->flags & URL_FLAG_NOHTML) && cb->is_html) {
		/* Do not try to match non-html like urls in html texts */
		return 0;
	}

	memset (&m, 0, sizeof (m));
	pos = text + match_pos;

	/* Find the next newline after our pos */
	if (cb->newlines && cb->newlines->len > 0) {
		newline_pos = g_ptr_array_index (cb->newlines, cb->newline_idx);

		while (pos > newline_pos && cb->newline_idx < cb->newlines->len - 1) {
			cb->newline_idx ++;
			newline_pos = g_ptr_array_index (cb->newlines, cb->newline_idx);
		}

		if (pos > newline_pos) {
			newline_pos = NULL;
		}
		if (cb->newline_idx > 0) {
			m.prev_newline_pos = g_ptr_array_index (cb->newlines,
					cb->newline_idx - 1);
		}
	}

	if (!rspamd_url_trie_is_match (matcher, pos, text + len, newline_pos)) {
		return 0;
	}

	pos = cb->begin + match_start;
	m.pattern = matcher->pattern;
	m.prefix = matcher->prefix;
	m.add_prefix = FALSE;
	m.m_begin = text + match_start;
	m.m_len = match_pos - match_start;
	m.newline_pos = newline_pos;

	if (matcher->start (cb, pos, &m) &&
			matcher->end (cb, pos, &m)) {
		if (m.add_prefix || matcher->prefix[0] != '\0') {
			cb->len = m.m_len + strlen (matcher->prefix);
			cb->url_str = rspamd_mempool_alloc (cb->pool, cb->len + 1);
			cb->len = rspamd_snprintf (cb->url_str,
					cb->len + 1,
					"%s%*s",
					m.prefix,
					(gint)m.m_len,
					m.m_begin);
			cb->prefix_added = TRUE;
		}
		else {
			cb->url_str = rspamd_mempool_alloc (cb->pool, m.m_len + 1);
			cb->len = rspamd_strlcpy (cb->url_str, m.m_begin, m.m_len + 1);
		}

		cb->start = m.m_begin;
		cb->fin = m.m_begin + m.m_len;
		url = rspamd_mempool_alloc0 (pool, sizeof (struct rspamd_url));
		g_strstrip (cb->url_str);
		rc = rspamd_url_parse (url, cb->url_str, strlen (cb->url_str), pool);

		if (rc == URI_ERRNO_OK && url->hostlen > 0) {
			if (cb->prefix_added) {
				url->flags |= RSPAMD_URL_FLAG_SCHEMALESS;
				cb->prefix_added = FALSE;
			}

			if (cb->func) {
				cb->func (url, cb->start - text, cb->fin - text, cb->funcd);
			}
		}
		else if (rc != URI_ERRNO_OK) {
			msg_debug_pool_check ("extract of url '%s' failed: %s",
					cb->url_str,
					rspamd_url_strerror (rc));
		}
	}
	else {
		cb->url_str = NULL;
	}

	/* Continue search if required (return 0 means continue) */
	return !multiple;
}

static gint
rspamd_url_trie_generic_callback_multiple (struct rspamd_multipattern *mp,
		guint strnum,
		gint match_start,
		gint match_pos,
		const gchar *text,
		gsize len,
		void *context)
{
	return rspamd_url_trie_generic_callback_common (mp, strnum, match_start,
			match_pos, text, len, context, TRUE);
}

static gint
rspamd_url_trie_generic_callback_single (struct rspamd_multipattern *mp,
		guint strnum,
		gint match_start,
		gint match_pos,
		const gchar *text,
		gsize len,
		void *context)
{
	return rspamd_url_trie_generic_callback_common (mp, strnum, match_start,
			match_pos, text, len, context, FALSE);
}

struct rspamd_url_mimepart_cbdata {
	struct rspamd_task *task;
	struct rspamd_mime_text_part *part;
};

static void
rspamd_url_text_part_callback (struct rspamd_url *url, gsize start_offset,
		gsize end_offset, gpointer ud)
{
	struct rspamd_url_mimepart_cbdata *cbd = ud;
	struct rspamd_process_exception *ex;
	struct rspamd_task *task;
	gchar *url_str = NULL;
	struct rspamd_url *query_url, *existing;
	GHashTable *target_tbl = NULL;
	gint rc;
	gboolean prefix_added;

	task = cbd->task;
	ex = rspamd_mempool_alloc0 (task->task_pool, sizeof (struct rspamd_process_exception));

	ex->pos = start_offset;
	ex->len = end_offset - start_offset;
	ex->type = RSPAMD_EXCEPTION_URL;
	ex->ptr = url;

	if (url->protocol == PROTOCOL_MAILTO) {
		if (url->userlen > 0) {
			target_tbl = task->emails;
		}
	}
	else {
		target_tbl = task->urls;
	}

	if (target_tbl) {
		if ((existing = g_hash_table_lookup (target_tbl, url)) == NULL) {
			url->flags |= RSPAMD_URL_FLAG_FROM_TEXT;
			g_hash_table_insert (target_tbl, url, url);
		}
		else {
			existing->count++;
		}
	}

	target_tbl = NULL;

	cbd->part->exceptions = g_list_prepend (
			cbd->part->exceptions,
			ex);

	/* We also search the query for additional url inside */
	if (url->querylen > 0) {
		if (rspamd_url_find (task->task_pool, url->query, url->querylen,
				&url_str, IS_PART_HTML (cbd->part), NULL, &prefix_added)) {

			query_url = rspamd_mempool_alloc0 (task->task_pool,
					sizeof (struct rspamd_url));
			rc = rspamd_url_parse (query_url,
					url_str,
					strlen (url_str),
					task->task_pool);

			if (rc == URI_ERRNO_OK &&
					query_url->hostlen > 0) {
				msg_debug_task ("found url %s in query of url"
						" %*s", url_str, url->querylen, url->query);

				if (prefix_added) {
					query_url->flags |= RSPAMD_URL_FLAG_SCHEMALESS;
				}

				if (query_url->protocol == PROTOCOL_MAILTO) {
					if (query_url->userlen > 0) {
						target_tbl = task->emails;
					}
				}
				else {
					target_tbl = task->urls;
				}

				if (target_tbl) {
					if ((existing = g_hash_table_lookup (target_tbl, query_url)) == NULL) {
						url->flags |= RSPAMD_URL_FLAG_FROM_TEXT;
						g_hash_table_insert (target_tbl, query_url, query_url);
					}
					else {
						existing->count++;
					}
				}
			}
		}
	}
}

void
rspamd_url_text_extract (rspamd_mempool_t *pool,
		struct rspamd_task *task,
		struct rspamd_mime_text_part *part,
		gboolean is_html)
{
	struct rspamd_url_mimepart_cbdata mcbd;

	if (part->utf_stripped_content == NULL || part->utf_stripped_content->len == 0) {
		msg_warn_task ("got empty text part");
		return;
	}

	mcbd.task = task;
	mcbd.part = part;

	rspamd_url_find_multiple (task->task_pool, part->utf_stripped_content->data,
			part->utf_stripped_content->len, is_html, part->newlines,
			rspamd_url_text_part_callback, &mcbd);
}

void
rspamd_url_find_multiple (rspamd_mempool_t *pool, const gchar *in,
		gsize inlen, gboolean is_html, GPtrArray *nlines,
		url_insert_function func, gpointer ud)
{
	struct url_callback_data cb;

	g_assert (in != NULL);

	if (inlen == 0) {
		inlen = strlen (in);
	}

	memset (&cb, 0, sizeof (cb));
	cb.begin = in;
	cb.end = in + inlen;
	cb.is_html = is_html;
	cb.pool = pool;

	cb.funcd = ud;
	cb.func = func;
	cb.newlines = nlines;

	rspamd_multipattern_lookup (url_scanner->search_trie, in,
			inlen,
			rspamd_url_trie_generic_callback_multiple, &cb, NULL);
}

void
rspamd_url_find_single (rspamd_mempool_t *pool, const gchar *in,
		gsize inlen, gboolean is_html,
		url_insert_function func, gpointer ud)
{
	struct url_callback_data cb;

	g_assert (in != NULL);

	if (inlen == 0) {
		inlen = strlen (in);
	}

	memset (&cb, 0, sizeof (cb));
	cb.begin = in;
	cb.end = in + inlen;
	cb.is_html = is_html;
	cb.pool = pool;

	cb.funcd = ud;
	cb.func = func;

	rspamd_multipattern_lookup (url_scanner->search_trie, in,
			inlen,
			rspamd_url_trie_generic_callback_single, &cb, NULL);
}


void
rspamd_url_task_subject_callback (struct rspamd_url *url, gsize start_offset,
		gsize end_offset, gpointer ud)
{
	struct rspamd_task *task = ud;
	gchar *url_str = NULL;
	struct rspamd_url *query_url, *existing;
	gint rc;
	gboolean prefix_added;

	/* It is just a displayed URL, we should not check it for certain things */
	url->flags |= RSPAMD_URL_FLAG_HTML_DISPLAYED|RSPAMD_URL_FLAG_SUBJECT;

	if (url->protocol == PROTOCOL_MAILTO) {
		if (url->userlen > 0) {
			if ((existing = g_hash_table_lookup (task->emails, url)) == NULL) {
				g_hash_table_insert (task->emails, url,
						url);
			}
			else {
				existing->count ++;
			}
		}
	}
	else {
		if ((existing = g_hash_table_lookup (task->urls, url)) == NULL) {
			g_hash_table_insert (task->urls, url, url);
		}
		else {
			existing->count ++;
		}
	}

	/* We also search the query for additional url inside */
	if (url->querylen > 0) {
		if (rspamd_url_find (task->task_pool, url->query, url->querylen,
				&url_str, FALSE, NULL, &prefix_added)) {

			query_url = rspamd_mempool_alloc0 (task->task_pool,
					sizeof (struct rspamd_url));
			rc = rspamd_url_parse (query_url,
					url_str,
					strlen (url_str),
					task->task_pool);

			if (rc == URI_ERRNO_OK &&
					url->hostlen > 0) {
				msg_debug_task ("found url %s in query of url"
						" %*s", url_str, url->querylen, url->query);

				if (prefix_added) {
					query_url->flags |= RSPAMD_URL_FLAG_SCHEMALESS;
				}

				if ((existing = g_hash_table_lookup (task->urls,
						query_url)) == NULL) {
					g_hash_table_insert (task->urls,
							query_url,
							query_url);
				}
				else {
					existing->count ++;
				}
			}
		}
	}
}

void
rspamd_url_add_tag (struct rspamd_url *url, const gchar *tag,
		const gchar *value,
		rspamd_mempool_t *pool)
{
	struct rspamd_url_tag *found, *ntag;

	g_assert (url != NULL && tag != NULL && value != NULL);

	if (url->tags == NULL) {
		url->tags = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
		rspamd_mempool_add_destructor (pool,
				(rspamd_mempool_destruct_t)g_hash_table_unref, url->tags);
	}

	found = g_hash_table_lookup (url->tags, tag);

	ntag = rspamd_mempool_alloc0 (pool, sizeof (*ntag));
	ntag->data = rspamd_mempool_strdup (pool, value);

	if (found == NULL) {
		g_hash_table_insert (url->tags, rspamd_mempool_strdup (pool, tag),
				ntag);
	}

	DL_APPEND (found, ntag);
}

guint
rspamd_url_hash (gconstpointer u)
{
	const struct rspamd_url *url = u;
	rspamd_cryptobox_fast_hash_state_t st;

	rspamd_cryptobox_fast_hash_init (&st, rspamd_hash_seed ());

	if (url->urllen > 0) {
		rspamd_cryptobox_fast_hash_update (&st, url->string, url->urllen);
	}

	return rspamd_cryptobox_fast_hash_final (&st);
}

guint
rspamd_email_hash (gconstpointer u)
{
	const struct rspamd_url *url = u;
	rspamd_cryptobox_fast_hash_state_t st;

	rspamd_cryptobox_fast_hash_init (&st, rspamd_hash_seed ());

	if (url->hostlen > 0) {
		rspamd_cryptobox_fast_hash_update (&st, url->host, url->hostlen);
	}

	if (url->userlen > 0) {
		rspamd_cryptobox_fast_hash_update (&st, url->user, url->userlen);
	}

	return rspamd_cryptobox_fast_hash_final (&st);
}

/* Compare two emails for building emails tree */
gboolean
rspamd_emails_cmp (gconstpointer a, gconstpointer b)
{
	const struct rspamd_url *u1 = a, *u2 = b;
	gint r;

	if (u1->hostlen != u2->hostlen || u1->hostlen == 0) {
		return FALSE;
	}
	else {
		if ((r = rspamd_lc_cmp (u1->host, u2->host, u1->hostlen)) == 0) {
			if (u1->userlen != u2->userlen || u1->userlen == 0) {
				return FALSE;
			}
			else {
				return rspamd_lc_cmp (u1->user, u2->user, u1->userlen) ==
						0;
			}
		}
		else {
			return r == 0;
		}
	}

	return FALSE;
}

gboolean
rspamd_urls_cmp (gconstpointer a, gconstpointer b)
{
	const struct rspamd_url *u1 = a, *u2 = b;
	int r = 0;

	if (u1->urllen != u2->urllen) {
		return FALSE;
	}
	else {
		r = memcmp (u1->string, u2->string, u1->urllen);
	}

	return r == 0;
}

gsize
rspamd_url_decode (gchar *dst, const gchar *src, gsize size)
{
	gchar *d, ch, c, decoded;
	const gchar *s;
	enum {
		sw_usual = 0,
		sw_quoted,
		sw_quoted_second
	} state;

	d = dst;
	s = src;

	state = 0;
	decoded = 0;

	while (size--) {

		ch = *s++;

		switch (state) {
		case sw_usual:

			if (ch == '%') {
				state = sw_quoted;
				break;
			}
			else if (ch == '+') {
				*d++ = ' ';
			}
			else {
				*d++ = ch;
			}
			break;

		case sw_quoted:

			if (ch >= '0' && ch <= '9') {
				decoded = (ch - '0');
				state = sw_quoted_second;
				break;
			}

			c = (ch | 0x20);
			if (c >= 'a' && c <= 'f') {
				decoded = (c - 'a' + 10);
				state = sw_quoted_second;
				break;
			}

			/* the invalid quoted character */

			state = sw_usual;

			*d++ = ch;

			break;

		case sw_quoted_second:

			state = sw_usual;

			if (ch >= '0' && ch <= '9') {
				ch = ((decoded << 4) + ch - '0');
				*d++ = ch;

				break;
			}

			c = (u_char) (ch | 0x20);
			if (c >= 'a' && c <= 'f') {
				ch = ((decoded << 4) + c - 'a' + 10);

				*d++ = ch;
				break;
			}

			/* the invalid quoted character */
			break;
		}
	}

	return (d - dst);
}

enum rspamd_url_char_class {
	RSPAMD_URL_UNRESERVED = (1 << 0),
	RSPAMD_URL_SUBDELIM = (1 << 1),
	RSPAMD_URL_PATHSAFE = (1 << 2),
	RSPAMD_URL_QUERYSAFE = (1 << 3),
	RSPAMD_URL_FRAGMENTSAFE = (1 << 4),
	RSPAMD_URL_HOSTSAFE = (1 << 5),
	RSPAMD_URL_USERSAFE = (1 << 6),
};

#define RSPAMD_URL_FLAGS_HOSTSAFE (RSPAMD_URL_UNRESERVED|RSPAMD_URL_HOSTSAFE|RSPAMD_URL_SUBDELIM)
#define RSPAMD_URL_FLAGS_USERSAFE (RSPAMD_URL_UNRESERVED|RSPAMD_URL_USERSAFE|RSPAMD_URL_SUBDELIM)
#define RSPAMD_URL_FLAGS_PATHSAFE (RSPAMD_URL_UNRESERVED|RSPAMD_URL_PATHSAFE|RSPAMD_URL_SUBDELIM)
#define RSPAMD_URL_FLAGS_QUERYSAFE (RSPAMD_URL_UNRESERVED|RSPAMD_URL_QUERYSAFE|RSPAMD_URL_SUBDELIM)
#define RSPAMD_URL_FLAGS_FRAGMENTSAFE (RSPAMD_URL_UNRESERVED|RSPAMD_URL_FRAGMENTSAFE|RSPAMD_URL_SUBDELIM)

static const unsigned char rspamd_url_encoding_classes[256] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0 /*   */, RSPAMD_URL_SUBDELIM /* ! */, 0 /* " */, 0 /* # */,
	RSPAMD_URL_SUBDELIM /* $ */, 0 /* % */, RSPAMD_URL_SUBDELIM /* & */,
	RSPAMD_URL_SUBDELIM /* ' */, RSPAMD_URL_SUBDELIM /* ( */,
	RSPAMD_URL_SUBDELIM /* ) */, RSPAMD_URL_SUBDELIM /* * */,
	RSPAMD_URL_SUBDELIM /* + */, RSPAMD_URL_SUBDELIM /* , */,
	RSPAMD_URL_UNRESERVED /* - */, RSPAMD_URL_UNRESERVED /* . */,
	RSPAMD_URL_PATHSAFE|RSPAMD_URL_QUERYSAFE|RSPAMD_URL_FRAGMENTSAFE /* / */,
	RSPAMD_URL_UNRESERVED /* 0 */, RSPAMD_URL_UNRESERVED /* 1 */,
	RSPAMD_URL_UNRESERVED /* 2 */, RSPAMD_URL_UNRESERVED /* 3 */,
	RSPAMD_URL_UNRESERVED /* 4 */, RSPAMD_URL_UNRESERVED /* 5 */,
	RSPAMD_URL_UNRESERVED /* 6 */, RSPAMD_URL_UNRESERVED /* 7 */,
	RSPAMD_URL_UNRESERVED /* 8 */, RSPAMD_URL_UNRESERVED /* 9 */,
	RSPAMD_URL_USERSAFE|RSPAMD_URL_HOSTSAFE|RSPAMD_URL_PATHSAFE|RSPAMD_URL_QUERYSAFE|RSPAMD_URL_FRAGMENTSAFE /* : */,
	RSPAMD_URL_SUBDELIM /* ; */, 0 /* < */, RSPAMD_URL_SUBDELIM /* = */, 0 /* > */,
	RSPAMD_URL_QUERYSAFE|RSPAMD_URL_FRAGMENTSAFE /* ? */,
	RSPAMD_URL_PATHSAFE|RSPAMD_URL_QUERYSAFE|RSPAMD_URL_FRAGMENTSAFE /* @ */,
	RSPAMD_URL_UNRESERVED /* A */, RSPAMD_URL_UNRESERVED /* B */,
	RSPAMD_URL_UNRESERVED /* C */, RSPAMD_URL_UNRESERVED /* D */,
	RSPAMD_URL_UNRESERVED /* E */, RSPAMD_URL_UNRESERVED /* F */,
	RSPAMD_URL_UNRESERVED /* G */, RSPAMD_URL_UNRESERVED /* H */,
	RSPAMD_URL_UNRESERVED /* I */, RSPAMD_URL_UNRESERVED /* J */,
	RSPAMD_URL_UNRESERVED /* K */, RSPAMD_URL_UNRESERVED /* L */,
	RSPAMD_URL_UNRESERVED /* M */, RSPAMD_URL_UNRESERVED /* N */,
	RSPAMD_URL_UNRESERVED /* O */, RSPAMD_URL_UNRESERVED /* P */,
	RSPAMD_URL_UNRESERVED /* Q */, RSPAMD_URL_UNRESERVED /* R */,
	RSPAMD_URL_UNRESERVED /* S */, RSPAMD_URL_UNRESERVED /* T */,
	RSPAMD_URL_UNRESERVED /* U */, RSPAMD_URL_UNRESERVED /* V */,
	RSPAMD_URL_UNRESERVED /* W */, RSPAMD_URL_UNRESERVED /* X */,
	RSPAMD_URL_UNRESERVED /* Y */, RSPAMD_URL_UNRESERVED /* Z */,
	RSPAMD_URL_HOSTSAFE /* [ */, 0 /* \ */, RSPAMD_URL_HOSTSAFE /* ] */, 0 /* ^ */,
	RSPAMD_URL_UNRESERVED /* _ */, 0 /* ` */, RSPAMD_URL_UNRESERVED /* a */,
	RSPAMD_URL_UNRESERVED /* b */, RSPAMD_URL_UNRESERVED /* c */,
	RSPAMD_URL_UNRESERVED /* d */, RSPAMD_URL_UNRESERVED /* e */,
	RSPAMD_URL_UNRESERVED /* f */, RSPAMD_URL_UNRESERVED /* g */,
	RSPAMD_URL_UNRESERVED /* h */, RSPAMD_URL_UNRESERVED /* i */,
	RSPAMD_URL_UNRESERVED /* j */, RSPAMD_URL_UNRESERVED /* k */,
	RSPAMD_URL_UNRESERVED /* l */, RSPAMD_URL_UNRESERVED /* m */,
	RSPAMD_URL_UNRESERVED /* n */, RSPAMD_URL_UNRESERVED /* o */,
	RSPAMD_URL_UNRESERVED /* p */, RSPAMD_URL_UNRESERVED /* q */,
	RSPAMD_URL_UNRESERVED /* r */, RSPAMD_URL_UNRESERVED /* s */,
	RSPAMD_URL_UNRESERVED /* t */, RSPAMD_URL_UNRESERVED /* u */,
	RSPAMD_URL_UNRESERVED /* v */, RSPAMD_URL_UNRESERVED /* w */,
	RSPAMD_URL_UNRESERVED /* x */, RSPAMD_URL_UNRESERVED /* y */,
	RSPAMD_URL_UNRESERVED /* z */, 0 /* { */, 0 /* | */, 0 /* } */,
	RSPAMD_URL_UNRESERVED /* ~ */, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0
};

#define CHECK_URL_COMPONENT(beg, len, flags) do { \
	for (i = 0; i < (len); i ++) { \
		if ((rspamd_url_encoding_classes[(beg)[i]] & (flags)) == 0) { \
			dlen += 2; \
		} \
	} \
} while (0)

#define ENCODE_URL_COMPONENT(beg, len, flags) do { \
	for (i = 0; i < (len) && dend > d; i ++) { \
		if ((rspamd_url_encoding_classes[(beg)[i]] & (flags)) == 0) { \
			*d++ = '%'; \
			*d++ = hexdigests[((beg)[i] >> 4) & 0xf]; \
			*d++ = hexdigests[(beg)[i] & 0xf]; \
		} \
		else { \
			*d++ = (beg)[i]; \
		} \
	} \
} while (0)

const gchar *
rspamd_url_encode (struct rspamd_url *url, gsize *pdlen,
		rspamd_mempool_t *pool)
{
	guchar *dest, *d, *dend;
	static const gchar hexdigests[16] = "0123456789ABCDEF";
	guint i;
	gsize dlen = 0;

	g_assert (pdlen != NULL && url != NULL && pool != NULL);

	CHECK_URL_COMPONENT ((guchar *)url->host, url->hostlen,
			RSPAMD_URL_FLAGS_HOSTSAFE);
	CHECK_URL_COMPONENT ((guchar *)url->user, url->userlen,
			RSPAMD_URL_FLAGS_USERSAFE);
	CHECK_URL_COMPONENT ((guchar *)url->data, url->datalen,
			RSPAMD_URL_FLAGS_PATHSAFE);
	CHECK_URL_COMPONENT ((guchar *)url->query, url->querylen,
			RSPAMD_URL_FLAGS_QUERYSAFE);
	CHECK_URL_COMPONENT ((guchar *)url->fragment, url->fragmentlen,
			RSPAMD_URL_FLAGS_FRAGMENTSAFE);

	if (dlen == 0) {
		*pdlen = url->urllen;

		return url->string;
	}

	/* Need to encode */
	dlen += url->urllen;
	dest = rspamd_mempool_alloc (pool, dlen + 1);
	d = dest;
	dend = d + dlen;
	d += rspamd_snprintf ((gchar *)d, dend - d,
			"%*s://", url->protocollen, rspamd_url_protocols[url->protocol].name);

	if (url->userlen > 0) {
		ENCODE_URL_COMPONENT ((guchar *)url->user, url->userlen,
				RSPAMD_URL_FLAGS_USERSAFE);
		*d++ = ':';
	}

	ENCODE_URL_COMPONENT ((guchar *)url->host, url->hostlen,
			RSPAMD_URL_FLAGS_HOSTSAFE);

	if (url->datalen > 0) {
		*d++ = '/';
		ENCODE_URL_COMPONENT ((guchar *)url->data, url->datalen,
				RSPAMD_URL_FLAGS_PATHSAFE);
	}

	if (url->querylen > 0) {
		*d++ = '/';
		ENCODE_URL_COMPONENT ((guchar *)url->query, url->querylen,
				RSPAMD_URL_FLAGS_QUERYSAFE);
	}

	if (url->fragmentlen > 0) {
		*d++ = '/';
		ENCODE_URL_COMPONENT ((guchar *)url->fragment, url->fragmentlen,
				RSPAMD_URL_FLAGS_FRAGMENTSAFE);
	}

	*pdlen = (d - dest);

	return (const gchar *)dest;
}
