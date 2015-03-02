/*
 * Copyright (c) 2009-2015, Vsevolod Stakhov
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
#include "fstring.h"
#include "main.h"
#include "message.h"
#include "trie.h"
#include "http.h"

typedef struct url_match_s {
	const gchar *m_begin;
	gsize m_len;
	const gchar *pattern;
	const gchar *prefix;
	gboolean add_prefix;
} url_match_t;

#define URL_FLAG_NOHTML 0x1
#define URL_FLAG_STRICT_MATCH 0x2

struct url_matcher {
	const gchar *pattern;
	const gchar *prefix;
	gboolean (*start)(const gchar *begin, const gchar *end, const gchar *pos,
		url_match_t *match);
	gboolean (*end)(const gchar *begin, const gchar *end, const gchar *pos,
		url_match_t *match);
	gint flags;
};

static gboolean url_file_start (const gchar *begin,
	const gchar *end,
	const gchar *pos,
	url_match_t *match);
static gboolean url_file_end (const gchar *begin,
	const gchar *end,
	const gchar *pos,
	url_match_t *match);

static gboolean url_web_start (const gchar *begin,
	const gchar *end,
	const gchar *pos,
	url_match_t *match);
static gboolean url_web_end (const gchar *begin,
	const gchar *end,
	const gchar *pos,
	url_match_t *match);

static gboolean url_tld_start (const gchar *begin,
	const gchar *end,
	const gchar *pos,
	url_match_t *match);
static gboolean url_tld_end (const gchar *begin,
	const gchar *end,
	const gchar *pos,
	url_match_t *match);

static gboolean url_email_start (const gchar *begin,
	const gchar *end,
	const gchar *pos,
	url_match_t *match);
static gboolean url_email_end (const gchar *begin,
	const gchar *end,
	const gchar *pos,
	url_match_t *match);

struct url_matcher matchers[] = {
	/* Common prefixes */
	{ "file://",        "",         url_file_start,         url_file_end,
	  0                   },
	{ "ftp://",         "",         url_web_start,          url_web_end,
	  0                   },
	{ "sftp://",        "",         url_web_start,          url_web_end,
	  0                   },
	{ "http://",        "",         url_web_start,          url_web_end,
	  0                   },
	{ "https://",       "",         url_web_start,          url_web_end,
	  0                   },
	{ "news://",        "",         url_web_start,          url_web_end,
	  0                   },
	{ "nntp://",        "",         url_web_start,          url_web_end,
	  0                   },
	{ "telnet://",      "",         url_web_start,          url_web_end,
	  0                   },
	{ "webcal://",      "",         url_web_start,          url_web_end,
	  0                   },
	{ "mailto:",        "",         url_email_start,        url_email_end,
	  0                   },
	{ "callto://",      "",         url_web_start,          url_web_end,
	  0                   },
	{ "h323:",          "",         url_web_start,          url_web_end,
	  0                   },
	{ "sip:",           "",         url_web_start,          url_web_end,
	  0                   },
	{ "www.",           "http://",  url_web_start,          url_web_end,
	  0                   },
	{ "ftp.",           "ftp://",   url_web_start,          url_web_end,
	  URL_FLAG_NOHTML     },
	/* TLD domains parts */
	{ ".ac",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ad",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ae",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".aero",          "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".af",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ag",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ai",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".al",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".am",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".an",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ao",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".aq",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ar",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".arpa",          "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".as",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".asia",          "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".at",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".au",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".aw",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ax",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".az",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ba",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".bb",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".bd",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".be",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".bf",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".bg",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".bh",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".bi",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".biz",           "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".bj",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".bm",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".bn",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".bo",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".br",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".bs",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".bt",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".bv",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".bw",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".by",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".bz",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ca",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".cat",           "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".cc",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".cd",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".cf",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".cg",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ch",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ci",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ck",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".cl",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".cm",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".cn",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".co",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".com",           "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".coop",          "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".cr",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".cu",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".cv",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".cw",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".cx",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".cy",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".cz",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".de",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".dj",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".dk",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".dm",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".do",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".dz",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ec",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".edu",           "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ee",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".eg",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".er",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".es",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".et",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".eu",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".fi",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".fj",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".fk",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".fm",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".fo",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".fr",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ga",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".gb",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".gd",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ge",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".gf",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".gg",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".gh",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".gi",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".gl",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".gm",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".gn",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".gov",           "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".gp",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".gq",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".gr",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".gs",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".gt",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".gu",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".gw",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".gy",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".hk",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".hm",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".hn",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".hr",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ht",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".hu",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".id",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ie",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".il",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".im",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".in",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".info",          "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".int",           "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".io",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".iq",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ir",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".is",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".it",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".je",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".jm",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".jo",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".jobs",          "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".jp",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ke",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".kg",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".kh",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ki",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".km",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".kn",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".kp",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".kr",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".kw",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ky",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".kz",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".la",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".lb",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".lc",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".li",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".lk",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".lr",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ls",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".lt",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".lu",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".lv",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ly",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ma",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".mc",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".md",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".me",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".mg",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".mh",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".mil",           "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".mk",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ml",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".mm",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".mn",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".mo",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".mobi",          "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".mp",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".mq",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".mr",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ms",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".mt",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".mu",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".museum",        "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".mv",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".mw",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".mx",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".my",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".mz",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".na",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".name",          "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".nc",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ne",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".net",           "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".nf",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ng",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ni",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".nl",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".no",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".np",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".nr",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".nu",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".nz",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".om",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".org",           "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".pa",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".pe",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".pf",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".pg",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ph",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".pk",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".pl",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".pm",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".pn",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".pr",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".pro",           "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ps",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".pt",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".pw",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".py",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".qa",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".re",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ro",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".rs",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ru",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".rw",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".sa",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".sb",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".sc",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".sd",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".se",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".sg",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".sh",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".si",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".sj",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".sk",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".sl",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".sm",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".sn",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".so",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".sr",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".st",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".su",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".sv",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".sx",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".sy",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".sz",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".tc",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".td",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".tel",           "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".tf",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".tg",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".th",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".tj",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".tk",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".tl",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".tm",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".tn",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".to",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".tp",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".tr",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".travel",        "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".tt",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".tv",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".tw",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".tz",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ua",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ug",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".uk",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".us",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".uy",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".uz",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".va",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".vc",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ve",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".vg",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".vi",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".vn",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".vu",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".wf",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ws",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".xxx",           "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".ye",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".yt",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".za",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".zm",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	{ ".zw",            "http://",  url_tld_start,          url_tld_end,
	  URL_FLAG_NOHTML | URL_FLAG_STRICT_MATCH },
	/* Likely emails */
	{ "@",              "mailto://",url_email_start,        url_email_end,
	  URL_FLAG_NOHTML }
};

struct url_match_scanner {
	struct url_matcher *matchers;
	gsize matchers_count;
	rspamd_trie_t *patterns;
};

struct url_match_scanner *url_scanner = NULL;

static guchar url_scanner_table[256] = {
	1,  1,  1,  1,  1,  1,  1,  1,  1,  9,  9,  1,  1,  9,  1,  1,
	1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
	24,128,160,128,128,128,128,128,160,160,128,128,160,192,160,160,
	68, 68, 68, 68, 68, 68, 68, 68, 68, 68,160,160, 32,128, 32,128,
	160, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
	66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,160,160,160,128,192,
	128, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
	66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,128,128,128,128,  1,
	1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
	1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
	1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
	1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
	1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
	1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
	1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
	1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1
};

enum {
	IS_CTRL     = (1 << 0),
	IS_ALPHA        = (1 << 1),
	IS_DIGIT        = (1 << 2),
	IS_LWSP     = (1 << 3),
	IS_SPACE        = (1 << 4),
	IS_SPECIAL      = (1 << 5),
	IS_DOMAIN       = (1 << 6),
	IS_URLSAFE      = (1 << 7)
};

#define is_ctrl(x) ((url_scanner_table[(guchar)(x)] & IS_CTRL) != 0)
#define is_lwsp(x) ((url_scanner_table[(guchar)(x)] & IS_LWSP) != 0)
#define is_atom(x) ((url_scanner_table[(guchar)(x)] & (IS_SPECIAL | IS_SPACE | \
	IS_CTRL)) == 0)
#define is_usersafe(x) ((url_scanner_table[(guchar)(x)] & (IS_CTRL | IS_SPACE)) == 0)
#define is_alpha(x) ((url_scanner_table[(guchar)(x)] & IS_ALPHA) != 0)
#define is_digit(x) ((url_scanner_table[(guchar)(x)] & IS_DIGIT) != 0)
#define is_domain(x) ((url_scanner_table[(guchar)(x)] & IS_DOMAIN) != 0)
#define is_urlsafe(x) ((url_scanner_table[(guchar)(x)] & (IS_ALPHA | IS_DIGIT | \
	IS_URLSAFE)) != 0)

void
rspamd_unescape_uri (gchar *dst, const gchar *src, gsize size)
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

			*d++ = ch;
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

	*d = '\0';
}

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
	}
	return NULL;
}

static gint
url_init (void)
{
	guint i;
	gchar patbuf[128];

	if (url_scanner == NULL) {
		url_scanner = g_malloc (sizeof (struct url_match_scanner));
		url_scanner->matchers = matchers;
		url_scanner->matchers_count = G_N_ELEMENTS (matchers);
		url_scanner->patterns = rspamd_trie_create (TRUE);
		for (i = 0; i < url_scanner->matchers_count; i++) {
			if (matchers[i].flags & URL_FLAG_STRICT_MATCH) {
				/* Insert more specific patterns */

				/* some.tld/ */
				rspamd_snprintf (patbuf,
					sizeof (patbuf),
					"%s/",
					matchers[i].pattern);
				rspamd_trie_insert (url_scanner->patterns, patbuf, i);
				/* some.tld  */
				rspamd_snprintf (patbuf,
					sizeof (patbuf),
					"%s ",
					matchers[i].pattern);
				rspamd_trie_insert (url_scanner->patterns, patbuf, i);
				/* some.tld: */
				rspamd_snprintf (patbuf,
					sizeof (patbuf),
					"%s:",
					matchers[i].pattern);
				rspamd_trie_insert (url_scanner->patterns, patbuf, i);
			}
			else {
				rspamd_trie_insert (url_scanner->patterns,
					matchers[i].pattern,
					i);
			}
		}
	}

	return 0;
}

#define SET_U(u, field) do {												\
	if ((u) != NULL) {														\
		(u)->field_set |= 1 << (field);										\
		(u)->field_data[(field)].len = p - c;								\
		(u)->field_data[(field)].off = c - str;								\
	}																		\
} while (0)

static gint
rspamd_mailto_parse (struct http_parser_url *u, const gchar *str, gsize len,
		gchar const **end)
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

	while (p < last) {
		t = *p;

		switch (st) {
		case parse_mailto:
			if (t == ':') {
				st = parse_semicolon;
				SET_U (u, UF_SCHEMA);
			}
			p ++;
			break;
		case parse_semicolon:
			if (t == '/') {
				st = parse_slash;
				p ++;
			}
			else {
				st = parse_slash_slash;
			}
			break;
		case parse_slash:
			if (t == '/') {
				st = parse_slash_slash;
			}
			else {
				goto out;
			}
			p ++;
			break;
		case parse_slash_slash:
			if (t == '?') {
				st = parse_prefix_question;
				p ++;
			}
			else {
				c = p;
				st = parse_user;
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
			p ++;
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
			else if (!is_usersafe (t)) {
				goto out;
			}
			p ++;
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
			p ++;
			break;
		case parse_suffix_question:
			c = p;
			st = parse_query;
			break;
		case parse_query:
			if (!is_atom (t)) {
				goto out;
			}
			p ++;
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

	return ret;
}

static gint
rspamd_web_parse (struct http_parser_url *u, const gchar *str, gsize len,
		gchar const **end, gboolean strict)
{
	const gchar *p = str, *c = str, *last = str + len, *slash = NULL;
	gchar t;
	gunichar uc;
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
		parse_password_start,
		parse_password,
		parse_domain,
		parse_port_password,
		parse_port,
		parse_suffix_slash,
		parse_path,
		parse_query,
		parse_part
	} st = parse_protocol;

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
			p ++;
			break;
		case parse_semicolon:
			if (t == '/') {
				st = parse_slash;
				p ++;
			}
			else {
				st = parse_slash_slash;
			}
			break;
		case parse_slash:
			if (t == '/') {
				st = parse_slash_slash;
			}
			else {
				goto out;
			}
			p ++;
			break;
		case parse_slash_slash:
			c = p;
			st = parse_domain;
			slash = p;
			break;
		case parse_user:
			if (t == ':') {
				if (p - c == 0) {
					goto out;
				}
				SET_U (u, UF_USERINFO);
				st = parse_password_start;
			}
			else if (t == '@') {
				/* No password */
				if (p - c == 0) {
					goto out;
				}
				SET_U (u, UF_USERINFO);
				st = parse_at;
			}
			else if (!g_ascii_isgraph (t)) {
				goto out;
			}
			p ++;
			break;
		case parse_password_start:
			if (t == '@') {
				/* Empty password */
				st = parse_at;
			}
			else {
				c = p;
				st = parse_password;
			}
			p ++;
			break;
		case parse_password:
			if (t == '@') {
				/* XXX: password is not stored */
				st = parse_at;
			}
			else if (!g_ascii_isgraph (t)) {
				goto out;
			}
			p ++;
			break;
		case parse_at:
			c = p;
			st = parse_domain;
			break;
		case parse_domain:
			if (t == '/' || t == ':') {
				if (p - c == 0) {
					goto out;
				}
				if (t == '/') {
					SET_U (u, UF_HOST);
					st = parse_suffix_slash;
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
				p ++;
			}
			else {
				if (*p != '.' && *p != '-' && *p != '_') {
					uc = g_utf8_get_char_validated (p, last - p);

					if (uc == (gunichar)-1) {
						/* Bad utf8 */
						goto out;
					}

					if (!g_unichar_isalnum (uc)) {
						/* Bad symbol */
						if (strict) {
							goto out;
						}
						else {
							goto set;
						}
					}

					p = g_utf8_next_char (p);
				}
				else {
					p ++;
				}
			}
			break;
		case parse_port_password:
			if (g_ascii_isdigit (t)) {
				/* XXX: that breaks urls with passwords starting with number */
				st = parse_port;
				c = slash;
				p --;
				SET_U (u, UF_HOST);
				p ++;
				c = p;
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
				}
				st = parse_suffix_slash;
			}
			else if (!g_ascii_isdigit (t)) {
				if (strict || !g_ascii_isspace (t)) {
					goto out;
				}
				else {
					goto set;
				}
			}
			p ++;
			break;
		case parse_suffix_slash:
			if (t != '/') {
				c = p;
				st = parse_path;
			}
			else {
				/* Skip extra slashes */
				p ++;
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
			else if (!is_urlsafe (t)) {
				if (strict) {
					goto out;
				}
				else {
					goto set;
				}
			}
			p ++;
			break;
		case parse_query:
			if (t == '#') {
				if (p - c != 0) {
					SET_U (u, UF_QUERY);
				}
				c = p + 1;
				st = parse_part;
			}
			else if (!is_urlsafe (t)) {
				if (strict) {
					goto out;
				}
				else {
					goto set;
				}
			}
			p ++;
			break;
		case parse_part:
			if (!is_urlsafe (t)) {
				if (strict) {
					goto out;
				}
				else {
					goto set;
				}
			}
			p ++;
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

enum uri_errno
rspamd_url_parse (struct rspamd_url *uri, gchar *uristring, gsize len,
		rspamd_mempool_t *pool)
{
	struct http_parser_url u;
	gchar *p, *comp;
	guint i, complen, ret;

	const struct {
		enum rspamd_url_protocol proto;
		const gchar *name;
		gsize len;
	} protocols[] = {
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

	memset (uri, 0, sizeof (*uri));
	memset (&u, 0, sizeof (u));

	if (*uristring == '\0') {
		return URI_ERRNO_EMPTY;
	}

	p = uristring;

	if (len > sizeof ("mailto:") - 1) {
		/* For mailto: urls we also need to add slashes to make it a valid URL */
		if (g_ascii_strncasecmp (p, "mailto:", sizeof ("mailto:") - 1) == 0) {
			ret = rspamd_mailto_parse (&u, uristring, len, NULL);
		}
		else {
			ret = rspamd_web_parse (&u, uristring, len, NULL, TRUE);
		}
	}
	else {
		ret = rspamd_web_parse (&u, uristring, len, NULL, TRUE);
	}

	if (ret != 0) {
		return URI_ERRNO_BAD_FORMAT;
	}

	for (i = 0; i < UF_MAX; i ++) {
		if (u.field_set & (1 << i)) {
			comp = p + u.field_data[i].off;
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

	if (!uri->hostlen) {
		return URI_ERRNO_BAD_FORMAT;
	}

	/* Now decode url symbols */
	uri->string = p;
	rspamd_unescape_uri (uri->string, uri->string, len);
	rspamd_str_lc (uri->string, uri->protocollen);
	rspamd_str_lc_utf8 (uri->host,   uri->hostlen);

	uri->protocol = PROTOCOL_UNKNOWN;

	for (i = 0; i < G_N_ELEMENTS (protocols); i ++) {
		if (uri->protocollen == protocols[i].len) {
			if (memcmp (uri->string, protocols[i].name, uri->protocollen) == 0) {
				uri->protocol = i;
				break;
			}
		}
	}

	if (uri->protocol == PROTOCOL_UNKNOWN) {
		return URI_ERRNO_INVALID_PROTOCOL;
	}

	return URI_ERRNO_OK;
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
is_open_brace (gchar c)
{
	if (c == '(' ||
		c == '{' ||
		c == '[' ||
		c == '<' ||
		c == '|' ||
		c == '\'') {
		return TRUE;
	}

	return FALSE;
}

static gboolean
url_file_start (const gchar *begin,
	const gchar *end,
	const gchar *pos,
	url_match_t *match)
{
	match->m_begin = pos;
	return TRUE;
}
static gboolean
url_file_end (const gchar *begin,
	const gchar *end,
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

	while (p < end && *p != stop && is_urlsafe (*p)) {
		p++;
	}

	if (p == begin) {
		return FALSE;
	}
	match->m_len = p - match->m_begin;

	return TRUE;

}

static gboolean
url_tld_start (const gchar *begin,
	const gchar *end,
	const gchar *pos,
	url_match_t *match)
{
	const gchar *p = pos;

	/* Try to find the start of the url by finding any non-urlsafe character or whitespace/punctuation */
	while (p >= begin) {
		if ((!is_domain (*p) && *p != '.' &&
			*p != '/') || g_ascii_isspace (*p)) {
			p++;
			if (!g_ascii_isalnum (*p)) {
				/* Urls cannot start with strange symbols */
				return FALSE;
			}
			match->m_begin = p;
			return TRUE;
		}
		else if (p == begin && p != pos) {
			match->m_begin = p;
			return TRUE;
		}
		else if (*p == '.') {
			if (p == begin) {
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
url_tld_end (const gchar *begin,
	const gchar *end,
	const gchar *pos,
	url_match_t *match)
{
	const gchar *p;

	/* A url must be finished by tld, so it must be followed by space character */
	p = pos + strlen (match->pattern);
	if (p == end || g_ascii_isspace (*p) || *p == ',') {
		match->m_len = p - match->m_begin;
		return TRUE;
	}
	else if (*p == '/' || *p == ':') {
		/* Parse arguments, ports by normal way by url default function */
		p = match->m_begin;
		/* Check common prefix */
		if (g_ascii_strncasecmp (p, "http://", sizeof ("http://") - 1) == 0) {
			return url_web_end (begin,
					   end,
					   match->m_begin + sizeof ("http://") - 1,
					   match);
		}
		else {
			return url_web_end (begin, end, match->m_begin, match);
		}

	}
	return FALSE;
}

static gboolean
url_web_start (const gchar *begin,
	const gchar *end,
	const gchar *pos,
	url_match_t *match)
{
	/* Check what we have found */
	if (pos > begin &&
		(g_ascii_strncasecmp (pos, "www",
		3) == 0 || g_ascii_strncasecmp (pos, "ftp", 3) == 0)) {
		if (!is_open_brace (*(pos - 1)) && !g_ascii_isspace (*(pos - 1))) {
			return FALSE;
		}
	}
	if (*pos == '.') {
		/* Urls cannot start with . */
		return FALSE;
	}
	match->m_begin = pos;

	return TRUE;
}

static gboolean
url_web_end (const gchar *begin,
	const gchar *end,
	const gchar *pos,
	url_match_t *match)
{
	const gchar *last = NULL;

	if (rspamd_web_parse (NULL, pos, end - pos, &last, FALSE) != 0) {
		return FALSE;
	}

	match->m_len = (last - pos);

	return TRUE;
}


static gboolean
url_email_start (const gchar *begin,
	const gchar *end,
	const gchar *pos,
	url_match_t *match)
{
	const gchar *p;
	/* Check what we have found */
	if (pos > begin && *pos == '@') {
		/* Try to extract it with username */
		p = pos - 1;
		while (p > begin && is_atom (*p)) {
			p--;
		}
		if (!is_atom (*p) && p != pos - 1) {
			match->m_begin = p + 1;
			return TRUE;
		}
		else if (p == begin) {
			match->m_begin = p;
			return TRUE;
		}
	}
	else {
		p = pos + strlen (match->pattern);
		if (is_atom (*p)) {
			match->m_begin = pos;
			return TRUE;
		}
	}
	return FALSE;
}

static gboolean
url_email_end (const gchar *begin,
	const gchar *end,
	const gchar *pos,
	url_match_t *match)
{
	const gchar *p;
	gboolean got_at = FALSE;

	p = pos + strlen (match->pattern);
	if (*pos == '@') {
		got_at = TRUE;
	}

	while (p < end && (is_domain (*p) || *p == '_'
		|| (*p == '@' && !got_at) ||
		*p == '.')) {

		if (*p == '@') {
			got_at = TRUE;
		}

		p++;
	}

	/* Strip strange symbols at the end */
	if (got_at) {
		while ((!is_domain (*p) || *p == '.' || *p == '_') &&
				p >= match->m_begin) {
			p --;
		}
		p ++;
	}

	match->m_len = p - match->m_begin;
	match->add_prefix = TRUE;

	return got_at;
}

void
rspamd_url_text_extract (rspamd_mempool_t * pool,
	struct rspamd_task *task,
	struct mime_text_part *part,
	gboolean is_html)
{
	gint rc;
	gchar *url_str = NULL, *url_start, *url_end;
	struct rspamd_url *new;
	struct process_exception *ex;
	gchar *p, *end, *begin;


	if (part->content == NULL || part->content->len == 0) {
		msg_warn ("got empty text part");
		return;
	}

	if (url_init () == 0) {
		begin = part->content->data;
		end = begin + part->content->len;
		p = begin;
		while (p < end) {
			if (rspamd_url_find (pool, p, end - p, &url_start, &url_end, &url_str,
				is_html)) {
				if (url_str != NULL) {
					new = rspamd_mempool_alloc0 (pool, sizeof (struct rspamd_url));
					ex =
						rspamd_mempool_alloc0 (pool,
							sizeof (struct process_exception));
					if (new != NULL) {
						g_strstrip (url_str);
						rc = rspamd_url_parse (new, url_str, strlen (url_str), pool);
						if (rc == URI_ERRNO_OK &&
							new->hostlen > 0) {
							ex->pos = url_start - begin;
							ex->len = url_end - url_start;
							if (new->protocol == PROTOCOL_MAILTO) {
								if (new->userlen > 0) {
									if (!g_tree_lookup (task->emails, new)) {
										g_tree_insert (task->emails, new, new);
									}
								}
							}
							else {
								if (!g_tree_lookup (task->urls, new)) {
									g_tree_insert (task->urls, new, new);
								}
							}
							part->urls_offset = g_list_prepend (
								part->urls_offset,
								ex);
						}
						else if (rc != URI_ERRNO_OK) {
							msg_info ("extract of url '%s' failed: %s",
								url_str,
								rspamd_url_strerror (rc));
						}
					}
				}
			}
			else {
				break;
			}
			p = url_end + 1;
		}
	}
	/* Handle offsets of this part */
	if (part->urls_offset != NULL) {
		part->urls_offset = g_list_reverse (part->urls_offset);
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t)g_list_free, part->urls_offset);
	}
}

gboolean
rspamd_url_find (rspamd_mempool_t *pool,
	const gchar *begin,
	gsize len,
	gchar **start,
	gchar **fin,
	gchar **url_str,
	gboolean is_html)
{
	const gchar *end, *pos;
	gint idx, l;
	struct url_matcher *matcher;
	url_match_t m;

	end = begin + len;
	if (url_init () == 0) {
		if ((pos =
			rspamd_trie_lookup (url_scanner->patterns, begin, len,
			&idx)) == NULL) {
			return FALSE;
		}
		else {
			matcher = &matchers[idx];
			if ((matcher->flags & URL_FLAG_NOHTML) && is_html) {
				/* Do not try to match non-html like urls in html texts */
				return FALSE;
			}
			m.pattern = matcher->pattern;
			m.prefix = matcher->prefix;
			m.add_prefix = FALSE;
			if (matcher->start (begin, end, pos,
				&m) && matcher->end (begin, end, pos, &m)) {
				if (m.add_prefix || matcher->prefix[0] != '\0') {
					l = m.m_len + 1 + strlen (m.prefix);
					*url_str = rspamd_mempool_alloc (pool, l);
					rspamd_snprintf (*url_str,
						l,
						"%s%*s",
						m.prefix,
						m.m_len,
						m.m_begin);
				}
				else {
					*url_str = rspamd_mempool_alloc (pool, m.m_len + 1);
					memcpy (*url_str, m.m_begin, m.m_len);
					(*url_str)[m.m_len] = '\0';
				}
				if (start != NULL) {
					*start = (gchar *)m.m_begin;
				}
				if (fin != NULL) {
					*fin = (gchar *)m.m_begin + m.m_len;
				}
			}
			else {
				*url_str = NULL;
				if (start != NULL) {
					*start = (gchar *)pos;
				}
				if (fin != NULL) {
					*fin = (gchar *)pos + strlen (m.prefix);
				}
			}

			return TRUE;
		}
	}

	return FALSE;
}

struct rspamd_url *
rspamd_url_get_next (rspamd_mempool_t *pool,
		const gchar *start, gchar const **pos)
{
	const gchar *p, *end;
	gchar *url_str = NULL, *url_start, *url_end;
	struct rspamd_url *new;
	gint rc;

	end = start + strlen (start);

	if (pos == NULL || *pos == NULL) {
		p = start;
	}
	else {
		p = *pos;
	}

	if (p < end) {
		if (rspamd_url_find (pool, p, end - p, &url_start, &url_end, &url_str,
				FALSE)) {
			if (url_str != NULL) {
				new = rspamd_mempool_alloc0 (pool, sizeof (struct rspamd_url));

				if (new != NULL) {
					g_strstrip (url_str);
					rc = rspamd_url_parse (new, url_str, strlen (url_str), pool);
					if (rc == URI_ERRNO_OK &&
							new->hostlen > 0) {

						if (new->protocol == PROTOCOL_MAILTO) {
							if (new->userlen > 0) {
								return new;
							}
						}
						else {
							return new;
						}
					}
					else if (rc != URI_ERRNO_OK) {
						msg_info ("extract of url '%s' failed: %s",
								url_str,
								rspamd_url_strerror (rc));
					}
				}
			}
		}
		p = url_end + 1;

		if (pos != NULL) {
			*pos = p;
		}
	}

	return NULL;
}

/*
 * vi: ts=4
 */
