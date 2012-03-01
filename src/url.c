/*
 * Copyright (c) 2009, Rambler media
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
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
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

#define POST_CHAR 1
#define POST_CHAR_S "\001"

/* Tcp port range */
#define LOWEST_PORT 0
#define HIGHEST_PORT    65535

#define uri_port_is_valid(port) \
    (LOWEST_PORT <= (port) && (port) <= HIGHEST_PORT)

struct _proto {
	guchar                         *name;
	gint                            port;
	uintptr_t                      *unused;
	guint                           need_slashes:1;
	guint                           need_slash_after_host:1;
	guint                           free_syntax:1;
	guint                           need_ssl:1;
};

typedef struct url_match_s {
	const gchar *m_begin;
	gsize m_len;
	const gchar *pattern;
	const gchar *prefix;
	gboolean add_prefix;
} url_match_t;

struct url_matcher {
	const gchar *pattern;
	const gchar *prefix;
	gboolean (*start)(const gchar *begin, const gchar *end, const gchar *pos, url_match_t *match);
	gboolean (*end)(const gchar *begin, const gchar *end, const gchar *pos, url_match_t *match);
};

static gboolean url_file_start (const gchar *begin, const gchar *end, const gchar *pos, url_match_t *match);
static gboolean url_file_end (const gchar *begin, const gchar *end, const gchar *pos, url_match_t *match);

static gboolean url_web_start (const gchar *begin, const gchar *end, const gchar *pos, url_match_t *match);
static gboolean url_web_end (const gchar *begin, const gchar *end, const gchar *pos, url_match_t *match);

static gboolean url_email_start (const gchar *begin, const gchar *end, const gchar *pos, url_match_t *match);
static gboolean url_email_end (const gchar *begin, const gchar *end, const gchar *pos, url_match_t *match);

struct url_matcher matchers[] = {
		{ "file://",		"",			url_file_start, 		url_file_end	},
		{ "ftp://",			"", 		url_web_start,	 		url_web_end		},
		{ "sftp://",		"", 		url_web_start,	 		url_web_end		},
		{ "http://",		"", 		url_web_start,	 		url_web_end		},
		{ "https://",		"", 		url_web_start,	 		url_web_end		},
		{ "news://",		"", 		url_web_start,	 		url_web_end		},
		{ "nntp://",		"", 		url_web_start,	 		url_web_end		},
		{ "telnet://",		"", 		url_web_start,	 		url_web_end		},
		{ "webcal://",		"", 		url_web_start,	 		url_web_end		},
		{ "mailto://",		"", 		url_email_start,	 	url_email_end	},
		{ "callto://",		"", 		url_web_start,	 		url_web_end		},
		{ "h323:",			"", 		url_web_start,	 		url_web_end		},
		{ "sip:",			"", 		url_web_start,	 		url_web_end		},
		{ "www.",			"http://", 	url_web_start,	 		url_web_end		},
		{ "ftp.",			"ftp://", 	url_web_start,	 		url_web_end		},
		{ "@",				"mailto://",url_email_start,	 	url_email_end	}
};

struct url_match_scanner {
	struct url_matcher *matchers;
	gsize matchers_count;
	rspamd_trie_t *patterns;
};

struct url_match_scanner *url_scanner = NULL;

static const struct _proto      protocol_backends[] = {
	{"file", 0, NULL, 1, 0, 0, 0},
	{"ftp", 21, NULL, 1, 0, 0, 0},
	{"http", 80, NULL, 1, 0, 0, 0},
	{"https", 443, NULL, 1, 0, 0, 1},
	{"mailto", 25, NULL, 1, 0, 0, 0},
	/* Keep these last! */
	{NULL, 0, NULL, 0, 0, 1, 0}
};

/* Convert an ASCII hex digit to the corresponding number between 0
   and 15.  H should be a hexadecimal digit that satisfies isxdigit;
   otherwise, the result is undefined.  */
#define XDIGIT_TO_NUM(h) ((h) < 'A' ? (h) - '0' : g_ascii_toupper (h) - 'A' + 10)
#define X2DIGITS_TO_NUM(h1, h2) ((XDIGIT_TO_NUM (h1) << 4) + XDIGIT_TO_NUM (h2))
/* The reverse of the above: convert a number in the [0, 16) range to
   the ASCII representation of the corresponding hexadecimal digit.
   `+ 0' is there so you can't accidentally use it as an lvalue.  */
#define XNUM_TO_DIGIT(x) ("0123456789ABCDEF"[x] + 0)
#define XNUM_TO_digit(x) ("0123456789abcdef"[x] + 0)

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
	IS_CTRL		= (1 << 0),
	IS_ALPHA        = (1 << 1),
	IS_DIGIT        = (1 << 2),
	IS_LWSP		= (1 << 3),
	IS_SPACE	= (1 << 4),
	IS_SPECIAL	= (1 << 5),
	IS_DOMAIN       = (1 << 6),
	IS_URLSAFE      = (1 << 7)
};

#define is_ctrl(x) ((url_scanner_table[(guchar)(x)] & IS_CTRL) != 0)
#define is_lwsp(x) ((url_scanner_table[(guchar)(x)] & IS_LWSP) != 0)
#define is_atom(x) ((url_scanner_table[(guchar)(x)] & (IS_SPECIAL|IS_SPACE|IS_CTRL)) == 0)
#define is_alpha(x) ((url_scanner_table[(guchar)(x)] & IS_ALPHA) != 0)
#define is_digit(x) ((url_scanner_table[(guchar)(x)] & IS_DIGIT) != 0)
#define is_domain(x) ((url_scanner_table[(guchar)(x)] & IS_DOMAIN) != 0)
#define is_urlsafe(x) ((url_scanner_table[(guchar)(x)] & (IS_ALPHA|IS_DIGIT|IS_URLSAFE)) != 0)


const gchar              *
url_strerror (enum uri_errno err)
{
	switch (err) {
	case URI_ERRNO_OK:
		return "Parsing went well";
	case URI_ERRNO_EMPTY:
		return "The URI string was empty";
	case URI_ERRNO_INVALID_PROTOCOL:
		return "No protocol was found";
	case URI_ERRNO_NO_SLASHES:
		return "Slashes after protocol missing";
	case URI_ERRNO_TOO_MANY_SLASHES:
		return "Too many slashes after protocol";
	case URI_ERRNO_TRAILING_DOTS:
		return "'.' after host";
	case URI_ERRNO_NO_HOST:
		return "Host part is missing";
	case URI_ERRNO_NO_PORT_COLON:
		return "':' after host without port";
	case URI_ERRNO_NO_HOST_SLASH:
		return "Slash after host missing";
	case URI_ERRNO_IPV6_SECURITY:
		return "IPv6 security bug detected";
	case URI_ERRNO_INVALID_PORT:
		return "Port number is bad";
	case URI_ERRNO_INVALID_PORT_RANGE:
		return "Port number is not within 0-65535";
	}
	return NULL;
}

static inline gint
end_of_dir (gchar c)
{
	return c == POST_CHAR || c == '#' || c == ';' || c == '?';
}

static inline gint
is_uri_dir_sep (struct uri *uri, gchar pos)
{
	return (pos == '/');
}

static gint
check_uri_file (gchar *name)
{
	static const gchar      chars[] = POST_CHAR_S "#?";

	return strcspn (name, chars);
}

static gint
url_init (void)
{
	guint                            i;
	if (url_scanner == NULL) {
		url_scanner = g_malloc (sizeof (struct url_match_scanner));
		url_scanner->matchers = matchers;
		url_scanner->matchers_count = G_N_ELEMENTS (matchers);
		url_scanner->patterns = rspamd_trie_create (TRUE);
		for (i = 0; i < url_scanner->matchers_count; i ++) {
			rspamd_trie_insert (url_scanner->patterns, matchers[i].pattern, i);
		}
	}

	return 0;
}

enum protocol
get_protocol (gchar *name, gint namelen)
{
	/* These are really enum protocol values but can take on negative
	 * values and since 0 <= -1 for enum values it's better to use clean
	 * integer type. */
	gint                            start, end;
	enum protocol                   protocol;
	guchar                          *pname;
	gint                            pnamelen, minlen, compare;

	/* Almost dichotomic search is used here */
	/* Starting at the HTTP entry which is the most common that will make
	 * file and NNTP the next entries checked and amongst the third checks
	 * are proxy and FTP. */
	start = 0;
	end = PROTOCOL_UNKNOWN - 1;
	protocol = PROTOCOL_HTTP;

	while (start <= end) {
		pname = protocol_backends[protocol].name;
		pnamelen = strlen (pname);
		minlen = MIN (pnamelen, namelen);
		compare = g_ascii_strncasecmp (pname, name, minlen);

		if (compare == 0) {
			if (pnamelen == namelen)
				return protocol;

			/* If the current protocol name is longer than the
			 * protocol name being searched for move @end else move
			 * @start. */
			compare = pnamelen > namelen ? 1 : -1;
		}

		if (compare > 0)
			end = protocol - 1;
		else
			start = protocol + 1;

		protocol = (start + end) / 2;
	}

	return PROTOCOL_UNKNOWN;
}


gint
get_protocol_port (enum protocol protocol)
{
	return protocol_backends[protocol].port;
}

gint
get_protocol_need_slashes (enum protocol protocol)
{
	return protocol_backends[protocol].need_slashes;
}

gint
get_protocol_need_slash_after_host (enum protocol protocol)
{
	return protocol_backends[protocol].need_slash_after_host;
}

gint
get_protocol_free_syntax (enum protocol protocol)
{
	return protocol_backends[protocol].free_syntax;
}

static gint
get_protocol_length (const gchar *url)
{
	gchar                          *end = (gchar *)url;

	/* Seek the end of the protocol name if any. */
	/* RFC1738:
	 * scheme  = 1*[ lowalpha | digit | "+" | "-" | "." ]
	 * (but per its recommendations we accept "upalpha" too) */
	while (g_ascii_isalnum (*end) || *end == '+' || *end == '-' || *end == '.')
		end++;

	/* Also return 0 if there's no protocol name (@end == @url). */
	return (*end == ':') ? end - url : 0;
}


/*
 * Calcualte new length of unescaped hostlen
 */
static guint
url_calculate_escaped_hostlen (gchar *host, guint hostlen)
{
	guint                           i, result = hostlen;
	gchar                           *p = host, c;

	for (i = 0; i < hostlen; i++, p++) {
		if (*p == '%' && g_ascii_isxdigit (*(p + 1)) && g_ascii_isxdigit (*(p + 2)) && i < hostlen - 2) {
			c = X2DIGITS_TO_NUM (*(p + 1), *(p + 2));
			if (c != '\0') {
				result -= 2;
			}
		}
	}

	return result;
}

/* URL-unescape the string S.

   This is done by transforming the sequences "%HH" to the character
   represented by the hexadecimal digits HH.  If % is not followed by
   two hexadecimal digits, it is inserted literally.

   The transformation is done in place.  If you need the original
   string intact, make a copy before calling this function.  */

static void
url_unescape (gchar *s)
{
	gchar                           *t = s;	/* t - tortoise */
	gchar                           *h = s;	/* h - hare     */

	for (; *h; h++, t++) {
		if (*h != '%') {
		  copychar:
			*t = *h;
		}
		else {
			gchar                           c;
			/* Do nothing if '%' is not followed by two hex digits. */
			if (!h[1] || !h[2] || !(g_ascii_isxdigit (h[1]) && g_ascii_isxdigit (h[2])))
				goto copychar;
			c = X2DIGITS_TO_NUM (h[1], h[2]);
			/* Don't unescape %00 because there is no way to insert it
			 * into a C string without effectively truncating it. */
			if (c == '\0')
				goto copychar;
			*t = c;
			h += 2;
		}
	}
	*t = '\0';
}

static void
url_strip (gchar *s)
{
	gchar                           *t = s;	/* t - tortoise */
	gchar                           *h = s;	/* h - hare     */

	while (*h) {
		if (g_ascii_isgraph (*h)) {
			*t = *h;
			t++;
		}
		h++;
	}
	*t = '\0';
}

static gchar                    *
url_escape_1 (const gchar *s, gint allow_passthrough, memory_pool_t * pool)
{
	const gchar                     *p1;
	gchar                           *p2, *newstr;
	gint                            newlen;
	gint                            addition = 0;

	for (p1 = s; *p1; p1++)
		if (!is_urlsafe (*p1)) {
			addition += 2;		/* Two more characters (hex digits) */
		}

	if (!addition) {
		if (allow_passthrough) {
			return (gchar *)s;
		}
		else {
			return memory_pool_strdup (pool, s);
		}
	}

	newlen = (p1 - s) + addition;
	newstr = (gchar *)memory_pool_alloc (pool, newlen + 1);

	p1 = s;
	p2 = newstr;
	while (*p1) {
		/* Quote the characters that match the test mask. */
		if (!is_urlsafe (*p1)) {
			guchar                          c = *p1++;
			*p2++ = '%';
			*p2++ = XNUM_TO_DIGIT (c >> 4);
			*p2++ = XNUM_TO_DIGIT (c & 0xf);
		}
		else
			*p2++ = *p1++;
	}
	*p2 = '\0';

	return newstr;
}

/* URL-escape the unsafe characters (see urlchr_table) in a given
   string, returning a freshly allocated string.  */

gchar                           *
url_escape (const gchar *s, memory_pool_t * pool)
{
	return url_escape_1 (s, 0, pool);
}

/* URL-escape the unsafe characters (see urlchr_table) in a given
   string.  If no characters are unsafe, S is returned.  */

static gchar                    *
url_escape_allow_passthrough (const gchar *s, memory_pool_t * pool)
{
	return url_escape_1 (s, 1, pool);
}

/* Decide whether the gchar at position P needs to be encoded.  (It is
   not enough to pass a single gchar *P because the function may need
   to inspect the surrounding context.)

   Return 1 if the gchar should be escaped as %XX, 0 otherwise.  */

static inline gint
char_needs_escaping (const gchar *p)
{
	if (*p == '%') {
		if (g_ascii_isxdigit (*(p + 1)) && g_ascii_isxdigit (*(p + 2)))
			return 0;
		else
			/* Garbled %.. sequence: encode `%'. */
			return 1;
	}
	else if (! is_urlsafe (*p))
		return 1;
	else
		return 0;
}

/* Translate a %-escaped (but possibly non-conformant) input string S
   into a %-escaped (and conformant) output string.  If no characters
   are encoded or decoded, return the same string S; otherwise, return
   a freshly allocated string with the new contents.

   After a URL has been run through this function, the protocols that
   use `%' as the quote character can use the resulting string as-is,
   while those that don't can use url_unescape to get to the intended
   data.  This function is stable: once the input is transformed,
   further transformations of the result yield the same output.
*/

static gchar                    *
reencode_escapes (gchar *s, memory_pool_t * pool)
{
	const gchar                     *p1;
	gchar                           *newstr, *p2;
	gint                            oldlen, newlen;

	gint                            encode_count = 0;

	/* First pass: inspect the string to see if there's anything to do,
	   and to calculate the new length.  */
	for (p1 = s; *p1; p1++)
		if (char_needs_escaping (p1))
			++encode_count;

	if (!encode_count) {
		/* The string is good as it is. */
		return s;
	}

	oldlen = p1 - s;
	/* Each encoding adds two characters (hex digits).  */
	newlen = oldlen + 2 * encode_count;
	newstr = memory_pool_alloc (pool, newlen + 1);

	/* Second pass: copy the string to the destination address, encoding
	   chars when needed.  */
	p1 = s;
	p2 = newstr;

	while (*p1)
		if (char_needs_escaping (p1)) {
			guchar                          c = *p1++;
			*p2++ = '%';
			*p2++ = XNUM_TO_DIGIT (c >> 4);
			*p2++ = XNUM_TO_DIGIT (c & 0xf);
		}
		else {
			*p2++ = *p1++;
		}

	*p2 = '\0';
	return newstr;
}

/* Unescape CHR in an otherwise escaped STR.  Used to selectively
   escaping of certain characters, such as "/" and ":".  Returns a
   count of unescaped chars.  */

static void
unescape_single_char (gchar *str, gchar chr)
{
	const gchar                      c1 = XNUM_TO_DIGIT (chr >> 4);
	const gchar                      c2 = XNUM_TO_DIGIT (chr & 0xf);
	gchar                           *h = str;	/* hare */
	gchar                           *t = str;	/* tortoise */

	for (; *h; h++, t++) {
		if (h[0] == '%' && h[1] == c1 && h[2] == c2) {
			*t = chr;
			h += 2;
		}
		else {
			*t = *h;
		}
	}
	*t = '\0';
}

/* Escape unsafe and reserved characters, except for the slash
	 characters.  */

static gchar                    *
url_escape_dir (const gchar *dir, memory_pool_t * pool)
{
	gchar                           *newdir = url_escape_1 (dir, 1, pool);
	if (newdir == dir)
		return (gchar *)dir;

	unescape_single_char (newdir, '/');
	return newdir;
}

/* Resolve "." and ".." elements of PATH by destructively modifying
   PATH and return non-zero if PATH has been modified, zero otherwise.

   The algorithm is in spirit similar to the one described in rfc1808,
   although implemented differently, in one pass.  To recap, path
   elements containing only "." are removed, and ".." is taken to mean
   "back up one element".  Single leading and trailing slashes are
   preserved.

   For example, "a/b/c/./../d/.." will yield "a/b/".  More exhaustive
   test examples are provided below.  If you change anything in this
   function, run test_path_simplify to make sure you haven't broken a
   test case.  */

static gint
path_simplify (gchar *path)
{
	gchar                           *h = path;	/* hare */
	gchar                           *t = path;	/* tortoise */
	gchar                           *beg = path;	/* boundary for backing the tortoise */
	gchar                           *end = path + strlen (path);

	while (h < end) {
		/* Hare should be at the beginning of a path element. */
		if (h[0] == '.' && (h[1] == '/' || h[1] == '\0')) {
			/* Ignore "./". */
			h += 2;
		}
		else if (h[0] == '.' && h[1] == '.' && (h[2] == '/' || h[2] == '\0')) {
			/* Handle "../" by retreating the tortoise by one path
			   element -- but not past beggining.  */
			if (t > beg) {
				/* Move backwards until T hits the beginning of the
				   previous path element or the beginning of path. */
				for (--t; t > beg && t[-1] != '/'; t--);
			}
			else {
				/* If we're at the beginning, copy the "../" literally
				   move the beginning so a later ".." doesn't remove
				   it.  */
				beg = t + 3;
				goto regular;
			}
			h += 3;
		}
		else {
		  regular:
			/* A regular path element.  If H hasn't advanced past T,
			   simply skip to the next path element.  Otherwise, copy
			   the path element until the next slash.  */
			if (t == h) {
				/* Skip the path element, including the slash.  */
				while (h < end && *h != '/')
					t++, h++;
				if (h < end)
					t++, h++;
			}
			else {
				/* Copy the path element, including the final slash.  */
				while (h < end && *h != '/')
					*t++ = *h++;
				if (h < end)
					*t++ = *h++;
			}
		}
	}

	if (t != h)
		*t = '\0';

	return t != h;
}

enum uri_errno
parse_uri (struct uri *uri, gchar *uristring, memory_pool_t * pool)
{
	guchar                          *prefix_end, *host_end, *p;
	guchar                          *lbracket, *rbracket;
	gint                            datalen, n, addrlen;
	guchar                          *frag_or_post, *user_end, *port_end;

	memset (uri, 0, sizeof (*uri));

	/* Nothing to do for an empty url. */
	if (!*uristring)
		return URI_ERRNO_EMPTY;

	uri->string = reencode_escapes (uristring, pool);
	msg_debug ("reencoding escapes in original url: '%s'", struri (uri));
	uri->protocollen = get_protocol_length (struri (uri));

	/* Assume http as default protocol */
	if (!uri->protocollen || (uri->protocol = get_protocol (struri (uri), uri->protocollen)) == PROTOCOL_UNKNOWN) {
		/* Make exception for numeric urls */
		p = uri->string;
		while (*p && (g_ascii_isalnum (*p) || *p == ':')) {
			p ++;
		}
		if (*p == '\0') {
			return URI_ERRNO_INVALID_PROTOCOL;
		}
		p = g_strconcat ("http://", uri->string, NULL);
		uri->string = memory_pool_strdup (pool, p);
		g_free (p);
		uri->protocol = PROTOCOL_HTTP;
		prefix_end = struri (uri) + 7;
	}
	else {
		/* Figure out whether the protocol is known */
		msg_debug ("getting protocol from url: %d", uri->protocol);

		prefix_end = struri (uri) + uri->protocollen;	/* ':' */

		/* Check if there's a digit after the protocol name. */
		if (g_ascii_isdigit (*prefix_end)) {
			p = struri (uri);
			uri->ip_family = p[uri->protocollen] - '0';
			prefix_end++;
		}
		if (*prefix_end != ':') {
			msg_debug ("invalid protocol in uri");
			return URI_ERRNO_INVALID_PROTOCOL;
		}
		prefix_end++;

		/* Skip slashes */

		if (prefix_end[0] == '/' && prefix_end[1] == '/') {
			if (prefix_end[2] == '/') {
				msg_debug ("too many '/' in uri");
				return URI_ERRNO_TOO_MANY_SLASHES;
			}

			prefix_end += 2;

		}
		else {
			msg_debug ("no '/' in uri");
			return URI_ERRNO_NO_SLASHES;
		}
	}

	if (get_protocol_free_syntax (uri->protocol)) {
		uri->data = prefix_end;
		uri->datalen = strlen (prefix_end);
		return URI_ERRNO_OK;

	}
	else if (uri->protocol == PROTOCOL_FILE) {
		datalen = check_uri_file (prefix_end);
		frag_or_post = prefix_end + datalen;

		/* Extract the fragment part. */
		if (datalen >= 0) {
			if (*frag_or_post == '#') {
				uri->fragment = frag_or_post + 1;
				uri->fragmentlen = strcspn (uri->fragment, POST_CHAR_S);
				frag_or_post = uri->fragment + uri->fragmentlen;
			}
			if (*frag_or_post == POST_CHAR) {
				uri->post = frag_or_post + 1;
			}
		}
		else {
			datalen = strlen (prefix_end);
		}

		uri->data = prefix_end;
		uri->datalen = datalen;

		return URI_ERRNO_OK;
	}

	/* Isolate host */

	/* Get brackets enclosing IPv6 address */
	lbracket = strchr (prefix_end, '[');
	if (lbracket) {
		rbracket = strchr (lbracket, ']');
		/* [address] is handled only inside of hostname part (surprisingly). */
		if (rbracket && rbracket < prefix_end + strcspn (prefix_end, "/"))
			uri->ipv6 = 1;
		else
			lbracket = rbracket = NULL;
	}
	else {
		rbracket = NULL;
	}

	/* Possibly skip auth part */
	host_end = prefix_end + strcspn (prefix_end, "@");

	if (prefix_end + strcspn (prefix_end, "/?") > host_end && *host_end) {	/* we have auth info here */

		/* Allow '@' in the password component */
		while (strcspn (host_end + 1, "@") < strcspn (host_end + 1, "/?"))
			host_end = host_end + 1 + strcspn (host_end + 1, "@");

		user_end = strchr (prefix_end, ':');

		if (!user_end || user_end > host_end) {
			uri->user = prefix_end;
			uri->userlen = host_end - prefix_end;
		}
		else {
			uri->user = prefix_end;
			uri->userlen = user_end - prefix_end;
			uri->password = user_end + 1;
			uri->passwordlen = host_end - user_end - 1;
		}
		prefix_end = host_end + 1;
	}

	if (uri->ipv6 && rbracket != NULL) {
		host_end = rbracket + strcspn (rbracket, ":/?");
	}
	else {
		host_end = prefix_end + strcspn (prefix_end, ":/?");
	}

	if (uri->ipv6) {
		addrlen = rbracket - lbracket - 1;


		uri->host = lbracket + 1;
		uri->hostlen = addrlen;
	}
	else {
		uri->host = prefix_end;
		uri->hostlen = host_end - prefix_end;

		/* Trim trailing '.'s */
		if (uri->hostlen && uri->host[uri->hostlen - 1] == '.')
			return URI_ERRNO_TRAILING_DOTS;
	}

	if (*host_end == ':') {		/* we have port here */
		port_end = host_end + 1 + strcspn (host_end + 1, "/");

		host_end++;

		uri->port = host_end;
		uri->portlen = port_end - host_end;

		if (uri->portlen == 0)
			return URI_ERRNO_NO_PORT_COLON;

		/* We only use 8 bits for portlen so better check */
		if ((gint)uri->portlen != port_end - host_end)
			return URI_ERRNO_INVALID_PORT;

		/* test if port is number */
		for (; host_end < port_end; host_end++)
			if (!g_ascii_isdigit (*host_end))
				return URI_ERRNO_INVALID_PORT;

		/* Check valid port value, and let show an error message
		 * about invalid url syntax. */
		if (uri->port && uri->portlen) {

			errno = 0;
			n = strtol (uri->port, NULL, 10);
			if (errno || !uri_port_is_valid (n))
				return URI_ERRNO_INVALID_PORT;
		}
	}

	if (*host_end == '/') {
		host_end++;

	}
	else if (get_protocol_need_slash_after_host (uri->protocol) && *host_end != '?') {
		/* The need for slash after the host component depends on the
		 * need for a host component. -- The dangerous mind of Jonah */
		if (!uri->hostlen)
			return URI_ERRNO_NO_HOST;

		return URI_ERRNO_NO_HOST_SLASH;
	}

	/* Look for #fragment or POST_CHAR */
	prefix_end = host_end + strcspn (host_end, "#" POST_CHAR_S);
	uri->data = host_end;
	uri->datalen = prefix_end - host_end;

	if (*prefix_end == '#') {
		uri->fragment = prefix_end + 1;
		uri->fragmentlen = strcspn (uri->fragment, POST_CHAR_S);
		prefix_end = uri->fragment + uri->fragmentlen;
	}

	if (*prefix_end == POST_CHAR) {
		uri->post = prefix_end + 1;
	}

	convert_to_lowercase (uri->string, uri->protocollen);
	convert_to_lowercase (uri->host, uri->hostlen);
	/* Decode %HH sequences in host name.  This is important not so much
	   to support %HH sequences in host names (which other browser
	   don't), but to support binary characters (which will have been
	   converted to %HH by reencode_escapes).  */
	if (strchr (uri->host, '%')) {
		uri->hostlen = url_calculate_escaped_hostlen (uri->host, uri->hostlen);
	}

	url_strip (struri (uri));
	url_unescape (uri->host);

	path_simplify (uri->data);

	return URI_ERRNO_OK;
}

static const gchar url_braces[] = {
	 '(', ')' ,
	 '{', '}' ,
	 '[', ']' ,
	 '<', '>' ,
	 '|', '|' ,
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
url_file_start (const gchar *begin, const gchar *end, const gchar *pos, url_match_t *match)
{
	match->m_begin = pos;
	return TRUE;
}
static gboolean
url_file_end (const gchar *begin, const gchar *end, const gchar *pos, url_match_t *match)
{
	const gchar                    *p;
	gchar                           stop;
	guint                           i;

	p = pos + strlen (match->pattern);
	stop = *p;
	if (*p == '/') {
		p ++;
	}

	for (i = 0; i < G_N_ELEMENTS (url_braces) / 2; i += 2) {
		if (*p == url_braces[i]) {
			stop = url_braces[i + 1];
			break;
		}
	}

	while (p < end && *p != stop && is_urlsafe (*p)) {
		p ++;
	}

	if (p == begin) {
		return FALSE;
	}
	match->m_len = p - match->m_begin;

	return TRUE;

}


static gboolean
url_web_start (const gchar *begin, const gchar *end, const gchar *pos, url_match_t *match)
{
	/* Check what we have found */
	if (pos > begin && *pos == 'w' && *(pos + 1) == 'w' && *(pos + 2) == 'w') {
		if (!is_open_brace (*(pos - 1)) && !g_ascii_isspace (*(pos - 1))) {
			return FALSE;
		}
	}
	match->m_begin = pos;

	return TRUE;
}
static gboolean
url_web_end (const gchar *begin, const gchar *end, const gchar *pos, url_match_t *match)
{
	const gchar                    *p, *c;
	gchar                           open_brace = '\0', close_brace = '\0';
	gint                            brace_stack = 0;
	gboolean                        passwd = FALSE;
	guint                           port, i;

	p = pos + strlen (match->pattern);
	for (i = 0; i < G_N_ELEMENTS (url_braces) / 2; i += 2) {
		if (*p == url_braces[i]) {
			close_brace = url_braces[i + 1];
			open_brace = *p;
			break;
		}
	}

	/* find the end of the domain */
	if (is_atom (*p)) {
		/* might be a domain or user@domain */
		c = p;
		while (p < end) {
			if (!is_atom (*p)) {
				break;
			}

			p++;

			while (p < end && is_atom (*p)) {
				p++;
			}

			if ((p + 1) < end && *p == '.' && (is_atom (*(p + 1)) || *(p + 1) == '/')) {
				p++;
			}
		}

		if (*p != '@') {
			p = c;
		}
		else {
			p++;
		}

		goto domain;
	}
	else if (is_domain (*p) || (*p & 0x80)) {
domain:
		while (p < end) {
			if (!is_domain (*p) && !(*p & 0x80)) {
				break;
			}

			p++;

			while (p < end && (is_domain (*p) || (*p & 0x80))) {
				p++;
			}

			if ((p + 1) < end && *p == '.' && (is_domain (*(p + 1)) || *(p + 1) == '/' || (*(p + 1) & 0x80))) {
				p++;
			}
		}
	}
	else {
		return FALSE;
	}

	if (p < end) {
		switch (*p) {
		case ':': /* we either have a port or a password */
			p++;

			if (is_digit (*p) || passwd) {
				port = (*p++ - '0');

				while (p < end && is_digit (*p) && port < 65536) {
					port = (port * 10) + (*p++ - '0');
				}

				if (!passwd && (port >= 65536 || *p == '@')) {
					if (p < end) {
						/* this must be a password? */
						goto passwd;
					}

					p--;
				}
			}
			else {
				passwd:
				passwd = TRUE;
				c = p;

				while (p < end && is_atom (*p)) {
					p++;
				}

				if ((p + 2) < end) {
					if (*p == '@') {
						p++;
						if (is_domain (*p)) {
							goto domain;
						}
					}

					return FALSE;
				}
			}

			if (p >= end || *p != '/') {
				break;
			}

			/* we have a '/' so there could be a path - fall through */
		case '/': /* we've detected a path component to our url */
			p++;
		case '?':
			while (p < end && is_urlsafe (*p)) {
				if (*p == open_brace) {
					brace_stack++;
				}
				else if (*p == close_brace) {
					brace_stack--;
					if (brace_stack == -1) {
						break;
					}
				}
				p++;
			}

			break;
		default:
			break;
		}
	}

	/* urls are extremely unlikely to end with any
	 * punctuation, so strip any trailing
	 * punctuation off. Also strip off any closing
	 * double-quotes. */
	while (p > pos && strchr (",.:;?!-|}])\"", p[-1])) {
		p--;
	}

	match->m_len = (p - pos);

	return TRUE;
}


static gboolean
url_email_start (const gchar *begin, const gchar *end, const gchar *pos, url_match_t *match)
{
	const gchar                    *p;
	/* Check what we have found */
	if (pos > begin && *pos == '@') {
		/* Try to extract it with username */
		p = pos - 1;
		while (p > begin && (is_domain (*p) || *p == '.' || *p == '_')) {
			p --;
		}
		if (!is_domain (*p)) {
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
		if (is_domain (*p)) {
			match->m_begin = p;
			return TRUE;
		}
	}
	return FALSE;
}

static gboolean
url_email_end (const gchar *begin, const gchar *end, const gchar *pos, url_match_t *match)
{
	const gchar                    *p;

	p = pos + strlen (match->pattern);

	while (p < end && (is_domain (*p) || *p == '_' || (*p == '.' && p + 1 < end && is_domain (*(p + 1))))) {
		p ++;
	}
	match->m_len = p - match->m_begin;
	match->add_prefix = TRUE;
	return TRUE;
}

void
url_parse_text (memory_pool_t * pool, struct worker_task *task, struct mime_text_part *part, gboolean is_html)
{
	gint                            rc;
	gchar                          *url_str = NULL, *url_start, *url_end;
	struct uri                     *new;
	struct process_exception       *ex;
	gchar                          *p, *end, *begin;


	if (!part->orig->data || part->orig->len == 0) {
		msg_warn ("got empty text part");
		return;
	}

	if (url_init () == 0) {
		if (is_html) {
			begin = part->orig->data;
			end = begin + part->orig->len;
			p = begin;
		}
		else {
			begin = part->content->data;
			end = begin + part->content->len;
			p = begin;
		}
		while (p < end) {
			if (url_try_text (pool, p, end - p, &url_start, &url_end, &url_str)) {
				if (url_str != NULL) {
					new = memory_pool_alloc0 (pool, sizeof (struct uri));
					ex = memory_pool_alloc0 (pool, sizeof (struct process_exception));
					if (new != NULL) {
						g_strstrip (url_str);
						rc = parse_uri (new, url_str, pool);
						if ((rc == URI_ERRNO_OK || rc == URI_ERRNO_NO_SLASHES || rc == URI_ERRNO_NO_HOST_SLASH) &&
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
							part->urls_offset = g_list_prepend (part->urls_offset, ex);
						}
						else if (rc != URI_ERRNO_OK) {
							msg_info ("extract of url '%s' failed: %s", url_str, url_strerror (rc));
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
		memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_list_free, part->urls_offset);
	}
}

gboolean
url_try_text (memory_pool_t *pool, const gchar *begin, gsize len, gchar **start, gchar **fin, gchar **url_str)
{
	const gchar                    *end, *pos;
	gint                            idx, l;
	struct url_matcher             *matcher;
	url_match_t                     m;

	end = begin + len;
	if (url_init () == 0) {
		if ((pos = rspamd_trie_lookup (url_scanner->patterns, begin, len, &idx)) == NULL) {
			return FALSE;
		}
		else {
			matcher = &matchers[idx];
			m.pattern = matcher->pattern;
			m.prefix = matcher->prefix;
			m.add_prefix = FALSE;
			if (matcher->start (begin, end, pos, &m) && matcher->end (begin, end, pos, &m)) {
				if (m.add_prefix) {
					l = m.m_len + 1 + strlen (m.prefix);
					*url_str = memory_pool_alloc (pool, l);
					rspamd_snprintf (*url_str, l, "%s%*s", m.prefix, m.m_len, m.m_begin);
				}
				else {
					*url_str = memory_pool_alloc (pool, m.m_len + 1);
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

/*
 * vi: ts=4
 */
