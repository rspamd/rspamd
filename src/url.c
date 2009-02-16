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
 * DISCLAIMED. IN NO EVENT SHALL <copyright holder> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>

#include "url.h"
#include "fstring.h"
#include "main.h"

#define POST_CHAR 1
#define POST_CHAR_S "\001"

/* Tcp port range */
#define LOWEST_PORT 0
#define HIGHEST_PORT    65535

#define uri_port_is_valid(port) \
    (LOWEST_PORT <= (port) && (port) <= HIGHEST_PORT)

struct _proto {
	unsigned char *name;
	int port;
	uintptr_t *unused;
	unsigned int need_slashes:1;
	unsigned int need_slash_after_host:1;
	unsigned int free_syntax:1;
	unsigned int need_ssl:1;
};

static const char *text_url = "((https?|ftp)://)?"
"(\\b(?<![.\\@A-Za-z0-9-])"	
"(?: [A-Za-z0-9][A-Za-z0-9-]*(?:\\.[A-Za-z0-9-]+)*\\."
"(?i:com|net|org|biz|edu|gov|info|name|int|mil|aero|coop|jobs|mobi|museum|pro|travel"
"|[rs]u|uk|ua|by|de|jp|fr|fi|no|no|ca|it|ro|cn|nl|at|nu|se"
"|[a-z]{2}"
"(?(1)|(?=/)))"
"(?!\\w)"
"|(?:\\d{1,3}\\.){3}\\d{1,3}(?(1)|(?=[/:]))"
")"
"(?::\\d{1,5})?"	/* port */
"(?!\\.\\w)" /* host part ended, no more of this further on */
"(?:[/?][;/?:@&=+\\$,[\\]\\-_.!~*'()A-Za-z0-9#%]*)?" /* path (&query) */
"(?<![\\s>?!),.'\"\\]:])"
"(?!@)"
")";
static const char *html_url = "(?: src|href)=\"("
"((https?|ftp)://)?"
"(\\b(?<![.\\@A-Za-z0-9-])"	
"(?: [A-Za-z0-9][A-Za-z0-9-]*(?:\\.[A-Za-z0-9-]+)*\\."
"(?i:com|net|org|biz|edu|gov|info|name|int|mil|aero|coop|jobs|mobi|museum|pro|travel"
"|[rs]u|uk|ua|by|de|jp|fr|fi|no|no|ca|it|ro|cn|nl|at|nu|se"
"|[a-z]{2}"
"(?(1)|(?=/)))"
"(?!\\w)"
"|(?:\\d{1,3}\\.){3}\\d{1,3}(?(1)|(?=[/:]))"
")"
"(?::\\d{1,5})?"	/* port */
"(?!\\.\\w)" /* host part ended, no more of this further on */
"(?:[/?][;/?:@&=+\\$,[\\]\\-_.!~*'()A-Za-z0-9#%]*)?" /* path (&query) */
"(?<![\\s>?!),.'\"\\]:])"
"(?!@)"
"))\"";

static short url_initialized = 0;
GRegex *text_re, *html_re;

static const struct _proto protocol_backends[] = {
	{ "file",	   0, NULL,		1, 0, 0, 0 },
	{ "ftp",	  21, NULL,		1, 1, 0, 0 },
	{ "http",	  80, NULL,		1, 1, 0, 0 },
	{ "https",	 443, NULL,		1, 1, 0, 1 },

	/* Keep these last! */
	{ NULL,		   0, NULL,			0, 0, 1, 0 },
};

/* 
   Table of "reserved" and "unsafe" characters.  Those terms are
   rfc1738-speak, as such largely obsoleted by rfc2396 and later
   specs, but the general idea remains.

   A reserved character is the one that you can't decode without
   changing the meaning of the URL.  For example, you can't decode
   "/foo/%2f/bar" into "/foo///bar" because the number and contents of
   path components is different.  Non-reserved characters can be
   changed, so "/foo/%78/bar" is safe to change to "/foo/x/bar".  The
   unsafe characters are loosely based on rfc1738, plus "$" and ",",
   as recommended by rfc2396, and minus "~", which is very frequently
   used (and sometimes unrecognized as %7E by broken servers).

   An unsafe character is the one that should be encoded when URLs are
   placed in foreign environments.  E.g. space and newline are unsafe
   in HTTP contexts because HTTP uses them as separator and line
   terminator, so they must be encoded to %20 and %0A respectively.
   "*" is unsafe in shell context, etc.

   We determine whether a character is unsafe through static table
   lookup.  This code assumes ASCII character set and 8-bit chars.  */

enum {
  /* rfc1738 reserved chars + "$" and ",".  */
  urlchr_reserved = 1,

  /* rfc1738 unsafe chars, plus non-printables.  */
  urlchr_unsafe   = 2
};

#define urlchr_test(c, mask) (urlchr_table[(unsigned char)(c)] & (mask))
#define URL_RESERVED_CHAR(c) urlchr_test(c, urlchr_reserved)
#define URL_UNSAFE_CHAR(c) urlchr_test(c, urlchr_unsafe)
/* Convert an ASCII hex digit to the corresponding number between 0
   and 15.  H should be a hexadecimal digit that satisfies isxdigit;
   otherwise, the result is undefined.  */
#define XDIGIT_TO_NUM(h) ((h) < 'A' ? (h) - '0' : toupper (h) - 'A' + 10)
#define X2DIGITS_TO_NUM(h1, h2) ((XDIGIT_TO_NUM (h1) << 4) + XDIGIT_TO_NUM (h2))
/* The reverse of the above: convert a number in the [0, 16) range to
   the ASCII representation of the corresponding hexadecimal digit.
   `+ 0' is there so you can't accidentally use it as an lvalue.  */
#define XNUM_TO_DIGIT(x) ("0123456789ABCDEF"[x] + 0)
#define XNUM_TO_digit(x) ("0123456789abcdef"[x] + 0)

/* Shorthands for the table: */
#define R  urlchr_reserved
#define U  urlchr_unsafe
#define RU R|U

static const unsigned char urlchr_table[256] =
{
  U,  U,  U,  U,   U,  U,  U,  U,   /* NUL SOH STX ETX  EOT ENQ ACK BEL */
  U,  U,  U,  U,   U,  U,  U,  U,   /* BS  HT  LF  VT   FF  CR  SO  SI  */
  U,  U,  U,  U,   U,  U,  U,  U,   /* DLE DC1 DC2 DC3  DC4 NAK SYN ETB */
  U,  U,  U,  U,   U,  U,  U,  U,   /* CAN EM  SUB ESC  FS  GS  RS  US  */
  U,  0,  U, RU,   R,  U,  R,  0,   /* SP  !   "   #    $   %   &   '   */
  0,  0,  0,  R,   R,  0,  0,  R,   /* (   )   *   +    ,   -   .   /   */
  0,  0,  0,  0,   0,  0,  0,  0,   /* 0   1   2   3    4   5   6   7   */
  0,  0, RU,  R,   U,  R,  U,  R,   /* 8   9   :   ;    <   =   >   ?   */
 RU,  0,  0,  0,   0,  0,  0,  0,   /* @   A   B   C    D   E   F   G   */
  0,  0,  0,  0,   0,  0,  0,  0,   /* H   I   J   K    L   M   N   O   */
  0,  0,  0,  0,   0,  0,  0,  0,   /* P   Q   R   S    T   U   V   W   */
  0,  0,  0, RU,   U, RU,  U,  0,   /* X   Y   Z   [    \   ]   ^   _   */
  U,  0,  0,  0,   0,  0,  0,  0,   /* `   a   b   c    d   e   f   g   */
  0,  0,  0,  0,   0,  0,  0,  0,   /* h   i   j   k    l   m   n   o   */
  0,  0,  0,  0,   0,  0,  0,  0,   /* p   q   r   s    t   u   v   w   */
  0,  0,  0,  U,   U,  U,  0,  U,   /* x   y   z   {    |   }   ~   DEL */

  U, U, U, U,  U, U, U, U,  U, U, U, U,  U, U, U, U,
  U, U, U, U,  U, U, U, U,  U, U, U, U,  U, U, U, U,
  U, U, U, U,  U, U, U, U,  U, U, U, U,  U, U, U, U,
  U, U, U, U,  U, U, U, U,  U, U, U, U,  U, U, U, U,

  U, U, U, U,  U, U, U, U,  U, U, U, U,  U, U, U, U,
  U, U, U, U,  U, U, U, U,  U, U, U, U,  U, U, U, U,
  U, U, U, U,  U, U, U, U,  U, U, U, U,  U, U, U, U,
  U, U, U, U,  U, U, U, U,  U, U, U, U,  U, U, U, U,
};
#undef R
#undef U
#undef RU

static inline int
end_of_dir(unsigned char c)
{
	return c == POST_CHAR || c == '#' || c == ';' || c == '?';
}

static inline int
is_uri_dir_sep(struct uri *uri, unsigned char pos)
{
	return (pos == '/');
}

static int
check_uri_file(unsigned char *name)
{
	static const unsigned char chars[] = POST_CHAR_S "#?";

	return strcspn(name, chars);
}

static int
url_init (void)
{
	GError *err = NULL;
	if (url_initialized == 0) {
		text_re = g_regex_new  (text_url, G_REGEX_CASELESS | G_REGEX_MULTILINE | G_REGEX_OPTIMIZE | G_REGEX_EXTENDED, 0, &err);
		if (err != NULL) {
			msg_info ("url_init: cannot init text url parsing regexp: %s", err->message);
			g_error_free (err);
			return -1;
		}
		html_re = g_regex_new (html_url, G_REGEX_CASELESS | G_REGEX_MULTILINE | G_REGEX_OPTIMIZE | G_REGEX_EXTENDED, 0, &err);
		if (err != NULL) {
			msg_info ("url_init: cannot init html url parsing regexp: %s", err->message);
			g_error_free (err);
			return -1;
		}
		url_initialized = 1;
	}

	return 0;
}

enum protocol
get_protocol(unsigned char *name, int namelen)
{
	/* These are really enum protocol values but can take on negative
	 * values and since 0 <= -1 for enum values it's better to use clean
	 * integer type. */
	int start, end;
	enum protocol protocol;
	unsigned char *pname;
	int pnamelen, minlen, compare;

	/* Almost dichotomic search is used here */
	/* Starting at the HTTP entry which is the most common that will make
	 * file and NNTP the next entries checked and amongst the third checks
	 * are proxy and FTP. */
	start	 = 0;
	end	 = PROTOCOL_UNKNOWN - 1;
	protocol = PROTOCOL_HTTP;

	while (start <= end) {
		pname = protocol_backends[protocol].name;
		pnamelen = strlen (pname);
		minlen = MIN (pnamelen, namelen);
		compare = strncasecmp (pname, name, minlen);

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


int
get_protocol_port(enum protocol protocol)
{
	return protocol_backends[protocol].port;
}

int
get_protocol_need_slashes(enum protocol protocol)
{
	return protocol_backends[protocol].need_slashes;
}

int
get_protocol_need_slash_after_host(enum protocol protocol)
{
	return protocol_backends[protocol].need_slash_after_host;
}

int
get_protocol_free_syntax(enum protocol protocol)
{
	return protocol_backends[protocol].free_syntax;
}

static int
get_protocol_length(const unsigned char *url)
{
	unsigned char *end = (unsigned char *) url;

	/* Seek the end of the protocol name if any. */
	/* RFC1738:
	 * scheme  = 1*[ lowalpha | digit | "+" | "-" | "." ]
	 * (but per its recommendations we accept "upalpha" too) */
	while (isalnum(*end) || *end == '+' || *end == '-' || *end == '.')
		end++;

	/* Also return 0 if there's no protocol name (@end == @url). */
	return (*end == ':') ? end - url : 0;
}

/* URL-unescape the string S.

   This is done by transforming the sequences "%HH" to the character
   represented by the hexadecimal digits HH.  If % is not followed by
   two hexadecimal digits, it is inserted literally.

   The transformation is done in place.  If you need the original
   string intact, make a copy before calling this function.  */

static void
url_unescape (char *s)
{
 	char *t = s;			/* t - tortoise */
	char *h = s;			/* h - hare     */
    
	for (; *h; h++, t++) {
		if (*h != '%') {
			copychar:
			*t = *h;
		}
        else {
			char c;
			/* Do nothing if '%' is not followed by two hex digits. */
			if (!h[1] || !h[2] || !(isxdigit (h[1]) && isxdigit (h[2])))
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

/* The core of url_escape_* functions.  Escapes the characters that
   match the provided mask in urlchr_table.

   If ALLOW_PASSTHROUGH is non-zero, a string with no unsafe chars
   will be returned unchanged.  If ALLOW_PASSTHROUGH is zero, a
   freshly allocated string will be returned in all cases.  */

static char *
url_escape_1 (const char *s, unsigned char mask, int allow_passthrough, memory_pool_t *pool)
{
	const char *p1;
	char *p2, *newstr;
	int newlen;
	int addition = 0;

	for (p1 = s; *p1; p1++)
		if (urlchr_test (*p1, mask))
			addition += 2;		/* Two more characters (hex digits) */

	if (!addition) {
		if (allow_passthrough) {
			return (char *)s;
		}
		else {
			return memory_pool_strdup (pool, s);
		}
	}

	newlen = (p1 - s) + addition;
	newstr = (char *) memory_pool_alloc (pool, newlen + 1);

	p1 = s;
	p2 = newstr;
	while (*p1) {
		/* Quote the characters that match the test mask. */
		if (urlchr_test (*p1, mask)) {
			unsigned char c = *p1++;
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

char *
url_escape (const char *s, memory_pool_t *pool)
{
	return url_escape_1 (s, urlchr_unsafe, 0, pool);
}

/* URL-escape the unsafe characters (see urlchr_table) in a given
   string.  If no characters are unsafe, S is returned.  */

static char *
url_escape_allow_passthrough (const char *s, memory_pool_t *pool)
{
	return url_escape_1 (s, urlchr_unsafe, 1, pool);
}

/* Decide whether the char at position P needs to be encoded.  (It is
   not enough to pass a single char *P because the function may need
   to inspect the surrounding context.)

   Return 1 if the char should be escaped as %XX, 0 otherwise.  */

static inline int
char_needs_escaping (const char *p)
{
	if (*p == '%') {
		if (isxdigit (*(p + 1)) && isxdigit (*(p + 2)))
			return 0;
		else
			/* Garbled %.. sequence: encode `%'. */
			return 1;
	}
	else if (URL_UNSAFE_CHAR (*p) && !URL_RESERVED_CHAR (*p))
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

static char *
reencode_escapes (const char *s, memory_pool_t *pool)
{
	const char *p1;
	char *newstr, *p2;
	int oldlen, newlen;

	int encode_count = 0;

	/* First pass: inspect the string to see if there's anything to do,
	   and to calculate the new length.  */
	for (p1 = s; *p1; p1++)
		if (char_needs_escaping (p1))
			++encode_count;

	if (!encode_count) {
		/* The string is good as it is. */
		return memory_pool_strdup (pool, s);
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
		unsigned char c = *p1++;
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
unescape_single_char (char *str, char chr)
{
	const char c1 = XNUM_TO_DIGIT (chr >> 4);
	const char c2 = XNUM_TO_DIGIT (chr & 0xf);
	char *h = str;		/* hare */
	char *t = str;		/* tortoise */

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

static char *
url_escape_dir (const char *dir, memory_pool_t *pool)
{
	char *newdir = url_escape_1 (dir, urlchr_unsafe | urlchr_reserved, 1, pool);
	if (newdir == dir)
		return (char *)dir;

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

static int
path_simplify (char *path)
{
	char *h = path;		/* hare */
	char *t = path;		/* tortoise */
	char *beg = path;		/* boundary for backing the tortoise */
	char *end = path + strlen (path);

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
parse_uri(struct uri *uri, unsigned char *uristring, memory_pool_t *pool)
{
	unsigned char *prefix_end, *host_end, *p;
	unsigned char *lbracket, *rbracket;
	int datalen, n, addrlen;
	unsigned char *frag_or_post, *user_end, *port_end;

	memset (uri, 0, sizeof (*uri));

	/* Nothing to do for an empty url. */
	if (!*uristring) return URI_ERRNO_EMPTY;
	
	uri->string = reencode_escapes (uristring, pool);
	msg_debug ("parse_uri: reencoding escapes in original url: '%s'", struri (uri));
	uri->protocollen = get_protocol_length (struri (uri));

	/* Assume http as default protocol */
	if (!uri->protocollen || (uri->protocol = get_protocol (struri(uri), uri->protocollen)) == PROTOCOL_UNKNOWN) {
		p = g_strconcat ("http://", uri->string, NULL);
		g_free (uri->string);
		uri->string = p;
		uri->protocol = PROTOCOL_HTTP;
		prefix_end = struri (uri) + 7;
	}
	else {
		/* Figure out whether the protocol is known */
		msg_debug ("parse_uri: getting protocol from url: %d", uri->protocol);

		prefix_end = struri (uri) + uri->protocollen; /* ':' */

		/* Check if there's a digit after the protocol name. */
		if (isdigit (*prefix_end)) {
			p = struri (uri);
			uri->ip_family = p[uri->protocollen] - '0';
			prefix_end++;
		}
		if (*prefix_end != ':') {
			msg_debug ("parse_uri: invalid protocol in uri");
			return URI_ERRNO_INVALID_PROTOCOL;
		}
		prefix_end++;

		/* Skip slashes */

		if (prefix_end[0] == '/' && prefix_end[1] == '/') {
			if (prefix_end[2] == '/') {
				msg_debug ("parse_uri: too many '/' in uri");
				return URI_ERRNO_TOO_MANY_SLASHES;
			}

			prefix_end += 2;

		} else {
			msg_debug ("parse_uri: no '/' in uri");
			return URI_ERRNO_NO_SLASHES;
		}
	}

	if (get_protocol_free_syntax (uri->protocol)) {
		uri->data = prefix_end;
		uri->datalen = strlen (prefix_end);
		return URI_ERRNO_OK;

	} else if (uri->protocol == PROTOCOL_FILE) {
		datalen = check_uri_file (prefix_end);
		frag_or_post = prefix_end + datalen;

		/* Extract the fragment part. */
		if (datalen >= 0) {
			if (*frag_or_post == '#') {
				uri->fragment = frag_or_post + 1;
				uri->fragmentlen = strcspn(uri->fragment, POST_CHAR_S);
				frag_or_post = uri->fragment + uri->fragmentlen;
			}
			if (*frag_or_post == POST_CHAR) {
				uri->post = frag_or_post + 1;
			}
		} else {
			datalen = strlen(prefix_end);
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
	} else {
		rbracket = NULL;
	}

	/* Possibly skip auth part */
	host_end = prefix_end + strcspn (prefix_end, "@");

	if (prefix_end + strcspn (prefix_end, "/") > host_end
	    && *host_end) { /* we have auth info here */

		/* Allow '@' in the password component */
		while (strcspn (host_end + 1, "@") < strcspn (host_end + 1, "/?"))
			host_end = host_end + 1 + strcspn (host_end + 1, "@");

		user_end = strchr (prefix_end, ':');

		if (!user_end || user_end > host_end) {
			uri->user = prefix_end;
			uri->userlen = host_end - prefix_end;
		} else {
			uri->user = prefix_end;
			uri->userlen = user_end - prefix_end;
			uri->password = user_end + 1;
			uri->passwordlen = host_end - user_end - 1;
		}
		prefix_end = host_end + 1;
	}

	if (uri->ipv6)
		host_end = rbracket + strcspn (rbracket, ":/?");
	else
		host_end = prefix_end + strcspn (prefix_end, ":/?");

	if (uri->ipv6) {
		addrlen = rbracket - lbracket - 1;


		uri->host = lbracket + 1;
		uri->hostlen = addrlen;
	} else {
		uri->host = prefix_end;
		uri->hostlen = host_end - prefix_end;

		/* Trim trailing '.'s */
		if (uri->hostlen && uri->host[uri->hostlen - 1] == '.')
			return URI_ERRNO_TRAILING_DOTS;
	}

	if (*host_end == ':') { /* we have port here */
		port_end = host_end + 1 + strcspn (host_end + 1, "/");

		host_end++;

		uri->port = host_end;
		uri->portlen = port_end - host_end;

		if (uri->portlen == 0)
			return URI_ERRNO_NO_PORT_COLON;

		/* We only use 8 bits for portlen so better check */
		if (uri->portlen != port_end - host_end)
			return URI_ERRNO_INVALID_PORT;

		/* test if port is number */
		for (; host_end < port_end; host_end++)
			if (!isdigit (*host_end))
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

	} else if (get_protocol_need_slash_after_host (uri->protocol) && *host_end != '?') {
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
		url_unescape (uri->host);
	}
	path_simplify (uri->data);

	return URI_ERRNO_OK;
}

void 
url_parse_text (struct worker_task *task, GByteArray *content)
{
	GMatchInfo *info;
	GError *err = NULL;
	int pos = 0, start;
	gboolean rc;
	char *url_str = NULL;
	struct uri *new;

	if (url_init () == 0) {
		do {
			rc = g_regex_match_full (text_re, (const char *)content->data, content->len, pos, 0, &info, &err);
			if (rc) {
				if (g_match_info_matches (info)) {
					g_match_info_fetch_pos (info, 0, &start, &pos);
					url_str = g_match_info_fetch (info, 0);
					msg_debug ("url_parse_text: extracted string with regexp: '%s'", url_str);
					if (url_str != NULL) {
						new = memory_pool_alloc (task->task_pool, sizeof (struct uri));
						if (new != NULL) {
							parse_uri (new, url_str, task->task_pool);
							TAILQ_INSERT_TAIL (&task->urls, new, next);
						}
					}
					g_free (url_str);
				}
				g_match_info_free (info);
			}
			else if (err != NULL) {
				msg_debug ("url_parse_text: error matching regexp: %s", err->message);
				g_free (err);
			}
			else {
				msg_debug ("url_parse_text: cannot find url pattern in given string");
			}
		} while (rc);
	}
}

void 
url_parse_html (struct worker_task *task, GByteArray *content)
{
	GMatchInfo *info;
	GError *err = NULL;
	int pos = 0, start;
	gboolean rc;
	char *url_str = NULL;
	struct uri *new;

	if (url_init () == 0) {
		do {
			rc = g_regex_match_full (html_re, (const char *)content->data, content->len, pos, 0, &info, &err);
			if (rc) {
				if (g_match_info_matches (info)) {
					g_match_info_fetch_pos (info, 0, &start, &pos);
					url_str = g_match_info_fetch (info, 1);
					msg_debug ("url_parse_html: extracted string with regexp: '%s'", url_str);
					if (url_str != NULL) {
						new = memory_pool_alloc (task->task_pool, sizeof (struct uri));
						if (new != NULL) {
							parse_uri (new, url_str, task->task_pool);
							TAILQ_INSERT_TAIL (&task->urls, new, next);
						}
					}
					g_free (url_str);
				}
				g_match_info_free (info);
			}
			else if (err) {
				msg_debug ("url_parse_html: error matching regexp: %s", err->message);
				g_free (err);
			}
			else {
				msg_debug ("url_parse_html: cannot find url pattern in given string");
			}
		} while (rc);
	}
}
