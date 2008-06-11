#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <pcre.h>
#include <syslog.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "url.h"
#include "fstring.h"
#include "main.h"

#define POST_CHAR 1
#define POST_CHAR_S "\001"

struct _proto {
	unsigned char *name;
	int port;
	uintptr_t *unused;
	unsigned int need_slashes:1;
	unsigned int need_slash_after_host:1;
	unsigned int free_syntax:1;
	unsigned int need_ssl:1;
};

static const char *html_url = "((?:href=)|(?:archive=)|(?:code=)|(?:codebase=)|(?:src=)|(?:cite=)"
"|(:?background=)|(?:pluginspage=)|(?:pluginurl=)|(?:action=)|(?:dynsrc=)|(?:longdesc=)|(?:lowsrc=)|(?:src=)|(?:usemap=))"
"\\\"?([^>\"<]+)\\\"?";
static const char *text_url = "((mailto\\:|(news|(ht|f)tp(s?))\\://){1}[^>\"<]+)";

static short url_initialized = 0;
static pcre_extra *text_re_extra;
static pcre *text_re;
static pcre_extra *html_re_extra;
static pcre *html_re;

static const struct _proto protocol_backends[] = {
	{ "file",	   0, NULL,		1, 0, 0, 0 },
	{ "ftp",	  21, NULL,		1, 1, 0, 0 },
	{ "http",	  80, NULL,		1, 1, 0, 0 },
	{ "https",	 443, NULL,		1, 1, 0, 1 },

	/* Keep these last! */
	{ NULL,		   0, NULL,			0, 0, 1, 0 },
};

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
url_init (void)
{
	if (url_initialized == 0) {
		text_re = pcre_compile (text_url, PCRE_CASELESS, NULL, 0, NULL);
		if (text_re == NULL) {
			msg_info ("url_init: cannot init url parsing regexp");
			return -1;
		}
		text_re_extra = pcre_study (text_re, 0, NULL);
		html_re = pcre_compile (html_url, PCRE_CASELESS, NULL, 0, NULL);
		if (html_re == NULL) {
			msg_info ("url_init: cannot init url parsing regexp");
			return -1;
		}
		html_re_extra = pcre_study (html_re, 0, NULL);
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

	/* Now we make something to support our "IP version in protocol scheme
	 * name" hack and silently chop off the last digit if it's there. The
	 * IETF's not gonna notice I hope or it'd be going after us hard. */
	if (end != url && isdigit(end[-1]))
		end--;

	/* Also return 0 if there's no protocol name (@end == @url). */
	return (*end == ':' || isdigit(*end)) ? end - url : 0;
}

static enum uri_errno
parse_uri(struct uri *uri, unsigned char *uristring)
{
	unsigned char *prefix_end, *host_end;
	unsigned char *lbracket, *rbracket;
	int datalen, n, addrlen;
	unsigned char *frag_or_post, *user_end, *port_end;

	memset (uri, 0, sizeof (*uri));

	/* Nothing to do for an empty url. */
	if (!*uristring) return URI_ERRNO_EMPTY;

	uri->string = uristring;
	uri->protocollen = get_protocol_length (uristring);

	/* Invalid */
	if (!uri->protocollen) return URI_ERRNO_INVALID_PROTOCOL;

	/* Figure out whether the protocol is known */
	uri->protocol = get_protocol (struri(uri), uri->protocollen);

	prefix_end = uristring + uri->protocollen; /* ':' */

	/* Check if there's a digit after the protocol name. */
	if (isdigit (*prefix_end)) {
		uri->ip_family = uristring[uri->protocollen] - '0';
		prefix_end++;
	}
	if (*prefix_end != ':')
		return URI_ERRNO_INVALID_PROTOCOL;
	prefix_end++;

	/* Skip slashes */

	if (prefix_end[0] == '/' && prefix_end[1] == '/') {
		if (prefix_end[2] == '/')
			return URI_ERRNO_TOO_MANY_SLASHES;

		prefix_end += 2;

	} else {
		return URI_ERRNO_NO_SLASHES;
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

	} else if (get_protocol_need_slash_after_host (uri->protocol)) {
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

	return URI_ERRNO_OK;
}

static unsigned char *
normalize_uri(struct uri *uri, unsigned char *uristring)
{
	unsigned char *parse_string = uristring;
	unsigned char *src, *dest, *path;
	int need_slash = 0;
	int parse = (uri == NULL);
	struct uri uri_struct;

	if (!uri) uri = &uri_struct;

	/* 
	 * We need to get the real (proxied) URI but lowercase relevant URI
	 * parts along the way. 
	 */
	if (parse && parse_uri (uri, parse_string) != URI_ERRNO_OK)
		return uristring;


	/* This is a maybe not the right place but both join_urls() and
	 * get_translated_uri() through translate_url() calls this
	 * function and then it already works on and modifies an
	 * allocated copy. */
	convert_to_lowercase (uri->string, uri->protocollen);
	if (uri->hostlen) convert_to_lowercase (uri->host, uri->hostlen);

	parse = 1;
	parse_string = uri->data;

	if (get_protocol_free_syntax (uri->protocol))
		return uristring;

	if (uri->protocol != PROTOCOL_UNKNOWN)
		need_slash = get_protocol_need_slash_after_host (uri->protocol);

	/* We want to start at the first slash to also reduce URIs like
	 * http://host//index.html to http://host/index.html */
	path = uri->data - need_slash;
	dest = src = path;

	/* This loop mangles the URI string by removing directory elevators and
	 * other cruft. Example: /.././etc////..//usr/ -> /usr/ */
	while (*dest) {
		/* If the following pieces are the LAST parts of URL, we remove
		 * them as well. See RFC 1808 for details. */

		if (end_of_dir (src[0])) {
			/* URL data contains no more path. */
			memmove (dest, src, strlen(src) + 1);
			break;
		}

		if (!is_uri_dir_sep (uri, src[0])) {
			/* This is to reduce indentation */

		} else if (src[1] == '.') {
			if (!src[2]) {
				/* /. - skip the dot */
				*dest++ = *src;
				*dest = 0;
				break;

			} else if (is_uri_dir_sep (uri, src[2])) {
				/* /./ - strip that.. */
				src += 2;
				continue;

			} else if (src[2] == '.'
				   && (is_uri_dir_sep (uri, src[3]) || !src[3])) {
				/* /../ or /.. - skip it and preceding element. */

				/* First back out the last incrementation of
				 * @dest (dest++) to get the position that was
				 * last asigned to. */
				if (dest > path) dest--;

				/* @dest might be pointing to a dir separator
				 * so we decrement before any testing. */
				while (dest > path) {
					dest--;
					if (is_uri_dir_sep (uri, *dest)) break;
				}

				if (!src[3]) {
					/* /.. - add ending slash and stop */
					*dest++ = *src;
					*dest = 0;
					break;
				}

				src += 3;
				continue;
			}

		} else if (is_uri_dir_sep (uri, src[1])) {
			/* // - ignore first '/'. */
			src += 1;
			continue;
		}

		/* We don't want to access memory past the NUL char. */
		*dest = *src++;
		if (*dest) dest++;
	}

	return uristring;
}


void 
url_parse_text (struct worker_task *task, GByteArray *content)
{
	if (url_init () == 0) {
		/* TODO: */
	}
}

void 
url_parse_html (struct worker_task *task, GByteArray *content)
{
	if (url_init () == 0) {
		/* TODO: */
	}
}
