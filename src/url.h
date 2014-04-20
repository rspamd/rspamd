/* URL check functions */
#ifndef URL_H
#define URL_H

#include "config.h"
#include "mem_pool.h"

struct worker_task;
struct mime_text_part;

struct uri {
	/* The start of the uri (and thus start of the protocol string). */
	gchar *string;

	/* The internal type of protocol. Can _never_ be PROTOCOL_UNKNOWN. */
	gint protocol; /* enum protocol */

	gint ip_family;

	gchar *user;
	gchar *password;
	gchar *host;
	gchar *port;
	/* @data can contain both the path and query uri fields.
	 * It can never be NULL but can have zero length. */
	gchar *data;
	gchar *fragment;
	/* @post can contain some special encoded form data, used internally
	 * to make form data handling more efficient. The data is marked by
	 * POST_CHAR in the uri string. */
	gchar *post;

	struct uri *phished_url;

	/* @protocollen should only be usable if @protocol is either
	 * PROTOCOL_USER or an uri string should be composed. */
	guint protocollen;
	guint userlen;
	guint passwordlen;
	guint hostlen;
	guint portlen;
	guint datalen;
	guint fragmentlen;

	/* Flags */
	gboolean ipv6;	/* URI contains IPv6 host */
	gboolean form;	/* URI originated from form */
	gboolean is_phished; /* URI maybe phishing */
};

enum uri_errno {
	URI_ERRNO_OK,			/* Parsing went well */
	URI_ERRNO_EMPTY,		/* The URI string was empty */
	URI_ERRNO_INVALID_PROTOCOL,	/* No protocol was found */
	URI_ERRNO_NO_SLASHES,		/* Slashes after protocol missing */
	URI_ERRNO_TOO_MANY_SLASHES,	/* Too many slashes after protocol */
	URI_ERRNO_TRAILING_DOTS,	/* '.' after host */
	URI_ERRNO_NO_HOST,		/* Host part is missing */
	URI_ERRNO_NO_PORT_COLON,	/* ':' after host without port */
	URI_ERRNO_NO_HOST_SLASH,	/* Slash after host missing */
	URI_ERRNO_IPV6_SECURITY,	/* IPv6 security bug detected */
	URI_ERRNO_INVALID_PORT,		/* Port number is bad */
	URI_ERRNO_INVALID_PORT_RANGE	/* Port number is not within 0-65535 */
};

enum protocol {
	PROTOCOL_FILE,
	PROTOCOL_FTP,
	PROTOCOL_HTTP,
	PROTOCOL_HTTPS,
	PROTOCOL_MAILTO,
	PROTOCOL_UNKNOWN
};

#define struri(uri) ((uri)->string)

/*
 * Parse urls inside text
 * @param pool memory pool
 * @param task task object
 * @param part current text part
 * @param is_html turn on html euristic
 */
void url_parse_text (rspamd_mempool_t *pool, struct worker_task *task, struct mime_text_part *part, gboolean is_html);

/*
 * Parse a single url into an uri structure
 * @param pool memory pool
 * @param uristring text form of url
 * @param uri url object, must be pre allocated
 */
enum uri_errno parse_uri(struct uri *uri, gchar *uristring, rspamd_mempool_t *pool);

/*
 * Try to extract url from a text
 * @param pool memory pool
 * @param begin begin of text
 * @param len length of text
 * @param start storage for start position of url found (or NULL)
 * @param end storage for end position of url found (or NULL)
 * @param url_str storage for url string(or NULL)
 * @return TRUE if url is found in specified text
 */
gboolean url_try_text (rspamd_mempool_t *pool, const gchar *begin, gsize len, gchar **start, gchar **end, gchar **url_str, gboolean is_html);

/*
 * Return text representation of url parsing error
 */
const gchar* url_strerror (enum uri_errno err);

#endif
