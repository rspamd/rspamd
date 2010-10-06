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
	guint ipv6;	/* URI contains IPv6 host */
	guint form;	/* URI originated from form */
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
	URI_ERRNO_INVALID_PORT_RANGE,	/* Port number is not within 0-65535 */
};

enum protocol {
	PROTOCOL_FILE,
	PROTOCOL_FTP,
	PROTOCOL_HTTP,
	PROTOCOL_HTTPS,

	PROTOCOL_UNKNOWN,
};

#define struri(uri) ((uri)->string)

void url_parse_text (memory_pool_t *pool, struct worker_task *task, struct mime_text_part *part, gboolean is_html);
enum uri_errno parse_uri(struct uri *uri, gchar *uristring, memory_pool_t *pool);

#endif
