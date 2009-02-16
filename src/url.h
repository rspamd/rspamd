/* URL check functions */
#ifndef URL_H
#define URL_H

#include "config.h"
#include "mem_pool.h"

struct worker_task;

struct uri {
	/* The start of the uri (and thus start of the protocol string). */
	unsigned char *string;

	/* The internal type of protocol. Can _never_ be PROTOCOL_UNKNOWN. */
	int protocol; /* enum protocol */

	int ip_family;

	unsigned char *user;
	unsigned char *password;
	unsigned char *host;
	unsigned char *port;
	/* @data can contain both the path and query uri fields.
	 * It can never be NULL but can have zero length. */
	unsigned char *data;
	unsigned char *fragment;
	/* @post can contain some special encoded form data, used internally
	 * to make form data handling more efficient. The data is marked by
	 * POST_CHAR in the uri string. */
	unsigned char *post;

	/* @protocollen should only be usable if @protocol is either
	 * PROTOCOL_USER or an uri string should be composed. */
	unsigned int protocollen;
	unsigned int userlen;
	unsigned int passwordlen;
	unsigned int hostlen;
	unsigned int portlen;
	unsigned int datalen;
	unsigned int fragmentlen;

	/* Flags */
	unsigned int ipv6;	/* URI contains IPv6 host */
	unsigned int form;	/* URI originated from form */
	
	/* Link */
	TAILQ_ENTRY(uri) next;
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

void url_parse_html (struct worker_task *task, GByteArray *part);
void url_parse_text (struct worker_task *task, GByteArray *part);
enum uri_errno parse_uri(struct uri *uri, unsigned char *uristring, memory_pool_t *pool);

#endif
