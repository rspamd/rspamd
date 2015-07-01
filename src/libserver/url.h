/* URL check functions */
#ifndef URL_H
#define URL_H

#include "config.h"
#include "mem_pool.h"

struct rspamd_task;
struct mime_text_part;

struct rspamd_url {
	gchar *string;
	gint protocol;
	guint port;

	gchar *user;
	gchar *password;
	gchar *host;
	gchar *data;
	gchar *query;
	gchar *fragment;
	gchar *surbl;
	gchar *tld;

	struct rspamd_url *phished_url;

	guint protocollen;
	guint userlen;
	guint passwordlen;
	guint hostlen;
	guint datalen;
	guint querylen;
	guint fragmentlen;
	guint surbllen;
	guint tldlen;
	guint urllen;

	gboolean is_phished; /* URI maybe phishing */
};

enum uri_errno {
	URI_ERRNO_OK = 0,           /* Parsing went well */
	URI_ERRNO_EMPTY,        /* The URI string was empty */
	URI_ERRNO_INVALID_PROTOCOL, /* No protocol was found */
	URI_ERRNO_INVALID_PORT,     /* Port number is bad */
	URI_ERRNO_BAD_ENCODING, /* Bad characters encoding */
	URI_ERRNO_BAD_FORMAT
};

enum rspamd_url_protocol {
	PROTOCOL_FILE = 0,
	PROTOCOL_FTP,
	PROTOCOL_HTTP,
	PROTOCOL_HTTPS,
	PROTOCOL_MAILTO,
	PROTOCOL_UNKNOWN
};

#define struri(uri) ((uri)->string)

/**
 * Initialize url library
 * @param cfg
 */
void rspamd_url_init (const gchar *tld_file);

/*
 * Parse urls inside text
 * @param pool memory pool
 * @param task task object
 * @param part current text part
 * @param is_html turn on html euristic
 */
void rspamd_url_text_extract (rspamd_mempool_t *pool,
	struct rspamd_task *task,
	struct mime_text_part *part,
	gboolean is_html);

/*
 * Parse a single url into an uri structure
 * @param pool memory pool
 * @param uristring text form of url
 * @param uri url object, must be pre allocated
 */
enum uri_errno rspamd_url_parse (struct rspamd_url *uri,
	gchar *uristring,
	gsize len,
	rspamd_mempool_t *pool);

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
gboolean rspamd_url_find (rspamd_mempool_t *pool,
	const gchar *begin,
	gsize len,
	const gchar **start,
	const gchar **end,
	gchar **url_str,
	gboolean is_html,
	gint *statep);
/*
 * Return text representation of url parsing error
 */
const gchar * rspamd_url_strerror (enum uri_errno err);

/**
 * Convenience routine to extract urls from an arbitrarty text
 * @param pool
 * @param start
 * @param pos
 * @return url or NULL
 */
struct rspamd_url *
rspamd_url_get_next (rspamd_mempool_t *pool,
		const gchar *start, gchar const **pos, gint *statep);

#endif
