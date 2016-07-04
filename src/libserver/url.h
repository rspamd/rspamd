/* URL check functions */
#ifndef URL_H
#define URL_H

#include "config.h"
#include "mem_pool.h"
#include "fstring.h"

struct rspamd_task;
struct rspamd_mime_text_part;

enum rspamd_url_flags {
	RSPAMD_URL_FLAG_PHISHED = 1 << 0,
	RSPAMD_URL_FLAG_NUMERIC = 1 << 1,
	RSPAMD_URL_FLAG_OBSCURED = 1 << 2,
	RSPAMD_URL_FLAG_REDIRECTED = 1 << 3,
};

struct rspamd_url {
	gchar *string;
	gint protocol;
	guint port;

	gchar *user;
	gchar *host;
	gchar *data;
	gchar *query;
	gchar *fragment;
	gchar *surbl;
	gchar *tld;

	struct rspamd_url *phished_url;

	guint protocollen;
	guint userlen;
	guint hostlen;
	guint datalen;
	guint querylen;
	guint fragmentlen;
	guint surbllen;
	guint tldlen;
	guint urllen;

	enum rspamd_url_flags flags;
};

enum uri_errno {
	URI_ERRNO_OK = 0,           /* Parsing went well */
	URI_ERRNO_EMPTY,        /* The URI string was empty */
	URI_ERRNO_INVALID_PROTOCOL, /* No protocol was found */
	URI_ERRNO_INVALID_PORT,     /* Port number is bad */
	URI_ERRNO_BAD_ENCODING, /* Bad characters encoding */
	URI_ERRNO_BAD_FORMAT,
	URI_ERRNO_TLD_MISSING,
	URI_ERRNO_HOST_MISSING
};

enum rspamd_url_protocol {
	PROTOCOL_FILE = 0,
	PROTOCOL_FTP,
	PROTOCOL_HTTP,
	PROTOCOL_HTTPS,
	PROTOCOL_MAILTO,
	PROTOCOL_UNKNOWN
};

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
	struct rspamd_mime_text_part *part,
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
	gchar **url_str,
	gboolean is_html);
/*
 * Return text representation of url parsing error
 */
const gchar * rspamd_url_strerror (enum uri_errno err);


/**
 * Find TLD for a specified host string
 * @param in input host
 * @param inlen length of input
 * @param out output rspamd_ftok_t with tld position
 * @return TRUE if tld has been found
 */
gboolean rspamd_url_find_tld (const gchar *in, gsize inlen, rspamd_ftok_t *out);

typedef void (*url_insert_function) (struct rspamd_url *url,
		gsize start_offset, gsize end_offset, void *ud);

/**
 * Search for multiple urls in text and call `func` for each url found
 * @param pool
 * @param in
 * @param inlen
 * @param is_html
 * @param func
 * @param ud
 */
void rspamd_url_find_multiple (rspamd_mempool_t *pool, const gchar *in,
		gsize inlen, gboolean is_html, GPtrArray *nlines,
		url_insert_function func, gpointer ud);
/**
 * Search for a single url in text and call `func` for each url found
 * @param pool
 * @param in
 * @param inlen
 * @param is_html
 * @param func
 * @param ud
 */
void rspamd_url_find_single (rspamd_mempool_t *pool, const gchar *in,
		gsize inlen, gboolean is_html,
		url_insert_function func, gpointer ud);

/**
 * Generic callback to insert URLs into rspamd_task
 * @param url
 * @param start_offset
 * @param end_offset
 * @param ud
 */
void rspamd_url_task_callback (struct rspamd_url *url, gsize start_offset,
		gsize end_offset, gpointer ud);

#endif
