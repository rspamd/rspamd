/* URL check functions */
#ifndef URL_H
#define URL_H

#include "config.h"
#include "mem_pool.h"
#include "fstring.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_task;
struct rspamd_mime_text_part;

enum rspamd_url_flags {
	RSPAMD_URL_FLAG_PHISHED = 1u << 0u,
	RSPAMD_URL_FLAG_NUMERIC = 1u << 1u,
	RSPAMD_URL_FLAG_OBSCURED = 1u << 2u,
	RSPAMD_URL_FLAG_REDIRECTED = 1u << 3u,
	RSPAMD_URL_FLAG_HTML_DISPLAYED = 1u << 4u,
	RSPAMD_URL_FLAG_FROM_TEXT = 1u << 5u,
	RSPAMD_URL_FLAG_SUBJECT = 1u << 6u,
	RSPAMD_URL_FLAG_HOSTENCODED = 1u << 7u,
	RSPAMD_URL_FLAG_SCHEMAENCODED = 1u << 8u,
	RSPAMD_URL_FLAG_PATHENCODED = 1u << 9u,
	RSPAMD_URL_FLAG_QUERYENCODED = 1u << 10u,
	RSPAMD_URL_FLAG_MISSINGSLASHES = 1u << 11u,
	RSPAMD_URL_FLAG_IDN = 1u << 12u,
	RSPAMD_URL_FLAG_HAS_PORT = 1u << 13u,
	RSPAMD_URL_FLAG_HAS_USER = 1u << 14u,
	RSPAMD_URL_FLAG_SCHEMALESS = 1u << 15u,
	RSPAMD_URL_FLAG_UNNORMALISED = 1u << 16u,
	RSPAMD_URL_FLAG_ZW_SPACES = 1u << 17u,
	RSPAMD_URL_FLAG_DISPLAY_URL = 1u << 18u,
	RSPAMD_URL_FLAG_IMAGE = 1u << 19u,
};

struct rspamd_url_tag {
	const gchar *data;
	struct rspamd_url_tag *prev, *next;
};

struct rspamd_url {
	gchar *raw;
	gchar *string;
	guint protocol;
	guint port;

	gchar *user;
	gchar *host;
	gchar *data;
	gchar *query;
	gchar *fragment;
	gchar *tld;
	gchar *visible_part;

	struct rspamd_url *phished_url;

	guint protocollen;
	guint userlen;
	guint hostlen;
	guint datalen;
	guint querylen;
	guint fragmentlen;
	guint tldlen;
	guint urllen;
	guint rawlen;

	enum rspamd_url_flags flags;
	guint count;
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
	PROTOCOL_FILE = 1u << 0u,
	PROTOCOL_FTP = 1u << 1u,
	PROTOCOL_HTTP = 1u << 2u,
	PROTOCOL_HTTPS = 1u << 3u,
	PROTOCOL_MAILTO = 1u << 4u,
	PROTOCOL_TELEPHONE = 1u << 5u,
	PROTOCOL_UNKNOWN = 1u << 31u,
};

enum rspamd_url_parse_flags {
	RSPAMD_URL_PARSE_TEXT = 0u,
	RSPAMD_URL_PARSE_HREF = (1u << 0u),
	RSPAMD_URL_PARSE_CHECK = (1u << 1u),
};

enum rspamd_url_find_type {
	RSPAMD_URL_FIND_ALL = 0,
	RSPAMD_URL_FIND_STRICT,
};

/**
 * Initialize url library
 * @param cfg
 */
void rspamd_url_init (const gchar *tld_file);

void rspamd_url_deinit (void);

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
							  enum rspamd_url_find_type how);

/*
 * Parse a single url into an uri structure
 * @param pool memory pool
 * @param uristring text form of url
 * @param uri url object, must be pre allocated
 */
enum uri_errno rspamd_url_parse (struct rspamd_url *uri,
								 gchar *uristring,
								 gsize len,
								 rspamd_mempool_t *pool,
								 enum rspamd_url_parse_flags flags);

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
						  const gchar *begin, gsize len,
						  gchar **url_str,
						  enum rspamd_url_find_type how,
						  goffset *url_pos,
						  gboolean *prefix_added);

/*
 * Return text representation of url parsing error
 */
const gchar *rspamd_url_strerror (int err);


/**
 * Find TLD for a specified host string
 * @param in input host
 * @param inlen length of input
 * @param out output rspamd_ftok_t with tld position
 * @return TRUE if tld has been found
 */
gboolean rspamd_url_find_tld (const gchar *in, gsize inlen, rspamd_ftok_t *out);

typedef gboolean (*url_insert_function) (struct rspamd_url *url,
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
void rspamd_url_find_multiple (rspamd_mempool_t *pool,
							   const gchar *in, gsize inlen,
							   enum rspamd_url_find_type how,
							   GPtrArray *nlines,
							   url_insert_function func,
							   gpointer ud);

/**
 * Search for a single url in text and call `func` for each url found
 * @param pool
 * @param in
 * @param inlen
 * @param is_html
 * @param func
 * @param ud
 */
void rspamd_url_find_single (rspamd_mempool_t *pool,
							 const gchar *in, gsize inlen,
							 enum rspamd_url_find_type how,
							 url_insert_function func,
							 gpointer ud);

/**
 * Generic callback to insert URLs into rspamd_task
 * @param url
 * @param start_offset
 * @param end_offset
 * @param ud
 */
gboolean rspamd_url_task_subject_callback (struct rspamd_url *url,
									   gsize start_offset,
									   gsize end_offset, gpointer ud);

guint rspamd_url_hash (gconstpointer u);

guint rspamd_email_hash (gconstpointer u);

guint rspamd_url_host_hash (gconstpointer u);


/* Compare two emails for building emails hash */
gboolean rspamd_emails_cmp (gconstpointer a, gconstpointer b);

/* Compare two urls for building emails hash */
gboolean rspamd_urls_cmp (gconstpointer a, gconstpointer b);

gboolean rspamd_urls_host_cmp (gconstpointer a, gconstpointer b);

/**
 * Decode URL encoded string in-place and return new length of a string, src and dst are NULL terminated
 * @param dst
 * @param src
 * @param size
 * @return
 */
gsize rspamd_url_decode (gchar *dst, const gchar *src, gsize size);

/**
 * Encode url if needed. In this case, memory is allocated from the specific pool.
 * Returns pointer to begin and encoded length in `dlen`
 * @param url
 * @param pool
 * @return
 */
const gchar *rspamd_url_encode (struct rspamd_url *url, gsize *dlen,
								rspamd_mempool_t *pool);


/**
 * Returns if a character is domain character
 * @param c
 * @return
 */
gboolean rspamd_url_is_domain (int c);

/**
 * Returns symbolic name for protocol
 * @param proto
 * @return
 */
const gchar *rspamd_url_protocol_name (enum rspamd_url_protocol proto);


/**
 * Converts string to a numeric protocol
 * @param str
 * @return
 */
enum rspamd_url_protocol rspamd_url_protocol_from_string (const gchar *str);

#ifdef  __cplusplus
}
#endif

#endif
