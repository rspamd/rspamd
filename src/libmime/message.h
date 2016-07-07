/**
 * @file message.h
 * Message processing functions and structures
 */

#ifndef RSPAMD_MESSAGE_H
#define RSPAMD_MESSAGE_H

#include "config.h"
#include "email_addr.h"
#include "addr.h"
#include <gmime/gmime.h>

struct rspamd_task;
struct controller_session;
struct html_content;

enum rspamd_mime_part_flags {
	RSPAMD_MIME_PART_TEXT = (1 << 0),
	RSPAMD_MIME_PART_ATTACHEMENT = (1 << 1),
	RSPAMD_MIME_PART_IMAGE = (1 << 2),
	RSPAMD_MIME_PART_ARCHIVE = (1 << 3)
};

struct rspamd_mime_part {
	GMimeContentType *type;
	GByteArray *content;
	GMimeObject *parent;
	GMimeObject *mime;
	GHashTable *raw_headers;
	gchar *raw_headers_str;
	gchar *checksum;
	const gchar *filename;
	const gchar *boundary;
	enum rspamd_mime_part_flags flags;
	gpointer specific_data;
};

#define RSPAMD_MIME_TEXT_PART_FLAG_UTF (1 << 0)
#define RSPAMD_MIME_TEXT_PART_FLAG_BALANCED (1 << 1)
#define RSPAMD_MIME_TEXT_PART_FLAG_EMPTY (1 << 2)
#define RSPAMD_MIME_TEXT_PART_FLAG_HTML (1 << 3)

#define IS_PART_EMPTY(part) ((part)->flags & RSPAMD_MIME_TEXT_PART_FLAG_EMPTY)
#define IS_PART_UTF(part) ((part)->flags & RSPAMD_MIME_TEXT_PART_FLAG_UTF)
#define IS_PART_RAW(part) (!((part)->flags & RSPAMD_MIME_TEXT_PART_FLAG_UTF))
#define IS_PART_HTML(part) ((part)->flags & RSPAMD_MIME_TEXT_PART_FLAG_HTML)

struct rspamd_mime_text_part {
	guint flags;
	GUnicodeScript script;
	const gchar *lang_code;
	const gchar *language;
	const gchar *real_charset;
	GByteArray *orig;
	GByteArray *content;
	GByteArray *stripped_content; /**< no newlines or html tags 			*/
	GPtrArray *newlines;	/**< positions of newlines in text					*/
	struct html_content *html;
	GList *urls_offset;	/**< list of offsets of urls						*/
	GMimeObject *parent;
	struct rspamd_mime_part *mime_part;
	GArray *normalized_words;
	GArray *normalized_hashes;
	guint nlines;
	guint64 hash;
};

enum rspamd_received_type {
	RSPAMD_RECEIVED_SMTP = 0,
	RSPAMD_RECEIVED_ESMTP,
	RSPAMD_RECEIVED_ESMTPA,
	RSPAMD_RECEIVED_ESMTPS,
	RSPAMD_RECEIVED_ESMTPSA,
	RSPAMD_RECEIVED_LMTP,
	RSPAMD_RECEIVED_IMAP,
	RSPAMD_RECEIVED_UNKNOWN
};

struct received_header {
	gchar *from_hostname;
	gchar *from_ip;
	gchar *real_hostname;
	gchar *real_ip;
	gchar *by_hostname;
	rspamd_inet_addr_t *addr;
	time_t timestamp;
	enum rspamd_received_type type;
};

struct raw_header {
	gchar *name;
	gchar *value;
	const gchar *raw_value; /* As it is in the message (unfolded and unparsed) */
	gsize raw_len;
	gboolean tab_separated;
	gboolean empty_separator;
	gchar *separator;
	gchar *decoded;
	struct raw_header *prev, *next;
};

/**
 * Parse and pre-process mime message
 * @param task worker_task object
 * @return
 */
gboolean rspamd_message_parse (struct rspamd_task *task);

/**
 * Get a list of header's values with specified header's name using raw headers
 * @param task worker task structure
 * @param field header's name
 * @param strong if this flag is TRUE header's name is case sensitive, otherwise it is not
 * @return A list of header's values or NULL. Unlike previous function it is NOT required to free list or values. I should rework one of these functions some time.
 */
GList * rspamd_message_get_header (struct rspamd_task *task,
	const gchar *field,
	gboolean strong);

/**
 * Get an array of header's values with specified header's name using raw headers
 * @param task worker task structure
 * @param field header's name
 * @param strong if this flag is TRUE header's name is case sensitive, otherwise it is not
 * @return An array of header's values or NULL. It is NOT permitted to free array or values.
 */
GPtrArray *rspamd_message_get_header_array (struct rspamd_task *task,
		const gchar *field,
		gboolean strong);
/**
 * Get an array of mime parts header's values with specified header's name using raw headers
 * @param task worker task structure
 * @param field header's name
 * @param strong if this flag is TRUE header's name is case sensitive, otherwise it is not
 * @return An array of header's values or NULL. It is NOT permitted to free array or values.
 */
GPtrArray *rspamd_message_get_mime_header_array (struct rspamd_task *task,
		const gchar *field,
		gboolean strong);

/**
 * Get array of all headers from the list specified
 * @param task
 * @param h1
 * @return An array of headers (should not be freed as well)
 */
GPtrArray *rspamd_message_get_headers_array (struct rspamd_task *task, ...);

/**
 * Get an array of header's values with specified header's name returning decoded strings as values
 * @param task worker task structure
 * @param field header's name
 * @param strong if this flag is TRUE header's name is case sensitive, otherwise it is not
 * @return An array of header's values or NULL. It is NOT permitted to free array or values.
 */
GPtrArray *rspamd_message_get_header_array_str (struct rspamd_task *task,
		const gchar *field,
		gboolean strong);

/**
 * Get array of all headers from the list specified returning decoded strings as values
 * @param task
 * @param h1
 * @return An array of headers (should not be freed as well)
 */
GPtrArray *rspamd_message_get_headers_array_str (struct rspamd_task *task, ...);

#endif
