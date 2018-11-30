/**
 * @file message.h
 * Message processing functions and structures
 */

#ifndef RSPAMD_MESSAGE_H
#define RSPAMD_MESSAGE_H

#include "config.h"
#include "email_addr.h"
#include "addr.h"
#include "cryptobox.h"
#include "mime_headers.h"
#include "content_type.h"

#include <unicode/uchar.h>
#include <unicode/utext.h>

struct rspamd_task;
struct controller_session;
struct html_content;
struct rspamd_image;
struct rspamd_archive;

enum rspamd_mime_part_flags {
	RSPAMD_MIME_PART_TEXT = (1 << 0),
	RSPAMD_MIME_PART_ATTACHEMENT = (1 << 1),
	RSPAMD_MIME_PART_IMAGE = (1 << 2),
	RSPAMD_MIME_PART_ARCHIVE = (1 << 3),
	RSPAMD_MIME_PART_BAD_CTE = (1 << 4),
	RSPAMD_MIME_PART_MISSING_CTE = (1 << 5)
};

enum rspamd_cte {
	RSPAMD_CTE_UNKNOWN = 0,
	RSPAMD_CTE_7BIT = 1,
	RSPAMD_CTE_8BIT = 2,
	RSPAMD_CTE_QP = 3,
	RSPAMD_CTE_B64 = 4,
};

struct rspamd_mime_text_part;

struct rspamd_mime_multipart {
	GPtrArray *children;
};

struct rspamd_mime_part {
	struct rspamd_content_type *ct;
	struct rspamd_content_disposition *cd;
	rspamd_ftok_t raw_data;
	rspamd_ftok_t parsed_data;
	struct rspamd_mime_part *parent_part;

	GQueue *headers_order;
	GHashTable *raw_headers;

	gchar *raw_headers_str;
	gsize raw_headers_len;

	enum rspamd_cte cte;
	enum rspamd_mime_part_flags flags;
	guint id;

	union {
		struct rspamd_mime_multipart mp;
		struct rspamd_mime_text_part *txt;
		struct rspamd_image *img;
		struct rspamd_archive *arch;
	} specific;

	guchar digest[rspamd_cryptobox_HASHBYTES];
};

#define RSPAMD_MIME_TEXT_PART_FLAG_UTF (1 << 0)
#define RSPAMD_MIME_TEXT_PART_FLAG_BALANCED (1 << 1)
#define RSPAMD_MIME_TEXT_PART_FLAG_EMPTY (1 << 2)
#define RSPAMD_MIME_TEXT_PART_FLAG_HTML (1 << 3)
#define RSPAMD_MIME_TEXT_PART_FLAG_8BIT (1 << 4)
#define RSPAMD_MIME_TEXT_PART_FLAG_8BIT_ENCODED (1 << 5)
#define RSPAMD_MIME_TEXT_PART_HAS_SUBNORMAL (1 << 6)
#define RSPAMD_MIME_TEXT_PART_NORMALISED (1 << 7)

#define IS_PART_EMPTY(part) ((part)->flags & RSPAMD_MIME_TEXT_PART_FLAG_EMPTY)
#define IS_PART_UTF(part) ((part)->flags & RSPAMD_MIME_TEXT_PART_FLAG_UTF)
#define IS_PART_RAW(part) (!((part)->flags & RSPAMD_MIME_TEXT_PART_FLAG_UTF))
#define IS_PART_HTML(part) ((part)->flags & RSPAMD_MIME_TEXT_PART_FLAG_HTML)


struct rspamd_mime_text_part {
	const gchar *language;
	GPtrArray *languages;
	const gchar *real_charset;

	/* Raw data in native encoding */
	rspamd_ftok_t raw;
	rspamd_ftok_t parsed; /* decoded from mime encodings */

	/* UTF8 content */
	GByteArray *utf_content; /* utf8 encoded processed content */
	GByteArray *utf_raw_content; /* utf raw content */
	GByteArray *utf_stripped_content; /* utf content with no newlines */
	GArray *normalized_hashes;
	GArray *utf_words;
	UText utf_stripped_text; /* Used by libicu to represent the utf8 content */

	GPtrArray *newlines;	/**< positions of newlines in text, relative to content*/
	struct html_content *html;
	GList *exceptions;	/**< list of offsets of urls						*/
	struct rspamd_mime_part *mime_part;

	guint flags;
	guint nlines;
	guint spaces;
	guint nwords;
	guint non_ascii_chars;
	guint ascii_chars;
	guint double_spaces;
	guint non_spaces;
	guint empty_lines;
	guint capital_letters;
	guint numeric_characters;
	guint unicode_scripts;
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

#define RSPAMD_RECEIVED_FLAG_ARTIFICIAL (1 << 0)
#define RSPAMD_RECEIVED_FLAG_SSL (1 << 1)
#define RSPAMD_RECEIVED_FLAG_AUTHENTICATED (1 << 2)

struct received_header {
	gchar *from_hostname;
	gchar *from_ip;
	gchar *real_hostname;
	gchar *real_ip;
	gchar *by_hostname;
	gchar *for_mbox;
	gchar *comment_ip;
	rspamd_inet_addr_t *addr;
	struct rspamd_mime_header *hdr;
	time_t timestamp;
	enum rspamd_received_type type;
	gint flags;
};

/**
 * Parse and pre-process mime message
 * @param task worker_task object
 * @return
 */
gboolean rspamd_message_parse (struct rspamd_task *task);

/**
 * Process content in task (e.g. HTML parsing)
 * @param task
 */
void rspamd_message_process (struct rspamd_task *task);

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
 * Get an array of header's values with specified header's name using raw headers
 * @param htb hash table indexed by header name (caseless) with ptr arrays as elements
 * @param field header's name
 * @param strong if this flag is TRUE header's name is case sensitive, otherwise it is not
 * @return An array of header's values or NULL. It is NOT permitted to free array or values.
 */
GPtrArray *rspamd_message_get_header_from_hash (GHashTable *htb,
		rspamd_mempool_t *pool,
		const gchar *field,
		gboolean strong);


/**
 * Converts string to cte
 * @param str
 * @return
 */
enum rspamd_cte rspamd_cte_from_string (const gchar *str);

/**
 * Converts cte to string
 * @param ct
 * @return
 */
const gchar* rspamd_cte_to_string (enum rspamd_cte ct);

#endif
