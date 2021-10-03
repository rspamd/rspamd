/**
 * @file message.h
 * Message processing functions and structures
 */

#ifndef RSPAMD_MESSAGE_H
#define RSPAMD_MESSAGE_H

#include "config.h"

#include "libmime/email_addr.h"
#include "libutil/addr.h"
#include "libcryptobox/cryptobox.h"
#include "libmime/mime_headers.h"
#include "libmime/content_type.h"
#include "libserver/url.h"
#include "libutil/ref.h"
#include "libutil/str_util.h"

#include <unicode/uchar.h>
#include <unicode/utext.h>

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_task;
struct controller_session;
struct rspamd_image;
struct rspamd_archive;

enum rspamd_mime_part_flags {
	RSPAMD_MIME_PART_ATTACHEMENT = (1u << 1u),
	RSPAMD_MIME_PART_BAD_CTE = (1u << 4u),
	RSPAMD_MIME_PART_MISSING_CTE = (1u << 5u),
	RSPAMD_MIME_PART_NO_TEXT_EXTRACTION = (1u << 6u),
};

enum rspamd_mime_part_type {
	RSPAMD_MIME_PART_UNDEFINED = 0,
	RSPAMD_MIME_PART_MULTIPART,
	RSPAMD_MIME_PART_MESSAGE,
	RSPAMD_MIME_PART_TEXT,
	RSPAMD_MIME_PART_ARCHIVE,
	RSPAMD_MIME_PART_IMAGE,
	RSPAMD_MIME_PART_CUSTOM_LUA
};

#define IS_PART_MULTIPART(part) ((part) && ((part)->part_type == RSPAMD_MIME_PART_MULTIPART))
#define IS_PART_TEXT(part) ((part) && ((part)->part_type == RSPAMD_MIME_PART_TEXT))
#define IS_PART_MESSAGE(part) ((part) &&((part)->part_type == RSPAMD_MIME_PART_MESSAGE))

enum rspamd_cte {
	RSPAMD_CTE_UNKNOWN = 0,
	RSPAMD_CTE_7BIT = 1,
	RSPAMD_CTE_8BIT = 2,
	RSPAMD_CTE_QP = 3,
	RSPAMD_CTE_B64 = 4,
	RSPAMD_CTE_UUE = 5,
};

struct rspamd_mime_text_part;

struct rspamd_mime_multipart {
	GPtrArray *children;
	rspamd_ftok_t boundary;
};

enum rspamd_lua_specific_type {
	RSPAMD_LUA_PART_TEXT,
	RSPAMD_LUA_PART_STRING,
	RSPAMD_LUA_PART_TABLE,
	RSPAMD_LUA_PART_FUNCTION,
	RSPAMD_LUA_PART_UNKNOWN,
};

struct rspamd_lua_specific_part {
	gint cbref;
	enum rspamd_lua_specific_type type;
};

struct rspamd_mime_part {
	struct rspamd_content_type *ct;
	struct rspamd_content_type *detected_ct;
	gchar *detected_type;
	gchar *detected_ext;
	struct rspamd_content_disposition *cd;
	rspamd_ftok_t raw_data;
	rspamd_ftok_t parsed_data;
	struct rspamd_mime_part *parent_part;

	struct rspamd_mime_header *headers_order;
	struct rspamd_mime_headers_table *raw_headers;
	GPtrArray *urls;

	gchar *raw_headers_str;
	gsize raw_headers_len;

	enum rspamd_cte cte;
	guint flags;
	enum rspamd_mime_part_type part_type;
	guint part_number;

	union {
		struct rspamd_mime_multipart *mp;
		struct rspamd_mime_text_part *txt;
		struct rspamd_image *img;
		struct rspamd_archive *arch;
		struct rspamd_lua_specific_part lua_specific;
	} specific;

	guchar digest[rspamd_cryptobox_HASHBYTES];
};

#define RSPAMD_MIME_TEXT_PART_FLAG_UTF (1 << 0)
#define RSPAMD_MIME_TEXT_PART_FLAG_EMPTY (1 << 1)
#define RSPAMD_MIME_TEXT_PART_FLAG_HTML (1 << 2)
#define RSPAMD_MIME_TEXT_PART_FLAG_8BIT_RAW (1 << 3)
#define RSPAMD_MIME_TEXT_PART_FLAG_8BIT_ENCODED (1 << 4)
#define RSPAMD_MIME_TEXT_PART_ATTACHMENT (1 << 5)

#define IS_TEXT_PART_EMPTY(part) ((part)->flags & RSPAMD_MIME_TEXT_PART_FLAG_EMPTY)
#define IS_TEXT_PART_UTF(part) ((part)->flags & RSPAMD_MIME_TEXT_PART_FLAG_UTF)
#define IS_TEXT_PART_HTML(part) ((part)->flags & RSPAMD_MIME_TEXT_PART_FLAG_HTML)
#define IS_TEXT_PART_ATTACHMENT(part) ((part)->flags & RSPAMD_MIME_TEXT_PART_ATTACHMENT)


struct rspamd_mime_text_part {
	const gchar *language;
	GPtrArray *languages;
	const gchar *real_charset;

	/* Raw data in native encoding */
	rspamd_ftok_t raw;
	rspamd_ftok_t parsed; /* decoded from mime encodings */

	/* UTF8 content */
	rspamd_ftok_t utf_content; /* utf8 encoded processed content */
	GByteArray *utf_raw_content; /* utf raw content */
	GByteArray *utf_stripped_content; /* utf content with no newlines */
	GArray *normalized_hashes; /* Array of guint64 */
	GArray *utf_words; /* Array of rspamd_stat_token_t */
	UText utf_stripped_text; /* Used by libicu to represent the utf8 content */

	GPtrArray *newlines;    /**< positions of newlines in text, relative to content*/
	void *html;
	GList *exceptions;    /**< list of offsets of urls						*/
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

struct rspamd_message_raw_headers_content {
	const gchar *begin;
	gsize len;
	const gchar *body_start;
};

struct rspamd_message {
	const gchar *message_id;
	gchar *subject;

	GPtrArray *parts;				/**< list of parsed parts							*/
	GPtrArray *text_parts;			/**< list of text parts								*/
	struct rspamd_message_raw_headers_content raw_headers_content;
	void *received_headers;			/**< list of received headers						*/
	khash_t (rspamd_url_hash) *urls;
	struct rspamd_mime_headers_table *raw_headers;	/**< list of raw headers						*/
	struct rspamd_mime_header *headers_order;	/**< order of raw headers							*/
	struct rspamd_task *task;
	GPtrArray *rcpt_mime;
	GPtrArray *from_mime;
	guchar digest[16];
	enum rspamd_newlines_type nlines_type; 		/**< type of newlines (detected on most of headers 	*/
	ref_entry_t ref;
};

#define MESSAGE_FIELD(task, field) ((task)->message->field)
#define MESSAGE_FIELD_CHECK(task, field) ((task)->message ? \
	(task)->message->field : \
	(__typeof__((task)->message->field))NULL)

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
const gchar *rspamd_cte_to_string (enum rspamd_cte ct);

struct rspamd_message* rspamd_message_new (struct rspamd_task *task);

struct rspamd_message *rspamd_message_ref (struct rspamd_message *msg);

void rspamd_message_unref (struct rspamd_message *msg);

/**
 * Updates digest of the message if modified
 * @param msg
 * @param input
 * @param len
 */
void rspamd_message_update_digest (struct rspamd_message *msg,
		const void *input, gsize len);

#ifdef  __cplusplus
}
#endif

#endif
