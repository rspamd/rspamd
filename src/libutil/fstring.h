/*
 * Functions for handling with fixed size strings
 */

#ifndef FSTRING_H
#define FSTRING_H

#include "config.h"
#include "mem_pool.h"

#define update_buf_size(x) (x)->free = (x)->buf->size - \
		((x)->pos - (x)->buf->begin); (x)->buf->len = (x)->pos - (x)->buf->begin

typedef struct f_str_s {
	gchar *begin;
	size_t len;
	size_t size;
} rspamd_fstring_t;

typedef struct f_str_buf_s {
	rspamd_fstring_t *buf;
	gchar *pos;
	size_t free;
} rspamd_fstring_buf_t;

typedef struct f_tok_s {
	rspamd_fstring_t word;
	size_t pos;
} rspamd_fstring_token_t;

/*
 * Search first occurence of character in string
 */
ssize_t rspamd_fstrchr (rspamd_fstring_t *src, gchar c);

/*
 * Search last occurence of character in string
 */
ssize_t rspamd_fstrrchr (rspamd_fstring_t *src, gchar c);

/*
 * Search for pattern in orig
 */
ssize_t rspamd_fstrstr (rspamd_fstring_t *orig, rspamd_fstring_t *pattern);

/*
 * Search for pattern in orig ignoring case
 */
ssize_t rspamd_fstrstri (rspamd_fstring_t *orig, rspamd_fstring_t *pattern);

/*
 * Split string by tokens
 * word contains parsed word
 */
gint rspamd_fstrtok (rspamd_fstring_t *text, const gchar *sep, rspamd_fstring_token_t *state);

/*
 * Copy one string into other
 */
size_t rspamd_fstrcpy (rspamd_fstring_t *dest, rspamd_fstring_t *src);

/*
 * Concatenate two strings
 */
size_t rspamd_fstrcat (rspamd_fstring_t *dest, rspamd_fstring_t *src);

/*
 * Push one character to fstr
 */
gint rspamd_fstrappend_c (rspamd_fstring_t *dest, gchar c);

/*
 * Push one character to fstr
 */
gint rspamd_fstrappend_u (rspamd_fstring_t *dest, gunichar c);

/*
 * Allocate memory for f_str_t
 */
rspamd_fstring_t * rspamd_fstralloc (rspamd_mempool_t *pool, size_t len);

/*
 * Allocate memory for f_str_t from temporary pool
 */
rspamd_fstring_t * rspamd_fstralloc_tmp (rspamd_mempool_t *pool, size_t len);

/*
 * Truncate string to its len
 */
rspamd_fstring_t * rspamd_fstrtruncate (rspamd_mempool_t *pool, rspamd_fstring_t *orig);

/*
 * Enlarge string to new size
 */
rspamd_fstring_t * rspamd_fstrgrow (rspamd_mempool_t *pool, rspamd_fstring_t *orig, size_t newlen);

/*
 * Return specified character
 */
#define fstridx(str, pos) *((str)->begin + (pos))

/*
 * Return fast hash value for fixed string
 */
guint32 rspamd_fstrhash (rspamd_fstring_t *str);

/*
 * Return fast hash value for fixed string converted to lowercase
 */
guint32 rspamd_fstrhash_lc (rspamd_fstring_t *str, gboolean is_utf);
/*
 * Make copy of string to 0-terminated string
 */
gchar * rspamd_fstr_c_str (rspamd_fstring_t *str, rspamd_mempool_t *pool);

/*
 * Strip fstr string from space symbols
 */
void rspamd_fstrstrip (rspamd_fstring_t *str);

#endif
