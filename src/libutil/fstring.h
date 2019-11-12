/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef FSTRING_H
#define FSTRING_H

#include "config.h"
#include "mem_pool.h"
#include <unicode/uchar.h>

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Fixed strings library
 * These strings are NOT null-terminated for speed
 */

typedef struct f_str_s {
	gsize len;
	gsize allocated;
	gchar str[];
} rspamd_fstring_t;

#define RSPAMD_FSTRING_DATA(s) ((s)->str)
#define RSPAMD_FSTRING_LEN(s) ((s)->len)
#define RSPAMD_FSTRING_LIT(lit) rspamd_fstring_new_init((lit), sizeof(lit) - 1)

typedef struct f_str_tok {
	gsize len;
	const gchar *begin;
} rspamd_ftok_t;

typedef struct f_str_unicode_tok {
	gsize len; /* in UChar32 */
	const UChar32 *begin;
} rspamd_ftok_unicode_t;

/**
 * Create new fixed length string
 */
rspamd_fstring_t *rspamd_fstring_new (void)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Create new fixed length string with preallocated size
 */
rspamd_fstring_t *rspamd_fstring_sized_new (gsize initial_size)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Create new fixed length string and initialize it with the initial data
 */
rspamd_fstring_t *rspamd_fstring_new_init (const gchar *init, gsize len)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Assign new value to fixed string
 */
rspamd_fstring_t *rspamd_fstring_assign (rspamd_fstring_t *str,
										 const gchar *init, gsize len) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Free fixed length string
 */
void rspamd_fstring_free (rspamd_fstring_t *str);

/**
 * Append data to a fixed length string
 */
rspamd_fstring_t *rspamd_fstring_append (rspamd_fstring_t *str,
										 const char *in, gsize len) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Append `len` repeated chars `c` to string `str`
 */
rspamd_fstring_t *rspamd_fstring_append_chars (rspamd_fstring_t *str,
											   char c, gsize len) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Erase `len` characters at position `pos`
 */
void rspamd_fstring_erase (rspamd_fstring_t *str, gsize pos, gsize len);

#define rspamd_fstring_clear(s) rspamd_fstring_erase(s, 0, s->len)

/**
 * Convert fixed string to a zero terminated string. This string must be
 * freed by a caller
 */
char *rspamd_fstring_cstr (const rspamd_fstring_t *str)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Convert fixed string usign ftok_t to a zero terminated string. This string must be
 * freed by a caller
 */
char *rspamd_ftok_cstr (const rspamd_ftok_t *str)
G_GNUC_WARN_UNUSED_RESULT;

/*
 * Return fast hash value for fixed string converted to lowercase
 */
guint32 rspamd_fstrhash_lc (const rspamd_ftok_t *str, gboolean is_utf);

/**
 * Return true if two strings are equal
 */
gboolean rspamd_fstring_equal (const rspamd_fstring_t *s1,
							   const rspamd_fstring_t *s2);

/**
 * Compare two fixed strings ignoring case
 */
gint rspamd_fstring_casecmp (const rspamd_fstring_t *s1,
							 const rspamd_fstring_t *s2);

/**
 * Compare two fixed strings
 */
gint rspamd_fstring_cmp (const rspamd_fstring_t *s1,
						 const rspamd_fstring_t *s2);

/**
 * Compare two fixed tokens ignoring case
 */
gint rspamd_ftok_casecmp (const rspamd_ftok_t *s1,
						  const rspamd_ftok_t *s2);

/**
 * Compare two fixed tokens
 */
gint rspamd_ftok_cmp (const rspamd_ftok_t *s1,
					  const rspamd_ftok_t *s2);

/**
 * Returns true if `s1` starts with `s2`
 * @param s1
 * @param s2
 * @return
 */
gboolean rspamd_ftok_starts_with (const rspamd_ftok_t *s1,
								  const rspamd_ftok_t *s2);

/**
 * Return TRUE if ftok is equal to specified C string
 */
gboolean rspamd_ftok_cstr_equal (const rspamd_ftok_t *s,
								 const gchar *pat, gboolean icase);

/**
 * Free fstring_t that is mapped to ftok_t
 *
 * | len | allocated | <data> -- fstring_t
 *                     <begin> -- tok
 *
 * tok is expected to be allocated with g_malloc
 */
void rspamd_fstring_mapped_ftok_free (gpointer p);

/**
 * Map token to a specified string. Token must be freed using g_free
 */
rspamd_ftok_t *rspamd_ftok_map (const rspamd_fstring_t *s);

/**
 * Suggest suitable size to grow fstring
 * @param len
 * @param allocated
 * @param needed_len
 * @return
 */
gsize rspamd_fstring_suggest_size (gsize len, gsize allocated, gsize needed_len);

/**
 * Grow the specified fixed string
 * @param str
 * @param needed_len
 * @return
 */
rspamd_fstring_t *rspamd_fstring_grow (rspamd_fstring_t *str,
									   gsize needed_len) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Copies ftok to zero terminated string (must be freed using g_free)
 * @param src
 * @return
 */
gchar *rspamd_ftokdup (const rspamd_ftok_t *src) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Copies fstring to zero terminated string (must be freed using g_free)
 * @param src
 * @return
 */
gchar *rspamd_fstringdup (const rspamd_fstring_t *src) G_GNUC_WARN_UNUSED_RESULT;

#define RSPAMD_FTOK_ASSIGN(t, lit) do { (t)->begin = (lit); (t)->len = sizeof(lit) - 1; } while (0)
#define RSPAMD_FTOK_FROM_STR(t, str) do { \
    if (G_LIKELY(str)) { \
        (t)->begin = (const char*)(str); \
        (t)->len = strlen (str); \
    } \
    else { \
        (t)->begin = NULL; \
        (t)->len = 0; \
    } \
} while (0)

#ifdef  __cplusplus
}
#endif
#endif
