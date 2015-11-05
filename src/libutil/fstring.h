/*
 * Copyright (c) 2009-2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#ifndef FSTRING_H
#define FSTRING_H

#include "config.h"
#include "mem_pool.h"

/**
 * Fixed strings library
 * These strings are NOT null-terminated for speed
 */

typedef struct f_str_s {
	gsize len;
	gsize allocated;
	gchar str[];
} rspamd_fstring_t;

typedef struct f_str_tok {
	gsize len;
	const gchar *begin;
} rspamd_ftok_t;

/**
 * Create new fixed length string
 */
rspamd_fstring_t* rspamd_fstring_new (void)
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
rspamd_fstring_t* rspamd_fstring_append (rspamd_fstring_t *str,
		const char *in, gsize len) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Append `len` repeated chars `c` to string `str`
 */
rspamd_fstring_t *rspamd_fstring_append_chars (rspamd_fstring_t *str,
		char c, gsize len) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Erase `len` characters at postion `pos`
 */
void rspamd_fstring_erase (rspamd_fstring_t *str, gsize pos, gsize len);

/**
 * Convert fixed string to a zero terminated string. This string should be
 * freed by a caller
 */
char * rspamd_fstring_cstr (const rspamd_fstring_t *str)
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
 * tok is expected to be allocated with g_slice_alloc
 */
void rspamd_fstring_mapped_ftok_free (gpointer p);

/**
 * Map token to a specified string. Token must be freed using g_slice_free1
 */
rspamd_ftok_t *rspamd_ftok_map (const rspamd_fstring_t *s);

#endif
