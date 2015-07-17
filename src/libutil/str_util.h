/*
 * Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
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


#ifndef SRC_LIBUTIL_STR_UTIL_H_
#define SRC_LIBUTIL_STR_UTIL_H_

#include "config.h"

/**
 * Convert string to lowercase in-place using ASCII conversion
 */
void rspamd_str_lc (gchar *str, guint size);
/**
 * Convert string to lowercase in-place using utf (limited) conversion
 */
void rspamd_str_lc_utf8 (gchar *str, guint size);

/*
 * Hash table utility functions for case insensitive hashing
 */
guint rspamd_strcase_hash (gconstpointer key);
gboolean rspamd_strcase_equal (gconstpointer v, gconstpointer v2);

/*
 * Hash table utility functions for case sensitive hashing
 */
guint rspamd_str_hash (gconstpointer key);
gboolean rspamd_str_equal (gconstpointer v, gconstpointer v2);


/*
 * Hash table utility functions for hashing fixed strings
 */
guint rspamd_fstring_icase_hash (gconstpointer key);
gboolean rspamd_fstring_icase_equal (gconstpointer v, gconstpointer v2);
guint rspamd_gstring_icase_hash (gconstpointer key);
gboolean rspamd_gstring_icase_equal (gconstpointer v, gconstpointer v2);

/**
 * Copy src to dest limited to len, in compare with standart strlcpy(3) rspamd strlcpy does not
 * traverse the whole string and it is possible to use it for non NULL terminated strings. This is
 * more like memccpy(dst, src, size, '\0')
 *
 * @param dst destination string
 * @param src source string
 * @param siz length of destination buffer
 * @return bytes copied
 */
gsize rspamd_strlcpy (gchar *dst, const gchar *src, gsize siz);

/**
 * Lowercase strlcpy variant
 * @param dst
 * @param src
 * @param siz
 * @return
 */
gsize rspamd_strlcpy_tolower (gchar *dst, const gchar *src, gsize siz);

/*
 * Find string find in string s ignoring case
 */
gchar * rspamd_strncasestr (const gchar *s, const gchar *find, gint len);

/*
 * Try to convert string of length to long
 */
gboolean rspamd_strtol (const gchar *s, gsize len, glong *value);

/*
 * Try to convert string of length to unsigned long
 */
gboolean rspamd_strtoul (const gchar *s, gsize len, gulong *value);

/**
 * Utility function to provide mem_pool copy for rspamd_hash_table_copy function
 * @param data string to copy
 * @param ud memory pool to use
 * @return
 */
gpointer rspamd_str_pool_copy (gconstpointer data, gpointer ud);

/**
 * Encode string using base32 encoding
 * @param in input
 * @param inlen input length
 * @return freshly allocated base32 encoding of a specified string
 */
gchar * rspamd_encode_base32 (const guchar *in, gsize inlen);

/**
 * Decode string using base32 encoding
 * @param in input
 * @param inlen input length
 * @return freshly allocated base32 decoded value or NULL if input is invalid
 */
guchar* rspamd_decode_base32 (const gchar *in, gsize inlen, gsize *outlen);

/**
 * Encode string using base64 encoding
 * @param in input
 * @param inlen input length
 * @param str_len maximum string length (if <= 0 then no lines are split)
 * @return freshly allocated base64 encoded value or NULL if input is invalid
 */
gchar * rspamd_encode_base64 (const guchar *in, gsize inlen, gint str_len,
		gsize *outlen);

#ifndef g_tolower
#   define g_tolower(x) (((x) >= 'A' && (x) <= 'Z') ? (x) - 'A' + 'a' : (x))
#endif

#endif /* SRC_LIBUTIL_STR_UTIL_H_ */
