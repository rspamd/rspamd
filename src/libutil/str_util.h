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
#ifndef SRC_LIBUTIL_STR_UTIL_H_
#define SRC_LIBUTIL_STR_UTIL_H_

#include "config.h"
#include "ucl.h"
#include "fstring.h"

/**
 * Compare two memory regions of size `l` using case insensitive matching
 */
gint rspamd_lc_cmp (const gchar *s, const gchar *d, gsize l);

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
guint rspamd_ftok_icase_hash (gconstpointer key);
gboolean rspamd_ftok_icase_equal (gconstpointer v, gconstpointer v2);
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
 * Encode string using hex encoding
 * @param in input
 * @param inlen input length
 * @return freshly allocated base32 encoding of a specified string
 */
gchar * rspamd_encode_hex (const guchar *in, gsize inlen);

/**
 * Decode string using hex encoding
 * @param in input
 * @param inlen input length
 * @return freshly allocated base32 decoded value or NULL if input is invalid
 */
guchar* rspamd_decode_hex (const gchar *in, gsize inlen);

/**
 * Encode string using base32 encoding
 * @param in input
 * @param inlen input length
 * @param out output buf
 * @param outlen output buf len
 * @return encoded len if `outlen` is enough to encode `inlen`
 */
gint rspamd_encode_base32_buf (const guchar *in, gsize inlen, gchar *out,
		gsize outlen);

/**
 * Decode string using base32 encoding
 * @param in input
 * @param inlen input length
 * @param out output buf (may overlap with `in`)
 * @param outlen output buf len
 * @return decoded len if in is valid base32 and `outlen` is enough to encode `inlen`
 */
gint rspamd_decode_base32_buf (const gchar *in, gsize inlen,
		guchar *out, gsize outlen);

/**
 * Encode string using hex encoding
 * @param in input
 * @param inlen input length
 * @param out output buf
 * @param outlen output buf len
 * @return encoded len if `outlen` is enough to encode `inlen`
 */
gint rspamd_encode_hex_buf (const guchar *in, gsize inlen, gchar *out,
		gsize outlen);

/**
 * Decode string using hex encoding
 * @param in input
 * @param inlen input length
 * @param out output buf (may overlap with `in`)
 * @param outlen output buf len
 * @return decoded len if in is valid hex and `outlen` is enough to encode `inlen`
 */
gint rspamd_decode_hex_buf (const gchar *in, gsize inlen,
		guchar *out, gsize outlen);

/**
 * Encode string using base64 encoding
 * @param in input
 * @param inlen input length
 * @param str_len maximum string length (if <= 0 then no lines are split)
 * @return freshly allocated base64 encoded value or NULL if input is invalid
 */
gchar * rspamd_encode_base64 (const guchar *in, gsize inlen, gint str_len,
		gsize *outlen);

/**
 * Encode and fold string using base64 encoding
 * @param in input
 * @param inlen input length
 * @param str_len maximum string length (if <= 0 then no lines are split)
 * @return freshly allocated base64 encoded value or NULL if input is invalid
 */
gchar * rspamd_encode_base64_fold (const guchar *in, gsize inlen, gint str_len,
		gsize *outlen);

/**
 * Decode URL encoded string in-place and return new length of a string, src and dst are NULL terminated
 * @param dst
 * @param src
 * @param size
 * @return
 */
gsize rspamd_decode_url (gchar *dst, const gchar *src, gsize size);

#ifndef g_tolower
#   define g_tolower(x) (((x) >= 'A' && (x) <= 'Z') ? (x) - 'A' + 'a' : (x))
#endif

/**
 * Return levenstein distance between two strings
 * @param s1
 * @param s1len
 * @param s2
 * @param s2len
 * @return
 */
gint rspamd_strings_levenshtein_distance (const gchar *s1, gsize s1len,
		const gchar *s2, gsize s2len, guint replace_cost);

/**
 * Fold header using rfc822 rules, return new GString from the previous one
 * @param name name of header (used just for folding)
 * @param value value of header
 * @return new GString with the folded value
 */
GString *rspamd_header_value_fold (const gchar *name,
		const gchar *value,
		guint fold_max);

/**
 * Search for a substring `srch` in the text `in` using Karp-Rabin algorithm
 * @param in input
 * @param inlen input len
 * @param srch search string
 * @param srchlen length of the search string
 * @return position of the first substring match or (-1) if not found
 */
goffset rspamd_substring_search (const gchar *in, gsize inlen,
	const gchar *srch, gsize srchlen);

/**
 * Search for a substring `srch` in the text `in` using Karp-Rabin algorithm in caseless matter (ASCII only)
 * @param in input
 * @param inlen input len
 * @param srch search string
 * @param srchlen length of the search string
 * @return position of the first substring match or (-1) if not found
 */
goffset rspamd_substring_search_caseless (const gchar *in, gsize inlen,
		const gchar *srch, gsize srchlen);

/**
 * Search for a substring `srch` in the text `in` using 2-way algorithm:
 * http://www-igm.univ-mlv.fr/~lecroq/string/node26.html#SECTION00260
 * @param in input
 * @param inlen input len
 * @param srch search string
 * @param srchlen length of the search string
 * @return position of the first substring match or (-1) if not found
 */
goffset rspamd_substring_search_twoway (const gchar *in, gint inlen,
		const gchar *srch, gint srchlen);

/**
 * Search for end-of-headers mark in the input string. Returns position just after
 * the last header in message (but before the last newline character).
 * Hence, to obtain the real EOH position, it is also required to skip
 * space characters
 */
goffset rspamd_string_find_eoh (GString *input, goffset *body_start);


#define rspamd_ucl_emit_gstring(o, t, target) \
	rspamd_ucl_emit_gstring_comments((o), (t), (target), NULL)
/**
 * Emit UCL object to gstring
 * @param obj object to emit
 * @param emit_type emitter type
 * @param comments optional comments object
 * @param target target string
 */
void rspamd_ucl_emit_gstring_comments (const ucl_object_t *obj,
		enum ucl_emitter emit_type,
		GString *target,
		const ucl_object_t *comments);

#define rspamd_ucl_emit_fstring(o, t, target) \
	rspamd_ucl_emit_fstring_comments((o), (t), (target), NULL)
/**
 * Emit UCL object to fstring
 * @param obj object to emit
 * @param emit_type emitter type
 *  * @param comments optional comments object
 * @param target target string
 */
void rspamd_ucl_emit_fstring_comments (const ucl_object_t *obj,
		enum ucl_emitter emit_type,
		rspamd_fstring_t **target,
		const ucl_object_t *comments);

guint rspamd_url_hash (gconstpointer u);

/* Compare two emails for building emails hash */
gboolean rspamd_emails_cmp (gconstpointer a, gconstpointer b);

/* Compare two urls for building emails hash */
gboolean rspamd_urls_cmp (gconstpointer a, gconstpointer b);

extern const guchar lc_map[256];

/**
 * Search for the last occurrence of character `c` in memory block of size `len`
 * @param m
 * @param c
 * @param len
 * @return pointer to the last occurrence or NULL
 */
const void *rspamd_memrchr (const void *m, gint c, gsize len);

#endif /* SRC_LIBUTIL_STR_UTIL_H_ */
