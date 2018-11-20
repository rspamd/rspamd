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


enum rspamd_newlines_type {
	RSPAMD_TASK_NEWLINES_CR,
	RSPAMD_TASK_NEWLINES_LF,
	RSPAMD_TASK_NEWLINES_CRLF,
	RSPAMD_TASK_NEWLINES_MAX
};

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
guint64 rspamd_icase_hash (const gchar *in, gsize len, guint64 seed);
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
guint rspamd_ftok_hash (gconstpointer key);
gboolean rspamd_ftok_equal (gconstpointer v, gconstpointer v2);
guint rspamd_gstring_icase_hash (gconstpointer key);
gboolean rspamd_gstring_icase_equal (gconstpointer v, gconstpointer v2);

/**
 * Copy src to dest limited to len, in compare with standard strlcpy(3) rspamd strlcpy does not
 * traverse the whole string and it is possible to use it for non NULL terminated strings. This is
 * more like memccpy(dst, src, size, '\0')
 *
 * @param dst destination string
 * @param src source string
 * @param siz length of destination buffer
 * @return bytes copied
 */
gsize rspamd_strlcpy_fast (gchar *dst, const gchar *src, gsize siz);
gsize rspamd_strlcpy_safe (gchar *dst, const gchar *src, gsize siz);

#if defined(__has_feature)
#  if __has_feature(address_sanitizer)
#    define rspamd_strlcpy rspamd_strlcpy_safe
#  else
#    define rspamd_strlcpy rspamd_strlcpy_fast
#  endif
#else
#  define rspamd_strlcpy rspamd_strlcpy_fast
#endif

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
gssize rspamd_decode_hex_buf (const gchar *in, gsize inlen,
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
		gsize *outlen, enum rspamd_newlines_type how);

/**
 * Decode quoted-printable encoded buffer, input and output must not overlap
 * @param in input
 * @param inlen length of input
 * @param out output
 * @param outlen length of output
 * @return real size of decoded output or (-1) if outlen is not enough
 */
gssize rspamd_decode_qp_buf (const gchar *in, gsize inlen,
		gchar *out, gsize outlen);

/**
 * Decode quoted-printable encoded buffer using rfc2047 format, input and output must not overlap
 * @param in input
 * @param inlen length of input
 * @param out output
 * @param outlen length of output
 * @return real size of decoded output or (-1) if outlen is not enough
 */
gssize rspamd_decode_qp2047_buf (const gchar *in, gsize inlen,
		gchar *out, gsize outlen);

/**
 * Encode quoted-printable buffer using rfc2047 format, input and output must not overlap
 * @param in
 * @param inlen
 * @param out
 * @param outlen
 * @return
 */
gssize rspamd_encode_qp2047_buf (const gchar *in, gsize inlen,
		gchar *out, gsize outlen);

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
 * @param fold_max
 * @param how
 * @param fold_on_chars
 * @return new GString with the folded value
 */
GString *rspamd_header_value_fold (const gchar *name,
		const gchar *value,
		guint fold_max,
		enum rspamd_newlines_type how,
		const gchar *fold_on_chars);

/**
 * Search for a substring `srch` in the text `in` using Apostolico-Crochemore algorithm
 * http://www-igm.univ-mlv.fr/~lecroq/string/node12.html#SECTION00120
 * @param in input
 * @param inlen input len
 * @param srch search string
 * @param srchlen length of the search string
 * @return position of the first substring match or (-1) if not found
 */
goffset rspamd_substring_search (const gchar *in, gsize inlen,
	const gchar *srch, gsize srchlen);

/**
 * Search for a substring `srch` in the text `in` using Apostolico-Crochemore algorithm in caseless matter (ASCII only)
 * http://www-igm.univ-mlv.fr/~lecroq/string/node12.html#SECTION00120
 * @param in input
 * @param inlen input len
 * @param srch search string
 * @param srchlen length of the search string
 * @return position of the first substring match or (-1) if not found
 */
goffset rspamd_substring_search_caseless (const gchar *in, gsize inlen,
		const gchar *srch, gsize srchlen);

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

extern const guchar lc_map[256];

/**
 * Search for the last occurrence of character `c` in memory block of size `len`
 * @param m
 * @param c
 * @param len
 * @return pointer to the last occurrence or NULL
 */
const void *rspamd_memrchr (const void *m, gint c, gsize len);

/**
 * Return length of memory segment starting in `s` that contains no chars from `e`
 * @param s any input
 * @param e zero terminated string of exceptions
 * @param len length of `s`
 * @return segment size
 */
gsize rspamd_memcspn (const gchar *s, const gchar *e, gsize len);

/**
 * Return length of memory segment starting in `s` that contains only chars from `e`
 * @param s any input
 * @param e zero terminated string of inclusions
 * @param len length of `s`
 * @return segment size
 */
gsize rspamd_memspn (const gchar *s, const gchar *e, gsize len);

/* https://graphics.stanford.edu/~seander/bithacks.html#HasMoreInWord */
#define rspamd_str_hasmore(x,n) ((((x)+~0UL/255*(127-(n)))|(x))&~0UL/255*128)

static inline gboolean
rspamd_str_has_8bit (const guchar *beg, gsize len)
{
	unsigned long *w;
	gsize i, leftover = len % sizeof (*w);

	w = (unsigned long *)beg;

	for (i = 0; i < len / sizeof (*w); i ++) {
		if (rspamd_str_hasmore (*w, 127)) {
			return TRUE;
		}

		w ++;
	}

	beg = (const guchar *)w;

	for (i = 0; i < leftover; i ++) {
		if (beg[i] > 127) {
			return TRUE;
		}
	}

	return FALSE;
}

/**
 * Gets a string in UTF8 and normalises it to NFKC_Casefold form
 * @param pool optional memory pool used for logging purposes
 * @param start
 * @param len
 * @return TRUE if a string has been normalised
 */
gboolean rspamd_normalise_unicode_inplace (rspamd_mempool_t *pool,
		gchar *start, guint *len);

enum rspamd_regexp_escape_flags {
	RSPAMD_REGEXP_ESCAPE_ASCII = 0,
	RSPAMD_REGEXP_ESCAPE_UTF = 1u << 0,
	RSPAMD_REGEXP_ESCAPE_GLOB = 1u << 1,
};
/**
 * Escapes special characters when reading plain data to be processed in pcre
 * @param pattern pattern to process
 * @param slen source length
 * @param dst_len destination length pointer (can be NULL)
 * @param allow_glob allow glob expressions to be translated into pcre
 * @return newly allocated zero terminated escaped pattern
 */
gchar *
rspamd_str_regexp_escape (const gchar *pattern, gsize slen,
		gsize *dst_len, enum rspamd_regexp_escape_flags flags);

#endif /* SRC_LIBUTIL_STR_UTIL_H_ */
