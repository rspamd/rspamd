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

#include <stdalign.h>

#ifdef  __cplusplus
extern "C" {
#endif

enum rspamd_newlines_type {
	RSPAMD_TASK_NEWLINES_CR = 0,
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
guint rspamd_str_lc (gchar *str, guint size);

/**
 * Performs ascii copy & lowercase
 * @param src
 * @param size
 * @return
 */
gsize rspamd_str_copy_lc (const gchar *src, gchar *dst, gsize size);

/**
 * Convert string to lowercase in-place using utf (limited) conversion
 */
guint rspamd_str_lc_utf8 (gchar *str, guint size);

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
#    ifdef __SANITIZE_ADDRESS__
#      define rspamd_strlcpy rspamd_strlcpy_safe
#    else
#      define rspamd_strlcpy rspamd_strlcpy_fast
#    endif
#  endif
#else
#  ifdef __SANITIZE_ADDRESS__
#    define rspamd_strlcpy rspamd_strlcpy_safe
#  else
#    define rspamd_strlcpy rspamd_strlcpy_fast
#  endif
#endif

/**
 * Copies `srclen` characters from `src` to `dst` ignoring \0
 * @param src
 * @param srclen
 * @param dest
 * @param destlen
 * @return number of bytes copied
 */
gsize
rspamd_null_safe_copy (const gchar *src, gsize srclen,
					   gchar *dest, gsize destlen);

/*
 * Try to convert string of length to long
 */
gboolean rspamd_strtol (const gchar *s, gsize len, glong *value);

/*
 * Try to convert a string of length to unsigned long
 */
gboolean rspamd_strtoul (const gchar *s, gsize len, gulong *value);
gboolean rspamd_strtou64 (const gchar *s, gsize len, guint64 *value);

/*
 * Try to convert a hex string of length to unsigned long
 */
gboolean rspamd_xstrtoul (const gchar *s, gsize len, gulong *value);

/**
 * Utility function to provide mem_pool copy for rspamd_hash_table_copy function
 * @param data string to copy
 * @param ud memory pool to use
 * @return
 */
gpointer rspamd_str_pool_copy (gconstpointer data, gpointer ud);

/**
 * Encode string using hex encoding
 * @param in input
 * @param inlen input length
 * @return freshly allocated base32 encoding of a specified string
 */
gchar *rspamd_encode_hex (const guchar *in, gsize inlen);

/**
 * Decode string using hex encoding
 * @param in input
 * @param inlen input length
 * @return freshly allocated base32 decoded value or NULL if input is invalid
 */
guchar *rspamd_decode_hex (const gchar *in, gsize inlen);

enum rspamd_base32_type {
	RSPAMD_BASE32_DEFAULT = 0,
	RSPAMD_BASE32_ZBASE = 0,
	RSPAMD_BASE32_BLEACH,
	RSPAMD_BASE32_RFC,
	RSPAMD_BASE32_INVALID = -1,
};

/**
 * Returns base32 type from a string or RSPAMD_BASE32_INVALID
 * @param str
 * @return
 */
enum rspamd_base32_type rspamd_base32_decode_type_from_str (const gchar *str);

/**
 * Encode string using base32 encoding
 * @param in input
 * @param inlen input length
 * @return freshly allocated base32 encoding of a specified string
 */
gchar *rspamd_encode_base32 (const guchar *in, gsize inlen,
		enum rspamd_base32_type type);

/**
 * Decode string using base32 encoding
 * @param in input
 * @param inlen input length
 * @return freshly allocated base32 decoded value or NULL if input is invalid
 */
guchar *rspamd_decode_base32 (const gchar *in, gsize inlen, gsize *outlen, enum rspamd_base32_type type);

/**
 * Encode string using base32 encoding
 * @param in input
 * @param inlen input length
 * @param out output buf
 * @param outlen output buf len
 * @return encoded len if `outlen` is enough to encode `inlen`
 */
gint rspamd_encode_base32_buf (const guchar *in, gsize inlen, gchar *out,
		gsize outlen, enum rspamd_base32_type type);

/**
 * Decode string using base32 encoding
 * @param in input
 * @param inlen input length
 * @param out output buf (may overlap with `in`)
 * @param outlen output buf len
 * @return decoded len if in is valid base32 and `outlen` is enough to encode `inlen`
 */
gint rspamd_decode_base32_buf (const gchar *in, gsize inlen, guchar *out,
		gsize outlen, enum rspamd_base32_type type);

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
 * Common version of base64 encoder
 * @param in
 * @param inlen
 * @param str_len
 * @param outlen
 * @param fold
 * @param how
 * @return
 */
gchar *
rspamd_encode_base64_common (const guchar *in,
							 gsize inlen,
							 gint str_len,
							 gsize *outlen,
							 gboolean fold,
							 enum rspamd_newlines_type how);

/**
 * Encode string using base64 encoding
 * @param in input
 * @param inlen input length
 * @param str_len maximum string length (if <= 0 then no lines are split)
 * @return freshly allocated base64 encoded value or NULL if input is invalid
 */
gchar *rspamd_encode_base64 (const guchar *in, gsize inlen, gint str_len,
							 gsize *outlen);

/**
 * Encode and fold string using base64 encoding
 * @param in input
 * @param inlen input length
 * @param str_len maximum string length (if <= 0 then no lines are split)
 * @return freshly allocated base64 encoded value or NULL if input is invalid
 */
gchar *rspamd_encode_base64_fold (const guchar *in, gsize inlen, gint str_len,
								  gsize *outlen, enum rspamd_newlines_type how);

/**
 * Encode and fold string using quoted printable encoding
 * @param in input
 * @param inlen input length
 * @param str_len maximum string length (if <= 0 then no lines are split)
 * @return freshly allocated base64 encoded value or NULL if input is invalid
 */
gchar *rspamd_encode_qp_fold (const guchar *in, gsize inlen, gint str_len,
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
 * Decode uuencode encoded buffer, input and output must not overlap
 * @param in input
 * @param inlen length of input
 * @param out output
 * @param outlen length of output
 * @return real size of decoded output or (-1) if outlen is not enough
 */
gssize rspamd_decode_uue_buf (const gchar *in, gsize inlen,
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
#ifdef HAVE_MEMRCHR
#define rspamd_memrchr memrchr
#else
void *rspamd_memrchr (const void *m, gint c, gsize len);
#endif

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
#define rspamd_str_hasmore(x, n) ((((x)+~0UL/255*(127-(n)))|(x))&~0UL/255*128)
/*
 * Check if a pointer is aligned; n must be power of two
 */
#define rspamd_is_aligned(p, n) (((uintptr_t)(p) & ((uintptr_t)(n) - 1)) == 0)
#define rspamd_is_aligned_as(p, v) rspamd_is_aligned(p, _Alignof(__typeof((v))))
gboolean rspamd_str_has_8bit (const guchar *beg, gsize len);

struct UConverter;

struct UConverter *rspamd_get_utf8_converter (void);

struct UNormalizer2;

const struct UNormalizer2 *rspamd_get_unicode_normalizer (void);



enum rspamd_regexp_escape_flags {
	RSPAMD_REGEXP_ESCAPE_ASCII = 0,
	RSPAMD_REGEXP_ESCAPE_UTF = 1u << 0,
	RSPAMD_REGEXP_ESCAPE_GLOB = 1u << 1,
	RSPAMD_REGEXP_ESCAPE_RE = 1u << 2,
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
						  gsize *dst_len, enum rspamd_regexp_escape_flags flags) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Returns copy of src (zero terminated) where all unicode is made valid or replaced
 * to FFFD characters. Caller must free string after usage
 * @param src
 * @param slen
 * @param dstelen
 * @return
 */
gchar *rspamd_str_make_utf_valid (const guchar *src, gsize slen, gsize *dstlen,
								  rspamd_mempool_t *pool) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Strips characters in `strip_chars` from start and end of the GString
 * @param s
 * @param strip_chars
 */
gsize rspamd_gstring_strip (GString *s, const gchar *strip_chars);

/**
 * Strips characters in `strip_chars` from start and end of the sized string
 * @param s
 * @param strip_chars
 */
const gchar *rspamd_string_len_strip (const gchar *in,
									  gsize *len, const gchar *strip_chars) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Returns a NULL terminated list of zero terminated strings based on splitting of
 * the base string into parts. If pool is not NULL then memory is allocated from
 * the pool. Otherwise, it is allocated from the heap using `g_malloc` (so
 * g_strfreev could be used to free stuff)
 * @param in
 * @param len
 * @param spill
 * @param max_elts
 * @return
 */
gchar ** rspamd_string_len_split (const gchar *in, gsize len,
		const gchar *spill, gint max_elts, rspamd_mempool_t *pool);

#define IS_ZERO_WIDTH_SPACE(uc) ((uc) == 0x200B || \
                                (uc) == 0x200C || \
                                (uc) == 0x200D || \
                                (uc) == 0xFEFF || \
								(uc) == 0x00AD)
#define IS_OBSCURED_CHAR(uc) (((uc) >= 0x200B && (uc) <= 0x200F) || \
                                ((uc) >= 0x2028 && (uc) <= 0x202F) || \
                                ((uc) >= 0x205F && (uc) <= 0x206F) || \
                                (uc) == 0xFEFF)

#define RSPAMD_LEN_CHECK_STARTS_WITH(s, len, lit) \
    ((len) >= sizeof(lit) - 1 && g_ascii_strncasecmp ((s), (lit), sizeof(lit) - 1) == 0)

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBUTIL_STR_UTIL_H_ */
