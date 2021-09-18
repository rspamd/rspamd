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

#include "config.h"
#include "libutil/mem_pool.h"
#include "libutil/regexp.h"
#include "libutil/hash.h"
#include "libserver/cfg_file.h"
#include "libserver/task.h"
#include "mime_encoding.h"
#include "message.h"
#include "contrib/fastutf8/fastutf8.h"
#include "contrib/google-ced/ced_c.h"
#include <unicode/ucnv.h>
#if U_ICU_VERSION_MAJOR_NUM >= 44
#include <unicode/unorm2.h>
#endif
#include <math.h>

#define UTF8_CHARSET "UTF-8"

#define RSPAMD_CHARSET_FLAG_UTF (1 << 0)
#define RSPAMD_CHARSET_FLAG_ASCII (1 << 1)

#define RSPAMD_CHARSET_CACHE_SIZE 32
#define RSPAMD_CHARSET_MAX_CONTENT 512

#define SET_PART_RAW(part) ((part)->flags &= ~RSPAMD_MIME_TEXT_PART_FLAG_UTF)
#define SET_PART_UTF(part) ((part)->flags |= RSPAMD_MIME_TEXT_PART_FLAG_UTF)

static rspamd_regexp_t *utf_compatible_re = NULL;

struct rspamd_charset_substitution {
	const gchar *input;
	const gchar *canon;
	gint flags;
};

#include "mime_encoding_list.h"

static GHashTable *sub_hash = NULL;

static const UChar iso_8859_16_map[] = {
		0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,
		0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F,
		0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,
		0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F,
		0x00A0, 0x0104, 0x0105, 0x0141, 0x20AC, 0x201E, 0x0160, 0x00A7,
		0x0161, 0x00A9, 0x0218, 0x00AB, 0x0179, 0x00AD, 0x017A, 0x017B,
		0x00B0, 0x00B1, 0x010C, 0x0142, 0x017D, 0x201D, 0x00B6, 0x00B7,
		0x017E, 0x010D, 0x0219, 0x00BB, 0x0152, 0x0153, 0x0178, 0x017C,
		0x00C0, 0x00C1, 0x00C2, 0x0102, 0x00C4, 0x0106, 0x00C6, 0x00C7,
		0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF,
		0x0110, 0x0143, 0x00D2, 0x00D3, 0x00D4, 0x0150, 0x00D6, 0x015A,
		0x0170, 0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x0118, 0x021A, 0x00DF,
		0x00E0, 0x00E1, 0x00E2, 0x0103, 0x00E4, 0x0107, 0x00E6, 0x00E7,
		0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF,
		0x0111, 0x0144, 0x00F2, 0x00F3, 0x00F4, 0x0151, 0x00F6, 0x015B,
		0x0171, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x0119, 0x021B, 0x00FF
};

struct rspamd_charset_converter {
	gchar *canon_name;
	union {
		UConverter *conv;
		const UChar *cnv_table;
	} d;
	gboolean is_internal;
};

static GQuark
rspamd_charset_conv_error_quark (void)
{
	return g_quark_from_static_string ("charset conversion error");
}

static void
rspamd_converter_dtor (gpointer p)
{
	struct rspamd_charset_converter *c = (struct rspamd_charset_converter *)p;

	if (!c->is_internal) {
		ucnv_close (c->d.conv);
	}

	g_free (c->canon_name);
	g_free (c);
}

int32_t
rspamd_converter_to_uchars (struct rspamd_charset_converter *cnv,
							UChar *dest,
							int32_t destCapacity,
							const char *src,
							int32_t srcLength,
							UErrorCode *pErrorCode)
{
	if (!cnv->is_internal) {
		return ucnv_toUChars (cnv->d.conv,
				dest, destCapacity,
				src, srcLength,
				pErrorCode);
	}
	else {
		UChar *d = dest, *dend = dest + destCapacity;
		const guchar *p = src, *end = src + srcLength;

		while (p < end && d < dend) {
			if (*p <= 127) {
				*d++ = (UChar)*p;
			}
			else {
				*d++ = cnv->d.cnv_table[*p - 128];
			}

			p ++;
		}

		return d - dest;
	}
}


struct rspamd_charset_converter *
rspamd_mime_get_converter_cached (const gchar *enc,
								  rspamd_mempool_t *pool,
								  gboolean is_canon,
								  UErrorCode *err)
{
	const gchar *canon_name;
	static rspamd_lru_hash_t *cache;
	struct rspamd_charset_converter *conv;

	if (cache == NULL) {
		cache = rspamd_lru_hash_new_full (RSPAMD_CHARSET_CACHE_SIZE, NULL,
				rspamd_converter_dtor, rspamd_str_hash,
				rspamd_str_equal);
	}

	if (enc == NULL) {
		return NULL;
	}

	if (!is_canon) {
		rspamd_ftok_t cset_tok;

		RSPAMD_FTOK_FROM_STR (&cset_tok, enc);
		canon_name = rspamd_mime_detect_charset (&cset_tok, pool);
	}
	else {
		canon_name = enc;
	}

	if (canon_name == NULL) {
		return NULL;
	}

	conv = rspamd_lru_hash_lookup (cache, (gpointer)canon_name, 0);

	if (conv == NULL) {
		if (!(strcmp (canon_name, "ISO-8859-16") == 0 ||
				strcmp (canon_name, "latin10") == 0 ||
				strcmp (canon_name, "iso-ir-226") == 0)) {
			conv = g_malloc0 (sizeof (*conv));
			conv->d.conv = ucnv_open (canon_name, err);
			conv->canon_name = g_strdup (canon_name);

			if (conv->d.conv != NULL) {
				ucnv_setToUCallBack (conv->d.conv,
						UCNV_TO_U_CALLBACK_SUBSTITUTE,
						NULL,
						NULL,
						NULL,
						err);
				rspamd_lru_hash_insert (cache, conv->canon_name, conv, 0, 0);
			}
			else {
				g_free (conv);
				conv = NULL;
			}
		}
		else {
			/* ISO-8859-16 */
			conv = g_malloc0 (sizeof (*conv));
			conv->is_internal = TRUE;
			conv->d.cnv_table = iso_8859_16_map;
			conv->canon_name = g_strdup (canon_name);

			rspamd_lru_hash_insert (cache, conv->canon_name, conv, 0, 0);
		}
	}

	return conv;
}

static void
rspamd_mime_encoding_substitute_init (void)
{
	guint i;

	sub_hash = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);

	for (i = 0; i < G_N_ELEMENTS (sub); i ++) {
		g_hash_table_insert (sub_hash, (void *)sub[i].input, (void *)&sub[i]);
	}
}

static void
rspamd_charset_normalize (gchar *in)
{
	/*
	 * This is a simple routine to validate input charset
	 * we just check that charset starts with alphanumeric and ends
	 * with alphanumeric
	 */
	gchar *begin, *end;
	gboolean changed = FALSE;

	begin = in;

	while (*begin && !g_ascii_isalnum (*begin)) {
		begin ++;
		changed = TRUE;
	}

	end = begin + strlen (begin) - 1;

	while (end > begin && !g_ascii_isalnum (*end)) {
		end --;
		changed = TRUE;
	}

	if (changed) {
		memmove (in, begin, end - begin + 2);
		*(end + 1) = '\0';
	}
}

const gchar *
rspamd_mime_detect_charset (const rspamd_ftok_t *in, rspamd_mempool_t *pool)
{
	gchar *ret = NULL, *h, *t;
	struct rspamd_charset_substitution *s;
	const gchar *cset;
	rspamd_ftok_t utf8_tok;
	UErrorCode uc_err = U_ZERO_ERROR;

	if (sub_hash == NULL) {
		rspamd_mime_encoding_substitute_init ();
	}

	/* Fast path */
	RSPAMD_FTOK_ASSIGN (&utf8_tok, "utf-8");

	if (rspamd_ftok_casecmp (in, &utf8_tok) == 0) {
		return UTF8_CHARSET;
	}

	RSPAMD_FTOK_ASSIGN (&utf8_tok, "utf8");

	if (rspamd_ftok_casecmp (in, &utf8_tok) == 0) {
		return UTF8_CHARSET;
	}

	ret = rspamd_mempool_ftokdup (pool, in);
	rspamd_charset_normalize (ret);

	if ((in->len > 3 && rspamd_lc_cmp (in->begin, "cp-", 3) == 0) ||
			(in->len > 4 && (rspamd_lc_cmp (in->begin, "ibm-", 4) == 0))) {
		/* Try to remove '-' chars from encoding: e.g. CP-100 to CP100 */
		h = ret;
		t = ret;

		while (*h != '\0') {
			if (*h != '-') {
				*t++ = *h;
			}

			h ++;
		}

		*t = '\0';
	}

	s = g_hash_table_lookup (sub_hash, ret);

	if (s) {
		ret = (char *)s->canon;
	}

	/* Try different aliases */
	cset = ucnv_getCanonicalName (ret, "MIME", &uc_err);

	if (cset == NULL) {
		uc_err = U_ZERO_ERROR;
		cset = ucnv_getCanonicalName (ret, "IANA", &uc_err);
	}

	if (cset == NULL) {
		uc_err = U_ZERO_ERROR;
		cset = ucnv_getCanonicalName (ret, "", &uc_err);
	}

	if (cset == NULL) {
		uc_err = U_ZERO_ERROR;
		cset = ucnv_getAlias (ret, 0, &uc_err);
	}

	return cset;
}

gchar *
rspamd_mime_text_to_utf8 (rspamd_mempool_t *pool,
		gchar *input, gsize len, const gchar *in_enc,
		gsize *olen, GError **err)
{
	gchar *d;
	gint32 r, clen, dlen;
	UChar *tmp_buf;

	UErrorCode uc_err = U_ZERO_ERROR;
	UConverter *utf8_converter;
	struct rspamd_charset_converter *conv;
	rspamd_ftok_t cset_tok;

	/* Check if already utf8 */
	RSPAMD_FTOK_FROM_STR (&cset_tok, in_enc);

	if (rspamd_mime_charset_utf_check (&cset_tok, input, len,
			FALSE)) {
		d = rspamd_mempool_alloc (pool, len);
		memcpy (d, input, len);
		if (olen) {
			*olen = len;
		}

		return d;
	}

	conv = rspamd_mime_get_converter_cached (in_enc, pool, TRUE, &uc_err);
	utf8_converter = rspamd_get_utf8_converter ();

	if (conv == NULL) {
		g_set_error (err, rspamd_charset_conv_error_quark(), EINVAL,
				"cannot open converter for %s: %s",
				in_enc, u_errorName (uc_err));

		return NULL;
	}

	tmp_buf = g_new (UChar, len + 1);
	uc_err = U_ZERO_ERROR;
	r = rspamd_converter_to_uchars (conv, tmp_buf, len + 1, input, len, &uc_err);

	if (!U_SUCCESS (uc_err)) {
		g_set_error (err, rspamd_charset_conv_error_quark(), EINVAL,
					"cannot convert data to unicode from %s: %s",
					in_enc, u_errorName (uc_err));
		g_free (tmp_buf);

		return NULL;
	}

	/* Now, convert to utf8 */
	clen = ucnv_getMaxCharSize (utf8_converter);
	dlen = UCNV_GET_MAX_BYTES_FOR_STRING (r, clen);
	d = rspamd_mempool_alloc (pool, dlen);
	r = ucnv_fromUChars (utf8_converter, d, dlen, tmp_buf, r, &uc_err);

	if (!U_SUCCESS (uc_err)) {
		g_set_error (err, rspamd_charset_conv_error_quark(), EINVAL,
				"cannot convert data from unicode from %s: %s",
				in_enc, u_errorName (uc_err));
		g_free (tmp_buf);

		return NULL;
	}

	msg_debug_pool ("converted from %s to UTF-8 inlen: %z, outlen: %d",
			in_enc, len, r);
	g_free (tmp_buf);

	if (olen) {
		*olen = r;
	}

	return d;
}

static gboolean
rspamd_mime_text_part_utf8_convert (struct rspamd_task *task,
									struct rspamd_mime_text_part *text_part,
									GByteArray *input,
									const gchar *charset,
									GError **err)
{
	gchar *d;
	gint32 r, clen, dlen, uc_len;
	UChar *tmp_buf;
	UErrorCode uc_err = U_ZERO_ERROR;
	UConverter *utf8_converter;
	struct rspamd_charset_converter *conv;

	conv = rspamd_mime_get_converter_cached (charset, task->task_pool,
			TRUE, &uc_err);
	utf8_converter = rspamd_get_utf8_converter ();

	if (conv == NULL) {
		g_set_error (err, rspamd_charset_conv_error_quark(), EINVAL,
				"cannot open converter for %s: %s",
				charset, u_errorName (uc_err));

		return FALSE;
	}

	tmp_buf = g_new (UChar, input->len + 1);
	uc_err = U_ZERO_ERROR;
	uc_len = rspamd_converter_to_uchars (conv,
			tmp_buf,
			input->len + 1,
			input->data,
			input->len,
			&uc_err);

	if (!U_SUCCESS (uc_err)) {
		g_set_error (err, rspamd_charset_conv_error_quark(), EINVAL,
				"cannot convert data to unicode from %s: %s",
				charset, u_errorName (uc_err));
		g_free (tmp_buf);

		return FALSE;
	}

	/* Now, convert to utf8 */
	clen = ucnv_getMaxCharSize (utf8_converter);
	dlen = UCNV_GET_MAX_BYTES_FOR_STRING (uc_len, clen);
	d = rspamd_mempool_alloc (task->task_pool, dlen);
	r = ucnv_fromUChars (utf8_converter, d, dlen,
			tmp_buf, uc_len, &uc_err);

	if (!U_SUCCESS (uc_err)) {
		g_set_error (err, rspamd_charset_conv_error_quark(), EINVAL,
				"cannot convert data from unicode from %s: %s",
				charset, u_errorName (uc_err));
		g_free (tmp_buf);

		return FALSE;
	}

	if (text_part->mime_part && text_part->mime_part->ct) {
		msg_info_task ("converted text part from %s ('%T' announced) to UTF-8 inlen: %d, outlen: %d (%d UTF16 chars)",
				charset, &text_part->mime_part->ct->charset, input->len, r, uc_len);
	}
	else {
		msg_info_task ("converted text part from %s (no charset announced) to UTF-8 inlen: %d, "
				 "outlen: %d (%d UTF16 chars)",
				charset, input->len, r, uc_len);
	}

	text_part->utf_raw_content = rspamd_mempool_alloc (task->task_pool,
			sizeof (*text_part->utf_raw_content) + sizeof (gpointer) * 4);
	text_part->utf_raw_content->data = d;
	text_part->utf_raw_content->len = r;
	g_free (tmp_buf);

	return TRUE;
}

gboolean
rspamd_mime_to_utf8_byte_array (GByteArray *in,
		GByteArray *out,
		rspamd_mempool_t *pool,
		const gchar *enc)
{
	gint32 r, clen, dlen;
	UChar *tmp_buf;
	UErrorCode uc_err = U_ZERO_ERROR;
	UConverter *utf8_converter;
	struct rspamd_charset_converter *conv;
	rspamd_ftok_t charset_tok;

	if (in == NULL || in->len == 0) {
		return FALSE;
	}

	if (enc == NULL) {
		/* Assume utf ? */
		if (rspamd_fast_utf8_validate (in->data, in->len) == 0) {
			g_byte_array_set_size (out, in->len);
			memcpy (out->data, in->data, out->len);

			return TRUE;
		}
		else {
			/* Bad stuff, keep out */
			return FALSE;
		}
	}

	RSPAMD_FTOK_FROM_STR (&charset_tok, enc);

	if (rspamd_mime_charset_utf_check (&charset_tok, (gchar *)in->data, in->len,
			FALSE)) {
		g_byte_array_set_size (out, in->len);
		memcpy (out->data, in->data, out->len);

		return TRUE;
	}

	utf8_converter = rspamd_get_utf8_converter ();
	conv = rspamd_mime_get_converter_cached (enc, pool, TRUE, &uc_err);

	if (conv == NULL) {
		return FALSE;
	}

	tmp_buf = g_new (UChar, in->len + 1);
	uc_err = U_ZERO_ERROR;
	r = rspamd_converter_to_uchars (conv,
			tmp_buf, in->len + 1,
			in->data, in->len, &uc_err);

	if (!U_SUCCESS (uc_err)) {
		g_free (tmp_buf);

		return FALSE;
	}

	/* Now, convert to utf8 */
	clen = ucnv_getMaxCharSize (utf8_converter);
	dlen = UCNV_GET_MAX_BYTES_FOR_STRING (r, clen);
	g_byte_array_set_size (out, dlen);
	r = ucnv_fromUChars (utf8_converter, out->data, dlen, tmp_buf, r, &uc_err);

	if (!U_SUCCESS (uc_err)) {
		g_free (tmp_buf);

		return FALSE;
	}

	g_free (tmp_buf);
	out->len = r;

	return TRUE;
}

void
rspamd_mime_charset_utf_enforce (gchar *in, gsize len)
{
	gchar *p, *end;
	goffset err_offset;
	UChar32 uc = 0;

	/* Now we validate input and replace bad characters with '?' symbol */
	p = in;
	end = in + len;

	while (p < end && len > 0 && (err_offset = rspamd_fast_utf8_validate (p, len)) > 0) {
		err_offset --; /* As it returns it 1 indexed */
		gint32 cur_offset = err_offset;

		while (cur_offset < len) {
			gint32 tmp = cur_offset;

			U8_NEXT (p, cur_offset, len, uc);

			if (uc > 0) {
				/* Fill string between err_offset and tmp with `?` character */
				memset (p + err_offset, '?', tmp - err_offset);
				break;
			}
		}

		if (uc < 0) {
			/* Fill till the end */
			memset (p + err_offset, '?', len - err_offset);
			break;
		}

		p += cur_offset;
		len = end - p;
	}
}

const char *
rspamd_mime_charset_find_by_content (const gchar *in, gsize inlen,
									 bool check_utf8)
{
	int nconsumed;
	bool is_reliable;
	const gchar *ced_name;

	if (check_utf8) {
		if (rspamd_fast_utf8_validate (in, inlen) == 0) {
			return UTF8_CHARSET;
		}
	}


	ced_name = ced_encoding_detect (in, inlen, NULL, NULL,
			NULL, 0, CED_EMAIL_CORPUS,
			false, &nconsumed, &is_reliable);

	if (ced_name) {

		return ced_name;
	}

	return NULL;
}

static const char *
rspamd_mime_charset_find_by_content_maybe_split (const gchar *in, gsize inlen)
{
	if (inlen < RSPAMD_CHARSET_MAX_CONTENT * 3) {
		return rspamd_mime_charset_find_by_content (in, inlen, false);
	}
	else {
		const gchar *c1, *c2, *c3;

		c1 = rspamd_mime_charset_find_by_content (in, RSPAMD_CHARSET_MAX_CONTENT, false);
		c2 = rspamd_mime_charset_find_by_content (in + inlen / 2,
				RSPAMD_CHARSET_MAX_CONTENT, false);
		c3 = rspamd_mime_charset_find_by_content (in + inlen - RSPAMD_CHARSET_MAX_CONTENT,
				RSPAMD_CHARSET_MAX_CONTENT, false);

		/* 7bit stuff */
		if (c1 && strcmp (c1, "US-ASCII") == 0) {
			c1 = NULL; /* Invalid - we have 8 bit there */
		}
		if (c2 && strcmp (c2, "US-ASCII") == 0) {
			c2 = NULL; /* Invalid - we have 8 bit there */
		}
		if (c3 && strcmp (c3, "US-ASCII") == 0) {
			c3 = NULL; /* Invalid - we have 8 bit there */
		}

		if (!c1) {
			c1 = c2 ? c2 : c3;
		}
		if (!c2) {
			c2 = c3 ? c3 : c1;
		}
		if (!c3) {
			c3 = c1 ? c2 : c1;
		}

		if (c1 && c2 && c3) {
			/* Quorum */
			if (c1 == c2) {
				return c1;
			}
			else if (c2 == c3) {
				return c2;
			}
			else if (c1 == c3) {
				return c3;
			}

			/* All charsets are distinct. Use the one from the top */
			return c1;
		}

		return NULL;
	}
}

gboolean
rspamd_mime_charset_utf_check (rspamd_ftok_t *charset,
		gchar *in, gsize len, gboolean content_check)
{
	const gchar *real_charset;

	if (utf_compatible_re == NULL) {
		utf_compatible_re = rspamd_regexp_new (
				"^(?:utf-?8.*)|(?:us-ascii)|(?:ascii)|(?:ansi.*)|(?:CSASCII)$",
				"i", NULL);
	}

	if (charset->len == 0 ||
			rspamd_regexp_match (utf_compatible_re,
					charset->begin, charset->len, TRUE)) {
		/*
		 * In case of UTF8 charset we still can check the content to find
		 * corner cases
		 */
		if (content_check) {
			if (rspamd_fast_utf8_validate (in, len) != 0) {
				real_charset = rspamd_mime_charset_find_by_content_maybe_split(in, len);

				if (real_charset) {

					if (rspamd_regexp_match (utf_compatible_re,
							real_charset, strlen (real_charset), TRUE)) {
						RSPAMD_FTOK_ASSIGN (charset, UTF8_CHARSET);

						return TRUE;
					}
					else {
						charset->begin = real_charset;
						charset->len = strlen (real_charset);

						return FALSE;
					}
				}

				rspamd_mime_charset_utf_enforce (in, len);
			}
		}

		return TRUE;
	}

	return FALSE;
}

void
rspamd_mime_text_part_maybe_convert (struct rspamd_task *task,
		struct rspamd_mime_text_part *text_part)
{
	GError *err = NULL;
	const gchar *charset = NULL;
	gboolean checked = FALSE, need_charset_heuristic = TRUE, valid_utf8 = FALSE;
	GByteArray *part_content;
	rspamd_ftok_t charset_tok;
	struct rspamd_mime_part *part = text_part->mime_part;

	if (rspamd_str_has_8bit (text_part->raw.begin, text_part->raw.len)) {
		text_part->flags |= RSPAMD_MIME_TEXT_PART_FLAG_8BIT_RAW;
	}

	/* Allocate copy storage */
	part_content = g_byte_array_sized_new (text_part->parsed.len);
	memcpy (part_content->data, text_part->parsed.begin, text_part->parsed.len);
	part_content->len = text_part->parsed.len;
	rspamd_mempool_notify_alloc (task->task_pool,
			part_content->len);
	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t)g_byte_array_unref, part_content);

	if (rspamd_str_has_8bit (text_part->parsed.begin, text_part->parsed.len)) {
		if (rspamd_fast_utf8_validate (text_part->parsed.begin, text_part->parsed.len) == 0) {
			/* Valid UTF, likely all good */
			need_charset_heuristic = FALSE;
			valid_utf8 = TRUE;
			checked = TRUE;
		}

		text_part->flags |= RSPAMD_MIME_TEXT_PART_FLAG_8BIT_ENCODED;
	}
	else {
		/* All 7bit characters, assume it valid utf */
		need_charset_heuristic = FALSE;
		valid_utf8 = TRUE;
		checked = TRUE; /* Already valid utf, no need in further checks */
	}

	if (part->ct->charset.len == 0) {
		if (need_charset_heuristic) {
			charset = rspamd_mime_charset_find_by_content_maybe_split (text_part->parsed.begin,
					text_part->parsed.len);

			if (charset != NULL) {
				msg_info_task ("detected charset %s", charset);
			}

			checked = TRUE;
			text_part->real_charset = charset;
		}
		else if (valid_utf8) {
			SET_PART_UTF (text_part);
			text_part->utf_raw_content = part_content;
			text_part->real_charset = UTF8_CHARSET;

			return;
		}
	}
	else {
		charset = rspamd_mime_detect_charset (&part->ct->charset,
				task->task_pool);

		if (charset == NULL) {
			/* We don't know the real charset but can try heuristic */
			if (need_charset_heuristic) {
				charset = rspamd_mime_charset_find_by_content_maybe_split (part_content->data,
						part_content->len);
				msg_info_task ("detected charset: %s", charset);
				checked = TRUE;
				text_part->real_charset = charset;
			}
			else if (valid_utf8) {
				/* We already know that the input is valid utf, so skip heuristic */
				text_part->real_charset = UTF8_CHARSET;
			}
		}
		else {
			text_part->real_charset = charset;

			if (strcmp (charset, UTF8_CHARSET) != 0) {
				/*
				 * We have detected some charset, but we don't know which one,
				 * so we need to reset valid utf8 flag and enforce it later
				 */
				valid_utf8 = FALSE;
			}
		}
	}

	if (text_part->real_charset == NULL) {
		msg_info_task ("<%s>: has invalid charset; original charset: %T; Content-Type: \"%s\"",
				MESSAGE_FIELD_CHECK (task, message_id), &part->ct->charset,
				part->ct->cpy);
		SET_PART_RAW (text_part);
		text_part->utf_raw_content = part_content;

		return;
	}

	RSPAMD_FTOK_FROM_STR (&charset_tok, charset);

	if (!valid_utf8) {
		if (rspamd_mime_charset_utf_check (&charset_tok, part_content->data,
				part_content->len, !checked)) {
			SET_PART_UTF (text_part);
			text_part->utf_raw_content = part_content;
			text_part->real_charset = UTF8_CHARSET;

			return;
		}
		else {
			charset = charset_tok.begin;

			if (!rspamd_mime_text_part_utf8_convert (task, text_part,
					part_content, charset, &err)) {
				msg_warn_task ("<%s>: cannot convert from %s to utf8: %s",
						MESSAGE_FIELD (task, message_id),
						charset,
						err ? err->message : "unknown problem");
				SET_PART_RAW (text_part);
				g_error_free (err);

				text_part->utf_raw_content = part_content;
				return;
			}

			SET_PART_UTF (text_part);
			text_part->real_charset = charset;
		}
	}
	else {
		SET_PART_UTF (text_part);
		text_part->utf_raw_content = part_content;
	}
}
