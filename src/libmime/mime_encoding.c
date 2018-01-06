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
#include "libserver/task.h"
#include "mime_encoding.h"
#include "message.h"
#include <unicode/ucnv.h>
#include <unicode/ucsdet.h>

#define UTF8_CHARSET "UTF-8"

#define RSPAMD_CHARSET_FLAG_UTF (1 << 0)
#define RSPAMD_CHARSET_FLAG_ASCII (1 << 1)

#define RSPAMD_CHARSET_CACHE_SIZE 32
#define RSPAMD_CHARSET_MAX_CONTENT 128

#define SET_PART_RAW(part) ((part)->flags &= ~RSPAMD_MIME_TEXT_PART_FLAG_UTF)
#define SET_PART_UTF(part) ((part)->flags |= RSPAMD_MIME_TEXT_PART_FLAG_UTF)

static rspamd_regexp_t *utf_compatible_re = NULL;
UConverter *utf8_converter = NULL;

struct rspamd_charset_substitution {
	const gchar *input;
	const gchar *canon;
	gint flags;
};

#include "mime_encoding_list.h"

static GHashTable *sub_hash = NULL;


static GQuark
rspamd_iconv_error_quark (void)
{
	return g_quark_from_static_string ("iconv error");
}

static UConverter *
rspamd_mime_get_converter_cached (const gchar *enc, UErrorCode *err)
{
	const gchar *canon_name;
	static rspamd_lru_hash_t *cache;
	UConverter *conv;

	if (cache == NULL) {
		cache = rspamd_lru_hash_new_full (RSPAMD_CHARSET_CACHE_SIZE, g_free,
				(GDestroyNotify)ucnv_close, rspamd_str_hash,
				rspamd_str_equal);
	}

	canon_name = ucnv_getStandardName (enc, "IANA", err);

	if (canon_name == NULL) {
		return NULL;
	}

	conv = rspamd_lru_hash_lookup (cache, (gpointer)canon_name, 0);

	if (conv == NULL) {
		conv = ucnv_open (canon_name, err);

		if (conv != NULL) {
			ucnv_setToUCallBack (conv,
					UCNV_TO_U_CALLBACK_SUBSTITUTE,
					UCNV_SUB_STOP_ON_ILLEGAL,
					NULL,
					NULL,
					err);
			rspamd_lru_hash_insert (cache, g_strdup (canon_name), conv, 0, 0);
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
	UErrorCode uc_err = U_ZERO_ERROR;

	if (sub_hash == NULL) {
		rspamd_mime_encoding_substitute_init ();
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
		return ucnv_getStandardName (s->canon, "IANA", &uc_err);
	}

	return ucnv_getStandardName (ret, "IANA", &uc_err);
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
	UConverter *conv;

	if (utf8_converter == NULL) {
		utf8_converter = ucnv_open (UTF8_CHARSET, &uc_err);

		if (uc_err != U_ZERO_ERROR) {
			g_set_error (err, rspamd_iconv_error_quark (), EINVAL,
					"cannot open converter for utf8: %s",
					u_errorName (uc_err));

			return NULL;
		}

		ucnv_setFromUCallBack (utf8_converter,
				UCNV_FROM_U_CALLBACK_SUBSTITUTE,
				NULL,
				NULL,
				NULL,
				&uc_err);
	}

	conv = rspamd_mime_get_converter_cached (in_enc, &uc_err);

	if (conv == NULL) {
		g_set_error (err, rspamd_iconv_error_quark (), EINVAL,
				"cannot open converter for %s: %s",
				in_enc, u_errorName (uc_err));

		return NULL;
	}

	tmp_buf = g_new (UChar, len + 1);
	uc_err = U_ZERO_ERROR;
	r = ucnv_toUChars (conv, tmp_buf, len + 1, input, len, &uc_err);

	if (uc_err != U_ZERO_ERROR) {
		g_set_error (err, rspamd_iconv_error_quark (), EINVAL,
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

	if (uc_err != U_ZERO_ERROR) {
		g_set_error (err, rspamd_iconv_error_quark (), EINVAL,
				"cannot convert data from unicode from %s: %s",
				in_enc, u_errorName (uc_err));
		g_free (tmp_buf);

		return NULL;
	}

	msg_info_pool ("converted from %s to UTF-8 inlen: %z, outlen: %d",
			in_enc, len, r);
	g_free (tmp_buf);

	if (olen) {
		*olen = r;
	}

	return d;
}

gboolean
rspamd_mime_to_utf8_byte_array (GByteArray *in,
		GByteArray *out,
		const gchar *enc)
{
	gint32 r, clen, dlen;
	UChar *tmp_buf;
	UErrorCode uc_err = U_ZERO_ERROR;
	UConverter *conv;
	rspamd_ftok_t charset_tok;

	RSPAMD_FTOK_FROM_STR (&charset_tok, enc);

	if (rspamd_mime_charset_utf_check (&charset_tok, (gchar *)in->data, in->len,
			FALSE)) {
		g_byte_array_set_size (out, in->len);
		memcpy (out->data, in->data, out->len);

		return TRUE;
	}

	if (utf8_converter == NULL) {
		utf8_converter = ucnv_open (UTF8_CHARSET, &uc_err);

		if (uc_err != U_ZERO_ERROR) {
			msg_warn ("cannot open converter for utf8: %s",
					u_errorName (uc_err));

			return FALSE;
		}

		ucnv_setFromUCallBack (utf8_converter,
				UCNV_FROM_U_CALLBACK_SUBSTITUTE,
				NULL,
				NULL,
				NULL,
				&uc_err);
	}

	conv = rspamd_mime_get_converter_cached (enc, &uc_err);

	if (conv == NULL) {
		return FALSE;
	}

	tmp_buf = g_new (UChar, in->len + 1);
	uc_err = U_ZERO_ERROR;
	r = ucnv_toUChars (conv, tmp_buf, in->len + 1, in->data, in->len, &uc_err);

	if (uc_err != U_ZERO_ERROR) {
		g_free (tmp_buf);

		return FALSE;
	}

	/* Now, convert to utf8 */
	clen = ucnv_getMaxCharSize (utf8_converter);
	dlen = UCNV_GET_MAX_BYTES_FOR_STRING (r, clen);
	g_byte_array_set_size (out, dlen);
	r = ucnv_fromUChars (utf8_converter, out->data, dlen, tmp_buf, r, &uc_err);

	if (uc_err != U_ZERO_ERROR) {
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
	const gchar *end, *p;
	gsize remain = len;

	/* Now we validate input and replace bad characters with '?' symbol */
	p = in;

	while (remain > 0 && !g_utf8_validate (p, remain, &end)) {
		gchar *valid;

		if (end >= in + len) {
			if (p < in + len) {
				memset ((gchar *)p, '?', (in + len) - p);
			}
			break;
		}

		valid = g_utf8_find_next_char (end, in + len);

		if (!valid) {
			valid = in + len;
		}

		if (valid > end) {
			memset ((gchar *)end, '?', valid - end);
			p = valid;
			remain = (in + len) - p;
		}
		else {
			break;
		}
	}
}

static const char *
rspamd_mime_charset_find_by_content (gchar *in, gsize inlen)
{
	static UCharsetDetector *csd;
	const UCharsetMatch **csm, *sel = NULL;
	UErrorCode uc_err = U_ZERO_ERROR;
	gint32 matches, i, max_conf = G_MININT32, conf;

	if (csd == NULL) {
		csd = ucsdet_open (&uc_err);

		g_assert (csd != NULL);
	}

	/* If text is ascii, then we can treat it as utf8 data */
	for (i = 0; i < inlen; i++) {
		if ((((guchar)in[i]) & 0x80) != 0) {
			goto detect;
		}
	}

	return UTF8_CHARSET;

detect:

	ucsdet_setText (csd, in, inlen, &uc_err);
	csm = ucsdet_detectAll(csd, &matches, &uc_err);

	for (i = 0; i < matches; i ++) {
		if ((conf = ucsdet_getConfidence (csm[i], &uc_err)) > max_conf) {
			max_conf = conf;
			sel = csm[i];
		}
	}

	if (sel && max_conf > 50) {
		return ucsdet_getName (sel, &uc_err);
	}

	return NULL;
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
			real_charset = rspamd_mime_charset_find_by_content (in,
					MIN (RSPAMD_CHARSET_MAX_CONTENT, len));

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
		}

		rspamd_mime_charset_utf_enforce (in, len);

		return TRUE;
	}

	return FALSE;
}

GByteArray *
rspamd_mime_text_part_maybe_convert (struct rspamd_task *task,
		struct rspamd_mime_text_part *text_part)
{
	GError *err = NULL;
	gsize write_bytes;
	const gchar *charset = NULL;
	gboolean checked = FALSE, need_charset_heuristic = TRUE;
	gchar *res_str;
	GByteArray *result_array, *part_content;
	rspamd_ftok_t charset_tok;
	struct rspamd_mime_part *part = text_part->mime_part;

	if (rspamd_str_has_8bit (text_part->raw.begin, text_part->raw.len)) {
		text_part->flags |= RSPAMD_MIME_TEXT_PART_FLAG_8BIT;
	}

	part_content = rspamd_mempool_alloc0 (task->task_pool, sizeof (GByteArray));
	part_content->data = rspamd_mempool_alloc (task->task_pool,
			text_part->parsed.len);
	memcpy (part_content->data, text_part->parsed.begin, text_part->parsed.len);
	part_content->len = text_part->parsed.len;

	if (rspamd_str_has_8bit (text_part->parsed.begin, text_part->parsed.len)) {
		text_part->flags |= RSPAMD_MIME_TEXT_PART_FLAG_8BIT_ENCODED;
	}

	if (!(text_part->flags & RSPAMD_MIME_TEXT_PART_FLAG_8BIT_ENCODED)) {
		need_charset_heuristic = FALSE;
	}

	if (task->cfg && task->cfg->raw_mode) {
		SET_PART_RAW (text_part);

		return part_content;
	}

	if (part->ct->charset.len == 0) {
		if (need_charset_heuristic) {
			charset = rspamd_mime_charset_find_by_content (part_content->data,
					MIN (RSPAMD_CHARSET_MAX_CONTENT, part_content->len));

			if (charset != NULL) {
				msg_info_task ("detected charset %s", charset);
			}

			checked = TRUE;
		}
		else {
			SET_PART_UTF (text_part);

			return part_content;
		}
	}
	else {
		charset = rspamd_mime_detect_charset (&part->ct->charset,
				task->task_pool);

		if (charset == NULL) {
			charset = rspamd_mime_charset_find_by_content (part_content->data,
					MIN (RSPAMD_CHARSET_MAX_CONTENT, part_content->len));
			msg_info_task ("detected charset: %s", charset);
			checked = TRUE;
		}
	}

	if (charset == NULL) {
		msg_info_task ("<%s>: has invalid charset", task->message_id);
		SET_PART_RAW (text_part);

		return NULL;
	}

	RSPAMD_FTOK_FROM_STR (&charset_tok, charset);

	if (rspamd_mime_charset_utf_check (&charset_tok, part_content->data,
			part_content->len, !checked)) {
		SET_PART_UTF (text_part);

		return part_content;
	}
	else {
		charset = charset_tok.begin;
		res_str = rspamd_mime_text_to_utf8 (task->task_pool, part_content->data,
				part_content->len,
				charset,
				&write_bytes,
				&err);

		if (res_str == NULL) {
			msg_warn_task ("<%s>: cannot convert from %s to utf8: %s",
					task->message_id,
					charset,
					err ? err->message : "unknown problem");
			SET_PART_RAW (text_part);
			g_error_free (err);

			return NULL;
		}
	}

	result_array = rspamd_mempool_alloc (task->task_pool, sizeof (GByteArray));
	result_array->data = res_str;
	result_array->len = write_bytes;
	SET_PART_UTF (text_part);

	return result_array;
}
