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
#include "libserver/task.h"
#include "mime_encoding.h"
#include "message.h"
#include <iconv.h>

#define UTF8_CHARSET "UTF-8"

#define RSPAMD_CHARSET_FLAG_UTF (1 << 0)
#define RSPAMD_CHARSET_FLAG_ASCII (1 << 1)

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


static GQuark
rspamd_iconv_error_quark (void)
{
	return g_quark_from_static_string ("iconv error");
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
		return s->canon;
	}

	return ret;
}

gchar *
rspamd_mime_text_to_utf8 (rspamd_mempool_t *pool,
		gchar *input, gsize len, const gchar *in_enc,
		gsize *olen, GError **err)
{
	gchar *s, *d;
	gsize outlen;
	iconv_t ic;
	rspamd_fstring_t *dst;
	gsize remain, ret, inremain = len;

	ic = iconv_open (UTF8_CHARSET, in_enc);

	if (ic == (iconv_t)-1) {
		g_set_error (err, rspamd_iconv_error_quark (), EINVAL,
				"cannot open iconv for: %s", in_enc);

		return NULL;
	}

	/* Preallocate for half of characters to be converted */
	outlen = len + len / 2 + 1;
	dst = rspamd_fstring_sized_new (outlen);
	s = input;
	d = dst->str;
	remain = outlen - 1;

	while (inremain > 0 && remain > 0) {
		ret = iconv (ic, &s, &inremain, &d, &remain);
		dst->len = d - dst->str;

		if (ret == (gsize)-1) {
			switch (errno) {
			case E2BIG:
				/* Enlarge string */
				if (inremain > 0) {
					dst = rspamd_fstring_grow (dst, inremain * 2);
					d = dst->str + dst->len;
					remain = dst->allocated - dst->len - 1;
				}
				break;
			case EILSEQ:
			case EINVAL:
				/* Ignore bad characters */
				if (remain > 0 && inremain > 0) {
					*d++ = '?';
					s++;
					inremain --;
					remain --;
				}
				break;
			}
		}
		else if (ret == 0) {
			break;
		}
	}

	*d = '\0';
	*olen = dst->len;
	iconv_close (ic);
	rspamd_mempool_add_destructor (pool,
			(rspamd_mempool_destruct_t)rspamd_fstring_free, dst);
	msg_info_pool ("converted from %s to UTF-8 inlen: %z, outlen: %z",
			in_enc, len, dst->len);

	return dst->str;
}

gboolean
rspamd_mime_to_utf8_byte_array (GByteArray *in,
		GByteArray *out,
		const gchar *enc)
{
	guchar *s, *d;
	gsize outlen, pos;
	iconv_t ic;
	gsize remain, ret, inremain = in->len;
	rspamd_ftok_t charset_tok;

	RSPAMD_FTOK_FROM_STR (&charset_tok, enc);

	if (rspamd_mime_charset_utf_check (&charset_tok, (gchar *)in->data, in->len)) {
		g_byte_array_set_size (out, in->len);
		memcpy (out->data, in->data, out->len);

		return TRUE;
	}

	ic = iconv_open (UTF8_CHARSET, enc);

	if (ic == (iconv_t)-1) {
		return FALSE;
	}

	/* Preallocate for half of characters to be converted */
	outlen = inremain + inremain / 2 + 1;
	g_byte_array_set_size (out, outlen);
	s = in->data;
	d = out->data;
	remain = outlen;

	while (inremain > 0 && remain > 0) {
		ret = iconv (ic, (gchar **)&s, &inremain, (gchar **)&d, &remain);
		out->len = d - out->data;

		if (ret == (gsize)-1) {
			switch (errno) {
			case E2BIG:
				/* Enlarge string */
				if (inremain > 0) {
					pos = outlen;
					outlen += inremain * 2;
					/* May cause reallocate, so store previous len in pos */
					g_byte_array_set_size (out, outlen);
					d = out->data + pos;
					remain = outlen - pos;
				}
				break;
			case EILSEQ:
			case EINVAL:
				/* Ignore bad characters */
				if (remain > 0 && inremain > 0) {
					*d++ = '?';
					s++;
					inremain --;
					remain --;
				}
				break;
			}
		}
		else if (ret == 0) {
			break;
		}
	}

	out->len = d - out->data;
	iconv_close (ic);

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

gboolean
rspamd_mime_charset_utf_check (rspamd_ftok_t *charset,
		gchar *in, gsize len)
{
	if (utf_compatible_re == NULL) {
		utf_compatible_re = rspamd_regexp_new (
				"^(?:utf-?8.*)|(?:us-ascii)|(?:ascii)|(?:ansi)|(?:us)|(?:ISO-8859-1)|"
				"(?:latin.*)|(?:CSASCII)$",
				"i", NULL);
	}

	if (rspamd_regexp_match (utf_compatible_re, charset->begin, charset->len,
			TRUE)) {
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
	const gchar *charset;
	gchar *res_str;
	GByteArray *result_array, *part_content;
	rspamd_ftok_t charset_tok;
	struct rspamd_mime_part *part = text_part->mime_part;

	part_content = rspamd_mempool_alloc0 (task->task_pool, sizeof (GByteArray));
	part_content->data = (guint8 *)text_part->parsed.begin;
	part_content->len = text_part->parsed.len;

	if (task->cfg && task->cfg->raw_mode) {
		SET_PART_RAW (text_part);
		return part_content;
	}

	if (part->ct->charset.len == 0) {
		SET_PART_RAW (text_part);
		return part_content;
	}

	charset = rspamd_mime_detect_charset (&part->ct->charset, task->task_pool);

	if (charset == NULL) {
		msg_info_task ("<%s>: has invalid charset", task->message_id);
		SET_PART_RAW (text_part);

		return part_content;
	}

	RSPAMD_FTOK_FROM_STR (&charset_tok, charset);

	if (rspamd_mime_charset_utf_check (&charset_tok, part_content->data,
			part_content->len)) {
		SET_PART_UTF (text_part);

		return part_content;
	}
	else {
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

			return part_content;
		}
	}

	result_array = rspamd_mempool_alloc (task->task_pool, sizeof (GByteArray));
	result_array->data = res_str;
	result_array->len = write_bytes;
	SET_PART_UTF (text_part);

	return result_array;
}
