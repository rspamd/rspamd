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

#include "mime_headers.h"
#include "smtp_parsers.h"
#include "mime_encoding.h"
#include "libserver/mempool_vars_internal.h"
#include <unicode/utf8.h>

static void
rspamd_mime_header_check_special (struct rspamd_task *task,
		struct rspamd_mime_header *rh)
{
	guint64 h;
	struct received_header *recv;
	const gchar *p, *end;
	gchar *id;

	h = rspamd_icase_hash (rh->name, strlen (rh->name), 0xdeadbabe);

	switch (h) {
	case 0x88705DC4D9D61ABULL:	/* received */
		recv = rspamd_mempool_alloc0 (task->task_pool,
				sizeof (struct received_header));
		recv->hdr = rh;
		rspamd_smtp_received_parse (task, rh->decoded,
				strlen (rh->decoded), recv);
		/* Set flags */
		if (recv->type == RSPAMD_RECEIVED_ESMTPA ||
				recv->type == RSPAMD_RECEIVED_ESMTPSA) {
			recv->flags |= RSPAMD_RECEIVED_FLAG_AUTHENTICATED;
		}
		if (recv->type == RSPAMD_RECEIVED_ESMTPS ||
				recv->type == RSPAMD_RECEIVED_ESMTPSA) {
			recv->flags |= RSPAMD_RECEIVED_FLAG_SSL;
		}

		g_ptr_array_add (task->received, recv);
		rh->type = RSPAMD_HEADER_RECEIVED;
		break;
	case 0x76F31A09F4352521ULL:	/* to */
		task->rcpt_mime = rspamd_email_address_from_mime (task->task_pool,
				rh->decoded, strlen (rh->decoded), task->rcpt_mime);
		rh->type = RSPAMD_HEADER_TO|RSPAMD_HEADER_RCPT|RSPAMD_HEADER_UNIQUE;
		break;
	case 0x7EB117C1480B76ULL:	/* cc */
		task->rcpt_mime = rspamd_email_address_from_mime (task->task_pool,
				rh->decoded, strlen (rh->decoded), task->rcpt_mime);
		rh->type = RSPAMD_HEADER_CC|RSPAMD_HEADER_RCPT|RSPAMD_HEADER_UNIQUE;
		break;
	case 0xE4923E11C4989C8DULL:	/* bcc */
		task->rcpt_mime = rspamd_email_address_from_mime (task->task_pool,
				rh->decoded, strlen (rh->decoded), task->rcpt_mime);
		rh->type = RSPAMD_HEADER_BCC|RSPAMD_HEADER_RCPT|RSPAMD_HEADER_UNIQUE;
		break;
	case 0x41E1985EDC1CBDE4ULL:	/* from */
		task->from_mime = rspamd_email_address_from_mime (task->task_pool,
				rh->decoded, strlen (rh->decoded), task->from_mime);
		rh->type = RSPAMD_HEADER_FROM|RSPAMD_HEADER_SENDER|RSPAMD_HEADER_UNIQUE;
		break;
	case 0x43A558FC7C240226ULL:	/* message-id */ {

		rh->type = RSPAMD_HEADER_MESSAGE_ID|RSPAMD_HEADER_UNIQUE;
		p = rh->decoded;
		end = p + strlen (p);

		if (*p == '<') {
			p ++;

			if (end > p) {
				gchar *d;

				if (*(end - 1) == '>') {
					end --;
				}

				id = rspamd_mempool_alloc (task->task_pool, end - p + 1);
				d = id;

				while (p < end) {
					if (g_ascii_isgraph (*p)) {
						*d++ = *p++;
					}
					else {
						*d++ = '?';
						p++;
					}
				}

				*d = '\0';

				task->message_id = id;
			}
		}

		break;
	}
	case 0xB91D3910358E8212ULL:	/* subject */
		if (task->subject == NULL) {
			task->subject = rh->decoded;
		}
		rh->type = RSPAMD_HEADER_SUBJECT|RSPAMD_HEADER_UNIQUE;
		break;
	case 0xEE4AA2EAAC61D6F4ULL:	/* return-path */
		if (task->from_envelope == NULL) {
			task->from_envelope = rspamd_email_address_from_smtp (rh->decoded,
					strlen (rh->decoded));
		}
		rh->type = RSPAMD_HEADER_RETURN_PATH|RSPAMD_HEADER_UNIQUE;
		break;
	case 0xB9EEFAD2E93C2161ULL:	/* delivered-to */
		if (task->deliver_to == NULL) {
			task->deliver_to = rh->decoded;
		}
		rh->type = RSPAMD_HEADER_DELIVERED_TO;
		break;
	case 0x2EC3BFF3C393FC10ULL: /* date */
	case 0xAC0DDB1A1D214CAULL: /* sender */
	case 0x54094572367AB695ULL: /* in-reply-to */
	case 0x81CD9E9131AB6A9AULL: /* content-type */
	case 0xC39BD9A75AA25B60ULL: /* content-transfer-encoding */
	case 0xB3F6704CB3AD6589ULL: /* references */
		rh->type = RSPAMD_HEADER_UNIQUE;
		break;
	}
}

static void
rspamd_mime_header_add (struct rspamd_task *task,
		GHashTable *target, GQueue *order,
		struct rspamd_mime_header *rh,
		gboolean check_special)
{
	GPtrArray *ar;

	if ((ar = g_hash_table_lookup (target, rh->name)) != NULL) {
		g_ptr_array_add (ar, rh);
		msg_debug_task ("append raw header %s: %s", rh->name, rh->value);
	}
	else {
		ar = g_ptr_array_sized_new (2);
		g_ptr_array_add (ar, rh);
		g_hash_table_insert (target, rh->name, ar);
		msg_debug_task ("add new raw header %s: %s", rh->name, rh->value);
	}

	g_queue_push_tail (order, rh);

	if (check_special) {
		rspamd_mime_header_check_special (task, rh);
	}
}

/* Convert raw headers to a list of struct raw_header * */
void
rspamd_mime_headers_process (struct rspamd_task *task, GHashTable *target,
		GQueue *order,
		const gchar *in, gsize len,
		gboolean check_newlines)
{
	struct rspamd_mime_header *nh = NULL;
	const gchar *p, *c, *end;
	gchar *tmp, *tp;
	gint state = 0, l, next_state = 100, err_state = 100, t_state;
	gboolean valid_folding = FALSE;
	guint nlines_count[RSPAMD_TASK_NEWLINES_MAX];
	guint norder = 0;

	p = in;
	end = p + len;
	c = p;
	memset (nlines_count, 0, sizeof (nlines_count));
	msg_debug_task ("start processing headers");

	while (p < end) {
		/* FSM for processing headers */
		switch (state) {
		case 0:
			/* Begin processing headers */
			if (!g_ascii_isalpha (*p)) {
				/* We have some garbage at the beginning of headers, skip this line */
				state = 100;
				next_state = 0;
			}
			else {
				state = 1;
				c = p;
			}
			break;
		case 1:
			/* We got something like header's name */
			if (*p == ':') {
				nh = rspamd_mempool_alloc0 (task->task_pool,
						sizeof (struct rspamd_mime_header));
				l = p - c;
				tmp = rspamd_mempool_alloc (task->task_pool, l + 1);
				rspamd_strlcpy (tmp, c, l + 1);
				nh->name = tmp;
				nh->empty_separator = TRUE;
				nh->raw_value = c;
				nh->raw_len = p - c; /* Including trailing ':' */
				p++;
				state = 2;
				c = p;
			}
			else if (g_ascii_isspace (*p)) {
				/* Not header but some garbage */
				task->flags |= RSPAMD_TASK_FLAG_BROKEN_HEADERS;
				state = 100;
				next_state = 0;
			}
			else {
				p++;
			}
			break;
		case 2:
			/* We got header's name, so skip any \t or spaces */
			if (*p == '\t') {
				nh->tab_separated = TRUE;
				nh->empty_separator = FALSE;
				p++;
			}
			else if (*p == ' ') {
				nh->empty_separator = FALSE;
				p++;
			}
			else if (*p == '\n' || *p == '\r') {

				if (check_newlines) {
					if (*p == '\n') {
						nlines_count[RSPAMD_TASK_NEWLINES_LF] ++;
					}
					else if (*(p + 1) == '\n') {
						nlines_count[RSPAMD_TASK_NEWLINES_CRLF] ++;
					}
					else {
						nlines_count[RSPAMD_TASK_NEWLINES_CR] ++;
					}
				}

				/* Process folding */
				state = 99;
				l = p - c;
				if (l > 0) {
					tmp = rspamd_mempool_alloc (task->task_pool, l + 1);
					rspamd_strlcpy (tmp, c, l + 1);
					nh->separator = tmp;
				}
				next_state = 3;
				err_state = 5;
				c = p;
			}
			else {
				/* Process value */
				l = p - c;
				if (l >= 0) {
					tmp = rspamd_mempool_alloc (task->task_pool, l + 1);
					rspamd_strlcpy (tmp, c, l + 1);
					nh->separator = tmp;
				}
				c = p;
				state = 3;
			}
			break;
		case 3:
			if (*p == '\r' || *p == '\n') {
				/* Hold folding */
				if (check_newlines) {
					if (*p == '\n') {
						nlines_count[RSPAMD_TASK_NEWLINES_LF] ++;
					}
					else if (*(p + 1) == '\n') {
						nlines_count[RSPAMD_TASK_NEWLINES_CRLF] ++;
					}
					else {
						nlines_count[RSPAMD_TASK_NEWLINES_CR] ++;
					}
				}
				state = 99;
				next_state = 3;
				err_state = 4;
			}
			else if (p + 1 == end) {
				state = 4;
			}
			else {
				p++;
			}
			break;
		case 4:
			/* Copy header's value */
			l = p - c;
			tmp = rspamd_mempool_alloc (task->task_pool, l + 1);
			tp = tmp;
			t_state = 0;
			while (l--) {
				if (t_state == 0) {
					/* Before folding */
					if (*c == '\n' || *c == '\r') {
						t_state = 1;
						c++;
						*tp++ = ' ';
					}
					else {
						*tp++ = *c++;
					}
				}
				else if (t_state == 1) {
					/* Inside folding */
					if (g_ascii_isspace (*c)) {
						c++;
					}
					else {
						t_state = 0;
						*tp++ = *c++;
					}
				}
			}
			/* Strip last space that can be added by \r\n parsing */
			if (*(tp - 1) == ' ') {
				tp--;
			}

			*tp = '\0';
			/* Strip the initial spaces that could also be added by folding */
			while (*tmp != '\0' && g_ascii_isspace (*tmp)) {
				tmp ++;
			}

			if (p + 1 == end) {
				nh->raw_len = end - nh->raw_value;
			}
			else {
				nh->raw_len = p - nh->raw_value;
			}

			nh->value = tmp;

			gboolean broken_utf = FALSE;

			nh->decoded = rspamd_mime_header_decode (task->task_pool,
					nh->value, strlen (tmp), &broken_utf);

			if (broken_utf) {
				task->flags |= RSPAMD_TASK_FLAG_BAD_UNICODE;
			}

			if (nh->decoded == NULL) {
				nh->decoded = "";
			}

			/* We also validate utf8 and replace all non-valid utf8 chars */
			rspamd_mime_charset_utf_enforce (nh->decoded, strlen (nh->decoded));
			nh->order = norder ++;
			rspamd_mime_header_add (task, target, order, nh, check_newlines);
			nh = NULL;
			state = 0;
			break;
		case 5:
			/* Header has only name, no value */
			nh->value = "";
			nh->decoded = "";
			nh->raw_len = p - nh->raw_value;
			nh->order = norder ++;
			rspamd_mime_header_add (task, target, order, nh, check_newlines);
			nh = NULL;
			state = 0;
			break;
		case 99:
			/* Folding state */
			if (p + 1 == end) {
				state = err_state;
			}
			else {
				if (*p == '\r' || *p == '\n') {
					p++;
					valid_folding = FALSE;
				}
				else if (*p == '\t' || *p == ' ') {
					/* Valid folding */
					p++;
					valid_folding = TRUE;
				}
				else {
					if (valid_folding) {
						debug_task ("go to state: %d->%d", state, next_state);
						state = next_state;
					}
					else {
						/* Fall back */
						debug_task ("go to state: %d->%d", state, err_state);
						state = err_state;
					}
				}
			}
			break;
		case 100:
			/* Fail state, skip line */

			if (*p == '\r') {
				if (*(p + 1) == '\n') {
					nlines_count[RSPAMD_TASK_NEWLINES_CRLF] ++;
					p++;
				}
				p++;
				state = next_state;
			}
			else if (*p == '\n') {
				nlines_count[RSPAMD_TASK_NEWLINES_LF] ++;

				if (*(p + 1) == '\r') {
					p++;
				}
				p++;
				state = next_state;
			}
			else if (p + 1 == end) {
				state = next_state;
				p++;
			}
			else {
				p++;
			}
			break;
		}
	}

	if (check_newlines) {
		guint max_cnt = 0;
		gint sel = 0;
		GList *cur;
		rspamd_cryptobox_hash_state_t hs;
		guchar hout[rspamd_cryptobox_HASHBYTES], *hexout;

		for (gint i = 0; i < RSPAMD_TASK_NEWLINES_MAX; i ++) {
			if (nlines_count[i] > max_cnt) {
				max_cnt = nlines_count[i];
				sel = i;
			}
		}

		task->nlines_type = sel;

		cur = order->head;
		rspamd_cryptobox_hash_init (&hs, NULL, 0);

		while (cur) {
			nh = cur->data;

			if (nh->name && nh->type != RSPAMD_HEADER_RECEIVED) {
				rspamd_cryptobox_hash_update (&hs, nh->name, strlen (nh->name));
			}

			cur = g_list_next (cur);
		}

		rspamd_cryptobox_hash_final (&hs, hout);
		hexout = rspamd_mempool_alloc (task->task_pool, sizeof (hout) * 2 + 1);
		hexout[sizeof (hout) * 2] = '\0';
		rspamd_encode_hex_buf (hout, sizeof (hout), hexout,
				sizeof (hout) * 2 + 1);
		rspamd_mempool_set_variable (task->task_pool,
				RSPAMD_MEMPOOL_HEADERS_HASH,
				hexout, NULL);
	}
}

static void
rspamd_mime_header_maybe_save_token (rspamd_mempool_t *pool, GString *out,
		GByteArray *token, GByteArray *decoded_token,
		rspamd_ftok_t *old_charset, rspamd_ftok_t *new_charset)
{
	if (new_charset->len == 0) {
		g_assert_not_reached ();
	}

	if (old_charset->len > 0) {
		if (rspamd_ftok_casecmp (new_charset, old_charset) == 0) {
			rspamd_ftok_t srch;

			/*
			 * Special case for iso-2022-jp:
			 * https://github.com/vstakhov/rspamd/issues/1669
			 */
			RSPAMD_FTOK_ASSIGN (&srch, "iso-2022-jp");

			if (rspamd_ftok_casecmp (new_charset, &srch) != 0) {
				/* We can concatenate buffers, just return */
				return;
			}
		}
	}

	/* We need to flush and decode old token to out string */
	if (rspamd_mime_to_utf8_byte_array (token, decoded_token,
			rspamd_mime_detect_charset (new_charset, pool))) {
		g_string_append_len (out, decoded_token->data, decoded_token->len);
	}

	/* We also reset buffer */
	g_byte_array_set_size (token, 0);
	/* Propagate charset */
	memcpy (old_charset, new_charset, sizeof (*old_charset));
}

static void
rspamd_mime_header_sanity_check (GString *str)
{
	gsize i;
	gchar t;

	for (i = 0; i < str->len; i ++) {
		t = str->str[i];
		if (!((t & 0x80) || g_ascii_isgraph (t))) {
			if (g_ascii_isspace (t)) {
				/* Replace spaces characters with plain space */
				str->str[i] = ' ';
			}
			else {
				str->str[i] = '?';
			}
		}
	}
}

gchar *
rspamd_mime_header_decode (rspamd_mempool_t *pool, const gchar *in,
		gsize inlen, gboolean *invalid_utf)
{
	GString *out;
	const guchar *c, *p, *end;
	const gchar *tok_start = NULL;
	gsize tok_len = 0, pos;
	GByteArray *token = NULL, *decoded;
	rspamd_ftok_t cur_charset = {0, NULL}, old_charset = {0, NULL};
	gint encoding;
	gssize r;
	guint qmarks = 0;
	gchar *ret;
	enum {
		parse_normal = 0,
		got_eqsign,
		got_encoded_start,
		got_more_qmark,
		skip_spaces,
	} state = parse_normal;

	g_assert (in != NULL);

	c = in;
	p = in;
	end = in + inlen;
	out = g_string_sized_new (inlen);
	token = g_byte_array_sized_new (80);
	decoded = g_byte_array_sized_new (122);

	while (p < end) {
		switch (state) {
		case parse_normal:
			if (*p == '=') {
				g_string_append_len (out, c, p - c);
				c = p;
				state = got_eqsign;
			}
			else if (*p >= 128) {
				gint off = 0;
				UChar32 uc;
				/* Unencoded character */
				g_string_append_len (out, c, p - c);
				/* Check if that's valid UTF8 */
				U8_NEXT (p, off, end - p, uc);

				if (uc <= 0) {
					c = p + 1;
					/* 0xFFFD in UTF8 */
					g_string_append_len (out, "   ", 3);
					off = 0;
					U8_APPEND_UNSAFE (out->str + out->len - 3,
							off, 0xfffd);

					if (invalid_utf) {
						*invalid_utf = TRUE;
					}
				}
				else {
					c = p;
					p = p + off;
					continue; /* To avoid p ++ after this block */
				}
			}
			p ++;
			break;
		case got_eqsign:
			if (*p == '?') {
				state = got_encoded_start;
				qmarks = 0;
			}
			else {
				g_string_append_len (out, c, 2);
				c = p + 1;
				state = parse_normal;
			}
			p ++;
			break;
		case got_encoded_start:
			if (*p == '?') {
				state = got_more_qmark;
				qmarks ++;
			}
			p ++;
			break;
		case got_more_qmark:
			if (*p == '=') {
				if (qmarks < 3) {
					state = got_encoded_start;
				}
				/* Finished encoded boundary */
				else if (rspamd_rfc2047_parser (c, p - c + 1, &encoding,
						&cur_charset.begin, &cur_charset.len,
						&tok_start, &tok_len)) {
					/* We have a token, so we can decode it from `encoding` */
					if (token->len > 0) {
						if (old_charset.len == 0) {
							memcpy (&old_charset, &cur_charset,
									sizeof (old_charset));
						}

						rspamd_mime_header_maybe_save_token (pool, out,
								token, decoded,
								&old_charset, &cur_charset);
					}

					qmarks = 0;
					pos = token->len;
					g_byte_array_set_size (token, pos + tok_len);

					if (encoding == RSPAMD_RFC2047_QP) {
						r = rspamd_decode_qp2047_buf (tok_start, tok_len,
								token->data + pos, tok_len);

						if (r != -1) {
							token->len = pos + r;
						}
						else {
							/* Cannot decode qp */
							token->len -= tok_len;
						}
					}
					else {
						if (rspamd_cryptobox_base64_decode (tok_start, tok_len,
								token->data + pos, &tok_len)) {
							token->len = pos + tok_len;
						}
						else {
							/* Cannot decode */
							token->len -= tok_len;
						}
					}

					c = p + 1;
					state = skip_spaces;
				}
				else {
					/* Not encoded-word */
					old_charset.len = 0;

					if (token->len > 0) {
						rspamd_mime_header_maybe_save_token (pool, out,
								token, decoded,
								&old_charset, &cur_charset);
					}

					g_string_append_len (out, c, p - c);
					c = p;
					state = parse_normal;
				}

			}
			else {
				state = got_encoded_start;
			}
			p ++;
			break;
		case skip_spaces:
			if (g_ascii_isspace (*p)) {
				p ++;
			}
			else if (*p == '=' && p < end - 1 && p[1] == '?') {
				/* Next boundary, can glue */
				c = p;
				p += 2;
				state = got_encoded_start;
			}
			else {
				/* Need to save spaces and decoded token */
				if (token->len > 0) {
					old_charset.len = 0;
					rspamd_mime_header_maybe_save_token (pool, out,
							token, decoded,
							&old_charset, &cur_charset);
				}

				g_string_append_len (out, c, p - c);
				c = p;
				state = parse_normal;
			}
			break;
		}
	}

	/* Leftover */
	switch (state) {
	case skip_spaces:
		if (token->len > 0 && cur_charset.len > 0) {
			old_charset.len = 0;
			rspamd_mime_header_maybe_save_token (pool, out,
					token, decoded,
					&old_charset, &cur_charset);
		}
		break;
	default:
		/* Just copy leftover */
		if (p > c) {
			g_string_append_len (out, c, p - c);
		}
		break;
	}

	g_byte_array_free (token, TRUE);
	g_byte_array_free (decoded, TRUE);
	rspamd_mime_header_sanity_check (out);
	ret = g_string_free (out, FALSE);
	rspamd_mempool_add_destructor (pool, g_free, ret);

	return ret;
}

gchar *
rspamd_mime_header_encode (const gchar *in, gsize len)
{
	const gchar *p = in, *end = in + len;
	gchar *out, encode_buf[80 * sizeof (guint32)];
	GString *res;
	gboolean need_encoding = FALSE;

	/* Check if we need to encode */
	while (p < end) {
		if ((((guchar)*p) & 0x80) != 0) {
			need_encoding = TRUE;
			break;
		}
		p ++;
	}

	if (!need_encoding) {
		out = g_malloc (len + 1);
		rspamd_strlcpy (out, in, len + 1);
	}
	else {
		/* Need encode */
		gsize ulen, pos;
		gint r;
		const gchar *prev;
		/* Choose step: =?UTF-8?Q?<qp>?= should be less than 76 chars */
		guint step = (76 - 12) / 3 + 1;

		ulen = g_utf8_strlen (in, len);
		res = g_string_sized_new (len * 2 + 1);
		pos = 0;
		prev = in;
		/* Adjust chunk size for unicode average length */
		step *= 1.0 * ulen / (gdouble)len;

		while (pos < ulen) {
			p = g_utf8_offset_to_pointer (in, pos);

			if (p > prev) {
				/* Encode and print */
				r = rspamd_encode_qp2047_buf (prev, p - prev,
						encode_buf, sizeof (encode_buf));

				if (r != -1) {
					if (res->len > 0) {
						rspamd_printf_gstring (res, " =?UTF-8?Q?%*s?=", r,
								encode_buf);
					}
					else {
						rspamd_printf_gstring (res, "=?UTF-8?Q?%*s?=", r,
								encode_buf);
					}
				}
			}

			pos += MIN (step, ulen - pos);
			prev = p;
		}

		/* Leftover */
		if (prev < end) {
			r = rspamd_encode_qp2047_buf (prev, end - prev,
					encode_buf, sizeof (encode_buf));

			if (r != -1) {
				if (res->len > 0) {
					rspamd_printf_gstring (res, " =?UTF-8?Q?%*s?=", r,
							encode_buf);
				}
				else {
					rspamd_printf_gstring (res, "=?UTF-8?Q?%*s?=", r,
							encode_buf);
				}
			}
		}

		out = g_string_free (res, FALSE);
	}

	return out;
}

gchar *
rspamd_mime_message_id_generate (const gchar *fqdn)
{
	GString *out;
	guint64 rnd, clk;

	out = g_string_sized_new (strlen (fqdn) + 22);
	rnd = ottery_rand_uint64 ();
	clk = rspamd_get_calendar_ticks () * 1e6;

	rspamd_printf_gstring (out, "%*bs.%*bs@%s",
			(gint)sizeof (guint64) - 3, (guchar *)&clk,
			(gint)sizeof (guint64), (gchar *)&rnd,
			fqdn);

	return g_string_free (out, FALSE);
}
