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
#include "received.h"
#include "contrib/uthash/utlist.h"
#include "libserver/mempool_vars_internal.h"
#include "libserver/cfg_file.h"
#include "libutil/util.h"
#include <unicode/utf8.h>

KHASH_INIT (rspamd_mime_headers_htb, gchar *,
		struct rspamd_mime_header *, 1,
		rspamd_strcase_hash, rspamd_strcase_equal);

struct rspamd_mime_headers_table {
	khash_t(rspamd_mime_headers_htb) htb;
	ref_entry_t ref;
};

static void
rspamd_mime_header_check_special (struct rspamd_task *task,
		struct rspamd_mime_header *rh)
{
	guint64 h;
	const gchar *p, *end;
	gchar *id;
	gint max_recipients = -1, len;

	if (task->cfg) {
		max_recipients = task->cfg->max_recipients;
	}

	h = rspamd_icase_hash (rh->name, strlen (rh->name), 0xdeadbabe);

	switch (h) {
	case 0x88705DC4D9D61ABULL:	/* received */
		if (rspamd_received_header_parse(task, rh->decoded, strlen (rh->decoded), rh)) {
			rh->flags |= RSPAMD_HEADER_RECEIVED;
		}
		break;
	case 0x76F31A09F4352521ULL:	/* to */
		MESSAGE_FIELD (task, rcpt_mime) = rspamd_email_address_from_mime (task->task_pool,
				rh->value, strlen (rh->value),
				MESSAGE_FIELD (task, rcpt_mime), max_recipients);
		rh->flags |= RSPAMD_HEADER_TO|RSPAMD_HEADER_RCPT|RSPAMD_HEADER_UNIQUE;
		break;
	case 0x7EB117C1480B76ULL:	/* cc */
		MESSAGE_FIELD (task, rcpt_mime) = rspamd_email_address_from_mime (task->task_pool,
				rh->value, strlen (rh->value),
				MESSAGE_FIELD (task, rcpt_mime), max_recipients);
		rh->flags |= RSPAMD_HEADER_CC|RSPAMD_HEADER_RCPT|RSPAMD_HEADER_UNIQUE;
		break;
	case 0xE4923E11C4989C8DULL:	/* bcc */
		MESSAGE_FIELD (task, rcpt_mime) = rspamd_email_address_from_mime (task->task_pool,
				rh->value, strlen (rh->value),
				MESSAGE_FIELD (task, rcpt_mime), max_recipients);
		rh->flags |= RSPAMD_HEADER_BCC|RSPAMD_HEADER_RCPT|RSPAMD_HEADER_UNIQUE;
		break;
	case 0x41E1985EDC1CBDE4ULL:	/* from */
		MESSAGE_FIELD (task, from_mime) = rspamd_email_address_from_mime (task->task_pool,
				rh->value, strlen (rh->value),
				MESSAGE_FIELD (task, from_mime), max_recipients);
		rh->flags |= RSPAMD_HEADER_FROM|RSPAMD_HEADER_SENDER|RSPAMD_HEADER_UNIQUE;
		break;
	case 0x43A558FC7C240226ULL:	/* message-id */ {

		rh->flags = RSPAMD_HEADER_MESSAGE_ID|RSPAMD_HEADER_UNIQUE;
		p = rh->decoded;
		len = rspamd_strip_smtp_comments_inplace(rh->decoded, strlen(p));
		rh->decoded[len] = '\0'; /* Zero terminate after stripping */
		end = p + len;

		if (*p == '<') {
			p++;
		}

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

			MESSAGE_FIELD (task, message_id) = id;
		}

		break;
	}
	case 0xB91D3910358E8212ULL:	/* subject */
		if (MESSAGE_FIELD (task, subject) == NULL) {
			MESSAGE_FIELD (task, subject) = rh->decoded;
		}
		rh->flags = RSPAMD_HEADER_SUBJECT|RSPAMD_HEADER_UNIQUE;
		break;
	case 0xEE4AA2EAAC61D6F4ULL:	/* return-path */
		if (task->from_envelope == NULL) {
			task->from_envelope = rspamd_email_address_from_smtp (rh->decoded,
					strlen (rh->decoded));
		}
		rh->flags = RSPAMD_HEADER_RETURN_PATH|RSPAMD_HEADER_UNIQUE;
		break;
	case 0xB9EEFAD2E93C2161ULL:	/* delivered-to */
		if (task->deliver_to == NULL) {
			task->deliver_to = rh->decoded;
		}
		rh->flags = RSPAMD_HEADER_DELIVERED_TO;
		break;
	case 0x2EC3BFF3C393FC10ULL: /* date */
	case 0xAC0DDB1A1D214CAULL: /* sender */
	case 0x54094572367AB695ULL: /* in-reply-to */
	case 0x81CD9E9131AB6A9AULL: /* content-type */
	case 0xC39BD9A75AA25B60ULL: /* content-transfer-encoding */
	case 0xB3F6704CB3AD6589ULL: /* references */
		rh->flags = RSPAMD_HEADER_UNIQUE;
		break;
	}
}

static void
rspamd_mime_header_add (struct rspamd_task *task,
						khash_t(rspamd_mime_headers_htb) *target,
						struct rspamd_mime_header **order_ptr,
						struct rspamd_mime_header *rh,
						gboolean check_special)
{
	khiter_t k;
	struct rspamd_mime_header *ex;
	int res;

	k = kh_put (rspamd_mime_headers_htb, target, rh->name, &res);

	if (res == 0) {
		ex = kh_value (target, k);
		DL_APPEND (ex, rh);
		msg_debug_task ("append raw header %s: %s", rh->name, rh->value);
	}
	else {
		kh_value (target, k) = rh;
		rh->prev = rh;
		rh->next = NULL;
		msg_debug_task ("add new raw header %s: %s", rh->name, rh->value);
	}

	LL_PREPEND2 (*order_ptr, rh, ord_next);

	if (check_special) {
		rspamd_mime_header_check_special (task, rh);
	}
}


/* Convert raw headers to a list of struct raw_header * */
void
rspamd_mime_headers_process (struct rspamd_task *task,
		struct rspamd_mime_headers_table *target,
		struct rspamd_mime_header **order_ptr,
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
				rspamd_null_safe_copy (c, l, tmp, l + 1);
				nh->name = tmp;
				nh->flags |= RSPAMD_HEADER_EMPTY_SEPARATOR;
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
				nh->flags &= ~RSPAMD_HEADER_EMPTY_SEPARATOR;
				nh->flags |= RSPAMD_HEADER_TAB_SEPARATED;
				p++;
			}
			else if (*p == ' ') {
				nh->flags &= ~RSPAMD_HEADER_EMPTY_SEPARATOR;
				p++;
			}
			else if (*p == '\n' || *p == '\r') {

				if (check_newlines) {
					if (*p == '\n') {
						nlines_count[RSPAMD_TASK_NEWLINES_LF] ++;
					}
					else if (p + 1 < end && *(p + 1) == '\n') {
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
					rspamd_null_safe_copy (c, l, tmp, l + 1);
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
					rspamd_null_safe_copy (c, l, tmp, l + 1);
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
					else if (p + 1 < end && *(p + 1) == '\n') {
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

			/*
			 * XXX:
			 * The original decision to use here null terminated
			 * strings was extremely poor!
			 */
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
						if (*c != '\0') {
							*tp++ = *c++;
						}
						else {
							c++;
						}
					}
				}
				else if (t_state == 1) {
					/* Inside folding */
					if (g_ascii_isspace (*c)) {
						c++;
					}
					else {
						t_state = 0;
						if (*c != '\0') {
							*tp++ = *c++;
						}
						else {
							c++;
						}
					}
				}
			}
			/* Strip last space that can be added by \r\n parsing */
			if (tp > tmp && *(tp - 1) == ' ') {
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
				/* As we strip comments in place... */
				nh->decoded = rspamd_mempool_strdup (task->task_pool, "");
			}

			/* We also validate utf8 and replace all non-valid utf8 chars */
			rspamd_mime_charset_utf_enforce (nh->decoded, strlen (nh->decoded));
			nh->order = norder ++;
			rspamd_mime_header_add (task, &target->htb, order_ptr, nh, check_newlines);
			nh = NULL;
			state = 0;
			break;
		case 5:
			/* Header has only name, no value */
			nh->value = rspamd_mempool_strdup (task->task_pool, "");;
			nh->decoded = rspamd_mempool_strdup (task->task_pool, "");;
			nh->raw_len = p - nh->raw_value;
			nh->order = norder ++;
			rspamd_mime_header_add (task, &target->htb, order_ptr, nh, check_newlines);
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
				if (p + 1 < end && *(p + 1) == '\n') {
					nlines_count[RSPAMD_TASK_NEWLINES_CRLF] ++;
					p++;
				}
				p++;
				state = next_state;
			}
			else if (*p == '\n') {
				nlines_count[RSPAMD_TASK_NEWLINES_LF] ++;

				if (p + 1 < end && *(p + 1) == '\r') {
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

	/* Since we have prepended headers, we need to reverse the list to get the actual order */
	LL_REVERSE (*order_ptr);

	if (check_newlines) {
		guint max_cnt = 0;
		gint sel = 0;
		rspamd_cryptobox_hash_state_t hs;
		guchar hout[rspamd_cryptobox_HASHBYTES], *hexout;

		for (gint i = RSPAMD_TASK_NEWLINES_CR; i < RSPAMD_TASK_NEWLINES_MAX; i ++) {
			if (nlines_count[i] > max_cnt) {
				max_cnt = nlines_count[i];
				sel = i;
			}
		}

		MESSAGE_FIELD (task, nlines_type) = sel;

		rspamd_cryptobox_hash_init (&hs, NULL, 0);

		LL_FOREACH (*order_ptr, nh) {
			if (nh->name && nh->flags != RSPAMD_HEADER_RECEIVED) {
				rspamd_cryptobox_hash_update (&hs, nh->name, strlen (nh->name));
			}
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
rspamd_mime_header_maybe_save_token (rspamd_mempool_t *pool,
									 GString *out,
									 GByteArray *token,
									 GByteArray *decoded_token,
									 rspamd_ftok_t *old_charset,
									 rspamd_ftok_t *new_charset)
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
	if (rspamd_mime_to_utf8_byte_array (token, decoded_token, pool,
			rspamd_mime_detect_charset (new_charset, pool))) {
		g_string_append_len (out, decoded_token->data, decoded_token->len);
	}

	/* We also reset buffer */
	g_byte_array_set_size (token, 0);
	/*
	 * Propagate charset
	 *
	 * Here are dragons: we save the original charset to allow buffers concat
	 * in the condition at the beginning of the function.
	 * However, it will likely cause unnecessary calls for
	 * `rspamd_mime_detect_charset` which could be relatively expensive.
	 * But we ignore that for now...
	 */
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
				g_string_append_len (out, c, 1);
				c = p;
				state = parse_normal;
				continue; /* Deal with == case */
			}
			p ++;
			break;
		case got_encoded_start:
			if (*p == '?') {
				state = got_more_qmark;
				qmarks ++;

				/* Skip multiple ? signs */
				p ++;
				while (p < end && *p == '?') {
					p ++;
				}

				continue;
			}
			p ++;
			break;
		case got_more_qmark:
			if (*p == '=') {
				if (qmarks < 3) {
					state = got_encoded_start;
				}
				else {
					/* Finished encoded boundary */
					if (*c == '"') {
						/* Quoted string, non-RFC conformant but used by retards */
						c ++;
					}
					if (rspamd_rfc2047_parser (c, p - c + 1, &encoding,
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
							} else {
								/* Cannot decode qp */
								token->len -= tok_len;
							}
						} else {
							if (rspamd_cryptobox_base64_decode (tok_start, tok_len,
									token->data + pos, &tok_len)) {
								token->len = pos + tok_len;
							} else {
								/* Cannot decode */
								token->len -= tok_len;
							}
						}

						c = p + 1;
						state = skip_spaces;
					} else {
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
				} /* qmarks >= 3 */
			} /* p == '=' */
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
	rspamd_mempool_notify_alloc (pool, out->len);
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

struct rspamd_mime_header *
rspamd_message_get_header_from_hash (struct rspamd_mime_headers_table *hdrs,
									 const gchar *field,
									 gboolean need_modified)
{
	khiter_t k;
	khash_t(rspamd_mime_headers_htb) *htb = &hdrs->htb;
	struct rspamd_mime_header *hdr;

	if (htb) {
		k = kh_get (rspamd_mime_headers_htb, htb, (gchar *) field);

		if (k == kh_end (htb)) {
			return NULL;
		}

		hdr = kh_value (htb, k);

		if (!need_modified) {
			if (hdr->flags & RSPAMD_HEADER_NON_EXISTING) {
				return NULL;
			}

			return hdr;
		}
		else {
			if (hdr->flags & RSPAMD_HEADER_MODIFIED) {
				return hdr->modified_chain;
			}

			return hdr;
		}
	}

	return NULL;
}

struct rspamd_mime_header *
rspamd_message_get_header_array (struct rspamd_task *task, const gchar *field,
		gboolean need_modified)
{
	return rspamd_message_get_header_from_hash(
			MESSAGE_FIELD_CHECK (task, raw_headers),
			field, need_modified);
}

gsize
rspamd_mime_headers_count (struct rspamd_mime_headers_table *hdrs)
{
	if (hdrs) {
		return kh_size (&hdrs->htb);
	}

	return 0;
}

bool
rspamd_mime_headers_foreach(const struct rspamd_mime_headers_table *hdrs,
								 rspamd_hdr_traverse_func_t func, void *ud)
{
	const gchar *name;
	struct rspamd_mime_header *hdr;

	kh_foreach(&hdrs->htb, name, hdr, {
		if (!func(name, hdr, ud)) {
			return false;
		}
	});

	return true;
}

static void
rspamd_message_headers_dtor (struct rspamd_mime_headers_table *hdrs)
{
	if (hdrs) {
		kfree (hdrs->htb.keys);
		kfree (hdrs->htb.vals);
		kfree (hdrs->htb.flags);
		g_free (hdrs);
	}
}

struct rspamd_mime_headers_table *
rspamd_message_headers_ref (struct rspamd_mime_headers_table *hdrs)
{
	REF_RETAIN (hdrs);

	return hdrs;
}

void
rspamd_message_headers_unref (struct rspamd_mime_headers_table *hdrs)
{
	REF_RELEASE (hdrs);
}

struct rspamd_mime_headers_table *
rspamd_message_headers_new (void)
{
	struct rspamd_mime_headers_table *nhdrs;

	nhdrs = g_malloc0 (sizeof (*nhdrs));
	REF_INIT_RETAIN (nhdrs, rspamd_message_headers_dtor);

	return nhdrs;
}

void
rspamd_message_set_modified_header (struct rspamd_task *task,
									struct rspamd_mime_headers_table *hdrs,
									const gchar *hdr_name,
									const ucl_object_t *obj)
{
	khiter_t k;
	khash_t(rspamd_mime_headers_htb) *htb = &hdrs->htb;
	struct rspamd_mime_header *hdr_elt, *existing_chain;
	int i;

	if (htb) {
		k = kh_get (rspamd_mime_headers_htb, htb, (gchar *)hdr_name);

		if (k == kh_end (htb)) {
			hdr_elt = rspamd_mempool_alloc0 (task->task_pool, sizeof (*hdr_elt));

			hdr_elt->flags |= RSPAMD_HEADER_MODIFIED|RSPAMD_HEADER_NON_EXISTING;
			hdr_elt->name = rspamd_mempool_strdup (task->task_pool, hdr_name);

			int r;
			k = kh_put (rspamd_mime_headers_htb, htb, hdr_elt->name, &r);

			kh_value (htb, k) = hdr_elt;
		}
		else {
			hdr_elt = kh_value (htb, k);
		}
	}
	else {
		/* No hash, no modification */
		msg_err_task ("internal error: calling for set_modified_header for no headers");
		return;
	}

	if (hdr_elt->flags & RSPAMD_HEADER_MODIFIED) {
		existing_chain = hdr_elt->modified_chain;
	}
	else {
		existing_chain = hdr_elt;
	}

	const ucl_object_t *elt, *cur;
	ucl_object_iter_t it;

	/* First, deal with removed headers, copying the relevant headers with remove flag */
	elt = ucl_object_lookup (obj, "remove");

	/*
	 * remove:  {1, 2 ...}
	 * where number is the header's position starting from '1'
	 */
	if (elt && ucl_object_type (elt) == UCL_ARRAY) {
		/* First, use a temporary array to keep all headers */
		GPtrArray *existing_ar = g_ptr_array_new ();
		struct rspamd_mime_header *cur_hdr;

		/* Exclude removed headers */
		LL_FOREACH (existing_chain, cur_hdr) {
			if (!(cur_hdr->flags & RSPAMD_HEADER_REMOVED)) {
				g_ptr_array_add (existing_ar, cur_hdr);
			}
		}

		it = NULL;

		while ((cur = ucl_object_iterate (elt, &it, true)) != NULL) {
			if (ucl_object_type (cur) == UCL_INT) {
				int ord = ucl_object_toint (cur);

				if (ord == 0) {
					/* Remove all headers in the existing chain */
					PTR_ARRAY_FOREACH (existing_ar, i, cur_hdr) {
						cur_hdr->flags |= RSPAMD_HEADER_MODIFIED|RSPAMD_HEADER_REMOVED;
					}
				}
				else if (ord > 0) {
					/* Start from the top */

					if (ord <= existing_ar->len) {
						cur_hdr = g_ptr_array_index (existing_ar, ord - 1);
						cur_hdr->flags |= RSPAMD_HEADER_MODIFIED|RSPAMD_HEADER_REMOVED;
					}
				}
				else {
					/* Start from the bottom; ord < 0 */
					if ((-ord) <= existing_ar->len) {
						cur_hdr = g_ptr_array_index (existing_ar, existing_ar->len + ord);
						cur_hdr->flags |= RSPAMD_HEADER_MODIFIED|RSPAMD_HEADER_REMOVED;
					}
				}
			}
		}

		/*
		 * Next, we return all headers modified to the existing chain
		 * This implies an additional copy of all structures but is safe enough to
		 * deal with it
		 */
		hdr_elt->flags |= RSPAMD_HEADER_MODIFIED;
		hdr_elt->modified_chain = NULL;
		gint new_chain_length = 0;

		PTR_ARRAY_FOREACH (existing_ar, i, cur_hdr) {
			if (!(cur_hdr->flags & RSPAMD_HEADER_REMOVED)) {
				struct rspamd_mime_header *nhdr = rspamd_mempool_alloc (
						task->task_pool, sizeof (*nhdr));
				memcpy (nhdr, cur_hdr, sizeof (*nhdr));
				nhdr->modified_chain = NULL;
				nhdr->prev = NULL;
				nhdr->next = NULL;
				nhdr->ord_next = NULL;

				DL_APPEND (hdr_elt->modified_chain, nhdr);
				new_chain_length ++;
			}
		}

		g_ptr_array_free (existing_ar, TRUE);

		/* End of headers removal logic */
	}

	/* We can now deal with headers additions */
	elt = ucl_object_lookup (obj, "add");
	if (elt && ucl_object_type (elt) == UCL_ARRAY) {
		if (!(hdr_elt->flags & RSPAMD_HEADER_MODIFIED)) {
			/* Copy the header itself to the modified chain */
			struct rspamd_mime_header *nhdr;
			hdr_elt->flags |= RSPAMD_HEADER_MODIFIED;
			nhdr = rspamd_mempool_alloc (
					task->task_pool, sizeof (*nhdr));
			memcpy (nhdr, hdr_elt, sizeof (*hdr_elt));
			nhdr->modified_chain = NULL;
			nhdr->next = NULL;
			nhdr->ord_next = NULL;
			nhdr->prev = nhdr;
			hdr_elt->modified_chain = nhdr;
		}

		/*
		 * add:  {{1, "foo"}, {-1, "bar"} ...}
		 * where number is the header's position starting from '1'
		 */
		it = NULL;

		while ((cur = ucl_object_iterate (elt, &it, true)) != NULL) {
			if (ucl_object_type (cur) == UCL_ARRAY) {
				const ucl_object_t *order = ucl_array_find_index (cur, 0),
					*value = ucl_array_find_index (cur, 1);

				if (order && value &&
					(ucl_object_type (order) == UCL_INT &&
					 ucl_object_type (value) == UCL_STRING)) {
					int ord = ucl_object_toint (order);
					const char *raw_value;
					gsize raw_len;

					raw_value = ucl_object_tolstring (value, &raw_len);

					if (raw_len == 0) {
						continue;
					}

					struct rspamd_mime_header *nhdr = rspamd_mempool_alloc0 (
							task->task_pool, sizeof (*nhdr));

					nhdr->flags |= RSPAMD_HEADER_ADDED;
					nhdr->name = hdr_elt->name;
					nhdr->value = rspamd_mempool_alloc (task->task_pool,
							raw_len + 1);
					nhdr->raw_len = rspamd_strlcpy (nhdr->value, raw_value,
							raw_len + 1);
					nhdr->raw_value = nhdr->value;
					nhdr->decoded = rspamd_mime_header_decode (task->task_pool,
							raw_value, raw_len, NULL);

					/* Now find a position to insert a value */
					struct rspamd_mime_header **pos = &hdr_elt->modified_chain;

					if (ord == 0) {
						DL_PREPEND (hdr_elt->modified_chain, nhdr);
					}
					else if (ord == -1) {
						DL_APPEND (hdr_elt->modified_chain, nhdr);
					}
					else if (ord > 0) {
						while (ord > 0 && (*pos)) {
							ord --;
							pos = &((*pos)->next);
						}
						if (*pos) {
							/* pos is &(elt)->next */
							nhdr->next = (*pos);
							nhdr->prev = (*pos)->prev;
							(*pos)->prev = nhdr;
							*pos = nhdr;
						}
						else {
							/* Last element */
							DL_APPEND (*pos, nhdr);
						}
					}
					else {
						/* NYI: negative order is not defined */
						msg_err_task ("internal error: calling for set_modified_header "
									  "with negative add order header");
					}
				}
				else {
					msg_err_task ("internal error: calling for set_modified_header "
								  "with invalid header");
				}
			}
		}
	}
}

gsize
rspamd_strip_smtp_comments_inplace (gchar *input, gsize len)
{
	enum parser_state {
		parse_normal,
		parse_obrace,
		parse_comment,
		parse_quoted_copy,
		parse_quoted_ignore,
	} state = parse_normal, next_state = parse_normal;
	gchar *d = input, *end = input + len, *start = input;
	gchar t;
	int obraces = 0, ebraces = 0;

	while (input < end) {
		t = *input;
		switch (state) {
		case parse_normal:
			if (t == '(') {
				state = parse_obrace;
			}
			else if (t == '\\') {
				state = parse_quoted_copy;
				next_state = parse_normal;
			}
			else {
				*d++ = t;
			}
			input ++;
			break;
		case parse_obrace:
			obraces ++;
			if (t == '(') {
				obraces ++;
			}
			else if (t == ')') {
				ebraces ++;

				if (obraces == ebraces) {
					obraces = 0;
					ebraces = 0;
					state = parse_normal;
				}
			}
			else if (t == '\\') {
				state = parse_quoted_ignore;
				next_state = parse_comment;
			}
			else {
				state = parse_comment;
			}
			input ++;
			break;
		case parse_comment:
			if (t == '(') {
				state = parse_obrace;
			}
			else if (t == ')') {
				ebraces ++;

				if (obraces == ebraces) {
					obraces = 0;
					ebraces = 0;
					state = parse_normal;
				}
			}
			else if (t == '\\') {
				state = parse_quoted_ignore;
				next_state = parse_comment;
			}
			input ++;
			break;
		case parse_quoted_copy:
			*d++ = t;
			state = next_state;
			input ++;
			break;
		case parse_quoted_ignore:
			state = next_state;
			input ++;
			break;
		}
	}

	return (d - start);
}