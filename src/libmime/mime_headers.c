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
#include "task.h"

static void
rspamd_mime_header_add (struct rspamd_task *task,
		GHashTable *target, struct rspamd_mime_header *rh)
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
}

/* Convert raw headers to a list of struct raw_header * */
void
rspamd_mime_headers_process (struct rspamd_task *task, GHashTable *target,
		const gchar *in, gsize len, gboolean check_newlines)
{
	struct rspamd_mime_header *new = NULL;
	const gchar *p, *c, *end;
	gchar *tmp, *tp;
	gint state = 0, l, next_state = 100, err_state = 100, t_state;
	gboolean valid_folding = FALSE;
	guint nlines_count[RSPAMD_TASK_NEWLINES_MAX];

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
				new =
					rspamd_mempool_alloc0 (task->task_pool,
						sizeof (struct rspamd_mime_header));
				l = p - c;
				tmp = rspamd_mempool_alloc (task->task_pool, l + 1);
				rspamd_strlcpy (tmp, c, l + 1);
				new->name = tmp;
				new->empty_separator = TRUE;
				new->raw_value = c;
				new->raw_len = p - c; /* Including trailing ':' */
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
				new->tab_separated = TRUE;
				new->empty_separator = FALSE;
				p++;
			}
			else if (*p == ' ') {
				new->empty_separator = FALSE;
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
					new->separator = tmp;
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
					new->separator = tmp;
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
				new->raw_len = end - new->raw_value;
			}
			else {
				new->raw_len = p - new->raw_value;
			}

			new->value = tmp;
			new->decoded = g_mime_utils_header_decode_text (new->value);

			if (new->decoded != NULL) {
				rspamd_mempool_add_destructor (task->task_pool,
						(rspamd_mempool_destruct_t)g_free, new->decoded);
			}
			else {
				new->decoded = "";
			}

			rspamd_mime_header_add (task, target, new);
			state = 0;
			break;
		case 5:
			/* Header has only name, no value */
			new->value = "";
			new->decoded = "";
			rspamd_mime_header_add (task, target, new);
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

		for (gint i = 0; i < RSPAMD_TASK_NEWLINES_MAX; i ++) {
			if (nlines_count[i] > max_cnt) {
				max_cnt = nlines_count[i];
				sel = i;
			}
		}

		task->nlines_type = sel;
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
			/* We can concatenate buffers, just return */
			return;
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

gchar *
rspamd_mime_header_decode (rspamd_mempool_t *pool, const gchar *in,
		gsize inlen)
{
	GString *out;
	const gchar *c, *p, *end, *tok_start = NULL;
	gsize tok_len = 0, pos;
	GByteArray *token = NULL, *decoded;
	rspamd_ftok_t cur_charset = {0, NULL}, old_charset = {0, NULL};
	gint encoding;
	gssize r;
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
	out = rspamd_mempool_alloc0 (pool, sizeof (*out));
	g_string_set_size (out, inlen);
	out->len = 0;
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
			p ++;
			break;
		case got_eqsign:
			if (*p == '?') {
				state = got_encoded_start;
			}
			else {
				g_string_append_len (out, c, 2);
				c = p + 1;
			}
			p ++;
			break;
		case got_encoded_start:
			if (*p == '?') {
				state = got_more_qmark;
			}
			p ++;
			break;
		case got_more_qmark:
			if (*p == '=') {
				/* Finished encoded boundary */
				if (rspamd_rfc2047_parser (c, p - c + 1, &encoding,
						&cur_charset.begin, &cur_charset.len,
						&tok_start, &tok_len)) {
					/* We have a token, so we can decode it from `encoding` */
					if (token->len > 0) {
						rspamd_mime_header_maybe_save_token (pool, out,
								token, decoded,
								&old_charset, &cur_charset);
					}
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
	rspamd_mempool_add_destructor (pool, g_free, out->str);

	return out->str;
}
