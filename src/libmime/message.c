/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
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

#include "config.h"
#include "util.h"
#include "main.h"
#include "message.h"
#include "cfg_file.h"
#include "html.h"
#include "images.h"
#include "utlist.h"

#define RECURSION_LIMIT 30
#define UTF8_CHARSET "UTF-8"

GByteArray *
strip_html_tags (struct rspamd_task *task,
	rspamd_mempool_t * pool,
	struct mime_text_part *part,
	GByteArray * src,
	gint *stateptr)
{
	uint8_t *p, *rp, *tbegin = NULL, *end, c, lc;
	gint br, i = 0, depth = 0, in_q = 0;
	gint state = 0;
	GByteArray *buf;
	GNode *level_ptr = NULL;
	gboolean erase = FALSE;

	if (stateptr)
		state = *stateptr;

	buf = g_byte_array_sized_new (src->len);
	g_byte_array_append (buf, src->data, src->len);

	c = *src->data;
	lc = '\0';
	p = src->data;
	rp = buf->data;
	end = src->data + src->len;
	br = 0;

	while (i < (gint)src->len) {
		switch (c) {
		case '\0':
			break;
		case '<':
			if (g_ascii_isspace (*(p + 1))) {
				goto reg_char;
			}
			if (state == 0) {
				lc = '<';
				tbegin = p + 1;
				state = 1;
			}
			else if (state == 1) {
				/* Opening bracket without closing one */
				p--;
				while (g_ascii_isspace (*p) && p > src->data) {
					p--;
				}
				p++;
				goto unbreak_tag;
			}
			break;

		case '(':
			if (state == 2) {
				if (lc != '"' && lc != '\'') {
					lc = '(';
					br++;
				}
			}
			else if (state == 0 && !erase) {
				*(rp++) = c;
			}
			break;

		case ')':
			if (state == 2) {
				if (lc != '"' && lc != '\'') {
					lc = ')';
					br--;
				}
			}
			else if (state == 0 && !erase) {
				*(rp++) = c;
			}
			break;

		case '>':
			if (depth) {
				depth--;
				break;
			}

			if (in_q) {
				break;
			}
unbreak_tag:
			switch (state) {
			case 1:         /* HTML/XML */
				lc = '>';
				in_q = state = 0;
				erase = !add_html_node (task,
						pool,
						part,
						tbegin,
						p - tbegin,
						end - tbegin,
						&level_ptr);
				break;

			case 2:         /* PHP */
				if (!br && lc != '\"' && *(p - 1) == '?') {
					in_q = state = 0;
				}
				break;

			case 3:
				in_q = state = 0;
				break;

			case 4:         /* JavaScript/CSS/etc... */
				if (p >= src->data + 2 && *(p - 1) == '-' && *(p - 2) == '-') {
					in_q = state = 0;
				}
				break;

			default:
				if (!erase) {
					*(rp++) = c;
				}
				break;
			}
			break;

		case '"':
		case '\'':
			if (state == 2 && *(p - 1) != '\\') {
				if (lc == c) {
					lc = '\0';
				}
				else if (lc != '\\') {
					lc = c;
				}
			}
			else if (state == 0 && !erase) {
				*(rp++) = c;
			}
			if (state && p != src->data && *(p - 1) != '\\' &&
				(!in_q || *p == in_q)) {
				if (in_q) {
					in_q = 0;
				}
				else {
					in_q = *p;
				}
			}
			break;

		case '!':
			/* JavaScript & Other HTML scripting languages */
			if (state == 1 && *(p - 1) == '<') {
				state = 3;
				lc = c;
			}
			else {
				if (state == 0 && !erase) {
					*(rp++) = c;
				}
			}
			break;

		case '-':
			if (state == 3 && p >= src->data + 2 && *(p - 1) == '-' &&
				*(p - 2) == '!') {
				state = 4;
			}
			else {
				goto reg_char;
			}
			break;

		case '?':

			if (state == 1 && *(p - 1) == '<') {
				br = 0;
				state = 2;
				break;
			}

		case 'E':
		case 'e':
			/* !DOCTYPE exception */
			if (state == 3 && p > src->data + 6
				&& g_ascii_tolower (*(p - 1)) == 'p'
				&& g_ascii_tolower (*(p - 2)) == 'y'
				&& g_ascii_tolower (*(p - 3)) == 't' &&
				g_ascii_tolower (*(p - 4)) == 'c' &&
				g_ascii_tolower (*(p - 5)) == 'o' &&
				g_ascii_tolower (*(p - 6)) == 'd') {
				state = 1;
				break;
			}
		/* fall-through */

		case 'l':

			/* swm: If we encounter '<?xml' then we shouldn't be in
			 * state == 2 (PHP). Switch back to HTML.
			 */

			if (state == 2 && p > src->data + 2 && *(p - 1) == 'm' &&
				*(p - 2) == 'x') {
				state = 1;
				break;
			}

		/* fall-through */
		default:
reg_char:
			if (state == 0 && !erase) {
				*(rp++) = c;
			}
			break;
		}
		i++;
		if (i < (gint)src->len) {
			c = *(++p);
		}
	}
	if (rp < buf->data + src->len) {
		*rp = '\0';
		g_byte_array_set_size (buf, rp - buf->data);
	}

	/* Check tag balancing */
	if (level_ptr && level_ptr->data != NULL) {
		part->is_balanced = FALSE;
	}

	if (stateptr) {
		*stateptr = state;
	}

	return buf;
}

static void
parse_qmail_recv (rspamd_mempool_t * pool,
	gchar *line,
	struct received_header *r)
{
	gchar *s, *p, t;

	/* We are interested only with received from network headers */
	if ((p = strstr (line, "from network")) == NULL) {
		r->is_error = 2;
		return;
	}

	p += sizeof ("from network") - 1;
	while (g_ascii_isspace (*p) || *p == '[') {
		p++;
	}
	/* format is ip/host */
	s = p;
	if (*p) {
		while (g_ascii_isdigit (*++p) || *p == '.') ;
		if (*p != '/') {
			r->is_error = 1;
			return;
		}
		else {
			*p = '\0';
			r->real_ip = rspamd_mempool_strdup (pool, s);
			*p = '/';
			/* Now try to parse hostname */
			s = ++p;
			while (g_ascii_isalnum (*p) || *p == '.' || *p == '-' || *p ==
				'_') {
				p++;
			}
			t = *p;
			*p = '\0';
			r->real_hostname = rspamd_mempool_strdup (pool, s);
			*p = t;
		}
	}
}

static void
parse_recv_header (rspamd_mempool_t * pool,
	gchar *line,
	struct received_header *r)
{
	gchar *p, *s, t, **res = NULL;
	enum {
		RSPAMD_RECV_STATE_INIT = 0,
		RSPAMD_RECV_STATE_FROM,
		RSPAMD_RECV_STATE_IP_BLOCK,
		RSPAMD_RECV_STATE_BRACES_BLOCK,
		RSPAMD_RECV_STATE_BY_BLOCK,
		RSPAMD_RECV_STATE_PARSE_IP,
		RSPAMD_RECV_STATE_SKIP_SPACES,
		RSPAMD_RECV_STATE_ERROR
	}                               state = RSPAMD_RECV_STATE_INIT,
		next_state = RSPAMD_RECV_STATE_INIT;
	gboolean is_exim = FALSE;

	g_strstrip (line);
	p = line;
	s = line;

	while (*p) {
		switch (state) {
		/* Initial state, search for from */
		case RSPAMD_RECV_STATE_INIT:
			if (*p == 'f' || *p == 'F') {
				if (g_ascii_tolower (*++p) == 'r' && g_ascii_tolower (*++p) ==
					'o' && g_ascii_tolower (*++p) == 'm') {
					p++;
					state = RSPAMD_RECV_STATE_SKIP_SPACES;
					next_state = RSPAMD_RECV_STATE_FROM;
				}
			}
			else if (g_ascii_tolower (*p) == 'b' &&
				g_ascii_tolower (*(p + 1)) == 'y') {
				state = RSPAMD_RECV_STATE_IP_BLOCK;
			}
			else {
				/* This can be qmail header, parse it separately */
				parse_qmail_recv (pool, line, r);
				return;
			}
			break;
		/* Read hostname */
		case RSPAMD_RECV_STATE_FROM:
			if (*p == '[') {
				/* This should be IP address */
				res = &r->from_ip;
				state = RSPAMD_RECV_STATE_PARSE_IP;
				next_state = RSPAMD_RECV_STATE_IP_BLOCK;
				s = ++p;
			}
			else if (g_ascii_isalnum (*p) || *p == '.' || *p == '-' || *p ==
				'_') {
				p++;
			}
			else {
				t = *p;
				*p = '\0';
				r->from_hostname = rspamd_mempool_strdup (pool, s);
				*p = t;
				state = RSPAMD_RECV_STATE_SKIP_SPACES;
				next_state = RSPAMD_RECV_STATE_IP_BLOCK;
			}
			break;
		/* Try to extract additional info */
		case RSPAMD_RECV_STATE_IP_BLOCK:
			/* Try to extract ip or () info or by */
			if (g_ascii_tolower (*p) == 'b' && g_ascii_tolower (*(p + 1)) ==
				'y') {
				p += 2;
				/* Skip spaces after by */
				state = RSPAMD_RECV_STATE_SKIP_SPACES;
				next_state = RSPAMD_RECV_STATE_BY_BLOCK;
			}
			else if (*p == '(') {
				state = RSPAMD_RECV_STATE_SKIP_SPACES;
				next_state = RSPAMD_RECV_STATE_BRACES_BLOCK;
				p++;
			}
			else if (*p == '[') {
				/* Got ip before '(' so extract it */
				s = ++p;
				res = &r->from_ip;
				state = RSPAMD_RECV_STATE_PARSE_IP;
				next_state = RSPAMD_RECV_STATE_IP_BLOCK;
			}
			else {
				p++;
			}
			break;
		/* We are in () block. Here can be found real hostname and real ip, this is written by some MTA */
		case RSPAMD_RECV_STATE_BRACES_BLOCK:
			/* End of block */
			if (g_ascii_isalnum (*p) || *p == '.' || *p == '-' ||
				*p == '_' || *p == ':') {
				p++;
			}
			else if (*p == '[') {
				s = ++p;
				state = RSPAMD_RECV_STATE_PARSE_IP;
				res = &r->real_ip;
				next_state = RSPAMD_RECV_STATE_BRACES_BLOCK;
			}
			else {
				if (p > s) {
					/* Got some real hostname */
					/* check whether it is helo or p is not space symbol */
					if (!g_ascii_isspace (*p) || *(p + 1) != '[') {
						/* Exim style ([ip]:port helo=hostname) */
						if (*s == ':' && (g_ascii_isspace (*p) || *p == ')')) {
							/* Ip ending */
							is_exim = TRUE;
							state = RSPAMD_RECV_STATE_SKIP_SPACES;
							next_state = RSPAMD_RECV_STATE_BRACES_BLOCK;
						}
						else if (p - s == 4 && memcmp (s, "helo=", 5) == 0) {
							p++;
							is_exim = TRUE;
							if (r->real_hostname == NULL && r->from_hostname !=
								NULL) {
								r->real_hostname = r->from_hostname;
							}
							s = p;
							while (*p != ')' && !g_ascii_isspace (*p) && *p !=
								'\0') {
								p++;
							}
							if (p > s) {
								r->from_hostname = rspamd_mempool_alloc (pool,
										p - s + 1);
								rspamd_strlcpy (r->from_hostname, s, p - s + 1);
							}
						}
						else if (p - s == 4 && memcmp (s, "port=", 5) == 0) {
							p++;
							is_exim = TRUE;
							while (g_ascii_isdigit (*p)) {
								p++;
							}
							state = RSPAMD_RECV_STATE_SKIP_SPACES;
							next_state = RSPAMD_RECV_STATE_BRACES_BLOCK;
						}
						else if (*p == '=' && is_exim) {
							/* Just skip unknown pairs */
							p++;
							while (!g_ascii_isspace (*p) && *p != ')' && *p !=
								'\0') {
								p++;
							}
							state = RSPAMD_RECV_STATE_SKIP_SPACES;
							next_state = RSPAMD_RECV_STATE_BRACES_BLOCK;
						}
						else {
							/* skip all  */
							while (*p++ != ')' && *p != '\0') ;
							state = RSPAMD_RECV_STATE_IP_BLOCK;
						}
					}
					else {
						/* Postfix style (hostname [ip]) */
						t = *p;
						*p = '\0';
						r->real_hostname = rspamd_mempool_strdup (pool, s);
						*p = t;
						/* Now parse ip */
						p += 2;
						s = p;
						res = &r->real_ip;
						state = RSPAMD_RECV_STATE_PARSE_IP;
						next_state = RSPAMD_RECV_STATE_BRACES_BLOCK;
						continue;
					}
					if (*p == ')') {
						p++;
						state = RSPAMD_RECV_STATE_SKIP_SPACES;
						next_state = RSPAMD_RECV_STATE_IP_BLOCK;
					}
				}
				else if (*p == ')') {
					p++;
					state = RSPAMD_RECV_STATE_SKIP_SPACES;
					next_state = RSPAMD_RECV_STATE_IP_BLOCK;
				}
				else {
					r->is_error = 1;
					return;
				}
			}
			break;
		/* Got by word */
		case RSPAMD_RECV_STATE_BY_BLOCK:
			/* Here can be only hostname */
			if ((g_ascii_isalnum (*p) || *p == '.' || *p == '-'
				|| *p == '_') && p[1] != '\0') {
				p++;
			}
			else {
				/* We got something like hostname */
				if (p[1] != '\0') {
					t = *p;
					*p = '\0';
					r->by_hostname = rspamd_mempool_strdup (pool, s);
					*p = t;
				}
				else {
					r->by_hostname = rspamd_mempool_strdup (pool, s);
				}
				/* Now end of parsing */
				if (is_exim) {
					/* Adjust for exim received */
					if (r->real_ip == NULL && r->from_ip != NULL) {
						r->real_ip = r->from_ip;
					}
					else if (r->from_ip == NULL && r->real_ip != NULL) {
						r->from_ip = r->real_ip;
						if (r->real_hostname == NULL && r->from_hostname !=
							NULL) {
							r->real_hostname = r->from_hostname;
						}
					}
				}
				return;
			}
			break;

		/* Extract ip */
		case RSPAMD_RECV_STATE_PARSE_IP:
			while (g_ascii_isxdigit (*p) || *p == '.' || *p == ':') {
				p++;
			}
			if (*p != ']') {
				/* Not an ip in fact */
				state = RSPAMD_RECV_STATE_SKIP_SPACES;
				p++;
			}
			else {
				*p = '\0';
				*res = rspamd_mempool_strdup (pool, s);
				*p = ']';
				p++;
				state = RSPAMD_RECV_STATE_SKIP_SPACES;
			}
			break;

		/* Skip spaces */
		case RSPAMD_RECV_STATE_SKIP_SPACES:
			if (!g_ascii_isspace (*p)) {
				state = next_state;
				s = p;
			}
			else {
				p++;
			}
			break;
		default:
			r->is_error = 1;
			return;
			break;
		}
	}

	r->is_error = 1;
	return;
}

static void
append_raw_header (struct rspamd_task *task, struct raw_header *rh)
{
	struct raw_header *lp;

	rh->next = NULL;
	rh->prev = rh;
	if ((lp =
			g_hash_table_lookup (task->raw_headers, rh->name)) != NULL) {
		DL_APPEND (lp, rh);
	}
	else {
		g_hash_table_insert (task->raw_headers, rh->name, rh);
	}
	debug_task ("add raw header %s: %s", rh->name, rh->value);
}

/* Convert raw headers to a list of struct raw_header * */
static void
process_raw_headers (struct rspamd_task *task, const gchar *in)
{
	struct raw_header *new = NULL;
	const gchar *p, *c;
	gchar *tmp, *tp;
	gint state = 0, l, next_state = 100, err_state = 100, t_state;
	gboolean valid_folding = FALSE;

	p = in;
	c = p;
	while (*p) {
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
						sizeof (struct raw_header));
				new->prev = new;
				l = p - c;
				tmp = rspamd_mempool_alloc (task->task_pool, l + 1);
				rspamd_strlcpy (tmp, c, l + 1);
				new->name = tmp;
				new->empty_separator = TRUE;
				p++;
				state = 2;
				c = p;
			}
			else if (g_ascii_isspace (*p)) {
				/* Not header but some garbage */
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
				state = 99;
				next_state = 3;
				err_state = 4;
			}
			else if (*(p + 1) == '\0') {
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
			new->value = tmp;
			new->decoded = g_mime_utils_header_decode_text (new->value);
			rspamd_mempool_add_destructor (task->task_pool,
					(rspamd_mempool_destruct_t)g_free, new->decoded);
			append_raw_header (task, new);
			state = 0;
			break;
		case 5:
			/* Header has only name, no value */
			new->value = "";
			new->decoded = NULL;
			append_raw_header (task, new);
			state = 0;
			break;
		case 99:
			/* Folding state */
			if (*(p + 1) == '\0') {
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
					p++;
				}
				p++;
				state = next_state;
			}
			else if (*p == '\n') {
				if (*(p + 1) == '\r') {
					p++;
				}
				p++;
				state = next_state;
			}
			else if (*(p + 1) == '\0') {
				state = next_state;
				p++;
			}
			else {
				p++;
			}
			break;
		}
	}
}

static void
free_byte_array_callback (void *pointer)
{
	GByteArray *arr = (GByteArray *) pointer;
	g_byte_array_free (arr, TRUE);
}

static gboolean
charset_validate (rspamd_mempool_t *pool, const gchar *in, gchar **out)
{
	/*
	 * This is a simple routine to validate input charset
	 * we just check that charset starts with alphanumeric and ends
	 * with alphanumeric
	 */
	const gchar *begin, *end;
	gboolean changed = FALSE;

	begin = in;

	while (!g_ascii_isalnum (*begin)) {
		begin ++;
		changed = TRUE;
	}
	end = begin + strlen (begin) - 1;
	while (!g_ascii_isalnum (*end)) {
		end --;
		changed = TRUE;
	}

	if (!changed) {
		*out = (gchar *)in;
	}
	else {
		*out = rspamd_mempool_alloc (pool, end - begin + 2);
		rspamd_strlcpy (*out, begin, end - begin + 2);
	}

	return TRUE;
}

static GByteArray *
convert_text_to_utf (struct rspamd_task *task,
	GByteArray * part_content,
	GMimeContentType * type,
	struct mime_text_part *text_part)
{
	GError *err = NULL;
	gsize read_bytes, write_bytes;
	const gchar *charset;
	gchar *res_str, *ocharset;
	GByteArray *result_array;

	if (task->cfg->raw_mode) {
		text_part->is_raw = TRUE;
		return part_content;
	}

	if ((charset =
		g_mime_content_type_get_parameter (type, "charset")) == NULL) {
		text_part->is_raw = TRUE;
		return part_content;
	}
	if (!charset_validate (task->task_pool, charset, &ocharset)) {
		msg_info (
			"<%s>: has invalid charset",
			task->message_id);
		text_part->is_raw = TRUE;
		return part_content;
	}
	if (g_ascii_strcasecmp (ocharset,
		"utf-8") == 0 || g_ascii_strcasecmp (ocharset, "utf8") == 0) {
		if (g_utf8_validate (part_content->data, part_content->len, NULL)) {
			text_part->is_raw = FALSE;
			text_part->is_utf = TRUE;
			return part_content;
		}
		else {
			msg_info (
				"<%s>: contains invalid utf8 characters, assume it as raw",
				task->message_id);
			text_part->is_raw = TRUE;
			return part_content;
		}
	}

	res_str = g_convert_with_fallback (part_content->data,
			part_content->len,
			UTF8_CHARSET,
			ocharset,
			NULL,
			&read_bytes,
			&write_bytes,
			&err);
	if (res_str == NULL) {
		msg_warn ("<%s>: cannot convert from %s to utf8: %s",
			task->message_id,
			ocharset,
			err ? err->message : "unknown problem");
		text_part->is_raw = TRUE;
		return part_content;
	}

	result_array = rspamd_mempool_alloc (task->task_pool, sizeof (GByteArray));
	result_array->data = res_str;
	result_array->len = write_bytes;
	rspamd_mempool_add_destructor (task->task_pool,
		(rspamd_mempool_destruct_t) g_free,
		res_str);
	text_part->is_raw = FALSE;
	text_part->is_utf = TRUE;

	return result_array;
}

static void
process_text_part (struct rspamd_task *task,
	GByteArray *part_content,
	GMimeContentType *type,
	GMimeObject *part,
	GMimeObject *parent,
	gboolean is_empty)
{
	struct mime_text_part *text_part;
	const gchar *cd;
	gchar *raw_headers;

	/* Skip attachements */
#ifndef GMIME24
	cd = g_mime_part_get_content_disposition (GMIME_PART (part));
	if (cd &&
		g_ascii_strcasecmp (cd,
		"attachment") == 0 && !task->cfg->check_text_attachements) {
		debug_task ("skip attachments for checking as text parts");
		return;
	}
#else
	cd = g_mime_object_get_disposition (GMIME_OBJECT (part));
	if (cd &&
		g_ascii_strcasecmp (cd,
		GMIME_DISPOSITION_ATTACHMENT) == 0 &&
		!task->cfg->check_text_attachements) {
		debug_task ("skip attachments for checking as text parts");
		return;
	}

	raw_headers = g_mime_object_get_headers (GMIME_OBJECT (part));
	if (raw_headers) {
		process_raw_headers (task, raw_headers);
		g_free (raw_headers);
	}
#endif

	if (g_mime_content_type_is_type (type, "text",
		"html") || g_mime_content_type_is_type (type, "text", "xhtml")) {
		debug_task ("got urls from text/html part");

		text_part =
			rspamd_mempool_alloc0 (task->task_pool,
				sizeof (struct mime_text_part));
		text_part->is_html = TRUE;
		if (is_empty) {
			text_part->is_empty = TRUE;
			text_part->orig = NULL;
			text_part->content = NULL;
			task->text_parts = g_list_prepend (task->text_parts, text_part);
			return;
		}
		text_part->orig = convert_text_to_utf (task,
				part_content,
				type,
				text_part);
		text_part->is_balanced = TRUE;
		text_part->html_nodes = NULL;
		text_part->parent = parent;

		text_part->content = strip_html_tags (task,
				task->task_pool,
				text_part,
				text_part->orig,
				NULL);

		if (text_part->html_nodes != NULL) {
			decode_entitles (text_part->content->data,
				&text_part->content->len);
		}
		url_parse_text (task->task_pool, task, text_part, TRUE);

		fuzzy_init_part (text_part, task->task_pool, task->cfg->max_diff);
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) free_byte_array_callback,
			text_part->content);
		task->text_parts = g_list_prepend (task->text_parts, text_part);
	}
	else if (g_mime_content_type_is_type (type, "text", "*")) {
		debug_task ("got urls from text/plain part");

		text_part =
			rspamd_mempool_alloc0 (task->task_pool,
				sizeof (struct mime_text_part));
		text_part->is_html = FALSE;
		text_part->parent = parent;
		if (is_empty) {
			text_part->is_empty = TRUE;
			text_part->orig = NULL;
			text_part->content = NULL;
			task->text_parts = g_list_prepend (task->text_parts, text_part);
			return;
		}
		text_part->orig = convert_text_to_utf (task,
				part_content,
				type,
				text_part);
		text_part->content = text_part->orig;
		url_parse_text (task->task_pool, task, text_part, FALSE);
		fuzzy_init_part (text_part, task->task_pool, task->cfg->max_diff);
		task->text_parts = g_list_prepend (task->text_parts, text_part);
	}
}

#ifdef GMIME24
static void
mime_foreach_callback (GMimeObject * parent,
	GMimeObject * part,
	gpointer user_data)
#else
static void
mime_foreach_callback (GMimeObject * part, gpointer user_data)
#endif
{
	struct rspamd_task *task = (struct rspamd_task *)user_data;
	struct mime_part *mime_part;
	GMimeContentType *type;
	GMimeDataWrapper *wrapper;
	GMimeStream *part_stream;
	GByteArray *part_content;

	task->parts_count++;

	/* 'part' points to the current part node that g_mime_message_foreach_part() is iterating over */

	/* find out what class 'part' is... */
	if (GMIME_IS_MESSAGE_PART (part)) {
		/* message/rfc822 or message/news */
		GMimeMessage *message;

		/* g_mime_message_foreach_part() won't descend into
		   child message parts, so if we want to count any
		   subparts of this child message, we'll have to call
		   g_mime_message_foreach_part() again here. */

		message = g_mime_message_part_get_message ((GMimeMessagePart *) part);
		if (task->parser_recursion++ < RECURSION_LIMIT) {
#ifdef GMIME24
			g_mime_message_foreach (message, mime_foreach_callback, task);
#else
			g_mime_message_foreach_part (message, mime_foreach_callback, task);
#endif
		}
		else {
			msg_err ("endless recursion detected: %d", task->parser_recursion);
			return;
		}
#ifndef GMIME24
		g_object_unref (message);
#endif
	}
	else if (GMIME_IS_MESSAGE_PARTIAL (part)) {
		/* message/partial */

		/* this is an incomplete message part, probably a
		   large message that the sender has broken into
		   smaller parts and is sending us bit by bit. we
		   could save some info about it so that we could
		   piece this back together again once we get all the
		   parts? */
	}
	else if (GMIME_IS_MULTIPART (part)) {
		/* multipart/mixed, multipart/alternative, multipart/related, multipart/signed, multipart/encrypted, etc... */
		task->parser_parent_part = part;
#ifndef GMIME24
		debug_task ("detected multipart part");
		/* we'll get to finding out if this is a signed/encrypted multipart later... */
		if (task->parser_recursion++ < RECURSION_LIMIT) {
			g_mime_multipart_foreach ((GMimeMultipart *) part,
				mime_foreach_callback,
				task);
		}
		else {
			msg_err ("endless recursion detected: %d", task->parser_recursion);
			return;
		}
#endif
	}
	else if (GMIME_IS_PART (part)) {
		/* a normal leaf part, could be text/plain or image/jpeg etc */
#ifdef GMIME24
		type = (GMimeContentType *) g_mime_object_get_content_type (GMIME_OBJECT (
					part));
#else
		type =
			(GMimeContentType *) g_mime_part_get_content_type (GMIME_PART (part));
#endif
		if (type == NULL) {
			msg_warn ("type of part is unknown, assume text/plain");
			type = g_mime_content_type_new ("text", "plain");
#ifdef GMIME24
			rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t) g_object_unref,				 type);
#else
			rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t) g_mime_content_type_destroy, type);
#endif
		}
		wrapper = g_mime_part_get_content_object (GMIME_PART (part));
#ifdef GMIME24
		if (wrapper != NULL && GMIME_IS_DATA_WRAPPER (wrapper)) {
#else
		if (wrapper != NULL) {
#endif
			part_stream = g_mime_stream_mem_new ();
			if (g_mime_data_wrapper_write_to_stream (wrapper,
				part_stream) != -1) {
				g_mime_stream_mem_set_owner (GMIME_STREAM_MEM (
						part_stream), FALSE);
				part_content = g_mime_stream_mem_get_byte_array (GMIME_STREAM_MEM (
							part_stream));
				g_object_unref (part_stream);
				mime_part =
					rspamd_mempool_alloc (task->task_pool,
						sizeof (struct mime_part));
				mime_part->type = type;
				mime_part->content = part_content;
				mime_part->parent = task->parser_parent_part;
				mime_part->filename = g_mime_part_get_filename (GMIME_PART (
							part));
				debug_task ("found part with content-type: %s/%s",
					type->type,
					type->subtype);
				task->parts = g_list_prepend (task->parts, mime_part);
				/* Skip empty parts */
				process_text_part (task,
					part_content,
					type,
					part,
					task->parser_parent_part,
					(part_content->len <= 0));
			}
			else {
				msg_warn ("write to stream failed: %d, %s", errno,
					strerror (errno));
			}
#ifndef GMIME24
			g_object_unref (wrapper);
#endif
		}
		else {
			msg_warn ("cannot get wrapper for mime part, type of part: %s/%s",
				type->type,
				type->subtype);
		}
	}
	else {
		g_assert_not_reached ();
	}
}

static void
destroy_message (void *pointer)
{
	GMimeMessage *msg = pointer;

	msg_debug ("freeing pointer %p", msg);
	g_object_unref (msg);
}

gint
process_message (struct rspamd_task *task)
{
	GMimeMessage *message;
	GMimeParser *parser;
	GMimeStream *stream;
	GByteArray *tmp;
	GList *first, *cur;
	GMimePart *part;
	GMimeDataWrapper *wrapper;
	struct received_header *recv;
	gchar *mid, *url_str, *p, *end, *url_end;
	struct uri *subject_url;
	gsize len;
	gint rc;

	tmp = rspamd_mempool_alloc (task->task_pool, sizeof (GByteArray));
	tmp->data = task->msg->str;
	tmp->len = task->msg->len;

	stream = g_mime_stream_mem_new_with_byte_array (tmp);
	/*
	 * This causes g_mime_stream not to free memory by itself as it is memory allocated by
	 * pool allocator
	 */
	g_mime_stream_mem_set_owner (GMIME_STREAM_MEM (stream), FALSE);

	if (task->is_mime) {

		debug_task ("construct mime parser from string length %d",
			(gint)task->msg->len);
		/* create a new parser object to parse the stream */
		parser = g_mime_parser_new_with_stream (stream);
		g_object_unref (stream);

		/* parse the message from the stream */
		message = g_mime_parser_construct_message (parser);

		if (message == NULL) {
			msg_warn ("cannot construct mime from stream");
			return -1;
		}

		task->message = message;
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) destroy_message, task->message);

		/* Save message id for future use */
		task->message_id = g_mime_message_get_message_id (task->message);
		if (task->message_id == NULL) {
			task->message_id = "undef";
		}

		task->parser_recursion = 0;
#ifdef GMIME24
		g_mime_message_foreach (message, mime_foreach_callback, task);
#else
		/*
		 * This is rather strange, but gmime 2.2 do NOT pass top-level part to foreach callback
		 * so we need to set up parent part by hands
		 */
		task->parser_parent_part = g_mime_message_get_mime_part (message);
		g_object_unref (task->parser_parent_part);
		g_mime_message_foreach_part (message, mime_foreach_callback, task);
#endif

		debug_task ("found %d parts in message", task->parts_count);
		if (task->queue_id == NULL) {
			task->queue_id = "undef";
		}

#ifdef GMIME24
		task->raw_headers_str =
			g_mime_object_get_headers (GMIME_OBJECT (task->message));
#else
		task->raw_headers_str = g_mime_message_get_headers (task->message);
#endif

		if (task->raw_headers_str) {
			rspamd_mempool_add_destructor (task->task_pool,
					(rspamd_mempool_destruct_t) g_free, task->raw_headers_str);
			process_raw_headers (task, task->raw_headers_str);
		}
		process_images (task);

		/* Parse received headers */
		first =
			message_get_raw_header (task, "Received", FALSE);
		cur = first;
		while (cur) {
			recv =
				rspamd_mempool_alloc0 (task->task_pool,
					sizeof (struct received_header));
			parse_recv_header (task->task_pool, cur->data, recv);
			task->received = g_list_prepend (task->received, recv);
			cur = g_list_next (cur);
		}

		/* free the parser (and the stream) */
		g_object_unref (parser);
	}
	else {
		/* We got only message, no mime headers or anything like this */
		/* Construct fake message for it */
		message = g_mime_message_new (TRUE);
		task->message = message;
		if (task->from_envelope) {
			g_mime_message_set_sender (task->message,
					rspamd_task_get_sender (task));
		}
		/* Construct part for it */
		part = g_mime_part_new_with_type ("text", "html");
#ifdef GMIME24
		wrapper = g_mime_data_wrapper_new_with_stream (stream,
				GMIME_CONTENT_ENCODING_8BIT);
#else
		wrapper = g_mime_data_wrapper_new_with_stream (stream,
				GMIME_PART_ENCODING_8BIT);
#endif
		g_mime_part_set_content_object (part, wrapper);
		g_mime_message_set_mime_part (task->message, GMIME_OBJECT (part));
		/* Register destructors */
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) g_object_unref,	 wrapper);
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) g_object_unref,	 part);
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) destroy_message, task->message);
		/* Now parse in a normal way */
		task->parser_recursion = 0;
#ifdef GMIME24
		g_mime_message_foreach (task->message, mime_foreach_callback, task);
#else
		g_mime_message_foreach_part (task->message, mime_foreach_callback,
			task);
#endif
		/* Generate message ID */
		mid = g_mime_utils_generate_message_id ("localhost.localdomain");
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) g_free, mid);
		g_mime_message_set_message_id (task->message, mid);
		task->message_id = mid;
		task->queue_id = mid;
		/* Set headers for message */
		if (task->subject) {
			g_mime_message_set_subject (task->message, task->subject);
		}
	}

	/* Set mime recipients and sender for the task */
	task->rcpt_mime = g_mime_message_get_all_recipients (message);
	if (task->rcpt_mime) {
#ifdef GMIME24
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) g_object_unref,
			task->rcpt_mime);
#else
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) internet_address_list_destroy,
			task->rcpt_mime);
#endif
	}
	task->from_mime = internet_address_list_parse_string(
			g_mime_message_get_sender (message));
	if (task->from_mime) {
#ifdef GMIME24
		rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t) g_object_unref,
				task->from_mime);
#else
		rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t) internet_address_list_destroy,
				task->from_mime);
#endif
	}

	/* Parse urls inside Subject header */
	cur = message_get_raw_header (task, "Subject", FALSE);
	if (cur) {
		p = cur->data;
		len = strlen (p);
		end = p + len;

		while (p < end) {
			/* Search to the end of url */
			if (url_try_text (task->task_pool, p, end - p, NULL, &url_end,
				&url_str, FALSE)) {
				if (url_str != NULL) {
					subject_url = rspamd_mempool_alloc0 (task->task_pool,
							sizeof (struct uri));
					if (subject_url != NULL) {
						/* Try to parse url */
						rc = parse_uri (subject_url, url_str, task->task_pool);
						if ((rc == URI_ERRNO_OK || rc == URI_ERRNO_NO_SLASHES ||
							rc == URI_ERRNO_NO_HOST_SLASH) &&
							subject_url->hostlen > 0) {
							if (subject_url->protocol != PROTOCOL_MAILTO) {
								if (!g_tree_lookup (task->urls, subject_url)) {
									g_tree_insert (task->urls,
										subject_url,
										subject_url);
								}
							}
						}
						else if (rc != URI_ERRNO_OK) {
							msg_info ("extract of url '%s' failed: %s",
								url_str,
								url_strerror (rc));
						}
					}
				}
			}
			else {
				break;
			}
			p = url_end + 1;
		}
	}

	return 0;
}

struct gmime_raw_header {
	struct raw_header *next;
	gchar *name;
	gchar *value;
};

typedef struct _GMimeHeader {
	GHashTable *hash;
	GHashTable *writers;
	struct raw_header *headers;
} local_GMimeHeader;


/* known header field types */
enum {
	HEADER_FROM = 0,
	HEADER_REPLY_TO,
	HEADER_TO,
	HEADER_CC,
	HEADER_BCC,
	HEADER_SUBJECT,
	HEADER_DATE,
	HEADER_MESSAGE_ID,
	HEADER_UNKNOWN
};

/*
 * Iterate throught all headers and make a list
 */
#ifndef GMIME24
static void
header_iterate (rspamd_mempool_t * pool,
	struct gmime_raw_header *h,
	GList ** ret,
	const gchar *field,
	gboolean strong)
{
	while (h) {
		if (G_LIKELY (!strong)) {
			if (h->value &&
				!g_ascii_strncasecmp (field, h->name, strlen (field))) {
				if (pool != NULL) {
					*ret =
						g_list_prepend (*ret,
							rspamd_mempool_strdup (pool, h->value));
				}
				else {
					*ret = g_list_prepend (*ret, g_strdup (h->value));
				}
			}
		}
		else {
			if (h->value && !strncmp (field, h->name, strlen (field))) {
				if (pool != NULL) {
					*ret =
						g_list_prepend (*ret,
							rspamd_mempool_strdup (pool, h->value));
				}
				else {
					*ret = g_list_prepend (*ret, g_strdup (h->value));
				}
			}
		}
		h = (struct gmime_raw_header *)h->next;
	}
}
#else
static void
header_iterate (rspamd_mempool_t * pool,
	GMimeHeaderList * ls,
	GList ** ret,
	const gchar *field,
	gboolean strong)
{
	/* Use iterator in case of gmime 2.4 */
	GMimeHeaderIter *iter;
	const gchar *name;

	if (ls == NULL) {
		*ret = NULL;
		return;
	}

	iter = g_mime_header_iter_new ();
	if (g_mime_header_list_get_iter (ls,
		iter) && g_mime_header_iter_first (iter)) {
		/* Iterate throught headers */
		while (g_mime_header_iter_is_valid (iter)) {
			name = g_mime_header_iter_get_name (iter);
			if (G_LIKELY (!strong)) {
				if (!g_ascii_strncasecmp (field, name, strlen (name))) {
					if (pool != NULL) {
						*ret =
							g_list_prepend (*ret,
								rspamd_mempool_strdup (pool,
								g_mime_header_iter_get_value (iter)));
					}
					else {
						*ret =
							g_list_prepend (*ret,
								g_strdup (g_mime_header_iter_get_value (iter)));
					}
				}
			}
			else {
				if (!strncmp (field, name, strlen (name))) {
					if (pool != NULL) {
						*ret =
							g_list_prepend (*ret,
								rspamd_mempool_strdup (pool,
								g_mime_header_iter_get_value (iter)));
					}
					else {
						*ret =
							g_list_prepend (*ret,
								g_strdup (g_mime_header_iter_get_value (iter)));
					}
				}
			}
			if (!g_mime_header_iter_next (iter)) {
				break;
			}
		}
	}
	g_mime_header_iter_free (iter);
}
#endif


struct multipart_cb_data {
	GList *ret;
	rspamd_mempool_t *pool;
	const gchar *field;
	gboolean try_search;
	gboolean strong;
	gint rec;
};

#define MAX_REC 10

static void
#ifdef GMIME24
multipart_iterate (GMimeObject * parent, GMimeObject * part, gpointer user_data)
#else
multipart_iterate (GMimeObject * part, gpointer user_data)
#endif
{
	struct multipart_cb_data *data = user_data;
#ifndef GMIME24
	struct gmime_raw_header *h;
#endif
	GList *l = NULL;

	if (data->try_search && part != NULL && GMIME_IS_PART (part)) {
#ifdef GMIME24
		GMimeHeaderList *ls;

		ls = g_mime_object_get_header_list (GMIME_OBJECT (part));
		header_iterate (data->pool, ls, &l, data->field, data->strong);
#else
		h = (struct gmime_raw_header *)part->headers->headers;
		header_iterate (data->pool, h,	&l, data->field, data->strong);
#endif
		if (l == NULL) {
			/* Header not found, abandon search results */
			data->try_search = FALSE;
			g_list_free (data->ret);
			data->ret = NULL;
		}
		else {
			data->ret = g_list_concat (l, data->ret);
		}
	}
	else if (data->try_search && GMIME_IS_MULTIPART (part)) {
		/* Maybe endless recursion here ? */
		if (data->rec++ < MAX_REC) {
			g_mime_multipart_foreach (GMIME_MULTIPART (
					part), multipart_iterate, data);
		}
		else {
			msg_info ("maximum recurse limit is over, stop recursing, %d",
				data->rec);
			data->try_search = FALSE;
		}
	}
}

static GList *
local_message_get_header (rspamd_mempool_t * pool,
	GMimeMessage * message,
	const gchar *field,
	gboolean strong)
{
	GList *gret = NULL;
	GMimeObject *part;
	struct multipart_cb_data cb = {
		.try_search = TRUE,
		.rec = 0,
		.ret = NULL,
	};
	cb.pool = pool;
	cb.field = field;
	cb.strong = strong;

#ifndef GMIME24
	struct gmime_raw_header *h;

	if (field == NULL) {
		return NULL;
	}

	msg_debug ("iterate over headers to find header %s", field);
	h = (struct gmime_raw_header *) (GMIME_OBJECT (message)->headers->headers);
	header_iterate (pool, h, &gret, field, strong);

	if (gret == NULL) {
		/* Try to iterate with mime part headers */
		msg_debug ("iterate over headers of mime part to find header %s",
			field);
		part = g_mime_message_get_mime_part (message);
		if (part) {
			h = (struct gmime_raw_header *)part->headers->headers;
			header_iterate (pool, h, &gret, field, strong);
			if (gret == NULL && GMIME_IS_MULTIPART (part)) {
				msg_debug (
					"iterate over headers of each multipart's subparts %s",
					field);
				g_mime_multipart_foreach (GMIME_MULTIPART (
						part), multipart_iterate, &cb);
				if (cb.ret != NULL) {
					gret = cb.ret;
				}
			}
#ifndef GMIME24
			g_object_unref (part);
#endif
		}
	}

	return gret;
#else
	GMimeHeaderList *ls;

	ls = g_mime_object_get_header_list (GMIME_OBJECT (message));
	header_iterate (pool, ls, &gret, field, strong);
	if (gret == NULL) {
		/* Try to iterate with mime part headers */
		part = g_mime_message_get_mime_part (message);
		if (part) {
			ls = g_mime_object_get_header_list (GMIME_OBJECT (part));
			header_iterate (pool, ls, &gret, field, strong);
			if (gret == NULL && GMIME_IS_MULTIPART (part)) {
				g_mime_multipart_foreach (GMIME_MULTIPART (
						part), multipart_iterate, &cb);
				if (cb.ret != NULL) {
					gret = cb.ret;
				}
			}
#ifndef GMIME24
			g_object_unref (part);
#endif
		}
	}


	return gret;
#endif
}

/**
 * g_mime_message_set_date_from_string: Set the message sent-date
 * @message: MIME Message
 * @string: A string of date
 *
 * Set the sent-date on a MIME Message.
 **/
void
local_mime_message_set_date_from_string (GMimeMessage * message,
	const gchar * string)
{
	time_t date;
	gint offset = 0;

	date = g_mime_utils_header_decode_date (string, &offset);
	g_mime_message_set_date (message, date, offset);
}

/*
 * Replacements for standart gmime functions but converting adresses to IA
 */
static const gchar *
local_message_get_sender (GMimeMessage * message)
{
	gchar *res;
	const gchar *from = g_mime_message_get_sender (message);
	InternetAddressList *ia;

#ifndef GMIME24
	ia = internet_address_parse_string (from);
#else
	ia = internet_address_list_parse_string (from);
#endif
	if (!ia) {
		return NULL;
	}
	res = internet_address_list_to_string (ia, FALSE);
#ifndef GMIME24
	internet_address_list_destroy (ia);
#else
	g_object_unref (ia);
#endif

	return res;
}

#ifdef GMIME24
static const gchar*
local_message_get_content_type (GMimeMessage * message)
{
	GMimeContentType *ct;

	ct = g_mime_object_get_content_type (GMIME_OBJECT (message));
	if (ct) {
		return g_mime_content_type_to_string (ct);
	}
	return NULL;
}
static void
local_message_set_content_type (GMimeMessage * message, const gchar *in)
{
	GMimeContentType *ct;

	ct = g_mime_content_type_new_from_string (in);
	if (ct) {
		g_mime_object_set_content_type (GMIME_OBJECT (message), ct);
	}
}
#endif

static const gchar *
local_message_get_reply_to (GMimeMessage * message)
{
	gchar *res;
	const gchar *from = g_mime_message_get_reply_to (message);
	InternetAddressList *ia;

#ifndef GMIME24
	ia = internet_address_parse_string (from);
#else
	ia = internet_address_list_parse_string (from);
#endif
	if (!ia) {
		return NULL;
	}
	res = internet_address_list_to_string (ia, FALSE);
#ifndef GMIME24
	internet_address_list_destroy (ia);
#else
	g_object_unref (ia);
#endif

	return res;
}

#ifdef GMIME24

#   define ADD_RECIPIENT_TEMPLATE(type,def)                                                     \
	static void                                                                                     \
	local_message_add_recipients_from_string_ ## type (GMimeMessage * message, \
		const gchar * string, \
		const gchar * value)    \
	{                                                                                               \
		InternetAddressList *il, *new;                                                              \
                                                                                                \
		il = g_mime_message_get_recipients (message, (def));                                        \
		new = internet_address_list_parse_string (string);                                          \
		internet_address_list_append (il, new);                                                     \
	}                                                                                               \

ADD_RECIPIENT_TEMPLATE (to,	 GMIME_RECIPIENT_TYPE_TO)
ADD_RECIPIENT_TEMPLATE (cc,	 GMIME_RECIPIENT_TYPE_CC)
ADD_RECIPIENT_TEMPLATE (bcc, GMIME_RECIPIENT_TYPE_BCC)
#   define GET_RECIPIENT_TEMPLATE(type,def)                                                     \
	static InternetAddressList *                                                                     \
	local_message_get_recipients_ ## type (GMimeMessage * message, \
		const gchar * unused)                    \
	{                                                                                               \
		return g_mime_message_get_recipients (message, (def));                                      \
	}
GET_RECIPIENT_TEMPLATE (to,	 GMIME_RECIPIENT_TYPE_TO)
GET_RECIPIENT_TEMPLATE (cc,	 GMIME_RECIPIENT_TYPE_CC)
GET_RECIPIENT_TEMPLATE (bcc, GMIME_RECIPIENT_TYPE_BCC)
#endif
/* different declarations for different types of set and get functions */
typedef const gchar *(*GetFunc) (GMimeMessage * message);
typedef InternetAddressList *(*GetRcptFunc) (GMimeMessage * message,
	const gchar *type);
typedef GList *(*GetListFunc) (rspamd_mempool_t * pool, GMimeMessage * message,
	const gchar *type, gboolean strong);
typedef void (*SetFunc) (GMimeMessage * message, const gchar *value);
typedef void (*SetListFunc) (GMimeMessage * message, const gchar *field,
	const gchar *value);

/** different types of functions
 *
 * FUNC_CHARPTR
 *	- function with no arguments
 *	- get returns gchar*
 *
 * FUNC_IA (from Internet Address)
 *	- function with additional "field" argument from the fieldfunc table,
 *	- get returns Glist*
 *
 * FUNC_LIST
 *	- function with additional "field" argument (given arbitrary header field name)
 *	- get returns Glist*
 **/
enum {
	FUNC_CHARPTR = 0,
	FUNC_CHARFREEPTR,
	FUNC_IA,
	FUNC_LIST
};

/**
 * fieldfunc struct: structure of MIME fields and corresponding get and set
 * functions.
 **/
static struct {
	gchar *name;
	GetFunc func;
	GetRcptFunc rcptfunc;
	GetListFunc getlistfunc;
	SetFunc setfunc;
	SetListFunc setlfunc;
	gint functype;
} fieldfunc[] =
{
	{
		"From", local_message_get_sender, NULL, NULL, g_mime_message_set_sender,
		NULL, FUNC_CHARFREEPTR
	}, {
		"Reply-To", local_message_get_reply_to, NULL, NULL,
		g_mime_message_set_reply_to, NULL, FUNC_CHARFREEPTR
	},
#ifndef GMIME24
	{
		"To", NULL, (GetRcptFunc) g_mime_message_get_recipients, NULL, NULL,
		(SetListFunc) g_mime_message_add_recipients_from_string, FUNC_IA
	}, {
		"Cc", NULL, (GetRcptFunc) g_mime_message_get_recipients, NULL, NULL,
		(SetListFunc) g_mime_message_add_recipients_from_string, FUNC_IA
	}, {
		"Bcc", NULL, (GetRcptFunc) g_mime_message_get_recipients, NULL, NULL,
		(SetListFunc) g_mime_message_add_recipients_from_string, FUNC_IA
	}, {
		"Date", (GetFunc) g_mime_message_get_date_string, NULL, NULL,
		local_mime_message_set_date_from_string, NULL, FUNC_CHARFREEPTR
	},
#else
	{
		"To", NULL, local_message_get_recipients_to, NULL, NULL,
		local_message_add_recipients_from_string_to, FUNC_IA
	}, {
		"Cc", NULL, local_message_get_recipients_cc, NULL, NULL,
		local_message_add_recipients_from_string_cc, FUNC_IA
	}, {
		"Bcc", NULL, local_message_get_recipients_bcc, NULL, NULL,
		local_message_add_recipients_from_string_bcc, FUNC_IA
	}, {
		"Date", (GetFunc)g_mime_message_get_date_as_string, NULL, NULL,
		local_mime_message_set_date_from_string, NULL, FUNC_CHARFREEPTR
	}, {
		"Content-Type", local_message_get_content_type, NULL, NULL,
		local_message_set_content_type, NULL, FUNC_CHARFREEPTR
	},
#endif
	{
		"Subject", g_mime_message_get_subject, NULL, NULL,
		g_mime_message_set_subject, NULL, FUNC_CHARPTR
	}, {
		"Message-Id", g_mime_message_get_message_id, NULL, NULL,
		g_mime_message_set_message_id, NULL, FUNC_CHARPTR
	},
#ifndef GMIME24
	{
		NULL, NULL, NULL, local_message_get_header, NULL,
		g_mime_message_add_header, FUNC_LIST
	}
#else
	{
		NULL, NULL, NULL, local_message_get_header, NULL,
		(SetListFunc)g_mime_object_append_header, FUNC_LIST
	}
#endif
};

/**
 * message_set_header: set header of any type excluding special (Content- and MIME-Version:)
 **/
void
message_set_header (GMimeMessage * message,
	const gchar *field,
	const gchar *value)
{
	gint i;

	if (!g_ascii_strcasecmp (field,
		"MIME-Version:") || !g_ascii_strncasecmp (field, "Content-", 8)) {
		return;
	}
	for (i = 0; i <= HEADER_UNKNOWN; ++i) {
		if (!fieldfunc[i].name ||
			!g_ascii_strncasecmp (field, fieldfunc[i].name,
			strlen (fieldfunc[i].name))) {
			switch (fieldfunc[i].functype) {
			case FUNC_CHARPTR:
			case FUNC_CHARFREEPTR:
				if (fieldfunc[i].setfunc) {
					(*(fieldfunc[i].setfunc))(message, value);
				}
				break;
			case FUNC_IA:
				(*(fieldfunc[i].setlfunc))(message, fieldfunc[i].name, value);
				break;
			case FUNC_LIST:
				(*(fieldfunc[i].setlfunc))(message, field, value);
				break;
			}
			break;
		}
	}
}


/**
 * message_get_header: returns the list of 'any header' values
 * (except of unsupported yet Content- and MIME-Version special headers)
 *
 * You should free the GList list by yourself.
 **/
GList *
message_get_header (rspamd_mempool_t * pool,
	GMimeMessage * message,
	const gchar *field,
	gboolean strong)
{
	gint i;
	gchar *ret = NULL, *ia_string;
	GList *gret = NULL;
	InternetAddressList *ia_list = NULL, *ia;

	for (i = 0; i <= HEADER_UNKNOWN; ++i) {
		if (!fieldfunc[i].name ||
			!g_ascii_strncasecmp (field, fieldfunc[i].name,
			strlen (fieldfunc[i].name))) {
			switch (fieldfunc[i].functype) {
			case FUNC_CHARFREEPTR:
				ret = (gchar *)(*(fieldfunc[i].func))(message);
				break;
			case FUNC_CHARPTR:
				ret = (gchar *)(*(fieldfunc[i].func))(message);
				break;
			case FUNC_IA:
				ia_list = (*(fieldfunc[i].rcptfunc))(message, field);
				ia = ia_list;
#ifndef GMIME24
				while (ia && ia->address) {

					ia_string = internet_address_to_string (
						(InternetAddress *) ia->address,
						FALSE);
					if (pool != NULL) {
						rspamd_mempool_add_destructor (pool,
							(rspamd_mempool_destruct_t) g_free, ia_string);
					}
					gret = g_list_prepend (gret, ia_string);
					ia = ia->next;
				}
#else
				i = internet_address_list_length (ia);
				while (--i >= 0) {
					ia_string = internet_address_to_string (internet_address_list_get_address (
								ia,
								i),
							FALSE);
					if (pool != NULL) {
						rspamd_mempool_add_destructor (pool,
							(rspamd_mempool_destruct_t) g_free, ia_string);
					}
					gret = g_list_prepend (gret, ia_string);
				}
#endif
				break;
			case FUNC_LIST:
				gret =
					(*(fieldfunc[i].getlistfunc))(pool, message, field, strong);
				break;
			}
			break;
		}
	}
	if (gret == NULL && ret != NULL) {
		if (pool != NULL) {
			gret = g_list_prepend (gret, rspamd_mempool_strdup (pool, ret));
		}
		else {
			gret = g_list_prepend (gret, g_strdup (ret));
		}
	}
	if (fieldfunc[i].functype == FUNC_CHARFREEPTR && ret) {
		g_free (ret);
	}

	return gret;
}

GList *
message_get_raw_header (struct rspamd_task *task,
	const gchar *field,
	gboolean strong)
{
	GList *gret = NULL;
	struct raw_header *rh;

	rh = g_hash_table_lookup (task->raw_headers, field);

	if (rh == NULL) {
		return NULL;
	}

	while (rh) {
		if (strong) {
			if (strcmp (rh->name, field) == 0) {
				gret = g_list_prepend (gret, rh);
			}
		}
		else {
			gret = g_list_prepend (gret, rh);
		}
		rh = rh->next;
	}

	if (gret != NULL) {
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t)g_list_free, gret);
	}

	return gret;
}
