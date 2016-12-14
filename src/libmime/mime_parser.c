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
#include "task.h"
#include "mime_parser.h"
#include "mime_headers.h"
#include "message.h"
#include "content_type.h"
#include "multipattern.h"
#include "cryptobox.h"

static struct rspamd_multipattern *mp_boundary = NULL;
static const guint max_nested = 32;

#define msg_debug_mime(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
        "mime", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

struct rspamd_mime_parser_stack {
	GPtrArray *stack; /* Stack of parts */
	struct rspamd_mime_part *cur_part;
	const gchar *pos;
	const gchar *end;
};

static gboolean
rspamd_mime_parse_multipart_part (struct rspamd_task *task,
		struct rspamd_mime_part *part,
		struct rspamd_mime_parser_stack *st,
		GError **err);
static gboolean
rspamd_mime_parse_message (struct rspamd_task *task,
		struct rspamd_mime_part *part,
		struct rspamd_mime_parser_stack *st,
		GError **err);
static gboolean
rspamd_mime_parse_normal_part (struct rspamd_task *task,
		struct rspamd_mime_part *part,
		struct rspamd_mime_parser_stack *st,
		GError **err);


#define RSPAMD_MIME_QUARK (rspamd_mime_parser_quark())
static GQuark
rspamd_mime_parser_quark (void)
{
	return g_quark_from_static_string ("mime-parser");
}

static const gchar*
rspamd_cte_to_string (enum rspamd_cte ct)
{
	const gchar *ret = "unknown";

	switch (ct) {
	case RSPAMD_CTE_7BIT:
		ret = "7bit";
		break;
	case RSPAMD_CTE_8BIT:
		ret = "8bit";
		break;
	case RSPAMD_CTE_QP:
		ret = "quoted-printable";
		break;
	case RSPAMD_CTE_B64:
		ret = "base64";
		break;
	default:
		break;
	}

	return ret;
}

static void
rspamd_mime_parser_init_mp (void)
{
	mp_boundary = rspamd_multipattern_create (RSPAMD_MULTIPATTERN_DEFAULT);
	g_assert (mp_boundary != NULL);
	rspamd_multipattern_add_pattern (mp_boundary, "\r--", 0);
	rspamd_multipattern_add_pattern (mp_boundary, "\n--", 0);
	g_assert (rspamd_multipattern_compile (mp_boundary, NULL));
}

static enum rspamd_cte
rspamd_mime_parse_cte (const gchar *in, gsize len)
{
	guint64 h = rspamd_cryptobox_fast_hash_specific (RSPAMD_CRYPTOBOX_XXHASH64,
			in, len, 0xdeadbabe);
	enum rspamd_cte ret = RSPAMD_CTE_UNKNOWN;

	switch (h) {
	case 0xCEDAA7056B4753F7ULL: /* 7bit */
		ret = RSPAMD_CTE_7BIT;
		break;
	case 0x42E0745448B39FC1ULL: /* 8bit */
		ret = RSPAMD_CTE_8BIT;
		break;
	case 0x6D69A5BB02A633B0ULL: /* quoted-printable */
		ret = RSPAMD_CTE_QP;
		break;
	case 0x96305588A76DC9A9ULL: /* base64 */
	case 0x171029DE1B0423A9ULL: /* base-64 */
		ret = RSPAMD_CTE_B64;
		break;
	}

	return ret;
}

static void
rspamd_mime_part_get_cte_heuristic (struct rspamd_task *task,
		struct rspamd_mime_part *part)
{
	const guint check_len = 80;
	guint real_len, nspaces = 0, neqsign = 0, n8bit = 0;
	gboolean b64_chars = TRUE;
	const guchar *p, *end;
	enum rspamd_cte ret = RSPAMD_CTE_UNKNOWN;

	real_len = MIN (check_len, part->raw_data.len);
	p = (const guchar *)part->raw_data.begin;
	end = p + real_len;

	while (p < end) {
		if (*p == ' ') {
			nspaces ++;
		}
		else if (*p == '=') {
			neqsign ++;
		}
		else if (*p >= 0x80) {
			n8bit ++;
			b64_chars = FALSE;
		}
		else if (!(g_ascii_isalnum (*p) || *p == '/' || *p == '+')) {
			b64_chars = FALSE;
		}

		p ++;
	}

	if (b64_chars && neqsign < 2 && nspaces == 0) {
		ret = RSPAMD_CTE_B64;
	}
	else if (n8bit == 0) {
		if (neqsign > 2 && nspaces > 2) {
			ret = RSPAMD_CTE_QP;
		}
		else {
			ret = RSPAMD_CTE_7BIT;
		}
	}
	else {
		ret = RSPAMD_CTE_8BIT;
	}

	part->cte = ret;
	msg_debug_mime ("detected cte: %s", rspamd_cte_to_string (ret));
}

static void
rspamd_mime_part_get_cte (struct rspamd_task *task, struct rspamd_mime_part *part)
{
	struct rspamd_mime_header *hdr;
	guint i;
	GPtrArray *hdrs;
	enum rspamd_cte cte = RSPAMD_CTE_UNKNOWN;

	hdrs = rspamd_message_get_header_from_hash (part->raw_headers,
			task->task_pool,
			"Content-Transfer-Encoding", FALSE);

	if (hdrs == NULL) {
		rspamd_mime_part_get_cte_heuristic (task, part);
	}
	else {
		for (i = 0; i < hdrs->len; i ++) {
			gsize hlen;

			hdr = g_ptr_array_index (hdrs, i);
			hlen = strlen (hdr->value);
			rspamd_str_lc (hdr->value, hlen);
			cte = rspamd_mime_parse_cte (hdr->value, hlen);

			if (cte != RSPAMD_CTE_UNKNOWN) {
				break;
			}
		}

		if (cte == RSPAMD_CTE_UNKNOWN) {
			rspamd_mime_part_get_cte_heuristic (task, part);
		}
		else {
			part->cte = cte;
			msg_debug_mime ("processed cte: %s", rspamd_cte_to_string (cte));
		}
	}
}

static gboolean
rspamd_mime_parse_normal_part (struct rspamd_task *task,
		struct rspamd_mime_part *part,
		struct rspamd_mime_parser_stack *st,
		GError **err)
{
	rspamd_fstring_t *parsed;
	gssize r;

	g_assert (part != NULL);

	rspamd_mime_part_get_cte (task, part);

	switch (part->cte) {
	case RSPAMD_CTE_7BIT:
	case RSPAMD_CTE_8BIT:
	case RSPAMD_CTE_UNKNOWN:
		part->parsed_data.begin = part->raw_data.begin;
		part->parsed_data.len = part->raw_data.len;
		break;
	case RSPAMD_CTE_QP:
		parsed = rspamd_fstring_sized_new (part->raw_data.len);
		r = rspamd_decode_qp_buf (part->raw_data.begin, part->raw_data.len,
				parsed->str, parsed->allocated);
		g_assert (r != -1);
		parsed->len = r;
		part->parsed_data.begin = parsed->str;
		part->parsed_data.len = parsed->len;
		rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t)rspamd_fstring_free, parsed);
		break;
	case RSPAMD_CTE_B64:
		parsed = rspamd_fstring_sized_new (part->raw_data.len / 4 * 3 + 12);
		rspamd_cryptobox_base64_decode (part->raw_data.begin, part->raw_data.len,
				parsed->str, &parsed->len);
		part->parsed_data.begin = parsed->str;
		part->parsed_data.len = parsed->len;
		rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t)rspamd_fstring_free, parsed);
		break;
	default:
		g_assert_not_reached ();
	}

	g_ptr_array_add (task->parts, part);
	msg_debug_mime ("parsed data part %T/%T of length %z (%z orig), %s cte",
			&part->ct->type, &part->ct->subtype, part->parsed_data.len,
			part->raw_data.len, rspamd_cte_to_string (part->cte));

	return TRUE;
}

struct rspamd_mime_multipart_cbdata {
	struct rspamd_task *task;
	struct rspamd_mime_part *multipart;
	struct rspamd_mime_parser_stack *st;
	const gchar *part_start;
	rspamd_ftok_t *cur_boundary;
	GError **err;
};

static gboolean
rspamd_mime_process_multipart_node (struct rspamd_task *task,
		struct rspamd_mime_parser_stack *st,
		struct rspamd_mime_part *multipart,
		const gchar *start, const gchar *end,
		GError **err)
{
	struct rspamd_content_type *ct, *sel = NULL;
	struct rspamd_mime_header *hdr;
	GPtrArray *hdrs = NULL;
	struct rspamd_mime_part *npart;
	GString str;
	goffset hdr_pos, body_pos;
	guint i;
	gboolean ret = FALSE;


	str.str = (gchar *)start;
	str.len = end - start;

	hdr_pos = rspamd_string_find_eoh (&str, &body_pos);

	if (multipart->children == NULL) {
		multipart->children = g_ptr_array_sized_new (2);
	}

	npart = rspamd_mempool_alloc0 (task->task_pool,
			sizeof (struct rspamd_mime_part));
	npart->parent_part = multipart;
	npart->raw_headers =  g_hash_table_new_full (rspamd_strcase_hash,
			rspamd_strcase_equal, NULL, rspamd_ptr_array_free_hard);
	g_ptr_array_add (multipart->children, npart);

	if (hdr_pos > 0 && hdr_pos < str.len) {
			npart->raw_headers_str = str.str;
			npart->raw_headers_len = hdr_pos;
			npart->raw_data.begin = start + body_pos;
			npart->raw_data.len = (end - start) - body_pos;

			if (task->raw_headers_content.len > 0) {
				rspamd_mime_headers_process (task, npart->raw_headers,
						npart->raw_headers_str,
						npart->raw_headers_len,
						TRUE);
			}

			hdrs = rspamd_message_get_header_from_hash (npart->raw_headers,
					task->task_pool,
					"Content-Type", FALSE);

	}
	else {
		npart->raw_headers_str = 0;
		npart->raw_headers_len = 0;
		npart->raw_data.begin = start;
		npart->raw_data.len = end - start;
	}


	if (hdrs != NULL) {

		for (i = 0; i < hdrs->len; i ++) {
			hdr = g_ptr_array_index (hdrs, i);
			ct = rspamd_content_type_parse (hdr->value, strlen (hdr->value),
					task->task_pool);

			/* Here we prefer multipart content-type or any content-type */
			if (ct) {
				if (sel == NULL) {
					sel = ct;
				}
				else if (ct->flags & RSPAMD_CONTENT_TYPE_MULTIPART) {
					sel = ct;
				}
			}
		}
	}

	if (sel == NULL) {
		/* TODO: assume part as octet-stream */
		g_set_error (err, RSPAMD_MIME_QUARK, EINVAL, "no content type");
		return FALSE;
	}

	npart->ct = sel;

	if (sel->flags & RSPAMD_CONTENT_TYPE_MULTIPART) {
		st->cur_part = npart;
		g_ptr_array_add (st->stack, npart);
		ret = rspamd_mime_parse_multipart_part (task, npart, st, err);
	}
	else if (sel->flags & RSPAMD_CONTENT_TYPE_MESSAGE) {
		st->cur_part = npart;
		g_ptr_array_add (st->stack, npart);
		ret = rspamd_mime_parse_message (task, npart, st, err);
	}
	else {
		ret = rspamd_mime_parse_normal_part (task, npart, st, err);
	}

	return ret;
}

static gint
rspamd_mime_parse_multipart_cb (struct rspamd_multipattern *mp,
		guint strnum,
		gint match_start,
		gint match_pos,
		const gchar *text,
		gsize len,
		void *context)
{
	struct rspamd_mime_multipart_cbdata *cb = context;
	struct rspamd_task *task;
	const gchar *pos = text + match_pos, *end = text + len, *st;
	gint ret = 0;

	task = cb->task;

	if (cb->st->pos && pos <= cb->st->pos) {
		/* Already processed */
		return 0;
	}

	/* Now check boundary */
	if (!cb->part_start) {
		if (cb->cur_boundary) {
			if (match_pos + cb->cur_boundary->len < len) {
				if (rspamd_lc_cmp (pos, cb->cur_boundary->begin,
						cb->cur_boundary->len) != 0) {
					msg_debug_mime ("found invalid boundary: %*s, %T expected",
							(gint)cb->cur_boundary->len, pos, cb->cur_boundary);

					/* Just continue search */
					return 0;
				}

				pos += cb->cur_boundary->len;

				while (pos < end && (*pos == '\r' || *pos == '\n')) {
					pos ++;
				}

				cb->part_start = pos;
				cb->st->pos = pos;
			}
			else {
				msg_debug_mime ("boundary is stripped");
				g_set_error (cb->err, RSPAMD_MIME_QUARK, EINVAL,
						"start boundary is stripped at %d (%zd available)",
						match_pos, len);

				return (-1);
			}
		}
		else {
			/* We see something like boundary: '[\r\n]--xxx */
			/* TODO: write heuristic */
			g_assert_not_reached ();
		}
	}
	else {
		/* We have seen the start of the boundary */
		if (cb->part_start < pos) {
			/* We should have seen some boundary */
			g_assert (cb->cur_boundary != NULL);

			if (match_pos + cb->cur_boundary->len <= len) {
				if (rspamd_lc_cmp (pos, cb->cur_boundary->begin,
						cb->cur_boundary->len) != 0) {
					msg_debug_mime ("found invalid boundary: %*s, %T expected",
							(gint)cb->cur_boundary->len, pos, cb->cur_boundary);

					/* Just continue search */
					return 0;
				}

				pos += cb->cur_boundary->len;
				cb->st->pos = pos;

				if (pos < end - 1 && pos[0] == '-' && pos[1] == '-') {
					/* It should be end of multipart, but it is sometimes isn't */
					/* TODO: deal with such perversions */
					pos += 2;
					g_ptr_array_remove_index_fast (cb->st->stack,
							cb->st->stack->len - 1);
					ret = 1;
				}
				else if (pos[0] != '\r' && pos[0] != '\n' && pos != end) {
					/* This is not actually our boundary, but somethig else */
					return 0;
				}

				st = match_pos + text;
				/* Find the start of part */
				while (st > cb->part_start && (*st == '\n' || *st == '\r')) {
					st --;
				}

				if (!rspamd_mime_process_multipart_node (task, cb->st,
						cb->multipart, cb->part_start, st, cb->err)) {
					return -1;
				}

				while (pos < end && (*pos == '\r' || *pos == '\n')) {
					pos ++;
				}

				/* Go towards the next part */
				cb->part_start = pos;
				cb->st->pos = pos;
			}
			else {
				msg_debug_mime ("boundary is stripped");
				g_set_error (cb->err, RSPAMD_MIME_QUARK, EINVAL,
						"middle boundary is stripped at %d (%zd available)",
						match_pos, len);

				return (-1);
			}
		}
		else {
			/* We have something very bad in fact */
			g_assert_not_reached ();
		}
	}

	return ret;
}

static gboolean
rspamd_mime_parse_multipart_part (struct rspamd_task *task,
		struct rspamd_mime_part *part,
		struct rspamd_mime_parser_stack *st,
		GError **err)
{
	struct rspamd_mime_multipart_cbdata cbdata;
	gint ret;

	if (st->stack->len > max_nested) {
		g_set_error (err, RSPAMD_MIME_QUARK, E2BIG, "Nesting level is too high: %d",
				st->stack->len);
		return FALSE;
	}

	g_ptr_array_add (task->parts, part);

	st->pos = part->raw_data.begin;
	cbdata.multipart = part;
	cbdata.task = task;
	cbdata.st = st;
	cbdata.part_start = NULL;
	cbdata.err = err;

	if (part->ct->boundary.len > 0) {
		/* We know our boundary */
		cbdata.cur_boundary = &part->ct->boundary;
	}
	else {
		/* Guess boundary */
		cbdata.cur_boundary = NULL;
	}

	ret = rspamd_multipattern_lookup (mp_boundary, part->raw_data.begin,
			part->raw_data.len, rspamd_mime_parse_multipart_cb, &cbdata, NULL);

	return (ret != -1);
}

static gboolean
rspamd_mime_parse_message (struct rspamd_task *task,
		struct rspamd_mime_part *part,
		struct rspamd_mime_parser_stack *st,
		GError **err)
{
	struct rspamd_content_type *ct, *sel = NULL;
	struct rspamd_mime_header *hdr;
	GPtrArray *hdrs = NULL;
	const gchar *pbegin, *p;
	gsize plen, len;
	struct rspamd_mime_part *npart;
	goffset hdr_pos, body_pos;
	guint i;
	gboolean ret = FALSE;
	GString str;

	if (st->stack->len > max_nested) {
		g_set_error (err, RSPAMD_MIME_QUARK, E2BIG, "Nesting level is too high: %d",
				st->stack->len);
		return FALSE;
	}

	if (part) {
		g_ptr_array_add (task->parts, part);
	}

	/* Parse headers */
	if (st->cur_part == NULL) {
		p = task->msg.begin;
		len = task->msg.len;
		/* Skip any space characters to avoid some bad messages to be unparsed */
		while (len > 0 && g_ascii_isspace (*p)) {
			p ++;
			len --;
		}

		/*
		 * Exim somehow uses mailbox format for messages being scanned:
		 * From xxx@xxx.com Fri May 13 19:08:48 2016
		 *
		 * So we check if a task has non-http format then we check for such a line
		 * at the beginning to avoid errors
		 */
		if (!(task->flags & RSPAMD_TASK_FLAG_JSON) || (task->flags &
				RSPAMD_TASK_FLAG_LOCAL_CLIENT)) {
			if (len > sizeof ("From ") - 1) {
				if (memcmp (p, "From ", sizeof ("From ") - 1) == 0) {
					/* Skip to CRLF */
					msg_info_task ("mailbox input detected, enable workaround");
					p += sizeof ("From ") - 1;
					len -= sizeof ("From ") - 1;

					while (len > 0 && *p != '\n') {
						p ++;
						len --;
					}
					while (len > 0 && g_ascii_isspace (*p)) {
						p ++;
						len --;
					}
				}
			}
		}

		str.str = (gchar *)p;
		str.len = len;
	}
	else {
		p = part->raw_data.begin;
		len = part->raw_data.len;

		/* Skip any space characters to avoid some bad messages to be unparsed */
		while (len > 0 && g_ascii_isspace (*p)) {
			p ++;
			len --;
		}

		str.str = (gchar *)p;
		str.len = len;
	}

	hdr_pos = rspamd_string_find_eoh (&str, &body_pos);

	if (hdr_pos > 0 && hdr_pos < str.len) {

		if (part == NULL) {
			task->raw_headers_content.begin = (gchar *) (str.str);
			task->raw_headers_content.len = hdr_pos;
			task->raw_headers_content.body_start = str.str + body_pos;

			if (task->raw_headers_content.len > 0) {
				rspamd_mime_headers_process (task, task->raw_headers,
						task->raw_headers_content.begin,
						task->raw_headers_content.len,
						TRUE);
			}

			hdrs = rspamd_message_get_header_from_hash (task->raw_headers,
					task->task_pool,
					"Content-Type", FALSE);
		}
		else {
			/* Adjust part data */
			part->raw_headers =  g_hash_table_new_full (rspamd_strcase_hash,
						rspamd_strcase_equal, NULL, rspamd_ptr_array_free_hard);
			part->raw_headers_str = str.str;
			part->raw_headers_len = hdr_pos;
			part->raw_data.begin = p + body_pos;
			part->raw_data.len -= body_pos;

			if (part->raw_headers_len > 0) {
				rspamd_mime_headers_process (task, part->raw_headers,
						part->raw_headers_str,
						part->raw_headers_len,
						TRUE);
			}

			hdrs = rspamd_message_get_header_from_hash (part->raw_headers,
					task->task_pool,
					"Content-Type", FALSE);
		}

	}


	if (hdrs == NULL) {
		g_set_error (err, RSPAMD_MIME_QUARK, EINVAL,
				"Content type header is absent");

		return FALSE;
	}

	for (i = 0; i < hdrs->len; i ++) {
		hdr = g_ptr_array_index (hdrs, i);
		ct = rspamd_content_type_parse (hdr->value, strlen (hdr->value),
				task->task_pool);

		/* Here we prefer multipart content-type or any content-type */
		if (ct) {
			if (sel == NULL) {
				sel = ct;
			}
			else if (ct->flags & RSPAMD_CONTENT_TYPE_MULTIPART) {
				sel = ct;
			}
		}
	}

	if (sel == NULL) {
		g_set_error (err, RSPAMD_MIME_QUARK, EINVAL,
				"Content type header cannot be parsed");

		return FALSE;
	}

	if (part) {
		pbegin = part->raw_data.begin;
		plen = part->raw_data.len;
	}
	else {
		pbegin = st->pos;
		plen = st->end - pbegin;
	}

	npart = rspamd_mempool_alloc0 (task->task_pool,
			sizeof (struct rspamd_mime_part));
	npart->raw_data.begin = pbegin;
	npart->raw_data.len = plen;
	npart->parent_part = part;
	npart->ct = sel;

	if (part == NULL) {
		npart->raw_headers = g_hash_table_ref (task->raw_headers);
	}
	else {
		npart->raw_headers = g_hash_table_ref (part->raw_headers);
	}

	if (sel->flags & RSPAMD_CONTENT_TYPE_MULTIPART) {
		st->cur_part = npart;
		g_ptr_array_add (st->stack, npart);
		ret = rspamd_mime_parse_multipart_part (task, npart, st, err);
	}
	else if (sel->flags & RSPAMD_CONTENT_TYPE_MESSAGE) {
		st->cur_part = npart;
		g_ptr_array_add (st->stack, npart);
		ret = rspamd_mime_parse_message (task, npart, st, err);
	}
	else {
		ret = rspamd_mime_parse_normal_part (task, npart, st, err);
	}

	if (part) {
		/* Remove message part from the stack */
		g_ptr_array_remove_index_fast (st->stack, st->stack->len - 1);
	}

	return ret;
}

static void
rspamd_mime_parse_stack_free (struct rspamd_mime_parser_stack *st)
{
	if (st) {
		g_ptr_array_free (st->stack, TRUE);
		g_slice_free1 (sizeof (*st), st);
	}
}

gboolean
rspamd_mime_parse_task (struct rspamd_task *task, GError **err)
{
	struct rspamd_mime_parser_stack *st;
	gboolean ret;

	if (mp_boundary == NULL) {
		rspamd_mime_parser_init_mp ();
	}

	st = g_slice_alloc0 (sizeof (*st));
	st->stack = g_ptr_array_sized_new (4);
	st->pos = task->raw_headers_content.body_start;
	st->end = task->msg.begin + task->msg.len;

	if (st->pos == NULL) {
		st->pos = task->msg.begin;
	}

	ret = rspamd_mime_parse_message (task, NULL, st, err);
	rspamd_mime_parse_stack_free (st);

	return ret;
}
