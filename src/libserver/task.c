/* Copyright (c) 2014, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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

#include "task.h"
#include "main.h"
#include "filter.h"
#include "protocol.h"
#include "message.h"
#include "lua/lua_common.h"

static void
gstring_destruct (gpointer ptr)
{
	GString *s = (GString *)ptr;

	g_string_free (s, TRUE);
}

/*
 * Create new task
 */
struct rspamd_task *
rspamd_task_new (struct rspamd_worker *worker)
{
	struct rspamd_task *new_task;

	new_task = g_slice_alloc0 (sizeof (struct rspamd_task));

	new_task->worker = worker;
	new_task->state = READ_MESSAGE;
	if (worker) {
		new_task->cfg = worker->srv->cfg;
		if (new_task->cfg->check_all_filters) {
			new_task->flags |= RSPAMD_TASK_FLAG_PASS_ALL;
		}
	}

	gettimeofday (&new_task->tv, NULL);
	new_task->time_real = rspamd_get_ticks ();
	new_task->time_virtual = rspamd_get_virtual_ticks ();

	new_task->task_pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());

	new_task->results = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	rspamd_mempool_add_destructor (new_task->task_pool,
		(rspamd_mempool_destruct_t) g_hash_table_unref,
		new_task->results);
	new_task->re_cache = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	rspamd_mempool_add_destructor (new_task->task_pool,
		(rspamd_mempool_destruct_t) g_hash_table_unref,
		new_task->re_cache);
	new_task->raw_headers = g_hash_table_new (rspamd_strcase_hash,
			rspamd_strcase_equal);
	new_task->request_headers = g_hash_table_new_full (rspamd_gstring_icase_hash,
		rspamd_gstring_icase_equal, gstring_destruct, gstring_destruct);
	rspamd_mempool_add_destructor (new_task->task_pool,
		(rspamd_mempool_destruct_t) g_hash_table_unref,
		new_task->request_headers);
	new_task->reply_headers = g_hash_table_new_full (rspamd_gstring_icase_hash,
			rspamd_gstring_icase_equal, gstring_destruct, gstring_destruct);
	rspamd_mempool_add_destructor (new_task->task_pool,
		(rspamd_mempool_destruct_t) g_hash_table_unref,
		new_task->reply_headers);
	rspamd_mempool_add_destructor (new_task->task_pool,
		(rspamd_mempool_destruct_t) g_hash_table_unref,
		new_task->raw_headers);
	new_task->emails = g_hash_table_new (rspamd_url_hash, rspamd_emails_cmp);
	rspamd_mempool_add_destructor (new_task->task_pool,
		(rspamd_mempool_destruct_t) g_hash_table_unref,
		new_task->emails);
	new_task->urls = g_hash_table_new (rspamd_url_hash, rspamd_urls_cmp);
	rspamd_mempool_add_destructor (new_task->task_pool,
		(rspamd_mempool_destruct_t) g_hash_table_unref,
		new_task->urls);
	new_task->sock = -1;
	new_task->flags |= (RSPAMD_TASK_FLAG_MIME|RSPAMD_TASK_FLAG_JSON);
	new_task->pre_result.action = METRIC_ACTION_NOACTION;

	new_task->message_id = new_task->queue_id = "undef";

	return new_task;
}


static void
rspamd_task_reply (struct rspamd_task *task)
{
	if (task->fin_callback) {
		task->fin_callback (task, task->fin_arg);
	}
	else {
		rspamd_protocol_write_reply (task);
	}
}

/*
 * Called if all filters are processed
 * @return TRUE if session should be terminated
 */
gboolean
rspamd_task_fin (void *arg)
{
	struct rspamd_task *task = (struct rspamd_task *) arg;
	gint r;

	/* Task is already finished or skipped */
	if (task->state == WRITE_REPLY) {
		rspamd_task_reply (task);
		return TRUE;
	}

	/* We processed all filters and want to process statfiles */
	if (task->state != WAIT_POST_FILTER && task->state != WAIT_PRE_FILTER) {
		/* Process all statfiles */
		/* Non-threaded version */
		rspamd_process_statistics (task);

		if (task->cfg->post_filters) {
			/* More to process */
			/* Special state */
			task->state = WAIT_POST_FILTER;
			return FALSE;
		}

	}

	/* We are on post-filter waiting state */
	if (task->state != WAIT_PRE_FILTER) {
		/* Check if we have all events finished */
		task->state = WRITE_REPLY;
		rspamd_task_reply (task);
	}
	else {
		/* We were waiting for pre-filter */
		if (task->pre_result.action != METRIC_ACTION_NOACTION) {
			/* Write result based on pre filters */
			task->state = WRITE_REPLY;
			rspamd_task_reply (task);
			return TRUE;
		}
		else {
			task->state = WAIT_FILTER;
			r = rspamd_process_filters (task);
			if (r == -1) {
				task->last_error = "Filter processing error";
				task->error_code = RSPAMD_FILTER_ERROR;
				task->state = WRITE_REPLY;
				rspamd_task_reply (task);
				return TRUE;
			}

			if (RSPAMD_TASK_IS_SKIPPED (task)) {
				rspamd_task_reply (task);
			}
			else {
				return FALSE;
			}
		}
	}

	return TRUE;
}

/*
 * Called if session was restored inside fin callback
 */
void
rspamd_task_restore (void *arg)
{
	struct rspamd_task *task = (struct rspamd_task *) arg;

	/* Call post filters */
	if (task->state == WAIT_POST_FILTER &&
			!(task->flags & RSPAMD_TASK_FLAG_SKIP_EXTRA)) {
		rspamd_lua_call_post_filters (task);
	}
}

/*
 * Free all structures of worker_task
 */
void
rspamd_task_free (struct rspamd_task *task, gboolean is_soft)
{
	GList *part;
	struct mime_part *p;
	struct mime_text_part *tp;

	if (task) {
		debug_task ("free pointer %p", task);
		while ((part = g_list_first (task->parts))) {
			task->parts = g_list_remove_link (task->parts, part);
			p = (struct mime_part *) part->data;
			g_byte_array_free (p->content, TRUE);
			g_list_free_1 (part);
		}
		if (task->text_parts) {
			part = task->text_parts;
			while (part) {
				tp = (struct mime_text_part *)part->data;
				if (tp->words) {
					g_array_free (tp->words, TRUE);
				}
				if (tp->normalized_words) {
					g_array_free (tp->normalized_words, TRUE);
				}
				part = g_list_next (part);
			}

			g_list_free (task->text_parts);
		}
		if (task->images) {
			g_list_free (task->images);
		}
		if (task->messages) {
			g_list_free (task->messages);
		}
		if (task->received) {
			g_list_free (task->received);
		}
		if (task->http_conn != NULL) {
			rspamd_http_connection_unref (task->http_conn);
		}
		if (task->sock != -1) {
			close (task->sock);
		}
		if (task->settings != NULL) {
			ucl_object_unref (task->settings);
		}
		if (task->client_addr) {
			rspamd_inet_address_destroy (task->client_addr);
		}
		if (task->from_addr) {
			rspamd_inet_address_destroy (task->from_addr);
		}
		rspamd_mempool_delete (task->task_pool);
		g_slice_free1 (sizeof (struct rspamd_task), task);
	}
}

void
rspamd_task_free_hard (gpointer ud)
{
	struct rspamd_task *task = ud;

	rspamd_task_free (task, FALSE);
}

void
rspamd_task_free_soft (gpointer ud)
{
	struct rspamd_task *task = ud;

	rspamd_task_free (task, FALSE);
}


gboolean
rspamd_task_process (struct rspamd_task *task,
	struct rspamd_http_message *msg, const gchar *start, gsize len,
	gboolean process_extra_filters)
{
	gint r;
	guint control_len;
	struct ucl_parser *parser;
	ucl_object_t *control_obj;

	task->msg.start = start;
	task->msg.len = len;
	debug_task ("got string of length %z", task->msg.len);

	if (msg) {
		rspamd_protocol_handle_headers (task, msg);
	}

	if (task->flags & RSPAMD_TASK_FLAG_HAS_CONTROL) {
		/* We have control chunk, so we need to process it separately */
		if (task->msg.len < task->message_len) {
			msg_warn ("message has invalid message length: %ud and total len: %ud",
					task->message_len, task->msg.len);
			task->last_error = "Invalid length";
			task->error_code = RSPAMD_PROTOCOL_ERROR;
			task->state = WRITE_REPLY;
			return FALSE;
		}
		control_len = task->msg.len - task->message_len;

		if (control_len > 0) {
			parser = ucl_parser_new (UCL_PARSER_KEY_LOWERCASE);

			if (!ucl_parser_add_chunk (parser, task->msg.start, control_len)) {
				msg_warn ("processing of control chunk failed: %s",
					ucl_parser_get_error (parser));
				ucl_parser_free (parser);
			}
			else {
				control_obj = ucl_parser_get_object (parser);
				ucl_parser_free (parser);
				rspamd_protocol_handle_control (task, control_obj);
				ucl_object_unref (control_obj);
			}

			task->msg.start += control_len;
			task->msg.len -= control_len;
		}
	}

	r = process_message (task);
	if (r == -1) {
		msg_warn ("processing of message failed");
		task->last_error = "MIME processing error";
		task->error_code = RSPAMD_FILTER_ERROR;
		task->state = WRITE_REPLY;
		return FALSE;
	}
	if (!process_extra_filters) {
		task->flags |= RSPAMD_TASK_FLAG_SKIP_EXTRA;
	}
	if (!process_extra_filters || task->cfg->pre_filters == NULL) {
		r = rspamd_process_filters (task);

		if (r == -1) {
			task->last_error = "filter processing error";
			task->error_code = RSPAMD_FILTER_ERROR;
			task->state = WRITE_REPLY;
			return FALSE;
		}

		if (RSPAMD_TASK_IS_SKIPPED (task)) {
			/* Call write_socket to write reply and exit */
			task->state = WRITE_REPLY;
		}

	}
	else {
		rspamd_lua_call_pre_filters (task);
		/* We want fin_task after pre filters are processed */
		task->state = WAIT_PRE_FILTER;
	}

	rspamd_session_pending (task->s);

	return TRUE;
}

const gchar *
rspamd_task_get_sender (struct rspamd_task *task)
{
	InternetAddress *iaelt = NULL;
#ifdef GMIME24
	InternetAddressMailbox *imb;

	if (task->from_envelope != NULL) {
		iaelt = internet_address_list_get_address (task->from_envelope, 0);
	}
	else if (task->from_mime != NULL) {
		iaelt = internet_address_list_get_address (task->from_mime, 0);
	}
	imb = INTERNET_ADDRESS_IS_MAILBOX(iaelt) ?
			INTERNET_ADDRESS_MAILBOX (iaelt) : NULL;

	return (imb ? internet_address_mailbox_get_addr (imb) : NULL);
#else
	if (task->from_envelope != NULL) {
		iaelt = internet_address_list_get_address (task->from_envelope);
	}
	else if (task->from_mime != NULL) {
		iaelt = internet_address_list_get_address (task->from_mime);
	}

	return (iaelt != NULL ? internet_address_get_addr (iaelt) : NULL);
#endif
}

gboolean
rspamd_task_add_recipient (struct rspamd_task *task, const gchar *rcpt)
{
	InternetAddressList *tmp_addr;

	if (task->rcpt_envelope == NULL) {
		task->rcpt_envelope = internet_address_list_new ();
#ifdef GMIME24
		rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t) g_object_unref,
				task->rcpt_envelope);
#else
		rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t) internet_address_list_destroy,
				task->rcpt_envelope);
#endif
	}
	tmp_addr = internet_address_list_parse_string (rcpt);

	if (tmp_addr) {
		internet_address_list_append (task->rcpt_envelope, tmp_addr);
#ifdef GMIME24
		g_object_unref (tmp_addr);
#else
		internet_address_list_destroy (tmp_addr);
#endif
		return TRUE;
	}

	return FALSE;
}

gboolean
rspamd_task_add_sender (struct rspamd_task *task, const gchar *sender)
{
	InternetAddressList *tmp_addr;

	if (task->from_envelope == NULL) {
		task->from_envelope = internet_address_list_new ();
#ifdef GMIME24
		rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t) g_object_unref,
				task->from_envelope);
#else
		rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t) internet_address_list_destroy,
				task->from_envelope);
#endif
	}
	tmp_addr = internet_address_list_parse_string (sender);

	if (tmp_addr) {
		internet_address_list_append (task->from_envelope, tmp_addr);
#ifdef GMIME24
		g_object_unref (tmp_addr);
#else
		internet_address_list_destroy (tmp_addr);
#endif
		return TRUE;
	}

	return FALSE;
}


guint
rspamd_task_re_cache_add (struct rspamd_task *task, const gchar *re,
		guint value)
{
	guint ret = RSPAMD_TASK_CACHE_NO_VALUE;
	static const guint32 mask = 1 << 31;
	gpointer p;

	p = g_hash_table_lookup (task->re_cache, re);

	if (p != NULL) {
		ret = GPOINTER_TO_INT (p) & ~mask;
	}

	g_hash_table_insert (task->re_cache, (gpointer)re,
			GINT_TO_POINTER (value | mask));

	return ret;
}

guint
rspamd_task_re_cache_check (struct rspamd_task *task, const gchar *re)
{
	guint ret = RSPAMD_TASK_CACHE_NO_VALUE;
	static const guint32 mask = 1 << 31;
	gpointer p;

	p = g_hash_table_lookup (task->re_cache, re);

	if (p != NULL) {
		ret = GPOINTER_TO_INT (p) & ~mask;
	}

	return ret;
}
