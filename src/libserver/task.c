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
		new_task->pass_all_filters = new_task->cfg->check_all_filters;
	}
#ifdef HAVE_CLOCK_GETTIME
# ifdef HAVE_CLOCK_PROCESS_CPUTIME_ID
	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &new_task->ts);
# elif defined(HAVE_CLOCK_VIRTUAL)
	clock_gettime (CLOCK_VIRTUAL,			 &new_task->ts);
# else
	clock_gettime (CLOCK_REALTIME,			 &new_task->ts);
# endif
#endif
	if (gettimeofday (&new_task->tv, NULL) == -1) {
		msg_warn ("gettimeofday failed: %s", strerror (errno));
	}

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
	new_task->request_headers = g_hash_table_new_full ((GHashFunc)g_string_hash,
		(GEqualFunc)g_string_equal, gstring_destruct, gstring_destruct);
	rspamd_mempool_add_destructor (new_task->task_pool,
		(rspamd_mempool_destruct_t) g_hash_table_unref,
		new_task->request_headers);
	new_task->reply_headers = g_hash_table_new_full ((GHashFunc)g_string_hash,
		(GEqualFunc)g_string_equal, gstring_destruct, gstring_destruct);
	rspamd_mempool_add_destructor (new_task->task_pool,
		(rspamd_mempool_destruct_t) g_hash_table_unref,
		new_task->reply_headers);
	rspamd_mempool_add_destructor (new_task->task_pool,
		(rspamd_mempool_destruct_t) g_hash_table_unref,
		new_task->raw_headers);
	new_task->emails = g_tree_new (rspamd_emails_cmp);
	rspamd_mempool_add_destructor (new_task->task_pool,
		(rspamd_mempool_destruct_t) g_tree_destroy,
		new_task->emails);
	new_task->urls = g_tree_new (rspamd_urls_cmp);
	rspamd_mempool_add_destructor (new_task->task_pool,
		(rspamd_mempool_destruct_t) g_tree_destroy,
		new_task->urls);
	new_task->sock = -1;
	new_task->is_mime = TRUE;
	new_task->is_json = TRUE;
	new_task->pre_result.action = METRIC_ACTION_NOACTION;

	new_task->message_id = new_task->queue_id = "undef";

	return new_task;
}


static void
rspamd_task_reply (struct rspamd_task *task)
{
	if (task->fin_callback) {
		task->fin_callback (task->fin_arg);
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
	GError *err = NULL;

	/* Task is already finished or skipped */
	if (task->state == WRITE_REPLY) {
		rspamd_task_reply (task);
		return TRUE;
	}

	/* We processed all filters and want to process statfiles */
	if (task->state != WAIT_POST_FILTER && task->state != WAIT_PRE_FILTER) {
		/* Process all statfiles */
		if (task->classify_pool == NULL) {
			/* Non-threaded version */
			rspamd_process_statistics (task);
		}
		else {
			/* Just process composites */
			rspamd_make_composites (task);
		}
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
			/* Add task to classify to classify pool */
			if (!task->is_skipped && task->classify_pool) {
				register_async_thread (task->s);
				g_thread_pool_push (task->classify_pool, task, &err);
				if (err != NULL) {
					msg_err ("cannot pull task to the pool: %s", err->message);
					remove_async_thread (task->s);
					g_error_free (err);
				}
			}
			if (task->is_skipped) {
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
	if (task->state == WAIT_POST_FILTER && !task->skip_extra_filters) {
		rspamd_lua_call_post_filters (task);
	}
	task->s->wanna_die = TRUE;
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
		if (task->peer_key != NULL) {
			rspamd_http_connection_key_unref (task->peer_key);
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
	struct rspamd_http_message *msg, GThreadPool *classify_pool,
	gboolean process_extra_filters)
{
	gint r;
	GError *err = NULL;

	if (msg->body->len == 0) {
		msg_err ("got zero length body");
		task->last_error = "message's body is empty";
		return FALSE;
	}

	/* XXX: awful hack */
	if (msg->peer_key != NULL) {
		task->msg = rspamd_mempool_alloc (task->task_pool, sizeof (GString));
		task->msg->len = msg->body->len - 16;
		task->msg->allocated_len = 0;
		task->msg->str = msg->body->str + 16;
	}
	else {
		task->msg = msg->body;
	}
	debug_task ("got string of length %z", task->msg->len);

	/* We got body, set wanna_die flag */
	task->s->wanna_die = TRUE;

	rspamd_protocol_handle_headers (task, msg);

	r = process_message (task);
	if (r == -1) {
		msg_warn ("processing of message failed");
		task->last_error = "MIME processing error";
		task->error_code = RSPAMD_FILTER_ERROR;
		task->state = WRITE_REPLY;
		return FALSE;
	}
	task->skip_extra_filters = !process_extra_filters;
	if (!process_extra_filters || task->cfg->pre_filters == NULL) {
		r = rspamd_process_filters (task);
		if (r == -1) {
			task->last_error = "filter processing error";
			task->error_code = RSPAMD_FILTER_ERROR;
			task->state = WRITE_REPLY;
			return FALSE;
		}
		/* Add task to classify to classify pool */
		if (!task->is_skipped && classify_pool) {
			register_async_thread (task->s);
			g_thread_pool_push (classify_pool, task, &err);
			if (err != NULL) {
				msg_err ("cannot pull task to the pool: %s", err->message);
				remove_async_thread (task->s);
				g_error_free (err);
			}
			else {
				task->classify_pool = classify_pool;
			}
		}
		if (task->is_skipped) {
			/* Call write_socket to write reply and exit */
			task->state = WRITE_REPLY;
		}
		task->s->wanna_die = TRUE;
	}
	else {
		rspamd_lua_call_pre_filters (task);
		/* We want fin_task after pre filters are processed */
		task->s->wanna_die = TRUE;
		task->state = WAIT_PRE_FILTER;
	}

	return TRUE;
}

const gchar *
rspamd_task_get_sender (struct rspamd_task *task)
{
	InternetAddressMailbox *imb;
	InternetAddress *iaelt = NULL;


	if (task->from_envelope != NULL) {
		iaelt = internet_address_list_get_address (task->from_envelope, 0);
	}
	else if (task->from_mime != NULL) {
		iaelt = internet_address_list_get_address (task->from_mime, 0);
	}
	imb = INTERNET_ADDRESS_IS_MAILBOX(iaelt) ?
			INTERNET_ADDRESS_MAILBOX (iaelt) : NULL;

	return (imb ? internet_address_mailbox_get_addr (imb) : NULL);
}
