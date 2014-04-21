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
#include "message.h"

/*
 * Destructor for recipients list in a task
 */
static void
rcpt_destruct (void *pointer)
{
	struct rspamd_task             *task = (struct rspamd_task *) pointer;

	if (task->rcpt) {
		g_list_free (task->rcpt);
	}
}

/*
 * Create new task
 */
struct rspamd_task             *
rspamd_task_new (struct rspamd_worker *worker)
{
	struct rspamd_task             *new_task;

	new_task = g_slice_alloc0 (sizeof (struct rspamd_task));

	new_task->worker = worker;
	new_task->state = READ_MESSAGE;
	if (worker) {
		new_task->cfg = worker->srv->cfg;
	}
#ifdef HAVE_CLOCK_GETTIME
# ifdef HAVE_CLOCK_PROCESS_CPUTIME_ID
	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &new_task->ts);
# elif defined(HAVE_CLOCK_VIRTUAL)
	clock_gettime (CLOCK_VIRTUAL, &new_task->ts);
# else
	clock_gettime (CLOCK_REALTIME, &new_task->ts);
# endif
#endif
	if (gettimeofday (&new_task->tv, NULL) == -1) {
		msg_warn ("gettimeofday failed: %s", strerror (errno));
	}

	new_task->task_pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());

	/* Add destructor for recipients list (it would be better to use anonymous function here */
	rspamd_mempool_add_destructor (new_task->task_pool,
			(rspamd_mempool_destruct_t) rcpt_destruct, new_task);
	new_task->results = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	rspamd_mempool_add_destructor (new_task->task_pool,
			(rspamd_mempool_destruct_t) g_hash_table_destroy,
			new_task->results);
	new_task->re_cache = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	rspamd_mempool_add_destructor (new_task->task_pool,
			(rspamd_mempool_destruct_t) g_hash_table_destroy,
			new_task->re_cache);
	new_task->raw_headers = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
	rspamd_mempool_add_destructor (new_task->task_pool,
				(rspamd_mempool_destruct_t) g_hash_table_destroy,
				new_task->raw_headers);
	new_task->emails = g_tree_new (compare_email_func);
	rspamd_mempool_add_destructor (new_task->task_pool,
				(rspamd_mempool_destruct_t) g_tree_destroy,
				new_task->emails);
	new_task->urls = g_tree_new (compare_url_func);
	rspamd_mempool_add_destructor (new_task->task_pool,
					(rspamd_mempool_destruct_t) g_tree_destroy,
					new_task->urls);
	new_task->sock = -1;
	new_task->is_mime = TRUE;
	new_task->pre_result.action = METRIC_ACTION_NOACTION;

	new_task->message_id = new_task->queue_id = "undef";

	return new_task;
}


/*
 * Free all structures of worker_task
 */
void
rspamd_task_free (struct rspamd_task *task, gboolean is_soft)
{
	GList                          *part;
	struct mime_part               *p;

	if (task) {
		debug_task ("free pointer %p", task);
		while ((part = g_list_first (task->parts))) {
			task->parts = g_list_remove_link (task->parts, part);
			p = (struct mime_part *) part->data;
			g_byte_array_free (p->content, TRUE);
			g_list_free_1 (part);
		}
		if (task->text_parts) {
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
		rspamd_mempool_delete (task->task_pool);
		g_slice_free1 (sizeof (struct rspamd_task), task);
	}
}

void
rspamd_task_free_hard (gpointer ud)
{
  struct rspamd_task             *task = ud;

  rspamd_task_free (task, FALSE);
}

void
rspamd_task_free_soft (gpointer ud)
{
  struct rspamd_task             *task = ud;

  rspamd_task_free (task, FALSE);
}
