/* Copyright (c) 2010-2011, Vsevolod Stakhov
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

#include "config.h"
#include "main.h"
#include "message.h"

extern struct rspamd_main			*rspamd_main;

/*
 * Destructor for recipients list in a task
 */
static void
rcpt_destruct (void *pointer)
{
	struct worker_task             *task = (struct worker_task *) pointer;

	if (task->rcpt) {
		g_list_free (task->rcpt);
	}
}

/*
 * Create new task
 */
struct worker_task             *
construct_task (struct rspamd_worker *worker)
{
	struct worker_task             *new_task;

	new_task = g_slice_alloc0 (sizeof (struct worker_task));

	new_task->worker = worker;
	new_task->state = READ_MESSAGE;
	if (worker) {
		new_task->cfg = worker->srv->cfg;
	}
	new_task->view_checked = FALSE;
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

	new_task->task_pool = memory_pool_new (memory_pool_get_size ());

	/* Add destructor for recipients list (it would be better to use anonymous function here */
	memory_pool_add_destructor (new_task->task_pool,
			(pool_destruct_func) rcpt_destruct, new_task);
	new_task->results = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	memory_pool_add_destructor (new_task->task_pool,
			(pool_destruct_func) g_hash_table_destroy,
			new_task->results);
	new_task->re_cache = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	memory_pool_add_destructor (new_task->task_pool,
			(pool_destruct_func) g_hash_table_destroy,
			new_task->re_cache);
	new_task->raw_headers = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
	memory_pool_add_destructor (new_task->task_pool,
				(pool_destruct_func) g_hash_table_destroy,
				new_task->raw_headers);
	new_task->emails = g_tree_new (compare_email_func);
	memory_pool_add_destructor (new_task->task_pool,
				(pool_destruct_func) g_tree_destroy,
				new_task->emails);
	new_task->urls = g_tree_new (compare_url_func);
	memory_pool_add_destructor (new_task->task_pool,
					(pool_destruct_func) g_tree_destroy,
					new_task->urls);
	new_task->sock = -1;
	new_task->is_mime = TRUE;
	new_task->pre_result.action = METRIC_ACTION_NOACTION;

	return new_task;
}

/**
 * Return worker's control structure by its type
 * @param type
 * @return worker's control structure or NULL
 */
worker_t*
get_worker_by_type (GQuark type)
{
	worker_t						**cur;

	cur = &workers[0];
	while (*cur) {
		if (g_quark_from_string ((*cur)->name) == type) {
			return *cur;
		}
		cur ++;
	}

	return NULL;
}


/*
 * Free all structures of worker_task
 */
void
free_task (struct worker_task *task, gboolean is_soft)
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
		if (task->dispatcher) {
			if (is_soft) {
				/* Plan dispatcher shutdown */
				task->dispatcher->wanna_die = 1;
			}
			else {
				rspamd_remove_dispatcher (task->dispatcher);
			}
		}
		if (task->http_conn != NULL) {
			rspamd_http_connection_unref (task->http_conn);
		}
		if (task->sock != -1) {
			close (task->sock);
		}
		memory_pool_delete (task->task_pool);
		g_slice_free1 (sizeof (struct worker_task), task);
	}
}

void
free_task_hard (gpointer ud)
{
  struct worker_task             *task = ud;

  free_task (task, FALSE);
}

void
free_task_soft (gpointer ud)
{
  struct worker_task             *task = ud;

  free_task (task, FALSE);
}

double
set_counter (const gchar *name, guint32 value)
{
	struct counter_data            *cd;
	double                          alpha;
	gchar                           *key;

	cd = rspamd_hash_lookup (rspamd_main->counters, (gpointer) name);

	if (cd == NULL) {
		cd = memory_pool_alloc_shared (rspamd_main->counters->pool, sizeof (struct counter_data));
		cd->value = value;
		cd->number = 0;
		key = memory_pool_strdup_shared (rspamd_main->counters->pool, name);
		rspamd_hash_insert (rspamd_main->counters, (gpointer) key, (gpointer) cd);
	}
	else {
		/* Calculate new value */
		memory_pool_wlock_rwlock (rspamd_main->counters->lock);

		alpha = 2. / (++cd->number + 1);
		cd->value = cd->value * (1. - alpha) + value * alpha;

		memory_pool_wunlock_rwlock (rspamd_main->counters->lock);
	}

	return cd->value;
}

struct event_base *
prepare_worker (struct rspamd_worker *worker, const char *name,
		rspamd_sig_handler_t sig_handler,
		void (*accept_handler)(int, short, void *))
{
	struct event_base                *ev_base;
	struct event                     *accept_event;
	struct sigaction                  signals;
	GList                             *cur;
	gint                               listen_socket;

#ifdef WITH_PROFILER
	extern void                     _start (void), etext (void);
	monstartup ((u_long) & _start, (u_long) & etext);
#endif

	gperf_profiler_init (worker->srv->cfg, "worker");

	worker->srv->pid = getpid ();

	ev_base = event_init ();

	init_signals (&signals, sig_handler);
	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);

	/* Accept all sockets */
	cur = worker->cf->listen_socks;
	while (cur) {
		listen_socket = GPOINTER_TO_INT (cur->data);
		if (listen_socket != -1) {
			accept_event = g_slice_alloc0 (sizeof (struct event));
			event_set (accept_event, listen_socket, EV_READ | EV_PERSIST,
					accept_handler, worker);
			event_base_set (ev_base, accept_event);
			event_add (accept_event, NULL);
			worker->accept_events = g_list_prepend (worker->accept_events, accept_event);
		}
		cur = g_list_next (cur);
	}

	return ev_base;
}

void
worker_stop_accept (struct rspamd_worker *worker)
{
	GList                             *cur;
	struct event                     *event;

	/* Remove all events */
	cur = worker->accept_events;
	while (cur) {
		event = cur->data;
		event_del (event);
		cur = g_list_next (cur);
		g_slice_free1 (sizeof (struct event), event);
	}

	if (worker->accept_events != NULL) {
		g_list_free (worker->accept_events);
	}
}
