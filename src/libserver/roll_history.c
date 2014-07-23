/* Copyright (c) 2010-2012, Vsevolod Stakhov
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
#include "roll_history.h"


/**
 * Returns new roll history
 * @param pool pool for shared memory
 * @return new structure
 */
struct roll_history*
rspamd_roll_history_new (rspamd_mempool_t *pool)
{
	struct roll_history						*new;

	if (pool == NULL) {
		return NULL;
	}

	new = rspamd_mempool_alloc0_shared (pool, sizeof (struct roll_history));
	new->pool = pool;
	new->mtx = rspamd_mempool_get_mutex (pool);

	return new;
}

struct history_metric_callback_data {
	gchar *pos;
	gint remain;
};

static void
roll_history_symbols_callback (gpointer key, gpointer value, void *user_data)
{
	struct history_metric_callback_data		*cb = user_data;
	struct symbol							*s = value;
	guint									 wr;

	if (cb->remain > 0) {
		wr = rspamd_snprintf (cb->pos, cb->remain, "%s, ", s->name);
		cb->pos += wr;
		cb->remain -= wr;
	}
}

/**
 * Update roll history with data from task
 * @param history roll history object
 * @param task task object
 */
void
rspamd_roll_history_update (struct roll_history *history, struct rspamd_task *task)
{
	gint									 row_num;
	struct roll_history_row					*row;
	struct metric_result					*metric_res;
	struct history_metric_callback_data		 cbdata;

	if (history->need_lock) {
		/* Some process is getting history, so wait on a mutex */
		rspamd_mempool_lock_mutex (history->mtx);
		history->need_lock = FALSE;
		rspamd_mempool_unlock_mutex (history->mtx);
	}

	/* First of all obtain check and obtain row number */
	g_atomic_int_compare_and_exchange (&history->cur_row, HISTORY_MAX_ROWS, 0);
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	row_num = g_atomic_int_add (&history->cur_row, 1);
#else
	row_num = g_atomic_int_exchange_and_add (&history->cur_row, 1);
#endif

	if (row_num < HISTORY_MAX_ROWS) {
		row = &history->rows[row_num];
		row->completed = FALSE;
	}
	else {
		/* Race condition */
		history->cur_row = 0;
		return;
	}

	/* Add information from task to roll history */
	memcpy (&row->from_addr, &task->from_addr, sizeof (row->from_addr));
	memcpy (&row->tv, &task->tv, sizeof (row->tv));

	/* Strings */
	rspamd_strlcpy (row->message_id, task->message_id, sizeof (row->message_id));
	if (task->user) {
		rspamd_strlcpy (row->user, task->user, sizeof (row->message_id));
	}
	else {
		row->user[0] = '\0';
	}

	/* Get default metric */
	metric_res =  g_hash_table_lookup (task->results, DEFAULT_METRIC);
	if (metric_res == NULL) {
		row->symbols[0] = '\0';
		row->action = METRIC_ACTION_NOACTION;
	}
	else {
		row->score = metric_res->score;
		row->required_score = metric_res->metric->actions[METRIC_ACTION_REJECT].score;
		row->action = check_metric_action (metric_res->score,
				metric_res->metric->actions[METRIC_ACTION_REJECT].score, metric_res->metric);
		cbdata.pos = row->symbols;
		cbdata.remain = sizeof (row->symbols);
		g_hash_table_foreach (metric_res->symbols, roll_history_symbols_callback, &cbdata);
		if (cbdata.remain > 0) {
			/* Remove last whitespace and comma */
			*cbdata.pos-- = '\0';
			*cbdata.pos-- = '\0';
			*cbdata.pos = '\0';
		}
	}

	row->scan_time = task->scan_milliseconds;
	row->len = (task->msg == NULL ? 0 : task->msg->len);
	row->completed = TRUE;
}

/**
 * Load previously saved history from file
 * @param history roll history object
 * @param filename filename to load from
 * @return TRUE if history has been loaded
 */
gboolean
rspamd_roll_history_load (struct roll_history *history, const gchar *filename)
{
	gint									 fd;
	struct stat								 st;

	if (stat (filename, &st) == -1) {
		msg_info ("cannot load history from %s: %s", filename, strerror (errno));
		return FALSE;
	}

	if (st.st_size != sizeof (history->rows)) {
		msg_info ("cannot load history from %s: size mismatch", filename);
		return FALSE;
	}

	if ((fd = open (filename, O_RDONLY)) == -1) {
		msg_info ("cannot load history from %s: %s", filename, strerror (errno));
		return FALSE;
	}

	if (read (fd, history->rows, sizeof (history->rows)) == -1) {
		close (fd);
		msg_info ("cannot read history from %s: %s", filename, strerror (errno));
		return FALSE;
	}

	close (fd);

	return TRUE;
}

/**
 * Save history to file
 * @param history roll history object
 * @param filename filename to load from
 * @return TRUE if history has been saved
 */
gboolean
rspamd_roll_history_save (struct roll_history *history, const gchar *filename)
{
	gint									 fd;

	if ((fd = open (filename, O_WRONLY | O_CREAT | O_TRUNC, 00600)) == -1) {
		msg_info ("cannot save history to %s: %s", filename, strerror (errno));
		return FALSE;
	}

	if (write (fd, history->rows, sizeof (history->rows)) == -1) {
		close (fd);
		msg_info ("cannot write history to %s: %s", filename, strerror (errno));
		return FALSE;
	}

	close (fd);

	return TRUE;
}
