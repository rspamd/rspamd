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
#include "rspamd.h"
#include "libmime/message.h"
#include "lua/lua_common.h"
#include "unix-std.h"
#include "cfg_file_private.h"

static const gchar rspamd_history_magic_old[] = {'r', 's', 'h', '1'};

/**
 * Returns new roll history
 * @param pool pool for shared memory
 * @return new structure
 */
struct roll_history *
rspamd_roll_history_new (rspamd_mempool_t *pool, guint max_rows,
		struct rspamd_config *cfg)
{
	struct roll_history *history;
	lua_State *L = cfg->lua_state;

	if (pool == NULL || max_rows == 0) {
		return NULL;
	}

	history = rspamd_mempool_alloc0_shared (pool, sizeof (struct roll_history));

	/*
	 * Here, we check if there is any plugin that handles history,
	 * in this case, we disable this code completely
	 */
	lua_getglobal (L, "rspamd_plugins");
	if (lua_istable (L, -1)) {
		lua_pushstring (L, "history");
		lua_gettable (L, -2);

		if (lua_istable (L, -1)) {
			history->disabled = TRUE;
		}

		lua_pop (L, 1);
	}

	lua_pop (L, 1);

	if (!history->disabled) {
		history->rows = rspamd_mempool_alloc0_shared (pool,
				sizeof (struct roll_history_row) * max_rows);
		history->nrows = max_rows;
	}

	return history;
}

struct history_metric_callback_data {
	gchar *pos;
	gint remain;
};

static void
roll_history_symbols_callback (gpointer key, gpointer value, void *user_data)
{
	struct history_metric_callback_data *cb = user_data;
	struct rspamd_symbol_result *s = value;
	guint wr;

	if (s->flags & RSPAMD_SYMBOL_RESULT_IGNORED) {
		return;
	}

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
rspamd_roll_history_update (struct roll_history *history,
	struct rspamd_task *task)
{
	guint row_num;
	struct roll_history_row *row;
	struct rspamd_scan_result *metric_res;
	struct history_metric_callback_data cbdata;
	struct rspamd_action *action;

	if (history->disabled) {
		return;
	}

	/* First of all obtain check and obtain row number */
	g_atomic_int_compare_and_exchange (&history->cur_row, history->nrows, 0);
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	row_num = g_atomic_int_add (&history->cur_row, 1);
#else
	row_num = g_atomic_int_exchange_and_add (&history->cur_row, 1);
#endif

	if (row_num < history->nrows) {
		row = &history->rows[row_num];
		g_atomic_int_set (&row->completed, FALSE);
	}
	else {
		/* Race condition */
		history->cur_row = 0;
		return;
	}

	/* Add information from task to roll history */
	if (task->from_addr) {
		rspamd_strlcpy (row->from_addr,
				rspamd_inet_address_to_string (task->from_addr),
				sizeof (row->from_addr));
	}
	else {
		rspamd_strlcpy (row->from_addr, "unknown", sizeof (row->from_addr));
	}

	row->timestamp = task->task_timestamp;

	/* Strings */
	if (task->message) {
		rspamd_strlcpy (row->message_id, MESSAGE_FIELD (task, message_id),
				sizeof (row->message_id));
	}
	if (task->user) {
		rspamd_strlcpy (row->user, task->user, sizeof (row->user));
	}
	else {
		row->user[0] = '\0';
	}

	/* Get default metric */
	metric_res = task->result;

	if (metric_res == NULL) {
		row->symbols[0] = '\0';
		row->action = METRIC_ACTION_NOACTION;
	}
	else {
		row->score = metric_res->score;
		action = rspamd_check_action_metric (task, NULL, NULL);
		row->action = action->action_type;
		row->required_score = rspamd_task_get_required_score (task, metric_res);
		cbdata.pos = row->symbols;
		cbdata.remain = sizeof (row->symbols);
		rspamd_task_symbol_result_foreach (task, NULL,
				roll_history_symbols_callback,
				&cbdata);
		if (cbdata.remain > 0) {
			/* Remove last whitespace and comma */
			*cbdata.pos-- = '\0';
			*cbdata.pos-- = '\0';
			*cbdata.pos = '\0';
		}
	}

	row->scan_time = task->time_real_finish - task->task_timestamp;
	row->len = task->msg.len;
	g_atomic_int_set (&row->completed, TRUE);
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
	gint fd;
	struct stat st;
	gchar magic[sizeof(rspamd_history_magic_old)];
	ucl_object_t *top;
	const ucl_object_t *cur, *elt;
	struct ucl_parser *parser;
	struct roll_history_row *row;
	guint n, i;

	g_assert (history != NULL);
	if (history->disabled) {
		return TRUE;
	}

	if (stat (filename, &st) == -1) {
		msg_info ("cannot load history from %s: %s", filename,
			strerror (errno));
		return FALSE;
	}

	if ((fd = open (filename, O_RDONLY)) == -1) {
		msg_info ("cannot load history from %s: %s", filename,
			strerror (errno));
		return FALSE;
	}

	/* Check for old format */
	if (read (fd, magic, sizeof (magic)) == -1) {
		close (fd);
		msg_info ("cannot read history from %s: %s", filename,
				strerror (errno));
		return FALSE;
	}

	if (memcmp (magic, rspamd_history_magic_old, sizeof (magic)) == 0) {
		close (fd);
		msg_warn ("cannot read history from old format %s, "
				"it will be replaced after restart", filename);
		return FALSE;
	}

	parser = ucl_parser_new (0);

	if (!ucl_parser_add_fd (parser, fd)) {
		msg_warn ("cannot parse history file %s: %s", filename,
				ucl_parser_get_error (parser));
		ucl_parser_free (parser);
		close (fd);

		return FALSE;
	}

	top = ucl_parser_get_object (parser);
	ucl_parser_free (parser);
	close (fd);

	if (top == NULL) {
		msg_warn ("cannot parse history file %s: no object", filename);

		return FALSE;
	}

	if (ucl_object_type (top) != UCL_ARRAY) {
		msg_warn ("invalid object type read from: %s", filename);
		ucl_object_unref (top);

		return FALSE;
	}

	if (top->len > history->nrows) {
		msg_warn ("stored history is larger than the current one: %ud (file) vs "
				"%ud (history)", top->len, history->nrows);
		n = history->nrows;
	}
	else if (top->len < history->nrows) {
		msg_warn (
				"stored history is smaller than the current one: %ud (file) vs "
						"%ud (history)",
				top->len, history->nrows);
		n = top->len;
	}
	else {
		n = top->len;
	}

	for (i = 0; i < n; i ++) {
		cur = ucl_array_find_index (top, i);

		if (cur != NULL && ucl_object_type (cur) == UCL_OBJECT) {
			row = &history->rows[i];
			memset (row, 0, sizeof (*row));

			elt = ucl_object_lookup (cur, "time");

			if (elt && ucl_object_type (elt) == UCL_FLOAT) {
				row->timestamp = ucl_object_todouble (elt);
			}

			elt = ucl_object_lookup (cur, "id");

			if (elt && ucl_object_type (elt) == UCL_STRING) {
				rspamd_strlcpy (row->message_id, ucl_object_tostring (elt),
						sizeof (row->message_id));
			}

			elt = ucl_object_lookup (cur, "symbols");

			if (elt && ucl_object_type (elt) == UCL_STRING) {
				rspamd_strlcpy (row->symbols, ucl_object_tostring (elt),
						sizeof (row->symbols));
			}

			elt = ucl_object_lookup (cur, "user");

			if (elt && ucl_object_type (elt) == UCL_STRING) {
				rspamd_strlcpy (row->user, ucl_object_tostring (elt),
						sizeof (row->user));
			}

			elt = ucl_object_lookup (cur, "from");

			if (elt && ucl_object_type (elt) == UCL_STRING) {
				rspamd_strlcpy (row->from_addr, ucl_object_tostring (elt),
						sizeof (row->from_addr));
			}

			elt = ucl_object_lookup (cur, "len");

			if (elt && ucl_object_type (elt) == UCL_INT) {
				row->len = ucl_object_toint (elt);
			}

			elt = ucl_object_lookup (cur, "scan_time");

			if (elt && ucl_object_type (elt) == UCL_FLOAT) {
				row->scan_time = ucl_object_todouble (elt);
			}

			elt = ucl_object_lookup (cur, "score");

			if (elt && ucl_object_type (elt) == UCL_FLOAT) {
				row->score = ucl_object_todouble (elt);
			}

			elt = ucl_object_lookup (cur, "required_score");

			if (elt && ucl_object_type (elt) == UCL_FLOAT) {
				row->required_score = ucl_object_todouble (elt);
			}

			elt = ucl_object_lookup (cur, "action");

			if (elt && ucl_object_type (elt) == UCL_INT) {
				row->action = ucl_object_toint (elt);
			}

			row->completed = TRUE;
		}
	}

	ucl_object_unref (top);

	history->cur_row = n;

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
	gint fd;
	FILE *fp;
	ucl_object_t *obj, *elt;
	guint i;
	struct roll_history_row *row;
	struct ucl_emitter_functions *emitter_func;

	g_assert (history != NULL);

	if (history->disabled) {
		return TRUE;
	}

	if ((fd = open (filename, O_WRONLY | O_CREAT | O_TRUNC, 00600)) == -1) {
		msg_info ("cannot save history to %s: %s", filename, strerror (errno));
		return FALSE;
	}

	fp = fdopen (fd, "w");
	obj = ucl_object_typed_new (UCL_ARRAY);

	for (i = 0; i < history->nrows; i ++) {
		row = &history->rows[i];

		if (!row->completed) {
			continue;
		}

		elt = ucl_object_typed_new (UCL_OBJECT);

		ucl_object_insert_key (elt, ucl_object_fromdouble (row->timestamp),
				"time", 0, false);
		ucl_object_insert_key (elt, ucl_object_fromstring (row->message_id),
				"id", 0, false);
		ucl_object_insert_key (elt, ucl_object_fromstring (row->symbols),
				"symbols", 0, false);
		ucl_object_insert_key (elt, ucl_object_fromstring (row->user),
				"user", 0, false);
		ucl_object_insert_key (elt, ucl_object_fromstring (row->from_addr),
				"from", 0, false);
		ucl_object_insert_key (elt, ucl_object_fromint (row->len),
				"len", 0, false);
		ucl_object_insert_key (elt, ucl_object_fromdouble (row->scan_time),
				"scan_time", 0, false);
		ucl_object_insert_key (elt, ucl_object_fromdouble (row->score),
				"score", 0, false);
		ucl_object_insert_key (elt, ucl_object_fromdouble (row->required_score),
				"required_score", 0, false);
		ucl_object_insert_key (elt, ucl_object_fromint (row->action),
				"action", 0, false);

		ucl_array_append (obj, elt);
	}

	emitter_func = ucl_object_emit_file_funcs (fp);
	ucl_object_emit_full (obj, UCL_EMIT_JSON_COMPACT, emitter_func, NULL);
	ucl_object_emit_funcs_free (emitter_func);
	ucl_object_unref (obj);

	fclose (fp);

	return TRUE;
}
