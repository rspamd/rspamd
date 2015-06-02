/* Copyright (c) 2014-2015, Vsevolod Stakhov
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
#include "composites.h"
#include "stat_api.h"

static GQuark
rspamd_task_quark (void)
{
	return g_quark_from_static_string ("task-error");
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
		rspamd_gstring_icase_equal, rspamd_gstring_free_hard,
		rspamd_gstring_free_hard);
	rspamd_mempool_add_destructor (new_task->task_pool,
		(rspamd_mempool_destruct_t) g_hash_table_unref,
		new_task->request_headers);
	new_task->reply_headers = g_hash_table_new_full (rspamd_gstring_icase_hash,
			rspamd_gstring_icase_equal, rspamd_gstring_free_hard,
			rspamd_gstring_free_hard);
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

	/* Task is already finished or skipped */
	if (RSPAMD_TASK_IS_PROCESSED (task)) {
		rspamd_task_reply (task);
		return TRUE;
	}

	if (!rspamd_task_process (task, RSPAMD_TASK_PROCESS_ALL)) {
		rspamd_task_reply (task);
		return TRUE;
	}

	/* One more iteration */
	return FALSE;
}

/*
 * Called if session was restored inside fin callback
 */
void
rspamd_task_restore (void *arg)
{
	/* XXX: not needed now ? */
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
		if (task->err) {
			g_error_free (task->err);
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
rspamd_task_load_message (struct rspamd_task *task,
	struct rspamd_http_message *msg, const gchar *start, gsize len)
{
	guint control_len;
	struct ucl_parser *parser;
	ucl_object_t *control_obj;

	debug_task ("got input of length %z", task->msg.len);
	task->msg.start = start;
	task->msg.len = len;

	if (msg) {
		rspamd_protocol_handle_headers (task, msg);
	}

	if (task->flags & RSPAMD_TASK_FLAG_HAS_CONTROL) {
		/* We have control chunk, so we need to process it separately */
		if (task->msg.len < task->message_len) {
			msg_warn ("message has invalid message length: %ud and total len: %ud",
					task->message_len, task->msg.len);
			g_set_error (&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"Invalid length");
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

	return TRUE;
}

static gint
rspamd_task_select_processing_stage (struct rspamd_task *task, guint stages)
{
	gint st, mask;

	mask = task->processed_stages;

	if (mask == 0) {
		st = 0;
	}
	else {
		for (st = 1; mask != 1; st ++) {
			mask = (unsigned int)mask >> 1;
		}
	}

	st = 1 << st;

	if (stages & st) {
		return st;
	}
	else if (st < RSPAMD_TASK_STAGE_DONE) {
		/* We assume that the stage that was not requested is done */
		task->processed_stages |= st;
		return rspamd_task_select_processing_stage (task, stages);
	}

	/* We are done */
	return RSPAMD_TASK_STAGE_DONE;
}

static gboolean
check_metric_settings (struct rspamd_task *task, struct metric *metric,
	double *score)
{
	const ucl_object_t *mobj, *reject, *act;
	double val;

	if (task->settings == NULL) {
		return FALSE;
	}

	mobj = ucl_object_find_key (task->settings, metric->name);
	if (mobj != NULL) {
		act = ucl_object_find_key (mobj, "actions");
		if (act != NULL) {
			reject = ucl_object_find_key (act,
					rspamd_action_to_str (METRIC_ACTION_REJECT));
			if (reject != NULL && ucl_object_todouble_safe (reject, &val)) {
				*score = val;
				return TRUE;
			}
		}
	}

	return FALSE;
}

/* Return true if metric has score that is more than spam score for it */
static gboolean
check_metric_is_spam (struct rspamd_task *task, struct metric *metric)
{
	struct metric_result *res;
	double ms;

	res = g_hash_table_lookup (task->results, metric->name);
	if (res) {
		if (!check_metric_settings (task, metric, &ms)) {
			ms = metric->actions[METRIC_ACTION_REJECT].score;
		}
		return (ms > 0 && res->score >= ms);
	}

	return FALSE;
}

static gboolean
rspamd_process_filters (struct rspamd_task *task)
{
	GList *cur;
	struct metric *metric;
	gpointer item = NULL;

	/* Insert default metric to be sure that it exists all the time */

	if (task->checkpoint == NULL) {
		rspamd_create_metric_result (task, DEFAULT_METRIC);
		if (task->settings) {
			const ucl_object_t *wl;

			wl = ucl_object_find_key (task->settings, "whitelist");
			if (wl != NULL) {
				msg_info ("<%s> is whitelisted", task->message_id);
				task->flags |= RSPAMD_TASK_FLAG_SKIP;
				return TRUE;
			}
		}

		task->checkpoint = GUINT_TO_POINTER (0x1);
	}
	else {
		/* TODO: in future, we need to add dependencies here */
		return TRUE;
	}

	/* Process metrics symbols */
	while (rspamd_symbols_cache_process_symbol (task, task->cfg->cache, &item)) {
		/* Check reject actions */
		cur = task->cfg->metrics_list;
		while (cur) {
			metric = cur->data;
			if (!(task->flags & RSPAMD_TASK_FLAG_PASS_ALL) &&
				metric->actions[METRIC_ACTION_REJECT].score > 0 &&
				check_metric_is_spam (task, metric)) {
				msg_info ("<%s> has already scored more than %.2f, so do not "
						"plan any more checks", task->message_id,
						metric->actions[METRIC_ACTION_REJECT].score);
				return TRUE;
			}
			cur = g_list_next (cur);
		}
	}

	return TRUE;
}

gboolean
rspamd_task_process (struct rspamd_task *task, guint stages)
{
	gint st;

	if (RSPAMD_TASK_IS_PROCESSED (task)) {
		return TRUE;
	}

	st = rspamd_task_select_processing_stage (task, stages);

	switch (st) {
	case RSPAMD_TASK_STAGE_READ_MESSAGE:
		if (!rspamd_message_parse (task)) {
			return FALSE;
		}
		break;

	case RSPAMD_TASK_STAGE_PRE_FILTERS:
		rspamd_lua_call_pre_filters (task);
		break;

	case RSPAMD_TASK_STAGE_FILTERS:
		if (!rspamd_process_filters (task)) {
			return FALSE;
		}
		break;

	case RSPAMD_TASK_STAGE_CLASSIFIERS:
		if (!rspamd_stat_classify (task, task->cfg->lua_state, &task->err)) {
			return FALSE;
		}
		break;

	case RSPAMD_TASK_STAGE_COMPOSITES:
		rspamd_make_composites (task);
		break;

	case RSPAMD_TASK_STAGE_POST_FILTERS:
		rspamd_lua_call_post_filters (task);
		break;

	case RSPAMD_TASK_STAGE_DONE:
		task->processed_stages |= RSPAMD_TASK_STAGE_DONE;
		return TRUE;

	default:
		/* TODO: not implemented stage */
		break;
	}

	if (RSPAMD_TASK_IS_SKIPPED (task)) {
		task->processed_stages |= RSPAMD_TASK_STAGE_DONE;
		return TRUE;
	}

	if (rspamd_session_events_pending (task->s) != 0) {
		/* We have events pending, so we consider this stage as incomplete */
		msg_debug ("need more work on stage %d", st);
	}
	else {
		/* Mark the current stage as done and go to the next stage */
		msg_debug ("completed stage %d", st);
		task->processed_stages |= st;

		/* Reset checkpoint */
		task->checkpoint = NULL;

		/* Tail recursion */
		return rspamd_task_process (task, stages);
	}

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

gboolean
rspamd_learn_task_spam (struct rspamd_classifier_config *cl,
	struct rspamd_task *task,
	gboolean is_spam,
	GError **err)
{
	return rspamd_stat_learn (task, is_spam, task->cfg->lua_state, err);
}
