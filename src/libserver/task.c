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
#include "task.h"
#include "rspamd.h"
#include "filter.h"
#include "protocol.h"
#include "message.h"
#include "lua/lua_common.h"
#include "composites.h"
#include "stat_api.h"
#include "unix-std.h"
#include <utlist.h>

static GQuark
rspamd_task_quark (void)
{
	return g_quark_from_static_string ("task-error");
}

/*
 * Create new task
 */
struct rspamd_task *
rspamd_task_new (struct rspamd_worker *worker, struct rspamd_config *cfg)
{
	struct rspamd_task *new_task;

	g_assert (cfg != NULL);

	new_task = g_slice_alloc0 (sizeof (struct rspamd_task));
	new_task->worker = worker;
	new_task->cfg = cfg;
	REF_RETAIN (cfg);

	if (cfg->check_all_filters) {
		new_task->flags |= RSPAMD_TASK_FLAG_PASS_ALL;
	}

	gettimeofday (&new_task->tv, NULL);
	new_task->time_real = rspamd_get_ticks ();
	new_task->time_virtual = rspamd_get_virtual_ticks ();

	new_task->task_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), "task");

	new_task->results = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	rspamd_mempool_add_destructor (new_task->task_pool,
		(rspamd_mempool_destruct_t) g_hash_table_unref,
		new_task->results);
	new_task->re_rt = rspamd_re_cache_runtime_new (cfg->re_cache);
	new_task->raw_headers = g_hash_table_new (rspamd_strcase_hash,
			rspamd_strcase_equal);
	new_task->request_headers = g_hash_table_new_full (rspamd_ftok_icase_hash,
			rspamd_ftok_icase_equal, rspamd_fstring_mapped_ftok_free,
			rspamd_fstring_mapped_ftok_free);
	rspamd_mempool_add_destructor (new_task->task_pool,
		(rspamd_mempool_destruct_t) g_hash_table_unref,
		new_task->request_headers);
	new_task->reply_headers = g_hash_table_new_full (rspamd_ftok_icase_hash,
			rspamd_ftok_icase_equal, rspamd_fstring_mapped_ftok_free,
			rspamd_fstring_mapped_ftok_free);
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
	new_task->parts = g_ptr_array_sized_new (4);
	rspamd_mempool_add_destructor (new_task->task_pool,
			rspamd_ptr_array_free_hard, new_task->parts);
	new_task->text_parts = g_ptr_array_sized_new (2);
	rspamd_mempool_add_destructor (new_task->task_pool,
			rspamd_ptr_array_free_hard, new_task->text_parts);
	new_task->received = g_ptr_array_sized_new (8);
	rspamd_mempool_add_destructor (new_task->task_pool,
			rspamd_ptr_array_free_hard, new_task->received);

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

	if (RSPAMD_TASK_IS_PROCESSED (task)) {
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
rspamd_task_free (struct rspamd_task *task)
{
	struct mime_part *p;
	struct mime_text_part *tp;
	guint i;

	if (task) {
		debug_task ("free pointer %p", task);

		for (i = 0; i < task->parts->len; i ++) {
			p = g_ptr_array_index (task->parts, i);
			g_byte_array_free (p->content, TRUE);
		}

		for (i = 0; i < task->text_parts->len; i ++) {
			tp = g_ptr_array_index (task->text_parts, i);
			if (tp->normalized_words) {
				g_array_free (tp->normalized_words, TRUE);
			}
		}

		if (task->images) {
			g_list_free (task->images);
		}

		if (task->messages) {
			g_list_free (task->messages);
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

		if (event_get_base (&task->timeout_ev) != NULL) {
			event_del (&task->timeout_ev);
		}

		if (task->guard_ev) {
			event_del (task->guard_ev);
		}

		rspamd_re_cache_runtime_destroy (task->re_rt);
		REF_RELEASE (task->cfg);

		rspamd_mempool_delete (task->task_pool);
		g_slice_free1 (sizeof (struct rspamd_task), task);
	}
}

static void
rspamd_task_unmapper (gpointer ud)
{
	struct rspamd_task *task = ud;

	munmap ((void *)task->msg.begin, task->msg.len);
}

gboolean
rspamd_task_load_message (struct rspamd_task *task,
	struct rspamd_http_message *msg, const gchar *start, gsize len)
{
	guint control_len, r;
	struct ucl_parser *parser;
	ucl_object_t *control_obj;
	gchar filepath[PATH_MAX], *fp;
	gint fd, flen;
	rspamd_ftok_t srch, *tok;
	gpointer map;
	struct stat st;

	if (msg) {
		rspamd_protocol_handle_headers (task, msg);
	}

	srch.begin = "file";
	srch.len = 4;
	tok = g_hash_table_lookup (task->request_headers, &srch);

	if (tok == NULL) {
		srch.begin = "path";
		srch.len = 4;
		tok = g_hash_table_lookup (task->request_headers, &srch);
	}

	if (tok) {
		debug_task ("want to scan file %T", tok);

		r = rspamd_strlcpy (filepath, tok->begin,
				MIN (sizeof (filepath), tok->len + 1));

		rspamd_decode_url (filepath, filepath, r + 1);
		flen = strlen (filepath);

		if (filepath[0] == '"' && flen > 2) {
			/* We need to unquote filepath */
			fp = &filepath[1];
			fp[flen - 2] = '\0';
		}
		else {
			fp = &filepath[0];
		}

		if (access (fp, R_OK) == -1 || stat (fp, &st) == -1) {
			g_set_error (&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"Invalid file (%s): %s", fp, strerror (errno));
			return FALSE;
		}

		fd = open (fp, O_RDONLY);

		if (fd == -1) {
			g_set_error (&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"Cannot open file (%s): %s", fp, strerror (errno));
			return FALSE;
		}

		map = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);


		if (map == MAP_FAILED) {
			close (fd);
			g_set_error (&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"Cannot mmap file (%s): %s", fp, strerror (errno));
			return FALSE;
		}

		close (fd);
		task->msg.begin = map;
		task->msg.len = st.st_size;
		task->flags |= RSPAMD_TASK_FLAG_FILE;

		rspamd_mempool_add_destructor (task->task_pool, rspamd_task_unmapper, task);
	}
	else {
		debug_task ("got input of length %z", task->msg.len);
		task->msg.begin = start;
		task->msg.len = len;

		if (task->msg.len == 0) {
			msg_warn_task ("message has invalid message length: %uz",
					task->msg.len);
			g_set_error (&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"Invalid length");
			return FALSE;
		}

		if (task->flags & RSPAMD_TASK_FLAG_HAS_CONTROL) {
			/* We have control chunk, so we need to process it separately */
			if (task->msg.len < task->message_len) {
				msg_warn_task ("message has invalid message length: %ul and total len: %ul",
						task->message_len, task->msg.len);
				g_set_error (&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
						"Invalid length");
				return FALSE;
			}
			control_len = task->msg.len - task->message_len;

			if (control_len > 0) {
				parser = ucl_parser_new (UCL_PARSER_KEY_LOWERCASE);

				if (!ucl_parser_add_chunk (parser, task->msg.begin, control_len)) {
					msg_warn_task ("processing of control chunk failed: %s",
							ucl_parser_get_error (parser));
					ucl_parser_free (parser);
				}
				else {
					control_obj = ucl_parser_get_object (parser);
					ucl_parser_free (parser);
					rspamd_protocol_handle_control (task, control_obj);
					ucl_object_unref (control_obj);
				}

				task->msg.begin += control_len;
				task->msg.len -= control_len;
			}
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
rspamd_process_filters (struct rspamd_task *task)
{
	/* Process metrics symbols */
	return rspamd_symbols_cache_process_symbols (task, task->cfg->cache);
}

gboolean
rspamd_task_process (struct rspamd_task *task, guint stages)
{
	gint st;
	gboolean ret = TRUE;
	GError *stat_error = NULL;

	/* Avoid nested calls */
	if (task->flags & RSPAMD_TASK_FLAG_PROCESSING) {
		return TRUE;
	}


	if (RSPAMD_TASK_IS_PROCESSED (task)) {
		return TRUE;
	}

	task->flags |= RSPAMD_TASK_FLAG_PROCESSING;

	st = rspamd_task_select_processing_stage (task, stages);

	switch (st) {
	case RSPAMD_TASK_STAGE_READ_MESSAGE:
		if (!rspamd_message_parse (task)) {
			ret = FALSE;
		}
		break;

	case RSPAMD_TASK_STAGE_PRE_FILTERS:
		rspamd_lua_call_pre_filters (task);
		break;

	case RSPAMD_TASK_STAGE_FILTERS:
		if (!rspamd_process_filters (task)) {
			ret = FALSE;
		}
		break;

	case RSPAMD_TASK_STAGE_CLASSIFIERS:
	case RSPAMD_TASK_STAGE_CLASSIFIERS_PRE:
	case RSPAMD_TASK_STAGE_CLASSIFIERS_POST:
		if (rspamd_stat_classify (task, task->cfg->lua_state, st, &stat_error) ==
				RSPAMD_STAT_PROCESS_ERROR) {
			msg_err_task ("classify error: %e", stat_error);
			g_error_free (stat_error);
		}
		break;

	case RSPAMD_TASK_STAGE_COMPOSITES:
		rspamd_make_composites (task);
		break;

	case RSPAMD_TASK_STAGE_POST_FILTERS:
		rspamd_lua_call_post_filters (task);
		if (task->flags & RSPAMD_TASK_FLAG_LEARN_AUTO) {
			rspamd_stat_check_autolearn (task);
		}
		break;

	case RSPAMD_TASK_STAGE_LEARN:
	case RSPAMD_TASK_STAGE_LEARN_PRE:
	case RSPAMD_TASK_STAGE_LEARN_POST:
		if (task->flags & (RSPAMD_TASK_FLAG_LEARN_SPAM|RSPAMD_TASK_FLAG_LEARN_HAM)) {
			if (task->err == NULL) {
				if (!rspamd_stat_learn (task,
						task->flags & RSPAMD_TASK_FLAG_LEARN_SPAM,
						task->cfg->lua_state, task->classifier,
						st, &stat_error)) {

					if (!(task->flags & RSPAMD_TASK_FLAG_LEARN_AUTO)) {
						task->err = stat_error;
					}

					msg_err_task ("learn error: %e", stat_error);
					task->processed_stages |= RSPAMD_TASK_STAGE_DONE;
				}
			}
		}
		break;

	case RSPAMD_TASK_STAGE_DONE:
		task->processed_stages |= RSPAMD_TASK_STAGE_DONE;
		break;

	default:
		/* TODO: not implemented stage */
		break;
	}

	if (RSPAMD_TASK_IS_SKIPPED (task)) {
		task->processed_stages |= RSPAMD_TASK_STAGE_DONE;
	}

	task->flags &= ~RSPAMD_TASK_FLAG_PROCESSING;

	if (!ret || RSPAMD_TASK_IS_PROCESSED (task)) {
		if (!ret) {
			/* Set processed flags */
			task->processed_stages |= RSPAMD_TASK_STAGE_DONE;
		}

		msg_debug_task ("task is processed");

		return ret;
	}

	if (rspamd_session_events_pending (task->s) != 0) {
		/* We have events pending, so we consider this stage as incomplete */
		msg_debug_task ("need more work on stage %d", st);
	}
	else {
		/* Mark the current stage as done and go to the next stage */
		msg_debug_task ("completed stage %d", st);
		task->processed_stages |= st;

		/* Reset checkpoint */
		task->checkpoint = NULL;

		/* Tail recursion */
		return rspamd_task_process (task, stages);
	}

	return ret;
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

static const gchar *
rspamd_task_cache_principal_recipient (struct rspamd_task *task,
		const gchar *rcpt)
{
	gchar *rcpt_lc;
	gsize len;

	if (rcpt == NULL) {
		return NULL;
	}

	len = strlen (rcpt);

	rcpt_lc = rspamd_mempool_alloc (task->task_pool, len + 1);
	rspamd_strlcpy (rcpt_lc, rcpt, len + 1);
	rspamd_str_lc (rcpt_lc, len);

	rspamd_mempool_set_variable (task->task_pool, "recipient", rcpt_lc, NULL);

	return rcpt_lc;
}

const gchar *
rspamd_task_get_principal_recipient (struct rspamd_task *task)
{
	InternetAddress *iaelt = NULL;
	const gchar *val;

	val = rspamd_mempool_get_variable (task->task_pool, "recipient");

	if (val) {
		return val;
	}

	if (task->deliver_to) {
		return rspamd_task_cache_principal_recipient (task, task->deliver_to);
	}

#ifdef GMIME24
	InternetAddressMailbox *imb;

	if (task->rcpt_envelope != NULL) {
		iaelt = internet_address_list_get_address (task->rcpt_envelope, 0);
	}
	else if (task->rcpt_mime != NULL) {
		iaelt = internet_address_list_get_address (task->rcpt_mime, 0);
	}

	imb = INTERNET_ADDRESS_IS_MAILBOX(iaelt) ?
			INTERNET_ADDRESS_MAILBOX (iaelt) : NULL;

	if (imb) {
		val = internet_address_mailbox_get_addr (imb);

		return rspamd_task_cache_principal_recipient (task, val);
	}
#else
	if (task->rcpt_envelope != NULL) {
		iaelt = internet_address_list_get_address (task->rcpt_envelope);
	}
	else if (task->rcpt_mime != NULL) {
		iaelt = internet_address_list_get_address (task->rcpt_mime);
	}

	if (iaelt) {
		val = internet_address_get_addr (iaelt);

		return rspamd_task_cache_principal_recipient (task, val);
	}
#endif

	return NULL;
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

	if (strcmp (sender, "<>") == 0) {
		/* Workaround for gmime */
		internet_address_list_add (task->from_envelope,
				internet_address_mailbox_new ("", ""));
		return TRUE;
	}
	else {
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
	}

	return FALSE;
}

gboolean
rspamd_learn_task_spam (struct rspamd_task *task,
	gboolean is_spam,
	const gchar *classifier,
	GError **err)
{
	if (is_spam) {
		task->flags |= RSPAMD_TASK_FLAG_LEARN_SPAM;
	}
	else {
		task->flags |= RSPAMD_TASK_FLAG_LEARN_HAM;
	}

	task->classifier = classifier;

	return TRUE;
}

static gboolean
rspamd_task_log_check_condition (struct rspamd_task *task,
		struct rspamd_log_format *lf)
{
	gboolean ret = FALSE;

	switch (lf->type) {
	case RSPAMD_LOG_MID:
		if (task->message_id && strcmp (task->message_id, "undef") != 0) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_QID:
		if (task->queue_id && strcmp (task->queue_id, "undef") != 0) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_USER:
		if (task->user) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_IP:
		if (task->from_addr && rspamd_ip_is_valid (task->from_addr)) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_SMTP_RCPT:
	case RSPAMD_LOG_SMTP_RCPTS:
		if (task->rcpt_envelope &&
					internet_address_list_length (task->rcpt_envelope) > 0) {
			ret = TRUE;
		}
		else if (task->rcpt_mime &&
				internet_address_list_length (task->rcpt_mime) > 0) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_MIME_RCPT:
	case RSPAMD_LOG_MIME_RCPTS:
		if (task->rcpt_mime &&
				internet_address_list_length (task->rcpt_mime) > 0) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_SMTP_FROM:
		if (task->from_envelope &&
				internet_address_list_length (task->from_envelope) > 0) {
			ret = TRUE;
		}
		else if (task->from_mime &&
				internet_address_list_length (task->from_mime) > 0) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_MIME_FROM:
		if (task->from_mime &&
				internet_address_list_length (task->from_mime) > 0) {
			ret = TRUE;
		}
		break;
	default:
		ret = TRUE;
		break;
	}

	return ret;
}

static rspamd_ftok_t
rspamd_task_log_metric_res (struct rspamd_task *task,
		struct rspamd_log_format *lf)
{
	static gchar scorebuf[32];
	rspamd_ftok_t res = {.begin = NULL, .len = 0};
	struct metric_result *mres;
	GHashTableIter it;
	gboolean first = TRUE;
	gpointer k, v;
	rspamd_fstring_t *symbuf;
	struct symbol *sym;

	mres = g_hash_table_lookup (task->results, DEFAULT_METRIC);

	if (mres != NULL) {
		switch (lf->type) {
		case RSPAMD_LOG_ISSPAM:
			if (RSPAMD_TASK_IS_SKIPPED (task)) {
				res.begin = "S";
			}
			else if (mres->action == METRIC_ACTION_REJECT) {
				res.begin = "T";
			}
			else {
				res.begin = "F";
			}

			res.len = 1;
			break;
		case RSPAMD_LOG_ACTION:
			res.begin = rspamd_action_to_str (mres->action);
			res.len = strlen (res.begin);
			break;
		case RSPAMD_LOG_SCORES:
			res.len = rspamd_snprintf (scorebuf, sizeof (scorebuf), "%.2f/%.2f",
					mres->score, mres->required_score);
			res.begin = scorebuf;
			break;
		case RSPAMD_LOG_SYMBOLS:
			symbuf = rspamd_fstring_sized_new (128);
			g_hash_table_iter_init (&it, mres->symbols);

			while (g_hash_table_iter_next (&it, &k, &v)) {
				sym = (struct symbol *) v;

				if (first) {
					if (lf->flags & RSPAMD_LOG_FLAG_SYMBOLS_SCORES) {
						rspamd_printf_fstring (&symbuf, "%s(%.2f)", sym->name,
								sym->score);
					}
					else {
						rspamd_printf_fstring (&symbuf, "%s", sym->name);
					}
					first = FALSE;
				}
				else {
					if (lf->flags & RSPAMD_LOG_FLAG_SYMBOLS_SCORES) {
						rspamd_printf_fstring (&symbuf, ",%s(%.2f)", sym->name,
								sym->score);
					}
					else {
						rspamd_printf_fstring (&symbuf, ",%s", sym->name);
					}
				}
			}

			rspamd_mempool_add_destructor (task->task_pool,
					(rspamd_mempool_destruct_t)rspamd_fstring_free,
					symbuf);
			res.begin = symbuf->str;
			res.len = symbuf->len;
			break;
		default:
			break;
		}
	}

	return res;
}

static rspamd_fstring_t *
rspamd_task_log_write_var (struct rspamd_task *task, rspamd_fstring_t *logbuf,
		const rspamd_ftok_t *var, const rspamd_ftok_t *content)
{
	rspamd_fstring_t *res = logbuf;
	const gchar *p, *c, *end;

	if (content == NULL) {
		/* Just output variable */
		res = rspamd_fstring_append (res, var->begin, var->len);
	}
	else {
		/* Replace $ with variable value */
		p = content->begin;
		c = p;
		end = p + content->len;

		while (p < end) {
			if (*p == '$') {
				if (p > c) {
					res = rspamd_fstring_append (res, c, p - c);
				}

				res = rspamd_fstring_append (res, var->begin, var->len);
				p ++;
				c = p;
			}
			else {
				p ++;
			}
		}

		if (p > c) {
			res = rspamd_fstring_append (res, c, p - c);
		}
	}

	return res;
}

static rspamd_fstring_t *
rspamd_task_write_ialist (struct rspamd_task *task,
		InternetAddressList *ialist, gint lim,
		struct rspamd_log_format *lf,
		rspamd_fstring_t *logbuf)
{
	rspamd_fstring_t *res = logbuf, *varbuf;
	rspamd_ftok_t var = {.begin = NULL, .len = 0};
	InternetAddressMailbox *iamb;
	InternetAddress *ia = NULL;
	gint i;

	if (lim <= 0) {
		lim = internet_address_list_length (ialist);
	}

	varbuf = rspamd_fstring_new ();

	for (i = 0; i < lim; i++) {
		ia = internet_address_list_get_address (ialist, i);

		if (ia && INTERNET_ADDRESS_IS_MAILBOX (ia)) {
			iamb = INTERNET_ADDRESS_MAILBOX (ia);
			varbuf = rspamd_fstring_append (varbuf, iamb->addr,
					strlen (iamb->addr));
		}

		if (varbuf->len > 0) {
			if (i != lim - 1) {
				varbuf = rspamd_fstring_append (varbuf, ",", 1);
			}
		}
	}

	if (varbuf->len > 0) {
		var.begin = varbuf->str;
		var.len = varbuf->len;
		res = rspamd_task_log_write_var (task, logbuf,
				&var, (const rspamd_ftok_t *) lf->data);
	}

	rspamd_fstring_free (varbuf);

	return res;
}

static rspamd_fstring_t *
rspamd_task_log_variable (struct rspamd_task *task,
		struct rspamd_log_format *lf, rspamd_fstring_t *logbuf)
{
	rspamd_fstring_t *res = logbuf;
	rspamd_ftok_t var = {.begin = NULL, .len = 0};
	static gchar numbuf[32];

	switch (lf->type) {
	/* String vars */
	case RSPAMD_LOG_MID:
		if (task->message_id) {
			var.begin = task->message_id;
			var.len = strlen (var.begin);
		}
		else {
			var.begin = "undef";
			var.len = 5;
		}
		break;
	case RSPAMD_LOG_QID:
		if (task->queue_id) {
			var.begin = task->queue_id;
			var.len = strlen (var.begin);
		}
		else {
			var.begin = "undef";
			var.len = 5;
		}
		break;
	case RSPAMD_LOG_USER:
		if (task->user) {
			var.begin = task->user;
			var.len = strlen (var.begin);
		}
		else {
			var.begin = "undef";
			var.len = 5;
		}
		break;
	case RSPAMD_LOG_IP:
		if (task->from_addr && rspamd_ip_is_valid (task->from_addr)) {
			var.begin = rspamd_inet_address_to_string (task->from_addr);
			var.len = strlen (var.begin);
		}
		else {
			var.begin = "undef";
			var.len = 5;
		}
		break;
	/* Numeric vars */
	case RSPAMD_LOG_LEN:
		var.len = rspamd_snprintf (numbuf, sizeof (numbuf), "%uz",
				task->msg.len);
		var.begin = numbuf;
		break;
	case RSPAMD_LOG_DNS_REQ:
		var.len = rspamd_snprintf (numbuf, sizeof (numbuf), "%uD",
				task->dns_requests);
		var.begin = numbuf;
		break;
	case RSPAMD_LOG_TIME_REAL:
		var.begin = rspamd_log_check_time (task->time_real, rspamd_get_ticks (),
				task->cfg->clock_res);
		var.len = strlen (var.begin);
		break;
	case RSPAMD_LOG_TIME_VIRTUAL:
		var.begin = rspamd_log_check_time (task->time_virtual,
				rspamd_get_virtual_ticks (),
				task->cfg->clock_res);
		var.len = strlen (var.begin);
		break;
	/* InternetAddress vars */
	case RSPAMD_LOG_SMTP_FROM:
		if (task->from_envelope) {
			return rspamd_task_write_ialist (task, task->from_envelope, 1, lf,
					logbuf);
		}
		else if (task->from_mime) {
			return rspamd_task_write_ialist (task, task->from_mime, 1, lf,
					logbuf);
		}
		break;
	case RSPAMD_LOG_MIME_FROM:
		if (task->from_mime) {
			return rspamd_task_write_ialist (task, task->from_mime, 1, lf,
					logbuf);
		}
		break;
	case RSPAMD_LOG_SMTP_RCPT:
		if (task->rcpt_envelope) {
			return rspamd_task_write_ialist (task, task->rcpt_envelope, 1, lf,
					logbuf);
		}
		else if (task->rcpt_mime) {
			return rspamd_task_write_ialist (task, task->rcpt_mime, 1, lf,
					logbuf);
		}
		break;
	case RSPAMD_LOG_MIME_RCPT:
		if (task->rcpt_mime) {
			return rspamd_task_write_ialist (task, task->rcpt_mime, 1, lf,
					logbuf);
		}
		break;
	case RSPAMD_LOG_SMTP_RCPTS:
		if (task->rcpt_envelope) {
			return rspamd_task_write_ialist (task, task->rcpt_envelope, -1, lf,
					logbuf);
		}
		else if (task->rcpt_mime) {
			return rspamd_task_write_ialist (task, task->rcpt_mime, -1, lf,
					logbuf);
		}
		break;
	case RSPAMD_LOG_MIME_RCPTS:
		if (task->rcpt_mime) {
			return rspamd_task_write_ialist (task, task->rcpt_mime, -1, lf,
					logbuf);
		}
		break;
	default:
		var = rspamd_task_log_metric_res (task, lf);
		break;
	}

	if (var.len > 0) {
		res = rspamd_task_log_write_var (task, logbuf,
				&var, (const rspamd_ftok_t *)lf->data);
	}

	return res;
}

void
rspamd_task_write_log (struct rspamd_task *task)
{
	rspamd_fstring_t *logbuf;
	struct rspamd_log_format *lf;
	struct rspamd_task **ptask;
	const gchar *lua_str;
	gsize lua_str_len;
	lua_State *L;

	g_assert (task != NULL);

	if (task->cfg->log_format == NULL ||
			(task->flags & RSPAMD_TASK_FLAG_NO_LOG)) {
		return;
	}

	logbuf = rspamd_fstring_sized_new (1000);

	DL_FOREACH (task->cfg->log_format, lf) {
		switch (lf->type) {
		case RSPAMD_LOG_STRING:
			logbuf = rspamd_fstring_append (logbuf, lf->data, lf->len);
			break;
		case RSPAMD_LOG_LUA:
			L = task->cfg->lua_state;
			lua_rawgeti (L, LUA_REGISTRYINDEX, GPOINTER_TO_INT (lf->data));
			ptask = lua_newuserdata (L, sizeof (*ptask));
			rspamd_lua_setclass (L, "rspamd{task}", -1);
			*ptask = task;

			if (lua_pcall (L, 1, 1, 0) != 0) {
				msg_err_task ("call to log function failed: %s",
						lua_tostring (L, -1));
				lua_pop (L, 1);
			}
			else {
				lua_str = lua_tolstring (L, -1, &lua_str_len);

				if (lua_str != NULL) {
					logbuf = rspamd_fstring_append (logbuf, lua_str, lua_str_len);
				}
				lua_pop (L, 1);
			}
			break;
		default:
			/* We have a variable in log format */
			if (lf->flags & RSPAMD_LOG_FLAG_CONDITION) {
				if (!rspamd_task_log_check_condition (task, lf)) {
					continue;
				}
			}

			logbuf = rspamd_task_log_variable (task, lf, logbuf);
			break;
		}
	}

	msg_info_task ("%V", logbuf);

	rspamd_fstring_free (logbuf);
}
