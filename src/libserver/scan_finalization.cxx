/*
 * Copyright 2026 Vsevolod Stakhov
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 */
#include "scan_finalization.h"
#include "task.h"
#include "rspamd.h"
#include "cfg_file_private.h"
#include "roll_history.h"
#include "email_addr.h"
#include "symcache/symcache_runtime.hxx"
#include "symcache/symcache_checkpoint.h"
#include <algorithm>
#include <cmath>

namespace {
struct early_result {
	struct rspamd_action *action;
	ucl_object_t *event;
	bool finished = false;
	bool processing = false;
	bool timed_out = false;
	bool observer_error = false;
	~early_result()
	{
		ucl_object_unref(event);
	}
};

auto get_early(struct rspamd_task *task) -> early_result *
{
	return static_cast<early_result *>(task->early_result);
}


auto number(double value) -> ucl_object_t *
{
	return std::isfinite(value) ? ucl_object_fromdouble(value) : ucl_object_typed_new(UCL_NULL);
}

struct symbol_event {
	ucl_object_t *symbols;
	size_t bytes = 0;
	bool truncated = false;
};

void add_symbol(gpointer key, gpointer value, gpointer ud)
{
	auto *ctx = static_cast<symbol_event *>(ud);
	auto *s = static_cast<rspamd_symbol_result *>(value);

	if (s->flags & RSPAMD_SYMBOL_RESULT_IGNORED) {
		return;
	}

	if (ctx->symbols->len >= 128 || ctx->bytes + strlen(s->name) > 65536) {
		ctx->truncated = true;
		return;
	}

	auto *entry = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(entry, ucl_object_fromstring(s->name), "name", 0, true);
	ucl_object_insert_key(entry, number(s->score), "score", 0, true);
	auto *options = ucl_object_typed_new(UCL_ARRAY);
	ctx->bytes += strlen(s->name);

	for (auto *opt = s->opts_head; opt; opt = opt->next) {
		if (options->len >= 32 || opt->optlen > 4096 || ctx->bytes + opt->optlen > 65536) {
			ctx->truncated = true;
			break;
		}

		ctx->bytes += opt->optlen;
		ucl_array_append(options, ucl_object_fromlstring(opt->option, opt->optlen));
	}

	ucl_object_insert_key(entry, options, "options", 0, true);
	ucl_array_append(ctx->symbols, entry);
}

void account(struct rspamd_task *task)
{
	if ((task->flags & RSPAMD_TASK_FLAG_NO_STAT) || !task->worker || !task->worker->srv || !task->worker->srv->stat) {
		return;
	}

	auto *stat = task->worker->srv->stat;

	if (task->result) {
		auto *action = rspamd_check_action_metric(task, nullptr, nullptr);
		auto type = action->action_type;

		if (!task->early_result && type == METRIC_ACTION_SOFT_REJECT && (task->flags & RSPAMD_TASK_FLAG_GREYLISTED)) {
			type = METRIC_ACTION_GREYLIST;
		}

		if (type >= 0 && type < METRIC_ACTION_MAX) {
#ifndef HAVE_ATOMIC_BUILTINS
			stat->actions_stat[type]++;
#else
			__atomic_add_fetch(&stat->actions_stat[type], 1, __ATOMIC_RELEASE);
#endif
		}
	}
#ifndef HAVE_ATOMIC_BUILTINS
	stat->messages_scanned++;
	auto slot = stat->avg_time.cur_slot++;
#else
	__atomic_add_fetch(&stat->messages_scanned, 1, __ATOMIC_RELEASE);
	auto slot = __atomic_fetch_add(&stat->avg_time.cur_slot, 1, __ATOMIC_RELEASE);
#endif
	stat->avg_time.avg_time[slot % MAX_AVG_TIME_SLOTS] = task->time_real_finish - task->task_timestamp;
}
}// namespace

gboolean rspamd_task_finalize_scan(struct rspamd_task *task)
{
	if (!task || !RSPAMD_TASK_IS_PROCESSED(task) || (task->finalization_flags & RSPAMD_TASK_FINALIZED)) {
		return FALSE;
	}

	if (auto *early = get_early(task)) {
		if (!early->finished) {
			return FALSE;
		}
	}
	else if (rspamd_symcache_is_checkpoint(task)) {
		return FALSE;
	}

	if (task->cmd == CMD_PING || task->cmd == CMD_METRICS) {
		return FALSE;
	}

	task->finalization_flags |= RSPAMD_TASK_FINALIZED;
	rspamd_task_set_finish_time(task);

	if (task->early_result && !(task->flags & RSPAMD_TASK_FLAG_NO_STAT)) {
		rspamd_symcache_checkpoint_flush_frequencies(task);
	}

	account(task);

	if (!(task->flags & RSPAMD_TASK_FLAG_NO_LOG)) {
		if (task->worker && task->worker->srv && task->worker->srv->history) {
			rspamd_roll_history_update(task->worker->srv->history, task);
		}

		if (auto *early = get_early(task)) {
			/* Custom log format callbacks have not been audited for missing MIME. */
			auto *json = ucl_object_emit(early->event, UCL_EMIT_JSON_COMPACT);
			msg_info_task("early terminal: %s", json);
			free(json);
		}
		else {
			rspamd_task_write_log(task);
		}
	}

	return TRUE;
}

gboolean rspamd_task_begin_early_result(struct rspamd_task *task, const char *action_name, const char *policy,
										const char *reason, const char *event_id)
{
	return rspamd_task_begin_early_result_full(task, action_name, policy, reason, event_id, nullptr);
}

gboolean rspamd_task_begin_early_result_full(struct rspamd_task *task, const char *action_name, const char *policy,
											 const char *reason, const char *event_id, const char *recipient)
{
	if (!task || task->early_result || !task->s || task->err || task->message || task->msg.len != 0 ||
		task->processed_stages != 0 || !task->symcache_runtime || rspamd_session_blocked(task->s) ||
		rspamd_session_events_pending(task->s) != 0 || !action_name || !policy || !*policy || strlen(policy) > 128 ||
		!reason || strlen(reason) > 512 || (event_id && (!*event_id || strlen(event_id) > 128))) {
		return FALSE;
	}

	auto *runtime = static_cast<rspamd::symcache::symcache_runtime *>(task->symcache_runtime);

	if (!runtime->can_export_checkpoint() || runtime->checkpoint_inputs() != RSPAMD_SYMCACHE_INPUT_ENVELOPE) {
		return FALSE;
	}

	auto *action = rspamd_config_get_action(task->cfg, action_name);

	if (!action || (action->action_type != METRIC_ACTION_REJECT && action->action_type != METRIC_ACTION_SOFT_REJECT)) {
		return FALSE;
	}

	auto *event = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(event, ucl_object_fromint(1), "format", 0, true);
	ucl_object_insert_key(event, ucl_object_fromstring(event_id ? event_id : task->task_uuid), "event_id", 0, true);
	ucl_object_insert_key(event, ucl_object_fromstring("data"), "decision_stage", 0, true);
	const char *completion = action->action_type == METRIC_ACTION_REJECT ? "early_reject" : "early_tempfail";
	ucl_object_insert_key(event, ucl_object_fromstring(completion), "completion_kind", 0, true);
	ucl_object_insert_key(event, ucl_object_fromstring(action->name), "action", 0, true);
	ucl_object_insert_key(event, ucl_object_fromstring(policy), "policy", 0, true);

	if (recipient) {
		ucl_object_insert_key(event, ucl_object_fromstring(recipient), "policy_recipient", 0, true);
	}

	ucl_object_insert_key(event, ucl_object_fromstring(reason), "reason", 0, true);
	ucl_object_insert_key(event, number(task->task_timestamp), "timestamp", 0, true);
	ucl_object_insert_key(event, number(ev_time() - task->task_timestamp), "early_time", 0, true);
	ucl_object_insert_key(event, rspamd_symcache_inputs_to_ucl(runtime->checkpoint_inputs()), "available_inputs", 0,
						  true);
	ucl_object_insert_key(event, ucl_object_frombool(false), "has_headers", 0, true);
	ucl_object_insert_key(event, ucl_object_frombool(false), "has_body", 0, true);
	ucl_object_insert_key(event, ucl_object_frombool(false), "has_mime", 0, true);
	ucl_object_insert_key(event, ucl_object_typed_new(UCL_NULL), "size", 0, true);
	ucl_object_insert_key(event, ucl_object_fromint(0), "received_bytes", 0, true);
	ucl_object_insert_key(event, number(task->result->score), "partial_score", 0, true);
	ucl_object_insert_key(event, ucl_object_fromstring("pending"), "observer_status", 0, true);
	ucl_object_insert_key(event, ucl_object_typed_new(UCL_NULL), "reply_delivered", 0, true);

	if (task->helo) {
		ucl_object_insert_key(event, ucl_object_fromstring(task->helo), "helo", 0, true);
	}

	if (task->from_addr) {
		ucl_object_insert_key(event, ucl_object_fromstring(rspamd_inet_address_to_string(task->from_addr)), "ip", 0,
							  true);
	}

	if (task->from_envelope) {
		ucl_object_insert_key(event, ucl_object_fromlstring(task->from_envelope->addr, task->from_envelope->addr_len),
							  "sender", 0, true);
	}

	if (task->auth_user) {
		ucl_object_insert_key(event, ucl_object_fromstring(task->auth_user), "user", 0, true);
	}

	if (task->queue_id && strcmp(task->queue_id, "undef") != 0) {
		ucl_object_insert_key(event, ucl_object_fromstring(task->queue_id), "queue_id", 0, true);
	}

	auto *recipients = ucl_object_typed_new(UCL_ARRAY);
	auto count = task->rcpt_envelope ? task->rcpt_envelope->len : 0;

	for (auto i = 0u; i < std::min(count, 128u); i++) {
		auto *rcpt = static_cast<rspamd_email_address *>(g_ptr_array_index(task->rcpt_envelope, i));
		ucl_array_append(recipients, ucl_object_fromlstring(rcpt->addr, rcpt->addr_len));
	}

	ucl_object_insert_key(event, recipients, "recipients", 0, true);
	ucl_object_insert_key(event, ucl_object_fromint(count), "recipient_count", 0, true);
	ucl_object_insert_key(event, ucl_object_frombool(count > 128), "recipients_truncated", 0, true);
	symbol_event symbols{ucl_object_typed_new(UCL_ARRAY)};
	rspamd_task_symbol_result_foreach(task, nullptr, add_symbol, &symbols);
	ucl_object_insert_key(event, symbols.symbols, "symbols", 0, true);
	ucl_object_insert_key(event, ucl_object_frombool(symbols.truncated), "symbols_truncated", 0, true);
	task->early_result = new early_result{action, event};
	rspamd_mempool_add_destructor(
		task->task_pool,
		[](void *p) {
			delete static_cast<early_result *>(p);
		},
		task->early_result);
	return TRUE;
}

enum rspamd_symcache_checkpoint_result rspamd_task_process_early_result(struct rspamd_task *task,
																		gboolean deadline_expired)
{
	auto *early = task ? get_early(task) : nullptr;

	if (!early || early->processing || !task->s || rspamd_session_blocked(task->s)) {
		return RSPAMD_SYMCACHE_CHECKPOINT_ERROR;
	}

	if (early->finished) {
		return RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE;
	}

	early->processing = true;
	auto *runtime = static_cast<rspamd::symcache::symcache_runtime *>(task->symcache_runtime);
	auto result = RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE;

	if (deadline_expired || early->timed_out) {
		early->timed_out = true;
		rspamd_session_cleanup(task->s, true);

		if (rspamd_session_events_pending(task->s)) {
			result = RSPAMD_SYMCACHE_CHECKPOINT_PENDING;
		}
	}
	else {
		result = runtime->process_checkpoint(task, *reinterpret_cast<rspamd::symcache::symcache *>(task->cfg->cache),
											 runtime->checkpoint_inputs(), true);
	}

	if (result == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE) {
		const char *observer_status = "complete";

		if (early->timed_out) {
			observer_status = "timeout";
			rspamd_multistage_count(task->worker, RSPAMD_MULTISTAGE_OBSERVER_TIMEOUT);
		}
		else if (early->observer_error) {
			observer_status = "error";
			rspamd_multistage_count(task->worker, RSPAMD_MULTISTAGE_OBSERVER_ERROR);
		}

		early->finished = true;
		ucl_object_replace_key(early->event, ucl_object_fromstring(observer_status), "observer_status", 0, true);
		ucl_object_insert_key(early->event, number(ev_time() - task->task_timestamp), "elapsed", 0, true);
		task->processed_stages |= RSPAMD_TASK_STAGE_DONE;
		rspamd_task_finalize_scan(task);
	}

	early->processing = false;
	return result;
}

const ucl_object_t *rspamd_task_get_terminal_event(struct rspamd_task *task)
{
	return task && get_early(task) ? get_early(task)->event : nullptr;
}

struct rspamd_action *rspamd_task_get_early_action(struct rspamd_task *task)
{
	return task && get_early(task) ? get_early(task)->action : nullptr;
}

void rspamd_task_terminal_observer_error(struct rspamd_task *task)
{
	if (auto *early = get_early(task); early && !early->finished) {
		early->observer_error = true;
	}
}
