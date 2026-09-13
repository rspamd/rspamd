/*
 * Copyright 2026 Vsevolod Stakhov
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 */
#ifndef RSPAMD_SCAN_FINALIZATION_H
#define RSPAMD_SCAN_FINALIZATION_H

#include "rspamd_symcache.h"
#ifdef __cplusplus
extern "C" {
#endif

struct rspamd_action;

/* Called by the scan owner, not by serializers. Returns TRUE exactly once
 * for a completed task; a checkpoint continuation is never accounted. */
gboolean rspamd_task_finalize_scan(struct rspamd_task *task);

/* Freeze an explicit reject/soft-reject decision after a drained DATA
 * checkpoint. No score threshold can call this implicitly. event_id must be
 * stable across transport retries; NULL uses this task's UUID. This API does
 * not deduplicate separate tasks or make external writes crash-proof. */
gboolean rspamd_task_begin_early_result(struct rspamd_task *task,
										const char *action, const char *policy, const char *reason, const char *event_id);

/* Run only audited, input-ready terminal observers. The owner supplies the
 * session and deadline, drives events, and calls again when they drain.
 * On deadline expiry pass TRUE to cancel remaining observer work. Observers
 * must register cancellable events; uncancellable events keep this PENDING
 * and the task must remain alive until they drain. No normal stages run. */
enum rspamd_symcache_checkpoint_result rspamd_task_process_early_result(
	struct rspamd_task *task, gboolean deadline_expired);

/* Borrowed immutable decision data, or NULL for an ordinary EOM task. */
const ucl_object_t *rspamd_task_get_terminal_event(struct rspamd_task *task);
struct rspamd_action *rspamd_task_get_early_action(struct rspamd_task *task);
void rspamd_task_terminal_observer_error(struct rspamd_task *task);

enum rspamd_task_finalization_flags {
	RSPAMD_TASK_FINALIZED = 1u << 0u,
	RSPAMD_TASK_LOG_PIPE_WRITTEN = 1u << 1u,
};

#ifdef __cplusplus
}
#endif
#endif
