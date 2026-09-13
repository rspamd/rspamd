/*
 * Copyright 2026 Vsevolod Stakhov
 * Licensed under the Apache License, Version 2.0.
 */
#ifndef RSPAMD_MULTISTAGE_H
#define RSPAMD_MULTISTAGE_H

#include "config.h"
#include "fstring.h"
#include "contrib/libucl/ucl.h"
#ifdef __cplusplus
extern "C" {
#endif
struct rspamd_config;
struct rspamd_task;
struct rspamd_http_message;

#define RSPAMD_MULTISTAGE_MAX_WIRE (256 * 1024)
#define RSPAMD_MULTISTAGE_ID_LEN 32

enum rspamd_multistage_decision {
	RSPAMD_MULTISTAGE_CONTINUE,
	RSPAMD_MULTISTAGE_REJECT,
	RSPAMD_MULTISTAGE_TEMPFAIL,
};

gboolean rspamd_multistage_enabled(struct rspamd_config *cfg);
gboolean rspamd_multistage_validate(struct rspamd_config *cfg);
double rspamd_multistage_timeout(struct rspamd_config *cfg);
rspamd_fstring_t *rspamd_multistage_seal(struct rspamd_config *cfg, const char *kind, const ucl_object_t *payload);
ucl_object_t *rspamd_multistage_open(struct rspamd_config *cfg, const char *kind, const char *wire, gsize len);

/* Authenticate and bind a DATA reply to this transaction. Failures continue at
 * EOM without a record. An authenticated continue may return an owned record. */
enum rspamd_multistage_decision rspamd_multistage_check_reply(struct rspamd_config *cfg,
															  const char *wire, gsize len, const char *id, const rspamd_fstring_t *binding,
															  rspamd_fstring_t **record);

rspamd_fstring_t *rspamd_multistage_binding(const ucl_object_t *metadata, const char *id);
struct rspamd_http_message *rspamd_multistage_data_request(struct rspamd_config *cfg,
														   const ucl_object_t *metadata, const char *id);
gboolean rspamd_multistage_attach_record(struct rspamd_http_message *msg,
										 ucl_object_t *metadata, const rspamd_fstring_t *record);
/* Invalid, stale or incompatible records leave an ordinary full scan. */
gboolean rspamd_multistage_import(struct rspamd_task *task);

typedef void (*rspamd_multistage_done)(struct rspamd_task *task, const rspamd_fstring_t *reply, void *ud);
/* Owns the task's session and deadline; caller retains task until completion
 * or cancellation. The callback must not free task from inside the pump. */
gboolean rspamd_multistage_start(struct rspamd_task *task, struct rspamd_http_message *msg,
								 rspamd_multistage_done done, void *ud);
const rspamd_fstring_t *rspamd_multistage_reply(struct rspamd_task *task);

#ifdef __cplusplus
}
#endif
#endif
