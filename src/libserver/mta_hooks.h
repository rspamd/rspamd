/* Copyright 2026 Vsevolod Stakhov. SPDX-License-Identifier: Apache-2.0 */
#ifndef RSPAMD_MTA_HOOKS_H
#define RSPAMD_MTA_HOOKS_H

#include "config.h"
#include "ucl.h"

#ifdef __cplusplus
extern "C" {
#endif
struct rspamd_http_message;
struct rspamd_config;
struct rspamd_mta_hooks_config;
struct rspamd_mta_hooks_request;

/* Experimental draft-01 DATA/add-only frontend. All callbacks may run inline.
 * A callback receives ownership of exactly one message: native scan input or
 * HTTP response. The caller keeps the request and its callback data alive until
 * the callback has completed, including when the peer disconnects. */
typedef void (*rspamd_mta_hooks_callback)(struct rspamd_http_message *message,
										  gboolean scan, gpointer ud);
struct rspamd_mta_hooks_config *rspamd_mta_hooks_config_new(
	const ucl_object_t *obj, struct rspamd_config *cfg, GError **err);
void rspamd_mta_hooks_config_free(struct rspamd_mta_hooks_config *cfg);
gsize rspamd_mta_hooks_max_request(struct rspamd_mta_hooks_config *cfg);
struct rspamd_mta_hooks_request *rspamd_mta_hooks_request_new(
	struct rspamd_mta_hooks_config *cfg, struct rspamd_http_message *msg,
	gboolean tls, gboolean loopback);
void rspamd_mta_hooks_request_free(struct rspamd_mta_hooks_request *request);
void rspamd_mta_hooks_begin(struct rspamd_mta_hooks_request *request,
							rspamd_mta_hooks_callback callback, gpointer ud);
void rspamd_mta_hooks_finish(struct rspamd_mta_hooks_request *request,
							 const ucl_object_t *results, gboolean rewritten,
							 rspamd_mta_hooks_callback callback, gpointer ud);
double rspamd_mta_hooks_remaining(struct rspamd_mta_hooks_request *request);
struct rspamd_http_message *rspamd_mta_hooks_error(int status,
												   const char *code, const char *message);
/* Pure codec entry points also used by unit tests. */
struct rspamd_http_message *rspamd_mta_hooks_decode(const char *data, gsize len,
													gsize max_message, GError **err);
struct rspamd_http_message *rspamd_mta_hooks_encode(const ucl_object_t *results,
													gboolean rewritten);
#ifdef __cplusplus
}
#endif
#endif
