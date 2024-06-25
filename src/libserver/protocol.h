/*
 * Copyright 2024 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file protocol.h
 * Rspamd protocol definition
 */

#ifndef RSPAMD_PROTOCOL_H
#define RSPAMD_PROTOCOL_H

#include "config.h"
#include "scan_result.h"
#include "libserver/http/http_connection.h"
#include "task.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RSPAMD_BASE_ERROR 500
#define RSPAMD_FILTER_ERROR RSPAMD_BASE_ERROR + 1
#define RSPAMD_NETWORK_ERROR RSPAMD_BASE_ERROR + 2
#define RSPAMD_PROTOCOL_ERROR RSPAMD_BASE_ERROR + 3
#define RSPAMD_LENGTH_ERROR RSPAMD_BASE_ERROR + 4
#define RSPAMD_STATFILE_ERROR RSPAMD_BASE_ERROR + 5

struct rspamd_protocol_log_symbol_result {
	uint32_t id;
	float score;
};
struct rspamd_protocol_log_message_sum {
	uint32_t nresults;
	uint32_t nextra;
	uint32_t settings_id;
	double score;
	double required_score;
	struct rspamd_protocol_log_symbol_result results[];
};

struct rspamd_main;

/**
 * Process headers into HTTP message and set appropriate task fields
 * @param task
 * @param msg
 * @return
 */
gboolean rspamd_protocol_handle_headers(struct rspamd_task *task,
										struct rspamd_http_message *msg);

/**
 * Process control chunk and update task structure accordingly
 * @param task
 * @param control
 * @return
 */
gboolean rspamd_protocol_handle_control(struct rspamd_task *task,
										const ucl_object_t *control);

/**
 * Process HTTP request to the task structure
 * @param task
 * @param msg
 * @return
 */
gboolean rspamd_protocol_handle_request(struct rspamd_task *task,
										struct rspamd_http_message *msg);

/**
 * Write task results to http message
 * @param msg
 * @param task
 */
void rspamd_protocol_http_reply(struct rspamd_http_message *msg,
								struct rspamd_task *task, ucl_object_t **pobj,
								int how);

/**
 * Write data to log pipes
 * @param task
 */
void rspamd_protocol_write_log_pipe(struct rspamd_task *task);

enum rspamd_protocol_flags {
	RSPAMD_PROTOCOL_BASIC = 1 << 0,
	RSPAMD_PROTOCOL_METRICS = 1 << 1,
	RSPAMD_PROTOCOL_MESSAGES = 1 << 2,
	RSPAMD_PROTOCOL_RMILTER = 1 << 3,
	RSPAMD_PROTOCOL_DKIM = 1 << 4,
	RSPAMD_PROTOCOL_URLS = 1 << 5,
	RSPAMD_PROTOCOL_EXTRA = 1 << 6,
};

#define RSPAMD_PROTOCOL_DEFAULT (RSPAMD_PROTOCOL_BASIC |    \
								 RSPAMD_PROTOCOL_METRICS |  \
								 RSPAMD_PROTOCOL_MESSAGES | \
								 RSPAMD_PROTOCOL_RMILTER |  \
								 RSPAMD_PROTOCOL_DKIM |     \
								 RSPAMD_PROTOCOL_EXTRA)

/**
 * Write reply to ucl object filling log buffer
 * @param task
 * @param logbuf
 * @return
 */
ucl_object_t *rspamd_protocol_write_ucl(struct rspamd_task *task,
										enum rspamd_protocol_flags flags);

/**
 * Write reply for specified task command
 * @param task task object
 * @return 0 if we wrote reply and -1 if there was some error
 */
void rspamd_protocol_write_reply(struct rspamd_task *task, ev_tstamp timeout, struct rspamd_main *srv);

/**
 * Convert rspamd output to legacy protocol reply
 * @param task
 * @param top
 * @param out
 */
void rspamd_ucl_torspamc_output(const ucl_object_t *top,
								rspamd_fstring_t **out);

void rspamd_ucl_tospamc_output(const ucl_object_t *top,
							   rspamd_fstring_t **out);

#ifdef __cplusplus
}
#endif

#endif
