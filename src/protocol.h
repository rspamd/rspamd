/**
 * @file protocol.h
 * Rspamd protocol definition
 */

#ifndef RSPAMD_PROTOCOL_H
#define RSPAMD_PROTOCOL_H

#include "config.h"
#include "filter.h"
#include "http.h"

#define RSPAMD_BASE_ERROR 500
#define RSPAMD_FILTER_ERROR RSPAMD_BASE_ERROR + 1
#define RSPAMD_NETWORK_ERROR RSPAMD_BASE_ERROR + 2
#define RSPAMD_PROTOCOL_ERROR RSPAMD_BASE_ERROR + 3
#define RSPAMD_LENGTH_ERROR RSPAMD_BASE_ERROR + 4
#define RSPAMD_STATFILE_ERROR RSPAMD_BASE_ERROR + 5

struct worker_task;
struct metric;


enum rspamd_command {
	CMD_CHECK,
	CMD_SYMBOLS,
	CMD_REPORT,
	CMD_REPORT_IFSPAM,
	CMD_SKIP,
	CMD_PING,
	CMD_PROCESS,
	CMD_OTHER
};


typedef gint (*protocol_reply_func)(struct worker_task *task);

struct custom_command {
	const gchar *name;
	protocol_reply_func func;
};

/**
 * Process HTTP request to the task structure
 * @param task
 * @param msg
 * @return
 */
gboolean rspamd_protocol_handle_request (struct worker_task *task, struct rspamd_http_message *msg);

/**
 * Write reply for specified task command
 * @param task task object
 * @return 0 if we wrote reply and -1 if there was some error
 */
void rspamd_protocol_write_reply (struct worker_task *task);


/**
 * Register custom fucntion to extend protocol
 * @param name symbolic name of custom function
 * @param func callback function for writing reply
 */
void register_protocol_command (const gchar *name, protocol_reply_func func);

#endif
