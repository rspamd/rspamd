/**
 * @file protocol.h
 * Rspamd protocol definition
 */

#ifndef RSPAMD_PROTOCOL_H
#define RSPAMD_PROTOCOL_H

#include "config.h"

#define RSPAMD_FILTER_ERROR 1
#define RSPAMD_NETWORK_ERROR 2
#define RSPAMD_PROTOCOL_ERROR 3
#define RSPAMD_LENGTH_ERROR 4

/*
 * Reply messages
 */
#define RSPAMD_REPLY_BANNER "RSPAMD/1.0"
#define SPAMD_REPLY_BANNER "SPAMD/1.1"
#define SPAMD_OK "EX_OK"
/* XXX: try to convert rspamd errors to spamd errors */
#define SPAMD_ERROR "EX_ERROR"

struct worker_task;

enum rspamd_protocol {
	SPAMC_PROTO,
	RSPAMC_PROTO,
};

enum rspamd_command {
	CMD_CHECK,
	CMD_SYMBOLS,
	CMD_REPORT,
	CMD_REPORT_IFSPAM,
	CMD_SKIP,
	CMD_PING,
	CMD_PROCESS,
	CMD_URLS,
	CMD_OTHER,
};


typedef int (*protocol_reply_func)(struct worker_task *task);

struct custom_command {
	const char *name;
	protocol_reply_func func;
};

/**
 * Read one line of user's input for specified task
 * @param task task object
 * @param line line of user's input
 * @return 0 if line was successfully parsed and -1 if we have protocol error
 */
int read_rspamd_input_line (struct worker_task *task, f_str_t *line);

/**
 * Write reply for specified task command
 * @param task task object
 * @return 0 if we wrote reply and -1 if there was some error
 */
int write_reply (struct worker_task *task);


/**
 * Register custom fucntion to extend protocol
 * @param name symbolic name of custom function
 * @param func callback function for writing reply
 */
void register_protocol_command (const char *name, protocol_reply_func func);

#endif
