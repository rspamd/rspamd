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

#endif
