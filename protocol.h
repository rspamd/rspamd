#ifndef RSPAMD_PROTOCOL_H
#define RSPAMD_PROTOCOL_H

#include "config.h"

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

int read_rspamd_input_line (struct worker_task *task, char *line);

#endif
