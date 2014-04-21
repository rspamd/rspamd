#ifndef RSPAMD_LMTP_PROTO_H
#define RSPAMD_LMTP_PROTO_H

#include "config.h"

struct rspamd_task;

enum lmtp_state {
	LMTP_READ_LHLO,
	LMTP_READ_FROM,
	LMTP_READ_RCPT,
	LMTP_READ_DATA,
	LMTP_READ_MESSAGE,
	LMTP_READ_DOT,
};

struct rspamd_lmtp_proto {
	struct rspamd_task *task;
	enum lmtp_state state;
};

/**
 * Read one line of user's input for specified task
 * @param lmtp lmtp object
 * @param line line of user's input
 * @return 0 if line was successfully parsed and -1 if we have protocol error
 */
gint read_lmtp_input_line (struct rspamd_lmtp_proto *lmtp, f_str_t *line);

/**
 * Deliver message via lmtp/smtp or pipe to LDA
 * @param task task object
 * @return 0 if we wrote message and -1 if there was some error
 */
gint lmtp_deliver_message (struct rspamd_task *task);

/**
 * Write reply for specified lmtp object
 * @param lmtp lmtp object
 * @return 0 if we wrote reply and -1 if there was some error
 */
gint write_lmtp_reply (struct rspamd_lmtp_proto *lmtp);

#endif
