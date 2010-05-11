#ifndef RSPAMD_SMTP_H
#define RSPAMD_SMTP_H

#include "config.h"
#include "main.h"
#include "upstream.h"

struct smtp_upstream {
	struct upstream up;
	
	const char *name;
	struct in_addr addr;
	uint16_t port;
	gboolean is_unix;
}; 

#define MAX_UPSTREAM 128

struct smtp_worker_ctx {
	struct smtp_upstream upstreams[MAX_UPSTREAM];
	size_t upstream_num;
	
	memory_pool_t *pool;
	char *smtp_banner;
	uint32_t smtp_delay;
	uint32_t smtp_timeout;

	gboolean use_xclient;
	gboolean helo_required;
	const char *smtp_capabilities;
};

enum rspamd_smtp_state {
	SMTP_STATE_RESOLVE_REVERSE,
	SMTP_STATE_RESOLVE_NORMAL,
	SMTP_STATE_DELAY,
	SMTP_STATE_GREETING,
	SMTP_STATE_HELO,
	SMTP_STATE_FROM,
	SMTP_STATE_RCPT,
	SMTP_STATE_DATA,
	SMTP_STATE_EOD,
	SMTP_STATE_END
};

struct smtp_session {
	struct smtp_worker_ctx *ctx;
	memory_pool_t *pool;

	enum rspamd_smtp_state state;
	struct worker_task *task;
	struct in_addr client_addr;
	char *hostname;
	int sock;
	struct smtp_upstream *upstream;
	int upstream_sock;
	gboolean resolved;
};

#endif
