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
#define DEFAULT_MAX_ERRORS 10

struct smtp_worker_ctx {
	struct smtp_upstream upstreams[MAX_UPSTREAM];
	size_t upstream_num;
	
	memory_pool_t *pool;
	char *smtp_banner;
	uint32_t smtp_delay;
	uint32_t delay_jitter;
	struct timeval smtp_timeout;

	gboolean use_xclient;
	gboolean helo_required;
	char *smtp_capabilities;
	char *reject_message;
	size_t max_size;
	guint max_errors;
	char *metric;
};

enum rspamd_smtp_state {
	SMTP_STATE_RESOLVE_REVERSE,
	SMTP_STATE_RESOLVE_NORMAL,
	SMTP_STATE_DELAY,
	SMTP_STATE_GREETING,
	SMTP_STATE_HELO,
	SMTP_STATE_FROM,
	SMTP_STATE_RCPT,
	SMTP_STATE_BEFORE_DATA,
	SMTP_STATE_DATA,
	SMTP_STATE_AFTER_DATA,
	SMTP_STATE_END,
	SMTP_STATE_WAIT_UPSTREAM,
	SMTP_STATE_IN_SENDFILE,
	SMTP_STATE_ERROR,
	SMTP_STATE_CRITICAL_ERROR,
	SMTP_STATE_WRITE_ERROR
};

struct smtp_session {
	struct smtp_worker_ctx *ctx;
	struct config_file *cfg;
	memory_pool_t *pool;

	enum rspamd_smtp_state state;
	enum rspamd_smtp_state upstream_state;
	struct rspamd_worker *worker;
	struct worker_task *task;
	struct in_addr client_addr;
	char *hostname;
	char *error;
	char *temp_name;
	int sock;
	int upstream_sock;
	int temp_fd;
	size_t temp_size;
	time_t session_time;

	gchar *helo;
	GList *from;
	GList *rcpt;
	GList *cur_rcpt;

	guint errors;
	
	struct rspamd_async_session *s;
	rspamd_io_dispatcher_t *dispatcher;
	rspamd_io_dispatcher_t *upstream_dispatcher;

	struct smtp_upstream *upstream;

	gboolean resolved;
	gboolean esmtp;
};

void start_smtp_worker (struct rspamd_worker *worker);

#endif
