#ifndef RSPAMD_SMTP_H
#define RSPAMD_SMTP_H

#include "config.h"
#include "main.h"
#include "upstream.h"
#include "smtp_utils.h"

struct rspamd_dns_resolver;

#define DEFAULT_MAX_ERRORS 10

enum rspamd_smtp_stage {
	SMTP_STAGE_CONNECT = 0,
	SMTP_STAGE_HELO,
	SMTP_STAGE_MAIL,
	SMTP_STAGE_RCPT,
	SMTP_STAGE_DATA,
	SMTP_STAGE_MAX
};

struct smtp_worker_ctx {
	struct smtp_upstream upstreams[MAX_SMTP_UPSTREAMS];
	gsize upstream_num;
	gchar *upstreams_str;
	
	rspamd_mempool_t *pool;
	gchar *smtp_banner;
	gchar *smtp_banner_str;
	guint32 smtp_delay;
	guint32 delay_jitter;
	guint32 smtp_timeout_raw;
	struct timeval smtp_timeout;

	gboolean use_xclient;
	gboolean helo_required;
	gchar *smtp_capabilities;
	gchar *smtp_capabilities_str;
	gchar *reject_message;
	gsize max_size;
	guint32 max_errors;
	gchar *metric;
	GList *smtp_filters[SMTP_STAGE_MAX];
	struct rspamd_dns_resolver *resolver;
	struct event_base *ev_base;
};

enum rspamd_smtp_state {
	SMTP_STATE_RESOLVE_REVERSE = 0,
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
	SMTP_STATE_QUIT,
	SMTP_STATE_WAIT_UPSTREAM,
	SMTP_STATE_IN_SENDFILE,
	SMTP_STATE_ERROR,
	SMTP_STATE_CRITICAL_ERROR,
	SMTP_STATE_WRITE_ERROR
};

struct smtp_session {
	struct smtp_worker_ctx *ctx;
	struct config_file *cfg;
	rspamd_mempool_t *pool;

	enum rspamd_smtp_state state;
	enum rspamd_smtp_state upstream_state;
	struct rspamd_worker *worker;
	struct rspamd_task *task;
	struct in_addr client_addr;
	gchar *hostname;
	gchar *error;
	gchar *temp_name;
	gint sock;
	gint upstream_sock;
	gint temp_fd;
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

	struct event *delay_timer;

	gboolean resolved;
	gboolean esmtp;
	struct rspamd_dns_resolver *resolver;
	struct event_base *ev_base;
};

typedef gboolean (*smtp_filter_t)(struct smtp_session *session, gpointer filter_data);

struct smtp_filter {
	smtp_filter_t filter;
	gpointer filter_data;
};

/*
 * Register new SMTP filter
 * XXX: work is still in progress
 */
void register_smtp_filter (struct smtp_worker_ctx *ctx, enum rspamd_smtp_stage stage, smtp_filter_t filter, gpointer filter_data);

#endif
