#ifndef RPOP_MAIN_H
#define RPOP_MAIN_H

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#ifndef HAVE_OWN_QUEUE_H
#include <sys/queue.h>
#else
#include "queue.h"
#endif
#include <sys/time.h>

#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <signal.h>
#include <event.h>

#include "fstring.h"
#include "mem_pool.h"
#include "url.h"
#include "memcached.h"
#include "protocol.h"
#include "filter.h"

#include <glib.h>
#include <gmime/gmime.h>

/* Default values */
#define FIXED_CONFIG_FILE "./rspamd.conf"
/* Time in seconds to exit for old worker */
#define SOFT_SHUTDOWN_TIME 60
/* Default metric name */
#define DEFAULT_METRIC "default"

/* Logging in postfix style */
#define msg_err g_error
#define msg_warn	g_warning
#define msg_info	g_message
#define msg_debug g_debug

/* Process type: main or worker */
enum process_type {
	TYPE_MAIN,
	TYPE_WORKER,
	TYPE_CONTROLLER,
};

/* Filter type */
enum script_type {
	SCRIPT_HEADER,
	SCRIPT_MIME,
	SCRIPT_URL,
	SCRIPT_MESSAGE,
};

/* Logic expression */
struct expression {
	enum { EXPR_OPERAND, EXPR_OPERATION } type;
	union {
		void *operand;
		char operation;
	} content;
	struct expression *next;
};

/* Worker process structure */
struct rspamd_worker {
	pid_t pid;
	char is_initialized;
	char is_dying;
	TAILQ_ENTRY (rspamd_worker) next;
	struct rspamd_main *srv;
	enum process_type type;
	struct event sig_ev;
	struct event bind_ev;
};

struct pidfh;
struct config_file;

/* Server statistics */
struct rspamd_stat {
	unsigned int messages_scanned;
	unsigned int messages_spam;
	unsigned int messages_ham;
	unsigned int connections_count;
	unsigned int control_connections_count;
	unsigned int messages_learned;
};

/* Struct that determine main server object (for logging purposes) */
struct rspamd_main {
	struct config_file *cfg;
	pid_t pid;
	/* Pid file structure */
	struct pidfh *pfh;
	enum process_type type;
	unsigned int ev_initialized;
	struct rspamd_stat *stat;

	memory_pool_t *server_pool;

	TAILQ_HEAD (workq, rspamd_worker) workers;
};

struct mime_part {
	GMimeContentType *type;
	GByteArray *content;
	TAILQ_ENTRY (mime_part) next;
};

struct save_point {
	void *entry;
	enum script_type type;
	unsigned int saved;
};

/* Control session */
struct controller_session {
	struct rspamd_worker *worker;
	int sock;
	/* Access to authorized commands */
	int authorized;
	memory_pool_t *session_pool;
	struct bufferevent *bev;
	struct config_file *cfg;
};

/* Worker task structure */
struct worker_task {
	struct rspamd_worker *worker;
	enum {
		READ_COMMAND,
		READ_HEADER,
		READ_MESSAGE,
		WRITE_REPLY,
		WRITE_ERROR,
		WAIT_FILTER,
		CLOSING_CONNECTION,
	} state;
	size_t content_length;
	enum rspamd_protocol proto;
	enum rspamd_command cmd;
	int sock;
	char *helo;
	char *from;
	GList *rcpt;
	unsigned int nrcpt;
	struct in_addr from_addr;
	f_str_buf_t *msg;
	struct bufferevent *bev;
	/* Memcached connection for this task */
	memcached_ctx_t *memc_ctx;
	unsigned memc_busy:1;
	/* Number of mime parts */
	int parts_count;
	/* Message */
	GMimeMessage *message;
	/* All parts of message */
	TAILQ_HEAD (mime_partq, mime_part) parts;
	/* URLs extracted from message */
	TAILQ_HEAD (uriq, uri) urls;
	/* Hash of metric result structures */
	GHashTable *results;
	struct config_file *cfg;
	/* Save point for filters deferred processing */
	struct save_point save;
	/* Saved error message and code */
	char *last_error;
	int error_code;
	/* Memory pool that is associated with this task */
	memory_pool_t *task_pool;
};

struct module_ctx {
	int (*header_filter)(struct worker_task *task);
	int (*mime_filter)(struct worker_task *task);
	int (*message_filter)(struct worker_task *task);
	int (*url_filter)(struct worker_task *task);
};

struct c_module {
	const char *name;
	struct module_ctx *ctx;
	LIST_ENTRY (c_module) next;
};

void start_worker (struct rspamd_worker *worker, int listen_sock);
void start_controller (struct rspamd_worker *worker);

extern sig_atomic_t do_reopen_log;

#endif

/* 
 * vi:ts=4 
 */
