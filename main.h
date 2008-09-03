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
#include "url.h"
#include "memcached.h"

#include <glib.h>
#include <gmime/gmime.h>

/* Default values */
#define FIXED_CONFIG_FILE "./rspamd.conf"
/* Time in seconds to exit for old worker */
#define SOFT_SHUTDOWN_TIME 60

/* Logging in postfix style */
#define msg_err(args...) syslog(LOG_ERR, ##args)
#define msg_warn(args...)	syslog(LOG_WARNING, ##args)
#define msg_info(args...)	syslog(LOG_INFO, ##args)
#define msg_debug(args...) syslog(LOG_DEBUG, ##args)

/* Process type: main or worker */
enum process_type {
	TYPE_MAIN,
	TYPE_WORKER,
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
struct filter_chain;


/* Struct that determine main server object (for logging purposes) */
struct rspamd_main {
	struct config_file *cfg;
	pid_t pid;
	/* Pid file structure */
	struct pidfh *pfh;
	enum process_type type;
	unsigned ev_initialized:1;

	TAILQ_HEAD (workq, rspamd_worker) workers;
};

struct filter_result {
	const char *symbol;
	struct filter_chain *chain;
	int mark;
	TAILQ_ENTRY (filter_result) next;
};

struct chain_result {
	struct filter_chain *chain;
	int *marks;
	unsigned int marks_num;
	int result_mark;
	TAILQ_ENTRY (chain_result) next;
};

struct mime_part {
	GMimeContentType *type;
	GByteArray *content;
	TAILQ_ENTRY (mime_part) next;
};

struct save_point {
	enum { C_FILTER, PERL_FILTER } save_type;
	void *entry;
	void *chain;
	unsigned int saved;
};

struct worker_task {
	struct rspamd_worker *worker;
	enum {
		READ_COMMAND,
		READ_HEADER,
		READ_MESSAGE,
		WRITE_REPLY,
		WRITE_ERROR,
		WAIT_FILTER,
	} state;
	size_t content_length;
	char *helo;
	char *from;
	char *rcpt;
	unsigned int nrcpt;
	struct in_addr from_addr;
	f_str_buf_t *msg;
	struct bufferevent *bev;
	/* Memcached connection for this task */
	memcached_ctx_t *memc_ctx;
	unsigned memc_busy:1;
	/* Number of mime parts */
	int parts_count;
	/* Headers */
	GMimeMessage *message;
	/* All parts of message */
	TAILQ_HEAD (mime_partq, mime_part) parts;
	/* URLs extracted from message */
	TAILQ_HEAD (uriq, uri) urls;
	/* List of filter results */
	TAILQ_HEAD (resultsq, filter_result) results;
	/* Results of all chains */
	TAILQ_HEAD (chainsq, chain_result) chain_results;
	struct config_file *cfg;
	struct save_point save;
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
int process_filters (struct worker_task *task);

#endif

/* 
 * vi:ts=4 
 */
