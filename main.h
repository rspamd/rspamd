#ifndef RPOP_MAIN_H
#define RPOP_MAIN_H

#include <sys/types.h>
#include <sys/socket.h>
#ifndef OWN_QUEUE_H
#include <sys/queue.h>
#else
#include "queue.h"
#endif
#include <sys/time.h>

#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <signal.h>

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
};

struct pidfh;
struct config_file;

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

struct worker_task {
	int id;
};

void start_worker (struct rspamd_worker *worker, int listen_sock);

#endif

/* 
 * vi:ts=4 
 */
