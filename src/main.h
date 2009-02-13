/**
 * @file main.h
 * Definitions for main rspamd structures
 */

#ifndef RSPAMD_MAIN_H
#define RSPAMD_MAIN_H

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
#include "statfile.h"
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
#define msg_err g_critical
#define msg_warn	g_warning
#define msg_info	g_message
#define msg_debug g_debug

/** 
 * Process type: main or worker
 */
enum process_type {
	TYPE_MAIN,
	TYPE_WORKER,
	TYPE_CONTROLLER,
};

/** 
 * Filter type
 */
enum script_type {
	SCRIPT_HEADER,
	SCRIPT_MIME,
	SCRIPT_URL,
	SCRIPT_MESSAGE,
};

/** 
 * Logic expression 
 */
struct expression {
	enum { EXPR_OPERAND, EXPR_OPERATION } type;					/**< expression type								*/
	union {
		void *operand;
		char operation;
	} content;													/**< union for storing operand or operation code 	*/
	struct expression *next;									/**< chain link										*/
};

/** 
 * Worker process structure 
 */
struct rspamd_worker {
	pid_t pid;													/**< pid of worker									*/
	char is_initialized;										/**< is initialized									*/
	char is_dying;												/**< if worker is going to shutdown					*/
	struct rspamd_main *srv;									/**< pointer to server structure					*/
	enum process_type type;										/**< process type									*/
	struct event sig_ev;										/**< signals event									*/
	struct event bind_ev;										/**< socket events									*/
	TAILQ_ENTRY (rspamd_worker) next;							/**< chain link to next worker						*/
};

struct pidfh;
struct config_file;
struct tokenizer;
struct classifier;
struct mime_part;

/** 
 * Server statistics
 */
struct rspamd_stat {
	unsigned int messages_scanned;								/**< total number of messages scanned				*/
	unsigned int messages_spam;									/**< messages treated as spam						*/
	unsigned int messages_ham;									/**< messages treated as ham						*/
	unsigned int connections_count;								/**< total connections count						*/
	unsigned int control_connections_count;						/**< connections count to control interface			*/
	unsigned int messages_learned;								/**< messages learned								*/
};

/**
 * Struct that determine main server object (for logging purposes)
 */
struct rspamd_main {
	struct config_file *cfg;									/**< pointer to config structure					*/
	pid_t pid;													/**< main pid										*/
	/* Pid file structure */
	struct pidfh *pfh;											/**< struct pidfh for pidfile						*/
	enum process_type type;										/**< process type									*/
	unsigned int ev_initialized;								/**< is event system is initialized					*/
	struct rspamd_stat *stat;									/**< pointer to statistics							*/

	memory_pool_t *server_pool;									/**< server's memory pool							*/
	statfile_pool_t *statfile_pool;								/**< shared statfiles pool							*/

	TAILQ_HEAD (workq, rspamd_worker) workers;					/**< linked list of workers							*/
};

/**
 * Save point object for delayed filters processing
 */
struct save_point {
	void *entry;												/**< pointer to C function or perl function name	*/
	enum script_type type;										/**< where we did stop								*/
	unsigned int saved;											/**< how much time we have delayed processing		*/
};

/**
 * Control session object
 */
struct controller_session {
	struct rspamd_worker *worker;								/**< pointer to worker structure (controller in fact) */
	enum {
		STATE_COMMAND,
		STATE_LEARN,
		STATE_REPLY,
		STATE_QUIT,
	} state;													/**< current session state							*/
	int sock;													/**< socket descriptor								*/
	/* Access to authorized commands */
	int authorized;												/**< whether this session is authorized				*/
	memory_pool_t *session_pool;								/**< memory pool for session 						*/
	struct bufferevent *bev;									/**< buffered event for IO							*/
	struct config_file *cfg;									/**< pointer to config file							*/
	char *learn_rcpt;											/**< recipient for learning							*/
	char *learn_from;											/**< from address for learning						*/
	struct tokenizer *learn_tokenizer;							/**< tokenizer for learning							*/
	struct classifier *learn_classifier;						/**< classifier for learning						*/
	char *learn_filename;										/**< real filename for learning						*/
	f_str_buf_t *learn_buf;										/**< learn input									*/
	GList *parts;												/**< extracted mime parts							*/
	int in_class;												/**< positive or negative learn						*/
};

/**
 * Worker task structure
 */
struct worker_task {
	struct rspamd_worker *worker;								/**< pointer to worker object						*/
	enum {
		READ_COMMAND,
		READ_HEADER,
		READ_MESSAGE,
		WRITE_REPLY,
		WRITE_ERROR,
		WAIT_FILTER,
		CLOSING_CONNECTION,
	} state;													/**< current session state							*/
	size_t content_length;										/**< length of user's input							*/
	enum rspamd_protocol proto;									/**< protocol (rspamc or spamc)						*/
	enum rspamd_command cmd;									/**< command										*/
	int sock;													/**< socket descriptor								*/
	char *helo;													/**< helo header value								*/
	char *from;													/**< from header value								*/
	GList *rcpt;												/**< recipients list								*/
	unsigned int nrcpt;											/**< number of recipients							*/
	struct in_addr from_addr;									/**< client addr in numeric form					*/
	f_str_buf_t *msg;											/**< message buffer									*/
	struct bufferevent *bev;									/**< buffered event for IO							*/
	memcached_ctx_t *memc_ctx;									/**< memcached context associated with task			*/
	int parts_count;											/**< mime parts count								*/
	GMimeMessage *message;										/**< message, parsed with GMime						*/
	GList *parts;												/**< list of parsed parts							*/
	TAILQ_HEAD (uriq, uri) urls;								/**< list of parsed urls							*/
	GHashTable *results;										/**< hash table of metric_result indexed by 
																 *    metric's name									*/
	struct config_file *cfg;									/**< pointer to config object						*/
	struct save_point save;										/**< save point for delayed processing				*/
	char *last_error;											/**< last error										*/
	int error_code;												/**< code of last error								*/
	memory_pool_t *task_pool;									/**< memory pool for task							*/
};

/**
 * Common structure representing C module context
 */
struct module_ctx {
	int (*header_filter)(struct worker_task *task);				/**< pointer to headers process function			*/
	int (*mime_filter)(struct worker_task *task);				/**< pointer to mime parts process function			*/
	int (*message_filter)(struct worker_task *task);			/**< pointer to the whole message process function	*/
	int (*url_filter)(struct worker_task *task);				/**< pointer to urls process function				*/
};

/**
 * Common structure for C module
 */
struct c_module {
	const char *name;											/**< name											*/
	struct module_ctx *ctx;										/**< pointer to context								*/
	LIST_ENTRY (c_module) next;									/**< linked list									*/
};

void start_worker (struct rspamd_worker *worker, int listen_sock);
void start_controller (struct rspamd_worker *worker);

/**
 * If set, reopen log file on next write
 */
extern sig_atomic_t do_reopen_log;

#endif

/* 
 * vi:ts=4 
 */
