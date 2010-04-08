/**
 * @file main.h
 * Definitions for main rspamd structures
 */

#ifndef RSPAMD_MAIN_H
#define RSPAMD_MAIN_H

#include "config.h"
#include "fstring.h"
#include "mem_pool.h"
#include "statfile.h"
#include "url.h"
#include "memcached.h"
#include "protocol.h"
#include "filter.h"
#include "buffer.h"
#include "hash.h"
#include "events.h"
#include "util.h"
#include "logger.h"

/* Default values */
#define FIXED_CONFIG_FILE ETC_PREFIX "/rspamd.xml"
/* Time in seconds to exit for old worker */
#define SOFT_SHUTDOWN_TIME 10
/* Default metric name */
#define DEFAULT_METRIC "default"
/* 60 seconds for worker's IO */
#define WORKER_IO_TIMEOUT 60

#ifdef CRLF
#undef CRLF
#undef CR
#undef LF
#endif

#define CRLF "\r\n"
#define CR '\r'
#define LF '\n'

/** 
 * Process type: main or worker
 */
enum process_type {
	TYPE_MAIN,
	TYPE_WORKER,
	TYPE_CONTROLLER,
	TYPE_LMTP,
	TYPE_FUZZY
};


/** 
 * Worker process structure 
 */
struct rspamd_worker {
	pid_t pid;													/**< pid of worker									*/
	gboolean is_initialized;									/**< is initialized									*/
	gboolean is_dying;											/**< if worker is going to shutdown					*/
	gboolean pending;											/**< if worker is pending to run					*/
	struct rspamd_main *srv;									/**< pointer to server structure					*/
	enum process_type type;										/**< process type									*/
	struct event sig_ev;										/**< signals event									*/
	struct event bind_ev;										/**< socket events									*/
	struct worker_conf *cf;										/**< worker config data								*/
};

struct pidfh;
struct config_file;
struct tokenizer;
struct classifier;
struct classifier_config;
struct mime_part;
struct rspamd_view;

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
	unsigned int fuzzy_hashes;									/**< number of fuzzy hashes stored					*/
	unsigned int fuzzy_hashes_expired;							/**< number of fuzzy hashes expired					*/
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
    GHashTable *workers;                                        /**< workers pool indexed by pid                    */
};

struct counter_data {
	uint64_t value;
	int number;
};

/**
 * Save point object for delayed filters processing
 */
struct save_point {
	GList *entry;												/**< pointer to saved metric						*/
	void *item;													/**< pointer to saved item 							*/
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
		STATE_OTHER,
		STATE_WAIT,
		STATE_WEIGHTS
	} state;													/**< current session state							*/
	int sock;													/**< socket descriptor								*/
	/* Access to authorized commands */
	int authorized;												/**< whether this session is authorized				*/
	memory_pool_t *session_pool;								/**< memory pool for session 						*/
	struct config_file *cfg;									/**< pointer to config file							*/
	char *learn_rcpt;											/**< recipient for learning							*/
	char *learn_from;											/**< from address for learning						*/
	struct classifier_config *learn_classifier;
	char *learn_symbol;											/**< symbol to train								*/
	double learn_multiplier;									/**< multiplier for learning						*/
	rspamd_io_dispatcher_t *dispatcher;							/**< IO dispatcher object							*/
	f_str_t *learn_buf;											/**< learn input									*/
	GList *parts;												/**< extracted mime parts							*/
	int in_class;												/**< positive or negative learn						*/
	void (*other_handler)(struct controller_session *session, 
								f_str_t *in);					/**< other command handler to execute at the end of processing */
	void *other_data;											/**< and its data 									*/
    struct rspamd_async_session* s;								/**< async session object							*/
};

typedef void (*controller_func_t)(char **args, struct controller_session *session);

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
		CLOSING_CONNECTION
	} state;													/**< current session state							*/
	size_t content_length;										/**< length of user's input							*/
	enum rspamd_protocol proto;									/**< protocol (rspamc or spamc)						*/
	const char *proto_ver;										/**< protocol version								*/
	enum rspamd_command cmd;									/**< command										*/
	struct custom_command *custom_cmd;							/**< custom command if any							*/	
	int sock;													/**< socket descriptor								*/
    gboolean is_mime;                                           /**< if this task is mime task                      */
    gboolean is_skipped;                                        /**< whether message was skipped by configuration   */
	char *helo;													/**< helo header value								*/
	char *from;													/**< from header value								*/
	char *queue_id;												/**< queue id if specified							*/
	const char *message_id;										/**< message id										*/
	GList *rcpt;												/**< recipients list								*/
	unsigned int nrcpt;											/**< number of recipients							*/
	struct in_addr from_addr;									/**< client addr in numeric form					*/
	struct in_addr client_addr;									/**< client addr in numeric form					*/
	char *deliver_to;											/**< address to deliver								*/
	char *user;													/**< user to deliver								*/
	char *subject;												/**< subject (for non-mime)							*/
	f_str_t *msg;												/**< message buffer									*/
	rspamd_io_dispatcher_t *dispatcher;							/**< IO dispatcher object							*/
    struct rspamd_async_session* s;								/**< async session object							*/
	int parts_count;											/**< mime parts count								*/
	GMimeMessage *message;										/**< message, parsed with GMime						*/
	InternetAddressList *rcpts;									/**< list of all recipients 						*/
	GList *parts;												/**< list of parsed parts							*/
	GList *text_parts;											/**< list of text parts								*/
	char *raw_headers;											/**< list of raw headers							*/
	GList *received;											/**< list of received headers						*/
	GList *urls;												/**< list of parsed urls							*/
	GHashTable *results;										/**< hash table of metric_result indexed by 
																 *    metric's name									*/
	GList *messages;											/**< list of messages that would be reported		*/
	GHashTable *re_cache;										/**< cache for matched or not matched regexps		*/
	struct config_file *cfg;									/**< pointer to config object						*/
	struct save_point save;										/**< save point for delayed processing				*/
	char *last_error;											/**< last error										*/
	int error_code;												/**< code of last error								*/
	memory_pool_t *task_pool;									/**< memory pool for task							*/
	struct timespec ts;											/**< time of connection								*/
	struct rspamd_view *view;									/**< matching view									*/
	gboolean view_checked;
	uint32_t parser_recursion;									/**< for avoiding recursion stack overflow			*/
};

/**
 * Common structure representing C module context
 */
struct module_ctx {
	int (*filter)(struct worker_task *task);					/**< pointer to headers process function			*/
};

/**
 * Common structure for C module
 */
struct c_module {
	const char *name;											/**< name											*/
	struct module_ctx *ctx;										/**< pointer to context								*/
};

void start_worker (struct rspamd_worker *worker);
void start_controller (struct rspamd_worker *worker);

/**
 * Register custom controller function
 */
void register_custom_controller_command (const char *name, controller_func_t handler, gboolean privilleged, gboolean require_message);

/**
 * Construct new task for worker
 */
struct worker_task* construct_task (struct rspamd_worker *worker);
/**
 * Destroy task object and remove its IO dispatcher if it exists
 */
void free_task (struct worker_task *task, gboolean is_soft);

/**
 * If set, reopen log file on next write
 */
extern sig_atomic_t do_reopen_log;

#endif

/* 
 * vi:ts=4 
 */
