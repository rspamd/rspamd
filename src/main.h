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

/* Spam subject */
#define SPAM_SUBJECT "*** SPAM *** "

#ifdef CRLF
#undef CRLF
#undef CR
#undef LF
#endif

#define CRLF "\r\n"
#define CR '\r'
#define LF '\n'

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
	gpointer ctx;												/**< worker's specific data							*/
};

struct pidfh;
struct config_file;
struct tokenizer;
struct classifier;
struct classifier_config;
struct mime_part;
struct rspamd_view;
struct rspamd_dns_resolver;
struct worker_task;

/** 
 * Server statistics
 */
struct rspamd_stat {
	guint messages_scanned;								/**< total number of messages scanned				*/
	guint messages_spam;									/**< messages treated as spam						*/
	guint messages_ham;									/**< messages treated as ham						*/
	guint connections_count;								/**< total connections count						*/
	guint control_connections_count;						/**< connections count to control interface			*/
	guint messages_learned;								/**< messages learned								*/
	guint fuzzy_hashes;									/**< number of fuzzy hashes stored					*/
	guint fuzzy_hashes_expired;							/**< number of fuzzy hashes expired					*/
};

/**
 * Struct that determine main server object (for logging purposes)
 */
struct rspamd_main {
	struct config_file *cfg;									/**< pointer to config structure					*/
	pid_t pid;													/**< main pid										*/
	/* Pid file structure */
	rspamd_pidfh_t *pfh;											/**< struct pidfh for pidfile						*/
	enum process_type type;										/**< process type									*/
	guint ev_initialized;										/**< is event system is initialized					*/
	struct rspamd_stat *stat;									/**< pointer to statistics							*/

	memory_pool_t *server_pool;									/**< server's memory pool							*/
	statfile_pool_t *statfile_pool;								/**< shared statfiles pool							*/
	GHashTable *workers;                                        /**< workers pool indexed by pid                    */
	rspamd_logger_t *logger;
};

struct counter_data {
	guint64 value;
	gint number;
};

/**
 * Save point object for delayed filters processing
 */
struct save_point {
	GList *entry;												/**< pointer to saved metric						*/
	void *item;													/**< pointer to saved item 							*/
	guint saved;											/**< how much time we have delayed processing		*/
};

/**
 * Structure to point exception in text from processing
 */
struct process_exception {
	gsize pos;
	gsize len;
};

/**
 * Union that would be used for storing sockaddrs
 */
union sa_union {
	struct sockaddr_storage ss;
	struct sockaddr_in s4;
	struct sockaddr_in6 s6;
};

/**
 * Control session object
 */
struct controller_session {
	struct rspamd_worker *worker;								/**< pointer to worker structure (controller in fact) */
	enum {
		STATE_COMMAND,
		STATE_LEARN,
		STATE_LEARN_SPAM_PRE,
		STATE_LEARN_SPAM,
		STATE_REPLY,
		STATE_QUIT,
		STATE_OTHER,
		STATE_WAIT,
		STATE_WEIGHTS
	} state;													/**< current session state							*/
	gint sock;													/**< socket descriptor								*/
	/* Access to authorized commands */
	gint authorized;												/**< whether this session is authorized				*/
	memory_pool_t *session_pool;								/**< memory pool for session 						*/
	struct config_file *cfg;									/**< pointer to config file							*/
	gchar *learn_rcpt;											/**< recipient for learning							*/
	gchar *learn_from;											/**< from address for learning						*/
	struct classifier_config *learn_classifier;
	gchar *learn_symbol;											/**< symbol to train								*/
	double learn_multiplier;									/**< multiplier for learning						*/
	rspamd_io_dispatcher_t *dispatcher;							/**< IO dispatcher object							*/
	f_str_t *learn_buf;											/**< learn input									*/
	GList *parts;												/**< extracted mime parts							*/
	gint in_class;												/**< positive or negative learn						*/
	void (*other_handler)(struct controller_session *session, 
			f_str_t *in);					/**< other command handler to execute at the end of processing */
	void *other_data;											/**< and its data 									*/
	struct rspamd_async_session* s;								/**< async session object							*/
	struct worker_task *learn_task;
	struct rspamd_dns_resolver *resolver;						/**< DNS resolver									*/
	struct event_base *ev_base;									/**< Event base										*/
};

typedef void (*controller_func_t)(gchar **args, struct controller_session *session);

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
	guint proto_ver;											/**< protocol version								*/
	enum rspamd_command cmd;									/**< command										*/
	struct custom_command *custom_cmd;							/**< custom command if any							*/	
	gint sock;													/**< socket descriptor								*/
	gboolean is_mime;                                           /**< if this task is mime task                      */
	gboolean is_json;											/**< output is JSON									*/
	gboolean is_http;											/**< output is HTTP									*/
	gboolean allow_learn;										/**< allow learning									*/
	gboolean is_skipped;                                        /**< whether message was skipped by configuration   */

	gchar *helo;													/**< helo header value								*/
	gchar *from;													/**< from header value								*/
	gchar *queue_id;												/**< queue id if specified							*/
	const gchar *message_id;										/**< message id										*/
	GList *rcpt;												/**< recipients list								*/
	guint nrcpt;											/**< number of recipients							*/
	struct in_addr from_addr;									/**< client addr in numeric form					*/
	struct in_addr client_addr;									/**< client addr in numeric form					*/
	gchar *deliver_to;											/**< address to deliver								*/
	gchar *user;													/**< user to deliver								*/
	gchar *subject;												/**< subject (for non-mime)							*/
	gchar *statfile;											/**< statfile for learning							*/
	f_str_t *msg;												/**< message buffer									*/
	rspamd_io_dispatcher_t *dispatcher;							/**< IO dispatcher object							*/
	struct rspamd_async_session* s;								/**< async session object							*/
	gint parts_count;											/**< mime parts count								*/
	GMimeMessage *message;										/**< message, parsed with GMime						*/
	GMimeObject *parser_parent_part;							/**< current parent part							*/
	InternetAddressList *rcpts;									/**< list of all recipients 						*/
	GList *parts;												/**< list of parsed parts							*/
	GList *text_parts;											/**< list of text parts								*/
	gchar *raw_headers_str;											/**< list of raw headers							*/
	GList *received;											/**< list of received headers						*/
	GTree *urls;												/**< list of parsed urls							*/
	GTree *emails;												/**< list of parsed emails							*/
	GList *images;												/**< list of images									*/
	GHashTable *raw_headers;									/**< list of raw headers							*/
	GHashTable *results;										/**< hash table of metric_result indexed by 
	 *    metric's name									*/
	GHashTable *tokens;											/**< hash table of tokens indexed by tokenizer
	 *    pointer 										*/
	GList *messages;											/**< list of messages that would be reported		*/
	GHashTable *re_cache;										/**< cache for matched or not matched regexps		*/
	struct config_file *cfg;									/**< pointer to config object						*/
	struct save_point save;										/**< save point for delayed processing				*/
	gchar *last_error;											/**< last error										*/
	gint error_code;												/**< code of last error								*/
	memory_pool_t *task_pool;									/**< memory pool for task							*/
#ifdef HAVE_CLOCK_GETTIME
	struct timespec ts;											/**< time of connection								*/
#endif
	struct timeval tv;											/**< time of connection								*/
	struct rspamd_view *view;									/**< matching view									*/
	gboolean view_checked;
	gboolean pass_all_filters;									/**< pass task throught every rule					*/
	guint32 parser_recursion;									/**< for avoiding recursion stack overflow			*/
	gboolean (*fin_callback)(void *arg);						/**< calback for filters finalizing					*/
	void *fin_arg;												/**< argument for fin callback						*/

	guint32 dns_requests;										/**< number of DNS requests per this task			*/

	struct rspamd_dns_resolver *resolver;						/**< DNS resolver									*/
	struct event_base *ev_base;									/**< Event base										*/
};

/**
 * Common structure representing C module context
 */
struct module_ctx {
	gint (*filter)(struct worker_task *task);					/**< pointer to headers process function			*/
};

/**
 * Common structure for C module
 */
struct c_module {
	const gchar *name;											/**< name											*/
	struct module_ctx *ctx;										/**< pointer to context								*/
};

/* Workers' initialization and start functions */
gpointer init_worker (void);
void start_worker (struct rspamd_worker *worker);
gpointer init_controller (void);
void start_controller (struct rspamd_worker *worker);
gpointer init_greylist (void);
void start_greylist_storage (struct rspamd_worker *worker);

/**
 * Register custom controller function
 */
void register_custom_controller_command (const gchar *name, controller_func_t handler, gboolean privilleged, gboolean require_message);

/**
 * Initialize context for worker of specified type
 */
gpointer init_workers_ctx (enum process_type type);

/**
 * If set, reopen log file on next write
 */
extern struct rspamd_main *rspamd_main;

#endif

/* 
 * vi:ts=4 
 */
