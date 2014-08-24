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
#include "protocol.h"
#include "filter.h"
#include "buffer.h"
#include "events.h"
#include "util.h"
#include "logger.h"
#include "roll_history.h"
#include "http.h"
#include "task.h"
#include "worker_util.h"

/* Default values */
#define FIXED_CONFIG_FILE RSPAMD_CONFDIR "/rspamd.conf"
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
	pid_t pid;                                                  /**< pid of worker									*/
	gboolean is_initialized;                                    /**< is initialized									*/
	gboolean is_dying;                                          /**< if worker is going to shutdown					*/
	gboolean pending;                                           /**< if worker is pending to run					*/
	struct rspamd_main *srv;                                    /**< pointer to server structure					*/
	GQuark type;                                                /**< process type									*/
	struct event sig_ev_usr1;                                   /**< signals event									*/
	struct event sig_ev_usr2;                                   /**< signals event									*/
	GList *accept_events;                                       /**< socket events									*/
	struct rspamd_worker_conf *cf;                                      /**< worker config data								*/
	gpointer ctx;                                               /**< worker's specific data							*/
};

/**
 * Module
 */

struct pidfh;
struct rspamd_config;
struct tokenizer;
struct classifier;
struct rspamd_classifier_config;
struct mime_part;
struct rspamd_dns_resolver;
struct rspamd_task;

/**
 * Server statistics
 */
struct rspamd_stat {
	guint messages_scanned;                             /**< total number of messages scanned				*/
	guint actions_stat[METRIC_ACTION_NOACTION + 1];     /**< statistic for each action						*/
	guint connections_count;                            /**< total connections count						*/
	guint control_connections_count;                    /**< connections count to control interface			*/
	guint messages_learned;                             /**< messages learned								*/
	guint fuzzy_hashes;                                 /**< number of fuzzy hashes stored					*/
	guint fuzzy_hashes_expired;                         /**< number of fuzzy hashes expired					*/
};

/**
 * Struct that determine main server object (for logging purposes)
 */
struct rspamd_main {
	struct rspamd_config *cfg;                                  /**< pointer to config structure					*/
	pid_t pid;                                                  /**< main pid										*/
	/* Pid file structure */
	rspamd_pidfh_t *pfh;                                        /**< struct pidfh for pidfile						*/
	GQuark type;                                                /**< process type									*/
	guint ev_initialized;                                       /**< is event system is initialized					*/
	struct rspamd_stat *stat;                                   /**< pointer to statistics							*/

	rspamd_mempool_t *server_pool;                                  /**< server's memory pool							*/
	statfile_pool_t *statfile_pool;                             /**< shared statfiles pool							*/
	GHashTable *workers;                                        /**< workers pool indexed by pid                    */
	rspamd_logger_t *logger;
	uid_t workers_uid;                                          /**< worker's uid running to                        */
	gid_t workers_gid;                                          /**< worker's gid running to						*/
	gboolean is_privilleged;                                    /**< true if run in privilleged mode                */
	struct roll_history *history;                               /**< rolling history								*/
};

/**
 * Structure to point exception in text from processing
 */
struct process_exception {
	gsize pos;
	gsize len;
};

/**
 * Control session object
 */
struct controller_command;
struct controller_session;
typedef gboolean (*controller_func_t)(gchar **args,
	struct controller_session *session);

struct controller_session {
	struct rspamd_worker *worker;                               /**< pointer to worker structure (controller in fact) */
	enum {
		STATE_COMMAND,
		STATE_HEADER,
		STATE_LEARN,
		STATE_LEARN_SPAM_PRE,
		STATE_LEARN_SPAM,
		STATE_REPLY,
		STATE_QUIT,
		STATE_OTHER,
		STATE_WAIT,
		STATE_WEIGHTS
	} state;                                                    /**< current session state							*/
	gint sock;                                                  /**< socket descriptor								*/
	/* Access to authorized commands */
	gboolean authorized;                                        /**< whether this session is authorized				*/
	gboolean restful;                                           /**< whether this session is a restful session		*/
	GHashTable *kwargs;                                         /**< keyword arguments for restful command			*/
	struct controller_command *cmd;                             /**< real command									*/
	rspamd_mempool_t *session_pool;                             /**< memory pool for session                        */
	struct rspamd_config *cfg;                                  /**< pointer to config file							*/
	gchar *learn_rcpt;                                          /**< recipient for learning							*/
	gchar *learn_from;                                          /**< from address for learning						*/
	struct rspamd_classifier_config *learn_classifier;
	gchar *learn_symbol;                                            /**< symbol to train								*/
	double learn_multiplier;                                    /**< multiplier for learning						*/
	rspamd_io_dispatcher_t *dispatcher;                         /**< IO dispatcher object							*/
	f_str_t *learn_buf;                                         /**< learn input									*/
	GList *parts;                                               /**< extracted mime parts							*/
	gint in_class;                                              /**< positive or negative learn						*/
	gboolean (*other_handler)(struct controller_session *session,
		f_str_t *in);                       /**< other command handler to execute at the end of processing */
	void *other_data;                                           /**< and its data                                   */
	controller_func_t custom_handler;                           /**< custom command handler							*/
	struct rspamd_async_session * s;                             /**< async session object							*/
	struct rspamd_task *learn_task;
	struct rspamd_dns_resolver *resolver;                       /**< DNS resolver									*/
	struct event_base *ev_base;                                 /**< Event base										*/
};

/**
 * Common structure representing C module context
 */
struct module_ctx {
	gint (*filter)(struct rspamd_task *task);                   /**< pointer to headers process function			*/
};

/**
 * Register custom controller function
 */
void register_custom_controller_command (const gchar *name,
	controller_func_t handler,
	gboolean privilleged,
	gboolean require_message);

/**
 * If set, reopen log file on next write
 */
extern struct rspamd_main *rspamd_main;

#endif

/*
 * vi:ts=4
 */
