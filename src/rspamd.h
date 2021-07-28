/*-
 * Copyright 2016-2017 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RSPAMD_MAIN_H
#define RSPAMD_MAIN_H

#include "config.h"
#include "libutil/fstring.h"
#include "libutil/mem_pool.h"
#include "libutil/util.h"
#include "libserver/logger.h"
#include "libserver/http/http_connection.h"
#include "libutil/upstream.h"
#include "libutil/radix.h"
#include "libserver/cfg_file.h"
#include "libserver/url.h"
#include "libserver/protocol.h"
#include "libserver/async_session.h"
#include "libserver/roll_history.h"
#include "libserver/task.h"

#include <openssl/ssl.h>

/* Default values */
#define FIXED_CONFIG_FILE RSPAMD_CONFDIR "/rspamd.conf"
/* Time in seconds to exit for old worker */
#define SOFT_SHUTDOWN_TIME 10

/* Spam subject */
#define SPAM_SUBJECT "*** SPAM *** %s"

#ifdef CRLF
#undef CRLF
#undef CR
#undef LF
#endif

#define CRLF "\r\n"
#define CR '\r'
#define LF '\n'

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_main;

enum rspamd_worker_flags {
	RSPAMD_WORKER_HAS_SOCKET = (1 << 0),
	RSPAMD_WORKER_UNIQUE = (1 << 1),
	RSPAMD_WORKER_THREADED = (1 << 2),
	RSPAMD_WORKER_KILLABLE = (1 << 3),
	RSPAMD_WORKER_ALWAYS_START = (1 << 4),
	RSPAMD_WORKER_SCANNER = (1 << 5),
	RSPAMD_WORKER_CONTROLLER = (1 << 6),
	RSPAMD_WORKER_NO_TERMINATE_DELAY = (1 << 7),
	RSPAMD_WORKER_OLD_CONFIG = (1 << 8),
};

struct rspamd_worker_accept_event {
	ev_io accept_ev;
	ev_timer throttling_ev;
	struct ev_loop *event_loop;
	struct rspamd_worker_accept_event *prev, *next;
};

typedef void (*rspamd_worker_term_cb) (EV_P_ ev_child *, struct rspamd_main *,
									   struct rspamd_worker *);

struct rspamd_worker_heartbeat {
	ev_timer heartbeat_ev;          /**< used by main for checking heartbeats and by workers to send heartbeats */
	ev_tstamp last_event;           /**< last heartbeat received timestamp */
	gint64 nbeats;                  /**< positive for beats received, negative for beats missed */
};

enum rspamd_worker_state {
	rspamd_worker_state_running = 0,
	rspamd_worker_state_wanna_die,
	rspamd_worker_state_terminating,
	rspamd_worker_wait_connections,
	rspamd_worker_wait_final_scripts,
	rspamd_worker_wanna_die
};

/**
 * Worker process structure
 */
struct rspamd_worker {
	pid_t pid;                      /**< pid of worker									*/
	pid_t ppid;                     /**< pid of parent									*/
	guint index;                    /**< index number									*/
	guint nconns;                   /**< current connections count						*/
	enum rspamd_worker_state state; /**< current worker state							*/
	gboolean cores_throttled;       /**< set to true if cores throttling took place		*/
	gdouble start_time;             /**< start time										*/
	struct rspamd_main *srv;        /**< pointer to server structure					*/
	GQuark type;                    /**< process type									*/
	GHashTable *signal_events;      /**< signal events									*/
	struct rspamd_worker_accept_event *accept_events; /**< socket events				*/
	struct rspamd_worker_conf *cf;  /**< worker config data								*/
	gpointer ctx;                   /**< worker's specific data							*/
	gint flags;                     /**< worker's flags (enum rspamd_worker_flags)		*/
	gint control_pipe[2];           /**< control pipe. [0] is used by main process,
	                                                   [1] is used by a worker			*/
	gint srv_pipe[2];               /**< used by workers to request something from the
	                                     main process. [0] - main, [1] - worker			*/
	ev_io srv_ev;                   /**< used by main for read workers' requests		*/
	struct rspamd_worker_heartbeat hb; /**< heartbeat data */
	gpointer control_data;          /**< used by control protocol to handle commands	*/
	gpointer tmp_data;              /**< used to avoid race condition to deal with control messages */
	ev_child cld_ev;                /**< to allow reaping								*/
	rspamd_worker_term_cb term_handler; /**< custom term handler						*/
	GHashTable *control_events_pending; /**< control events pending indexed by ptr		*/
};

struct rspamd_abstract_worker_ctx {
	guint64 magic;
	/* Events base */
	struct ev_loop *event_loop;
	/* DNS resolver */
	struct rspamd_dns_resolver *resolver;
	/* Config */
	struct rspamd_config *cfg;
	char data[];
};

struct rspamd_worker_signal_handler;

typedef gboolean (*rspamd_worker_signal_cb_t) (
		struct rspamd_worker_signal_handler *, void *ud);

struct rspamd_worker_signal_handler_elt {
	rspamd_worker_signal_cb_t handler;
	void *handler_data;
	struct rspamd_worker_signal_handler_elt *next, *prev;
};

struct rspamd_worker_signal_handler {
	gint signo;
	gboolean enabled;
	ev_signal ev_sig;
	struct ev_loop *event_loop;
	struct rspamd_worker *worker;
	struct rspamd_worker_signal_handler_elt *cb;
};

/**
 * Common structure representing C module context
 */
struct module_s;

struct module_ctx {
	gint (*filter) (struct rspamd_task *task);                   /**< pointer to headers process function			*/
	struct module_s *mod;                                        /**< module pointer									*/
	gboolean enabled;                                            /**< true if module is enabled in configuration		*/
};

#ifndef WITH_HYPERSCAN
#define RSPAMD_FEATURE_HYPERSCAN "0"
#else
#define RSPAMD_FEATURE_HYPERSCAN "1"
#endif
#ifndef WITH_PCRE2
#define RSPAMD_FEATURE_PCRE2 "0"
#else
#define RSPAMD_FEATURE_PCRE2 "1"
#endif
#ifndef WITH_FANN
#define RSPAMD_FEATURE_FANN "0"
#else
#define RSPAMD_FEATURE_FANN "1"
#endif
#ifndef WITH_SNOWBALL
#define RSPAMD_FEATURE_SNOWBALL "0"
#else
#define RSPAMD_FEATURE_SNOWBALL "1"
#endif

#define RSPAMD_CUR_MODULE_VERSION 0x1
#define RSPAMD_CUR_WORKER_VERSION 0x2

#define RSPAMD_FEATURES \
        RSPAMD_FEATURE_HYPERSCAN RSPAMD_FEATURE_PCRE2 \
        RSPAMD_FEATURE_FANN RSPAMD_FEATURE_SNOWBALL

#define RSPAMD_MODULE_VER \
        RSPAMD_CUR_MODULE_VERSION, /* Module version */ \
        RSPAMD_VERSION_NUM, /* Rspamd version */ \
        RSPAMD_FEATURES /* Compilation features */ \

#define RSPAMD_WORKER_VER \
        RSPAMD_CUR_WORKER_VERSION, /* Worker version */ \
        RSPAMD_VERSION_NUM, /* Rspamd version */ \
        RSPAMD_FEATURES /* Compilation features */ \
/**
 * Module
 */
typedef struct module_s {
	const gchar *name;

	int (*module_init_func) (struct rspamd_config *cfg, struct module_ctx **ctx);

	int (*module_config_func) (struct rspamd_config *cfg, bool validate);

	int (*module_reconfig_func) (struct rspamd_config *cfg);

	int (*module_attach_controller_func) (struct module_ctx *ctx,
										  GHashTable *custom_commands);

	guint module_version;
	guint64 rspamd_version;
	const gchar *rspamd_features;
	guint ctx_offset;
} module_t;

enum rspamd_worker_socket_type {
	RSPAMD_WORKER_SOCKET_NONE = 0,
	RSPAMD_WORKER_SOCKET_TCP = (1 << 0),
	RSPAMD_WORKER_SOCKET_UDP = (1 << 1),
};

struct rspamd_worker_listen_socket {
	const rspamd_inet_addr_t *addr;
	gint fd;
	enum rspamd_worker_socket_type type;
	bool is_systemd;
};

typedef struct worker_s {
	const gchar *name;

	gpointer (*worker_init_func) (struct rspamd_config *cfg);

	void (*worker_start_func) (struct rspamd_worker *worker);

	int flags;
	int listen_type;
	guint worker_version;
	guint64 rspamd_version;
	const gchar *rspamd_features;
} worker_t;

/**
 * Check if loaded worker is compatible with rspamd
 * @param cfg
 * @param wrk
 * @return
 */
gboolean rspamd_check_worker (struct rspamd_config *cfg, worker_t *wrk);

/**
 * Check if loaded module is compatible with rspamd
 * @param cfg
 * @param wrk
 * @return
 */
gboolean rspamd_check_module (struct rspamd_config *cfg, module_t *wrk);

struct pidfh;
struct rspamd_config;
struct tokenizer;
struct rspamd_stat_classifier;
struct rspamd_classifier_config;
struct rspamd_mime_part;
struct rspamd_dns_resolver;
struct rspamd_task;
struct rspamd_cryptobox_library_ctx;

/**
 * Server statistics
 */
struct rspamd_stat {
	guint messages_scanned;                             /**< total number of messages scanned				*/
	guint actions_stat[METRIC_ACTION_MAX];              /**< statistic for each action						*/
	guint connections_count;                            /**< total connections count						*/
	guint control_connections_count;                    /**< connections count to control interface			*/
	guint messages_learned;                             /**< messages learned								*/
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
	struct rspamd_stat *stat;                                   /**< pointer to statistics							*/

	rspamd_mempool_t *server_pool;                              /**< server's memory pool							*/
	rspamd_mempool_mutex_t *start_mtx;                          /**< server is starting up							*/
	GHashTable *workers;                                        /**< workers pool indexed by pid                    */
	GHashTable *spairs;                                         /**< socket pairs requested by workers				*/
	rspamd_logger_t *logger;
	uid_t workers_uid;                                          /**< worker's uid running to                        */
	gid_t workers_gid;                                          /**< worker's gid running to						*/
	gboolean is_privilleged;                                    /**< true if run in privilleged mode                */
	gboolean wanna_die;                                         /**< no respawn of processes						*/
	gboolean cores_throttling;                                  /**< turn off cores when limits are exceeded		*/
	struct roll_history *history;                               /**< rolling history								*/
	struct ev_loop *event_loop;
	ev_signal term_ev, int_ev, hup_ev, usr1_ev;                 /**< signals 										*/
	struct rspamd_http_context *http_ctx;
};

/**
 * Control session object
 */
struct controller_command;
struct controller_session;

typedef gboolean (*controller_func_t) (gchar **args,
									   struct controller_session *session);

struct controller_session {
	struct rspamd_worker *worker;                               /**< pointer to worker structure (controller in fact) */
	gint sock;                                                  /**< socket descriptor								*/
	struct controller_command *cmd;                             /**< real command									*/
	struct rspamd_config *cfg;                                  /**< pointer to config file							*/
	GList *parts;                                               /**< extracted mime parts							*/
	struct rspamd_async_session *s;                             /**< async session object							*/
	struct rspamd_dns_resolver *resolver;                       /**< DNS resolver									*/
	struct ev_loop *ev_base;                                 /**< Event base										*/
};

struct zstd_dictionary {
	void *dict;
	gsize size;
	guint id;
};

struct rspamd_external_libs_ctx {
	void **local_addrs;
	struct rspamd_cryptobox_library_ctx *crypto_ctx;
	struct ottery_config *ottery_cfg;
	SSL_CTX *ssl_ctx;
	SSL_CTX *ssl_ctx_noverify;
	struct zstd_dictionary *in_dict;
	struct zstd_dictionary *out_dict;
	void *out_zstream;
	void *in_zstream;
	ref_entry_t ref;
};


/**
 * Register custom controller function
 */
void register_custom_controller_command (const gchar *name,
										 controller_func_t handler,
										 gboolean privilleged,
										 gboolean require_message);

#ifdef  __cplusplus
}
#endif

#endif