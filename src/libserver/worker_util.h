/*-
 * Copyright 2016 Vsevolod Stakhov
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
#ifndef WORKER_UTIL_H_
#define WORKER_UTIL_H_

#include "config.h"
#include "util.h"
#include "libserver/http/http_connection.h"
#include "rspamd.h"

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef HAVE_SA_SIGINFO
typedef void (*rspamd_sig_handler_t) (gint);
#else

typedef void (*rspamd_sig_handler_t) (gint, siginfo_t *, void *);

#endif

struct rspamd_worker;
struct rspamd_worker_signal_handler;

/**
 * Init basic signals for a worker
 * @param worker
 * @param event_loop
 */
void rspamd_worker_init_signals (struct rspamd_worker *worker, struct ev_loop *event_loop);

typedef void (*rspamd_accept_handler) (struct ev_loop *loop, ev_io *w, int revents);

/**
 * Prepare worker's startup
 * @param worker worker structure
 * @param name name of the worker
 * @param sig_handler handler of main signals
 * @param accept_handler handler of accept event for listen sockets
 * @return event base suitable for a worker
 */
struct ev_loop *
rspamd_prepare_worker (struct rspamd_worker *worker, const char *name,
					   rspamd_accept_handler hdl);

/**
 * Should be used to validate context for a worker as in assert like invocation
 * @param ctx
 * @param magic
 * @return
 */
gboolean rspamd_worker_check_context (gpointer ctx, guint64 magic);

/**
 * Set special signal handler for a worker
 */
void rspamd_worker_set_signal_handler (int signo,
									   struct rspamd_worker *worker,
									   struct ev_loop *event_loop,
									   rspamd_worker_signal_cb_t handler,
									   void *handler_data);

/**
 * Stop accepting new connections for a worker
 * @param worker
 */
void rspamd_worker_stop_accept (struct rspamd_worker *worker);

typedef gint (*rspamd_controller_func_t) (
		struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg,
		struct module_ctx *ctx);

struct rspamd_custom_controller_command {
	const gchar *command;
	struct module_ctx *ctx;
	gboolean privilleged;
	gboolean require_message;
	rspamd_controller_func_t handler;
};

struct rspamd_controller_worker_ctx;
struct rspamd_lang_detector;

struct rspamd_controller_session {
	struct rspamd_controller_worker_ctx *ctx;
	struct rspamd_worker *wrk;
	rspamd_mempool_t *pool;
	struct rspamd_task *task;
	gchar *classifier;
	rspamd_inet_addr_t *from_addr;
	struct rspamd_config *cfg;
	struct rspamd_lang_detector *lang_det;
	gboolean is_spam;
	gboolean is_enable;
};

/**
 * Send error using HTTP and JSON output
 * @param entry router entry
 * @param code error code
 * @param error_msg error message
 */
void rspamd_controller_send_error (struct rspamd_http_connection_entry *entry,
								   gint code, const gchar *error_msg, ...);

/**
 * Send openmetrics-formatted strings using HTTP
 * @param entry router entry
 * @param str rspamd fstring buffer, ownership is transferred
 */
void
rspamd_controller_send_openmetrics (struct rspamd_http_connection_entry *entry,
									rspamd_fstring_t *str);

/**
 * Send a custom string using HTTP
 * @param entry router entry
 * @param str string to send
 */
void rspamd_controller_send_string (struct rspamd_http_connection_entry *entry,
									const gchar *str);

/**
 * Send UCL using HTTP and JSON serialization
 * @param entry router entry
 * @param obj object to send
 */
void rspamd_controller_send_ucl (struct rspamd_http_connection_entry *entry,
								 ucl_object_t *obj);

/**
 * Return worker's control structure by its type
 * @param type
 * @return worker's control structure or NULL
 */
worker_t *rspamd_get_worker_by_type (struct rspamd_config *cfg, GQuark type);

/**
 * Block signals before terminations
 */
void rspamd_worker_block_signals (void);

/**
 * Unblock signals
 */
void rspamd_worker_unblock_signals (void);

/**
 * Kill rspamd main and all workers
 * @param rspamd_main
 */
void rspamd_hard_terminate (struct rspamd_main *rspamd_main) G_GNUC_NORETURN;

/**
 * Returns TRUE if a specific worker is a scanner worker
 * @param w
 * @return
 */
gboolean rspamd_worker_is_scanner (struct rspamd_worker *w);

/**
 * Returns TRUE if a specific worker is a primary controller
 * @param w
 * @return
 */
gboolean rspamd_worker_is_primary_controller (struct rspamd_worker *w);

/**
 * Creates new session cache
 * @param w
 * @return
 */
void *rspamd_worker_session_cache_new (struct rspamd_worker *w,
									   struct ev_loop *ev_base);

/**
 * Adds a new session identified by pointer
 * @param cache
 * @param tag
 * @param pref
 * @param ptr
 */
void rspamd_worker_session_cache_add (void *cache, const gchar *tag,
									  guint *pref, void *ptr);

/**
 * Removes session from cache
 * @param cache
 * @param ptr
 */
void rspamd_worker_session_cache_remove (void *cache, void *ptr);

/**
 * Fork new worker with the specified configuration
 */
struct rspamd_worker *rspamd_fork_worker (struct rspamd_main *,
										  struct rspamd_worker_conf *, guint idx,
										  struct ev_loop *ev_base,
										  rspamd_worker_term_cb term_handler,
										  GHashTable *listen_sockets);

/**
 * Sets crash signals handlers if compiled with libunwind
 */
RSPAMD_NO_SANITIZE void rspamd_set_crash_handler (struct rspamd_main *);

/**
 * Initialise the main monitoring worker
 * @param worker
 * @param ev_base
 * @param resolver
 */
void rspamd_worker_init_monitored (struct rspamd_worker *worker,
								   struct ev_loop *ev_base,
								   struct rspamd_dns_resolver *resolver);

/**
 * Performs throttling for accept events
 * @param sock
 * @param data struct rspamd_worker_accept_event * list
 */
void rspamd_worker_throttle_accept_events (gint sock, void *data);

/**
 * Checks (and logs) the worker's termination status. Returns TRUE if a worker
 * should be restarted.
 * @param rspamd_main
 * @param wrk
 * @param status waitpid res
 * @return TRUE if refork is desired
 */
gboolean rspamd_check_termination_clause (struct rspamd_main *rspamd_main,
										  struct rspamd_worker *wrk, int status);

/**
 * Call for final scripts for a worker
 * @param worker
 * @return
 */
gboolean rspamd_worker_call_finish_handlers (struct rspamd_worker *worker);

struct rspamd_rrd_file;
/**
 * Terminate controller worker
 * @param worker
 */
void rspamd_controller_on_terminate (struct rspamd_worker *worker,
		struct rspamd_rrd_file *rrd);

/**
 * Inits controller worker
 * @param worker
 * @param ev_base
 * @param prrd
 */
void rspamd_worker_init_controller (struct rspamd_worker *worker,
								   struct rspamd_rrd_file **prrd);

/**
 * Saves stats
 * @param rspamd_main
 * @param cfg
 */
void rspamd_controller_store_saved_stats (struct rspamd_main *rspamd_main,
									 struct rspamd_config *cfg);

#ifdef WITH_HYPERSCAN
struct rspamd_control_command;

gboolean rspamd_worker_hyperscan_ready (struct rspamd_main *rspamd_main,
										struct rspamd_worker *worker, gint fd,
										gint attached_fd,
										struct rspamd_control_command *cmd,
										gpointer ud);

#endif

#define msg_err_main(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        rspamd_main->server_pool->tag.tagname, rspamd_main->server_pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_warn_main(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        rspamd_main->server_pool->tag.tagname, rspamd_main->server_pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_notice_main(...)   rspamd_default_log_function (G_LOG_LEVEL_MESSAGE, \
        rspamd_main->server_pool->tag.tagname, rspamd_main->server_pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_info_main(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        rspamd_main->server_pool->tag.tagname, rspamd_main->server_pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)

#ifdef  __cplusplus
}
#endif

#endif /* WORKER_UTIL_H_ */
