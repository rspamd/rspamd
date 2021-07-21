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
#ifndef RSPAMD_RSPAMD_CONTROL_H
#define RSPAMD_RSPAMD_CONTROL_H

#include "config.h"
#include "mem_pool.h"
#include "contrib/libev/ev.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_main;
struct rspamd_worker;

enum rspamd_control_type {
	RSPAMD_CONTROL_STAT = 0,
	RSPAMD_CONTROL_RELOAD,
	RSPAMD_CONTROL_RERESOLVE,
	RSPAMD_CONTROL_RECOMPILE,
	RSPAMD_CONTROL_HYPERSCAN_LOADED,
	RSPAMD_CONTROL_LOG_PIPE,
	RSPAMD_CONTROL_FUZZY_STAT,
	RSPAMD_CONTROL_FUZZY_SYNC,
	RSPAMD_CONTROL_MONITORED_CHANGE,
	RSPAMD_CONTROL_CHILD_CHANGE,
	RSPAMD_CONTROL_MAX
};

enum rspamd_srv_type {
	RSPAMD_SRV_SOCKETPAIR = 0,
	RSPAMD_SRV_HYPERSCAN_LOADED,
	RSPAMD_SRV_MONITORED_CHANGE,
	RSPAMD_SRV_LOG_PIPE,
	RSPAMD_SRV_ON_FORK,
	RSPAMD_SRV_HEARTBEAT,
	RSPAMD_SRV_HEALTH,
};

enum rspamd_log_pipe_type {
	RSPAMD_LOG_PIPE_SYMBOLS = 0,
};
#define CONTROL_PATHLEN 400
struct rspamd_control_command {
	enum rspamd_control_type type;
	union {
		struct {
			guint unused;
		} stat;
		struct {
			guint unused;
		} reload;
		struct {
			guint unused;
		} reresolve;
		struct {
			guint unused;
		} recompile;
		struct {
			gchar cache_dir[CONTROL_PATHLEN];
			gboolean forced;
		} hs_loaded;
		struct {
			gchar tag[32];
			gboolean alive;
			pid_t sender;
		} monitored_change;
		struct {
			enum rspamd_log_pipe_type type;
		} log_pipe;
		struct {
			guint unused;
		} fuzzy_stat;
		struct {
			guint unused;
		} fuzzy_sync;
		struct {
			enum {
				rspamd_child_offline,
				rspamd_child_online,
				rspamd_child_terminated,
			} what;
			pid_t pid;
			guint additional;
		} child_change;
	} cmd;
};

struct rspamd_control_reply {
	enum rspamd_control_type type;
	union {
		struct {
			guint conns;
			gdouble uptime;
			gdouble utime;
			gdouble systime;
			gulong maxrss;
		} stat;
		struct {
			guint status;
		} reload;
		struct {
			guint status;
		} reresolve;
		struct {
			guint status;
		} recompile;
		struct {
			guint status;
		} hs_loaded;
		struct {
			guint status;
		} monitored_change;
		struct {
			guint status;
		} log_pipe;
		struct {
			guint status;
			gchar storage_id[MEMPOOL_UID_LEN];
		} fuzzy_stat;
		struct {
			guint status;
		} fuzzy_sync;
	} reply;
};

#define PAIR_ID_LEN 16

struct rspamd_srv_command {
	enum rspamd_srv_type type;
	guint64 id;
	union {
		struct {
			gint af;
			gchar pair_id[PAIR_ID_LEN];
			guint pair_num;
		} spair;
		struct {
			gchar cache_dir[CONTROL_PATHLEN];
			gboolean forced;
		} hs_loaded;
		struct {
			gchar tag[32];
			gboolean alive;
			pid_t sender;
		} monitored_change;
		struct {
			enum rspamd_log_pipe_type type;
		} log_pipe;
		struct {
			pid_t ppid;
			pid_t cpid;
			enum {
				child_create = 0,
				child_dead,
			} state;
		} on_fork;
		struct {
			guint status;
			/* TODO: add more fields */
		} heartbeat;
		struct {
			guint status;
		} health;
	} cmd;
};

struct rspamd_srv_reply {
	enum rspamd_srv_type type;
	guint64 id;
	union {
		struct {
			gint code;
		} spair;
		struct {
			gint forced;
		} hs_loaded;
		struct {
			gint status;
		};
		struct {
			enum rspamd_log_pipe_type type;
		} log_pipe;
		struct {
			gint status;
		} on_fork;
		struct {
			gint status;
		} heartbeat;
		struct {
			guint status;
			guint workers_count;
			guint scanners_count;
			guint workers_hb_lost;
		} health;
	} reply;
};

typedef gboolean (*rspamd_worker_control_handler) (struct rspamd_main *rspamd_main,
												   struct rspamd_worker *worker,
												   gint fd,
												   gint attached_fd,
												   struct rspamd_control_command *cmd,
												   gpointer ud);

typedef void (*rspamd_srv_reply_handler) (struct rspamd_worker *worker,
										  struct rspamd_srv_reply *rep, gint rep_fd,
										  gpointer ud);

/**
 * Process client socket connection
 */
void rspamd_control_process_client_socket (struct rspamd_main *rspamd_main,
										   gint fd, rspamd_inet_addr_t *addr);

/**
 * Register default handlers for a worker
 */
void rspamd_control_worker_add_default_cmd_handlers (struct rspamd_worker *worker,
													 struct ev_loop *ev_base);

/**
 * Register custom handler for a specific control command for this worker
 */
void rspamd_control_worker_add_cmd_handler (struct rspamd_worker *worker,
											enum rspamd_control_type type,
											rspamd_worker_control_handler handler,
											gpointer ud);

/**
 * Start watching on srv pipe
 */
void rspamd_srv_start_watching (struct rspamd_main *srv,
								struct rspamd_worker *worker,
								struct ev_loop *ev_base);


/**
 * Send command to srv pipe and read reply calling the specified callback at the
 * end
 */
void rspamd_srv_send_command (struct rspamd_worker *worker,
							  struct ev_loop *ev_base,
							  struct rspamd_srv_command *cmd,
							  gint attached_fd,
							  rspamd_srv_reply_handler handler,
							  gpointer ud);

/**
 * Broadcast srv cmd from rspamd_main to workers
 * @param rspamd_main
 * @param cmd
 * @param except_pid
 */
void rspamd_control_broadcast_srv_cmd (struct rspamd_main *rspamd_main,
									   struct rspamd_control_command *cmd,
									   pid_t except_pid);

/**
 * Returns command from a specified string (case insensitive)
 * @param str
 * @return
 */
enum rspamd_control_type rspamd_control_command_from_string (const gchar *str);

/**
 * Returns command name from it's type
 * @param cmd
 * @return
 */
const gchar *rspamd_control_command_to_string (enum rspamd_control_type cmd);

/**
 * Used to cleanup pending events
 * @param p
 */
void rspamd_pending_control_free (gpointer p);

#ifdef  __cplusplus
}
#endif

#endif
