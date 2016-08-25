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
#include "config.h"
#include "rspamd.h"
#include "message.h"
#include "lua/lua_common.h"
#include "worker_util.h"
#include "unix-std.h"
#include "utlist.h"
#include "ottery.h"
#include "rspamd_control.h"
#include "libutil/map.h"
#include "libutil/map_private.h"
#include "libutil/http_private.h"

#ifdef WITH_GPERF_TOOLS
#include <gperftools/profiler.h>
#endif
/* sys/resource.h */
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
/* pwd and grp */
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif

/**
 * Return worker's control structure by its type
 * @param type
 * @return worker's control structure or NULL
 */
worker_t *
rspamd_get_worker_by_type (struct rspamd_config *cfg, GQuark type)
{
	worker_t **pwrk, *wrk;
	struct rspamd_dynamic_worker *dyn_wrk;
	GList *cur;

	pwrk = cfg->compiled_workers;
	while (pwrk && *pwrk) {
		if (rspamd_check_worker (cfg, *pwrk)) {
			if (g_quark_from_string ((*pwrk)->name) == type) {
				return *pwrk;
			}
		}

		pwrk++;
	}

	cur = g_list_first (cfg->dynamic_workers);
	while (cur) {
		dyn_wrk = cur->data;

		if (dyn_wrk->lib) {
			wrk = &dyn_wrk->wrk;

			if (rspamd_check_worker (cfg, wrk)) {
				if (g_quark_from_string (wrk->name) == type) {
					return wrk;
				}
			}
		}

		cur = g_list_next (cur);
	}

	return NULL;
}

static void
rspamd_worker_terminate_handlers (struct rspamd_worker *w)
{
	guint i;
	void (*cb)(struct rspamd_worker *);

	for (i = 0; i < w->finish_actions->len; i ++) {
		cb = g_ptr_array_index (w->finish_actions, i);
		cb (w);
	}
}
/*
 * Config reload is designed by sending sigusr2 to active workers and pending shutdown of them
 */
static void
rspamd_worker_usr2_handler (struct rspamd_worker_signal_handler *sigh, void *arg)
{
	/* Do not accept new connections, preparing to end worker's process */
	struct timeval tv;

	if (!sigh->worker->wanna_die) {
		tv.tv_sec = SOFT_SHUTDOWN_TIME;
		tv.tv_usec = 0;
		sigh->worker->wanna_die = TRUE;
		rspamd_worker_terminate_handlers (sigh->worker);
		rspamd_default_log_function (G_LOG_LEVEL_INFO,
				sigh->worker->srv->server_pool->tag.tagname,
				sigh->worker->srv->server_pool->tag.uid,
				G_STRFUNC,
				"worker's shutdown is pending in %d sec",
				SOFT_SHUTDOWN_TIME);
		event_base_loopexit (sigh->base, &tv);
		rspamd_worker_stop_accept (sigh->worker);
	}
}

/*
 * Reopen log is designed by sending sigusr1 to active workers and pending shutdown of them
 */
static void
rspamd_worker_usr1_handler (struct rspamd_worker_signal_handler *sigh, void *arg)
{
	rspamd_log_reopen (sigh->worker->srv->logger);
}

static void
rspamd_worker_term_handler (struct rspamd_worker_signal_handler *sigh, void *arg)
{
	struct timeval tv;

	if (!sigh->worker->wanna_die) {
		rspamd_default_log_function (G_LOG_LEVEL_INFO,
				sigh->worker->srv->server_pool->tag.tagname,
				sigh->worker->srv->server_pool->tag.uid,
				G_STRFUNC,
				"terminating after receiving signal %s",
				g_strsignal (sigh->signo));
		rspamd_worker_terminate_handlers (sigh->worker);
		sigh->worker->wanna_die = 1;
		tv.tv_sec = 0;
		tv.tv_usec = 0;

		event_base_loopexit (sigh->base, &tv);
#ifdef WITH_GPERF_TOOLS
		ProfilerStop ();
#endif
		rspamd_worker_stop_accept (sigh->worker);
	}
}

static void
rspamd_worker_signal_handler (int fd, short what, void *arg)
{
	struct rspamd_worker_signal_handler *sigh =
			(struct rspamd_worker_signal_handler *) arg;
	struct rspamd_worker_signal_cb *cb;

	cb = sigh->cb;

	/* Call all signal handlers registered */
	while (cb) {
		cb->handler (sigh, cb->handler_data);
		cb = cb->next;
	}
}

static void
rspamd_worker_ignore_signal (int signo)
{
	struct sigaction sig;

	sigemptyset (&sig.sa_mask);
	sigaddset (&sig.sa_mask, signo);
	sig.sa_handler = SIG_IGN;
	sig.sa_flags = 0;
	sigaction (signo, &sig, NULL);
}

void
rspamd_worker_set_signal_handler (int signo, struct rspamd_worker *worker,
		struct event_base *base,
		void (*handler)(struct rspamd_worker_signal_handler *sigh, void *),
		void *handler_data)
{
	struct rspamd_worker_signal_handler *sigh;
	struct rspamd_worker_signal_cb *cb;

	sigh = g_hash_table_lookup (worker->signal_events, GINT_TO_POINTER (signo));

	if (sigh == NULL) {
		sigh = g_malloc0 (sizeof (*sigh));
		sigh->signo = signo;
		sigh->worker = worker;
		sigh->base = base;
		sigh->enabled = TRUE;

		signal_set (&sigh->ev, signo, rspamd_worker_signal_handler, sigh);
		event_base_set (base, &sigh->ev);
		signal_add (&sigh->ev, NULL);

		g_hash_table_insert (worker->signal_events,
				GINT_TO_POINTER (signo),
				sigh);
	}

	cb = g_malloc0 (sizeof (*cb));
	cb->handler = handler;
	cb->handler_data = handler_data;
	DL_APPEND (sigh->cb, cb);
}

static void
rspamd_worker_init_signals (struct rspamd_worker *worker, struct event_base *base)
{
	struct sigaction signals;
	/* We ignore these signals in the worker */
	rspamd_worker_ignore_signal (SIGPIPE);
	rspamd_worker_ignore_signal (SIGALRM);
	rspamd_worker_ignore_signal (SIGCHLD);

	/* A set of terminating signals */
	rspamd_worker_set_signal_handler (SIGTERM, worker, base,
			rspamd_worker_term_handler, NULL);
	rspamd_worker_set_signal_handler (SIGINT, worker, base,
			rspamd_worker_term_handler, NULL);
	rspamd_worker_set_signal_handler (SIGHUP, worker, base,
			rspamd_worker_term_handler, NULL);

	/* Special purpose signals */
	rspamd_worker_set_signal_handler (SIGUSR1, worker, base,
			rspamd_worker_usr1_handler, NULL);
	rspamd_worker_set_signal_handler (SIGUSR2, worker, base,
			rspamd_worker_usr2_handler, NULL);

	/* Unblock all signals processed */
	sigemptyset (&signals.sa_mask);
	sigaddset (&signals.sa_mask, SIGTERM);
	sigaddset (&signals.sa_mask, SIGINT);
	sigaddset (&signals.sa_mask, SIGHUP);
	sigaddset (&signals.sa_mask, SIGCHLD);
	sigaddset (&signals.sa_mask, SIGUSR1);
	sigaddset (&signals.sa_mask, SIGUSR2);
	sigaddset (&signals.sa_mask, SIGALRM);
	sigaddset (&signals.sa_mask, SIGPIPE);

	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);
}

struct event_base *
rspamd_prepare_worker (struct rspamd_worker *worker, const char *name,
	void (*accept_handler)(int, short, void *))
{
	struct event_base *ev_base;
	struct event *accept_events;
	GList *cur;
	struct rspamd_worker_listen_socket *ls;

#ifdef WITH_PROFILER
	extern void _start (void), etext (void);
	monstartup ((u_long) & _start, (u_long) & etext);
#endif

	gperf_profiler_init (worker->srv->cfg, name);

	worker->srv->pid = getpid ();
	worker->signal_events = g_hash_table_new_full (g_direct_hash, g_direct_equal,
			NULL, g_free);

	ev_base = event_init ();

	rspamd_worker_init_signals (worker, ev_base);
	rspamd_control_worker_add_default_handler (worker, ev_base);

	/* Accept all sockets */
	if (accept_handler) {
		cur = worker->cf->listen_socks;

		while (cur) {
			ls = cur->data;

			if (ls->fd != -1) {
				accept_events = g_slice_alloc0 (sizeof (struct event) * 2);
				event_set (&accept_events[0], ls->fd, EV_READ | EV_PERSIST,
						accept_handler, worker);
				event_base_set (ev_base, &accept_events[0]);
				event_add (&accept_events[0], NULL);
				worker->accept_events = g_list_prepend (worker->accept_events,
						accept_events);
			}

			cur = g_list_next (cur);
		}
	}

	return ev_base;
}

void
rspamd_worker_stop_accept (struct rspamd_worker *worker)
{
	GList *cur;
	struct event *events;
	GHashTableIter it;
	struct rspamd_worker_signal_handler *sigh;
	gpointer k, v;
	struct rspamd_map *map;

	/* Remove all events */
	cur = worker->accept_events;
	while (cur) {
		events = cur->data;

		if (event_get_base (&events[0])) {
			event_del (&events[0]);
		}

		if (event_get_base (&events[1])) {
			event_del (&events[1]);
		}

		cur = g_list_next (cur);
		g_slice_free1 (sizeof (struct event) * 2, events);
	}

	if (worker->accept_events != NULL) {
		g_list_free (worker->accept_events);
	}

	g_hash_table_iter_init (&it, worker->signal_events);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		sigh = (struct rspamd_worker_signal_handler *)v;
		g_hash_table_iter_steal (&it);
		if (sigh->enabled) {
			event_del (&sigh->ev);
		}
		g_free (sigh);
	}

	g_hash_table_unref (worker->signal_events);

	/* Cleanup maps */
	for (cur = worker->srv->cfg->maps; cur != NULL; cur = g_list_next (cur)) {
		map = cur->data;

		if (map->dtor) {
			map->dtor (map->dtor_data);
		}
	}
}

void
rspamd_controller_send_error (struct rspamd_http_connection_entry *entry,
	gint code, const gchar *error_msg, ...)
{
	struct rspamd_http_message *msg;
	va_list args;
	rspamd_fstring_t *reply;

	msg = rspamd_http_new_message (HTTP_RESPONSE);

	va_start (args, error_msg);
	msg->status = rspamd_fstring_new ();
	rspamd_vprintf_fstring (&msg->status, error_msg, args);
	va_end (args);

	msg->date = time (NULL);
	msg->code = code;
	reply = rspamd_fstring_sized_new (msg->status->len + 16);
	rspamd_printf_fstring (&reply, "{\"error\":\"%V\"}", msg->status);
	rspamd_http_message_set_body_from_fstring_steal (msg, reply);
	rspamd_http_connection_reset (entry->conn);
	rspamd_http_connection_write_message (entry->conn,
		msg,
		NULL,
		"application/json",
		entry,
		entry->conn->fd,
		entry->rt->ptv,
		entry->rt->ev_base);
	entry->is_reply = TRUE;
}

void
rspamd_controller_send_string (struct rspamd_http_connection_entry *entry,
	const gchar *str)
{
	struct rspamd_http_message *msg;
	rspamd_fstring_t *reply;

	msg = rspamd_http_new_message (HTTP_RESPONSE);
	msg->date = time (NULL);
	msg->code = 200;
	msg->status = rspamd_fstring_new_init ("OK", 2);
	reply = rspamd_fstring_new_init (str, strlen (str));
	rspamd_http_message_set_body_from_fstring_steal (msg, reply);
	rspamd_http_connection_reset (entry->conn);
	rspamd_http_connection_write_message (entry->conn,
		msg,
		NULL,
		"application/json",
		entry,
		entry->conn->fd,
		entry->rt->ptv,
		entry->rt->ev_base);
	entry->is_reply = TRUE;
}

void
rspamd_controller_send_ucl (struct rspamd_http_connection_entry *entry,
	ucl_object_t *obj)
{
	struct rspamd_http_message *msg;
	rspamd_fstring_t *reply;

	msg = rspamd_http_new_message (HTTP_RESPONSE);
	msg->date = time (NULL);
	msg->code = 200;
	msg->status = rspamd_fstring_new_init ("OK", 2);
	reply = rspamd_fstring_sized_new (BUFSIZ);
	rspamd_ucl_emit_fstring (obj, UCL_EMIT_JSON_COMPACT, &reply);
	rspamd_http_message_set_body_from_fstring_steal (msg, reply);
	rspamd_http_connection_reset (entry->conn);
	rspamd_http_connection_write_message (entry->conn,
		msg,
		NULL,
		"application/json",
		entry,
		entry->conn->fd,
		entry->rt->ptv,
		entry->rt->ev_base);
	entry->is_reply = TRUE;
}

static void
rspamd_worker_drop_priv (struct rspamd_main *rspamd_main)
{
	if (rspamd_main->is_privilleged) {
		if (setgid (rspamd_main->workers_gid) == -1) {
			msg_err_main ("cannot setgid to %d (%s), aborting",
					(gint) rspamd_main->workers_gid,
					strerror (errno));
			exit (-errno);
		}
		if (rspamd_main->cfg->rspamd_user &&
				initgroups (rspamd_main->cfg->rspamd_user, rspamd_main->workers_gid) ==
						-1) {
			msg_err_main ("initgroups failed (%s), aborting", strerror (errno));
			exit (-errno);
		}
		if (setuid (rspamd_main->workers_uid) == -1) {
			msg_err_main ("cannot setuid to %d (%s), aborting",
					(gint) rspamd_main->workers_uid,
					strerror (errno));
			exit (-errno);
		}
	}
}

static void
rspamd_worker_set_limits (struct rspamd_main *rspamd_main,
		struct rspamd_worker_conf *cf)
{
	struct rlimit rlmt;

	if (cf->rlimit_nofile != 0) {
		rlmt.rlim_cur = (rlim_t) cf->rlimit_nofile;
		rlmt.rlim_max = (rlim_t) cf->rlimit_nofile;

		if (setrlimit (RLIMIT_NOFILE, &rlmt) == -1) {
			msg_warn_main ("cannot set files rlimit: %d, %s",
					cf->rlimit_nofile,
					strerror (errno));
		}
	}

	if (rspamd_main->cores_throttling) {
		msg_info_main ("disable core files for the new worker, as limits are reached");
		rlmt.rlim_cur = 0;
		rlmt.rlim_max = 0;

		if (setrlimit (RLIMIT_CORE, &rlmt) == -1) {
			msg_warn_main ("cannot disable core: %s",
					strerror (errno));
		}
	}
	else {
		if (cf->rlimit_maxcore != 0) {
			rlmt.rlim_cur = (rlim_t) cf->rlimit_maxcore;
			rlmt.rlim_max = (rlim_t) cf->rlimit_maxcore;

			if (setrlimit (RLIMIT_CORE, &rlmt) == -1) {
				msg_warn_main ("cannot set max core rlimit: %d, %s",
						cf->rlimit_maxcore,
						strerror (errno));
			}
		}
	}
}

struct rspamd_worker *
rspamd_fork_worker (struct rspamd_main *rspamd_main,
		struct rspamd_worker_conf *cf,
		guint index,
		struct event_base *ev_base)
{
	struct rspamd_worker *wrk;
	gint rc;
	struct rlimit rlim;

	/* Starting worker process */
	wrk = (struct rspamd_worker *) g_malloc0 (sizeof (struct rspamd_worker));

	if (!rspamd_socketpair (wrk->control_pipe)) {
		msg_err ("socketpair failure: %s", strerror (errno));
		exit (-errno);
	}

	if (!rspamd_socketpair (wrk->srv_pipe)) {
		msg_err ("socketpair failure: %s", strerror (errno));
		exit (-errno);
	}

	wrk->srv = rspamd_main;
	wrk->type = cf->type;
	wrk->cf = g_malloc (sizeof (struct rspamd_worker_conf));
	memcpy (wrk->cf, cf, sizeof (struct rspamd_worker_conf));
	wrk->index = index;
	wrk->ctx = cf->ctx;
	wrk->finish_actions = g_ptr_array_new ();

	wrk->pid = fork ();

	switch (wrk->pid) {
	case 0:
		/* Update pid for logging */
		rspamd_log_update_pid (cf->type, rspamd_main->logger);
		/* Remove the inherited event base */
		event_reinit (rspamd_main->ev_base);
		event_base_free (rspamd_main->ev_base);
		/* Lock statfile pool if possible XXX */
		/* Init PRNG after fork */
		rc = ottery_init (rspamd_main->cfg->libs_ctx->ottery_cfg);
		rspamd_random_seed_fast ();
		if (rc != OTTERY_ERR_NONE) {
			msg_err_main ("cannot initialize PRNG: %d", rc);
			g_assert (0);
		}

		g_random_set_seed (ottery_rand_uint32 ());
		/* Drop privilleges */
		rspamd_worker_drop_priv (rspamd_main);
		/* Set limits */
		rspamd_worker_set_limits (rspamd_main, cf);
		/* Re-set stack limit */
		getrlimit (RLIMIT_STACK, &rlim);
		rlim.rlim_cur = 100 * 1024 * 1024;
		rlim.rlim_max = rlim.rlim_cur;
		setrlimit (RLIMIT_STACK, &rlim);

		setproctitle ("%s process", cf->worker->name);
		rspamd_pidfile_close (rspamd_main->pfh);
		/* Do silent log reopen to avoid collisions */
		rspamd_log_close (rspamd_main->logger);
		rspamd_log_open (rspamd_main->logger);
		wrk->start_time = rspamd_get_calendar_ticks ();

#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
# if (GLIB_MINOR_VERSION > 20)
		/* Ugly hack for old glib */
		if (!g_thread_get_initialized ()) {
			g_thread_init (NULL);
		}
# else
		g_thread_init (NULL);
# endif
#endif
		msg_info_main ("starting %s process %P", cf->worker->name, getpid ());
		/* Close parent part of socketpair */
		close (wrk->control_pipe[0]);
		close (wrk->srv_pipe[0]);
		rspamd_socket_nonblocking (wrk->control_pipe[1]);
		rspamd_socket_nonblocking (wrk->srv_pipe[1]);
		/* Execute worker */
		cf->worker->worker_start_func (wrk);
		exit (EXIT_FAILURE);
		break;
	case -1:
		msg_err_main ("cannot fork main process. %s", strerror (errno));
		rspamd_pidfile_remove (rspamd_main->pfh);
		exit (-errno);
		break;
	default:
		/* Close worker part of socketpair */
		close (wrk->control_pipe[1]);
		close (wrk->srv_pipe[1]);
		rspamd_socket_nonblocking (wrk->control_pipe[0]);
		rspamd_socket_nonblocking (wrk->srv_pipe[0]);
		rspamd_srv_start_watching (wrk, ev_base);
		/* Insert worker into worker's table, pid is index */
		g_hash_table_insert (rspamd_main->workers, GSIZE_TO_POINTER (
				wrk->pid), wrk);
		break;
	}

	return wrk;
}

void
rspamd_worker_block_signals (void)
{
	sigset_t set;

	sigemptyset (&set);
	sigaddset (&set, SIGTERM);
	sigaddset (&set, SIGINT);
	sigaddset (&set, SIGHUP);
	sigaddset (&set, SIGUSR1);
	sigaddset (&set, SIGUSR2);
	sigprocmask (SIG_BLOCK, &set, NULL);
}
