/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "rspamd.h"
#include "libutil/map.h"
#include "fuzzy_storage.h"
#include "lua/lua_common.h"
#include "libserver/worker_util.h"
#include "ottery.h"
#include "xxhash.h"
#include "utlist.h"
#include "unix-std.h"
/* sysexits */
#ifdef HAVE_SYSEXITS_H
#include <sysexits.h>
#endif
/* pwd and grp */
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#include <signal.h>
#ifdef HAVE_SIGINFO_H
#include <siginfo.h>
#endif
/* sys/resource.h */
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif
#ifdef WITH_GPERF_TOOLS
#include <google/profiler.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_STROPS_H
#include <stropts.h>
#endif

#ifdef HAVE_OPENSSL
#include <openssl/err.h>
#include <openssl/evp.h>
#endif

#define msg_err_main(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        rspamd_main->server_pool->tag.tagname, rspamd_main->server_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_main(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        rspamd_main->server_pool->tag.tagname, rspamd_main->server_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_main(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        rspamd_main->server_pool->tag.tagname, rspamd_main->server_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_main(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
        rspamd_main->server_pool->tag.tagname, rspamd_main->server_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

/* 2 seconds to fork new process in place of dead one */
#define SOFT_FORK_TIME 2

/* 10 seconds after getting termination signal to terminate all workers with SIGKILL */
#define TERMINATION_ATTEMPTS 40

static struct rspamd_worker * fork_worker (struct rspamd_main *,
	struct rspamd_worker_conf *, guint);
static gboolean load_rspamd_config (struct rspamd_config *cfg,
	gboolean init_modules);

/* Control socket */
static gint control_fd;

/* Cmdline options */
static gboolean config_test = FALSE;
static gboolean no_fork = FALSE;
static gchar **cfg_names = NULL;
static gchar **lua_tests = NULL;
static gchar **sign_configs = NULL;
static gchar *privkey = NULL;
static gchar *rspamd_user = NULL;
static gchar *rspamd_group = NULL;
static gchar *rspamd_pidfile = NULL;
static gboolean dump_cache = FALSE;
static gboolean is_debug = FALSE;
static gboolean is_insecure = FALSE;
static gboolean gen_keypair = FALSE;
static gboolean encrypt_password = FALSE;
static GHashTable *ucl_vars = NULL;

static guint term_attempts = 0;

/* List of unrelated forked processes */
static GArray *other_workers = NULL;

/* List of active listen sockets indexed by worker type */
static GHashTable *listen_sockets = NULL;

struct rspamd_main *rspamd_main;

/* Defined in modules.c */
extern module_t *modules[];
extern worker_t *workers[];

/* Commandline options */
static GOptionEntry entries[] =
{
	{ "config-test", 't', 0, G_OPTION_ARG_NONE, &config_test,
	  "Do config test and exit", NULL },
	{ "no-fork", 'f', 0, G_OPTION_ARG_NONE, &no_fork,
	  "Do not daemonize main process", NULL },
	{ "config", 'c', 0, G_OPTION_ARG_FILENAME_ARRAY, &cfg_names,
	  "Specify config file(s)", NULL },
	{ "user", 'u', 0, G_OPTION_ARG_STRING, &rspamd_user,
	  "User to run rspamd as", NULL },
	{ "group", 'g', 0, G_OPTION_ARG_STRING, &rspamd_group,
	  "Group to run rspamd as", NULL },
	{ "pid", 'p', 0, G_OPTION_ARG_STRING, &rspamd_pidfile, "Path to pidfile",
	  NULL },
	{ "dump-cache", 'C', 0, G_OPTION_ARG_NONE, &dump_cache,
	  "Dump symbols cache stats and exit", NULL },
	{ "debug", 'd', 0, G_OPTION_ARG_NONE, &is_debug, "Force debug output",
	  NULL },
	{ "insecure", 'i', 0, G_OPTION_ARG_NONE, &is_insecure,
	  "Ignore running workers as privileged users (insecure)", NULL },
	{ "test-lua", 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &lua_tests,
	  "Specify lua file(s) to test", NULL },
	{ "sign-config", 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &sign_configs,
	  "Specify config file(s) to sign", NULL },
	{ "private-key", 0, 0, G_OPTION_ARG_FILENAME, &privkey,
	  "Specify private key to sign", NULL },
	{ "gen-keypair", 0, 0, G_OPTION_ARG_NONE, &gen_keypair, "Generate new encryption "
			"keypair", NULL},
	{ "encrypt-password", 0, 0, G_OPTION_ARG_NONE, &encrypt_password, "Encrypt "
			"controller password to store in the configuration file", NULL },
	{ NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
};


static void
read_cmd_line (gint *argc, gchar ***argv, struct rspamd_config *cfg)
{
	GError *error = NULL;
	GOptionContext *context;
	guint i, cfg_num;
	pid_t r;

	context = g_option_context_new ("- run rspamd daemon");
	g_option_context_set_summary (context,
		"Summary:\n  Rspamd daemon version " RVERSION "\n  Release id: " RID);
	g_option_context_add_main_entries (context, entries, NULL);

	if (!g_option_context_parse (context, argc, argv, &error)) {
		fprintf (stderr, "option parsing failed: %s\n", error->message);
		exit (1);
	}

	cfg->no_fork = no_fork;
	cfg->config_test = config_test;
	cfg->rspamd_user = rspamd_user;
	cfg->rspamd_group = rspamd_group;
	cfg_num = cfg_names != NULL ? g_strv_length (cfg_names) : 0;
	if (cfg_num == 0) {
		cfg->cfg_name = FIXED_CONFIG_FILE;
	}
	else {
		cfg->cfg_name = cfg_names[0];
	}
	for (i = 1; i < cfg_num; i++) {
		r = fork ();
		if (r == 0) {
			/* Spawning new main process */
			ottery_init (NULL);
			cfg->cfg_name = cfg_names[i];
			(void)setsid ();
		}
		else if (r == -1) {
			fprintf (stderr,
				"fork failed while spawning process for %s configuration file: %s\n",
				cfg_names[i],
				strerror (errno));
		}
		else {
			/* Save pid to the list of other main processes, we need it to ignore SIGCHLD from them */
			g_array_append_val (other_workers, r);
		}
	}
	cfg->pid_file = rspamd_pidfile;
}

/* Detect privilleged mode */
static void
detect_priv (struct rspamd_main *rspamd)
{
	struct passwd *pwd;
	struct group *grp;
	uid_t euid;

	euid = geteuid ();

	if (euid == 0) {
		if (!rspamd->cfg->rspamd_user && !is_insecure) {
			msg_err_main (
				"cannot run rspamd workers as root user, please add -u and -g options to select a proper unprivilleged user or specify --insecure flag");
			exit (EXIT_FAILURE);
		}
		else if (is_insecure) {
			rspamd->is_privilleged = TRUE;
			rspamd->workers_uid = 0;
			rspamd->workers_gid = 0;
		}
		else {
			rspamd->is_privilleged = TRUE;
			pwd = getpwnam (rspamd->cfg->rspamd_user);
			if (pwd == NULL) {
				msg_err_main ("user specified does not exists (%s), aborting",
					strerror (errno));
				exit (-errno);
			}
			if (rspamd->cfg->rspamd_group) {
				grp = getgrnam (rspamd->cfg->rspamd_group);
				if (grp == NULL) {
					msg_err_main ("group specified does not exists (%s), aborting",
						strerror (errno));
					exit (-errno);
				}
				rspamd->workers_gid = grp->gr_gid;
			}
			else {
				rspamd->workers_gid = (gid_t)-1;
			}
			rspamd->workers_uid = pwd->pw_uid;
		}
	}
	else {
		rspamd->is_privilleged = FALSE;
		rspamd->workers_uid = (uid_t)-1;
		rspamd->workers_gid = (gid_t)-1;
	}
}

static void
drop_priv (struct rspamd_main *rspamd)
{
	if (rspamd->is_privilleged) {
		if (setgid (rspamd->workers_gid) == -1) {
			msg_err_main ("cannot setgid to %d (%s), aborting",
				(gint)rspamd->workers_gid,
				strerror (errno));
			exit (-errno);
		}
		if (rspamd->cfg->rspamd_user &&
			initgroups (rspamd->cfg->rspamd_user, rspamd->workers_gid) == -1) {
			msg_err_main ("initgroups failed (%s), aborting", strerror (errno));
			exit (-errno);
		}
		if (setuid (rspamd->workers_uid) == -1) {
			msg_err_main ("cannot setuid to %d (%s), aborting",
				(gint)rspamd->workers_uid,
				strerror (errno));
			exit (-errno);
		}
	}
}

static void
config_logger (rspamd_mempool_t *pool, gpointer ud)
{
	struct rspamd_main *rm = ud;

	if (config_test) {
		/* Explicitly set logger type to console in case of config testing */
		rm->cfg->log_type = RSPAMD_LOG_CONSOLE;
	}

	rspamd_set_logger (rm->cfg, g_quark_try_string ("main"), rm);
	if (rspamd_log_open_priv (rm->logger, rm->workers_uid, rm->workers_gid) == -1) {
		fprintf (stderr, "Fatal error, cannot open logfile, exiting\n");
		exit (EXIT_FAILURE);
	}
}

static void
reread_config (struct rspamd_main *rspamd)
{
	struct rspamd_config *tmp_cfg;
	gchar *cfg_file;

	tmp_cfg = (struct rspamd_config *)g_malloc0 (sizeof (struct rspamd_config));
	tmp_cfg->c_modules = g_hash_table_ref (rspamd->cfg->c_modules);
	rspamd_set_logger (tmp_cfg,  g_quark_try_string ("main"), rspamd);
	rspamd_init_cfg (tmp_cfg, TRUE);
	cfg_file = rspamd_mempool_strdup (tmp_cfg->cfg_pool,
			rspamd->cfg->cfg_name);
	tmp_cfg->cache = rspamd_symbols_cache_new (tmp_cfg);
	/* Save some variables */
	tmp_cfg->cfg_name = cfg_file;

	if (!load_rspamd_config (tmp_cfg, FALSE)) {
		rspamd_set_logger (rspamd_main->cfg, g_quark_try_string (
				"main"), rspamd_main);
		msg_err_main ("cannot parse new config file, revert to old one");
		rspamd_config_free (tmp_cfg);
	}
	else {
		msg_debug_main ("replacing config");
		rspamd_symbols_cache_destroy (rspamd_main->cfg->cache);
		rspamd_config_free (rspamd->cfg);
		g_free (rspamd->cfg);

		rspamd->cfg = tmp_cfg;
		rspamd_set_logger (tmp_cfg,  g_quark_try_string ("main"), rspamd);
		/* Force debug log */
		if (is_debug) {
			rspamd->cfg->log_level = G_LOG_LEVEL_DEBUG;
		}

		rspamd_init_filters (rspamd->cfg, TRUE);
		rspamd_symbols_cache_init (rspamd->cfg->cache);
		msg_info_main ("config has been reread successfully");
	}
}

static void
set_worker_limits (struct rspamd_worker_conf *cf)
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

static struct rspamd_worker *
fork_worker (struct rspamd_main *rspamd, struct rspamd_worker_conf *cf,
		guint index)
{
	struct rspamd_worker *cur;
	/* Starting worker process */
	cur = (struct rspamd_worker *)g_malloc0 (sizeof (struct rspamd_worker));

	if (!rspamd_socketpair (cur->control_pipe)) {
		msg_err ("socketpair failure: %s", strerror (errno));
		exit (-errno);
	}

	cur->srv = rspamd;
	cur->type = cf->type;
	cur->cf = g_malloc (sizeof (struct rspamd_worker_conf));
	memcpy (cur->cf, cf, sizeof (struct rspamd_worker_conf));
	cur->index = index;
	cur->ctx = cf->ctx;

	cur->pid = fork ();

	switch (cur->pid) {
	case 0:
		/* Update pid for logging */
		rspamd_log_update_pid (cf->type, rspamd->logger);
		/* Lock statfile pool if possible XXX */
		/* Init PRNG after fork */
		ottery_init (NULL);
		g_random_set_seed (ottery_rand_uint32 ());
		/* Drop privilleges */
		drop_priv (rspamd);
		/* Set limits */
		set_worker_limits (cf);
		setproctitle ("%s process", cf->worker->name);
		rspamd_pidfile_close (rspamd->pfh);
		/* Do silent log reopen to avoid collisions */
		rspamd_log_close (rspamd->logger);
		rspamd_log_open (rspamd->logger);
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
		close (cur->control_pipe[0]);
		/* Set non-blocking on the worker part of socketpair */
		rspamd_socket_nonblocking (cur->control_pipe[1]);
		/* Execute worker */
		cf->worker->worker_start_func (cur);
		break;
	case -1:
		msg_err_main ("cannot fork main process. %s", strerror (errno));
		rspamd_pidfile_remove (rspamd->pfh);
		exit (-errno);
		break;
	default:
		/* Close worker part of socketpair */
		close (cur->control_pipe[1]);
		/* Set blocking on the main part of socketpair */
		rspamd_socket_nonblocking (cur->control_pipe[0]);
		/* Insert worker into worker's table, pid is index */
		g_hash_table_insert (rspamd->workers, GSIZE_TO_POINTER (
				cur->pid), cur);
		break;
	}

	return cur;
}

struct waiting_worker {
	struct event_base *ev_base;
	struct event wait_ev;
	struct rspamd_worker_conf *cf;
	guint oldindex;
};

static void
rspamd_fork_delayed_cb (gint signo, short what, gpointer arg)
{
	struct waiting_worker *w = arg;

	event_del (&w->wait_ev);
	fork_worker (rspamd_main, w->cf, w->oldindex);
	g_slice_free1 (sizeof (*w), w);
}

static void
rspamd_fork_delayed (struct rspamd_worker_conf *cf,
		guint index,
		struct event_base *ev_base)
{
	struct waiting_worker *nw;
	struct timeval tv;

	nw = g_slice_alloc (sizeof (*nw));
	nw->cf = cf;
	nw->oldindex = index;
	nw->ev_base = ev_base;
	tv.tv_sec = SOFT_FORK_TIME;
	tv.tv_usec = 0;
	event_set (&nw->wait_ev, -1, EV_TIMEOUT, rspamd_fork_delayed_cb, nw);
	event_base_set (ev_base, &nw->wait_ev);
	event_add (&nw->wait_ev, &tv);
}

static GList *
create_listen_socket (GPtrArray *addrs, guint cnt, gint listen_type)
{
	GList *result = NULL;
	gint fd;
	guint i;

	g_ptr_array_sort (addrs, rspamd_inet_address_compare_ptr);
	for (i = 0; i < cnt; i ++) {
		fd = rspamd_inet_address_listen (g_ptr_array_index (addrs, i),
				listen_type, TRUE);
		if (fd != -1) {
			result = g_list_prepend (result, GINT_TO_POINTER (fd));
		}
	}

	return result;
}

static GList *
systemd_get_socket (gint number)
{
	int sock, num_passed, flags;
	GList *result = NULL;
	const gchar *e;
	gchar *err;
	struct stat st;
	/* XXX: can we trust the current choice ? */
	static const int sd_listen_fds_start = 3;

	e = getenv ("LISTEN_FDS");
	if (e != NULL) {
		errno = 0;
		num_passed = strtoul (e, &err, 10);
		if ((err == NULL || *err == '\0') && num_passed > number) {
			sock = number + sd_listen_fds_start;
			if (fstat (sock, &st) == -1) {
				msg_warn_main ("cannot stat systemd descriptor %d", sock);
				return NULL;
			}
			if (!S_ISSOCK (st.st_mode)) {
				msg_warn_main ("systemd descriptor %d is not a socket", sock);
				errno = EINVAL;
				return NULL;
			}
			flags = fcntl (sock, F_GETFD);
			if (flags != -1) {
				(void)fcntl (sock, F_SETFD, flags | FD_CLOEXEC);
			}
			result = g_list_prepend (result, GINT_TO_POINTER (sock));
		}
		else if (num_passed <= number) {
			msg_warn_main ("systemd LISTEN_FDS does not contain the expected fd: %d",
					num_passed);
			errno = EOVERFLOW;
		}
	}
	else {
		msg_warn_main ("cannot get systemd variable 'LISTEN_FDS'");
		errno = ENOENT;
	}

	return result;
}

static inline uintptr_t
make_listen_key (struct rspamd_worker_bind_conf *cf)
{
	XXH64_state_t st;
	guint i, keylen;
	guint8 *key;
	rspamd_inet_addr_t *addr;
	guint16 port;

	XXH64_reset (&st, rspamd_hash_seed ());
	if (cf->is_systemd) {
		XXH64_update (&st, "systemd", sizeof ("systemd"));
		XXH64_update (&st, &cf->cnt, sizeof (cf->cnt));
	}
	else {
		XXH64_update (&st, cf->name, strlen (cf->name));
		for (i = 0; i < cf->cnt; i ++) {
			addr = g_ptr_array_index (cf->addrs, i);
			key = rspamd_inet_address_get_radix_key (
					addr, &keylen);
			XXH64_update (&st, key, keylen);
			port = rspamd_inet_address_get_port (addr);
			XXH64_update (&st, &port, sizeof (port));
		}
	}

	return XXH64_digest (&st);
}

static void
spawn_workers (struct rspamd_main *rspamd)
{
	GList *cur, *ls;
	struct rspamd_worker_conf *cf;
	gint i;
	gpointer p;
	guintptr key;
	struct rspamd_worker_bind_conf *bcf;
	gboolean listen_ok = FALSE;

	cur = rspamd->cfg->workers;

	while (cur) {
		cf = cur->data;
		listen_ok = FALSE;

		if (cf->worker == NULL) {
			msg_err_main ("type of worker is unspecified, skip spawning");
		}
		else {
			if (cf->worker->has_socket) {
				LL_FOREACH (cf->bind_conf, bcf) {
					key = make_listen_key (bcf);
					if ((p =
						g_hash_table_lookup (listen_sockets,
						GINT_TO_POINTER (key))) == NULL) {
						if (!bcf->is_systemd) {
							/* Create listen socket */
							ls = create_listen_socket (bcf->addrs, bcf->cnt,
									cf->worker->listen_type);
						}
						else {
							ls = systemd_get_socket (bcf->cnt);
						}
						if (ls == NULL) {
							msg_err_main ("cannot listen on socket %s: %s",
								bcf->name,
								strerror (errno));
						}
						else {
							g_hash_table_insert (listen_sockets, (gpointer)key, ls);
							listen_ok = TRUE;
						}
					}
					else {
						/* We had socket for this type of worker */
						ls = p;
						listen_ok = TRUE;
					}
					/* Do not add existing lists as it causes loops */
					if (g_list_position (cf->listen_socks, ls) == -1) {
						cf->listen_socks = g_list_concat (cf->listen_socks, ls);
					}
				}
			}

			if (listen_ok) {
				if (cf->worker->unique) {
					if (cf->count > 1) {
						msg_warn_main ("cannot spawn more than 1 %s worker, so spawn one",
								cf->worker->name);
					}
					fork_worker (rspamd, cf, 0);
				}
				else if (cf->worker->threaded) {
					fork_worker (rspamd, cf, 0);
				}
				else {
					for (i = 0; i < cf->count; i++) {
						fork_worker (rspamd, cf, i);
					}
				}
			}
			else {
				msg_err_main ("cannot create listen socket for %s at %s",
						g_quark_to_string (cf->type), cf->bind_conf->name);

				exit (EXIT_FAILURE);
			}
		}

		cur = g_list_next (cur);
	}
}

static void
kill_old_workers (gpointer key, gpointer value, gpointer unused)
{
	struct rspamd_worker *w = value;

	kill (w->pid, SIGUSR2);
	msg_info_main ("send signal to worker %P", w->pid);
}

static gboolean
wait_for_workers (gpointer key, gpointer value, gpointer unused)
{
	struct rspamd_worker *w = value;
	gint res = 0;

	if (waitpid (w->pid, &res, WNOHANG) <= 0) {
		if (term_attempts == 0) {
			if (w->cf->worker->killable) {
				msg_info_main ("terminate worker %P with SIGKILL", w->pid);
				kill (w->pid, SIGKILL);
			}
			else {
				msg_info_main ("waiting for workers to sync");
				return FALSE;
			}
		}

		return FALSE;
	}

	msg_info_main ("%s process %P terminated %s", g_quark_to_string (
			w->type), w->pid,
			WTERMSIG (res) == SIGKILL ? "hardly" : "softly");
	g_free (w->cf);
	g_free (w);

	return TRUE;
}

static void
reopen_log_handler (gpointer key, gpointer value, gpointer unused)
{
	struct rspamd_worker *w = value;

	if (kill (w->pid, SIGUSR1) == -1) {
		msg_err_main ("kill failed for pid %P: %s", w->pid, strerror (errno));
	}
}

static gboolean
load_rspamd_config (struct rspamd_config *cfg, gboolean init_modules)
{
	cfg->cache = rspamd_symbols_cache_new (cfg);
	cfg->compiled_modules = modules;
	cfg->compiled_workers = workers;

	if (!rspamd_config_read (cfg, cfg->cfg_name, NULL,
		config_logger, rspamd_main, ucl_vars)) {
		return FALSE;
	}

	/* Strictly set temp dir */
	if (!cfg->temp_dir) {
		msg_warn_main ("tempdir is not set, trying to use $TMPDIR");
		cfg->temp_dir =
			rspamd_mempool_strdup (cfg->cfg_pool, getenv ("TMPDIR"));

		if (!cfg->temp_dir) {
			msg_warn_main ("$TMPDIR is empty too, using /tmp as default");
			cfg->temp_dir = rspamd_mempool_strdup (cfg->cfg_pool, "/tmp");
		}
	}

	/* Do post-load actions */
	rspamd_config_post_load (cfg);

	if (init_modules) {
		rspamd_init_filters (cfg, FALSE);
	}

	return TRUE;
}

static gint
perform_lua_tests (struct rspamd_config *cfg)
{
	rspamd_fprintf (stderr, "use rspamadm lua for this operation\n");
	return EXIT_FAILURE;
}

static gint
perform_configs_sign (void)
{
	rspamd_fprintf (stderr, "use rspamadm sign for this operation\n");
	return EXIT_FAILURE;
}

static void
do_encrypt_password (void)
{
	rspamd_fprintf (stderr, "use rspamadm pw for this operation\n");
}

/* Signal handlers */
static void
rspamd_term_handler (gint signo, short what, gpointer arg)
{
	struct event_base *ev_base = arg;

	msg_info_main ("catch termination signal, waiting for children");
	rspamd_pass_signal (rspamd_main->workers, SIGTERM);

	event_base_loopexit (ev_base, NULL);
}

static void
rspamd_usr1_handler (gint signo, short what, gpointer arg)
{
	rspamd_log_reopen_priv (rspamd_main->logger,
			rspamd_main->workers_uid,
			rspamd_main->workers_gid);
	g_hash_table_foreach (rspamd_main->workers, reopen_log_handler,
			NULL);
}

static void
rspamd_hup_handler (gint signo, short what, gpointer arg)
{
	rspamd_log_reopen_priv (rspamd_main->logger,
			rspamd_main->workers_uid,
			rspamd_main->workers_gid);
	msg_info_main ("rspamd "
			RVERSION
			" is restarting");
	g_hash_table_foreach (rspamd_main->workers, kill_old_workers, NULL);
	rspamd_map_remove_all (rspamd_main->cfg);
	reread_config (rspamd_main);
	spawn_workers (rspamd_main);
}

static void
rspamd_cld_handler (gint signo, short what, gpointer arg)
{
	struct event_base *ev_base = arg;
	guint i;
	gint res = 0;
	struct rspamd_worker *cur;
	pid_t wrk;

	msg_debug_main ("catch SIGCHLD signal, finding terminated worker");
	/* Remove dead child form children list */
	wrk = waitpid (0, &res, 0);
	if ((cur =
				 g_hash_table_lookup (rspamd_main->workers,
						 GSIZE_TO_POINTER (wrk))) != NULL) {
		/* Unlink dead process from queue and hash table */

		g_hash_table_remove (rspamd_main->workers, GSIZE_TO_POINTER (
				wrk));

		if (WIFEXITED (res) && WEXITSTATUS (res) == 0) {
			/* Normal worker termination, do not fork one more */
			msg_info_main ("%s process %P terminated normally",
					g_quark_to_string (cur->type),
					cur->pid);
		}
		else {
			if (WIFSIGNALED (res)) {
#ifdef WCOREDUMP
				if (WCOREDUMP (res)) {
					msg_warn_main (
							"%s process %P terminated abnormally by signal: %d"
							" and created core file",
							g_quark_to_string (cur->type),
							cur->pid,
							WTERMSIG (res));
				}
				else {
					msg_warn_main (
							"%s process %P terminated abnormally by signal: %d"
							" but NOT created core file",
							g_quark_to_string (cur->type),
							cur->pid,
							WTERMSIG (res));
				}
#else
				msg_warn_main (
						"%s process %P terminated abnormally by signal: %d",
						g_quark_to_string (cur->type),
						cur->pid,
						WTERMSIG (res));
#endif
			}
			else {
				msg_warn_main ("%s process %P terminated abnormally "
						"with exit code %d",
						g_quark_to_string (cur->type),
						cur->pid,
						WEXITSTATUS (res));
			}
			/* Fork another worker in replace of dead one */
			rspamd_fork_delayed (cur->cf, cur->index, ev_base);
		}

		g_free (cur);
	}
	else {
		for (i = 0; i < other_workers->len; i++) {
			if (g_array_index (other_workers, pid_t, i) == wrk) {
				g_array_remove_index_fast (other_workers, i);
				msg_info_main ("related process %P terminated", wrk);
			}
		}
	}
}

static void
rspamd_final_term_handler (gint signo, short what, gpointer arg)
{
	struct event_base *ev_base = arg;

	term_attempts --;

	g_hash_table_foreach_remove (rspamd_main->workers, wait_for_workers, NULL);

	if (g_hash_table_size (rspamd_main->workers) == 0) {
		event_base_loopexit (ev_base, NULL);
	}
}

gint
main (gint argc, gchar **argv, gchar **env)
{
	gint i, res = 0;
	struct sigaction signals, sigpipe_act;
	worker_t **pworker;
	GQuark type;
	rspamd_inet_addr_t *control_addr = NULL;
	struct event_base *ev_base;
	struct event term_ev, int_ev, cld_ev, hup_ev, usr1_ev, control_ev;
	struct timeval term_tv;

#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
	g_thread_init (NULL);
#endif
	rspamd_main = (struct rspamd_main *) g_malloc0 (sizeof (struct rspamd_main));

	rspamd_main->server_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
			"main");
	rspamd_main->stat = rspamd_mempool_alloc0_shared (rspamd_main->server_pool,
			sizeof (struct rspamd_stat));
	/* Create rolling history */
	rspamd_main->history = rspamd_roll_history_new (rspamd_main->server_pool);
	rspamd_main->cfg =
			(struct rspamd_config *) g_malloc0 (sizeof (struct rspamd_config));

#ifndef HAVE_SETPROCTITLE
	init_title (argc, argv, env);
#endif

	rspamd_init_libs ();
	rspamd_init_cfg (rspamd_main->cfg, TRUE);

	memset (&signals, 0, sizeof (struct sigaction));

	other_workers = g_array_new (FALSE, TRUE, sizeof (pid_t));

	read_cmd_line (&argc, &argv, rspamd_main->cfg);

	if (argc > 0) {
		/* Parse variables */
		for (i = 0; i < argc; i++) {
			if (strchr (argv[i], '=') != NULL) {
				gchar *k, *v, *t;

				k = g_strdup (argv[i]);
				t = strchr (k, '=');
				v = g_strdup (t + 1);
				*t = '\0';

				if (ucl_vars == NULL) {
					ucl_vars = g_hash_table_new_full (rspamd_strcase_hash,
							rspamd_strcase_equal, g_free, g_free);
				}

				g_hash_table_insert (ucl_vars, k, v);
			}
		}
	}

	if (rspamd_main->cfg->config_test || is_debug) {
		rspamd_main->cfg->log_level = G_LOG_LEVEL_DEBUG;
	}
	else {
		rspamd_main->cfg->log_level = G_LOG_LEVEL_WARNING;
	}

	type = g_quark_from_static_string ("main");

	/* First set logger to console logger */
	rspamd_main->cfg->log_type = RSPAMD_LOG_CONSOLE;
	rspamd_set_logger (rspamd_main->cfg, type, rspamd_main);
	(void) rspamd_log_open (rspamd_main->logger);
	g_log_set_default_handler (rspamd_glib_log_function, rspamd_main->logger);
	g_set_printerr_handler (rspamd_glib_printerr_function);

	detect_priv (rspamd_main);

	pworker = &workers[0];
	while (*pworker) {
		/* Init string quarks */
		(void) g_quark_from_static_string ((*pworker)->name);
		pworker++;
	}

	/* Init listen sockets hash */
	listen_sockets = g_hash_table_new (g_direct_hash, g_direct_equal);

	/* If we want to test lua skip everything except it */
	if (lua_tests != NULL && lua_tests[0] != NULL) {
		exit (perform_lua_tests (rspamd_main->cfg));
	}

	/* If we want to sign configs, just do it */
	if (sign_configs != NULL && privkey != NULL) {
		exit (perform_configs_sign ());
	}

	/* Same for keypair creation */
	if (gen_keypair) {
		rspamd_fprintf (stderr, "use rspamadm keypair for this operation\n");
		exit (EXIT_FAILURE);
	}

	if (encrypt_password) {
		do_encrypt_password ();
		exit (EXIT_SUCCESS);
	}

	if (rspamd_main->cfg->config_test || dump_cache) {
		rspamd_fprintf (stderr, "use rspamadm configtest for this operation\n");
		exit (EXIT_FAILURE);
	}

	/* Load config */
	if (!load_rspamd_config (rspamd_main->cfg, TRUE)) {
		exit (EXIT_FAILURE);
	}

	/* Override pidfile from configuration by command line argument */
	if (rspamd_pidfile != NULL) {
		rspamd_main->cfg->pid_file = rspamd_pidfile;
	}

	/* Force debug log */
	if (is_debug) {
		rspamd_main->cfg->log_level = G_LOG_LEVEL_DEBUG;
	}

	gperf_profiler_init (rspamd_main->cfg, "main");

	msg_info_main ("rspamd "
			RVERSION
			" is starting, build id: "
			RID);
	rspamd_main->cfg->cfg_name = rspamd_mempool_strdup (
			rspamd_main->cfg->cfg_pool,
			rspamd_main->cfg->cfg_name);

	/* Daemonize */
	if (!rspamd_main->cfg->no_fork && daemon (0, 0) == -1) {
		fprintf (stderr, "Cannot daemonize\n");
		exit (-errno);
	}

	/* Write info */
	rspamd_main->pid = getpid ();
	rspamd_main->type = type;

	/* Ignore SIGPIPE as we handle write errors manually */
	sigemptyset (&sigpipe_act.sa_mask);
	sigaddset (&sigpipe_act.sa_mask, SIGPIPE);
	sigpipe_act.sa_handler = SIG_IGN;
	sigpipe_act.sa_flags = 0;
	sigaction (SIGPIPE, &sigpipe_act, NULL);

	if (rspamd_main->cfg->pid_file == NULL) {
		msg_info("pid file is not specified, skipping writing it");
	}
	else if (rspamd_write_pid (rspamd_main) == -1) {
		msg_err_main ("cannot write pid file %s", rspamd_main->cfg->pid_file);
		exit (-errno);
	}

	/* Block signals to use sigsuspend in future */
	sigprocmask (SIG_BLOCK, &signals.sa_mask, NULL);

	/* Set title */
	setproctitle ("main process");

	/* Init config cache */
	rspamd_symbols_cache_init (rspamd_main->cfg->cache);

	/* Validate cache */
	(void) rspamd_symbols_cache_validate (rspamd_main->cfg->cache,
			rspamd_main->cfg,
			FALSE);

	/* Flush log */
	rspamd_log_flush (rspamd_main->logger);

	/* Open control socket if needed */
	control_fd = -1;
	if (rspamd_main->cfg->control_socket_path) {
		if (!rspamd_parse_inet_address (&control_addr,
				rspamd_main->cfg->control_socket_path)) {
			msg_err_main ("cannot parse inet address %s",
					rspamd_main->cfg->control_socket_path);
		}
		else {
			control_fd = rspamd_inet_address_listen (control_addr, SOCK_STREAM,
					FALSE);
			if (control_fd == -1) {
				msg_err_main ("cannot open control socket at path: %s",
						rspamd_main->cfg->control_socket_path);
			}
			else {
				/* Generate SIGIO on reads from this socket */
				if (fcntl (control_fd, F_SETOWN, getpid ()) == -1) {
					msg_err_main ("fnctl to set F_SETOWN failed: %s",
							strerror (errno));
				}
#ifdef HAVE_SETSIG
				if (ioctl (control_fd, I_SETSIG, S_INPUT) == -1) {
					msg_err_main ("ioctl I_SETSIG to set S_INPUT failed: %s",
							strerror (errno));
				}
#elif defined(HAVE_OASYNC)
				gint flags = fcntl (control_fd, F_GETFL);

				if (flags == -1 || fcntl (control_fd, F_SETFL,
						flags | O_ASYNC | O_NONBLOCK) == -1) {
					msg_err_main ("fnctl F_SETFL to set O_ASYNC failed: %s",
							strerror (errno));
				}
#else
				msg_err_main ("cannot get notifications about the control socket");
#endif
			}
		}
	}

	if (control_fd != -1) {
		msg_info_main ("listening for control commands on %s",
				rspamd_inet_address_to_string (control_addr));
	}

	/* Maybe read roll history */
	if (rspamd_main->cfg->history_file) {
		rspamd_roll_history_load (rspamd_main->history,
			rspamd_main->cfg->history_file);
	}

#if defined(WITH_GPERF_TOOLS)
	ProfilerStop ();
#endif
	/* Spawn workers */
	rspamd_main->workers = g_hash_table_new (g_direct_hash, g_direct_equal);
	spawn_workers (rspamd_main);

	/* Init event base */
	ev_base = event_init ();
	/* Unblock signals */
	sigemptyset (&signals.sa_mask);
	sigprocmask (SIG_SETMASK, &signals.sa_mask, NULL);

	/* Set events for signals */
	evsignal_set (&term_ev, SIGTERM, rspamd_term_handler, ev_base);
	event_base_set (ev_base, &term_ev);
	event_add (&term_ev, NULL);
	evsignal_set (&int_ev, SIGINT, rspamd_term_handler, ev_base);
	event_base_set (ev_base, &int_ev);
	event_add (&int_ev, NULL);
	evsignal_set (&hup_ev, SIGHUP, rspamd_hup_handler, ev_base);
	event_base_set (ev_base, &hup_ev);
	event_add (&hup_ev, NULL);
	evsignal_set (&cld_ev, SIGCHLD, rspamd_cld_handler, ev_base);
	event_base_set (ev_base, &cld_ev);
	event_add (&cld_ev, NULL);
	evsignal_set (&usr1_ev, SIGUSR1, rspamd_usr1_handler, ev_base);
	event_base_set (ev_base, &usr1_ev);
	event_add (&usr1_ev, NULL);

	event_base_loop (ev_base, 0);

	if (getenv ("G_SLICE") != NULL) {
		/* Special case if we are likely running with valgrind */
		term_attempts = TERMINATION_ATTEMPTS * 10;
	}
	else {
		term_attempts = TERMINATION_ATTEMPTS;
	}

	/* Check each 200 ms */
	term_tv.tv_sec = 0;
	term_tv.tv_usec = 200;

	/* Wait for workers termination */
	g_hash_table_foreach_remove (rspamd_main->workers, wait_for_workers, NULL);

	event_del (&term_ev);
	event_set (&term_ev, -1, EV_TIMEOUT|EV_PERSIST,
			rspamd_final_term_handler, ev_base);
	event_base_set (ev_base, &term_ev);
	event_add (&term_ev, &term_tv);

	event_base_loop (ev_base, 0);

	/* Maybe save roll history */
	if (rspamd_main->cfg->history_file) {
		rspamd_roll_history_save (rspamd_main->history,
			rspamd_main->cfg->history_file);
	}

	msg_info_main ("terminating...");

	if (control_fd != -1) {
		close (control_fd);
	}

	rspamd_symbols_cache_destroy (rspamd_main->cfg->cache);
	rspamd_log_close (rspamd_main->logger);
	rspamd_config_free (rspamd_main->cfg);
	g_free (rspamd_main->cfg);
	g_free (rspamd_main);
	event_base_free (ev_base);
	g_mime_shutdown ();

#ifdef HAVE_OPENSSL
	EVP_cleanup ();
	ERR_free_strings ();
#endif

	return (res);
}
