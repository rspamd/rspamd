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
#include "main.h"
#include "lmtp.h"
#include "smtp.h"
#include "libutil/map.h"
#include "fuzzy_storage.h"
#include "kvstorage_server.h"
#include "libserver/symbols_cache.h"
#include "lua/lua_common.h"
#include "ottery.h"
#include "xxhash.h"
#include "utlist.h"
#include "libstat/stat_api.h"
#include "cryptobox.h"
#include "regexp.h"
#ifdef HAVE_OPENSSL
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#endif
#ifdef HAVE_LOCALE_H
#include <locale.h>
#define HAVE_SETLOCALE 1
#endif

/* 2 seconds to fork new process in place of dead one */
#define SOFT_FORK_TIME 2

/* 10 seconds after getting termination signal to terminate all workers with SIGKILL */
#define HARD_TERMINATION_TIME 10

static struct rspamd_worker * fork_worker (struct rspamd_main *,
	struct rspamd_worker_conf *);
static gboolean load_rspamd_config (struct rspamd_config *cfg,
	gboolean init_modules);
static void init_cfg_cache (struct rspamd_config *cfg);
static void rspamd_init_cfg (struct rspamd_config *cfg);

sig_atomic_t do_restart = 0;
sig_atomic_t do_reopen_log = 0;
sig_atomic_t do_terminate = 0;
sig_atomic_t child_dead = 0;
sig_atomic_t got_alarm = 0;

#ifdef HAVE_SA_SIGINFO
GQueue *signals_info = NULL;
#endif

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
/* List of workers that are pending to start */
static GList *workers_pending = NULL;

#ifdef HAVE_SA_SIGINFO
static siginfo_t static_sg[64];
static sig_atomic_t cur_sg = 0;
#endif

/* List of unrelated forked processes */
static GArray *other_workers = NULL;

/* List of active listen sockets indexed by worker type */
static GHashTable *listen_sockets = NULL;

struct rspamd_main *rspamd_main;

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
	{ NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
};


#ifndef HAVE_SA_SIGINFO
static void
sig_handler (gint signo)
#else
static void
sig_handler (gint signo, siginfo_t *info, void *unused)
#endif
{
#ifdef HAVE_SA_SIGINFO
	if (cur_sg < (sig_atomic_t)G_N_ELEMENTS (static_sg)) {
		memcpy (&static_sg[cur_sg++], info, sizeof (siginfo_t));
	}
	/* XXX: discard more than 64 simultaneous signals */
#endif

	switch (signo) {
	case SIGHUP:
		do_restart = 1;
		break;
	case SIGINT:
	case SIGTERM:
		do_terminate = 1;
		break;
	case SIGCHLD:
		child_dead = 1;
		break;
	case SIGUSR1:
		do_reopen_log = 1;
		break;
	case SIGUSR2:
		/* Do nothing */
		break;
	case SIGALRM:
		got_alarm = 1;
		break;
	}
}

#ifdef HAVE_SA_SIGINFO

static const gchar *
chldsigcode (gint code) {
	switch (code) {
#ifdef CLD_EXITED
	case CLD_EXITED:
		return "Child exited normally";
	case CLD_KILLED:
		return "Child has terminated abnormally but did not create a core file";
	case CLD_DUMPED:
		return "Child has terminated abnormally and created a core file";
	case CLD_TRAPPED:
		return "Traced child has trapped";
#endif
	default:
		return "Unknown reason";
	}
}

/* Prints info about incoming signals by parsing siginfo structures */
static void
print_signals_info (void)
{
	siginfo_t *inf;

	while ((inf = g_queue_pop_head (signals_info))) {
		if (inf->si_signo == SIGCHLD) {
			msg_info ("got SIGCHLD from child: %P; reason: '%s'",
				inf->si_pid, chldsigcode (inf->si_code));
		}
		else {
			msg_info ("got signal: '%s'; received from pid: %P; uid: %ul",
				g_strsignal (inf->si_signo), inf->si_pid, (gulong)inf->si_uid);
		}
	}
}
#endif


static void
read_cmd_line (gint argc, gchar **argv, struct rspamd_config *cfg)
{
	GError *error = NULL;
	GOptionContext *context;
	guint i, cfg_num;
	pid_t r;

	context = g_option_context_new ("- run rspamd daemon");
	g_option_context_set_summary (context,
		"Summary:\n  Rspamd daemon version " RVERSION "\n  Release id: " RID);
	g_option_context_add_main_entries (context, entries, NULL);
	if (!g_option_context_parse (context, &argc, &argv, &error)) {
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
			msg_err (
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
				msg_err ("user specified does not exists (%s), aborting",
					strerror (errno));
				exit (-errno);
			}
			if (rspamd->cfg->rspamd_group) {
				grp = getgrnam (rspamd->cfg->rspamd_group);
				if (grp == NULL) {
					msg_err ("group specified does not exists (%s), aborting",
						strerror (errno));
					exit (-errno);
				}
				rspamd->workers_gid = grp->gr_gid;
			}
			else {
				rspamd->workers_gid = -1;
			}
			rspamd->workers_uid = pwd->pw_uid;
		}
	}
	else {
		rspamd->is_privilleged = FALSE;
		rspamd->workers_uid = -1;
		rspamd->workers_gid = -1;
	}
}

static void
drop_priv (struct rspamd_main *rspamd)
{
	if (rspamd->is_privilleged) {
		if (setgid (rspamd->workers_gid) == -1) {
			msg_err ("cannot setgid to %d (%s), aborting",
				(gint)rspamd->workers_gid,
				strerror (errno));
			exit (-errno);
		}
		if (rspamd->cfg->rspamd_user &&
			initgroups (rspamd->cfg->rspamd_user, rspamd->workers_gid) == -1) {
			msg_err ("initgroups failed (%s), aborting", strerror (errno));
			exit (-errno);
		}
		if (setuid (rspamd->workers_uid) == -1) {
			msg_err ("cannot setuid to %d (%s), aborting",
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
	if (tmp_cfg) {

		rspamd_init_cfg (tmp_cfg);
		cfg_file = rspamd_mempool_strdup (tmp_cfg->cfg_pool,
				rspamd->cfg->cfg_name);
		/* Save some variables */
		tmp_cfg->cfg_name = cfg_file;

		tmp_cfg->c_modules = g_hash_table_ref (rspamd->cfg->c_modules);

		if (!load_rspamd_config (tmp_cfg, FALSE)) {
			rspamd_set_logger (rspamd_main->cfg, g_quark_try_string (
					"main"), rspamd_main);
			msg_err ("cannot parse new config file, revert to old one");
			rspamd_config_free (tmp_cfg);
		}
		else {
			msg_debug ("replacing config");
			rspamd_config_free (rspamd->cfg);
			g_free (rspamd->cfg);

			rspamd->cfg = tmp_cfg;
			/* Force debug log */
			if (is_debug) {
				rspamd->cfg->log_level = G_LOG_LEVEL_DEBUG;
			}

			rspamd_init_filters (rspamd->cfg, TRUE);
			init_cfg_cache (rspamd->cfg);
			msg_info ("config rereaded successfully");
		}
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
			msg_warn ("cannot set files rlimit: %d, %s",
				cf->rlimit_nofile,
				strerror (errno));
		}
	}

	if (cf->rlimit_maxcore != 0) {
		rlmt.rlim_cur = (rlim_t) cf->rlimit_maxcore;
		rlmt.rlim_max = (rlim_t) cf->rlimit_maxcore;

		if (setrlimit (RLIMIT_CORE, &rlmt) == -1) {
			msg_warn ("cannot set max core rlimit: %d, %s",
				cf->rlimit_maxcore,
				strerror (errno));
		}
	}
}

static struct rspamd_worker *
fork_worker (struct rspamd_main *rspamd, struct rspamd_worker_conf *cf)
{
	struct rspamd_worker *cur;
	/* Starting worker process */
	cur = (struct rspamd_worker *)g_malloc (sizeof (struct rspamd_worker));
	if (cur) {
		bzero (cur, sizeof (struct rspamd_worker));
		cur->srv = rspamd;
		cur->type = cf->type;
		cur->pid = fork ();
		cur->cf = g_malloc (sizeof (struct rspamd_worker_conf));
		memcpy (cur->cf, cf, sizeof (struct rspamd_worker_conf));
		cur->pending = FALSE;
		cur->ctx = cf->ctx;
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
			msg_info ("starting %s process %P", cf->worker->name, getpid ());
			cf->worker->worker_start_func (cur);
			break;
		case -1:
			msg_err ("cannot fork main process. %s", strerror (errno));
			rspamd_pidfile_remove (rspamd->pfh);
			exit (-errno);
			break;
		default:
			/* Insert worker into worker's table, pid is index */
			g_hash_table_insert (rspamd->workers, GSIZE_TO_POINTER (
					cur->pid), cur);
			break;
		}
	}

	return cur;
}

static void
set_alarm (guint seconds)
{
#ifdef HAVE_SETITIMER
	static struct itimerval itv;

	itv.it_interval.tv_sec = 0;
	itv.it_interval.tv_usec = 0;
	itv.it_value.tv_sec = seconds;
	itv.it_value.tv_usec = 0;

	if (setitimer (ITIMER_REAL, &itv, NULL) == -1) {
		msg_err ("set alarm failed: %s", strerror (errno));
	}
#else
	(void)alarm (seconds);
#endif
}

static void
delay_fork (struct rspamd_worker_conf *cf)
{
	workers_pending = g_list_prepend (workers_pending, cf);
	set_alarm (SOFT_FORK_TIME);
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
				msg_warn ("cannot stat systemd descriptor %d", sock);
				return NULL;
			}
			if (!S_ISSOCK (st.st_mode)) {
				msg_warn ("systemd descriptor %d is not a socket", sock);
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
			msg_warn ("systemd LISTEN_FDS does not contain the expected fd: %d",
					num_passed);
			errno = EOVERFLOW;
		}
	}
	else {
		msg_warn ("cannot get systemd variable 'LISTEN_FDS'");
		errno = ENOENT;
	}

	return result;
}

static void
fork_delayed (struct rspamd_main *rspamd)
{
	GList *cur;
	struct rspamd_worker_conf *cf;

	while (workers_pending != NULL) {
		cur = workers_pending;
		cf = cur->data;

		workers_pending = g_list_remove_link (workers_pending, cur);
		fork_worker (rspamd, cf);
		g_list_free_1 (cur);
	}
}

static inline uintptr_t
make_listen_key (struct rspamd_worker_bind_conf *cf)
{
	gpointer xxh;
	guint i, keylen;
	guint8 *key;
	rspamd_inet_addr_t *addr;
	guint16 port;

	xxh = XXH32_init (0xdeadbeef);
	if (cf->is_systemd) {
		XXH32_update (xxh, "systemd", sizeof ("systemd"));
		XXH32_update (xxh, &cf->cnt, sizeof (cf->cnt));
	}
	else {
		XXH32_update (xxh, cf->name, strlen (cf->name));
		for (i = 0; i < cf->cnt; i ++) {
			addr = g_ptr_array_index (cf->addrs, i);
			key = rspamd_inet_address_get_radix_key (
					addr, &keylen);
			XXH32_update (xxh, key, keylen);
			port = rspamd_inet_address_get_port (addr);
			XXH32_update (xxh, &port, sizeof (port));
		}
	}

	return XXH32_digest (xxh);
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

	cur = rspamd->cfg->workers;

	while (cur) {
		cf = cur->data;

		if (cf->worker == NULL) {
			msg_err ("type of worker is unspecified, skip spawning");
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
							msg_err ("cannot listen on socket %s: %s",
								bcf->name,
								strerror (errno));
							exit (-errno);
						}
						g_hash_table_insert (listen_sockets, (gpointer)key, ls);
					}
					else {
						/* We had socket for this type of worker */
						ls = p;
					}
					/* Do not add existing lists as it causes loops */
					if (g_list_position (cf->listen_socks, ls) == -1) {
						cf->listen_socks = g_list_concat (cf->listen_socks, ls);
					}
				}
			}

			if (cf->worker->unique) {
				if (cf->count > 1) {
					msg_err ("cannot spawn more than 1 %s worker, so spawn one",
						cf->worker->name);
				}
				fork_worker (rspamd, cf);
			}
			else if (cf->worker->threaded) {
				fork_worker (rspamd, cf);
			}
			else {
				for (i = 0; i < cf->count; i++) {
					fork_worker (rspamd, cf);
				}
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
	msg_info ("send signal to worker %P", w->pid);
}

static gboolean
wait_for_workers (gpointer key, gpointer value, gpointer unused)
{
	struct rspamd_worker *w = value;
	gint res = 0;

	if (got_alarm) {
		got_alarm = 0;
		/* Set alarm for hard termination but with less time */
		set_alarm (HARD_TERMINATION_TIME / 10);
	}

	if (waitpid (w->pid, &res, 0) == -1) {
		if (errno == EINTR) {
			got_alarm = 1;
			if (w->cf->worker->killable) {
				msg_info ("terminate worker %P with SIGKILL", w->pid);
				kill (w->pid, SIGKILL);
			}
			else {
				msg_info ("waiting for workers to sync");
				wait_for_workers (key, value, unused);
				return TRUE;
			}
		}
	}

	msg_info ("%s process %P terminated %s", g_quark_to_string (
			w->type), w->pid,
		got_alarm ? "hardly" : "softly");
	g_free (w->cf);
	g_free (w);

	return TRUE;
}

static void
reopen_log_handler (gpointer key, gpointer value, gpointer unused)
{
	struct rspamd_worker *w = value;

	if (kill (w->pid, SIGUSR1) == -1) {
		msg_err ("kill failed for pid %P: %s", w->pid, strerror (errno));
	}
}

static gboolean
load_rspamd_config (struct rspamd_config *cfg, gboolean init_modules)
{
	if (!rspamd_config_read (cfg, cfg->cfg_name, NULL,
		config_logger, rspamd_main)) {
		return FALSE;
	}

	/* Strictly set temp dir */
	if (!cfg->temp_dir) {
		msg_warn ("tempdir is not set, trying to use $TMPDIR");
		cfg->temp_dir =
			rspamd_mempool_strdup (cfg->cfg_pool, getenv ("TMPDIR"));

		if (!cfg->temp_dir) {
			msg_warn ("$TMPDIR is empty too, using /tmp as default");
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

static void
init_cfg_cache (struct rspamd_config *cfg)
{

	if (!init_symbols_cache (cfg->cfg_pool, cfg->cache, cfg,
		cfg->cache_filename, FALSE)) {
		exit (EXIT_FAILURE);
	}
}

static void
print_symbols_cache (struct rspamd_config *cfg)
{
	GList *cur;
	struct cache_item *item;
	gint i;

	if (!init_symbols_cache (cfg->cfg_pool, cfg->cache, cfg,
		cfg->cache_filename, TRUE)) {
		exit (EXIT_FAILURE);
	}
	if (cfg->cache) {
		printf ("Symbols cache\n");
		printf (
			"-----------------------------------------------------------------\n");
		printf (
			"| Pri  | Symbol                | Weight | Frequency | Avg. time |\n");
		i = 0;
		cur = cfg->cache->negative_items;
		while (cur) {
			item = cur->data;
			if (!item->is_callback) {
				printf (
						"-----------------------------------------------------------------\n");
				printf ("| %3d | %22s | %6.1f | %9d | %9.3f |\n",
					i,
					item->s->symbol,
					item->s->weight,
					item->s->frequency,
					item->s->avg_time);
			}
			cur = g_list_next (cur);
			i++;
		}
		cur = cfg->cache->static_items;
		while (cur) {
			item = cur->data;
			if (!item->is_callback) {
				printf (
						"-----------------------------------------------------------------\n");
				printf ("| %3d | %22s | %6.1f | %9d | %9.3f |\n",
					i,
					item->s->symbol,
					item->s->weight,
					item->s->frequency,
					item->s->avg_time);
			}
			cur = g_list_next (cur);
			i++;
		}

		printf (
			"-----------------------------------------------------------------\n");
	}
}

static gint
perform_lua_tests (struct rspamd_config *cfg)
{
	gint i, tests_num, res = EXIT_SUCCESS;
	gchar *cur_script;
	lua_State *L = cfg->lua_state;

	tests_num = g_strv_length (lua_tests);

	for (i = 0; i < tests_num; i++) {

		if (luaL_loadfile (L, lua_tests[i]) != 0) {
			msg_err ("load of %s failed: %s", lua_tests[i],
				lua_tostring (L, -1));
			res = EXIT_FAILURE;
			continue;
		}

		cur_script = g_strdup (lua_tests[i]);
		lua_pushstring (L, cur_script);
		lua_setglobal (L, "test_script");
		lua_pushstring (L, dirname (cur_script));
		lua_setglobal (L, "test_dir");
		g_free (cur_script);

		/* do the call (0 arguments, N result) */
		if (lua_pcall (L, 0, LUA_MULTRET, 0) != 0) {
			msg_info ("init of %s failed: %s", lua_tests[i], lua_tostring (L,
				-1));
			res = EXIT_FAILURE;
			continue;
		}
		if (lua_gettop (L) != 0) {
			if (lua_tonumber (L, -1) == -1) {
				msg_info ("%s returned -1 that indicates configuration error",
					lua_tests[i]);
				res = EXIT_FAILURE;
				continue;
			}
			lua_pop (L, lua_gettop (L));
		}
	}

	return res;
}

static gint
perform_configs_sign (void)
{
#ifndef HAVE_OPENSSL
	msg_err ("cannot sign files without openssl support");
	return EXIT_FAILURE;
#else
# if (OPENSSL_VERSION_NUMBER < 0x10000000L)
	msg_err ("must have openssl at least 1.0.0 to perform this action");
	return EXIT_FAILURE;
# else
	gint i, tests_num, res = EXIT_SUCCESS, fd;
	guint diglen;
	gchar *cur_file, in_file[PATH_MAX],
		out_file[PATH_MAX], dig[EVP_MAX_MD_SIZE];
	gsize siglen;
	struct stat st;
	gpointer map, sig;
	EVP_PKEY *key = NULL;
	BIO *fbio;
	EVP_PKEY_CTX *key_ctx = NULL;
	EVP_MD_CTX *sign_ctx = NULL;

	/* Load private key */
	fbio = BIO_new_file (privkey, "r");
	if (fbio == NULL) {
		msg_err ("cannot open private key %s, %s", privkey,
			ERR_error_string (ERR_get_error (), NULL));
		return ERR_get_error ();
	}
	if (!PEM_read_bio_PrivateKey (fbio, &key, rspamd_read_passphrase, NULL)) {
		msg_err ("cannot read private key %s, %s", privkey,
			ERR_error_string (ERR_get_error (), NULL));
		return ERR_get_error ();
	}

	key_ctx = EVP_PKEY_CTX_new (key, NULL);
	if (key_ctx == NULL) {
		msg_err ("cannot parse private key %s, %s", privkey,
			ERR_error_string (ERR_get_error (), NULL));
		return ERR_get_error ();
	}

	if (EVP_PKEY_sign_init (key_ctx) <= 0) {
		msg_err ("cannot parse private key %s, %s", privkey,
			ERR_error_string (ERR_get_error (), NULL));
		return ERR_get_error ();
	}
	if (EVP_PKEY_CTX_set_rsa_padding (key_ctx, RSA_PKCS1_PADDING) <= 0) {
		msg_err ("cannot init private key %s, %s", privkey,
			ERR_error_string (ERR_get_error (), NULL));
		return ERR_get_error ();
	}
	if (EVP_PKEY_CTX_set_signature_md (key_ctx, EVP_sha256 ()) <= 0) {
		msg_err ("cannot init signature private key %s, %s", privkey,
			ERR_error_string (ERR_get_error (), NULL));
		return ERR_get_error ();
	}

	sign_ctx = EVP_MD_CTX_create ();

	tests_num = g_strv_length (sign_configs);

	for (i = 0; i < tests_num; i++) {
		cur_file = sign_configs[i];
		if (realpath (cur_file, in_file) == NULL) {
			msg_err ("cannot resolve %s: %s", cur_file, strerror (errno));
			continue;
		}
		if (stat (in_file, &st) == -1) {
			msg_err ("cannot stat %s: %s", in_file, strerror (errno));
			continue;
		}
		if ((fd = open (in_file, O_RDONLY)) == -1) {
			msg_err ("cannot open %s: %s", in_file, strerror (errno));
			continue;
		}

		if ((map =
			mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd,
			0)) == MAP_FAILED) {
			close (fd);
			msg_err ("cannot mmap %s: %s", in_file, strerror (errno));
			continue;
		}

		close (fd);
		/* Now try to sign */
		EVP_DigestInit (sign_ctx, EVP_sha256 ());
		EVP_DigestUpdate (sign_ctx, map, st.st_size);
		EVP_DigestFinal (sign_ctx, dig, &diglen);

		munmap (map, st.st_size);

		if (EVP_PKEY_sign (key_ctx, NULL, &siglen, dig, diglen) <= 0) {
			msg_err ("cannot sign %s using private key %s, %s",
				in_file,
				privkey,
				ERR_error_string (ERR_get_error (), NULL));
			continue;
		}

		sig = OPENSSL_malloc (siglen);
		if (EVP_PKEY_sign (key_ctx, sig, &siglen, dig, diglen) <= 0) {
			msg_err ("cannot sign %s using private key %s, %s",
				in_file,
				privkey,
				ERR_error_string (ERR_get_error (), NULL));
			OPENSSL_free (sig);
			continue;
		}

		rspamd_snprintf (out_file, sizeof (out_file), "%s.sig", in_file);
		fd = open (out_file, O_WRONLY | O_CREAT | O_TRUNC, 00644);
		if (fd == -1) {
			msg_err ("cannot open output file %s: %s", out_file, strerror (
					errno));
			OPENSSL_free (sig);
			continue;
		}
		if (write (fd, sig, siglen) == -1) {
			msg_err ("cannot write to output file %s: %s", out_file,
				strerror (errno));
		}
		OPENSSL_free (sig);
		close (fd);
	}

	/* Cleanup */
	EVP_MD_CTX_destroy (sign_ctx);
	EVP_PKEY_CTX_free (key_ctx);
	EVP_PKEY_free (key);
	BIO_free (fbio);

	return res;
# endif
#endif
}

static void
rspamd_init_cfg (struct rspamd_config *cfg)
{
	cfg->cfg_pool = rspamd_mempool_new (
			rspamd_mempool_suggest_size ());
	rspamd_config_defaults (cfg);

	cfg->lua_state = rspamd_lua_init (cfg);
	rspamd_mempool_add_destructor (cfg->cfg_pool,
		(rspamd_mempool_destruct_t)lua_close, cfg->lua_state);

	/* Pre-init of cache */
	cfg->cache = g_new0 (struct symbols_cache, 1);
	cfg->cache->static_pool = rspamd_mempool_new (
		rspamd_mempool_suggest_size ());
	cfg->cache->cfg = cfg;
	cfg->cache->items_by_symbol = g_hash_table_new (
		rspamd_str_hash,
		rspamd_str_equal);
}

static void
rspamd_init_main (struct rspamd_main *rspamd)
{
	rspamd->server_pool = rspamd_mempool_new (
		rspamd_mempool_suggest_size ());
	rspamd_main->stat = rspamd_mempool_alloc0_shared (rspamd_main->server_pool,
		sizeof (struct rspamd_stat));
	/* Create rolling history */
	rspamd_main->history = rspamd_roll_history_new (rspamd_main->server_pool);
}

gint
main (gint argc, gchar **argv, gchar **env)
{
	gint res = 0, i;
	struct sigaction signals;
	struct rspamd_worker *cur;
	pid_t wrk;
	worker_t **pworker;
	GQuark type;
	gpointer keypair;
	GString *keypair_out;

#ifdef HAVE_SA_SIGINFO
	signals_info = g_queue_new ();
#endif
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
	g_thread_init (NULL);
#endif
	rspamd_main = (struct rspamd_main *)g_malloc0 (sizeof (struct rspamd_main));

	rspamd_main->cfg =
		(struct rspamd_config *)g_malloc0 (sizeof (struct rspamd_config));

	if (!rspamd_main || !rspamd_main->cfg) {
		fprintf (stderr, "Cannot allocate memory\n");
		exit (-errno);
	}

#ifndef HAVE_SETPROCTITLE
	init_title (argc, argv, env);
#endif

	rspamd_init_libs ();
	rspamd_init_main (rspamd_main);
	rspamd_init_cfg (rspamd_main->cfg);

	memset (&signals, 0, sizeof (struct sigaction));

	other_workers = g_array_new (FALSE, TRUE, sizeof (pid_t));

	read_cmd_line (argc, argv, rspamd_main->cfg);

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
	(void)rspamd_log_open (rspamd_main->logger);
	g_log_set_default_handler (rspamd_glib_log_function, rspamd_main->logger);

	detect_priv (rspamd_main);

	pworker = &workers[0];
	while (*pworker) {
		/* Init string quarks */
		(void)g_quark_from_static_string ((*pworker)->name);
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
		keypair = rspamd_http_connection_gen_key ();
		if (keypair == NULL) {
			exit (EXIT_FAILURE);
		}
		keypair_out = rspamd_http_connection_print_key (keypair,
				RSPAMD_KEYPAIR_PUBKEY|RSPAMD_KEYPAIR_PRIVKEY|RSPAMD_KEYPAIR_ID|
				RSPAMD_KEYPAIR_BASE32|RSPAMD_KEYPAIR_HUMAN);
		rspamd_printf ("%V", keypair_out);
		exit (EXIT_SUCCESS);
	}

	if (rspamd_main->cfg->config_test || dump_cache) {
		if (!load_rspamd_config (rspamd_main->cfg, FALSE)) {
			exit (EXIT_FAILURE);
		}

		res = TRUE;

		if (!rspamd_init_filters (rspamd_main->cfg, FALSE)) {
			res = FALSE;
		}

		/* Insert classifiers symbols */
		(void)rspamd_config_insert_classify_symbols (rspamd_main->cfg);

		if (!validate_cache (rspamd_main->cfg->cache, rspamd_main->cfg,
			FALSE)) {
			res = FALSE;
		}
		if (dump_cache) {
			print_symbols_cache (rspamd_main->cfg);
			exit (EXIT_SUCCESS);
		}
		fprintf (stderr, "syntax %s\n", res ? "OK" : "BAD");
		return res ? EXIT_SUCCESS : EXIT_FAILURE;
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

	msg_info ("rspamd " RVERSION " is starting, build id: " RID);
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

	rspamd_signals_init (&signals, sig_handler);

	if (rspamd_main->cfg->pid_file == NULL) {
		msg_info("pid file is not specified, skipping writing it");
	} else if (rspamd_write_pid (rspamd_main) == -1) {
		msg_err ("cannot write pid file %s", rspamd_main->cfg->pid_file);
		exit (-errno);
	}

	/* Block signals to use sigsuspend in future */
	sigprocmask (SIG_BLOCK, &signals.sa_mask, NULL);

	setproctitle ("main process");

	rspamd_stat_init (rspamd_main->cfg);
	rspamd_url_init (rspamd_main->cfg->tld_file);

	/* Insert classifiers symbols */
	(void)rspamd_config_insert_classify_symbols (rspamd_main->cfg);

	/* Init config cache */
	init_cfg_cache (rspamd_main->cfg);

	/* Validate cache */
	(void)validate_cache (rspamd_main->cfg->cache, rspamd_main->cfg, FALSE);

	/* Flush log */
	rspamd_log_flush (rspamd_main->logger);

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

	/* Signal processing cycle */
	for (;; ) {
		msg_debug ("calling sigsuspend");
		sigemptyset (&signals.sa_mask);
		sigsuspend (&signals.sa_mask);
#ifdef HAVE_SA_SIGINFO
		for (i = 0; i < cur_sg; i ++) {
			g_queue_push_head (signals_info, &static_sg[i]);
		}
		cur_sg = 0;
		print_signals_info ();
#endif
		if (do_terminate) {
			do_terminate = 0;
			msg_info ("catch termination signal, waiting for children");
			rspamd_pass_signal (rspamd_main->workers, SIGTERM);
			break;
		}
		if (child_dead) {
			child_dead = 0;
			msg_debug ("catch SIGCHLD signal, finding terminated worker");
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
					msg_info ("%s process %P terminated normally",
						g_quark_to_string (cur->type),
						cur->pid);
				}
				else {
					if (WIFSIGNALED (res)) {
						msg_warn (
							"%s process %P terminated abnormally by signal: %d",
							g_quark_to_string (cur->type),
							cur->pid,
							WTERMSIG (res));
					}
					else {
						msg_warn ("%s process %P terminated abnormally",
							g_quark_to_string (cur->type),
							cur->pid);
					}
					/* Fork another worker in replace of dead one */
					delay_fork (cur->cf);
				}

				g_free (cur);
			}
			else {
				for (i = 0; i < (gint)other_workers->len; i++) {
					if (g_array_index (other_workers, pid_t, i) == wrk) {
						g_array_remove_index_fast (other_workers, i);
						msg_info ("related process %P terminated", wrk);
					}
				}
			}
		}
		if (do_restart) {
			do_restart = 0;
			rspamd_log_reopen_priv (rspamd_main->logger,
				rspamd_main->workers_uid,
				rspamd_main->workers_gid);
			msg_info ("rspamd " RVERSION " is restarting");
			g_hash_table_foreach (rspamd_main->workers, kill_old_workers, NULL);
			rspamd_map_remove_all (rspamd_main->cfg);
			reread_config (rspamd_main);
			spawn_workers (rspamd_main);
		}
		if (do_reopen_log) {
			do_reopen_log = 0;
			rspamd_log_reopen_priv (rspamd_main->logger,
				rspamd_main->workers_uid,
				rspamd_main->workers_gid);
			g_hash_table_foreach (rspamd_main->workers, reopen_log_handler,
				NULL);
		}
		if (got_alarm) {
			got_alarm = 0;
			fork_delayed (rspamd_main);
		}
	}

	/* Restore some signals */
	sigemptyset (&signals.sa_mask);
	sigaddset (&signals.sa_mask, SIGALRM);
	sigaddset (&signals.sa_mask, SIGINT);
	sigaddset (&signals.sa_mask, SIGTERM);
	sigaction (SIGALRM, &signals, NULL);
	sigaction (SIGTERM, &signals, NULL);
	sigaction (SIGINT,	&signals, NULL);
	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);
	/* Set alarm for hard termination */
	if (getenv ("G_SLICE") != NULL) {
		/* Special case if we are likely running with valgrind */
		set_alarm (HARD_TERMINATION_TIME * 10);
	}
	else {
		set_alarm (HARD_TERMINATION_TIME);
	}

	/* Wait for workers termination */
	g_hash_table_foreach_remove (rspamd_main->workers, wait_for_workers, NULL);

	/* Maybe save roll history */
	if (rspamd_main->cfg->history_file) {
		rspamd_roll_history_save (rspamd_main->history,
			rspamd_main->cfg->history_file);
	}

	msg_info ("terminating...");

	rspamd_log_close (rspamd_main->logger);

	rspamd_config_free (rspamd_main->cfg);
	g_free (rspamd_main->cfg);
	g_free (rspamd_main);

	g_mime_shutdown ();

#ifdef HAVE_OPENSSL
	EVP_cleanup ();
	ERR_free_strings ();
#endif

	return (res);
}

/*
 * vi:ts=4
 */
