/*
 * Copyright (c) 2009, Rambler media
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
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "main.h"
#include "cfg_file.h"
#include "util.h"
#include "lmtp.h"
#include "smtp.h"
#include "map.h"
#include "fuzzy_storage.h"
#include "cfg_xml.h"
#include "symbols_cache.h"

#ifndef WITHOUT_PERL

#   include <EXTERN.h>			/* from the Perl distribution     */
#   include <perl.h>			/* from the Perl distribution     */

#   ifndef PERL_IMPLICIT_CONTEXT
#      undef  dTHXa
#      define dTHXa(a)
#   endif
#   include "perl.h"

#elif defined(WITH_LUA)
#   include "lua/lua_common.h"
#endif

/* 2 seconds to fork new process in place of dead one */
#define SOFT_FORK_TIME 2


rspamd_hash_t                  *counters;

static struct rspamd_worker    *fork_worker (struct rspamd_main *, struct worker_conf *);
static gboolean                 load_rspamd_config (struct config_file *cfg, gboolean init_modules);
static void                     init_cfg_cache (struct config_file *cfg);

sig_atomic_t                    do_restart;
sig_atomic_t                    do_terminate;
sig_atomic_t                    child_dead;
sig_atomic_t                    got_alarm;

#ifdef HAVE_SA_SIGINFO
GQueue                         *signals_info;
#endif

static gboolean                 config_test;
static gboolean                 no_fork;
static gchar                   *cfg_name;
static gchar                   *rspamd_user;
static gchar                   *rspamd_group;
static gchar                   *rspamd_pidfile;
static gboolean                 dump_vars;
static gboolean                 dump_cache;
static gboolean                 is_debug;

/* List of workers that are pending to start */
static GList                   *workers_pending = NULL;

/* List of active listen sockets indexed by worker type */
static GHashTable              *listen_sockets;

/* Commandline options */
static GOptionEntry entries[] = 
{
  { "config-test", 't', 0, G_OPTION_ARG_NONE, &config_test, "Do config test and exit", NULL },
  { "no-fork", 'f', 0, G_OPTION_ARG_NONE, &no_fork, "Do not daemonize main process", NULL },
  { "config", 'c', 0, G_OPTION_ARG_STRING, &cfg_name, "Specify config file", NULL },
  { "user", 'u', 0, G_OPTION_ARG_STRING, &rspamd_user, "User to run rspamd as", NULL },
  { "group", 'g', 0, G_OPTION_ARG_STRING, &rspamd_group, "Group to run rspamd as", NULL },
  { "pid", 'p', 0, G_OPTION_ARG_STRING, &rspamd_pidfile, "Path to pidfile", NULL },
  { "dump-vars", 'V', 0, G_OPTION_ARG_NONE, &dump_vars, "Print all rspamd variables and exit", NULL },
  { "dump-cache", 'C', 0, G_OPTION_ARG_NONE, &dump_cache, "Dump symbols cache stats and exit", NULL },
  { "debug", 'd', 0, G_OPTION_ARG_NONE, &is_debug, "Force debug output", NULL },
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
	siginfo_t *new_info;
	new_info = g_malloc (sizeof (siginfo_t));
	memcpy (new_info, info, sizeof (siginfo_t));
	g_queue_push_head (signals_info, new_info);
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
print_signals_info ()
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
		g_free (inf);
	}
}
#endif


static void
read_cmd_line (gint argc, gchar **argv, struct config_file *cfg)
{
	GError                         *error = NULL;
	GOptionContext                 *context;

	context = g_option_context_new ("- run rspamd daemon");
	g_option_context_set_summary (context, "Summary:\n  Rspamd daemon version " RVERSION "\n  Release id: " RID);
	g_option_context_add_main_entries (context, entries, NULL);
	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		fprintf (stderr, "option parsing failed: %s\n", error->message);
		exit (1);
	}
	cfg->no_fork = no_fork;
	cfg->config_test = config_test;
	cfg->rspamd_user = rspamd_user;
	cfg->rspamd_group = rspamd_group;
	cfg->cfg_name = cfg_name;
	cfg->pid_file = rspamd_pidfile;
}

static void
drop_priv (struct config_file *cfg)
{
	struct passwd                  *pwd;
	struct group                   *grp;

	if (geteuid () == 0 && cfg->rspamd_user) {
		pwd = getpwnam (cfg->rspamd_user);
		if (pwd == NULL) {
			msg_err ("user specified does not exists (%s), aborting", strerror (errno));
			exit (-errno);
		}
		if (cfg->rspamd_group) {
			grp = getgrnam (cfg->rspamd_group);
			if (grp == NULL) {
				msg_err ("group specified does not exists (%s), aborting", strerror (errno));
				exit (-errno);
			}
			if (setgid (grp->gr_gid) == -1) {
				msg_err ("cannot setgid to %d (%s), aborting", (gint)grp->gr_gid, strerror (errno));
				exit (-errno);
			}
			if (initgroups (cfg->rspamd_user, grp->gr_gid) == -1) {
				msg_err ("initgroups failed (%s), aborting", strerror (errno));
				exit (-errno);
			}
		}
		if (setuid (pwd->pw_uid) == -1) {
			msg_err ("cannot setuid to %d (%s), aborting", (gint)pwd->pw_uid, strerror (errno));
			exit (-errno);
		}
	}
}

static void
config_logger (struct rspamd_main *rspamd, gboolean is_fatal)
{
	rspamd_set_logger (rspamd->cfg->log_type, TYPE_MAIN, rspamd->cfg);
	if (open_log () == -1) {
		if (is_fatal) {
			fprintf (stderr, "Fatal error, cannot open logfile, exiting\n");
			exit (EXIT_FAILURE);
		}
		else {
			msg_err ("cannot log to file, logfile unaccessable");
		}
	}
}

static void
reread_config (struct rspamd_main *rspamd)
{
	struct config_file             *tmp_cfg;
	gchar                           *cfg_file;
	GList                          *l;
	struct filter                  *filt;

	tmp_cfg = (struct config_file *)g_malloc (sizeof (struct config_file));
	if (tmp_cfg) {
		bzero (tmp_cfg, sizeof (struct config_file));
		tmp_cfg->cfg_pool = memory_pool_new (memory_pool_get_size ());
		init_defaults (tmp_cfg);
		cfg_file = memory_pool_strdup (tmp_cfg->cfg_pool, rspamd->cfg->cfg_name);
		/* Save some variables */
		tmp_cfg->cfg_name = cfg_file;
		init_lua (tmp_cfg);

		if (! load_rspamd_config (tmp_cfg, FALSE)) {
			msg_err ("cannot parse new config file, revert to old one");
			free_config (tmp_cfg);
		}
		else {
			msg_debug ("replacing config");
			free_config (rspamd->cfg);
			close_log ();
			g_free (rspamd->cfg);
			rspamd->cfg = tmp_cfg;
			/* Force debug log */
			if (is_debug) {
				rspamd->cfg->log_level = G_LOG_LEVEL_DEBUG;
			}
			config_logger (rspamd, FALSE);
			/* Pre-init of cache */
			rspamd->cfg->cache = g_new0 (struct symbols_cache, 1);
			rspamd->cfg->cache->static_pool = memory_pool_new (memory_pool_get_size ());
			rspamd->cfg->cache->cfg = rspamd->cfg;
			/* Perform modules configuring */
			l = g_list_first (rspamd->cfg->filters);

			while (l) {
				filt = l->data;
				if (filt->module) {
					(void)filt->module->module_reconfig_func (rspamd->cfg);
					msg_debug ("reconfig of %s", filt->module->name);
				}
				l = g_list_next (l);
			}
			init_lua_filters (rspamd->cfg);
			init_cfg_cache (rspamd->cfg);
			msg_info ("config rereaded successfully");
		}
	}
}

static void
set_worker_limits (struct worker_conf *cf)
{
	struct rlimit                   rlmt;

	if (cf->rlimit_nofile != 0) {
		rlmt.rlim_cur = (rlim_t) cf->rlimit_nofile;
		rlmt.rlim_max = (rlim_t) cf->rlimit_nofile;

		if (setrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
			msg_warn ("cannot set files rlimit: %d, %s", cf->rlimit_nofile, strerror (errno));
        }
	}

	if (cf->rlimit_maxcore != 0) {
		rlmt.rlim_cur = (rlim_t) cf->rlimit_maxcore;
		rlmt.rlim_max = (rlim_t) cf->rlimit_maxcore;

		if (setrlimit(RLIMIT_CORE, &rlmt) == -1) {
			msg_warn ("cannot set max core rlimit: %d, %s", cf->rlimit_maxcore, strerror (errno));
        }
	}

}

static struct rspamd_worker    *
fork_worker (struct rspamd_main *rspamd, struct worker_conf *cf)
{
	struct rspamd_worker           *cur;
	/* Starting worker process */
	cur = (struct rspamd_worker *)g_malloc (sizeof (struct rspamd_worker));
	if (cur) {
		bzero (cur, sizeof (struct rspamd_worker));
		cur->srv = rspamd;
		cur->type = cf->type;
		cur->pid = fork ();
		cur->cf = g_malloc (sizeof (struct worker_conf));
		cur->ctx = rspamd->workers_ctx[cf->type];
		memcpy (cur->cf, cf, sizeof (struct worker_conf));
		cur->pending = FALSE;
		switch (cur->pid) {
		case 0:
			/* Update pid for logging */
			update_log_pid (cf->type);
			/* Drop privilleges */
			drop_priv (rspamd->cfg);
			/* Set limits */
			set_worker_limits (cf);
			switch (cf->type) {
			case TYPE_CONTROLLER:
				setproctitle ("controller process");
				pidfile_close (rspamd->pfh);
				msg_info ("starting controller process %P", getpid ());
				start_controller (cur);
				break;
			case TYPE_LMTP:
				setproctitle ("lmtp process");
				pidfile_close (rspamd->pfh);
				msg_info ("starting lmtp process %P", getpid ());
				start_lmtp_worker (cur);
				break;
			case TYPE_SMTP:
				setproctitle ("smtp process");
				pidfile_close (rspamd->pfh);
				msg_info ("starting smtp process %P", getpid ());
				start_smtp_worker (cur);
				break;
			case TYPE_FUZZY:
				setproctitle ("fuzzy storage");
				pidfile_close (rspamd->pfh);
				msg_info ("starting fuzzy storage process %P", getpid ());
				start_fuzzy_storage (cur);
				break;
			case TYPE_GREYLIST:
				setproctitle ("greylist storage");
				pidfile_close (rspamd->pfh);
				msg_info ("starting greylist storage process %P", getpid ());
				start_greylist_storage (cur);
				break;
			case TYPE_WORKER:
			default:
				setproctitle ("worker process");
				pidfile_close (rspamd->pfh);
				msg_info ("starting worker process %P", getpid ());
				start_worker (cur);
				break;
			}
			break;
		case -1:
			msg_err ("cannot fork main process. %s", strerror (errno));
			pidfile_remove (rspamd->pfh);
			exit (-errno);
			break;
		default:
			/* Insert worker into worker's table, pid is index */
			g_hash_table_insert (rspamd->workers, GSIZE_TO_POINTER (cur->pid), cur);
			break;
		}
	}

	return cur;
}

static void
delay_fork (struct worker_conf *cf)
{
	workers_pending = g_list_prepend (workers_pending, cf);
	(void)alarm (SOFT_FORK_TIME);
}


static void
dump_module_variables (gpointer key, gpointer value, gpointer data)
{
	GList                          *cur_opt;
	struct module_opt              *cur;

	cur_opt = (GList *) value;

	while (cur_opt) {
		cur = cur_opt->data;
		if (cur->value) {
			printf ("$%s = \"%s\"\n", cur->param, cur->value);
		}
		cur_opt = g_list_next (cur_opt);
	}
}

static void
dump_all_variables (gpointer key, gpointer value, gpointer data)
{
	printf ("$%s = \"%s\"\n", (gchar *)key, (gchar *)value);
}


static void
dump_cfg_vars (struct config_file *cfg)
{
	g_hash_table_foreach (cfg->variables, dump_all_variables, NULL);
}

static gint
create_listen_socket (struct in_addr *addr, gint port, gint family, gchar *path)
{
	gint                            listen_sock = -1;
	struct sockaddr_un             *un_addr;
	/* Create listen socket */
	if (family == AF_INET) {
		if ((listen_sock = make_tcp_socket (addr, port, TRUE, TRUE)) == -1) {
			msg_err ("cannot create tcp listen socket. %s", strerror (errno));
		}
	}
	else {
		un_addr = (struct sockaddr_un *)alloca (sizeof (struct sockaddr_un));
		if (!un_addr || (listen_sock = make_unix_socket (path, un_addr, TRUE)) == -1) {
			msg_err ("cannot create unix listen socket. %s", strerror (errno));
		}
	}

	if (listen_sock != -1) {
		if (listen (listen_sock, -1) == -1) {
			msg_err ("cannot listen on socket. %s", strerror (errno));
		}
	}

	return listen_sock;
}

static void
fork_delayed (struct rspamd_main *rspamd)
{
	GList                          *cur;
	struct worker_conf             *cf;

	while (workers_pending != NULL) {
		cur = workers_pending;
		cf = cur->data;

		workers_pending = g_list_remove_link (workers_pending, cur);
		fork_worker (rspamd, cf);
		g_list_free_1 (cur);
	}
}

static inline uintptr_t
make_listen_key (struct in_addr *addr, gint port, gint family, gchar *path)
{
	uintptr_t                       res = 0;
	gchar                           *key;

	if (family == AF_INET) {
		/* Make fnv hash from bytes of addr and port */
		key = (gchar *)&addr->s_addr;
		while (key - (gchar *)&addr->s_addr < sizeof (addr->s_addr)) {
			res ^= (gchar)*key++;
			res += (res << 1) + (res << 4) + (res << 7) + (res << 8) + (res << 24);
		}
		key = (gchar *)&port;
		while (key - (gchar *)&port < sizeof (addr->s_addr)) {
			res ^= (gchar)*key++;
			res += (res << 1) + (res << 4) + (res << 7) + (res << 8) + (res << 24);
		}
	}
	else {
		/* Make fnv hash from bytes of path */
		key = path;
		while (*key) {
			res ^= (gchar)*key++;
			res += (res << 1) + (res << 4) + (res << 7) + (res << 8) + (res << 24);
		}
	}

	return res;
}

static void
spawn_workers (struct rspamd_main *rspamd)
{
	GList                          *cur;
	struct worker_conf             *cf;
	gint                            i, listen_sock;
	gpointer                        p;

	cur = rspamd->cfg->workers;

	while (cur) {
		cf = cur->data;

		if (cf->has_socket) {
			if ((p = g_hash_table_lookup (listen_sockets, GINT_TO_POINTER (
								make_listen_key (&cf->bind_addr, cf->bind_port, cf->bind_family, cf->bind_host)))) == NULL) {
				/* Create listen socket */
				listen_sock = create_listen_socket (&cf->bind_addr, cf->bind_port, cf->bind_family, cf->bind_host);
				if (listen_sock == -1) {
					exit (-errno);
				}
				g_hash_table_insert (listen_sockets, GINT_TO_POINTER (
								make_listen_key (&cf->bind_addr, cf->bind_port, cf->bind_family, cf->bind_host)), 
								GINT_TO_POINTER (listen_sock));
			}
			else {
				/* We had socket for this type of worker */
				listen_sock = GPOINTER_TO_INT (p);
			}
			cf->listen_sock = listen_sock;
		}
		
		if (cf->type == TYPE_FUZZY || cf->type == TYPE_GREYLIST) {
			if (cf->count > 1) {
				msg_err ("cannot spawn more than 1 fuzzy storage worker, so spawn one");
			}
			fork_worker (rspamd, cf);
		}
		else {
			for (i = 0; i < cf->count; i++) {
				fork_worker (rspamd, cf);
			}
		}

		cur = g_list_next (cur);
	}
}

static void
kill_old_workers (gpointer key, gpointer value, gpointer unused)
{
	struct rspamd_worker         *w = value;

	kill (w->pid, SIGUSR2);
	msg_info ("send signal to worker %P", w->pid);
}

static gboolean
wait_for_workers (gpointer key, gpointer value, gpointer unused)
{
	struct rspamd_worker          *w = value;
	gint                            res = 0;

	waitpid (w->pid, &res, 0);

	msg_debug ("%s process %P terminated", process_to_str (w->type), w->pid);
	g_free (w->cf);
	g_free (w);

	return TRUE;
}

static void
reopen_log_handler (gpointer key, gpointer value, gpointer unused)
{
	struct rspamd_worker          *w = value;

	if (kill (w->pid, SIGUSR1) == -1) {
		msg_err ("kill failed for pid %P: %s", w->pid, strerror (errno));
	}
}

#if 0
/* XXX: remove this as it is unused now */
static gboolean
convert_old_config (struct rspamd_main *rspamd) 
{
	FILE *f;

	f = fopen (rspamd->cfg->cfg_name, "r");
	if (f == NULL) {
		msg_err ("cannot open file: %s", rspamd->cfg->cfg_name);
		return EBADF;
	}
	yyin = f;
	
	yacc_cfg = rspamd->cfg;
	if (yyparse () != 0 || yynerrs > 0) {
		msg_err ("cannot parse config file, %d errors", yynerrs);
		return EBADF;
	}

	/* Strictly set temp dir */
	if (!rspamd->cfg->temp_dir) {
		msg_warn ("tempdir is not set, trying to use $TMPDIR");
		rspamd->cfg->temp_dir = memory_pool_strdup (rspamd->cfg->cfg_pool, getenv ("TMPDIR"));

		if (!rspamd->cfg->temp_dir) {
			msg_warn ("$TMPDIR is empty too, using /tmp as default");
			rspamd->cfg->temp_dir = memory_pool_strdup (rspamd->cfg->cfg_pool, "/tmp");
		}
	}


	fclose (f);
	/* Dump it to xml */
	if (get_config_checksum (rspamd->cfg)) {
		if (xml_dump_config (rspamd->cfg, convert_config)) {
			rspamd->cfg->cfg_name = convert_config;
			return TRUE;
		}
	}
	
	return FALSE;
}
#endif

static gboolean
load_rspamd_config (struct config_file *cfg, gboolean init_modules)
{
	GList                          *l;
	struct filter                  *filt;
	struct module_ctx              *cur_module = NULL;

	if (! read_xml_config (cfg, cfg->cfg_name)) {
		return FALSE;
	}

	/* Strictly set temp dir */
	if (!cfg->temp_dir) {
		msg_warn ("tempdir is not set, trying to use $TMPDIR");
		cfg->temp_dir = memory_pool_strdup (cfg->cfg_pool, getenv ("TMPDIR"));

		if (!cfg->temp_dir) {
			msg_warn ("$TMPDIR is empty too, using /tmp as default");
			cfg->temp_dir = memory_pool_strdup (cfg->cfg_pool, "/tmp");
		}
	}

	/* Do post-load actions */
	post_load_config (cfg);
	
	if (init_modules) {
		/* Init C modules */
		l = g_list_first (cfg->filters);

		while (l) {
			filt = l->data;
			if (filt->module) {
				cur_module = memory_pool_alloc (cfg->cfg_pool, sizeof (struct module_ctx));
				if (filt->module->module_init_func (cfg, &cur_module) == 0) {
					g_hash_table_insert (cfg->c_modules, (gpointer) filt->module->name, cur_module);
				}
			}
			l = g_list_next (l);
		}
	}
	
	return TRUE;
}

static void
init_cfg_cache (struct config_file *cfg) 
{

	if (!init_symbols_cache (cfg->cfg_pool, cfg->cache, cfg, cfg->cache_filename)) {
		exit (EXIT_FAILURE);
	}
}

static void
print_symbols_cache (struct config_file *cfg) 
{
	GList                          *cur;
	struct cache_item              *item;
	gint                            i;

	if (!init_symbols_cache (cfg->cfg_pool, cfg->cache, cfg, cfg->cache_filename)) {
		exit (EXIT_FAILURE);
	}
	if (cfg->cache) {
		printf ("Symbols cache\n");
		printf ("-----------------------------------------------------------------\n");
		printf ("| Pri  | Symbol                | Weight | Frequency | Avg. time |\n");
		i = 0;
		cur = cfg->cache->negative_items;
		while (cur) {
			item = cur->data;
			if (!item->is_callback) {
				printf ("-----------------------------------------------------------------\n");
				printf ("| %3d | %22s | %6.1f | %9d | %9.3f |\n", i, item->s->symbol, item->s->weight, item->s->frequency, item->s->avg_time);
			}
			cur = g_list_next (cur);
			i ++;
		}
		cur = cfg->cache->static_items;
		while (cur) {
			item = cur->data;
			if (!item->is_callback) {
				printf ("-----------------------------------------------------------------\n");
				printf ("| %3d | %22s | %6.1f | %9d | %9.3f |\n", i, item->s->symbol, item->s->weight, item->s->frequency, item->s->avg_time);
			}
			cur = g_list_next (cur);
			i ++;
		}

		printf ("-----------------------------------------------------------------\n");
	}
}

static void
init_workers_ctx (struct rspamd_main *main)
{
	main->workers_ctx[TYPE_WORKER] = init_worker ();
	main->workers_ctx[TYPE_CONTROLLER] = init_controller ();
	main->workers_ctx[TYPE_FUZZY] = init_fuzzy_storage ();
	main->workers_ctx[TYPE_SMTP] = init_smtp_worker ();
}

gint
main (gint argc, gchar **argv, gchar **env)
{
	struct rspamd_main             *rspamd;
	gint                            res = 0;
	struct sigaction                signals;
	struct rspamd_worker           *cur;
	struct rlimit                   rlim;
	struct filter                  *filt;
	pid_t                           wrk;
	GList                          *l;

#ifdef HAVE_SA_SIGINFO
	signals_info = g_queue_new ();
#endif
	rspamd = (struct rspamd_main *)g_malloc (sizeof (struct rspamd_main));
	bzero (rspamd, sizeof (struct rspamd_main));
	rspamd->server_pool = memory_pool_new (memory_pool_get_size ());
	rspamd->cfg = (struct config_file *)g_malloc (sizeof (struct config_file));
	if (!rspamd || !rspamd->cfg) {
		fprintf (stderr, "Cannot allocate memory\n");
		exit (-errno);
	}

	do_terminate = 0;
	do_restart = 0;
	child_dead = 0;
	do_reopen_log = 0;

#ifndef HAVE_SETPROCTITLE
	init_title (argc, argv, env);
#endif

	rspamd->stat = memory_pool_alloc_shared (rspamd->server_pool, sizeof (struct rspamd_stat));
	bzero (rspamd->stat, sizeof (struct rspamd_stat));

	bzero (rspamd->cfg, sizeof (struct config_file));
	rspamd->cfg->cfg_pool = memory_pool_new (memory_pool_get_size ());
	init_defaults (rspamd->cfg);

	bzero (&signals, sizeof (struct sigaction));

	read_cmd_line (argc, argv, rspamd->cfg);
	if (rspamd->cfg->cfg_name == NULL) {
		rspamd->cfg->cfg_name = FIXED_CONFIG_FILE;
	}

	if (rspamd->cfg->config_test || is_debug) {
		rspamd->cfg->log_level = G_LOG_LEVEL_DEBUG;
	}
	else {
		rspamd->cfg->log_level = G_LOG_LEVEL_CRITICAL;
	}

#ifdef HAVE_SETLOCALE
	/* Set locale setting to C locale to avoid problems in future */
	setlocale (LC_ALL, "C");
	setlocale (LC_CTYPE, "C");
	setlocale (LC_MESSAGES, "C");
	setlocale (LC_TIME, "C");
#endif

	/* First set logger to console logger */
	rspamd_set_logger (RSPAMD_LOG_CONSOLE, TYPE_MAIN, rspamd->cfg);
	(void)open_log ();
	g_log_set_default_handler (rspamd_glib_log_function, rspamd->cfg);

	init_lua (rspamd->cfg);

	/* Init counters */
	counters = rspamd_hash_new_shared (rspamd->server_pool, g_str_hash, g_str_equal, 64);
	/* Init listen sockets hash */
	listen_sockets = g_hash_table_new (g_direct_hash, g_direct_equal);
	
	/* Init contextes */
	init_workers_ctx (rspamd);

	/* Init classifiers options */
	register_classifier_opt ("bayes", "min_tokens");
	register_classifier_opt ("winnow", "min_tokens");
	register_classifier_opt ("winnow", "learn_threshold");

	/* Pre-init of cache */
	rspamd->cfg->cache = g_new0 (struct symbols_cache, 1);
	rspamd->cfg->cache->static_pool = memory_pool_new (memory_pool_get_size ());
	rspamd->cfg->cache->cfg = rspamd->cfg;

	/* Load config */
	if (! load_rspamd_config (rspamd->cfg, TRUE)) {
		exit (EXIT_FAILURE);
	}
	
	/* Force debug log */
	if (is_debug) {
		rspamd->cfg->log_level = G_LOG_LEVEL_DEBUG;
	}

	if (rspamd->cfg->config_test || dump_vars || dump_cache) {
		/* Init events to test modules */
		event_init ();
		res = TRUE;
		if (! init_lua_filters (rspamd->cfg)) {
			res = FALSE;
		}
		if (!check_modules_config (rspamd->cfg)) {
			res = FALSE;
		}
		/* Perform modules configuring */
		l = g_list_first (rspamd->cfg->filters);

		while (l) {
			filt = l->data;
			if (filt->module) {
				if (!filt->module->module_config_func (rspamd->cfg)) {
					res = FALSE;
				}
			}
			l = g_list_next (l);
		}
		/* Insert classifiers symbols */
		(void)insert_classifier_symbols (rspamd->cfg);

		if (! validate_cache (rspamd->cfg->cache, rspamd->cfg, TRUE)) {
			res = FALSE;
		}
		if (dump_vars) {
			dump_cfg_vars (rspamd->cfg);
		}
		if (dump_cache) {
			print_symbols_cache (rspamd->cfg);
			exit (EXIT_SUCCESS);
		}
		fprintf (stderr, "syntax %s\n", res ? "OK" : "BAD");
		return res ? EXIT_SUCCESS : EXIT_FAILURE;
	}

	/* Set stack size for pcre */
	getrlimit (RLIMIT_STACK, &rlim);
	rlim.rlim_cur = 100 * 1024 * 1024;
	setrlimit (RLIMIT_STACK, &rlim);

	config_logger (rspamd, TRUE);

	msg_info ("rspamd " RVERSION " is starting, build id: " RID);
	rspamd->cfg->cfg_name = memory_pool_strdup (rspamd->cfg->cfg_pool, rspamd->cfg->cfg_name);

	/* Daemonize */
	if (!rspamd->cfg->no_fork && daemon (0, 0) == -1) {
		fprintf (stderr, "Cannot daemonize\n");
		exit (-errno);
	}

	/* Write info */
	rspamd->pid = getpid ();
	rspamd->type = TYPE_MAIN;

	init_signals (&signals, sig_handler);

	if (write_pid (rspamd) == -1) {
		msg_err ("cannot write pid file %s", rspamd->cfg->pid_file);
		exit (-errno);
	}

	/* Block signals to use sigsuspend in future */
	sigprocmask (SIG_BLOCK, &signals.sa_mask, NULL);

	setproctitle ("main process");

	/* Init statfile pool */
	rspamd->statfile_pool = statfile_pool_new (rspamd->server_pool, rspamd->cfg->max_statfile_size);

	event_init ();
	g_mime_init (0);

	/* Init lua filters */
	if (! init_lua_filters (rspamd->cfg)) {
		msg_err ("error loading lua plugins");
		exit (EXIT_FAILURE);
	}

	/* Check configuration for modules */
	(void)check_modules_config (rspamd->cfg);

	/* Insert classifiers symbols */
	(void)insert_classifier_symbols (rspamd->cfg);

	/* Perform modules configuring */
	l = g_list_first (rspamd->cfg->filters);

	while (l) {
		filt = l->data;
		if (filt->module) {
			if (!filt->module->module_config_func (rspamd->cfg)) {
				res = FALSE;
			}
		}
		l = g_list_next (l);
	}

	/* Init config cache */
	init_cfg_cache (rspamd->cfg);

	/* Validate cache */
	(void)validate_cache (rspamd->cfg->cache, rspamd->cfg, FALSE);

	/* Flush log */
	flush_log_buf ();

	/* Spawn workers */
	rspamd->workers = g_hash_table_new (g_direct_hash, g_direct_equal);
	spawn_workers (rspamd);

	/* Signal processing cycle */
	for (;;) {
		msg_debug ("calling sigsuspend");
		sigemptyset (&signals.sa_mask);
		sigsuspend (&signals.sa_mask);
#ifdef HAVE_SA_SIGINFO
		print_signals_info ();
#endif
		if (do_terminate) {
			msg_debug ("catch termination signal, waiting for childs");
			pass_signal_worker (rspamd->workers, SIGTERM);
			break;
		}
		if (child_dead) {
			child_dead = 0;
			msg_debug ("catch SIGCHLD signal, finding terminated worker");
			/* Remove dead child form childs list */
			wrk = waitpid (0, &res, 0);
			if ((cur = g_hash_table_lookup (rspamd->workers, GSIZE_TO_POINTER (wrk))) != NULL) {
				/* Unlink dead process from queue and hash table */

				g_hash_table_remove (rspamd->workers, GSIZE_TO_POINTER (wrk));

				if (WIFEXITED (res) && WEXITSTATUS (res) == 0) {
					/* Normal worker termination, do not fork one more */
					msg_info ("%s process %P terminated normally", process_to_str (cur->type), cur->pid);
				}
				else {
					if (WIFSIGNALED (res)) {
						msg_warn ("%s process %P terminated abnormally by signal: %d", process_to_str (cur->type), cur->pid, WTERMSIG (res));
					}
					else {
						msg_warn ("%s process %P terminated abnormally", process_to_str (cur->type), cur->pid);
					}
					/* Fork another worker in replace of dead one */
					delay_fork (cur->cf);
				}

				g_free (cur);
			}
			else {
				msg_err ("got SIGCHLD, but pid %P is not found in workers hash table, something goes wrong", wrk);
			}
		}
		if (do_restart) {
			do_restart = 0;
			reopen_log ();
			msg_info ("rspamd " RVERSION " is restarting");
			g_hash_table_foreach (rspamd->workers, kill_old_workers, NULL);
			remove_all_maps ();
			reread_config (rspamd);
			spawn_workers (rspamd);
		}
		if (do_reopen_log) {
			do_reopen_log = 0;
			reopen_log ();
			g_hash_table_foreach (rspamd->workers, reopen_log_handler, NULL);
		}
		if (got_alarm) {
			got_alarm = 0;
			fork_delayed (rspamd);
		}
	}

	/* Wait for workers termination */
	g_hash_table_foreach_remove (rspamd->workers, wait_for_workers, NULL);

	msg_info ("terminating...");

	statfile_pool_delete (rspamd->statfile_pool);

	close_log ();

	free_config (rspamd->cfg);
	g_free (rspamd->cfg);
	g_free (rspamd);

	return (res);
}

/* 
 * vi:ts=4 
 */
