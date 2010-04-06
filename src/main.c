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
#include "fuzzy_storage.h"
#include "cfg_xml.h"

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

struct config_file             *cfg;

rspamd_hash_t                  *counters;

static struct rspamd_worker    *fork_worker (struct rspamd_main *, struct worker_conf *);

sig_atomic_t                    do_restart;
sig_atomic_t                    do_terminate;
sig_atomic_t                    child_dead;
sig_atomic_t                    got_alarm;

#ifdef HAVE_SA_SIGINFO
GQueue                         *signals_info;
#endif

extern int                      yynerrs;
extern FILE                    *yyin;

static gboolean                 config_test;
static gboolean                 no_fork;
static gchar                   *cfg_name;
static gchar                   *rspamd_user;
static gchar                   *rspamd_group;
static gchar                   *rspamd_pidfile;
static gboolean                 dump_vars;
static gboolean                 dump_cache;

#ifndef WITHOUT_PERL
extern void                     xs_init (pTHX);
extern PerlInterpreter         *perl_interpreter;
#endif

/* List of workers that are pending to start */
static GList                   *workers_pending = NULL;

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
  { NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
};


#ifndef HAVE_SA_SIGINFO
static void
sig_handler (int signo)
#else
static void
sig_handler (int signo, siginfo_t *info, void *unused)
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
		do_reopen_log = 1;
		break;
	case SIGINT:
	case SIGTERM:
		do_terminate = 1;
		break;
	case SIGCHLD:
		child_dead = 1;
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

static const char *
chldsigcode (int code) {
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
			msg_info ("got signal: '%s'; received from pid: %P; uid: %l",
					g_strsignal (inf->si_signo), inf->si_pid, (long int)inf->si_uid);
		}
		g_free (inf);
	}
}
#endif


static void
read_cmd_line (int argc, char **argv, struct config_file *cfg)
{
	GError                         *error = NULL;
	GOptionContext                 *context;

	context = g_option_context_new ("- run rspamd daemon");
	g_option_context_set_summary (context, "Summary:\n  Rspamd daemon version " RVERSION);
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
				msg_err ("cannot setgid to %d (%s), aborting", (int)grp->gr_gid, strerror (errno));
				exit (-errno);
			}
			if (initgroups (cfg->rspamd_user, grp->gr_gid) == -1) {
				msg_err ("initgroups failed (%s), aborting", strerror (errno));
				exit (-errno);
			}
		}
		if (setuid (pwd->pw_uid) == -1) {
			msg_err ("cannot setuid to %d (%s), aborting", (int)pwd->pw_uid, strerror (errno));
			exit (-errno);
		}
	}
}

static void
config_logger (struct rspamd_main *rspamd, gboolean is_fatal)
{
	rspamd_set_logger (rspamd->cfg->log_type, rspamd->cfg);
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
	char                           *cfg_file;
	FILE                           *f;

	tmp_cfg = (struct config_file *)g_malloc (sizeof (struct config_file));
	if (tmp_cfg) {
		bzero (tmp_cfg, sizeof (struct config_file));
		tmp_cfg->cfg_pool = memory_pool_new (memory_pool_get_size ());
		init_defaults (tmp_cfg);
		cfg_file = memory_pool_strdup (tmp_cfg->cfg_pool, rspamd->cfg->cfg_name);
		f = fopen (rspamd->cfg->cfg_name, "r");
		if (f == NULL) {
			msg_warn ("cannot open file: %s", rspamd->cfg->cfg_name);
		}
		else {
			yyin = f;
			yyrestart (yyin);

			if (yyparse () != 0 || yynerrs > 0) {
				msg_warn ("yyparse: cannot parse config file, %d errors", yynerrs);
				fclose (f);
			}
			else {
				msg_debug ("replacing config");
				free_config (rspamd->cfg);
				close_log ();
				g_free (rspamd->cfg);
				rspamd->cfg = tmp_cfg;
				rspamd->cfg->cfg_name = cfg_file;
				config_logger (rspamd, FALSE);
				open_log ();
				msg_info ("config rereaded successfully");
			}
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
		g_queue_push_head (cf->active_workers, cur);
		cur->srv = rspamd;
		cur->type = cf->type;
		cur->pid = fork ();
		cur->cf = cf;
		cur->pending = FALSE;
		switch (cur->pid) {
		case 0:
			/* Update pid for logging */
			update_log_pid ();
			/* Drop privilleges */
			drop_priv (cfg);
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
			case TYPE_FUZZY:
				setproctitle ("fuzzy storage");
				pidfile_close (rspamd->pfh);
				msg_info ("starting fuzzy storage process %P", getpid ());
				start_fuzzy_storage (cur);
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
	printf ("$%s = \"%s\"\n", (char *)key, (char *)value);
}


static void
dump_cfg_vars ()
{
	g_hash_table_foreach (cfg->variables, dump_all_variables, NULL);
}

static int
create_listen_socket (struct in_addr *addr, int port, int family, char *path)
{
	int                             listen_sock = -1;
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

static void
spawn_workers (struct rspamd_main *rspamd, gboolean make_sockets)
{
	GList                          *cur;
	struct worker_conf             *cf;
	int                             i, listen_sock;

	cur = cfg->workers;

	while (cur) {
		cf = cur->data;

		if (make_sockets && cf->has_socket) {
			/* Create listen socket */
			listen_sock = create_listen_socket (&cf->bind_addr, cf->bind_port, cf->bind_family, cf->bind_host);
			if (listen_sock == -1) {
				exit (-errno);
			}
			cf->listen_sock = listen_sock;
		}
		
		if (cf->type == TYPE_FUZZY) {
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

static const char              *
get_process_type (enum process_type type)
{
	switch (type) {
	case TYPE_MAIN:
		return "main";
	case TYPE_WORKER:
		return "worker";
	case TYPE_FUZZY:
		return "fuzzy";
	case TYPE_CONTROLLER:
		return "controller";
	case TYPE_LMTP:
		return "lmtp";
	}

	return NULL;
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
	int                            res = 0;

	waitpid (w->pid, &res, 0);

	msg_debug ("%s process %P terminated", get_process_type (w->type), w->pid);
	g_free (w);

	return TRUE;
}

int
main (int argc, char **argv, char **env)
{
	struct rspamd_main             *rspamd;
	struct module_ctx              *cur_module = NULL;
	int                             res = 0, i;
	struct sigaction                signals;
	struct rspamd_worker           *cur;
	struct rlimit                   rlim;
	struct metric                  *metric;
	struct cache_item              *item;
	struct filter                  *filt;
	FILE                           *f;
	pid_t                           wrk;
	GList                          *l;
#ifndef WITHOUT_PERL
	char                           *args[] = { "", "-e", "0", NULL };
#endif

#ifdef HAVE_SA_SIGINFO
	signals_info = g_queue_new ();
#endif
	rspamd = (struct rspamd_main *)g_malloc (sizeof (struct rspamd_main));
	bzero (rspamd, sizeof (struct rspamd_main));
	rspamd->server_pool = memory_pool_new (memory_pool_get_size ());
	cfg = (struct config_file *)g_malloc (sizeof (struct config_file));
	rspamd->cfg = cfg;
	if (!rspamd || !rspamd->cfg) {
		fprintf (stderr, "Cannot allocate memory\n");
		exit (-errno);
	}

	do_terminate = 0;
	do_restart = 0;
	child_dead = 0;
	do_reopen_log = 0;

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

	if (cfg->config_test) {
		cfg->log_level = G_LOG_LEVEL_DEBUG;
	}
	else {
		cfg->log_level = G_LOG_LEVEL_CRITICAL;
	}

#ifdef HAVE_SETLOCALE
	/* Set locale setting to C locale to avoid problems in future */
	setlocale (LC_ALL, "C");
	setlocale (LC_CTYPE, "C");
	setlocale (LC_MESSAGES, "C");
	setlocale (LC_TIME, "C");
#endif

	/* First set logger to console logger */
	rspamd_set_logger (RSPAMD_LOG_CONSOLE, rspamd->cfg);
	(void)open_log ();
	g_log_set_default_handler (rspamd_glib_log_function, cfg);

#ifndef HAVE_SETPROCTITLE
	init_title (argc, argv, environ);
#endif
	init_lua (cfg);

	f = fopen (rspamd->cfg->cfg_name, "r");
	if (f == NULL) {
		msg_err ("cannot open file: %s", rspamd->cfg->cfg_name);
		return EBADF;
	}
	yyin = f;

	if (yyparse () != 0 || yynerrs > 0) {
		msg_err ("cannot parse config file, %d errors", yynerrs);
		return EBADF;
	}

	fclose (f);
	/* Dump it to xml */
	if (get_config_checksum (rspamd->cfg)) {
		xml_dump_config (rspamd->cfg, "/tmp/rspamd.xml");
	}
	/* Do post-load actions */
	post_load_config (rspamd->cfg);
	/* Init counters */
	counters = rspamd_hash_new_shared (rspamd->server_pool, g_str_hash, g_str_equal, 64);

	/* Init C modules */
	l = g_list_first (rspamd->cfg->filters);

	while (l) {
		filt = l->data;
		if (filt->module) {
			cur_module = memory_pool_alloc (rspamd->cfg->cfg_pool, sizeof (struct module_ctx));
			if (filt->module->module_init_func (cfg, &cur_module) == 0) {
				g_hash_table_insert (cfg->c_modules, (gpointer) filt->module->name, cur_module);
			}
		}
		l = g_list_next (l);
	}

	if (cfg->config_test || dump_vars || dump_cache) {
		/* Init events to test modules */
		event_init ();
		res = TRUE;
		/* Perform modules configuring */
		l = g_list_first (rspamd->cfg->filters);

		while (l) {
			filt = l->data;
			if (filt->module) {
				if (!filt->module->module_config_func (cfg)) {
					res = FALSE;
				}
			}
			l = g_list_next (l);
		}
		init_lua_filters (cfg);
		if (dump_vars) {
			dump_cfg_vars ();
		}
		if (dump_cache) {
			l = g_list_first (cfg->metrics_list);
			while (l) {
				metric = l->data;
				if (!init_symbols_cache (cfg->cfg_pool, metric->cache, metric->cache_filename)) {
					exit (EXIT_FAILURE);
				}
				if (metric->cache) {
					printf ("Cache for metric: %s\n", metric->name);
					printf ("-----------------------------------------------------------------\n");
					printf ("| Pri  | Symbol                | Weight | Frequency | Avg. time |\n");
					for (i = 0; i < metric->cache->used_items; i++) {
						item = &metric->cache->items[i];
						printf ("-----------------------------------------------------------------\n");
						printf ("| %3d | %22s | %6.1f | %9d | %9.3f |\n", i, item->s->symbol, item->s->weight, item->s->frequency, item->s->avg_time);

					}
					printf ("-----------------------------------------------------------------\n");
				}
				l = g_list_next (l);
			}
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

	msg_info ("rspamd " RVERSION " is starting");
	rspamd->cfg->cfg_name = memory_pool_strdup (rspamd->cfg->cfg_pool, rspamd->cfg->cfg_name);

	/* Strictly set temp dir */
	if (!rspamd->cfg->temp_dir) {
		msg_warn ("tempdir is not set, trying to use $TMPDIR");
		rspamd->cfg->temp_dir = memory_pool_strdup (rspamd->cfg->cfg_pool, getenv ("TMPDIR"));

		if (!rspamd->cfg->temp_dir) {
			msg_warn ("$TMPDIR is empty too, using /tmp as default");
			rspamd->cfg->temp_dir = memory_pool_strdup (rspamd->cfg->cfg_pool, "/tmp");
		}
	}

	if (!rspamd->cfg->no_fork && daemon (0, 0) == -1) {
		fprintf (stderr, "Cannot daemonize\n");
		exit (-errno);
	}

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
	rspamd->statfile_pool = statfile_pool_new (cfg->max_statfile_size);

	event_init ();
	g_mime_init (0);

	/* Perform modules configuring */
	l = g_list_first (rspamd->cfg->filters);

	while (l) {
		filt = l->data;
		if (filt->module) {
			if (!filt->module->module_config_func (cfg)) {
				res = FALSE;
			}
		}
		l = g_list_next (l);
	}

#ifndef WITHOUT_PERL
	/* Init perl interpreter */
	dTHXa (perl_interpreter);
	PERL_SYS_INIT3 (&argc, &argv, &env);
	perl_interpreter = perl_alloc ();
	if (perl_interpreter == NULL) {
		msg_err ("cannot allocate perl interpreter, %s", strerror (errno));
		exit (-errno);
	}

	PERL_SET_CONTEXT (perl_interpreter);
	perl_construct (perl_interpreter);
	perl_parse (perl_interpreter, xs_init, 3, args, NULL);
	init_perl_filters (cfg);
#endif

	init_lua_filters (cfg);

	/* Init symbols cache for each metric */
	l = g_list_first (cfg->metrics_list);
	while (l) {
		metric = l->data;
		if (metric->cache && !init_symbols_cache (cfg->cfg_pool, metric->cache, metric->cache_filename)) {
			exit (EXIT_FAILURE);
		}
		l = g_list_next (l);
	}

	flush_log_buf ();

	rspamd->workers = g_hash_table_new (g_direct_hash, g_direct_equal);
	spawn_workers (rspamd, TRUE);

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
				g_queue_remove (cur->cf->active_workers, cur);

				if (WIFEXITED (res) && WEXITSTATUS (res) == 0) {
					/* Normal worker termination, do not fork one more */
					msg_info ("%s process %P terminated normally", get_process_type (cur->type), cur->pid);
				}
				else {
					if (WIFSIGNALED (res)) {
						msg_warn ("%s process %P terminated abnormally by signal: %d", get_process_type (cur->type), cur->pid, WTERMSIG (res));
					}
					else {
						msg_warn ("%s process %P terminated abnormally", get_process_type (cur->type), cur->pid);
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
			do_reopen_log = 1;

			msg_info ("rspamd " RVERSION " is restarting");
			g_hash_table_foreach (rspamd->workers, kill_old_workers, NULL);
			spawn_workers (rspamd, FALSE);

		}
		if (got_alarm) {
			got_alarm = 0;
			fork_delayed (rspamd);
		}
	}

	/* Wait for workers termination */
	g_hash_table_foreach_remove (rspamd->workers, wait_for_workers, NULL);

	msg_info ("terminating...");

	close_log ();

	free_config (rspamd->cfg);
	g_free (rspamd->cfg);
	g_free (rspamd);

	return (res);
}

/* 
 * vi:ts=4 
 */
