
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/param.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif
#include <syslog.h>

#include <EXTERN.h>               /* from the Perl distribution     */
#include <perl.h>                 /* from the Perl distribution     */

#include "main.h"
#include "cfg_file.h"
#include "util.h"

/* 2 seconds to fork new process in place of dead one */
#define SOFT_FORK_TIME 2

struct config_file *cfg;

static void sig_handler (int );
static struct rspamd_worker * fork_worker (struct rspamd_main *, int, int, enum process_type);
	
sig_atomic_t do_restart;
sig_atomic_t do_terminate;
sig_atomic_t child_dead;
sig_atomic_t child_ready;
sig_atomic_t got_alarm;

extern int yynerrs;
extern FILE *yyin;
extern void boot_DynaLoader (pTHX_ CV* cv);
extern void boot_Socket (pTHX_ CV* cv);

PerlInterpreter *perl_interpreter;
/* XXX: remove this shit when it would be clear why perl need this line */
PerlInterpreter *my_perl;

/* List of workers that are pending to start */
static GList *workers_pending = NULL;

static 
void sig_handler (int signo)
{
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
			child_ready = 1;
			break;
		case SIGALRM:
			got_alarm = 1;
			break;
	}
}

void
xs_init(pTHX)
{
	dXSUB_SYS;
	/* DynaLoader is a special case */
	newXS ("DynaLoader::boot_DynaLoader", boot_DynaLoader, __FILE__);
}

static void
init_filters (struct config_file *cfg)
{
	struct perl_module *module;

	LIST_FOREACH (module, &cfg->perl_modules, next) {
		if (module->path) {
			require_pv (module->path);
		}
	}
}

static struct rspamd_worker *
fork_worker (struct rspamd_main *rspamd, int listen_sock, int reconfig, enum process_type type) 
{
	struct rspamd_worker *cur;
	char *cfg_file;
	FILE *f;
	struct config_file *tmp_cfg;
	/* Starting worker process */
	cur = (struct rspamd_worker *)g_malloc (sizeof (struct rspamd_worker));
	if (cur) {
		/* Reconfig needed */
		if (reconfig) {
			tmp_cfg = (struct config_file *) g_malloc (sizeof (struct config_file));
			if (tmp_cfg) {
        		bzero (tmp_cfg, sizeof (struct config_file));
				tmp_cfg->cfg_pool = memory_pool_new (32768);
        		cfg_file = memory_pool_strdup (tmp_cfg->cfg_pool, rspamd->cfg->cfg_name);
				f = fopen (rspamd->cfg->cfg_name , "r");
				if (f == NULL) {
					msg_warn ("fork_worker: cannot open file: %s", rspamd->cfg->cfg_name );
				}
				else {
					yyin = f;
					yyrestart (yyin);

					if (yyparse() != 0 || yynerrs > 0) {
						msg_warn ("fork_worker: yyparse: cannot parse config file, %d errors", yynerrs);
						fclose (f);
					}
					else {
        				free_config (rspamd->cfg);
						g_free (rspamd->cfg);
						rspamd->cfg = tmp_cfg;
        				rspamd->cfg->cfg_name = cfg_file;
					}
				}
			}
		}
		bzero (cur, sizeof (struct rspamd_worker));
		TAILQ_INSERT_HEAD (&rspamd->workers, cur, next);
		cur->srv = rspamd;
		cur->type = type;
		cur->pid = fork();
		switch (cur->pid) {
			case 0:
				/* TODO: add worker code */
				switch (type) {
					case TYPE_CONTROLLER:
						setproctitle ("controller process");
						pidfile_close (rspamd->pfh);
						msg_info ("fork_worker: starting controller process %d", getpid ());
						start_controller (cur);
						break;
					case TYPE_WORKER:
					default:
						setproctitle ("worker process");
						pidfile_close (rspamd->pfh);
						msg_info ("fork_worker: starting worker process %d", getpid ());
						start_worker (cur, listen_sock);
						break;
				}
				break;
			case -1:
				msg_err ("fork_worker: cannot fork main process. %m");
				pidfile_remove (rspamd->pfh);
				exit (-errno);
				break;
		}
	}

	return cur;
}

static void
delay_fork (enum process_type type)
{
	workers_pending = g_list_prepend (workers_pending, GINT_TO_POINTER (type));
	(void)alarm (SOFT_FORK_TIME);
}

static void
fork_delayed (struct rspamd_main *rspamd, int listen_sock)
{
	GList *cur;

	while (workers_pending != NULL) {
		cur = workers_pending;
		workers_pending = g_list_remove_link (workers_pending, cur);
		fork_worker (rspamd, listen_sock, 0, GPOINTER_TO_INT (cur->data));
		g_list_free_1 (cur);
	}
}

int 
main (int argc, char **argv, char **env)
{
	struct rspamd_main *rspamd;
	struct module_ctx *cur_module = NULL;
	int res = 0, i, listen_sock;
	struct sigaction signals;
	struct rspamd_worker *cur, *cur_tmp, *active_worker;
	struct sockaddr_un *un_addr;
	FILE *f;
	pid_t wrk;
	char *args[] = { "", "-e", "0", NULL };

	rspamd = (struct rspamd_main *)g_malloc (sizeof (struct rspamd_main));
	bzero (rspamd, sizeof (struct rspamd_main));
	rspamd->server_pool = memory_pool_new (memory_pool_get_size ());
	cfg = (struct config_file *)g_malloc (sizeof (struct config_file));
	rspamd->cfg = cfg;
	if (!rspamd || !rspamd->cfg) {
		fprintf(stderr, "Cannot allocate memory\n");
		exit(-errno);
	}
	
	do_terminate = 0;
	do_restart = 0;
	child_dead = 0;
	child_ready = 0;
	do_reopen_log = 0;
	active_worker = NULL;

	rspamd->stat = memory_pool_alloc_shared (rspamd->server_pool, sizeof (struct rspamd_stat));
	bzero (rspamd->stat, sizeof (struct rspamd_stat));

	bzero (rspamd->cfg, sizeof (struct config_file));
	rspamd->cfg->cfg_pool = memory_pool_new (memory_pool_get_size ());
	init_defaults (rspamd->cfg);

	bzero (&signals, sizeof (struct sigaction));

	rspamd->cfg->cfg_name = memory_pool_strdup (rspamd->cfg->cfg_pool, FIXED_CONFIG_FILE);
	read_cmd_line (argc, argv, rspamd->cfg);

    msg_warn ("(main) starting...");

	#ifndef HAVE_SETPROCTITLE
	init_title (argc, argv, environ);
	#endif
	
	f = fopen (rspamd->cfg->cfg_name , "r");
	if (f == NULL) {
		msg_warn ("cannot open file: %s", rspamd->cfg->cfg_name );
		return EBADF;
	}
	yyin = f;

	if (yyparse() != 0 || yynerrs > 0) {
		msg_warn ("yyparse: cannot parse config file, %d errors", yynerrs);
		return EBADF;
	}

	fclose (f);
	rspamd->cfg->cfg_name = memory_pool_strdup (rspamd->cfg->cfg_pool, rspamd->cfg->cfg_name );

	/* Strictly set temp dir */
    if (!rspamd->cfg->temp_dir) {
		msg_warn ("tempdir is not set, trying to use $TMPDIR");
		rspamd->cfg->temp_dir = memory_pool_strdup (rspamd->cfg->cfg_pool, getenv ("TMPDIR"));

		if (!rspamd->cfg->temp_dir) {
			msg_warn ("$TMPDIR is empty too, using /tmp as default");
	    	rspamd->cfg->temp_dir = memory_pool_strdup (rspamd->cfg->cfg_pool, "/tmp");
		}
    }

	switch (cfg->log_type) {
		case RSPAMD_LOG_CONSOLE:
			if (!rspamd->cfg->no_fork) {
				fprintf (stderr, "Cannot log to console while daemonized, disable logging");
				cfg->log_fd = -1;
			}
			else {
				cfg->log_fd = 2;
			}
			g_log_set_default_handler (file_log_function, cfg);
			break;
		case RSPAMD_LOG_FILE:
			if (cfg->log_file == NULL || open_log (cfg) == -1) {
				fprintf (stderr, "Fatal error, cannot open logfile, exiting");
				exit (EXIT_FAILURE);
			}
			g_log_set_default_handler (file_log_function, cfg);
			break;
		case RSPAMD_LOG_SYSLOG:
			if (open_log (cfg) == -1) {
				fprintf (stderr, "Fatal error, cannot open syslog facility, exiting");
				exit (EXIT_FAILURE);
			}
			g_log_set_default_handler (syslog_log_function, cfg);
			break;
	}

	if (!rspamd->cfg->no_fork && daemon (1, 1) == -1) {
		fprintf (stderr, "Cannot daemonize\n");
		exit (-errno);
	}

	if (write_pid (rspamd) == -1) {
		msg_err ("main: cannot write pid file %s", rspamd->cfg->pid_file);
		exit (-errno);
	}

	/* Init C modules */
	for (i = 0; i < MODULES_NUM; i ++) {
		cur_module = memory_pool_alloc (rspamd->cfg->cfg_pool, sizeof (struct module_ctx));
		if (modules[i].module_init_func(cfg, &cur_module) == 0) {
			g_hash_table_insert (cfg->c_modules, (gpointer)modules[i].name, cur_module);
		}
	}

	rspamd->pid = getpid();
	rspamd->type = TYPE_MAIN;
	
	init_signals (&signals, sig_handler);
	/* Init perl interpreter */
	PERL_SYS_INIT3 (&argc, &argv, &env);
	perl_interpreter = perl_alloc ();
	if (perl_interpreter == NULL) {
		msg_err ("main: cannot allocate perl interpreter, %m");
		exit (-errno);
	}

	my_perl = perl_interpreter;
	PERL_SET_CONTEXT (perl_interpreter);
	perl_construct (perl_interpreter);
	PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
	perl_parse (perl_interpreter, xs_init, 3, args, NULL);
	/* Block signals to use sigsuspend in future */
	sigprocmask(SIG_BLOCK, &signals.sa_mask, NULL);

	if (rspamd->cfg->bind_family == AF_INET) {
		if ((listen_sock = make_socket (&rspamd->cfg->bind_addr, rspamd->cfg->bind_port)) == -1) {
			msg_err ("main: cannot create tcp listen socket. %m");
			exit(-errno);
		}
	}
	else {
		un_addr = (struct sockaddr_un *) g_malloc (sizeof (struct sockaddr_un));
		if (!un_addr || (listen_sock = make_unix_socket (rspamd->cfg->bind_host, un_addr)) == -1) {
			msg_err ("main: cannot create unix listen socket. %m");
			exit(-errno);
		}
	}

	if (listen (listen_sock, -1) == -1) {
		msg_err ("main: cannot listen on socket. %m");
		exit(-errno);
	}
	
	TAILQ_INIT (&rspamd->workers);

	setproctitle ("main process");

	/* Init statfile pool */
	rspamd->statfile_pool = statfile_pool_new (cfg->max_statfile_size);
	
	for (i = 0; i < cfg->workers_number; i++) {
		fork_worker (rspamd, listen_sock, 0, TYPE_WORKER);
	}
	/* Start controller if enabled */
	if (cfg->controller_enabled) {
		fork_worker (rspamd, listen_sock, 0, TYPE_CONTROLLER);
	}

	/* Signal processing cycle */
	for (;;) {
		msg_debug ("main: calling sigsuspend");
		sigemptyset (&signals.sa_mask);
		sigsuspend (&signals.sa_mask);
		if (do_terminate) {
			msg_debug ("main: catch termination signal, waiting for childs");
			pass_signal_worker (&rspamd->workers, SIGTERM);
			break;
		}
		if (child_dead) {
			child_dead = 0;
			msg_debug ("main: catch SIGCHLD signal, finding terminated worker");
			/* Remove dead child form childs list */
			wrk = waitpid (0, &res, 0);
			TAILQ_FOREACH_SAFE (cur, &rspamd->workers, next, cur_tmp) {
				if (wrk == cur->pid) {
					/* Catch situations if active worker is abnormally terminated */
					if (cur == active_worker) {
						active_worker = NULL;
					}
					TAILQ_REMOVE(&rspamd->workers, cur, next);
					if (WIFEXITED (res) && WEXITSTATUS (res) == 0) {
						/* Normal worker termination, do not fork one more */
						msg_info ("main: %s process %d terminated normally", 
									(cur->type == TYPE_WORKER) ? "worker" : "controller", cur->pid);
					}
					else {
						if (WIFSIGNALED (res)) {
							msg_warn ("main: %s process %d terminated abnormally by signal: %d", 
										(cur->type == TYPE_WORKER) ? "worker" : "controller",
										cur->pid, WTERMSIG(res));
						}
						else {
							msg_warn ("main: %s process %d terminated abnormally", 
										(cur->type == TYPE_WORKER) ? "worker" : "controller", cur->pid);
						}
						/* Fork another worker in replace of dead one */
						delay_fork (cur->type);
					}
					g_free (cur);
				}
			}
		}
		if (do_restart) {	
			do_restart = 0;

			if (active_worker == NULL) {
				/* Start new worker that would reread configuration*/
				active_worker = fork_worker (rspamd, listen_sock, 1, TYPE_WORKER);
			}
			/* Do not start new workers untill active worker is not ready for accept */
		}
		if (child_ready) {
			child_ready = 0;

			if (active_worker != NULL) {
				msg_info ("main: worker process %d has been successfully started", active_worker->pid);
				TAILQ_FOREACH_SAFE (cur, &rspamd->workers, next, cur_tmp) {
					if (cur != active_worker && !cur->is_dying && cur->type == TYPE_WORKER) {
						/* Send to old workers SIGUSR2 */
						kill (cur->pid, SIGUSR2);
						cur->is_dying = 1;
					}
				}
				active_worker = NULL;
			}
		}
		if (got_alarm) {
			got_alarm = 0;
			fork_delayed (rspamd, listen_sock);
		}
	}

	/* Wait for workers termination */
	while (!TAILQ_EMPTY(&rspamd->workers)) {
		cur = TAILQ_FIRST(&rspamd->workers);
		waitpid (cur->pid, &res, 0);
		msg_debug ("main(cleaning): worker process %d terminated", cur->pid);
		TAILQ_REMOVE(&rspamd->workers, cur, next);
		g_free(cur);
	}
	
	msg_info ("main: terminating...");


	if (rspamd->cfg->bind_family == AF_UNIX) {
		unlink (rspamd->cfg->bind_host);
	}

	free_config (rspamd->cfg);
	g_free (rspamd->cfg);
	g_free (rspamd);

	return (res);
}

/* 
 * vi:ts=4 
 */
