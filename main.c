
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

struct config_file *cfg;

static void sig_handler (int );
static struct rspamd_worker * fork_worker (struct rspamd_main *, int, int, enum process_type);
	
sig_atomic_t do_restart;
sig_atomic_t do_terminate;
sig_atomic_t child_dead;
sig_atomic_t child_ready;

extern int yynerrs;
extern FILE *yyin;
extern void boot_DynaLoader (pTHX_ CV* cv);
extern void boot_Socket (pTHX_ CV* cv);

PerlInterpreter *perl_interpreter;
/* XXX: remove this shit when it would be clear why perl need this line */
PerlInterpreter *my_perl;

static 
void sig_handler (int signo)
{
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
		case SIGUSR2:
			child_ready = 1;
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
        		cfg_file = strdup (rspamd->cfg->cfg_name);
        		bzero (tmp_cfg, sizeof (struct config_file));
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
		cur->pid = fork();
		switch (cur->pid) {
			case 0:
				/* TODO: add worker code */
				switch (type) {
					case TYPE_WORKER:
					default:
						setproctitle ("worker process");
						pidfile_close (rspamd->pfh);
						msg_info ("fork_worker: starting worker process %d", getpid ());
						cur->type = TYPE_WORKER;
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

int 
main (int argc, char **argv)
{
	struct rspamd_main *rspamd;
	struct c_module *cur_module = NULL;
	int res = 0, i, listen_sock;
	struct sigaction signals;
	struct rspamd_worker *cur, *cur_tmp, *active_worker;
	struct sockaddr_un *un_addr;
	FILE *f;
	pid_t wrk;
	char *args[] = { "", "-e", "0", NULL };

	rspamd = (struct rspamd_main *)g_malloc (sizeof (struct rspamd_main));
	bzero (rspamd, sizeof (struct rspamd_main));
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
	active_worker = NULL;

	bzero (rspamd->cfg, sizeof (struct config_file));
	init_defaults (rspamd->cfg);

	bzero (&signals, sizeof (struct sigaction));

	rspamd->cfg->cfg_name = strdup (FIXED_CONFIG_FILE);
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
	rspamd->cfg->cfg_name = strdup (rspamd->cfg->cfg_name );

	/* Strictly set temp dir */
    if (!rspamd->cfg->temp_dir) {
		msg_warn ("tempdir is not set, trying to use $TMPDIR");
		rspamd->cfg->temp_dir = getenv ("TMPDIR");

		if (!rspamd->cfg->temp_dir) {
	    	rspamd->cfg->temp_dir = strdup ("/tmp");
		}
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
		cur_module = g_malloc (sizeof (struct c_module));
		cur_module->name = modules[i].name;
		if (modules[i].module_init_func(cfg, &cur_module->ctx) == 0) {
			LIST_INSERT_HEAD (&cfg->c_modules, cur_module, next);
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
		if ((listen_sock = make_socket (rspamd->cfg->bind_host, rspamd->cfg->bind_port)) == -1) {
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
	
	for (i = 0; i < cfg->workers_number; i++) {
		fork_worker (rspamd, listen_sock, 0, TYPE_WORKER);
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
						msg_info ("main: worker process %d terminated normally", cur->pid);
					}
					else {
						if (WIFSIGNALED (res)) {
							msg_warn ("main: worker process %d terminated abnormally by signal: %d", 
										cur->pid, WTERMSIG(res));
						}
						else {
							msg_warn ("main: worker process %d terminated abnormally", cur->pid);
						}
						/* Fork another worker in replace of dead one */
						fork_worker (rspamd, listen_sock, 0, cur->type);
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
					if (cur != active_worker && !cur->is_dying) {
						/* Send to old workers SIGUSR2 */
						kill (cur->pid, SIGUSR2);
						cur->is_dying = 1;
					}
				}
				active_worker = NULL;
			}
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
