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
#include "perl.h"
#include "lmtp.h"

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
extern void xs_init(pTHX);


extern PerlInterpreter *perl_interpreter;

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

static void 
read_cmd_line (int argc, char **argv, struct config_file *cfg)
{
	int ch;
	while ((ch = getopt(argc, argv, "thfc:u:g:")) != -1) {
        switch (ch) {
            case 'f':
                cfg->no_fork = 1;
                break;
            case 'c':
                if (optarg && cfg->cfg_name) {
                    cfg->cfg_name = memory_pool_strdup (cfg->cfg_pool, optarg);
                }
                break;
			case 't':
				cfg->config_test = 1;
				break;
			case 'u':
				if (optarg) {
					cfg->rspamd_user = memory_pool_strdup (cfg->cfg_pool, optarg);
				}
				break;
			case 'g':
				if (optarg) {
					cfg->rspamd_group = memory_pool_strdup (cfg->cfg_pool, optarg);
				}
				break;
            case 'h':
            case '?':
            default:
                /* Show help message and exit */
                printf ("Rspamd version " RVERSION "\n"
                        "Usage: rspamd [-t] [-h] [-n] [-f] [-c config_file]\n"
                        "-h:        This help message\n"
						"-t:        Do config test and exit\n"
                        "-f:        Do not daemonize main process\n"
                        "-c:        Specify config file (./rspamd.conf is used by default)\n"
						"-u:        User to run rspamd as\n"
						"-g:        Group to run rspamd as\n");
                exit (0);
                break;
        }
    }
}

static void
drop_priv (struct config_file *cfg) 
{
	struct passwd *pwd;
	struct group *grp;

	if (geteuid () == 0 && cfg->rspamd_user) {
		pwd = getpwnam (cfg->rspamd_user);
		if (pwd == NULL) {
			msg_err ("drop_priv: user specified does not exists (%s), aborting", strerror (errno));
			exit (-errno);
		}
		if (cfg->rspamd_group) {
			grp = getgrnam (cfg->rspamd_group);
			if (grp == NULL) {
				msg_err ("drop_priv: group specified does not exists (%s), aborting", strerror (errno));
				exit (-errno);
			}
			if (setgid (grp->gr_gid) == -1) {
				msg_err ("drop_priv: cannot setgid to %d (%s), aborting", (int)grp->gr_gid, strerror (errno));
				exit (-errno);
			}
			if (initgroups(cfg->rspamd_user, grp->gr_gid) == -1) {
				msg_err ("drop_priv: initgroups failed (%s), aborting", strerror (errno));
				exit (-errno);
			}
		}
		if (setuid (pwd->pw_uid) == -1) {
			msg_err ("drop_priv: cannot setuid to %d (%s), aborting", (int)pwd->pw_uid, strerror (errno));
			exit (-errno);
		}
	}
}

static void
config_logger (struct rspamd_main *rspamd, gboolean is_fatal)
{
	switch (rspamd->cfg->log_type) {
		case RSPAMD_LOG_CONSOLE:
			if (!rspamd->cfg->no_fork) {
				if (is_fatal) {
					fprintf (stderr, "Cannot log to console while daemonized, disable logging");
				}
				rspamd->cfg->log_fd = -1;
			}
			else {
				rspamd->cfg->log_fd = 2;
			}
			g_log_set_default_handler (file_log_function, rspamd->cfg);
			break;
		case RSPAMD_LOG_FILE:
			if (rspamd->cfg->log_file == NULL || open_log (rspamd->cfg) == -1) {
				if (is_fatal) {
					fprintf (stderr, "Fatal error, cannot open logfile, exiting");
					exit (EXIT_FAILURE);
				}
				else {
					msg_err ("config_logger: cannot log to file, logfile unaccessable");
				}
			}
			else {
				g_log_set_default_handler (file_log_function, rspamd->cfg);
			}
			break;
		case RSPAMD_LOG_SYSLOG:
			if (open_log (rspamd->cfg) == -1) {
				if (is_fatal) {
					fprintf (stderr, "Fatal error, cannot open syslog facility, exiting");
					exit (EXIT_FAILURE);
				}
				else {
					msg_err ("config_logger: cannot log to syslog");
				}
			}
			else {
				g_log_set_default_handler (syslog_log_function, rspamd->cfg);
			}
			break;
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
						config_logger (rspamd, FALSE);
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
					case TYPE_LMTP:
						setproctitle ("lmtp process");
						pidfile_close (rspamd->pfh);
						msg_info ("fork_worker: starting lmtp process %d", getpid ());
						start_lmtp_worker (cur);
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
				msg_err ("fork_worker: cannot fork main process. %s", strerror (errno));
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

	if (cfg->config_test) {
		cfg->log_level = G_LOG_LEVEL_DEBUG;
	}
	else {
		cfg->log_level = G_LOG_LEVEL_CRITICAL;
	}
	
	/* First set logger to console logger */
	cfg->log_fd = STDERR_FILENO;
	g_log_set_default_handler (file_log_function, cfg);

	#ifndef HAVE_SETPROCTITLE
	init_title (argc, argv, environ);
	#endif
	
	f = fopen (rspamd->cfg->cfg_name , "r");
	if (f == NULL) {
		msg_err ("main: cannot open file: %s", rspamd->cfg->cfg_name );
		return EBADF;
	}
	yyin = f;

	if (yyparse() != 0 || yynerrs > 0) {
		msg_err ("main: cannot parse config file, %d errors", yynerrs);
		return EBADF;
	}

	fclose (f);

	if (cfg->config_test) {
		fprintf (stderr, "syntax OK\n");
		return EXIT_SUCCESS;
	}

	/* Create listen socket */
	if (rspamd->cfg->bind_family == AF_INET) {
		if ((listen_sock = make_tcp_socket (&rspamd->cfg->bind_addr, rspamd->cfg->bind_port, TRUE)) == -1) {
			msg_err ("main: cannot create tcp listen socket. %s", strerror (errno));
			exit(-errno);
		}
	}
	else {
		un_addr = (struct sockaddr_un *) g_malloc (sizeof (struct sockaddr_un));
		if (!un_addr || (listen_sock = make_unix_socket (rspamd->cfg->bind_host, un_addr, TRUE)) == -1) {
			msg_err ("main: cannot create unix listen socket. %s", strerror (errno));
			exit(-errno);
		}
	}

	if (listen (listen_sock, -1) == -1) {
		msg_err ("main: cannot listen on socket. %s", strerror (errno));
		exit(-errno);
	}

	/* Drop privilleges */
	drop_priv (cfg);
	
	config_logger (rspamd, TRUE);

	msg_info ("main: starting...");
	rspamd->cfg->cfg_name = memory_pool_strdup (rspamd->cfg->cfg_pool, rspamd->cfg->cfg_name );

	/* Strictly set temp dir */
	if (!rspamd->cfg->temp_dir) {
		msg_warn ("main: tempdir is not set, trying to use $TMPDIR");
		rspamd->cfg->temp_dir = memory_pool_strdup (rspamd->cfg->cfg_pool, getenv ("TMPDIR"));

		if (!rspamd->cfg->temp_dir) {
			msg_warn ("main: $TMPDIR is empty too, using /tmp as default");
			rspamd->cfg->temp_dir = memory_pool_strdup (rspamd->cfg->cfg_pool, "/tmp");
		}
	}

	if (!rspamd->cfg->no_fork && daemon (1, 1) == -1) {
		fprintf (stderr, "Cannot daemonize\n");
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


	if (write_pid (rspamd) == -1) {
		msg_err ("main: cannot write pid file %s", rspamd->cfg->pid_file);
		exit (-errno);
	}

	/* Init perl interpreter */
	dTHXa (perl_interpreter);
	PERL_SYS_INIT3 (&argc, &argv, &env);
	perl_interpreter = perl_alloc ();
	if (perl_interpreter == NULL) {
		msg_err ("main: cannot allocate perl interpreter, %s", strerror (errno));
		exit (-errno);
	}

	PERL_SET_CONTEXT (perl_interpreter);
	perl_construct (perl_interpreter);
	perl_parse (perl_interpreter, xs_init, 3, args, NULL);
	/* Block signals to use sigsuspend in future */
	sigprocmask(SIG_BLOCK, &signals.sa_mask, NULL);

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
	
	/* Start lmtp if enabled */
	if (cfg->lmtp_enable) {
		for (i = 0; i < cfg->lmtp_workers_number; i++) {
			fork_worker (rspamd, listen_sock, 0, TYPE_LMTP);
		}
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
									(cur->type != TYPE_WORKER) ? "controller" : "worker", cur->pid);
					}
					else {
						if (WIFSIGNALED (res)) {
							msg_warn ("main: %s process %d terminated abnormally by signal: %d", 
										(cur->type != TYPE_WORKER) ? "controller" : "worker",
										cur->pid, WTERMSIG(res));
						}
						else {
							msg_warn ("main: %s process %d terminated abnormally", 
										(cur->type != TYPE_WORKER) ? "controller" : "worker", cur->pid);
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
			/* Do not start new workers until active worker is not ready for accept */
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
