
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#include <netinet/in.h>
#include <syslog.h>
#include <fcntl.h>
#include <netdb.h>

#include "util.h"
#include "main.h"
#include "upstream.h"
#include "cfg_file.h"

static 
void sig_handler (int signo)
{
	switch (signo) {
		case SIGINT:
		case SIGTERM:
			_exit (1);
			break;
	}
}

void
start_worker (struct rspamd_worker *worker, int listen_sock)
{
	struct sigaction signals;
	struct config_file *cfg = worker->srv->cfg;
	worker->srv->pid = getpid ();
	worker->srv->type = TYPE_WORKER;

	init_signals (&signals, sig_handler);
	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);

	/* Send SIGUSR2 to parent */
	kill (getppid (), SIGUSR2);

}

/* 
 * vi:ts=4 
 */
