#ifndef UTIL_H
#define UTIL_H

#include <sys/types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/time.h>

#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <signal.h>

#include "main.h"

struct config_file;

/* Create socket and bind it to specified address and port */
int make_socket(const char *, u_short );
/* Create and bind unix socket */
int make_unix_socket (const char *, struct sockaddr_un *);
/* Parse command line arguments using getopt (3) */
void read_cmd_line (int , char **, struct config_file *);
/* Write pid to file */
int write_pid (struct rspamd_main *);
/* Make specified socket non-blocking */
int event_make_socket_nonblocking(int);
/* Init signals */
void init_signals (struct sigaction *, sig_t);
/* Send specified signal to each worker */
void pass_signal_worker (struct workq *, int );

#ifndef HAVE_SETPROCTITLE
int init_title(int argc, char *argv[], char *envp[]);
int setproctitle(const char *fmt, ...);
#endif

#ifndef HAVE_PIDFILE
struct pidfh {
	int pf_fd;
	char    pf_path[MAXPATHLEN + 1];
 	__dev_t pf_dev;
 	ino_t   pf_ino;
};
struct pidfh *pidfile_open(const char *path, mode_t mode, pid_t *pidptr);
int pidfile_write(struct pidfh *pfh);
int pidfile_close(struct pidfh *pfh);
int pidfile_remove(struct pidfh *pfh);
#endif

#endif
