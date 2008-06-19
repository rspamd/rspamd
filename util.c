#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif
#include <stdarg.h>
#include <sys/file.h>
#include "util.h"
#include "cfg_file.h"

int
event_make_socket_nonblocking (int fd)
{
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		return -1;
	}
	return 0;
}

static int
make_socket_ai (struct addrinfo *ai)
{
	struct linger linger;
	int fd, on = 1, r;
	int serrno;
	
	/* Create listen socket */
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		return (-1);
	}

	if (event_make_socket_nonblocking(fd) < 0)
		goto out;

	if (fcntl(fd, F_SETFD, 1) == -1) {
		goto out;
	}

	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on, sizeof(on));
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on));
	linger.l_onoff = 1;
	linger.l_linger = 5;
	setsockopt(fd, SOL_SOCKET, SO_LINGER, (void *)&linger, sizeof(linger));
	
	r = bind(fd, ai->ai_addr, ai->ai_addrlen);

	if (r == -1) {
		if (errno != EINPROGRESS) {
			goto out;
		}
	}

	return (fd);

 out:
	serrno = errno;
	close(fd);
	errno = serrno;
	return (-1);
}

int
make_socket (const char *address, u_short port)
{
	int fd;
	struct addrinfo ai, *aitop = NULL;
	char strport[NI_MAXSERV];
	int ai_result;

	memset(&ai, 0, sizeof (ai));
	ai.ai_family = AF_INET;
	ai.ai_socktype = SOCK_STREAM;
	ai.ai_flags = AI_PASSIVE;
	snprintf(strport, sizeof (strport), "%d", port);
	if ((ai_result = getaddrinfo(address, strport, &ai, &aitop)) != 0) {
		return (-1);
	}

	fd = make_socket_ai(aitop);

	freeaddrinfo(aitop);

	return (fd);
}

int
make_unix_socket (const char *path, struct sockaddr_un *addr)
{
	size_t len = strlen (path);
	int sock;

	if (len > sizeof (addr->sun_path) - 1) return -1;
	
	#ifdef FREEBSD
	addr->sun_len = sizeof (struct sockaddr_un);
	#endif

	addr->sun_family = AF_UNIX;
	
	strncpy (addr->sun_path, path, len);
	
	sock = socket (PF_LOCAL, SOCK_STREAM, 0);

	if (sock != -1) {
		if (bind (sock, (struct sockaddr *) addr, sizeof (struct sockaddr_un)) == -1) return -1;
	}

	return sock;
}

void 
read_cmd_line (int argc, char **argv, struct config_file *cfg)
{
	int ch;
	while ((ch = getopt(argc, argv, "hfc:")) != -1) {
        switch (ch) {
            case 'f':
                cfg->no_fork = 1;
                break;
            case 'c':
                if (optarg && cfg->cfg_name) {
                    free (cfg->cfg_name);
                    cfg->cfg_name = strdup (optarg);
                }
                break;
            case 'h':
            case '?':
            default:
                /* Show help message and exit */
                printf ("Rspamd version " RVERSION "\n"
                        "Usage: rspamd [-h] [-n] [-f] [-c config_file]\n"
                        "-h:        This help message\n"
                        "-f:        Do not daemonize main process\n"
                        "-c:        Specify config file (./rspamd.conf is used by default)\n");
                exit (0);
                break;
        }
    }
}

int
write_pid (struct rspamd_main *main)
{
	pid_t pid;
	main->pfh = pidfile_open (main->cfg->pid_file, 0644, &pid);

	if (main->pfh == NULL) {
		return -1;
	}

	pidfile_write (main->pfh);

	return 0;
}

void
init_signals (struct sigaction *signals, sig_t sig_handler)
{
	/* Setting up signal handlers */
	/* SIGUSR1 - reopen config file */
	/* SIGUSR2 - worker is ready for accept */
	sigemptyset(&signals->sa_mask);
	sigaddset(&signals->sa_mask, SIGTERM);
	sigaddset(&signals->sa_mask, SIGINT);
	sigaddset(&signals->sa_mask, SIGHUP);
	sigaddset(&signals->sa_mask, SIGCHLD);
	sigaddset(&signals->sa_mask, SIGUSR1);
	sigaddset(&signals->sa_mask, SIGUSR2);


	signals->sa_handler = sig_handler;
	sigaction (SIGTERM, signals, NULL);
	sigaction (SIGINT, signals, NULL);
	sigaction (SIGHUP, signals, NULL);
	sigaction (SIGCHLD, signals, NULL);
	sigaction (SIGUSR1, signals, NULL);
	sigaction (SIGUSR2, signals, NULL);
}

void
pass_signal_worker (struct workq *workers, int signo)
{
	struct rspamd_worker *cur;
	TAILQ_FOREACH (cur, workers, next) {
		kill (cur->pid, signo);
	}
}

void convert_to_lowercase (char *str, unsigned int size)
{
	while (size--) {
		*str = tolower (*str ++);
	}
}

#ifndef HAVE_SETPROCTITLE

static char *title_buffer = 0;
static size_t title_buffer_size = 0;
static char *title_progname, *title_progname_full;

int
setproctitle(const char *fmt, ...)
{
	if (!title_buffer || !title_buffer_size) {
		errno = ENOMEM;
		return -1;
	}

	memset (title_buffer, '\0', title_buffer_size);

	ssize_t written;

	if (fmt) {
		ssize_t written2;
		va_list ap;

		written = snprintf (title_buffer, title_buffer_size, "%s: ", title_progname);
		if (written < 0 || (size_t) written >= title_buffer_size)
			return -1;

		va_start (ap, fmt);
		written2 =
			vsnprintf (title_buffer + written,
				  title_buffer_size - written, fmt, ap);
		va_end (ap);
		if (written2 < 0
		    || (size_t) written2 >= title_buffer_size - written)
			return -1;
	} else {
		written =
			snprintf (title_buffer, title_buffer_size, "%s",
				 title_progname);
		if (written < 0 || (size_t) written >= title_buffer_size)
			return -1;
	}

	written = strlen (title_buffer);
	memset (title_buffer + written, '\0', title_buffer_size - written);

	return 0;
}

/*
  It has to be _init function, because __attribute__((constructor))
  functions gets called without arguments.
*/

int
init_title(int argc, char *argv[], char *envp[])
{
	char   *begin_of_buffer = 0, *end_of_buffer = 0;
	int     i;

	for (i = 0; i < argc; ++i) {
		if (!begin_of_buffer)
			begin_of_buffer = argv[i];
		if (!end_of_buffer || end_of_buffer + 1 == argv[i])
			end_of_buffer = argv[i] + strlen (argv[i]);
	}

	for (i = 0; envp[i]; ++i) {
		if (!begin_of_buffer)
			begin_of_buffer = envp[i];
		if (!end_of_buffer || end_of_buffer + 1 == envp[i])
			end_of_buffer = envp[i] + strlen(envp[i]);
	}

	if (!end_of_buffer)
		return 0;

	char  **new_environ = g_malloc ((i + 1) * sizeof (envp[0]));

	if (!new_environ)
		return 0;

	for (i = 0; envp[i]; ++i) {
		if (!(new_environ[i] = strdup (envp[i])))
			goto cleanup_enomem;
	}
	new_environ[i] = 0;

	if (program_invocation_name) {
		title_progname_full = strdup (program_invocation_name);

		if (!title_progname_full)
			goto cleanup_enomem;

		char   *p = strrchr (title_progname_full, '/');

		if (p)
			title_progname = p + 1;
		else
			title_progname = title_progname_full;

		program_invocation_name = title_progname_full;
		program_invocation_short_name = title_progname;
	}

	environ = new_environ;
	title_buffer = begin_of_buffer;
	title_buffer_size = end_of_buffer - begin_of_buffer;

	return 0;

    cleanup_enomem:
	for (--i; i >= 0; --i) {
		free(new_environ[i]);
	}
	free(new_environ);
	return 0;
}
#endif

#ifndef HAVE_PIDFILE
extern char * __progname;
static int _pidfile_remove(struct pidfh *pfh, int freeit);

static int
pidfile_verify(struct pidfh *pfh)
{
	struct stat sb;

	if (pfh == NULL || pfh->pf_fd == -1)
		return (-1);
	/*
	 * Check remembered descriptor.
	 */
	if (fstat(pfh->pf_fd, &sb) == -1)
		return (errno);
	if (sb.st_dev != pfh->pf_dev || sb.st_ino != pfh->pf_ino)
		return (-1);
	return (0);
}

static int
pidfile_read(const char *path, pid_t *pidptr)
{
	char buf[16], *endptr;
	int error, fd, i;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return (errno);

	i = read(fd, buf, sizeof(buf) - 1);
	error = errno;	/* Remember errno in case close() wants to change it. */
	close(fd);
	if (i == -1)
		return (error);
	else if (i == 0)
		return (EAGAIN);
	buf[i] = '\0';

	*pidptr = strtol(buf, &endptr, 10);
	if (endptr != &buf[i])
		return (EINVAL);

	return (0);
}

struct pidfh *
pidfile_open(const char *path, mode_t mode, pid_t *pidptr)
{
	struct pidfh *pfh;
	struct stat sb;
	int error, fd, len, count;
	struct timespec rqtp;

	pfh = g_malloc(sizeof(*pfh));
	if (pfh == NULL)
		return (NULL);

	if (path == NULL)
		len = snprintf(pfh->pf_path, sizeof(pfh->pf_path),
		    "/var/run/%s.pid", __progname);
	else
		len = snprintf(pfh->pf_path, sizeof(pfh->pf_path),
		    "%s", path);
	if (len >= (int)sizeof(pfh->pf_path)) {
		free(pfh);
		errno = ENAMETOOLONG;
		return (NULL);
	}

	/*
	 * Open the PID file and obtain exclusive lock.
	 * We truncate PID file here only to remove old PID immediatelly,
	 * PID file will be truncated again in pidfile_write(), so
	 * pidfile_write() can be called multiple times.
	 */
	fd = open(pfh->pf_path,
	    O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK, mode);
	flock (fd, LOCK_EX | LOCK_NB);
	if (fd == -1) {
		count = 0;
		rqtp.tv_sec = 0;
		rqtp.tv_nsec = 5000000;
		if (errno == EWOULDBLOCK && pidptr != NULL) {
		again:
			errno = pidfile_read(pfh->pf_path, pidptr);
			if (errno == 0)
				errno = EEXIST;
			else if (errno == EAGAIN) {
				if (++count <= 3) {
					nanosleep(&rqtp, 0);
					goto again;
				}
			}
		}
		free(pfh);
		return (NULL);
	}
	/*
	 * Remember file information, so in pidfile_write() we are sure we write
	 * to the proper descriptor.
	 */
	if (fstat(fd, &sb) == -1) {
		error = errno;
		unlink(pfh->pf_path);
		close(fd);
		free(pfh);
		errno = error;
		return (NULL);
	}

	pfh->pf_fd = fd;
	pfh->pf_dev = sb.st_dev;
	pfh->pf_ino = sb.st_ino;

	return (pfh);
}

int
pidfile_write(struct pidfh *pfh)
{
	char pidstr[16];
	int error, fd;

	/*
	 * Check remembered descriptor, so we don't overwrite some other
	 * file if pidfile was closed and descriptor reused.
	 */
	errno = pidfile_verify(pfh);
	if (errno != 0) {
		/*
		 * Don't close descriptor, because we are not sure if it's ours.
		 */
		return (-1);
	}
	fd = pfh->pf_fd;

	/*
	 * Truncate PID file, so multiple calls of pidfile_write() are allowed.
	 */
	if (ftruncate(fd, 0) == -1) {
		error = errno;
		_pidfile_remove(pfh, 0);
		errno = error;
		return (-1);
	}

	snprintf(pidstr, sizeof(pidstr), "%u", getpid());
	if (pwrite(fd, pidstr, strlen(pidstr), 0) != (ssize_t)strlen(pidstr)) {
		error = errno;
		_pidfile_remove(pfh, 0);
		errno = error;
		return (-1);
	}

	return (0);
}

int
pidfile_close(struct pidfh *pfh)
{
	int error;

	error = pidfile_verify(pfh);
	if (error != 0) {
		errno = error;
		return (-1);
	}

	if (close(pfh->pf_fd) == -1)
		error = errno;
	free(pfh);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

static int
_pidfile_remove(struct pidfh *pfh, int freeit)
{
	int error;

	error = pidfile_verify(pfh);
	if (error != 0) {
		errno = error;
		return (-1);
	}

	if (unlink(pfh->pf_path) == -1)
		error = errno;
	if (flock(pfh->pf_fd, LOCK_UN) == -1) {
		if (error == 0)
			error = errno;
	}
	if (close(pfh->pf_fd) == -1) {
		if (error == 0)
			error = errno;
	}
	if (freeit)
		free(pfh);
	else
		pfh->pf_fd = -1;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

int
pidfile_remove(struct pidfh *pfh)
{

	return (_pidfile_remove(pfh, 1));
}
#endif
