/*
 * Copyright (c) 2009, Rambler media
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
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
#include "util.h"
#include "cfg_file.h"
#include "main.h"

/* Check log messages intensity once per minute */
#define CHECK_TIME 60
/* More than 2 log messages per second */
#define BUF_INTENSITY 2
/* Default connect timeout for sync sockets */
#define CONNECT_TIMEOUT 3

#ifdef RSPAMD_MAIN
sig_atomic_t do_reopen_log = 0;
extern rspamd_hash_t *counters;
#endif

struct logger_params {
    GLogFunc log_func;
    struct config_file *cfg;
};

static struct logger_params log_params;

/* Here would be put log messages intensity */
static uint32_t log_written;
static time_t last_check;
static char *io_buf = NULL;
static gboolean log_buffered = FALSE;

int
make_socket_nonblocking (int fd)
{
	int ofl;

	ofl = fcntl (fd, F_GETFL, 0);

	if (fcntl (fd, F_SETFL, ofl | O_NONBLOCK) == -1) {
		msg_warn ("make_socket_nonblocking: fcntl failed: %d, '%s'", errno, strerror (errno));
		return -1;
	}
	return 0;
}

int
make_socket_blocking (int fd)
{	
	int ofl;

	ofl = fcntl (fd, F_GETFL, 0);

	if (fcntl (fd, F_SETFL, ofl & (~O_NONBLOCK)) == -1) {
		msg_warn ("make_socket_nonblocking: fcntl failed: %d, '%s'", errno, strerror (errno));
		return -1;
	}
	return 0;
}

int 
poll_sync_socket (int fd, int timeout, short events)
{
	int r;
	struct pollfd fds[1];

	fds->fd = fd;
	fds->events = events;
	fds->revents = 0;
	while ((r = poll (fds, 1, timeout)) < 0) {
		if (errno != EINTR) {
			break;
		}
	}

	return r;
}

static int
make_inet_socket (int family, struct in_addr *addr, u_short port, gboolean is_server, gboolean async)
{
	int fd, r, optlen, on = 1, s_error;
	int serrno;
	struct sockaddr_in sin;
	
	/* Create socket */
	fd = socket (AF_INET, family, 0);
	if (fd == -1) {
		msg_warn ("make_tcp_socket: socket failed: %d, '%s'", errno, strerror (errno));
		return -1;
	}

	if (make_socket_nonblocking (fd) < 0) {
		goto out;
	}
	
	/* Set close on exec */
	if (fcntl (fd, F_SETFD, FD_CLOEXEC) == -1) {
		msg_warn ("make_tcp_socket: fcntl failed: %d, '%s'", errno, strerror (errno));
		goto out;
	}
	
	/* Bind options */
	sin.sin_family = AF_INET;
	sin.sin_port = htons (port);
	sin.sin_addr.s_addr = addr->s_addr;
	
	if (is_server) {
		setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (const void *) &on, sizeof(int));
		r = bind (fd, (struct sockaddr *)&sin, sizeof (struct sockaddr_in));
	}
	else {
		r = connect (fd, (struct sockaddr *)&sin, sizeof (struct sockaddr_in));
	}

	if (r == -1) {
		if (errno != EINPROGRESS) {
			msg_warn ("make_tcp_socket: bind/connect failed: %d, '%s'", errno, strerror (errno));
			goto out;
		}
		if (!async) {
			/* Try to poll */
			if (poll_sync_socket (fd, CONNECT_TIMEOUT * 1000, POLLOUT) <= 0) {
				errno = ETIMEDOUT;
				msg_warn ("make_tcp_socket: bind/connect failed: timeout");
				goto out;
			}
			else {
				/* Make synced again */
				if (make_socket_blocking (fd) < 0) {
					goto out;
				}
			}
		}
	}
	else {
		/* Still need to check SO_ERROR on socket */
		optlen = sizeof(s_error);
		getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&s_error, &optlen);
		if (s_error) {
			errno = s_error;
			goto out;
		}
	}


	return (fd);

 out:
	serrno = errno;
	close (fd);
	errno = serrno;
	return (-1);
}

int
make_tcp_socket (struct in_addr *addr, u_short port, gboolean is_server, gboolean async)
{
	return make_inet_socket (SOCK_STREAM, addr, port, is_server, async);	
}

int
make_udp_socket (struct in_addr *addr, u_short port, gboolean is_server, gboolean async)
{
	return make_inet_socket (SOCK_DGRAM, addr, port, is_server, async);	
}

int
accept_from_socket (int listen_sock, struct sockaddr *addr, socklen_t *len)
{
	int nfd;
	int serrno;

	if ((nfd = accept (listen_sock, addr, len)) == -1) {
		if (errno == EAGAIN) {
			return 0;	
		}
		msg_warn ("accept_from_socket: accept failed: %d, '%s'", errno, strerror (errno));
		return -1;
	}
	if (make_socket_nonblocking(nfd) < 0) {
		goto out;
	}
	
	/* Set close on exec */
	if (fcntl (nfd, F_SETFD, FD_CLOEXEC) == -1) {
		msg_warn ("accept_from_socket: fcntl failed: %d, '%s'", errno, strerror (errno));
		goto out;
	}



	return (nfd);

 out:
	serrno = errno;
	close (nfd);
	errno = serrno;
	return (-1);

}

int
make_unix_socket (const char *path, struct sockaddr_un *addr, gboolean is_server)
{
	size_t len = strlen (path);
	int fd, s_error, r, optlen, serrno, on = 1;

	if (len > sizeof (addr->sun_path) - 1 || path == NULL) return -1;
	
	#ifdef FREEBSD
	addr->sun_len = sizeof (struct sockaddr_un);
	#endif

	addr->sun_family = AF_UNIX;
	
	strncpy (addr->sun_path, path, len);
	
	fd = socket (PF_LOCAL, SOCK_STREAM, 0);
	
	if (fd == -1) {
		msg_warn ("make_unix_socket: socket failed: %d, '%s'", errno, strerror (errno));
		return -1;
	}

	if (make_socket_nonblocking(fd) < 0) {
		goto out;
	}
	
	/* Set close on exec */
	if (fcntl (fd, F_SETFD, FD_CLOEXEC) == -1) {
		msg_warn ("make_unix_socket: fcntl failed: %d, '%s'", errno, strerror (errno));
		goto out;
	}
	if (is_server) {
		setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (const void *) &on, sizeof(int));
		r = bind (fd, (struct sockaddr *)addr, sizeof (struct sockaddr_in));
	}
	else {
		r = connect (fd, (struct sockaddr *)addr, sizeof (struct sockaddr_in));
	}

	if (r == -1) {
		if (errno != EINPROGRESS) {
			msg_warn ("make_unix_socket: bind/connect failed: %d, '%s'", errno, strerror (errno));
			goto out;
		}
	}
	else {
		/* Still need to check SO_ERROR on socket */
		optlen = sizeof(s_error);
		getsockopt (fd, SOL_SOCKET, SO_ERROR, (void *)&s_error, &optlen);
		if (s_error) {
			errno = s_error;
			goto out;
		}
	}


	return (fd);

 out:
	serrno = errno;
	close (fd);
	errno = serrno;
	return (-1);
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
	struct sigaction sigpipe_act;
	/* Setting up signal handlers */
	/* SIGUSR1 - reopen config file */
	/* SIGUSR2 - worker is ready for accept */
	sigemptyset (&signals->sa_mask);
	sigaddset (&signals->sa_mask, SIGTERM);
	sigaddset (&signals->sa_mask, SIGINT);
	sigaddset (&signals->sa_mask, SIGHUP);
	sigaddset (&signals->sa_mask, SIGCHLD);
	sigaddset (&signals->sa_mask, SIGUSR1);
	sigaddset (&signals->sa_mask, SIGUSR2);
	sigaddset (&signals->sa_mask, SIGALRM);


	signals->sa_handler = sig_handler;
	signals->sa_flags = 0;
	sigaction (SIGTERM, signals, NULL);
	sigaction (SIGINT, signals, NULL);
	sigaction (SIGHUP, signals, NULL);
	sigaction (SIGCHLD, signals, NULL);
	sigaction (SIGUSR1, signals, NULL);
	sigaction (SIGUSR2, signals, NULL);
	sigaction (SIGALRM, signals, NULL);
	
	/* Ignore SIGPIPE as we handle write errors manually */
	sigemptyset (&sigpipe_act.sa_mask);
	sigaddset (&sigpipe_act.sa_mask, SIGPIPE);
	sigpipe_act.sa_handler = SIG_IGN;
	sigpipe_act.sa_flags = 0;
	sigaction (SIGPIPE, &sigpipe_act, NULL);
}

void
pass_signal_worker (GList *workers, int signo)
{
	struct rspamd_worker *cur;
	GList *l;

	l = workers;
	while (l) {
		cur = l->data;
		kill (cur->pid, signo);
		l = g_list_next (l);
	}
}

void convert_to_lowercase (char *str, unsigned int size)
{
	while (size--) {
		*str = g_ascii_tolower (*str);
		str ++;
	}
}

#ifndef HAVE_SETPROCTITLE

static char *title_buffer = 0;
static size_t title_buffer_size = 0;
static char *title_progname, *title_progname_full;

int
setproctitle (const char *fmt, ...)
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
init_title (int argc, char *argv[], char *envp[])
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
		if (!(new_environ[i] = g_strdup (envp[i])))
			goto cleanup_enomem;
	}
	new_environ[i] = 0;

	if (program_invocation_name) {
		title_progname_full = g_strdup (program_invocation_name);

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
		g_free (new_environ[i]);
	}
	g_free (new_environ);
	return 0;
}
#endif

#ifndef HAVE_PIDFILE
extern char * __progname;
static int _pidfile_remove (struct pidfh *pfh, int freeit);

static int
pidfile_verify (struct pidfh *pfh)
{
	struct stat sb;

	if (pfh == NULL || pfh->pf_fd == -1)
		return (-1);
	/*
	 * Check remembered descriptor.
	 */
	if (fstat (pfh->pf_fd, &sb) == -1)
		return (errno);
	if (sb.st_dev != pfh->pf_dev || sb.st_ino != pfh->pf_ino)
		return -1;
	return 0;
}

static int
pidfile_read (const char *path, pid_t *pidptr)
{
	char buf[16], *endptr;
	int error, fd, i;

	fd = open (path, O_RDONLY);
	if (fd == -1)
		return (errno);

	i = read (fd, buf, sizeof(buf) - 1);
	error = errno;	/* Remember errno in case close() wants to change it. */
	close (fd);
	if (i == -1)
		return error;
	else if (i == 0)
		return EAGAIN;
	buf[i] = '\0';

	*pidptr = strtol (buf, &endptr, 10);
	if (endptr != &buf[i])
		return EINVAL;

	return 0;
}

struct pidfh *
pidfile_open (const char *path, mode_t mode, pid_t *pidptr)
{
	struct pidfh *pfh;
	struct stat sb;
	int error, fd, len, count;
	struct timespec rqtp;

	pfh = g_malloc (sizeof(*pfh));
	if (pfh == NULL)
		return NULL;

	if (path == NULL)
		len = snprintf (pfh->pf_path, sizeof(pfh->pf_path),
		    "/var/run/%s.pid", __progname);
	else
		len = snprintf (pfh->pf_path, sizeof(pfh->pf_path),
		    "%s", path);
	if (len >= (int)sizeof (pfh->pf_path)) {
		g_free (pfh);
		errno = ENAMETOOLONG;
		return NULL;
	}

	/*
	 * Open the PID file and obtain exclusive lock.
	 * We truncate PID file here only to remove old PID immediatelly,
	 * PID file will be truncated again in pidfile_write(), so
	 * pidfile_write() can be called multiple times.
	 */
	fd = open (pfh->pf_path,
	    O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK, mode);
	flock (fd, LOCK_EX | LOCK_NB);
	if (fd == -1) {
		count = 0;
		rqtp.tv_sec = 0;
		rqtp.tv_nsec = 5000000;
		if (errno == EWOULDBLOCK && pidptr != NULL) {
		again:
			errno = pidfile_read (pfh->pf_path, pidptr);
			if (errno == 0)
				errno = EEXIST;
			else if (errno == EAGAIN) {
				if (++count <= 3) {
					nanosleep (&rqtp, 0);
					goto again;
				}
			}
		}
		g_free (pfh);
		return NULL;
	}
	/*
	 * Remember file information, so in pidfile_write() we are sure we write
	 * to the proper descriptor.
	 */
	if (fstat (fd, &sb) == -1) {
		error = errno;
		unlink (pfh->pf_path);
		close (fd);
		g_free (pfh);
		errno = error;
		return NULL;
	}

	pfh->pf_fd = fd;
	pfh->pf_dev = sb.st_dev;
	pfh->pf_ino = sb.st_ino;

	return pfh;
}

int
pidfile_write (struct pidfh *pfh)
{
	char pidstr[16];
	int error, fd;

	/*
	 * Check remembered descriptor, so we don't overwrite some other
	 * file if pidfile was closed and descriptor reused.
	 */
	errno = pidfile_verify (pfh);
	if (errno != 0) {
		/*
		 * Don't close descriptor, because we are not sure if it's ours.
		 */
		return -1;
	}
	fd = pfh->pf_fd;

	/*
	 * Truncate PID file, so multiple calls of pidfile_write() are allowed.
	 */
	if (ftruncate (fd, 0) == -1) {
		error = errno;
		_pidfile_remove (pfh, 0);
		errno = error;
		return -1;
	}

	snprintf (pidstr, sizeof(pidstr), "%u", getpid ());
	if (pwrite (fd, pidstr, strlen (pidstr), 0) != (ssize_t)strlen (pidstr)) {
		error = errno;
		_pidfile_remove (pfh, 0);
		errno = error;
		return -1;
	}

	return 0;
}

int
pidfile_close (struct pidfh *pfh)
{
	int error;

	error = pidfile_verify (pfh);
	if (error != 0) {
		errno = error;
		return -1;
	}

	if (close (pfh->pf_fd) == -1)
		error = errno;
	g_free (pfh);
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}

static int
_pidfile_remove (struct pidfh *pfh, int freeit)
{
	int error;

	error = pidfile_verify (pfh);
	if (error != 0) {
		errno = error;
		return -1;
	}

	if (unlink (pfh->pf_path) == -1)
		error = errno;
	if (flock (pfh->pf_fd, LOCK_UN) == -1) {
		if (error == 0)
			error = errno;
	}
	if (close (pfh->pf_fd) == -1) {
		if (error == 0)
			error = errno;
	}
	if (freeit)
		g_free (pfh);
	else
		pfh->pf_fd = -1;
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}

int
pidfile_remove (struct pidfh *pfh)
{

	return (_pidfile_remove (pfh, 1));
}
#endif


/* Logging utility functions */
int
open_log (struct config_file *cfg)
{
	switch (cfg->log_type) {
		case RSPAMD_LOG_CONSOLE:
			/* Do nothing with console */
			return 0;
		case RSPAMD_LOG_SYSLOG:
			openlog ("rspamd", LOG_NDELAY | LOG_PID, cfg->log_facility);
			return 0;
		case RSPAMD_LOG_FILE:
			cfg->log_fd = open (cfg->log_file, O_CREAT | O_WRONLY | O_APPEND, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
			if (cfg->log_fd == -1) {
				fprintf (stderr, "open_log: cannot open desired log file: %s, %s", cfg->log_file, strerror (errno));
				return -1;
			}
			cfg->logf = fdopen (cfg->log_fd, "w");
			/* Set line buffering */
			setvbuf (cfg->logf, (char *) NULL, _IOLBF, 0);
			return 0;
	}
	return -1;
}

void 
close_log (struct config_file *cfg)
{
	switch (cfg->log_type) {
		case RSPAMD_LOG_CONSOLE:
			/* Do nothing with console */
			break;
		case RSPAMD_LOG_SYSLOG:
			closelog ();
			break;
		case RSPAMD_LOG_FILE:
			if (cfg->logf != NULL) {
				if (fsync (cfg->log_fd) == -1) {
					msg_err ("close_log: error syncing log file: %s", strerror (errno));
				}
				fclose (cfg->logf);
				/* XXX: I think this is not needed */
				close (cfg->log_fd);
			}
			break;
	}

}

void
rspamd_set_logger (GLogFunc func, struct config_file *cfg)
{
	log_params.log_func = func;
	log_params.cfg = cfg;
}

int
reopen_log (struct config_file *cfg)
{
#ifdef RSPAMD_MAIN
	do_reopen_log = 0;
#endif
	close_log (cfg);
	return open_log (cfg);
}

void
rspamd_log_function (GLogLevelFlags log_level, const char *fmt, ...)
{
	static char logbuf[BUFSIZ];
	va_list vp;

	if (log_level <= log_params.cfg->log_level) {
		va_start (vp, fmt);
		vsnprintf (logbuf, sizeof (logbuf), fmt, vp);
		va_end (vp);
		log_params.log_func (NULL, log_level, logbuf, log_params.cfg);
	}
}

void
syslog_log_function (const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer arg)
{
	struct config_file *cfg = (struct config_file *)arg;
#ifdef RSPAMD_MAIN
	if (do_reopen_log) {
		reopen_log (cfg);
	}
#endif

	if (log_level <= cfg->log_level) {
		if (log_level >= G_LOG_LEVEL_DEBUG) {
			syslog (LOG_DEBUG, "%s", message);
		}
		else if (log_level >= G_LOG_LEVEL_INFO) {
			syslog (LOG_INFO, "%s", message);
		}
		else if (log_level >= G_LOG_LEVEL_WARNING) {
			syslog (LOG_WARNING, "%s", message);
		}
		else if (log_level >= G_LOG_LEVEL_CRITICAL) {
			syslog (LOG_ERR, "%s", message);
		}
	}
}

void
file_log_function (const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer arg)
{
	struct config_file *cfg = (struct config_file *)arg;
	char tmpbuf[128], timebuf[32];
	time_t now;
	struct tm *tms;
	
	if (cfg->log_fd == -1 || cfg->logf == NULL) {
		return;
	}
#ifdef RSPAMD_MAIN
	if (do_reopen_log) {
		reopen_log (cfg);
	}
#endif

	if (log_level <= cfg->log_level) {
		now = time (NULL);
		tms = localtime (&now);

		if (last_check == 0) {
			last_check = now;
		}
		else if (now - last_check > CHECK_TIME) {
			if (log_written / (now - last_check) > BUF_INTENSITY && !log_buffered) {
				/* Switch to buffered logging */
				if (io_buf == NULL) {
					io_buf = g_malloc (BUFSIZ);
				}
				setvbuf (cfg->logf, io_buf, _IOFBF, BUFSIZ);
				log_buffered = TRUE;
			}
			else if (log_buffered) {
				/* Switch to line buffering */
				setvbuf (cfg->logf, NULL, _IOLBF, 0);
				log_buffered = FALSE;
			}
			last_check = now;
			log_written = 0;
		}

		strftime (timebuf, sizeof (timebuf), "%b %d %H:%M:%S", tms);
		snprintf (tmpbuf, sizeof (tmpbuf), "#%d: %s rspamd ", (int)getpid (), timebuf);
		fprintf (cfg->logf, "%s%s" CRLF, tmpbuf, message);
		log_written ++;
	}
}

/* Replace %r with rcpt value and %f with from value, new string is allocated in pool */
char *
resolve_stat_filename (memory_pool_t *pool, char *pattern, char *rcpt, char *from)
{
	int need_to_format = 0, len = 0;
	int rcptlen, fromlen;
	char *c = pattern, *new, *s;
	
	if (rcpt) {
		rcptlen = strlen (rcpt);
	}
	else {
		rcptlen = 0;
	}

	if (from) {
		fromlen = strlen (from);
	}
	else {
		fromlen = 0;
	}

	/* Calculate length */
	while (*c++) {
		if (*c == '%' && *(c + 1) == 'r') {
			len += rcptlen;
			c += 2;
			need_to_format = 1;
			continue;
		}
		else if (*c == '%' && *(c + 1) == 'f') {
			len += fromlen;
			c += 2;
			need_to_format = 1;
			continue;
		}
		len ++;
	}
	
	/* Do not allocate extra memory if we do not need to format string */
	if (!need_to_format) {
		return pattern;
	}
	
	/* Allocate new string */
	new = memory_pool_alloc (pool, len);
	c = pattern;
	s = new;
	
	/* Format string */
	while (*c ++) {
		if (*c == '%' && *(c + 1) == 'r') {
			c += 2;
			memcpy (s, rcpt, rcptlen);
			s += rcptlen;
			continue;
		}
		else if (*c == '%' && *(c + 1) == 'r') {
			c += 2;
			memcpy (s, from, fromlen);
			s += fromlen;
			continue;
		}
		*s ++ = *c;
	}
	
	*s = '\0';

	return new;
}

const char *
calculate_check_time (struct timespec *begin, int resolution)
{
	struct timespec ts;
	double diff;
	static char res[sizeof("100000.000")];
	static char fmt[sizeof("%.10f")];
	
#ifdef HAVE_CLOCK_PROCESS_CPUTIME_ID
	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &ts);
#elif defined(HAVE_CLOCK_VIRTUAL)
	clock_gettime (CLOCK_VIRTUAL, &ts);
#else
	clock_gettime (CLOCK_REALTIME, &ts);
#endif

	diff = (ts.tv_sec - begin->tv_sec) * 1000. + 		/* Seconds */
		   (ts.tv_nsec - begin->tv_nsec) / 1000000.; 	/* Nanoseconds */
	sprintf (fmt, "%%.%df", resolution);
	snprintf (res, sizeof (res), fmt, diff);

	return (const char *)res;
}

double
set_counter (const char *name, long int value)
{
#ifdef RSPAMD_MAIN
	struct counter_data *cd;
	double alpha;
	char *key;
	
	cd = rspamd_hash_lookup (counters, (gpointer)name);

	if (cd == NULL) {
		cd = memory_pool_alloc_shared (counters->pool, sizeof (struct counter_data));
		cd->value = value;
		cd->number = 0;
		key = memory_pool_strdup_shared (counters->pool, name);
		rspamd_hash_insert (counters, (gpointer)key, (gpointer)cd);
	}
	else {
		/* Calculate new value */
		memory_pool_wlock_rwlock (counters->lock);

		alpha = 2. / (++cd->number + 1);
		cd->value = cd->value * (1. - alpha) + value * alpha;

		memory_pool_wunlock_rwlock (counters->lock);
	}

	return cd->value;
#else
	return 0;
#endif
}

#ifndef g_tolower
#define g_tolower(x) (((x) >= 'A' && (x) <= 'Z') ? (x) - 'A' + 'a' : (x))
#endif

gboolean
rspamd_strcase_equal (gconstpointer v, gconstpointer v2)
{
	if (g_ascii_strcasecmp ((const char *) v, (const char *) v2) == 0) {
		return TRUE;
	}

	return FALSE;
}


guint
rspamd_strcase_hash (gconstpointer key)
{
	const char *p = key;
	guint h = 0;
	
	while (*p != '\0') {
		h = (h << 5) - h + g_tolower (*p);
		p++;
	}
	
	return h;
}

void 
gperf_profiler_init (struct config_file *cfg, const char *descr)
{
#if defined(WITH_GPERF_TOOLS) && defined(RSPAMD_MAIN)
	char prof_path[PATH_MAX];

	if (getenv("CPUPROFILE")) {

		/* disable inherited Profiler enabled in master process */
		ProfilerStop ();
	}
	/* Try to create temp directory for gmon.out and chdir to it */
	if (cfg->profile_path == NULL) {
		cfg->profile_path = g_strdup_printf ("%s/rspamd-profile", cfg->temp_dir);
	}

	snprintf (prof_path, sizeof (prof_path), "%s-%s.%d", cfg->profile_path, descr, (int)getpid ());
	if (ProfilerStart (prof_path)) {
		/* start ITIMER_PROF timer */
		ProfilerRegisterThread();
	}
	else {
		msg_warn ("gperf_frofiler_init: cannot start google perftools profiler");
	}

#endif
}

/*
 * vi:ts=4
 */
