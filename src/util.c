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
#include "statfile.h"
#include "filter.h"
#include "message.h"

/* Check log messages intensity once per minute */
#define CHECK_TIME 60
/* More than 2 log messages per second */
#define BUF_INTENSITY 2
/* Default connect timeout for sync sockets */
#define CONNECT_TIMEOUT 3

rspamd_hash_t                      *counters = NULL;

static gchar* rspamd_sprintf_num (gchar *buf, gchar *last, guint64 ui64, gchar zero, guint hexadecimal, guint width);

gint
make_socket_nonblocking (gint fd)
{
	gint                            ofl;

	ofl = fcntl (fd, F_GETFL, 0);

	if (fcntl (fd, F_SETFL, ofl | O_NONBLOCK) == -1) {
		msg_warn ("fcntl failed: %d, '%s'", errno, strerror (errno));
		return -1;
	}
	return 0;
}

gint
make_socket_blocking (gint fd)
{
	gint                            ofl;

	ofl = fcntl (fd, F_GETFL, 0);

	if (fcntl (fd, F_SETFL, ofl & (~O_NONBLOCK)) == -1) {
		msg_warn ("fcntl failed: %d, '%s'", errno, strerror (errno));
		return -1;
	}
	return 0;
}

gint
poll_sync_socket (gint fd, gint timeout, short events)
{
	gint                            r;
	struct pollfd                   fds[1];

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

static gint
make_inet_socket (gint family, struct in_addr *addr, u_short port, gboolean is_server, gboolean async)
{
	gint                            fd, r, optlen, on = 1, s_error;
	gint                            serrno;
	struct sockaddr_in              sin;

	/* Create socket */
	fd = socket (AF_INET, family, 0);
	if (fd == -1) {
		msg_warn ("socket failed: %d, '%s'", errno, strerror (errno));
		return -1;
	}

	if (make_socket_nonblocking (fd) < 0) {
		goto out;
	}

	/* Set close on exec */
	if (fcntl (fd, F_SETFD, FD_CLOEXEC) == -1) {
		msg_warn ("fcntl failed: %d, '%s'", errno, strerror (errno));
		goto out;
	}

	memset (&sin, 0, sizeof (sin));

	/* Bind options */
	sin.sin_family = AF_INET;
	sin.sin_port = htons (port);
	sin.sin_addr.s_addr = addr->s_addr;

	if (is_server) {
		setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, sizeof (gint));
		r = bind (fd, (struct sockaddr *)&sin, sizeof (struct sockaddr_in));
	}
	else {
		r = connect (fd, (struct sockaddr *)&sin, sizeof (struct sockaddr_in));
	}

	if (r == -1) {
		if (errno != EINPROGRESS) {
			msg_warn ("bind/connect failed: %d, '%s'", errno, strerror (errno));
			goto out;
		}
		if (!async) {
			/* Try to poll */
			if (poll_sync_socket (fd, CONNECT_TIMEOUT * 1000, POLLOUT) <= 0) {
				errno = ETIMEDOUT;
				msg_warn ("bind/connect failed: timeout");
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
		optlen = sizeof (s_error);
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

gint
make_tcp_socket (struct in_addr *addr, u_short port, gboolean is_server, gboolean async)
{
	return make_inet_socket (SOCK_STREAM, addr, port, is_server, async);
}

gint
make_udp_socket (struct in_addr *addr, u_short port, gboolean is_server, gboolean async)
{
	return make_inet_socket (SOCK_DGRAM, addr, port, is_server, async);
}

gint
accept_from_socket (gint listen_sock, struct sockaddr *addr, socklen_t * len)
{
	gint                            nfd;
	gint                            serrno;

	if ((nfd = accept (listen_sock, addr, len)) == -1) {
		if (errno == EAGAIN) {
			return 0;
		}
		msg_warn ("accept failed: %d, '%s'", errno, strerror (errno));
		return -1;
	}
	if (make_socket_nonblocking (nfd) < 0) {
		goto out;
	}

	/* Set close on exec */
	if (fcntl (nfd, F_SETFD, FD_CLOEXEC) == -1) {
		msg_warn ("fcntl failed: %d, '%s'", errno, strerror (errno));
		goto out;
	}



	return (nfd);

  out:
	serrno = errno;
	close (nfd);
	errno = serrno;
	return (-1);

}

gint
make_unix_socket (const gchar *path, struct sockaddr_un *addr, gboolean is_server, gboolean async)
{
	gint                            fd, s_error, r, optlen, serrno, on = 1;

	if (path == NULL)
		return -1;

	addr->sun_family = AF_UNIX;

	rspamd_strlcpy (addr->sun_path, path, sizeof (addr->sun_path));
#ifdef FREEBSD
	addr->sun_len = SUN_LEN (addr);
#endif

	fd = socket (PF_LOCAL, SOCK_STREAM, 0);

	if (fd == -1) {
		msg_warn ("socket failed: %d, '%s'", errno, strerror (errno));
		return -1;
	}

	if (make_socket_nonblocking (fd) < 0) {
		goto out;
	}

	/* Set close on exec */
	if (fcntl (fd, F_SETFD, FD_CLOEXEC) == -1) {
		msg_warn ("fcntl failed: %d, '%s'", errno, strerror (errno));
		goto out;
	}
	if (is_server) {
		setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, sizeof (gint));
		r = bind (fd, (struct sockaddr *)addr, SUN_LEN (addr));
	}
	else {
		r = connect (fd, (struct sockaddr *)addr, SUN_LEN (addr));
	}

	if (r == -1) {
		if (errno != EINPROGRESS) {
			msg_warn ("bind/connect failed: %d, '%s'", errno, strerror (errno));
			goto out;
		}
		if (!async) {
			/* Try to poll */
			if (poll_sync_socket (fd, CONNECT_TIMEOUT * 1000, POLLOUT) <= 0) {
				errno = ETIMEDOUT;
				msg_warn ("bind/connect failed: timeout");
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
		optlen = sizeof (s_error);
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

/**
 * Make universal stream socket
 * @param credits host, ip or path to unix socket
 * @param port port (used for network sockets)
 * @param async make this socket asynced
 * @param is_server make this socket as server socket
 * @param try_resolve try name resolution for a socket (BLOCKING)
 */
gint
make_universal_stream_socket (const gchar *credits, guint16 port, gboolean async, gboolean is_server, gboolean try_resolve)
{
	struct sockaddr_un              un;
	struct stat                     st;
	struct in_addr                  in;
	struct hostent 				   *he;
	gint                            r;

	if (*credits == '/') {
		r = stat (credits, &st);
		if (is_server) {
			if (r == -1) {
				return make_unix_socket (credits, &un, is_server, async);
			}
			else {
				/* Unix socket exists, it must be unlinked first */
				errno = EEXIST;
				return -1;
			}
		}
		else {
			if (r == -1) {
				/* Unix socket doesn't exists it must be created first */
				errno = ENOENT;
				return -1;
			}
			else {
				if ((st.st_mode & S_IFSOCK) == 0) {
					/* Path is not valid socket */
					errno = EINVAL;
					return -1;
				}
				else {
					return make_unix_socket (credits, &un, is_server, async);
				}
			}
		}
	}
	else {
		/* TCP related part */
		if (inet_aton (credits, &in) == 0) {
			/* Try to resolve */
			if (try_resolve) {
				if ((he = gethostbyname (credits)) == NULL) {
					errno = ENOENT;
					return -1;
				}
				else {
					memcpy (&in, he->h_addr, sizeof (struct in_addr));
					return make_tcp_socket (&in, port, is_server, async);
				}
			}
			else {
				errno = ENOENT;
				return -1;
			}
		}
		else {
			return make_tcp_socket (&in, port, is_server, async);
		}
	}
}

gint
make_socketpair (gint pair[2])
{
	gint                            r;

	r = socketpair (AF_LOCAL, SOCK_STREAM, 0, pair);

	if (r == -1) {
		msg_warn ("socketpair failed: %d, '%s'", errno, strerror (errno), pair[0], pair[1]);
		return -1;
	}
	/* Set close on exec */
	if (fcntl (pair[0], F_SETFD, FD_CLOEXEC) == -1) {
		msg_warn ("fcntl failed: %d, '%s'", errno, strerror (errno));
		goto out;
	}
	if (fcntl (pair[1], F_SETFD, FD_CLOEXEC) == -1) {
		msg_warn ("fcntl failed: %d, '%s'", errno, strerror (errno));
		goto out;
	}

	return 0;

out:
	close (pair[0]);
	close (pair[1]);
	return (-1);
}

gint
write_pid (struct rspamd_main *main)
{
	pid_t                           pid;

	if (main->cfg->pid_file == NULL) {
		return -1;
	}
	main->pfh = rspamd_pidfile_open (main->cfg->pid_file, 0644, &pid);

	if (main->pfh == NULL) {
		return -1;
	}

	rspamd_pidfile_write (main->pfh);

	return 0;
}

#ifdef HAVE_SA_SIGINFO
void
init_signals (struct sigaction *signals, void (*sig_handler)(gint, siginfo_t *, void *))
#else
void
init_signals (struct sigaction *signals, void (*sig_handler)(gint))
#endif
{
	struct sigaction                sigpipe_act;
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


#ifdef HAVE_SA_SIGINFO
	signals->sa_flags = SA_SIGINFO;
	signals->sa_handler = NULL;
	signals->sa_sigaction = sig_handler;
#else
	signals->sa_handler = sig_handler;
	signals->sa_flags = 0;
#endif
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

static void
pass_signal_cb (gpointer key, gpointer value, gpointer ud)
{
	struct rspamd_worker           *cur = value;
    gint                            signo = GPOINTER_TO_INT (ud);

	kill (cur->pid, signo);
}

void
pass_signal_worker (GHashTable * workers, gint signo)
{
    g_hash_table_foreach (workers, pass_signal_cb, GINT_TO_POINTER (signo));
}

void
convert_to_lowercase (gchar *str, guint size)
{
	while (size--) {
		*str = g_ascii_tolower (*str);
		str++;
	}
}

#ifndef HAVE_SETPROCTITLE

static gchar                    *title_buffer = 0;
static size_t                   title_buffer_size = 0;
static gchar                    *title_progname, *title_progname_full;

gint
setproctitle (const gchar *fmt, ...)
{
	if (!title_buffer || !title_buffer_size) {
		errno = ENOMEM;
		return -1;
	}

	memset (title_buffer, '\0', title_buffer_size);

	ssize_t                         written;

	if (fmt) {
		ssize_t                         written2;
		va_list                         ap;

		written = snprintf (title_buffer, title_buffer_size, "%s: ", title_progname);
		if (written < 0 || (size_t) written >= title_buffer_size)
			return -1;

		va_start (ap, fmt);
		written2 = vsnprintf (title_buffer + written, title_buffer_size - written, fmt, ap);
		va_end (ap);
		if (written2 < 0 || (size_t) written2 >= title_buffer_size - written)
			return -1;
	}
	else {
		written = snprintf (title_buffer, title_buffer_size, "%s", title_progname);
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

gint
init_title (gint argc, gchar *argv[], gchar *envp[])
{
#if defined(DARWIN) || defined(SOLARIS)
	/* XXX: try to handle these OSes too */
	return 0;
#else
	gchar                           *begin_of_buffer = 0, *end_of_buffer = 0;
	gint                            i;

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
			end_of_buffer = envp[i] + strlen (envp[i]);
	}

	if (!end_of_buffer)
		return 0;

	gchar                           **new_environ = g_malloc ((i + 1) * sizeof (envp[0]));

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

		gchar                           *p = strrchr (title_progname_full, '/');

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
#endif
}
#endif

#ifndef HAVE_PIDFILE
extern gchar                    *__progname;
static gint                      _rspamd_pidfile_remove (rspamd_pidfh_t *pfh, gint freeit);

static gint
rspamd_pidfile_verify (rspamd_pidfh_t *pfh)
{
	struct stat                     sb;

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

static gint
rspamd_pidfile_read (const gchar *path, pid_t * pidptr)
{
	gchar                           buf[16], *endptr;
	gint                            error, fd, i;

	fd = open (path, O_RDONLY);
	if (fd == -1)
		return (errno);

	i = read (fd, buf, sizeof (buf) - 1);
	error = errno;				/* Remember errno in case close() wants to change it. */
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

rspamd_pidfh_t                   *
rspamd_pidfile_open (const gchar *path, mode_t mode, pid_t * pidptr)
{
	rspamd_pidfh_t                 *pfh;
	struct stat                     sb;
	gint                            error, fd, len, count;
	struct timespec                 rqtp;

	pfh = g_malloc (sizeof (*pfh));
	if (pfh == NULL)
		return NULL;

	if (path == NULL)
		len = snprintf (pfh->pf_path, sizeof (pfh->pf_path), "/var/run/%s.pid", g_get_prgname ());
	else
		len = snprintf (pfh->pf_path, sizeof (pfh->pf_path), "%s", path);
	if (len >= (gint)sizeof (pfh->pf_path)) {
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
	fd = open (pfh->pf_path, O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK, mode);
	lock_file (fd, TRUE);
	if (fd == -1) {
		count = 0;
		rqtp.tv_sec = 0;
		rqtp.tv_nsec = 5000000;
		if (errno == EWOULDBLOCK && pidptr != NULL) {
		  again:
			errno = rspamd_pidfile_read (pfh->pf_path, pidptr);
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

gint
rspamd_pidfile_write (rspamd_pidfh_t *pfh)
{
	gchar                           pidstr[16];
	gint                            error, fd;

	/*
	 * Check remembered descriptor, so we don't overwrite some other
	 * file if pidfile was closed and descriptor reused.
	 */
	errno = rspamd_pidfile_verify (pfh);
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
		_rspamd_pidfile_remove (pfh, 0);
		errno = error;
		return -1;
	}

	rspamd_snprintf (pidstr, sizeof (pidstr), "%P", getpid ());
	if (pwrite (fd, pidstr, strlen (pidstr), 0) != (ssize_t) strlen (pidstr)) {
		error = errno;
		_rspamd_pidfile_remove (pfh, 0);
		errno = error;
		return -1;
	}

	return 0;
}

gint
rspamd_pidfile_close (rspamd_pidfh_t *pfh)
{
	gint                            error;

	error = rspamd_pidfile_verify (pfh);
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

static gint
_rspamd_pidfile_remove (rspamd_pidfh_t *pfh, gint freeit)
{
	gint                            error;

	error = rspamd_pidfile_verify (pfh);
	if (error != 0) {
		errno = error;
		return -1;
	}

	if (unlink (pfh->pf_path) == -1)
		error = errno;
	if (!unlock_file (pfh->pf_fd, FALSE)) {
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

gint
rspamd_pidfile_remove (rspamd_pidfh_t *pfh)
{

	return (_rspamd_pidfile_remove (pfh, 1));
}
#endif

/* Replace %r with rcpt value and %f with from value, new string is allocated in pool */
gchar                           *
resolve_stat_filename (memory_pool_t * pool, gchar *pattern, gchar *rcpt, gchar *from)
{
	gint                            need_to_format = 0, len = 0;
	gint                            rcptlen, fromlen;
	gchar                           *c = pattern, *new, *s;

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
		len++;
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
	while (*c++) {
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
		*s++ = *c;
	}

	*s = '\0';

	return new;
}

#ifdef HAVE_CLOCK_GETTIME
const gchar                     *
calculate_check_time (struct timeval *tv, struct timespec *begin, gint resolution)
#else
const gchar                     *
calculate_check_time (struct timeval *begin, gint resolution)
#endif
{
	double                          vdiff, diff;
	static gchar                     res[64];
	static gchar                     fmt[sizeof ("%.10f ms real, %.10f ms virtual")];
	struct timeval                  tv_now;
	if (gettimeofday (&tv_now, NULL) == -1) {
		msg_warn ("gettimeofday failed: %s", strerror (errno));
	}
#ifdef HAVE_CLOCK_GETTIME
	struct timespec                 ts;

	diff = (tv_now.tv_sec - tv->tv_sec) * 1000. +	/* Seconds */
		(tv_now.tv_usec - tv->tv_usec) / 1000.;	/* Microseconds */
#ifdef HAVE_CLOCK_PROCESS_CPUTIME_ID
	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &ts);
#elif defined(HAVE_CLOCK_VIRTUAL)
	clock_gettime (CLOCK_VIRTUAL, &ts);
#else
	clock_gettime (CLOCK_REALTIME, &ts);
#endif

	vdiff = (ts.tv_sec - begin->tv_sec) * 1000. +	/* Seconds */
		(ts.tv_nsec - begin->tv_nsec) / 1000000.;	/* Nanoseconds */
#else
	diff = (tv_now.tv_sec - begin->tv_sec) * 1000. +	/* Seconds */
		(tv_now.tv_usec - begin->tv_usec) / 1000.;	/* Microseconds */

	vdiff = diff;
#endif

	sprintf (fmt, "%%.%dfms real, %%.%dfms virtual", resolution, resolution);
	snprintf (res, sizeof (res), fmt, diff, vdiff);

	return (const gchar *)res;
}

double
set_counter (const gchar *name, guint32 value)
{
	struct counter_data            *cd;
	double                          alpha;
	gchar                           *key;

	cd = rspamd_hash_lookup (counters, (gpointer) name);

	if (cd == NULL) {
		cd = memory_pool_alloc_shared (counters->pool, sizeof (struct counter_data));
		cd->value = value;
		cd->number = 0;
		key = memory_pool_strdup_shared (counters->pool, name);
		rspamd_hash_insert (counters, (gpointer) key, (gpointer) cd);
	}
	else {
		/* Calculate new value */
		memory_pool_wlock_rwlock (counters->lock);

		alpha = 2. / (++cd->number + 1);
		cd->value = cd->value * (1. - alpha) + value * alpha;

		memory_pool_wunlock_rwlock (counters->lock);
	}

	return cd->value;
}

#ifndef g_tolower
#   define g_tolower(x) (((x) >= 'A' && (x) <= 'Z') ? (x) - 'A' + 'a' : (x))
#endif

gboolean
rspamd_strcase_equal (gconstpointer v, gconstpointer v2)
{
	if (g_ascii_strcasecmp ((const gchar *)v, (const gchar *)v2) == 0) {
		return TRUE;
	}

	return FALSE;
}


guint
rspamd_strcase_hash (gconstpointer key)
{
	const gchar                     *p = key;
	guint                           h = 0;

	while (*p != '\0') {
		h = (h << 5) - h + g_tolower (*p);
		p++;
	}

	return h;
}

gboolean
fstr_strcase_equal (gconstpointer v, gconstpointer v2)
{
	const f_str_t *f1 = v, *f2 = v2;
	if (f1->len == f2->len && g_ascii_strncasecmp (f1->begin, f2->begin, f1->len) == 0) {
		return TRUE;
	}

	return FALSE;
}


guint
fstr_strcase_hash (gconstpointer key)
{
	const f_str_t                  *f = key;
	const gchar                     *p;
	guint                           h = 0;
	
	p = f->begin;
	while (p - f->begin < (gint)f->len) {
		h = (h << 5) - h + g_tolower (*p);
		p++;
	}

	return h;
}

void
gperf_profiler_init (struct config_file *cfg, const gchar *descr)
{
#if defined(WITH_GPERF_TOOLS)
	gchar                           prof_path[PATH_MAX];

	if (getenv ("CPUPROFILE")) {

		/* disable inherited Profiler enabled in master process */
		ProfilerStop ();
	}
	/* Try to create temp directory for gmon.out and chdir to it */
	if (cfg->profile_path == NULL) {
		cfg->profile_path = g_strdup_printf ("%s/rspamd-profile", cfg->temp_dir);
	}

	snprintf (prof_path, sizeof (prof_path), "%s-%s.%d", cfg->profile_path, descr, (gint)getpid ());
	if (ProfilerStart (prof_path)) {
		/* start ITIMER_PROF timer */
		ProfilerRegisterThread ();
	}
	else {
		msg_warn ("cannot start google perftools profiler");
	}

#endif
}

#ifdef HAVE_FLOCK
/* Flock version */
gboolean 
lock_file (gint fd, gboolean async)
{
    gint                            flags;

    if (async) {
        flags = LOCK_EX | LOCK_NB;
    }
    else {
        flags = LOCK_EX;
    }

    if (flock (fd, flags) == -1) {
        if (async && errno == EAGAIN) {
            return FALSE;
        }
        msg_warn ("lock on file failed: %s", strerror (errno));
        return FALSE;
    }

    return TRUE;
}

gboolean 
unlock_file (gint fd, gboolean async)
{
    gint                            flags;

    if (async) {
        flags = LOCK_UN | LOCK_NB;
    }
    else {
        flags = LOCK_UN;
    }

    if (flock (fd, flags) == -1) {
        if (async && errno == EAGAIN) {
            return FALSE;
        }
        msg_warn ("lock on file failed: %s", strerror (errno));
        return FALSE;
    }

    return TRUE;

}
#else /* HAVE_FLOCK */
/* Fctnl version */
gboolean 
lock_file (gint fd, gboolean async)
{
    struct flock fl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0
    };

    if (fcntl (fd, async ? F_SETLK : F_SETLKW, &fl) == -1) {
        if (async && (errno == EAGAIN || errno == EACCES)) {
            return FALSE;
        }
        msg_warn ("lock on file failed: %s", strerror (errno));
        return FALSE;
    }

    return TRUE;
}

gboolean 
unlock_file (gint fd, gboolean async)
{
    struct flock fl = {
        .l_type = F_UNLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0
    };

    if (fcntl (fd, async ? F_SETLK : F_SETLKW, &fl) == -1) {
        if (async && (errno == EAGAIN || errno == EACCES)) {
            return FALSE;
        }
        msg_warn ("lock on file failed: %s", strerror (errno));
        return FALSE;
    }

    return TRUE;

}
#endif /* HAVE_FLOCK */

stat_file_t *
get_statfile_by_symbol (statfile_pool_t *pool, struct classifier_config *ccf, 
        const gchar *symbol, struct statfile **st, gboolean try_create)
{
    stat_file_t *res = NULL;
    GList *cur;

    if (pool == NULL || ccf == NULL || symbol == NULL) {
		msg_err ("invalid input arguments");
        return NULL;
    }

    cur = g_list_first (ccf->statfiles);
	while (cur) {
		*st = cur->data;
		if (strcmp (symbol, (*st)->symbol) == 0) {
			break;
		}
		*st = NULL;
		cur = g_list_next (cur);
	}
    if (*st == NULL) {
		msg_info ("cannot find statfile with symbol %s", symbol);
        return NULL;
    }

    if ((res = statfile_pool_is_open (pool, (*st)->path)) == NULL) {
		if ((res = statfile_pool_open (pool, (*st)->path, (*st)->size, FALSE)) == NULL) {
			msg_warn ("cannot open %s", (*st)->path);
            if (try_create) {
                if (statfile_pool_create (pool, (*st)->path, (*st)->size) == -1) {
					msg_err ("cannot create statfile %s", (*st)->path);
					return NULL;
				}
                res = statfile_pool_open (pool, (*st)->path, (*st)->size, FALSE);
				if (res == NULL) {
					msg_err ("cannot open statfile %s after creation", (*st)->path);
				}
            }
		}
	}
    
    return res;
}



#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 22))
void
g_ptr_array_unref (GPtrArray *array)
{
	g_ptr_array_free (array, TRUE);
}
#endif

gsize
rspamd_strlcpy (gchar *dst, const gchar *src, gsize siz)
{
	gchar *d = dst;
	const gchar *s = src;
	gsize n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0) {
		while (--n != 0) {
			if ((*d++ = *s++) == '\0') {
				break;
			}
		}
	}

	if (n == 0 && siz != 0) {
		*d = '\0';
	}

	return (s - src - 1);    /* count does not include NUL */
}

/* Convert process type to its name */
const gchar              *
process_to_str (enum process_type type)
{
	switch (type) {
	case TYPE_MAIN:
		return "main";
	case TYPE_WORKER:
		return "worker";
	case TYPE_FUZZY:
		return "fuzzy";
	case TYPE_GREYLIST:
		return "greylist";
	case TYPE_CONTROLLER:
		return "controller";
	case TYPE_LMTP:
		return "lmtp";
	case TYPE_SMTP:
		return "smtp";
	case TYPE_KVSTORAGE:
		return "keystorage";
	default:
		return "unknown";
	}

	return NULL;
}
/* Convert string to process type */
enum process_type
str_to_process (const gchar *str)
{
	if (g_ascii_strcasecmp (str, "main") == 0) {
		return TYPE_MAIN;
	}
	else if (g_ascii_strcasecmp (str, "worker") == 0) {
		return TYPE_WORKER;
	}
	else if (g_ascii_strcasecmp (str, "fuzzy") == 0) {
		return TYPE_FUZZY;
	}
	else if (g_ascii_strcasecmp (str, "greylist") == 0) {
		return TYPE_GREYLIST;
	}
	else if (g_ascii_strcasecmp (str, "controller") == 0) {
		return TYPE_CONTROLLER;
	}
	else if (g_ascii_strcasecmp (str, "smtp") == 0) {
		return TYPE_SMTP;
	}
	else if (g_ascii_strcasecmp (str, "lmtp") == 0) {
		return TYPE_LMTP;
	}

	return TYPE_UNKNOWN;
}

/*
 * Destructor for recipients list
 */
static void
rcpt_destruct (void *pointer)
{
	struct worker_task             *task = (struct worker_task *) pointer;

	if (task->rcpt) {
		g_list_free (task->rcpt);
	}
}


/* Compare two emails for building emails tree */
static gint
compare_email_func (gconstpointer a, gconstpointer b)
{
	const struct uri               *u1 = a, *u2 = b;
	gint                            r;

	if (u1->hostlen != u2->hostlen || u1->hostlen == 0) {
		return u1->hostlen - u2->hostlen;
	}
	else {
		if ((r = g_ascii_strncasecmp (u1->host, u2->host, u1->hostlen)) == 0){
			if (u1->userlen != u2->userlen || u1->userlen == 0) {
				return u1->userlen - u2->userlen;
			}
			else {
				return g_ascii_strncasecmp (u1->user, u2->user, u1->userlen);
			}
		}
		else {
			return r;
		}
	}

	return 0;
}

static gint
compare_url_func (gconstpointer a, gconstpointer b)
{
	const struct uri               *u1 = a, *u2 = b;
	int                             r;

	if (u1->hostlen != u2->hostlen || u1->hostlen == 0) {
		return u1->hostlen - u2->hostlen;
	}
	else {
		r = g_ascii_strncasecmp (u1->host, u2->host, u1->hostlen);
	}

	return r;
}

/*
 * Create new task
 */
struct worker_task             *
construct_task (struct rspamd_worker *worker)
{
	struct worker_task             *new_task;

	new_task = g_slice_alloc0 (sizeof (struct worker_task));

	new_task->worker = worker;
	new_task->state = READ_COMMAND;
	new_task->cfg = worker->srv->cfg;
	new_task->from_addr.s_addr = INADDR_NONE;
	new_task->view_checked = FALSE;
#ifdef HAVE_CLOCK_GETTIME
# ifdef HAVE_CLOCK_PROCESS_CPUTIME_ID
	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &new_task->ts);
# elif defined(HAVE_CLOCK_VIRTUAL)
	clock_gettime (CLOCK_VIRTUAL, &new_task->ts);
# else
	clock_gettime (CLOCK_REALTIME, &new_task->ts);
# endif
#endif
	if (gettimeofday (&new_task->tv, NULL) == -1) {
		msg_warn ("gettimeofday failed: %s", strerror (errno));
	}

	new_task->task_pool = memory_pool_new (memory_pool_get_size ());

	/* Add destructor for recipients list (it would be better to use anonymous function here */
	memory_pool_add_destructor (new_task->task_pool,
			(pool_destruct_func) rcpt_destruct, new_task);
	new_task->results = g_hash_table_new (g_str_hash, g_str_equal);
	memory_pool_add_destructor (new_task->task_pool,
			(pool_destruct_func) g_hash_table_destroy,
			new_task->results);
	new_task->re_cache = g_hash_table_new (g_str_hash, g_str_equal);
	memory_pool_add_destructor (new_task->task_pool,
			(pool_destruct_func) g_hash_table_destroy,
			new_task->re_cache);
	new_task->raw_headers = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
	memory_pool_add_destructor (new_task->task_pool,
				(pool_destruct_func) g_hash_table_destroy,
				new_task->raw_headers);
	new_task->emails = g_tree_new (compare_email_func);
	memory_pool_add_destructor (new_task->task_pool,
				(pool_destruct_func) g_tree_destroy,
				new_task->emails);
	new_task->urls = g_tree_new (compare_url_func);
	memory_pool_add_destructor (new_task->task_pool,
					(pool_destruct_func) g_tree_destroy,
					new_task->urls);
	new_task->s =
			new_async_session (new_task->task_pool, free_task_hard, new_task);
	new_task->sock = -1;
	new_task->is_mime = TRUE;

	return new_task;
}


/*
 * Free all structures of worker_task
 */
void
free_task (struct worker_task *task, gboolean is_soft)
{
	GList                          *part;
	struct mime_part               *p;

	if (task) {
		debug_task ("free pointer %p", task);
		while ((part = g_list_first (task->parts))) {
			task->parts = g_list_remove_link (task->parts, part);
			p = (struct mime_part *) part->data;
			g_byte_array_free (p->content, TRUE);
			g_list_free_1 (part);
		}
		if (task->text_parts) {
			g_list_free (task->text_parts);
		}
		if (task->images) {
			g_list_free (task->images);
		}
		if (task->messages) {
			g_list_free (task->messages);
		}
		if (task->received) {
			g_list_free (task->received);
		}
		memory_pool_delete (task->task_pool);
		if (task->dispatcher) {
			if (is_soft) {
				/* Plan dispatcher shutdown */
				task->dispatcher->wanna_die = 1;
			}
			else {
				rspamd_remove_dispatcher (task->dispatcher);
			}
		}
		if (task->sock != -1) {
			close (task->sock);
		}
		g_slice_free1 (sizeof (struct worker_task), task);
	}
}

void
free_task_hard (gpointer ud)
{
  struct worker_task             *task = ud;

  free_task (task, FALSE);
}

void
free_task_soft (gpointer ud)
{
  struct worker_task             *task = ud;

  free_task (task, FALSE);
}

gchar *
escape_braces_addr_fstr (memory_pool_t *pool, f_str_t *in)
{
	gint                          len = 0;
	gchar                        *res, *orig, *p;

	orig = in->begin;
	while ((g_ascii_isspace (*orig) || *orig == '<') && orig - in->begin < (gint)in->len) {
		orig ++;
	}

	p = orig;
	while ((!g_ascii_isspace (*p) && *p != '>') && p - in->begin < (gint)in->len) {
		p ++;
		len ++;
	}

	res = memory_pool_alloc (pool, len + 1);
	rspamd_strlcpy (res, orig, len + 1);

	return res;
}

/*
 * Find the first occurrence of find in s, ignore case.
 */
gchar *
rspamd_strncasestr (const gchar *s, const gchar *find, gint len)
{
	gchar                           c, sc;
	gsize                           mlen;

	if ((c = *find++) != 0) {
		c = g_ascii_tolower (c);
		mlen = strlen (find);
		do {
			do {
				if ((sc = *s++) == 0 || len -- == 0)
					return (NULL);
			} while (g_ascii_tolower (sc) != c);
		} while (g_ascii_strncasecmp (s, find, mlen) != 0);
		s--;
	}
	return ((gchar *)s);
}

/*
 * vi:ts=4
 */
