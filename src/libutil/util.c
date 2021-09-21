/*-
 * Copyright 2017 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "util.h"
#include "unix-std.h"

#include "xxhash.h"
#include "ottery.h"
#include "cryptobox.h"

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#ifdef HAVE_READPASSPHRASE_H
#include <readpassphrase.h>
#endif
/* libutil */
#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif
#ifdef __APPLE__
#include <mach/mach_time.h>
#include <mach/mach_init.h>
#include <mach/thread_act.h>
#include <mach/mach_port.h>
#endif
/* poll */
#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_SIGINFO_H
#include <siginfo.h>
#endif
/* sys/wait */
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
/* sys/resource.h */
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_RDTSC
#ifdef __x86_64__
#include <x86intrin.h>
#endif
#endif

#include <math.h> /* for pow */
#include <glob.h> /* in fact, we require this file ultimately */

#include "zlib.h"
#include "contrib/uthash/utlist.h"
#include "blas-config.h"

/* Check log messages intensity once per minute */
#define CHECK_TIME 60
/* More than 2 log messages per second */
#define BUF_INTENSITY 2
/* Default connect timeout for sync sockets */
#define CONNECT_TIMEOUT 3

/*
 * Should be defined in a single point
 */
const struct rspamd_controller_pbkdf pbkdf_list[] = {
		{
				.name = "PBKDF2-blake2b",
				.alias = "pbkdf2",
				.description = "standard CPU intensive \"slow\" KDF using blake2b hash function",
				.type = RSPAMD_CRYPTOBOX_PBKDF2,
				.id = RSPAMD_PBKDF_ID_V1,
				.complexity = 16000,
				.salt_len = 20,
				.key_len = rspamd_cryptobox_HASHBYTES / 2
		},
		{
				.name = "Catena-Butterfly",
				.alias = "catena",
				.description = "modern CPU and memory intensive KDF",
				.type = RSPAMD_CRYPTOBOX_CATENA,
				.id = RSPAMD_PBKDF_ID_V2,
				.complexity = 10,
				.salt_len = 20,
				.key_len = rspamd_cryptobox_HASHBYTES / 2
		}
};

gint
rspamd_socket_nonblocking (gint fd)
{
	gint ofl;

	ofl = fcntl (fd, F_GETFL, 0);

	if (fcntl (fd, F_SETFL, ofl | O_NONBLOCK) == -1) {
		return -1;
	}
	return 0;
}

gint
rspamd_socket_blocking (gint fd)
{
	gint ofl;

	ofl = fcntl (fd, F_GETFL, 0);

	if (fcntl (fd, F_SETFL, ofl & (~O_NONBLOCK)) == -1) {
		return -1;
	}
	return 0;
}

gint
rspamd_socket_poll (gint fd, gint timeout, short events)
{
	gint r;
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

gint
rspamd_socket_create (gint af, gint type, gint protocol, gboolean async)
{
	gint fd;

	fd = socket (af, type, protocol);
	if (fd == -1) {
		return -1;
	}

	/* Set close on exec */
	if (fcntl (fd, F_SETFD, FD_CLOEXEC) == -1) {
		close (fd);
		return -1;
	}
	if (async) {
		if (rspamd_socket_nonblocking (fd) == -1) {
			close (fd);
			return -1;
		}
	}

	return fd;
}

static gint
rspamd_inet_socket_create (gint type, struct addrinfo *addr, gboolean is_server,
	gboolean async, GList **list)
{
	gint fd = -1, r, on = 1, s_error;
	struct addrinfo *cur;
	gpointer ptr;
	socklen_t optlen;

	cur = addr;
	while (cur) {
		/* Create socket */
		fd = rspamd_socket_create (cur->ai_family, type, cur->ai_protocol, TRUE);
		if (fd == -1) {
			goto out;
		}

		if (is_server) {
			(void)setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on,
					sizeof (gint));
#ifdef HAVE_IPV6_V6ONLY
			if (cur->ai_family == AF_INET6) {
				setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, (const void *)&on,
						sizeof (gint));
			}
#endif
			r = bind (fd, cur->ai_addr, cur->ai_addrlen);
		}
		else {
			r = connect (fd, cur->ai_addr, cur->ai_addrlen);
		}

		if (r == -1) {
			if (errno != EINPROGRESS) {
				goto out;
			}
			if (!async) {
				/* Try to poll */
				if (rspamd_socket_poll (fd, CONNECT_TIMEOUT * 1000,
					POLLOUT) <= 0) {
					errno = ETIMEDOUT;
					goto out;
				}
				else {
					/* Make synced again */
					if (rspamd_socket_blocking (fd) < 0) {
						goto out;
					}
				}
			}
		}
		else {
			/* Still need to check SO_ERROR on socket */
			optlen = sizeof (s_error);

			if (getsockopt (fd, SOL_SOCKET, SO_ERROR, (void *)&s_error, &optlen) != -1) {
				if (s_error) {
					errno = s_error;
					goto out;
				}
			}
		}
		if (list == NULL) {
			/* Go out immediately */
			break;
		}
		else if (fd != -1) {
			ptr = GINT_TO_POINTER (fd);
			*list = g_list_prepend (*list, ptr);
			cur = cur->ai_next;
			continue;
		}
out:
		if (fd != -1) {
			close (fd);
		}
		fd = -1;
		cur = cur->ai_next;
	}

	return (fd);
}

gint
rspamd_socket_tcp (struct addrinfo *addr, gboolean is_server, gboolean async)
{
	return rspamd_inet_socket_create (SOCK_STREAM, addr, is_server, async, NULL);
}

gint
rspamd_socket_udp (struct addrinfo *addr, gboolean is_server, gboolean async)
{
	return rspamd_inet_socket_create (SOCK_DGRAM, addr, is_server, async, NULL);
}

gint
rspamd_socket_unix (const gchar *path,
	struct sockaddr_un *addr,
	gint type,
	gboolean is_server,
	gboolean async)
{

	socklen_t optlen;
	gint fd = -1, s_error, r, serrno, on = 1;
	struct stat st;

	if (path == NULL)
		return -1;

	addr->sun_family = AF_UNIX;

	rspamd_strlcpy (addr->sun_path, path, sizeof (addr->sun_path));
#ifdef FREEBSD
	addr->sun_len = SUN_LEN (addr);
#endif

	if (is_server) {
		/* Unlink socket if it exists already */
		if (lstat (addr->sun_path, &st) != -1) {
			if (S_ISSOCK (st.st_mode)) {
				if (unlink (addr->sun_path) == -1) {
					goto out;
				}
			}
			else {
				goto out;
			}
		}
	}
	fd = socket (PF_LOCAL, type, 0);

	if (fd == -1) {
		return -1;
	}

	if (rspamd_socket_nonblocking (fd) < 0) {
		goto out;
	}

	/* Set close on exec */
	if (fcntl (fd, F_SETFD, FD_CLOEXEC) == -1) {
		goto out;
	}
	if (is_server) {
		(void)setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on,
			sizeof (gint));
		r = bind (fd, (struct sockaddr *)addr, SUN_LEN (addr));
	}
	else {
		r = connect (fd, (struct sockaddr *)addr, SUN_LEN (addr));
	}

	if (r == -1) {
		if (errno != EINPROGRESS) {
			goto out;
		}
		if (!async) {
			/* Try to poll */
			if (rspamd_socket_poll (fd, CONNECT_TIMEOUT * 1000, POLLOUT) <= 0) {
				errno = ETIMEDOUT;
				goto out;
			}
			else {
				/* Make synced again */
				if (rspamd_socket_blocking (fd) < 0) {
					goto out;
				}
			}
		}
	}
	else {
		/* Still need to check SO_ERROR on socket */
		optlen = sizeof (s_error);

		if (getsockopt (fd, SOL_SOCKET, SO_ERROR, (void *)&s_error, &optlen) != -1) {
			if (s_error) {
				errno = s_error;
				goto out;
			}
		}
	}


	return (fd);

out:
	serrno = errno;
	if (fd != -1) {
		close (fd);
	}
	errno = serrno;
	return (-1);
}

static int
rspamd_prefer_v4_hack (const struct addrinfo *a1, const struct addrinfo *a2)
{
	return a1->ai_addr->sa_family - a2->ai_addr->sa_family;
}

/**
 * Make a universal socket
 * @param credits host, ip or path to unix socket
 * @param port port (used for network sockets)
 * @param async make this socket asynced
 * @param is_server make this socket as server socket
 * @param try_resolve try name resolution for a socket (BLOCKING)
 */
gint
rspamd_socket (const gchar *credits, guint16 port,
	gint type, gboolean async, gboolean is_server, gboolean try_resolve)
{
	struct sockaddr_un un;
	struct stat st;
	struct addrinfo hints, *res;
	gint r;
	gchar portbuf[8];

	if (*credits == '/') {
		if (is_server) {
			return rspamd_socket_unix (credits, &un, type, is_server, async);
		}
		else {
			r = stat (credits, &st);
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
					return rspamd_socket_unix (credits,
							   &un,
							   type,
							   is_server,
							   async);
				}
			}
		}
	}
	else {
		/* TCP related part */
		memset (&hints, 0, sizeof (hints));
		hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
		hints.ai_socktype = type; /* Type of the socket */
		hints.ai_flags = is_server ? AI_PASSIVE : 0;
		hints.ai_protocol = 0;           /* Any protocol */
		hints.ai_canonname = NULL;
		hints.ai_addr = NULL;
		hints.ai_next = NULL;

		if (!try_resolve) {
			hints.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;
		}

		rspamd_snprintf (portbuf, sizeof (portbuf), "%d", (int)port);
		if ((r = getaddrinfo (credits, portbuf, &hints, &res)) == 0) {
			LL_SORT2 (res, rspamd_prefer_v4_hack, ai_next);
			r = rspamd_inet_socket_create (type, res, is_server, async, NULL);
			freeaddrinfo (res);
			return r;
		}
		else {
			return -1;
		}
	}
}

gboolean
rspamd_socketpair (gint pair[2], gint af)
{
	gint r = -1, serrno;

#ifdef HAVE_SOCK_SEQPACKET
	if (af == SOCK_SEQPACKET) {
		r = socketpair (AF_LOCAL, SOCK_SEQPACKET, 0, pair);

		if (r == -1) {
			r = socketpair (AF_LOCAL, SOCK_DGRAM, 0, pair);
		}
	}
#endif
	if (r == -1) {
		r = socketpair (AF_LOCAL, af, 0, pair);
	}

	if (r == -1) {
		return -1;
	}

	/* Set close on exec */
	if (fcntl (pair[0], F_SETFD, FD_CLOEXEC) == -1) {
		goto out;
	}
	if (fcntl (pair[1], F_SETFD, FD_CLOEXEC) == -1) {
		goto out;
	}

	return TRUE;

out:
	serrno = errno;
	close (pair[0]);
	close (pair[1]);
	errno = serrno;

	return FALSE;
}

#ifdef HAVE_SA_SIGINFO
void
rspamd_signals_init (struct sigaction *signals, void (*sig_handler)(gint,
	siginfo_t *,
	void *))
#else
void
rspamd_signals_init (struct sigaction *signals, void (*sig_handler)(gint))
#endif
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
#ifdef SIGPOLL
	sigaddset (&signals->sa_mask, SIGPOLL);
#endif
#ifdef SIGIO
	sigaddset (&signals->sa_mask, SIGIO);
#endif

#ifdef HAVE_SA_SIGINFO
	signals->sa_flags = SA_SIGINFO;
	signals->sa_handler = NULL;
	signals->sa_sigaction = sig_handler;
#else
	signals->sa_handler = sig_handler;
	signals->sa_flags = 0;
#endif
	sigaction (SIGTERM, signals, NULL);
	sigaction (SIGINT,	signals, NULL);
	sigaction (SIGHUP,	signals, NULL);
	sigaction (SIGCHLD, signals, NULL);
	sigaction (SIGUSR1, signals, NULL);
	sigaction (SIGUSR2, signals, NULL);
	sigaction (SIGALRM, signals, NULL);
#ifdef SIGPOLL
	sigaction (SIGPOLL, signals, NULL);
#endif
#ifdef SIGIO
	sigaction (SIGIO, signals, NULL);
#endif

	/* Ignore SIGPIPE as we handle write errors manually */
	sigemptyset (&sigpipe_act.sa_mask);
	sigaddset (&sigpipe_act.sa_mask, SIGPIPE);
	sigpipe_act.sa_handler = SIG_IGN;
	sigpipe_act.sa_flags = 0;
	sigaction (SIGPIPE, &sigpipe_act, NULL);
}

#ifndef HAVE_SETPROCTITLE

#ifdef LINUX
static gchar *title_buffer = NULL;
static size_t title_buffer_size = 0;
static gchar *title_progname, *title_progname_full;
#endif

#ifdef LINUX
static void
rspamd_title_dtor (gpointer d)
{
	gchar **env = (gchar **)d;
	guint i;

	for (i = 0; env[i] != NULL; i++) {
		g_free (env[i]);
	}

	g_free (env);
}
#endif

gint
init_title (rspamd_mempool_t *pool,
		gint argc, gchar *argv[], gchar *envp[])
{
#ifdef LINUX
	gchar *begin_of_buffer = 0, *end_of_buffer = 0;
	gint i;

	for (i = 0; i < argc; ++i) {
		if (!begin_of_buffer) {
			begin_of_buffer = argv[i];
		}
		if (!end_of_buffer || end_of_buffer + 1 == argv[i]) {
			end_of_buffer = argv[i] + strlen (argv[i]);
		}
	}

	for (i = 0; envp[i]; ++i) {
		if (!begin_of_buffer) {
			begin_of_buffer = envp[i];
		}
		if (!end_of_buffer || end_of_buffer + 1 == envp[i]) {
			end_of_buffer = envp[i] + strlen (envp[i]);
		}
	}

	if (!end_of_buffer) {
		return 0;
	}

	gchar **new_environ = g_malloc ((i + 1) * sizeof (envp[0]));

	for (i = 0; envp[i]; ++i) {
		new_environ[i] = g_strdup (envp[i]);
	}

	new_environ[i] = NULL;

	if (program_invocation_name) {
		title_progname_full = g_strdup (program_invocation_name);

		gchar *p = strrchr (title_progname_full, '/');

		if (p) {
			title_progname = p + 1;
		}
		else {
			title_progname = title_progname_full;
		}

		program_invocation_name = title_progname_full;
		program_invocation_short_name = title_progname;
	}

	environ = new_environ;
	title_buffer = begin_of_buffer;
	title_buffer_size = end_of_buffer - begin_of_buffer;

	rspamd_mempool_add_destructor (pool,
			rspamd_title_dtor, new_environ);
#endif

	return 0;
}

gint
setproctitle (const gchar *fmt, ...)
{
#if defined(LINUX)
	if (!title_buffer || !title_buffer_size) {
		errno = ENOMEM;
		return -1;
	}

	memset (title_buffer, '\0', title_buffer_size);

	ssize_t written;

	if (fmt) {
		va_list ap;

		written = rspamd_snprintf (title_buffer,
				title_buffer_size,
				"%s: ",
				title_progname);
		if (written < 0 || (size_t) written >= title_buffer_size)
			return -1;

		va_start (ap, fmt);
		rspamd_vsnprintf (title_buffer + written,
				title_buffer_size - written,
				fmt,
				ap);
		va_end (ap);
	}
	else {
		written = rspamd_snprintf (title_buffer,
				title_buffer_size,
				"%s",
				title_progname);
		if (written < 0 || (size_t) written >= title_buffer_size)
			return -1;
	}

	written = strlen (title_buffer);
	memset (title_buffer + written, '\0', title_buffer_size - written);
#elif defined(__APPLE__)
	/* OSX is broken, ignore this brain damaged system */
#else
	/* Last resort (usually broken, but eh...) */
	GString *dest;
	va_list ap;

	dest = g_string_new ("");
	va_start (ap, fmt);
	rspamd_vprintf_gstring (dest, fmt, ap);
	va_end (ap);

	g_set_prgname (dest->str);
	g_string_free (dest, TRUE);

#endif
	return 0;
}

#endif

#ifndef HAVE_PIDFILE
static gint _rspamd_pidfile_remove (rspamd_pidfh_t *pfh, gint freeit);

static gint
rspamd_pidfile_verify (rspamd_pidfh_t *pfh)
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

static gint
rspamd_pidfile_read (const gchar *path, pid_t * pidptr)
{
	gchar buf[16], *endptr;
	gint error, fd, i;

	fd = open (path, O_RDONLY);
	if (fd == -1)
		return (errno);

	i = read (fd, buf, sizeof (buf) - 1);
	error = errno;              /* Remember errno in case close() wants to change it. */
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

rspamd_pidfh_t *
rspamd_pidfile_open (const gchar *path, mode_t mode, pid_t * pidptr)
{
	rspamd_pidfh_t *pfh;
	struct stat sb;
	gint error, fd, len, count;
	struct timespec rqtp;

	pfh = g_malloc (sizeof (*pfh));
	if (pfh == NULL)
		return NULL;

	if (path == NULL)
		len = snprintf (pfh->pf_path,
				sizeof (pfh->pf_path),
				"/var/run/%s.pid",
				g_get_prgname ());
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
	rspamd_file_lock (fd, TRUE);
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
	gchar pidstr[16];
	gint error, fd;

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
	gint error;

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
	gint error;

	error = rspamd_pidfile_verify (pfh);
	if (error != 0) {
		errno = error;
		return -1;
	}

	if (unlink (pfh->pf_path) == -1)
		error = errno;
	if (!rspamd_file_unlock (pfh->pf_fd, FALSE)) {
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
gchar *
resolve_stat_filename (rspamd_mempool_t * pool,
	gchar *pattern,
	gchar *rcpt,
	gchar *from)
{
	gint need_to_format = 0, len = 0;
	gint rcptlen, fromlen;
	gchar *c = pattern, *new, *s;

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
	new = rspamd_mempool_alloc (pool, len);
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
		*s++ = *c;
	}

	*s = '\0';

	return new;
}

const gchar *
rspamd_log_check_time (gdouble start, gdouble end, gint resolution)
{
	gdouble diff;
	static gchar res[64];
	gchar fmt[32];

	diff = (end - start) * 1000.0;

	rspamd_snprintf (fmt, sizeof (fmt), "%%.%dfms", resolution);
	rspamd_snprintf (res, sizeof (res), fmt, diff);

	return (const gchar *)res;
}


#ifdef HAVE_FLOCK
/* Flock version */
gboolean
rspamd_file_lock (gint fd, gboolean async)
{
	gint flags;

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

		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_file_unlock (gint fd, gboolean async)
{
	gint flags;

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

		return FALSE;
	}

	return TRUE;

}
#else /* HAVE_FLOCK */
/* Fctnl version */
gboolean
rspamd_file_lock (gint fd, gboolean async)
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

		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_file_unlock (gint fd, gboolean async)
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

		return FALSE;
	}

	return TRUE;

}
#endif /* HAVE_FLOCK */


#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 22))
void
g_ptr_array_unref (GPtrArray *array)
{
	g_ptr_array_free (array, TRUE);
}
gboolean
g_int64_equal (gconstpointer v1, gconstpointer v2)
{
	return *((const gint64*) v1) == *((const gint64*) v2);
}
guint
g_int64_hash (gconstpointer v)
{
	guint64 v64 = *(guint64 *)v;

	return (guint) (v ^ (v >> 32));
}
#endif
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 14))
void
g_queue_clear (GQueue *queue)
{
	g_return_if_fail (queue != NULL);

	g_list_free (queue->head);
	queue->head = queue->tail = NULL;
	queue->length = 0;
}
#endif
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 30))
GPtrArray*
g_ptr_array_new_full (guint reserved_size,
		GDestroyNotify element_free_func)
{
	GPtrArray *array;

	array = g_ptr_array_sized_new (reserved_size);
	g_ptr_array_set_free_func (array, element_free_func);

	return array;
}
#endif
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 32))
void
g_queue_free_full (GQueue *queue, GDestroyNotify free_func)
{
	GList *cur;

	cur = queue->head;

	while (cur) {
		free_func (cur->data);
		cur = g_list_next (cur);
	}

	g_queue_free (queue);
}
#endif

#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 40))
void
g_ptr_array_insert (GPtrArray *array, gint index_, gpointer data)
{
	g_return_if_fail (array);
	g_return_if_fail (index_ >= -1);
	g_return_if_fail (index_ <= (gint )array->len);

	g_ptr_array_set_size (array, array->len + 1);

	if (index_ < 0) {
		index_ = array->len;
	}

	if (index_ < array->len) {
		memmove (&(array->pdata[index_ + 1]), &(array->pdata[index_]),
				(array->len - index_) * sizeof(gpointer));
	}

	array->pdata[index_] = data;
}
#endif

#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 32))
const gchar *
g_environ_getenv (gchar **envp, const gchar *variable)
{
	gsize len;
	gint i;

	if (envp == NULL) {
		return NULL;
	}

	len = strlen (variable);

	for (i = 0; envp[i]; i++) {
		if (strncmp (envp[i], variable, len) == 0 && envp[i][len] == '=') {
			return envp[i] + len + 1;
		}
	}

	return NULL;
}
#endif

gint
rspamd_fallocate (gint fd, off_t offset, off_t len)
{
#if defined(HAVE_FALLOCATE)
	return fallocate (fd, 0, offset, len);
#elif defined(HAVE_POSIX_FALLOCATE)
	return posix_fallocate (fd, offset, len);
#else
	/* Return 0 as nothing can be done on this system */
	return 0;
#endif
}


/**
 * Create new mutex
 * @return mutex or NULL
 */
inline rspamd_mutex_t *
rspamd_mutex_new (void)
{
	rspamd_mutex_t *new;

	new = g_malloc0 (sizeof (rspamd_mutex_t));
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_mutex_init (&new->mtx);
#else
	g_static_mutex_init (&new->mtx);
#endif

	return new;
}

/**
 * Lock mutex
 * @param mtx
 */
inline void
rspamd_mutex_lock (rspamd_mutex_t *mtx)
{
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_mutex_lock (&mtx->mtx);
#else
	g_static_mutex_lock (&mtx->mtx);
#endif
}

/**
 * Unlock mutex
 * @param mtx
 */
inline void
rspamd_mutex_unlock (rspamd_mutex_t *mtx)
{
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_mutex_unlock (&mtx->mtx);
#else
	g_static_mutex_unlock (&mtx->mtx);
#endif
}

void
rspamd_mutex_free (rspamd_mutex_t *mtx)
{
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_mutex_clear (&mtx->mtx);
#endif
	g_free (mtx);
}

struct rspamd_thread_data {
	gchar *name;
	gint id;
	GThreadFunc func;
	gpointer data;
};

static gpointer
rspamd_thread_func (gpointer ud)
{
	struct rspamd_thread_data *td = ud;
	sigset_t s_mask;

	/* Ignore signals in thread */
	sigemptyset (&s_mask);
	sigaddset (&s_mask, SIGINT);
	sigaddset (&s_mask, SIGHUP);
	sigaddset (&s_mask, SIGCHLD);
	sigaddset (&s_mask, SIGUSR1);
	sigaddset (&s_mask, SIGUSR2);
	sigaddset (&s_mask, SIGALRM);
	sigaddset (&s_mask, SIGPIPE);

	pthread_sigmask (SIG_BLOCK, &s_mask, NULL);

	ud = td->func (td->data);
	g_free (td->name);
	g_free (td);

	return ud;
}

struct hash_copy_callback_data {
	gpointer (*key_copy_func)(gconstpointer data, gpointer ud);
	gpointer (*value_copy_func)(gconstpointer data, gpointer ud);
	gpointer ud;
	GHashTable *dst;
};

static void
copy_foreach_callback (gpointer key, gpointer value, gpointer ud)
{
	struct hash_copy_callback_data *cb = ud;
	gpointer nkey, nvalue;

	nkey = cb->key_copy_func ? cb->key_copy_func (key, cb->ud) : (gpointer)key;
	nvalue =
		cb->value_copy_func ? cb->value_copy_func (value,
			cb->ud) : (gpointer)value;
	g_hash_table_insert (cb->dst, nkey, nvalue);
}
/**
 * Deep copy of one hash table to another
 * @param src source hash
 * @param dst destination hash
 * @param key_copy_func function called to copy or modify keys (or NULL)
 * @param value_copy_func function called to copy or modify values (or NULL)
 * @param ud user data for copy functions
 */
void
rspamd_hash_table_copy (GHashTable *src, GHashTable *dst,
	gpointer (*key_copy_func)(gconstpointer data, gpointer ud),
	gpointer (*value_copy_func)(gconstpointer data, gpointer ud),
	gpointer ud)
{
	struct hash_copy_callback_data cb;
	if (src != NULL && dst != NULL) {
		cb.key_copy_func = key_copy_func;
		cb.value_copy_func = value_copy_func;
		cb.ud = ud;
		cb.dst = dst;
		g_hash_table_foreach (src, copy_foreach_callback, &cb);
	}
}

static volatile sig_atomic_t saved_signo[NSIG];

static
void
read_pass_tmp_sig_handler (int s)
{

	saved_signo[s] = 1;
}

#ifndef _PATH_TTY
# define _PATH_TTY "/dev/tty"
#endif

gint
rspamd_read_passphrase (gchar *buf, gint size, gint rwflag, gpointer key)
{
#ifdef HAVE_READPASSPHRASE_H
	if (readpassphrase ("Enter passphrase: ", buf, size, RPP_ECHO_OFF |
		RPP_REQUIRE_TTY) == NULL) {
		return 0;
	}

	return strlen (buf);
#else
	struct sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	struct sigaction savetstp, savettin, savettou, savepipe;
	struct termios term, oterm;
	gint input, output, i;
	gchar *end, *p, ch;

restart:
	if ((input = output = open (_PATH_TTY, O_RDWR)) == -1) {
		errno = ENOTTY;
		return 0;
	}

	(void)fcntl (input, F_SETFD, FD_CLOEXEC);

	/* Turn echo off */
	if (tcgetattr (input, &oterm) != 0) {
		close (input);
		errno = ENOTTY;
		return 0;
	}

	memcpy (&term, &oterm, sizeof(term));
	term.c_lflag &= ~(ECHO | ECHONL);

	if (tcsetattr (input, TCSAFLUSH, &term) == -1) {
		errno = ENOTTY;
		close (input);
		return 0;
	}

	g_assert (write (output, "Enter passphrase: ", sizeof ("Enter passphrase: ") -
		1) != -1);

	/* Save the current sighandler */
	for (i = 0; i < NSIG; i++) {
		saved_signo[i] = 0;
	}
	sigemptyset (&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = read_pass_tmp_sig_handler;
	(void)sigaction (SIGALRM, &sa, &savealrm);
	(void)sigaction (SIGHUP, &sa, &savehup);
	(void)sigaction (SIGINT, &sa, &saveint);
	(void)sigaction (SIGPIPE, &sa, &savepipe);
	(void)sigaction (SIGQUIT, &sa, &savequit);
	(void)sigaction (SIGTERM, &sa, &saveterm);
	(void)sigaction (SIGTSTP, &sa, &savetstp);
	(void)sigaction (SIGTTIN, &sa, &savettin);
	(void)sigaction (SIGTTOU, &sa, &savettou);

	/* Now read a passphrase */
	p = buf;
	end = p + size - 1;
	while (read (input, &ch, 1) == 1 && ch != '\n' && ch != '\r') {
		if (p < end) {
			*p++ = ch;
		}
	}
	*p = '\0';
	g_assert (write (output, "\n", 1) == 1);

	/* Restore terminal state */
	if (memcmp (&term, &oterm, sizeof (term)) != 0) {
		while (tcsetattr (input, TCSAFLUSH, &oterm) == -1 &&
			errno == EINTR && !saved_signo[SIGTTOU]) ;
	}

	/* Restore signal handlers */
	(void)sigaction (SIGALRM, &savealrm, NULL);
	(void)sigaction (SIGHUP, &savehup, NULL);
	(void)sigaction (SIGINT, &saveint, NULL);
	(void)sigaction (SIGQUIT, &savequit, NULL);
	(void)sigaction (SIGPIPE, &savepipe, NULL);
	(void)sigaction (SIGTERM, &saveterm, NULL);
	(void)sigaction (SIGTSTP, &savetstp, NULL);
	(void)sigaction (SIGTTIN, &savettin, NULL);
	(void)sigaction (SIGTTOU, &savettou, NULL);

	close (input);

	/* Send signals pending */
	for (i = 0; i < NSIG; i++) {
		if (saved_signo[i]) {
			kill (getpid (), i);
			switch (i) {
			case SIGTSTP:
			case SIGTTIN:
			case SIGTTOU:
				goto restart;
			}
		}
	}

	return (p - buf);
#endif
}

#ifdef HAVE_CLOCK_GETTIME
# ifdef CLOCK_MONOTONIC_COARSE
#  define RSPAMD_FAST_MONOTONIC_CLOCK CLOCK_MONOTONIC_COARSE
# elif defined(CLOCK_MONOTONIC_FAST)
#  define RSPAMD_FAST_MONOTONIC_CLOCK CLOCK_MONOTONIC_FAST
# else
#  define RSPAMD_FAST_MONOTONIC_CLOCK CLOCK_MONOTONIC
# endif
#endif

gdouble
rspamd_get_ticks (gboolean rdtsc_ok)
{
	gdouble res;

#ifdef HAVE_RDTSC
# ifdef __x86_64__
	guint64 r64;

	if (rdtsc_ok) {
		__builtin_ia32_lfence ();
		r64 = __rdtsc ();
		/* Preserve lower 52 bits */
		res = r64 & ((1ULL << 53) - 1);
		return res;
	}
# endif
#endif
#ifdef HAVE_CLOCK_GETTIME
	struct timespec ts;
	gint clk_id = RSPAMD_FAST_MONOTONIC_CLOCK;

	clock_gettime (clk_id, &ts);

	if (rdtsc_ok) {
		res = (double) ts.tv_sec * 1e9 + ts.tv_nsec;
	}
	else {
		res = (double) ts.tv_sec + ts.tv_nsec / 1000000000.;
	}
# elif defined(__APPLE__)
	if (rdtsc_ok) {
		res = mach_absolute_time ();
	}
	else {
		res = mach_absolute_time () / 1000000000.;
	}
#else
	struct timeval tv;

	(void)gettimeofday (&tv, NULL);
	if (rdtsc_ok) {
		res = (double) ts.tv_sec * 1e9 + tv.tv_usec * 1e3;
	}
	else {
		res = (double)tv.tv_sec + tv.tv_usec / 1000000.;
	}
#endif

	return res;
}

gdouble
rspamd_get_virtual_ticks (void)
{
	gdouble res;

#ifdef HAVE_CLOCK_GETTIME
	struct timespec ts;
	static clockid_t cid = (clockid_t)-1;
	if (cid == (clockid_t)-1) {
# ifdef HAVE_CLOCK_GETCPUCLOCKID
		if (clock_getcpuclockid (0, &cid) == -1) {
# endif
# ifdef CLOCK_PROCESS_CPUTIME_ID
		cid = CLOCK_PROCESS_CPUTIME_ID;
# elif defined(CLOCK_PROF)
		cid = CLOCK_PROF;
# else
		cid = CLOCK_REALTIME;
# endif
# ifdef HAVE_CLOCK_GETCPUCLOCKID
		}
# endif
	}

	clock_gettime (cid, &ts);
	res = (double)ts.tv_sec + ts.tv_nsec / 1000000000.;
#elif defined(__APPLE__)
	thread_port_t thread = mach_thread_self ();

	mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
	thread_basic_info_data_t info;
	if (thread_info (thread, THREAD_BASIC_INFO, (thread_info_t)&info, &count) != KERN_SUCCESS) {
		return -1;
	}

	res = info.user_time.seconds + info.system_time.seconds;
	res += ((gdouble)(info.user_time.microseconds + info.system_time.microseconds)) / 1e6;
	mach_port_deallocate(mach_task_self(), thread);
#elif defined(HAVE_RUSAGE_SELF)
	struct rusage rusage;
	if (getrusage (RUSAGE_SELF, &rusage) != -1) {
		res = (double) rusage.ru_utime.tv_sec +
			  (double) rusage.ru_utime.tv_usec / 1000000.0;
	}
#else
	res = clock () / (double)CLOCKS_PER_SEC;
#endif

	return res;
}

gdouble
rspamd_get_calendar_ticks (void)
{
	gdouble res;
#ifdef HAVE_CLOCK_GETTIME
	struct timespec ts;

	clock_gettime (CLOCK_REALTIME, &ts);
	res = ts_to_double (&ts);
#else
	struct timeval tv;

	if (gettimeofday (&tv, NULL) == 0) {
		res = tv_to_double (&tv);
	}
	else {
		res = time (NULL);
	}
#endif

	return res;
}

void
rspamd_random_hex (guchar *buf, guint64 len)
{
	static const gchar hexdigests[16] = "0123456789abcdef";
	gint64 i;

	g_assert (len > 0);

	ottery_rand_bytes (buf, ceil (len / 2.0));

	for (i = (gint64)len - 1; i >= 0; i -= 2) {
		buf[i] = hexdigests[buf[i / 2] & 0xf];

		if (i > 0) {
			buf[i - 1] = hexdigests[(buf[i / 2] >> 4) & 0xf];
		}
	}
}

gint
rspamd_shmem_mkstemp (gchar *pattern)
{
	gint fd = -1;
	gchar *nbuf, *xpos;
	gsize blen;

	xpos = strchr (pattern, 'X');

	if (xpos == NULL) {
		errno = EINVAL;
		return -1;
	}

	blen = strlen (pattern);
	nbuf = g_malloc (blen + 1);
	rspamd_strlcpy (nbuf, pattern, blen + 1);
	xpos = nbuf + (xpos - pattern);

	for (;;) {
		rspamd_random_hex (xpos, blen - (xpos - nbuf));

		fd = shm_open (nbuf, O_RDWR | O_EXCL | O_CREAT, 0600);

		if (fd != -1) {
			rspamd_strlcpy (pattern, nbuf, blen + 1);
			break;
		}
		else if (errno != EEXIST) {
			g_free (nbuf);

			return -1;
		}
	}

	g_free (nbuf);

	return fd;
}

void
rspamd_ptr_array_free_hard (gpointer p)
{
	GPtrArray *ar = (GPtrArray *)p;

	g_ptr_array_free (ar, TRUE);
}

void
rspamd_array_free_hard (gpointer p)
{
	GArray *ar = (GArray *)p;

	g_array_free (ar, TRUE);
}

void
rspamd_gstring_free_hard (gpointer p)
{
	GString *ar = (GString *)p;

	g_string_free (ar, TRUE);
}

void rspamd_gerror_free_maybe (gpointer p)
{
	GError **err;

	if (p) {
		err = (GError **)p;

		if (*err) {
			g_error_free (*err);
		}
	}
}

/*
 * Openblas creates threads that are not supported by
 * jemalloc allocator (aside of being bloody stupid). So this hack
 * is intended to set number of threads to one by default.
 * FIXME: is it legit to do so in ctor?
 */
#ifdef HAVE_OPENBLAS_SET_NUM_THREADS
extern void openblas_set_num_threads(int num_threads);
RSPAMD_CONSTRUCTOR (openblas_thread_fix_ctor)
{
	openblas_set_num_threads (1);
}
#endif
#ifdef HAVE_BLI_THREAD_SET_NUM_THREADS
extern void bli_thread_set_num_threads(int num_threads);
RSPAMD_CONSTRUCTOR (blis_thread_fix_ctor)
{
	bli_thread_set_num_threads (1);
}
#endif

guint64
rspamd_hash_seed (void)
{
#if 0
	static guint64 seed;

	if (seed == 0) {
		seed = ottery_rand_uint64 ();
	}
#endif

	/* Proved to be random, I promise! */
	/*
	 * TODO: discover if it worth to use random seed on run
	 * with ordinary hash function or we need to switch to
	 * siphash1-3 or other slow cooker function...
	 */
	return 0xabf9727ba290690bULL;
}

static inline gdouble
rspamd_double_from_int64 (guint64 x)
{
	const union { guint64 i; double d; } u = {
			.i = G_GUINT64_CONSTANT(0x3FF) << 52 | x >> 12
	};

	return u.d - 1.0;
}

gdouble
rspamd_random_double (void)
{
	guint64 rnd_int;

	rnd_int = ottery_rand_uint64 ();

	return rspamd_double_from_int64 (rnd_int);
}


static guint64*
xorshifto_seed (void)
{
	static guint64 xorshifto_seed[4];
	static bool initialized = false;

	if (G_UNLIKELY(!initialized)) {
		ottery_rand_bytes((void *)xorshifto_seed, sizeof (xorshifto_seed));
		initialized = true;
	}

	return xorshifto_seed;
}

static inline guint64
xoroshiro_rotl (const guint64 x, int k) {
	return (x << k) | (x >> (64 - k));
}

gdouble
rspamd_random_double_fast (void)
{
	return rspamd_random_double_fast_seed (xorshifto_seed());
}

/* xoshiro256+ */
inline gdouble
rspamd_random_double_fast_seed (guint64 seed[4])
{
	const uint64_t result = seed[0] + seed[3];

	const uint64_t t = seed[1] << 17;

	seed[2] ^= seed[0];
	seed[3] ^= seed[1];
	seed[1] ^= seed[2];
	seed[0] ^= seed[3];

	seed[2] ^= t;

	seed[3] = xoroshiro_rotl (seed[3], 45);

	return rspamd_double_from_int64 (result);
}

/* xoroshiro256** */
static inline guint64
rspamd_random_uint64_fast_seed (guint64 seed[4])
{
	const uint64_t result = xoroshiro_rotl (seed[1] * 5, 7) * 9;

	const uint64_t t = seed[1] << 17;

	seed[2] ^= seed[0];
	seed[3] ^= seed[1];
	seed[1] ^= seed[2];
	seed[0] ^= seed[3];

	seed[2] ^= t;

	seed[3] = xoroshiro_rotl (seed[3], 45);

	return result;
}

guint64
rspamd_random_uint64_fast (void)
{
	return rspamd_random_uint64_fast_seed (xorshifto_seed());
}

void
rspamd_random_seed_fast (void)
{
	(void)xorshifto_seed();
}

gdouble
rspamd_time_jitter (gdouble in, gdouble jitter)
{
	if (jitter == 0) {
		jitter = in;
	}

	return in + jitter * rspamd_random_double ();
}

gboolean
rspamd_constant_memcmp (const void *a, const void *b, gsize len)
{
	gsize lena, lenb, i;
	guint16 d, r = 0, m;
	guint16 v;
	const guint8 *aa = (const guint8 *)a,
			*bb =  (const guint8 *)b;

	if (len == 0) {
		lena = strlen ((const char*)a);
		lenb = strlen ((const char*)b);

		if (lena != lenb) {
			return FALSE;
		}

		len = lena;
	}

	for (i = 0; i < len; i++) {
		v = ((guint16)(guint8)r) + 255;
		m = v / 256 - 1;
		d = (guint16)((int)aa[i] - (int)bb[i]);
		r |= (d & m);
	}

	return (((gint32)(guint16)((guint32)r + 0x8000) - 0x8000) == 0);
}

int
rspamd_file_xopen (const char *fname, int oflags, guint mode,
		gboolean allow_symlink)
{
	struct stat sb;
	int fd, flags = oflags;

	if (lstat (fname, &sb) == -1) {

		if (errno != ENOENT) {
			return (-1);
		}
	}
	else if (!S_ISREG (sb.st_mode)) {
		if (S_ISLNK (sb.st_mode)) {
			if (!allow_symlink) {
				return -1;
			}
		}
		else {
			return -1;
		}
	}

#ifdef HAVE_OCLOEXEC
	flags |= O_CLOEXEC;
#endif

#ifdef HAVE_ONOFOLLOW
	if (!allow_symlink) {
		flags |= O_NOFOLLOW;
		fd = open (fname, flags, mode);
	}
	else {
		fd = open (fname, flags, mode);
	}
#else
	fd = open (fname, flags, mode);
#endif

#ifndef HAVE_OCLOEXEC
	int serrno;
	if (fcntl (fd, F_SETFD, FD_CLOEXEC) == -1) {
		serrno = errno;
		close (fd);
		errno = serrno;

		return -1;
	}
#endif

	return (fd);
}

gpointer
rspamd_file_xmap (const char *fname, guint mode, gsize *size,
		gboolean allow_symlink)
{
	gint fd;
	struct stat sb;
	gpointer map;

	g_assert (fname != NULL);
	g_assert (size != NULL);

	if (mode & PROT_WRITE) {
		fd = rspamd_file_xopen (fname, O_RDWR, 0, allow_symlink);
	}
	else {
		fd = rspamd_file_xopen (fname, O_RDONLY, 0, allow_symlink);
	}

	if (fd == -1) {
		return NULL;
	}

	if (fstat (fd, &sb) == -1 || !S_ISREG (sb.st_mode)) {
		close (fd);
		*size = (gsize)-1;

		return NULL;
	}

	if (sb.st_size == 0) {
		close (fd);
		*size = (gsize)0;

		return NULL;
	}

	map = mmap (NULL, sb.st_size, mode, MAP_SHARED, fd, 0);
	close (fd);

	if (map == MAP_FAILED) {
		return NULL;
	}

	*size = sb.st_size;

	return map;
}


gpointer
rspamd_shmem_xmap (const char *fname, guint mode,
		gsize *size)
{
	gint fd;
	struct stat sb;
	gpointer map;

	g_assert (fname != NULL);
	g_assert (size != NULL);

#ifdef HAVE_SANE_SHMEM
	if (mode & PROT_WRITE) {
		fd = shm_open (fname, O_RDWR, 0);
	}
	else {
		fd = shm_open (fname, O_RDONLY, 0);
	}
#else
	if (mode & PROT_WRITE) {
		fd = open (fname, O_RDWR, 0);
	}
	else {
		fd = open (fname, O_RDONLY, 0);
	}
#endif

	if (fd == -1) {
		return NULL;
	}

	if (fstat (fd, &sb) == -1) {
		close (fd);

		return NULL;
	}

	map = mmap (NULL, sb.st_size, mode, MAP_SHARED, fd, 0);
	close (fd);

	if (map == MAP_FAILED) {
		return NULL;
	}

	*size = sb.st_size;

	return map;
}

/*
 * A(x - 0.5)^4 + B(x - 0.5)^3 + C(x - 0.5)^2 + D(x - 0.5)
 * A = 32,
 * B = -6
 * C = -7
 * D = 3
 * y = 32(x - 0.5)^4 - 6(x - 0.5)^3 - 7(x - 0.5)^2 + 3(x - 0.5)
 *
 * New approach:
 * y = ((x - bias)*2)^8
 */
gdouble
rspamd_normalize_probability (gdouble x, gdouble bias)
{
	gdouble xx;

	xx = (x - bias) * 2.0;

	return pow (xx, 8);
}

/*
 * Calculations from musl libc
 */
guint64
rspamd_tm_to_time (const struct tm *tm, glong tz)
{
	guint64 result;
	gboolean is_leap = FALSE;
	gint leaps, y = tm->tm_year, cycles, rem, centuries;
	glong offset = (tz / 100) * 3600 + (tz % 100) * 60;

	/* How many seconds in each month from the beginning of the year */
	static const gint secs_through_month[] = {
			0, 31*86400, 59*86400, 90*86400,
			120*86400, 151*86400, 181*86400, 212*86400,
			243*86400, 273*86400, 304*86400, 334*86400
	};

	/* Convert year */
	if (tm->tm_year - 2ULL <= 136) {
		leaps = (y - 68) / 4;

		if (!((y - 68) & 3)) {
			leaps--;
			is_leap = 1;
		}

		result = 31536000 * (y - 70) + 86400 * leaps;
	}
	else {
		cycles = (y - 100) / 400;
		rem = (y - 100) % 400;
		if (rem < 0) {
			cycles--;
			rem += 400;
		}

		if (!rem) {
			is_leap = 1;
			centuries = 0;
			leaps = 0;
		}
		else {
			if (rem >= 200) {
				if (rem >= 300) {
					centuries = 3;
					rem -= 300;
				}
				else {
					centuries = 2;
					rem -= 200;
				}
			}
			else {
				if (rem >= 100) {
					centuries = 1;
					rem -= 100;
				}
				else {
					centuries = 0;
				}
			}

			if (!rem) {
				is_leap = 1;
				leaps = 0;
			} else {
				leaps = rem / 4U;
				rem %= 4U;
				is_leap = !rem;
			}
		}

		leaps += 97 * cycles + 24 * centuries - (gint)is_leap;
		result = (y - 100) * 31536000LL + leaps * 86400LL + 946684800 + 86400;
	}

	/* Now convert months to seconds */
	result += secs_through_month[tm->tm_mon];
	/* One more day */
	if (is_leap && tm->tm_mon >= 2) {
		result += 86400;
	}

	result += 86400LL * (tm->tm_mday-1);
	result += 3600LL * tm->tm_hour;
	result += 60LL * tm->tm_min;
	result += tm->tm_sec;

	/* Now apply tz offset */
	result -= offset;

	return result;
}


void
rspamd_gmtime (gint64 ts, struct tm *dest)
{
	guint64 days, secs, years;
	int remdays, remsecs, remyears;
	int leap_400_cycles, leap_100_cycles, leap_4_cycles;
	int months;
	int wday, yday, leap;
	/* From March */
	static const uint8_t days_in_month[] = {31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 29};
	static const guint64 leap_epoch = 946684800ULL + 86400 * (31 + 29);
	static const guint64 days_per_400y = 365*400 + 97;
	static const guint64 days_per_100y = 365*100 + 24;
	static const guint64 days_per_4y = 365*4 + 1;

	secs = ts - leap_epoch;
	days = secs / 86400;
	remsecs = secs % 86400;

	if (remsecs < 0) {
		remsecs += 86400;
		days--;
	}

	wday = (3 + days) % 7;
	if (wday < 0) {
		wday += 7;
	}

	/* Deal with gregorian adjustments */
	leap_400_cycles = days / days_per_400y;
	remdays = days % days_per_400y;

	if (remdays < 0) {
		remdays += days_per_400y;
		leap_400_cycles--;
	}

	leap_100_cycles = remdays / days_per_100y;
	if (leap_100_cycles == 4) {
		/* 400 years */
		leap_100_cycles--;
	}

	remdays -= leap_100_cycles * days_per_100y;

	leap_4_cycles = remdays / days_per_4y;
	if (leap_4_cycles == 25) {
		/* 100 years */
		leap_4_cycles--;
	}
	remdays -= leap_4_cycles * days_per_4y;

	remyears = remdays / 365;
	if (remyears == 4) {
		/* Ordinary leap year */
		remyears--;
	}
	remdays -= remyears * 365;

	leap = !remyears && (leap_4_cycles || !leap_100_cycles);
	yday = remdays + 31 + 28 + leap;

	if (yday >= 365 + leap) {
		yday -= 365 + leap;
	}

	years = remyears + 4 * leap_4_cycles + 100 * leap_100_cycles +
			400ULL * leap_400_cycles;

	for (months=0; days_in_month[months] <= remdays; months++) {
		remdays -= days_in_month[months];
	}

	if (months >= 10) {
		months -= 12;
		years++;
	}

	dest->tm_year = years + 100;
	dest->tm_mon = months + 2;
	dest->tm_mday = remdays + 1;
	dest->tm_wday = wday;
	dest->tm_yday = yday;

	dest->tm_hour = remsecs / 3600;
	dest->tm_min = remsecs / 60 % 60;
	dest->tm_sec = remsecs % 60;
#if !defined(__sun)
	dest->tm_gmtoff = 0;
	dest->tm_zone = "GMT";
#endif
}

void
rspamd_localtime (gint64 ts, struct tm *dest)
{
	time_t t = ts;
	localtime_r (&t, dest);
}

gboolean
rspamd_fstring_gzip (rspamd_fstring_t **in)
{
	z_stream strm;
	gint rc;
	rspamd_fstring_t *comp, *buf = *in;
	gchar *p;
	gsize remain;

	memset (&strm, 0, sizeof (strm));
	rc = deflateInit2 (&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
			MAX_WBITS + 16, MAX_MEM_LEVEL - 1, Z_DEFAULT_STRATEGY);

	if (rc != Z_OK) {
		return FALSE;
	}

	comp = rspamd_fstring_sized_new (deflateBound (&strm, buf->len));

	strm.avail_in = buf->len;
	strm.next_in = (guchar *)buf->str;
	p = comp->str;
	remain = comp->allocated;

	while (strm.avail_in != 0) {
		strm.avail_out = remain;
		strm.next_out = p;

		rc = deflate (&strm, Z_FINISH);

		if (rc != Z_OK && rc != Z_BUF_ERROR) {
			if (rc == Z_STREAM_END) {
				break;
			}
			else {
				rspamd_fstring_free (comp);
				deflateEnd (&strm);

				return FALSE;
			}
		}

		comp->len = strm.total_out;

		if (strm.avail_out == 0 && strm.avail_in != 0) {
			/* Need to allocate more */
			remain = comp->len;
			comp = rspamd_fstring_grow (comp, strm.avail_in);
			p = comp->str + remain;
			remain = comp->allocated - remain;
		}
	}

	deflateEnd (&strm);
	comp->len = strm.total_out;
	rspamd_fstring_free (buf); /* We replace buf with its compressed version */
	*in = comp;

	return TRUE;
}

static gboolean
rspamd_glob_dir (const gchar *full_path, const gchar *pattern,
				 gboolean recursive, guint rec_len,
				 GPtrArray *res, GError **err)
{
	glob_t globbuf;
	const gchar *path;
	static gchar pathbuf[PATH_MAX]; /* Static to help recursion */
	guint i;
	gint rc;
	static const guint rec_lim = 16;
	struct stat st;

	if (rec_len > rec_lim) {
		g_set_error (err, g_quark_from_static_string ("glob"), EOVERFLOW,
				"maximum nesting is reached: %d", rec_lim);

		return FALSE;
	}

	memset (&globbuf, 0, sizeof (globbuf));

	if ((rc = glob (full_path, 0, NULL, &globbuf)) != 0) {

		if (rc != GLOB_NOMATCH) {
			g_set_error (err, g_quark_from_static_string ("glob"), errno,
					"glob %s failed: %s", full_path, strerror (errno));
			globfree (&globbuf);

			return FALSE;
		}
		else {
			globfree (&globbuf);

			return TRUE;
		}
	}

	for (i = 0; i < globbuf.gl_pathc; i ++) {
		path = globbuf.gl_pathv[i];

		if (stat (path, &st) == -1) {
			if (errno == EPERM || errno == EACCES || errno == ELOOP) {
				/* Silently ignore */
				continue;
			}

			g_set_error (err, g_quark_from_static_string ("glob"), errno,
					"stat %s failed: %s", path, strerror (errno));
			globfree (&globbuf);

			return FALSE;
		}

		if (S_ISREG (st.st_mode)) {
			g_ptr_array_add (res, g_strdup (path));
		}
		else if (recursive && S_ISDIR (st.st_mode)) {
			rspamd_snprintf (pathbuf, sizeof (pathbuf), "%s%c%s",
					path, G_DIR_SEPARATOR, pattern);

			if (!rspamd_glob_dir (full_path, pattern, recursive, rec_len + 1,
					res, err)) {
				globfree (&globbuf);

				return FALSE;
			}
		}
	}

	globfree (&globbuf);

	return TRUE;
}

GPtrArray *
rspamd_glob_path (const gchar *dir,
				  const gchar *pattern,
				  gboolean recursive,
				  GError **err)
{
	gchar path[PATH_MAX];
	GPtrArray *res;

	res = g_ptr_array_new_full (32, (GDestroyNotify)g_free);
	rspamd_snprintf (path, sizeof (path), "%s%c%s", dir, G_DIR_SEPARATOR, pattern);

	if (!rspamd_glob_dir (path, pattern, recursive, 0, res, err)) {
		g_ptr_array_free (res, TRUE);

		return NULL;
	}

	return res;
}

double
rspamd_set_counter (struct rspamd_counter_data *cd, gdouble value)
{
	gdouble cerr;

	/* Cumulative moving average using per-process counter data */
	if (cd->number == 0) {
		cd->mean = 0;
		cd->stddev = 0;
	}

	cd->mean += (value - cd->mean) / (gdouble)(++cd->number);
	cerr = (value - cd->mean) * (value - cd->mean);
	cd->stddev += (cerr - cd->stddev) / (gdouble)(cd->number);

	return cd->mean;
}

float
rspamd_set_counter_ema (struct rspamd_counter_data *cd,
		float value,
		float alpha)
{
	float diff, incr;

	/* Cumulative moving average using per-process counter data */
	if (cd->number == 0) {
		cd->mean = 0;
		cd->stddev = 0;
	}

	diff = value - cd->mean;
	incr = diff * alpha;
	cd->mean += incr;
	cd->stddev = (1.0f - alpha) * (cd->stddev + diff * incr);
	cd->number ++;

	return cd->mean;
}

void
rspamd_ptr_array_shuffle (GPtrArray *ar)
{
	if (ar->len < 2) {
		return;
	}

	guint n = ar->len;

	for (guint i = 0; i < n - 1; i++) {
		guint j = i + rspamd_random_uint64_fast () % (n - i);
		gpointer t = g_ptr_array_index (ar, j);
		g_ptr_array_index (ar, j) = g_ptr_array_index (ar, i);
		g_ptr_array_index (ar, i) = t;
	}
}
