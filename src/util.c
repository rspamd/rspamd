/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
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

#ifdef HAVE_OPENSSL
#include <openssl/rand.h>
#include <openssl/err.h>
#endif

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#ifdef HAVE_READPASSPHRASE_H
#include <readpassphrase.h>
#endif

/* Check log messages intensity once per minute */
#define CHECK_TIME 60
/* More than 2 log messages per second */
#define BUF_INTENSITY 2
/* Default connect timeout for sync sockets */
#define CONNECT_TIMEOUT 3

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
make_inet_socket (gint type, struct addrinfo *addr, gboolean is_server, gboolean async, GList **list)
{
	gint                            fd, r, optlen, on = 1, s_error;
	struct addrinfo               *cur;

	cur = addr;
	while (cur) {
		/* Create socket */
		fd = socket (cur->ai_family, type, 0);
		if (fd == -1) {
			msg_warn ("socket failed: %d, '%s'", errno, strerror (errno));
			goto out;
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
#ifdef HAVE_IPV6_V6ONLY
			if (cur->ai_family == AF_INET6) {
				setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, (const void *)&on, sizeof (gint));
			}
#endif
			r = bind (fd, cur->ai_addr, cur->ai_addrlen);
		}
		else {
			r = connect (fd, cur->ai_addr, cur->ai_addrlen);
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
		if (list == NULL) {
			/* Go out immediately */
			break;
		}
		else if (fd != -1) {
			*list = g_list_prepend (*list, GINT_TO_POINTER (fd));
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
make_tcp_socket (struct addrinfo *addr, gboolean is_server, gboolean async)
{
	return make_inet_socket (SOCK_STREAM, addr, is_server, async, NULL);
}

gint
make_udp_socket (struct addrinfo *addr, gboolean is_server, gboolean async)
{
	return make_inet_socket (SOCK_DGRAM, addr, is_server, async, NULL);
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
make_unix_socket (const gchar *path, struct sockaddr_un *addr, gint type, gboolean is_server, gboolean async)
{
	gint                            fd = -1, s_error, r, optlen, serrno, on = 1;
	struct stat                     st;

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
					msg_warn ("unlink %s failed: %d, '%s'", addr->sun_path, errno, strerror (errno));
					goto out;
				}
			}
			else {
				msg_warn ("%s is not a socket", addr->sun_path);
				goto out;
			}
		}
	}
	fd = socket (PF_LOCAL, type, 0);

	if (fd == -1) {
		msg_warn ("socket failed %s: %d, '%s'", addr->sun_path, errno, strerror (errno));
		return -1;
	}

	if (make_socket_nonblocking (fd) < 0) {
		goto out;
	}

	/* Set close on exec */
	if (fcntl (fd, F_SETFD, FD_CLOEXEC) == -1) {
		msg_warn ("fcntl failed %s: %d, '%s'", addr->sun_path, errno, strerror (errno));
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
			msg_warn ("bind/connect failed %s: %d, '%s'", addr->sun_path, errno, strerror (errno));
			goto out;
		}
		if (!async) {
			/* Try to poll */
			if (poll_sync_socket (fd, CONNECT_TIMEOUT * 1000, POLLOUT) <= 0) {
				errno = ETIMEDOUT;
				msg_warn ("bind/connect failed %s: timeout", addr->sun_path);
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
	if (fd != -1) {
		close (fd);
	}
	errno = serrno;
	return (-1);
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
make_universal_socket (const gchar *credits, guint16 port,
		gint type, gboolean async, gboolean is_server, gboolean try_resolve)
{
	struct sockaddr_un              un;
	struct stat                     st;
	struct addrinfo                 hints, *res;
	gint                             r;
	gchar                            portbuf[8];

	if (*credits == '/') {
		if (is_server) {
			return make_unix_socket (credits, &un, type, is_server, async);
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
					return make_unix_socket (credits, &un, type, is_server, async);
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
			r = make_inet_socket (type, res, is_server, async, NULL);
			freeaddrinfo (res);
			return r;
		}
		else {
			msg_err ("address resolution for %s failed: %s", credits, gai_strerror (r));
			return FALSE;
		}
	}
}

/**
 * Make universal stream socket
 * @param credits host, ip or path to unix socket
 * @param port port (used for network sockets)
 * @param async make this socket asynced
 * @param is_server make this socket as server socket
 * @param try_resolve try name resolution for a socket (BLOCKING)
 */
GList*
make_universal_sockets_list (const gchar *credits, guint16 port,
		gint type, gboolean async, gboolean is_server, gboolean try_resolve)
{
	struct sockaddr_un              un;
	struct stat                     st;
	struct addrinfo                 hints, *res;
	gint                             r, fd, serrno;
	gchar                            portbuf[8], **strv, **cur;
	GList                           *result = NULL, *rcur;

	strv = g_strsplit_set (credits, ",", -1);
	if (strv == NULL) {
		msg_err ("invalid sockets credentials: %s", credits);
		return NULL;
	}
	cur = strv;
	while (*cur != NULL) {
		if (*credits == '/') {
			if (is_server) {
				fd = make_unix_socket (credits, &un, type, is_server, async);
			}
			else {
				r = stat (credits, &st);
				if (r == -1) {
					/* Unix socket doesn't exists it must be created first */
					errno = ENOENT;
					goto err;
				}
				else {
					if ((st.st_mode & S_IFSOCK) == 0) {
						/* Path is not valid socket */
						errno = EINVAL;
						goto err;
					}
					else {
						fd = make_unix_socket (credits, &un, type, is_server, async);
					}
				}
			}
			if (fd != -1) {
				result = g_list_prepend (result, GINT_TO_POINTER (fd));
			}
			else {
				goto err;
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
				r = make_inet_socket (type, res, is_server, async, &result);
				freeaddrinfo (res);
				if (r == -1) {
					goto err;
				}
			}
			else {
				msg_err ("address resolution for %s failed: %s", credits, gai_strerror (r));
				goto err;
			}
		}
		cur ++;
	}

	g_strfreev (strv);
	return result;

err:
	g_strfreev (strv);
	serrno = errno;
	rcur = result;
	while (rcur != NULL) {
		fd = GPOINTER_TO_INT (rcur->data);
		if (fd != -1) {
			close (fd);
		}
		rcur = g_list_next (rcur);
	}
	if (result != NULL) {
		g_list_free (result);
	}

	errno = serrno;
	return NULL;
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

	if (main->is_privilleged) {
		/* Force root user as owner of pid file */
#ifdef HAVE_PIDFILE_FILENO
		if (fchown (pidfile_fileno (main->pfh), 0, 0) == -1) {
#else
		if (fchown (main->pfh->pf_fd, 0, 0) == -1) {
#endif
			msg_err ("cannot chown of pidfile %s to 0:0 user", main->cfg->pid_file);
		}
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
calculate_check_time (struct timeval *tv, struct timespec *begin, gint resolution, guint32 *scan_time)
#else
const gchar                     *
calculate_check_time (struct timeval *begin, gint resolution, guint32 *scan_time)
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

	*scan_time = diff;

	sprintf (fmt, "%%.%dfms real, %%.%dfms virtual", resolution, resolution);
	snprintf (res, sizeof (res), fmt, diff, vdiff);

	return (const gchar *)res;
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
	gchar							 buf[256];
	guint                            h = 0, i = 0;


	while (*p != '\0') {
		buf[i] = g_ascii_tolower (*p);
		i++;
		p++;
		if (i == sizeof (buf)) {
			h ^= murmur32_hash (buf, i);
			i = 0;
		}
	}

	if (i > 0) {
		h ^= murmur32_hash (buf, i);
	}

	return h;
}

guint
rspamd_str_hash (gconstpointer key)
{
	gsize							len;

	len = strlen ((const gchar *)key);

	return murmur32_hash (key, len);
}

gboolean
rspamd_str_equal (gconstpointer v, gconstpointer v2)
{
	return strcmp ((const gchar *)v, (const gchar *)v2) == 0;
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
	const f_str_t                   *f = key;
	const gchar                     *p;
	guint                            h = 0, i = 0;
	gchar							 buf[256];
	
	p = f->begin;
	while (p - f->begin < (gint)f->len) {
		buf[i] = g_ascii_tolower (*p);
		i++;
		p++;
		if (i == sizeof (buf)) {
			h ^= murmur32_hash (buf, i);
			i = 0;
		}
	}

	if (i > 0) {
		h ^= murmur32_hash (buf, i);
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


#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 22))
void
g_ptr_array_unref (GPtrArray *array)
{
	g_ptr_array_free (array, TRUE);
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

gsize
rspamd_strlcpy_tolower (gchar *dst, const gchar *src, gsize siz)
{
	gchar *d = dst;
	const gchar *s = src;
	gsize n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0) {
		while (--n != 0) {
			if ((*d++ = g_ascii_tolower (*s++)) == '\0') {
				break;
			}
		}
	}

	if (n == 0 && siz != 0) {
		*d = '\0';
	}

	return (s - src - 1);    /* count does not include NUL */
}

/* Compare two emails for building emails tree */
gint
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

gint
compare_url_func (gconstpointer a, gconstpointer b)
{
	const struct uri               *u1 = a, *u2 = b;
	int                             r;

	if (u1->hostlen != u2->hostlen || u1->hostlen == 0) {
		return u1->hostlen - u2->hostlen;
	}
	else {
		r = g_ascii_strncasecmp (u1->host, u2->host, u1->hostlen);
		if (r == 0 && u1->is_phished != u2->is_phished) {
			/* Always insert phished urls to the tree */
			return -1;
		}
	}

	return r;
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
 * Try to convert string of length to long
 */
gboolean
rspamd_strtol (const gchar *s, gsize len, glong *value)
{
	const gchar                    *p = s, *end = s + len;
	gchar							c;
	glong							v = 0;
	const glong						cutoff = G_MAXLONG / 10, cutlim = G_MAXLONG % 10;
	gboolean                        neg;

	/* Case negative values */
	if (*p == '-') {
		neg = TRUE;
		p ++;
	}
	else {
		neg = FALSE;
	}
	/* Some preparations for range errors */

	while (p < end) {
		c = *p;
		if (c >= '0' && c <= '9') {
			c -= '0';
			if (v > cutoff || (v == cutoff && c > cutlim)) {
				/* Range error */
				*value = neg ? G_MINLONG : G_MAXLONG;
				return FALSE;
			}
			else {
				v *= 10;
				v += c;
			}
		}
		else {
			return FALSE;
		}
		p ++;
	}

	*value = neg ? -(v) : v;
	return TRUE;
}

/*
 * Try to convert string of length to long
 */
gboolean
rspamd_strtoul (const gchar *s, gsize len, gulong *value)
{
	const gchar                    *p = s, *end = s + len;
	gchar							c;
	gulong							v = 0;
	const gulong					cutoff = G_MAXULONG / 10, cutlim = G_MAXULONG % 10;

	/* Some preparations for range errors */
	while (p < end) {
		c = *p;
		if (c >= '0' && c <= '9') {
			c -= '0';
			if (v > cutoff || (v == cutoff && (guint8)c > cutlim)) {
				/* Range error */
				*value = G_MAXULONG;
				return FALSE;
			}
			else {
				v *= 10;
				v += c;
			}
		}
		else {
			return FALSE;
		}
		p ++;
	}

	*value = v;
	return TRUE;
}

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
inline rspamd_mutex_t*
rspamd_mutex_new (void)
{
	rspamd_mutex_t					*new;

	new = g_slice_alloc (sizeof (rspamd_mutex_t));
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
	g_slice_free1 (sizeof (rspamd_mutex_t), mtx);
}

/**
 * Create new rwlock
 * @return
 */
rspamd_rwlock_t*
rspamd_rwlock_new (void)
{
	rspamd_rwlock_t					*new;

	new = g_malloc (sizeof (rspamd_rwlock_t));
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_rw_lock_init (&new->rwlock);
#else
	g_static_rw_lock_init (&new->rwlock);
#endif

	return new;
}

/**
 * Lock rwlock for writing
 * @param mtx
 */
inline void
rspamd_rwlock_writer_lock (rspamd_rwlock_t *mtx)
{
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_rw_lock_writer_lock (&mtx->rwlock);
#else
	g_static_rw_lock_writer_lock (&mtx->rwlock);
#endif
}

/**
 * Lock rwlock for reading
 * @param mtx
 */
inline void
rspamd_rwlock_reader_lock (rspamd_rwlock_t *mtx)
{
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_rw_lock_reader_lock (&mtx->rwlock);
#else
	g_static_rw_lock_reader_lock (&mtx->rwlock);
#endif
}

/**
 * Unlock rwlock from writing
 * @param mtx
 */
inline void
rspamd_rwlock_writer_unlock (rspamd_rwlock_t *mtx)
{
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_rw_lock_writer_unlock (&mtx->rwlock);
#else
	g_static_rw_lock_writer_unlock (&mtx->rwlock);
#endif
}

/**
 * Unlock rwlock from reading
 * @param mtx
 */
inline void
rspamd_rwlock_reader_unlock (rspamd_rwlock_t *mtx)
{
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_rw_lock_reader_unlock (&mtx->rwlock);
#else
	g_static_rw_lock_reader_unlock (&mtx->rwlock);
#endif
}

void
rspamd_rwlock_free (rspamd_rwlock_t *mtx)
{
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_rw_lock_clear (&mtx->rwlock);
#endif
	g_slice_free1 (sizeof (rspamd_rwlock_t), mtx);
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
	struct rspamd_thread_data		*td = ud;
	sigset_t						 s_mask;

	/* Ignore signals in thread */
	sigemptyset (&s_mask);
	sigaddset (&s_mask, SIGTERM);
	sigaddset (&s_mask, SIGINT);
	sigaddset (&s_mask, SIGHUP);
	sigaddset (&s_mask, SIGCHLD);
	sigaddset (&s_mask, SIGUSR1);
	sigaddset (&s_mask, SIGUSR2);
	sigaddset (&s_mask, SIGALRM);
	sigaddset (&s_mask, SIGPIPE);

	sigprocmask (SIG_BLOCK, &s_mask, NULL);

	ud = td->func (td->data);
	g_free (td->name);
	g_free (td);

	return ud;
}

/**
 * Create new named thread
 * @param name name pattern
 * @param func function to start
 * @param data data to pass to function
 * @param err error pointer
 * @return new thread object that can be joined
 */
GThread*
rspamd_create_thread (const gchar *name, GThreadFunc func, gpointer data, GError **err)
{
	GThread							*new;
	struct rspamd_thread_data		*td;
	static gint32					 id;
	guint							 r;

	r = strlen (name);
	td = g_malloc (sizeof (struct rspamd_thread_data));
	td->id = ++id;
	td->name = g_malloc (r + sizeof ("4294967296"));
	td->func = func;
	td->data = data;

	rspamd_snprintf (td->name, r + sizeof ("4294967296"), "%s-%d", name, id);
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	new = g_thread_try_new (td->name, rspamd_thread_func, td, err);
#else
	new = g_thread_create (rspamd_thread_func, td, TRUE, err);
#endif

	return new;
}

guint32
murmur32_hash (const guint8 *in, gsize len)
{


	const guint32 			 c1 = 0xcc9e2d51;
	const guint32 			 c2 = 0x1b873593;

	const int				 nblocks = len / 4;
	const guint32 			*blocks = (const guint32 *)(in);
	const guint8 			*tail;
	guint32 				 h = 0;
	gint 					 i;
	guint32 				 k;

	if (in == NULL || len == 0) {
		return 0;
	}

	tail = (const guint8 *)(in + (nblocks * 4));

	for (i = 0; i < nblocks; i++) {
		k = blocks[i];

		k *= c1;
		k = (k << 15) | (k >> (32 - 15));
		k *= c2;

		h ^= k;
		h = (h << 13) | (h >> (32 - 13));
		h = (h * 5) + 0xe6546b64;
	}

	k = 0;
	switch (len & 3) {
	case 3:
		k ^= tail[2] << 16;
	case 2:
		k ^= tail[1] << 8;
	case 1:
		k ^= tail[0];
		k *= c1;
		k = (k << 13) | (k >> (32 - 15));
		k *= c2;
		h ^= k;
	};

	h ^= len;

	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;

	return h;
}

void
murmur128_hash (const guint8 *in, gsize len, guint64 out[])
{
	const guint64 			 c1 = 0x87c37b91114253d5ULL;
	const guint64 			 c2 = 0x4cf5ad432745937fULL;
	const gint 				 nblocks = len / 16;
	const guint64 			*blocks = (const guint64 *)(in);
	const guint8 			*tail;
	guint64 				 h1 = 0;
	guint64 				 h2 = 0;
	int 					 i;
	guint64 				 k1, k2;

	if (in == NULL || len == 0 || out == NULL) {
		return;
	}

	tail = (const guint8 *)(in + (nblocks * 16));

	for (i = 0; i < nblocks; i++) {
		k1 = blocks[i*2+0];
		k2 = blocks[i*2+1];

		k1 *= c1;
		k1  = (k1 << 31) | (k1 >> (64 - 31));
		k1 *= c2;
		h1 ^= k1;

		h1 = (h1 << 27) | (h1 >> (64 - 27));
		h1 += h2;
		h1 = h1*5+0x52dce729;

		k2 *= c2;
		k2  = (k2 << 33) | (k2 >> (64 - 33));
		k2 *= c1;
		h2 ^= k2;

		h2 = (h2 << 31) | (h2 >> (64 - 31));
		h2 += h1;
		h2 = h2*5+0x38495ab5;
	}

	k1 = k2 = 0;
	switch (len & 15) {
	case 15:
		k2 ^= (guint64)(tail[14]) << 48;
	case 14:
		k2 ^= (guint64)(tail[13]) << 40;
	case 13:
		k2 ^= (guint64)(tail[12]) << 32;
	case 12:
		k2 ^= (guint64)(tail[11]) << 24;
	case 11:
		k2 ^= (guint64)(tail[10]) << 16;
	case 10:
		k2 ^= (guint64)(tail[ 9]) << 8;
	case  9:
		k2 ^= (guint64)(tail[ 8]) << 0;
		k2 *= c2;
		k2  = (k2 << 33) | (k2 >> (64 - 33));
		k2 *= c1;
		h2 ^= k2;

	case  8:
		k1 ^= (guint64)(tail[ 7]) << 56;
	case  7:
		k1 ^= (guint64)(tail[ 6]) << 48;
	case  6:
		k1 ^= (guint64)(tail[ 5]) << 40;
	case  5:
		k1 ^= (guint64)(tail[ 4]) << 32;
	case  4:
		k1 ^= (guint64)(tail[ 3]) << 24;
	case  3:
		k1 ^= (guint64)(tail[ 2]) << 16;
	case  2:
		k1 ^= (guint64)(tail[ 1]) << 8;
	case  1:
		k1 ^= (guint64)(tail[ 0]) << 0;
		k1 *= c1;
		k1  = (k1 << 31) | (k1 >> (64 - 31));
		k1 *= c2;
		h1 ^= k1;
	};

	//----------
	// finalization

	h1 ^= len;
	h2 ^= len;

	h1 += h2;
	h2 += h1;

	h1 ^= h1 >> 33;
	h1 *= 0xff51afd7ed558ccdULL;
	h1 ^= h1 >> 33;
	h1 *= 0xc4ceb9fe1a85ec53ULL;
	h1 ^= h1 >> 33;

	h2 ^= h2 >> 33;
	h2 *= 0xff51afd7ed558ccdULL;
	h2 ^= h2 >> 33;
	h2 *= 0xc4ceb9fe1a85ec53ULL;
	h2 ^= h2 >> 33;

	h1 += h2;
	h2 += h1;

	out[0] = h1;
	out[1] = h2;
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
	struct hash_copy_callback_data		*cb = ud;
	gpointer							 nkey, nvalue;

	nkey = cb->key_copy_func ? cb->key_copy_func (key, cb->ud) : (gpointer)key;
	nvalue = cb->value_copy_func ? cb->value_copy_func (value, cb->ud) : (gpointer)value;
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
void rspamd_hash_table_copy (GHashTable *src, GHashTable *dst,
		gpointer (*key_copy_func)(gconstpointer data, gpointer ud),
		gpointer (*value_copy_func)(gconstpointer data, gpointer ud),
		gpointer ud)
{
	struct hash_copy_callback_data		 cb;
	if (src != NULL && dst != NULL) {
		cb.key_copy_func = key_copy_func;
		cb.value_copy_func = value_copy_func;
		cb.ud = ud;
		cb.dst = dst;
		g_hash_table_foreach (src, copy_foreach_callback, &cb);
	}
}

/**
 * Utility function to provide mem_pool copy for rspamd_hash_table_copy function
 * @param data string to copy
 * @param ud memory pool to use
 * @return
 */
gpointer
rspamd_str_pool_copy (gconstpointer data, gpointer ud)
{
	memory_pool_t						*pool = ud;

	return data ? memory_pool_strdup (pool, data) : NULL;
}

gboolean
parse_ipmask_v4 (const char *line, struct in_addr *ina, int *mask)
{
	const char *pos;
	char ip_buf[INET_ADDRSTRLEN + 1], mask_buf[3] = { '\0', '\0', '\0' };

	bzero (ip_buf, sizeof (ip_buf));

	if ((pos = strchr (line, '/')) != NULL) {
		rspamd_strlcpy (ip_buf, line, MIN ((gsize)(pos - line), sizeof (ip_buf)));
		rspamd_strlcpy (mask_buf, pos + 1, sizeof (mask_buf));
	}
	else {
		rspamd_strlcpy (ip_buf, line, sizeof (ip_buf));
	}

	if (!inet_aton (ip_buf, ina)) {
		return FALSE;
	}

	if (mask_buf[0] != '\0') {
		/* Also parse mask */
		*mask = (mask_buf[0] - '0') * 10 + mask_buf[1] - '0';
		if (*mask > 32) {
			return FALSE;
		}
	}
	else {
		*mask = 32;
	}

	*mask = G_MAXUINT32 << (32 - *mask);

	return TRUE;
}

static volatile sig_atomic_t saved_signo[NSIG];

static
void read_pass_tmp_sig_handler (int s)
{

	saved_signo[s] = 1;
}

#ifndef _PATH_TTY
# define _PATH_TTY "/dev/tty"
#endif

gint
rspamd_read_passphrase (gchar *buf, gint size, gint rwflag, gpointer key)
{
#ifdef HAVE_PASSPHRASE_H
	gint len = 0;
	gchar pass[BUFSIZ];

	if (readpassphrase ("Enter passphrase: ", buf, size, RPP_ECHO_OFF | RPP_REQUIRE_TTY) == NULL) {
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
	if (fcntl (input, F_SETFD, FD_CLOEXEC) == -1) {
		msg_warn ("fcntl failed: %d, '%s'", errno, strerror (errno));
	}

	/* Turn echo off */
	if (tcgetattr (input, &oterm) != 0) {
		errno = ENOTTY;
		return 0;
	}
	memcpy(&term, &oterm, sizeof(term));
	term.c_lflag &= ~(ECHO | ECHONL);
	(void)tcsetattr(input, TCSAFLUSH, &term);
	(void)write (output, "Enter passphrase: ", sizeof ("Enter passphrase: ") - 1);

	/* Save the current sighandler */
	for (i = 0; i < NSIG; i++) {
		saved_signo[i] = 0;
	}
	sigemptyset(&sa.sa_mask);
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
	(void)write (output, "\n", 1);

	/* Restore terminal state */
	if (memcmp (&term, &oterm, sizeof (term)) != 0) {
		while (tcsetattr (input, TCSAFLUSH, &oterm) == -1 &&
				errno == EINTR && !saved_signo[SIGTTOU]);
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
			kill(getpid(), i);
			switch (i) {
			case SIGTSTP:
			case SIGTTIN:
			case SIGTTOU:
				goto restart;
			}
		}
	}

	return p - buf;
#endif
}

gboolean
rspamd_ip_is_valid (void *ptr, int af)
{
	const struct in_addr ip4_any = { INADDR_ANY }, ip4_none = { INADDR_NONE };
	const struct in6_addr ip6_any = IN6ADDR_ANY_INIT;

	gboolean ret = FALSE;

	if (G_LIKELY (af == AF_INET)) {
		if (memcmp (ptr, &ip4_any, sizeof (struct in_addr)) != 0 &&
				memcmp (ptr, &ip4_none, sizeof (struct in_addr)) != 0) {
			ret = TRUE;
		}
	}
	else if (G_UNLIKELY (af == AF_INET6)) {
		if (memcmp (ptr, &ip6_any, sizeof (struct in6_addr)) != 0) {
			ret = TRUE;
		}
	}

	return ret;
}

/*
 * GString ucl emitting functions
 */
static int
rspamd_gstring_append_character (unsigned char c, size_t len, void *ud)
{
	GString *buf = ud;
	gsize old_len;

	if (len == 1) {
		g_string_append_c (buf, c);
	}
	else {
		if (buf->allocated_len - buf->len <= len) {
			old_len = buf->len;
			g_string_set_size (buf, buf->len + len + 1);
			buf->len = old_len;
		}
		memset (&buf->str[buf->len], c, len);
		buf->len += len;
	}

	return 0;
}

static int
rspamd_gstring_append_len (const unsigned char *str, size_t len, void *ud)
{
	GString *buf = ud;

	g_string_append_len (buf, str, len);

	return 0;
}

static int
rspamd_gstring_append_int (int64_t val, void *ud)
{
	GString *buf = ud;

	rspamd_printf_gstring (buf, "%L", (intmax_t)val);
	return 0;
}

static int
rspamd_gstring_append_double (double val, void *ud)
{
	GString *buf = ud;
	const double delta = 0.0000001;

	if (val == (double)(int)val) {
		rspamd_printf_gstring (buf, "%.1f", val);
	}
	else if (fabs (val - (double)(int)val) < delta) {
		/* Write at maximum precision */
		rspamd_printf_gstring (buf, "%.*g", DBL_DIG, val);
	}
	else {
		rspamd_printf_gstring (buf, "%f", val);
	}

	return 0;
}

void
rspamd_ucl_emit_gstring (ucl_object_t *obj, enum ucl_emitter emit_type, GString *target)
{
	struct ucl_emitter_functions func = {
		.ucl_emitter_append_character = rspamd_gstring_append_character,
		.ucl_emitter_append_len = rspamd_gstring_append_len,
		.ucl_emitter_append_int = rspamd_gstring_append_int,
		.ucl_emitter_append_double = rspamd_gstring_append_double
	};

	func.ud = target;
	ucl_object_emit_full (obj, emit_type, &func);
}

/*
 * vi:ts=4
 */
