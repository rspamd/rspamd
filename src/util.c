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

/* Check log messages intensity once per minute */
#define CHECK_TIME 60
/* More than 2 log messages per second */
#define BUF_INTENSITY 2
/* Default connect timeout for sync sockets */
#define CONNECT_TIMEOUT 3

#ifdef RSPAMD_MAIN
extern rspamd_hash_t           *counters;
#endif

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
make_unix_socket (const gchar *path, struct sockaddr_un *addr, gboolean is_server)
{
	gint                            fd, s_error, r, optlen, serrno, on = 1;

	if (path == NULL)
		return -1;

	addr->sun_family = AF_UNIX;

	g_strlcpy (addr->sun_path, path, sizeof (addr->sun_path));
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
write_pid (struct rspamd_main *main)
{
	pid_t                           pid;

	if (main->cfg->pid_file == NULL) {
		return -1;
	}
	main->pfh = pidfile_open (main->cfg->pid_file, 0644, &pid);

	if (main->pfh == NULL) {
		return -1;
	}

	pidfile_write (main->pfh);

	return 0;
}

#ifdef HAVE_SA_SIGINFO
void
init_signals (struct sigaction *signals, void (*sig_handler)(gint, siginfo_t *, void *))
#else
void
init_signals (struct sigaction *signals, sighandler_t sig_handler)
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
static gint                      _pidfile_remove (struct pidfh *pfh, gint freeit);

static gint
pidfile_verify (struct pidfh *pfh)
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
pidfile_read (const gchar *path, pid_t * pidptr)
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

struct pidfh                   *
pidfile_open (const gchar *path, mode_t mode, pid_t * pidptr)
{
	struct pidfh                   *pfh;
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

gint
pidfile_write (struct pidfh *pfh)
{
	gchar                           pidstr[16];
	gint                            error, fd;

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

	rspamd_snprintf (pidstr, sizeof (pidstr), "%P", getpid ());
	if (pwrite (fd, pidstr, strlen (pidstr), 0) != (ssize_t) strlen (pidstr)) {
		error = errno;
		_pidfile_remove (pfh, 0);
		errno = error;
		return -1;
	}

	return 0;
}

gint
pidfile_close (struct pidfh *pfh)
{
	gint                            error;

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

static gint
_pidfile_remove (struct pidfh *pfh, gint freeit)
{
	gint                            error;

	error = pidfile_verify (pfh);
	if (error != 0) {
		errno = error;
		return -1;
	}

	if (unlink (pfh->pf_path) == -1)
		error = errno;
	if (! unlock_file (pfh->pf_fd, FALSE)) {
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
pidfile_remove (struct pidfh *pfh)
{

	return (_pidfile_remove (pfh, 1));
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
#ifdef RSPAMD_MAIN
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
#else
	return 0;
#endif
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
	while (p - f->begin < f->len) {
		h = (h << 5) - h + g_tolower (*p);
		p++;
	}

	return h;
}

void
gperf_profiler_init (struct config_file *cfg, const gchar *descr)
{
#if defined(WITH_GPERF_TOOLS) && defined(RSPAMD_MAIN)
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

#ifdef RSPAMD_MAIN
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
#endif /* RSPAMD_MAIN */


gint
rspamd_fprintf (FILE *f, const gchar *fmt, ...)
{
	gchar   *p;
	va_list   args;
    gchar buf[BUFSIZ];
    gint r;

	va_start (args, fmt);
	p = rspamd_vsnprintf (buf, sizeof (buf), fmt, args);
	va_end (args);

    r = fprintf (f, "%s", buf);

    return r;
}

gint
rspamd_sprintf (gchar *buf, const gchar *fmt, ...)
{
	gchar   *p;
	va_list   args;

	va_start (args, fmt);
	p = rspamd_vsnprintf (buf, /* STUB */ 65536, fmt, args);
	va_end (args);

	return p - buf;
}


gint
rspamd_snprintf (gchar *buf, size_t max, const gchar *fmt, ...)
{
	gchar   *p;
	va_list   args;

	va_start (args, fmt);
	p = rspamd_vsnprintf (buf, max - 1, fmt, args);
	va_end (args);
	*p = '\0';

	return p - buf;
}


gchar *
rspamd_vsnprintf (gchar *buf, size_t max, const gchar *fmt, va_list args)
{
	gchar             *p, zero, *last;
	gint                            d;
	long double         f, scale;
	size_t              len, slen;
	gint64                          i64;
	guint64                         ui64;
	guint                           width, sign, hex, max_width, frac_width, i;
	f_str_t			   *v;

	if (max == 0) {
		return buf;
	}

	last = buf + max;

	while (*fmt && buf < last) {

		/*
		 * "buf < last" means that we could copy at least one character:
		 * the plain character, "%%", "%c", and minus without the checking
		 */

		if (*fmt == '%') {

			i64 = 0;
			ui64 = 0;

			zero = (gchar) ((*++fmt == '0') ? '0' : ' ');
			width = 0;
			sign = 1;
			hex = 0;
			max_width = 0;
			frac_width = 0;
			slen = (size_t) -1;

			while (*fmt >= '0' && *fmt <= '9') {
				width = width * 10 + *fmt++ - '0';
			}


			for ( ;; ) {
				switch (*fmt) {

				case 'u':
					sign = 0;
					fmt++;
					continue;

				case 'm':
					max_width = 1;
					fmt++;
					continue;

				case 'X':
					hex = 2;
					sign = 0;
					fmt++;
					continue;

				case 'x':
					hex = 1;
					sign = 0;
					fmt++;
					continue;
				case '.':
					fmt++;

					while (*fmt >= '0' && *fmt <= '9') {
						frac_width = frac_width * 10 + *fmt++ - '0';
					}

					break;

				case '*':
					d = (gint)va_arg (args, gint);
					if (G_UNLIKELY (d < 0)) {
						msg_err ("crititcal error: size is less than 0");
						g_assert (0);
					}
					slen = (size_t)d;
					fmt++;
					continue;

				default:
					break;
				}

				break;
			}


			switch (*fmt) {

			case 'V':
				v = va_arg (args, f_str_t *);

				len = v->len;
				len = (buf + len < last) ? len : (size_t) (last - buf);

				buf = ((gchar *)memcpy (buf, v->begin, len)) + len;
				fmt++;

				continue;

			case 's':
				p = va_arg(args, gchar *);
				if (p == NULL) {
					p = "(NULL)";
				}

				if (slen == (size_t) -1) {
					while (*p && buf < last) {
						*buf++ = *p++;
					}

				} else {
					len = (buf + slen < last) ? slen : (size_t) (last - buf);

					buf = ((gchar *)memcpy (buf, p, len)) + len;
				}

				fmt++;

				continue;

			case 'O':
				i64 = (gint64) va_arg (args, off_t);
				sign = 1;
				break;

			case 'P':
				i64 = (gint64) va_arg (args, pid_t);
				sign = 1;
				break;

			case 'T':
				i64 = (gint64) va_arg (args, time_t);
				sign = 1;
				break;

			case 'z':
				if (sign) {
					i64 = (gint64) va_arg (args, ssize_t);
				} else {
					ui64 = (guint64) va_arg (args, size_t);
				}
				break;

			case 'd':
				if (sign) {
					i64 = (gint64) va_arg (args, gint);
				} else {
					ui64 = (guint64) va_arg (args, guint);
				}
				break;

			case 'l':
				if (sign) {
					i64 = (gint64) va_arg(args, long);
				} else {
					ui64 = (guint64) va_arg(args, guint32);
				}
				break;

			case 'D':
				if (sign) {
					i64 = (gint64) va_arg(args, gint32);
				} else {
					ui64 = (guint64) va_arg(args, guint32);
				}
				break;

			case 'L':
				if (sign) {
					i64 = va_arg (args, gint64);
				} else {
					ui64 = va_arg (args, guint64);
				}
				break;


			case 'f':
				f = (double) va_arg (args, double);
				if (f < 0) {
					*buf++ = '-';
					f = -f;
				}
				
				ui64 = (gint64) f;

				buf = rspamd_sprintf_num (buf, last, ui64, zero, 0, width);

				if (frac_width) {

					if (buf < last) {
						*buf++ = '.';
					}

					scale = 1.0;

					for (i = 0; i < frac_width; i++) {
						scale *= 10.0;
					}

					/*
					* (gint64) cast is required for msvc6:
					* it can not convert guint64 to double
					*/
					ui64 = (guint64) ((f - (gint64) ui64) * scale);

					buf = rspamd_sprintf_num (buf, last, ui64, '0', 0, frac_width);
				}

				fmt++;

				continue;

			case 'F':
				f = (long double) va_arg (args, long double);

				if (f < 0) {
					*buf++ = '-';
					f = -f;
				}

				ui64 = (gint64) f;

				buf = rspamd_sprintf_num (buf, last, ui64, zero, 0, width);

				if (frac_width) {

					if (buf < last) {
						*buf++ = '.';
					}

					scale = 1.0;

					for (i = 0; i < frac_width; i++) {
						scale *= 10.0;
					}

					/*
					* (gint64) cast is required for msvc6:
					* it can not convert guint64 to double
					*/
					ui64 = (guint64) ((f - (gint64) ui64) * scale);

					buf = rspamd_sprintf_num (buf, last, ui64, '0', 0, frac_width);
				}

				fmt++;

				continue;

			case 'g':
				f = (long double) va_arg (args, double);

				if (f < 0) {
					*buf++ = '-';
					f = -f;
				}
				g_ascii_formatd (buf, last - buf, "%g", (double)f);
				buf += strlen (buf);
				fmt++;

				continue;

			case 'G':
				f = (long double) va_arg (args, long double);

				if (f < 0) {
					*buf++ = '-';
					f = -f;
				}
				g_ascii_formatd (buf, last - buf, "%g", (double)f);
				buf += strlen (buf);
				fmt++;

				continue;

			case 'p':
				ui64 = (uintptr_t) va_arg (args, void *);
				hex = 2;
				sign = 0;
				zero = '0';
				width = sizeof (void *) * 2;
				break;

			case 'c':
				d = va_arg (args, gint);
				*buf++ = (gchar) (d & 0xff);
				fmt++;

				continue;

			case 'Z':
				*buf++ = '\0';
				fmt++;

				continue;

			case 'N':
				*buf++ = LF;
				fmt++;

				continue;

			case '%':
				*buf++ = '%';
				fmt++;

				continue;

			default:
				*buf++ = *fmt++;

				continue;
			}

			if (sign) {
				if (i64 < 0) {
					*buf++ = '-';
					ui64 = (guint64) -i64;

				} else {
					ui64 = (guint64) i64;
				}
			}

			buf = rspamd_sprintf_num (buf, last, ui64, zero, hex, width);

			fmt++;

		} else {
			*buf++ = *fmt++;
		}
	}

	return buf;
}


static gchar *
rspamd_sprintf_num (gchar *buf, gchar *last, guint64 ui64, gchar zero,
	guint                           hexadecimal, guint width)
{
	gchar		   *p, temp[sizeof ("18446744073709551615")];
	size_t		    len;
	guint32                         ui32;
	static gchar   hex[] = "0123456789abcdef";
	static gchar   HEX[] = "0123456789ABCDEF";

	p = temp + sizeof(temp);

	if (hexadecimal == 0) {

		if (ui64 <= G_MAXUINT32) {

			/*
			 * To divide 64-bit numbers and to find remainders
			 * on the x86 platform gcc and icc call the libc functions
			 * [u]divdi3() and [u]moddi3(), they call another function
			 * in its turn.  On FreeBSD it is the qdivrem() function,
			 * its source code is about 170 lines of the code.
			 * The glibc counterpart is about 150 lines of the code.
			 *
			 * For 32-bit numbers and some divisors gcc and icc use
			 * a inlined multiplication and shifts.  For example,
			 * guint "i32 / 10" is compiled to
			 *
			 *	 (i32 * 0xCCCCCCCD) >> 35
			 */

			ui32 = (guint32) ui64;

			do {
				*--p = (gchar) (ui32 % 10 + '0');
			} while (ui32 /= 10);

		} else {
			do {
				*--p = (gchar) (ui64 % 10 + '0');
			} while (ui64 /= 10);
		}

	} else if (hexadecimal == 1) {

		do {

			/* the "(guint32)" cast disables the BCC's warning */
			*--p = hex[(guint32) (ui64 & 0xf)];

		} while (ui64 >>= 4);

	} else { /* hexadecimal == 2 */

		do {

			/* the "(guint32)" cast disables the BCC's warning */
			*--p = HEX[(guint32) (ui64 & 0xf)];

		} while (ui64 >>= 4);
	}

	/* zero or space padding */

	len = (temp + sizeof (temp)) - p;

	while (len++ < width && buf < last) {
		*buf++ = zero;
	}

	/* number safe copy */

	len = (temp + sizeof (temp)) - p;

	if (buf + len > last) {
		len = last - buf;
	}

	return ((gchar *)memcpy (buf, p, len)) + len;
}

#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MICRO_VERSION == 2) && (GLIB_MINOR_VERSION < 22))
void
g_ptr_array_unref (GPtrArray *array)
{
	g_ptr_array_free (array, TRUE);
}
#endif

/*
 * vi:ts=4
 */
