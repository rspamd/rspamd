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
#include "logger.h"
#include "main.h"
#include "map.h"
#include "util.h"

/* How much message should be repeated before it is count to be repeated one */
#define REPEATS_MIN 3
#define REPEATS_MAX 300

/**
 * Static structure that store logging parameters
 * It is NOT shared between processes and is created by main process
 */
struct rspamd_logger_s {
	rspamd_log_func_t log_func;
	struct rspamd_config *cfg;
	struct {
		guint32 size;
		guint32 used;
		u_char *buf;
	}                        io_buf;
	gint fd;
	gboolean is_buffered;
	gboolean enabled;
	gboolean is_debug;
	gboolean throttling;
	time_t throttling_time;
	sig_atomic_t do_reopen_log;
	enum rspamd_log_type type;
	pid_t pid;
	GQuark process_type;
	radix_tree_t *debug_ip;
	guint32 last_line_cksum;
	guint32 repeats;
	gchar *saved_message;
	gchar *saved_function;
	GMutex *mtx;
};

static const gchar lf_chr = '\n';

static rspamd_logger_t *default_logger = NULL;


static void
syslog_log_function (const gchar * log_domain, const gchar *function,
	GLogLevelFlags log_level, const gchar * message,
	gboolean forced, gpointer arg);
static void
file_log_function (const gchar * log_domain, const gchar *function,
	GLogLevelFlags log_level, const gchar * message,
	gboolean forced, gpointer arg);

/**
 * Calculate checksum for log line (used for repeating logic)
 */
static inline guint32
rspamd_log_calculate_cksum (const gchar *message, size_t mlen)
{
	const gchar *bp = message;
	const gchar *be = bp + mlen;
	guint32 hval = 0;

	while (bp < be) {
		hval +=
			(hval <<
			1) + (hval << 4) + (hval << 7) + (hval << 8) + (hval << 24);
		hval ^= (guint32) * bp++;
	}

	/* return our new hash value */
	return hval;

}

/*
 * Write a line to log file (unbuffered)
 */
static void
direct_write_log_line (rspamd_logger_t *rspamd_log,
	void *data,
	gint count,
	gboolean is_iov)
{
	gchar errmsg[128];
	struct iovec *iov;
	const gchar *line;
	gint r;

	if (rspamd_log->enabled) {
		if (is_iov) {
			iov = (struct iovec *)data;
			r = writev (rspamd_log->fd, iov, count);
		}
		else {
			line = (const gchar *)data;
			r = write (rspamd_log->fd, line, count);
		}
		if (r == -1) {
			/* We cannot write message to file, so we need to detect error and make decision */
			r = rspamd_snprintf (errmsg,
					sizeof (errmsg),
					"direct_write_log_line: cannot write log line: %s",
					strerror (errno));
			if (errno == EIO || errno == EINTR) {
				/* Descriptor is somehow invalid, try to restart */
				reopen_log (rspamd_log);
				if (write (rspamd_log->fd, errmsg, r) != -1) {
					/* Try again */
					direct_write_log_line (rspamd_log, data, count, is_iov);
				}
			}
			else if (errno == EFAULT || errno == EINVAL || errno == EFBIG ||
				errno == ENOSPC) {
				/* Rare case */
				rspamd_log->throttling = TRUE;
				rspamd_log->throttling_time = time (NULL);
			}
			else if (errno == EPIPE || errno == EBADF) {
				/* We write to some pipe and it disappears, disable logging or we has opened bad file descriptor */
				rspamd_log->enabled = FALSE;
			}
		}
		else if (rspamd_log->throttling) {
			rspamd_log->throttling = FALSE;
		}
	}
}

static void
rspamd_escape_log_string (gchar *str)
{
	guchar *p = (guchar *)str;

	while (*p) {
		if ((*p & 0x80) || !g_ascii_isprint (*p)) {
			*p = '?';
		}
		else if (*p == '\n' || *p == '\r') {
			*p = ' ';
		}
		p++;
	}
}

/* Logging utility functions */
gint
open_log_priv (rspamd_logger_t *rspamd_log, uid_t uid, gid_t gid)
{
	switch (rspamd_log->cfg->log_type) {
	case RSPAMD_LOG_CONSOLE:
		/* Do nothing with console */
		rspamd_log->enabled = TRUE;
		return 0;
	case RSPAMD_LOG_SYSLOG:
		openlog ("rspamd", LOG_NDELAY | LOG_PID, rspamd_log->cfg->log_facility);
		rspamd_log->enabled = TRUE;
		return 0;
	case RSPAMD_LOG_FILE:
		rspamd_log->fd = open (rspamd_log->cfg->log_file,
				O_CREAT | O_WRONLY | O_APPEND,
				S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
		if (rspamd_log->fd == -1) {
			fprintf (stderr, "open_log: cannot open desired log file: %s, %s",
				rspamd_log->cfg->log_file, strerror (errno));
			return -1;
		}
		if (fchown (rspamd_log->fd, uid, gid) == -1) {
			fprintf (stderr, "open_log: cannot chown desired log file: %s, %s",
				rspamd_log->cfg->log_file, strerror (errno));
			close (rspamd_log->fd);
			return -1;
		}
		rspamd_log->enabled = TRUE;
		return 0;
	}
	return -1;
}

void
close_log_priv (rspamd_logger_t *rspamd_log, uid_t uid, gid_t gid)
{
	gchar tmpbuf[256];
	flush_log_buf (rspamd_log);

	switch (rspamd_log->type) {
	case RSPAMD_LOG_CONSOLE:
		/* Do nothing special */
		break;
	case RSPAMD_LOG_SYSLOG:
		closelog ();
		break;
	case RSPAMD_LOG_FILE:
		if (rspamd_log->enabled) {
			if (rspamd_log->repeats > REPEATS_MIN) {
				rspamd_snprintf (tmpbuf,
					sizeof (tmpbuf),
					"Last message repeated %ud times",
					rspamd_log->repeats);
				rspamd_log->repeats = 0;
				if (rspamd_log->saved_message) {
					file_log_function (NULL,
						rspamd_log->saved_function,
						rspamd_log->cfg->log_level,
						rspamd_log->saved_message,
						TRUE,
						rspamd_log);
					g_free (rspamd_log->saved_message);
					g_free (rspamd_log->saved_function);
					rspamd_log->saved_message = NULL;
					rspamd_log->saved_function = NULL;
				}
				/* It is safe to use temporary buffer here as it is not static */
				file_log_function (NULL,
					__FUNCTION__,
					rspamd_log->cfg->log_level,
					tmpbuf,
					TRUE,
					rspamd_log);
				return;
			}

			if (fsync (rspamd_log->fd) == -1) {
				msg_err ("error syncing log file: %s", strerror (errno));
			}
			close (rspamd_log->fd);
		}
		break;
	}

	rspamd_log->enabled = FALSE;
}

gint
reopen_log_priv (rspamd_logger_t *rspamd_log, uid_t uid, gid_t gid)
{
	close_log_priv (rspamd_log, uid, gid);
	if (open_log_priv (rspamd_log, uid, gid) == 0) {
		msg_info ("log file reopened");
		return 0;
	}

	return -1;
}

/**
 * Open log file or initialize other structures
 */
gint
open_log (rspamd_logger_t *logger)
{
	return open_log_priv (logger, -1, -1);
}
/**
 * Close log file or destroy other structures
 */
void
close_log (rspamd_logger_t *logger)
{
	close_log_priv (logger, -1, -1);
}
/**
 * Close and open log again
 */
gint
reopen_log (rspamd_logger_t *logger)
{
	return reopen_log_priv (logger, -1, -1);
}

/*
 * Setup logger
 */
void
rspamd_set_logger (struct rspamd_config *cfg,
	GQuark ptype,
	struct rspamd_main *rspamd)
{
	gchar **strvec, *p, *err;
	gint num, i, k;
	struct in_addr addr;
	guint32 mask = 0xFFFFFFFF;

	if (rspamd->logger == NULL) {
		rspamd->logger = g_malloc (sizeof (rspamd_logger_t));
		memset (rspamd->logger, 0, sizeof (rspamd_logger_t));
	}

	rspamd->logger->type = cfg->log_type;
	rspamd->logger->pid = getpid ();
	rspamd->logger->process_type = ptype;

#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
	rspamd->logger->mtx = g_mutex_new ();
#else
	rspamd->logger->mtx = g_malloc (sizeof (GMutex));
	g_mutex_init (rspamd->logger->mtx);
#endif

	switch (cfg->log_type) {
	case RSPAMD_LOG_CONSOLE:
		rspamd->logger->log_func = file_log_function;
		rspamd->logger->fd = STDERR_FILENO;
		break;
	case RSPAMD_LOG_SYSLOG:
		rspamd->logger->log_func = syslog_log_function;
		break;
	case RSPAMD_LOG_FILE:
		rspamd->logger->log_func = file_log_function;
		break;
	}

	rspamd->logger->cfg = cfg;
	/* Set up buffer */
	if (rspamd->cfg->log_buffered) {
		if (rspamd->cfg->log_buf_size != 0) {
			rspamd->logger->io_buf.size = rspamd->cfg->log_buf_size;
		}
		else {
			rspamd->logger->io_buf.size = BUFSIZ;
		}
		rspamd->logger->is_buffered = TRUE;
		rspamd->logger->io_buf.buf = g_malloc (rspamd->logger->io_buf.size);
	}
	/* Set up conditional logging */
	if (rspamd->cfg->debug_ip_map != NULL) {
		/* Try to add it as map first of all */
		if (rspamd->logger->debug_ip) {
			radix_tree_free (rspamd->logger->debug_ip);
		}
		rspamd->logger->debug_ip = radix_tree_create ();
		if (!add_map (rspamd->cfg, rspamd->cfg->debug_ip_map,
			"IP addresses for which debug logs are enabled",
			read_radix_list, fin_radix_list,
			(void **)&rspamd->logger->debug_ip)) {
			/* Try to parse it as list */
			strvec = g_strsplit_set (rspamd->cfg->debug_ip_map, ",; ", 0);
			num = g_strv_length (strvec);

			for (i = 0; i < num; i++) {
				g_strstrip (strvec[i]);

				if ((p = strchr (strvec[i], '/')) != NULL) {
					/* Try to extract mask */
					*p = '\0';
					p++;
					errno = 0;
					k = strtoul (p, &err, 10);
					if (errno != 0 || *err != '\0' || k > 32) {
						continue;
					}
				}
				else {
					k = 32;
				}
				if (inet_aton (strvec[i], &addr)) {
					/* Check ip */
					mask = mask << (32 - k);
					radix32tree_insert (rspamd->logger->debug_ip,
						ntohl (addr.s_addr), mask, 1);
				}
			}
			g_strfreev (strvec);
		}
	}
	else if (rspamd->logger->debug_ip) {
		radix_tree_free (rspamd->logger->debug_ip);
		rspamd->logger->debug_ip = NULL;
	}

	default_logger = rspamd->logger;
}

/**
 * Used after fork() for updating structure params
 */
void
update_log_pid (GQuark ptype, rspamd_logger_t *rspamd_log)
{
	rspamd_log->pid = getpid ();
	rspamd_log->process_type = ptype;
}

/**
 * Flush logging buffer
 */
void
flush_log_buf (rspamd_logger_t *rspamd_log)
{
	if (rspamd_log->is_buffered &&
		(rspamd_log->type == RSPAMD_LOG_CONSOLE || rspamd_log->type ==
		RSPAMD_LOG_FILE)) {
		direct_write_log_line (rspamd_log,
			rspamd_log->io_buf.buf,
			rspamd_log->io_buf.used,
			FALSE);
		rspamd_log->io_buf.used = 0;
	}
}


void
rspamd_common_logv (rspamd_logger_t *rspamd_log,
	GLogLevelFlags log_level,
	const gchar *function,
	const gchar *fmt,
	va_list args)
{
	static gchar logbuf[BUFSIZ];
	u_char *end;

	if (rspamd_log == NULL) {
		rspamd_log = default_logger;
	}

	if (rspamd_log == NULL) {
		/* Just fprintf message to stderr */
		if (log_level >= G_LOG_LEVEL_INFO) {
			end = rspamd_vsnprintf (logbuf, sizeof (logbuf), fmt, args);
			*end = '\0';
			rspamd_escape_log_string (logbuf);
			fprintf (stderr, "%s\n", logbuf);
		}
	}
	else if (log_level <= rspamd_log->cfg->log_level) {
		g_mutex_lock (rspamd_log->mtx);
		end = rspamd_vsnprintf (logbuf, sizeof (logbuf), fmt, args);
		*end = '\0';
		rspamd_escape_log_string (logbuf);
		rspamd_log->log_func (NULL,
			function,
			log_level,
			logbuf,
			FALSE,
			rspamd_log);
		g_mutex_unlock (rspamd_log->mtx);
	}
}

/**
 * This log functions select real logger and write message if level is less or equal to configured log level
 */
void
rspamd_common_log_function (rspamd_logger_t *rspamd_log,
	GLogLevelFlags log_level,
	const gchar *function,
	const gchar *fmt,
	...)
{
	va_list vp;

	va_start (vp, fmt);
	rspamd_common_logv (rspamd_log, log_level, function, fmt, vp);
	va_end (vp);
}

void
rspamd_default_logv (GLogLevelFlags log_level, const gchar *function,
	const gchar *fmt, va_list args)
{
	rspamd_common_logv (NULL, log_level, function, fmt, args);
}

void
rspamd_default_log_function (GLogLevelFlags log_level,
	const gchar *function, const gchar *fmt, ...)
{

	va_list vp;

	va_start (vp, fmt);
	rspamd_default_logv (log_level, function, fmt, vp);
	va_end (vp);
}


/**
 * Fill buffer with message (limits must be checked BEFORE this call)
 */
static void
fill_buffer (rspamd_logger_t *rspamd_log, const struct iovec *iov, gint iovcnt)
{
	gint i;

	for (i = 0; i < iovcnt; i++) {
		memcpy (rspamd_log->io_buf.buf + rspamd_log->io_buf.used,
			iov[i].iov_base,
			iov[i].iov_len);
		rspamd_log->io_buf.used += iov[i].iov_len;
	}

}

/*
 * Write message to buffer or to file (using direct_write_log_line function)
 */
static void
file_log_helper (rspamd_logger_t *rspamd_log,
	const struct iovec *iov,
	gint iovcnt)
{
	size_t len = 0;
	gint i;

	if (!rspamd_log->is_buffered) {
		/* Write string directly */
		direct_write_log_line (rspamd_log, (void *)iov, iovcnt, TRUE);
	}
	else {
		/* Calculate total length */
		for (i = 0; i < iovcnt; i++) {
			len += iov[i].iov_len;
		}
		/* Fill buffer */
		if (rspamd_log->io_buf.size < len) {
			/* Buffer is too small to hold this string, so write it dirrectly */
			flush_log_buf (rspamd_log);
			direct_write_log_line (rspamd_log, (void *)iov, iovcnt, TRUE);
		}
		else if (rspamd_log->io_buf.used + len >= rspamd_log->io_buf.size) {
			/* Buffer is full, try to write it dirrectly */
			flush_log_buf (rspamd_log);
			fill_buffer (rspamd_log, iov, iovcnt);
		}
		else {
			/* Copy incoming string to buffer */
			fill_buffer (rspamd_log, iov, iovcnt);
		}
	}
}

/**
 * Syslog interface for logging
 */
static void
syslog_log_function (const gchar * log_domain,
	const gchar *function,
	GLogLevelFlags log_level,
	const gchar * message,
	gboolean forced,
	gpointer arg)
{
	rspamd_logger_t *rspamd_log = arg;

	if (!rspamd_log->enabled) {
		return;
	}
	if (function == NULL) {
		if (forced || log_level <= rspamd_log->cfg->log_level) {
			if (forced || log_level >= G_LOG_LEVEL_DEBUG) {
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
	else {
		if (forced || log_level <= rspamd_log->cfg->log_level) {
			if (log_level >= G_LOG_LEVEL_DEBUG) {
				syslog (LOG_DEBUG, "%s: %s", function, message);
			}
			else if (log_level >= G_LOG_LEVEL_INFO) {
				syslog (LOG_INFO, "%s: %s", function, message);
			}
			else if (log_level >= G_LOG_LEVEL_WARNING) {
				syslog (LOG_WARNING, "%s: %s", function, message);
			}
			else if (log_level >= G_LOG_LEVEL_CRITICAL) {
				syslog (LOG_ERR, "%s: %s", function, message);
			}
		}
	}
}

/**
 * Main file interface for logging
 */
static void
file_log_function (const gchar * log_domain,
	const gchar *function,
	GLogLevelFlags log_level,
	const gchar * message,
	gboolean forced,
	gpointer arg)
{
	gchar tmpbuf[256], timebuf[32];
	time_t now;
	struct tm *tms;
	struct iovec iov[4];
	gint r = 0;
	guint32 cksum;
	size_t mlen;
	const gchar *cptype = NULL;
	gboolean got_time = FALSE;
	rspamd_logger_t *rspamd_log = arg;

	if (!rspamd_log->enabled) {
		return;
	}


	if (forced || log_level <= rspamd_log->cfg->log_level) {
		/* Check throttling due to write errors */
		if (rspamd_log->throttling) {
			now = time (NULL);
			if (rspamd_log->throttling_time != now) {
				rspamd_log->throttling_time = now;
				got_time = TRUE;
			}
			else {
				/* Do not try to write to file too often while throttling */
				return;
			}
		}
		/* Check repeats */
		mlen = strlen (message);
		cksum = rspamd_log_calculate_cksum (message, mlen);
		if (cksum == rspamd_log->last_line_cksum) {
			rspamd_log->repeats++;
			if (rspamd_log->repeats > REPEATS_MIN && rspamd_log->repeats <
				REPEATS_MAX) {
				/* Do not log anything */
				if (rspamd_log->saved_message == 0) {
					rspamd_log->saved_message = g_strdup (message);
					rspamd_log->saved_function = g_strdup (function);
				}
				return;
			}
			else if (rspamd_log->repeats > REPEATS_MAX) {
				rspamd_snprintf (tmpbuf,
					sizeof (tmpbuf),
					"Last message repeated %ud times",
					rspamd_log->repeats);
				rspamd_log->repeats = 0;
				/* It is safe to use temporary buffer here as it is not static */
				if (rspamd_log->saved_message) {
					file_log_function (log_domain,
						rspamd_log->saved_function,
						log_level,
						rspamd_log->saved_message,
						forced,
						arg);
				}
				file_log_function (log_domain,
					__FUNCTION__,
					log_level,
					tmpbuf,
					forced,
					arg);
				file_log_function (log_domain,
					function,
					log_level,
					message,
					forced,
					arg);
				rspamd_log->repeats = REPEATS_MIN + 1;
				return;
			}
		}
		else {
			/* Reset counter if new message differs from saved message */
			rspamd_log->last_line_cksum = cksum;
			if (rspamd_log->repeats > REPEATS_MIN) {
				rspamd_snprintf (tmpbuf,
					sizeof (tmpbuf),
					"Last message repeated %ud times",
					rspamd_log->repeats);
				rspamd_log->repeats = 0;
				if (rspamd_log->saved_message) {
					file_log_function (log_domain,
						rspamd_log->saved_function,
						log_level,
						rspamd_log->saved_message,
						forced,
						arg);
					g_free (rspamd_log->saved_message);
					g_free (rspamd_log->saved_function);
					rspamd_log->saved_message = NULL;
					rspamd_log->saved_function = NULL;
				}
				file_log_function (log_domain,
					__FUNCTION__,
					log_level,
					tmpbuf,
					forced,
					arg);
				/* It is safe to use temporary buffer here as it is not static */
				file_log_function (log_domain,
					function,
					log_level,
					message,
					forced,
					arg);
				return;
			}
			else {
				rspamd_log->repeats = 0;
			}
		}

		if (rspamd_log->cfg->log_extended) {
			if (!got_time) {
				now = time (NULL);
			}

			/* Format time */
			tms = localtime (&now);

			strftime (timebuf, sizeof (timebuf), "%F %H:%M:%S", tms);
			cptype = g_quark_to_string (rspamd_log->process_type);

			if (rspamd_log->cfg->log_color) {
				if (log_level >= G_LOG_LEVEL_INFO) {
					/* White */
					r = rspamd_snprintf (tmpbuf, sizeof (tmpbuf), "\033[1;37m");
				}
				else if (log_level >= G_LOG_LEVEL_WARNING) {
					/* Magenta */
					r = rspamd_snprintf (tmpbuf, sizeof (tmpbuf), "\033[2;32m");
				}
				else if (log_level >= G_LOG_LEVEL_CRITICAL) {
					/* Red */
					r = rspamd_snprintf (tmpbuf, sizeof (tmpbuf), "\033[1;31m");
				}
			}
			else {
				r = 0;
			}
			if (function == NULL) {
				r += rspamd_snprintf (tmpbuf + r,
						sizeof (tmpbuf) - r,
						"%s #%P(%s) ",
						timebuf,
						rspamd_log->pid,
						cptype);
			}
			else {
				r += rspamd_snprintf (tmpbuf + r,
						sizeof (tmpbuf) - r,
						"%s #%P(%s) %s: ",
						timebuf,
						rspamd_log->pid,
						cptype,
						function);
			}
			/* Construct IOV for log line */
			iov[0].iov_base = tmpbuf;
			iov[0].iov_len = r;
			iov[1].iov_base = (void *)message;
			iov[1].iov_len = mlen;
			iov[2].iov_base = (void *)&lf_chr;
			iov[2].iov_len = 1;
			if (rspamd_log->cfg->log_color) {
				iov[3].iov_base = "\033[0m";
				iov[3].iov_len = sizeof ("\033[0m") - 1;
				/* Call helper (for buffering) */
				file_log_helper (rspamd_log, iov, 4);
			}
			else {
				/* Call helper (for buffering) */
				file_log_helper (rspamd_log, iov, 3);
			}
		}
		else {
			iov[0].iov_base = (void *)message;
			iov[0].iov_len = mlen;
			iov[1].iov_base = (void *)&lf_chr;
			iov[1].iov_len = 1;
			if (rspamd_log->cfg->log_color) {
				iov[2].iov_base = "\033[0m";
				iov[2].iov_len = sizeof ("\033[0m") - 1;
				/* Call helper (for buffering) */
				file_log_helper (rspamd_log, iov, 3);
			}
			else {
				/* Call helper (for buffering) */
				file_log_helper (rspamd_log, iov, 2);
			}
		}
	}
}

/**
 * Write log line depending on ip
 */
void
rspamd_conditional_debug (rspamd_logger_t *rspamd_log,
	rspamd_inet_addr_t *addr, const gchar *function, const gchar *fmt, ...)
{
	static gchar logbuf[BUFSIZ];
	va_list vp;
	u_char *end;

	if (rspamd_log->cfg->log_level >= G_LOG_LEVEL_DEBUG ||
		rspamd_log->is_debug) {
		if (rspamd_log->debug_ip && addr != NULL) {
			if (addr->af == AF_INET && radix32tree_find (rspamd_log->debug_ip,
				ntohl (addr->addr.s4.sin_addr.s_addr)) == RADIX_NO_VALUE) {
				return;
			}
		}
		g_mutex_lock (rspamd_log->mtx);
		va_start (vp, fmt);
		end = rspamd_vsnprintf (logbuf, sizeof (logbuf), fmt, vp);
		*end = '\0';
		rspamd_escape_log_string (logbuf);
		va_end (vp);
		rspamd_log->log_func (NULL,
			function,
			G_LOG_LEVEL_DEBUG,
			logbuf,
			TRUE,
			rspamd_log);
		g_mutex_unlock (rspamd_log->mtx);
	}
}
/**
 * Wrapper for glib logger
 */
void
rspamd_glib_log_function (const gchar *log_domain,
	GLogLevelFlags log_level,
	const gchar *message,
	gpointer arg)
{
	rspamd_logger_t *rspamd_log = arg;

	if (rspamd_log->enabled) {
		g_mutex_lock (rspamd_log->mtx);
		rspamd_log->log_func (log_domain,
			NULL,
			log_level,
			message,
			FALSE,
			rspamd_log);
		g_mutex_unlock (rspamd_log->mtx);
	}
}

/**
 * Temporary turn on debugging
 */
void
rspamd_log_debug (rspamd_logger_t *rspamd_log)
{
	rspamd_log->is_debug = TRUE;
}

/**
 * Turn off temporary debugging
 */
void
rspamd_log_nodebug (rspamd_logger_t *rspamd_log)
{
	rspamd_log->is_debug = FALSE;
}
