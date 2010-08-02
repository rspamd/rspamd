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
#include "logger.h"
#include "util.h"
#include "main.h"
#include "map.h"

/* How much message should be repeated before it is count to be repeated one */
#define REPEATS_MIN 3
#define REPEATS_MAX 300

#ifdef RSPAMD_MAIN
sig_atomic_t                    do_reopen_log = 0;
#endif

typedef struct rspamd_logger_s {
	rspamd_log_func_t        log_func;
	struct config_file		*cfg;
	struct {
		uint32_t size;
		uint32_t used;
		u_char *buf;
	}                        io_buf;
	int                      fd;
	gboolean                 is_buffered;
	gboolean                 enabled;
	gboolean                 is_debug;
	gboolean                 throttling;
	time_t                   throttling_time;
	enum rspamd_log_type     type;
	pid_t                    pid;
	enum process_type		 process_type;
	radix_tree_t            *debug_ip;
	uint32_t                 last_line_cksum;
	uint32_t                 repeats;
	gchar                   *saved_message;
	gchar                   *saved_function;
} rspamd_logger_t;

rspamd_logger_t *rspamd_log = NULL;

static const char lf_chr = '\n';

static void
syslog_log_function (const gchar * log_domain, const gchar *function, 
					GLogLevelFlags log_level, const gchar * message, 
					gboolean forced, gpointer arg);
static void
file_log_function (const gchar * log_domain, const gchar *function, 
					GLogLevelFlags log_level, const gchar * message, 
					gboolean forced, gpointer arg);

static inline uint32_t
rspamd_log_calculate_cksum (const gchar *message, size_t mlen)
{
	const gchar                    *bp = message;
	const gchar                    *be = bp + mlen;
	uint32_t                        hval = 0;

    while (bp < be) {
		hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
		hval ^= (uint32_t)*bp++;
    }

    /* return our new hash value */
    return hval;
	
}

static void
direct_write_log_line (void *data, int count, gboolean is_iov)
{
	char                           errmsg[128];
	struct iovec                  *iov;
	const char                    *line;
	int                            r;
	
	if (rspamd_log->enabled) {
		if (is_iov) {
			iov = (struct iovec *)data;
			r = writev (rspamd_log->fd, iov, count);
		}
		else {
			line = (const char *)data;
			r = write (rspamd_log->fd, line, count);
		}
		if (r == -1) {
			/* We cannot write message to file, so we need to detect error and make decision */
			r = rspamd_snprintf (errmsg, sizeof (errmsg), "direct_write_log_line: cannot write log line: %s", strerror (errno));
			if (errno == EBADF || errno == EIO || errno == EINTR) {
				/* Descriptor is somehow invalid, try to restart */
				reopen_log ();
				if (write (rspamd_log->fd, errmsg, r) != -1) {
					/* Try again */
					direct_write_log_line (data, count, is_iov);
				}
			}
			else if (errno == EFAULT || errno == EINVAL || errno == EFBIG || errno == ENOSPC) {
				/* Rare case */
				rspamd_log->throttling = TRUE;
				rspamd_log->throttling_time = time (NULL);
			}
			else if (errno == EPIPE) {
				/* We write to some pipe and it disappears, disable logging */
				rspamd_log->enabled = FALSE;
			}
		}
		else if (rspamd_log->throttling) {
			rspamd_log->throttling = FALSE;
		}
	}
}

/* Logging utility functions */
int
open_log (void)
{

	rspamd_log->enabled = TRUE;

	switch (rspamd_log->cfg->log_type) {
	case RSPAMD_LOG_CONSOLE:
		/* Do nothing with console */
		return 0;
	case RSPAMD_LOG_SYSLOG:
		openlog ("rspamd", LOG_NDELAY | LOG_PID, rspamd_log->cfg->log_facility);
		return 0;
	case RSPAMD_LOG_FILE:
		rspamd_log->fd = open (rspamd_log->cfg->log_file, O_CREAT | O_WRONLY | O_APPEND, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
		if (rspamd_log->fd == -1) {
			fprintf (stderr, "open_log: cannot open desired log file: %s, %s", rspamd_log->cfg->log_file, strerror (errno));
			return -1;
		}
		return 0;
	}
	return -1;
}

void
close_log (void)
{
	char            tmpbuf[256];
	flush_log_buf ();

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
				rspamd_snprintf (tmpbuf, sizeof (tmpbuf), "Last message repeated %ud times", rspamd_log->repeats);
				rspamd_log->repeats = 0;
				if (rspamd_log->saved_message) {
					file_log_function (NULL, rspamd_log->saved_function, rspamd_log->cfg->log_level, rspamd_log->saved_message, TRUE, NULL);
					g_free (rspamd_log->saved_message);
					g_free (rspamd_log->saved_function);
					rspamd_log->saved_message = NULL;
					rspamd_log->saved_function = NULL;
				}	
				/* It is safe to use temporary buffer here as it is not static */
				file_log_function (NULL, __FUNCTION__, rspamd_log->cfg->log_level, tmpbuf, TRUE, NULL);
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

void
rspamd_set_logger (enum rspamd_log_type type, enum process_type ptype, struct config_file *cfg)
{
	char                          **strvec, *p, *err;
	int                             num, i, k;
	struct in_addr                  addr;
	uint32_t                        mask = 0xFFFFFFFF;

	if (rspamd_log == NULL) {
		rspamd_log = g_malloc (sizeof (rspamd_logger_t));
		bzero (rspamd_log, sizeof (rspamd_logger_t));
	}

	rspamd_log->type = type;
	rspamd_log->pid = getpid ();
	rspamd_log->process_type = ptype;

	switch (type) {
		case RSPAMD_LOG_CONSOLE:
			rspamd_log->log_func = file_log_function;
			rspamd_log->fd = STDERR_FILENO;
			break;
		case RSPAMD_LOG_SYSLOG:
			rspamd_log->log_func = syslog_log_function;
			break;
		case RSPAMD_LOG_FILE:
			rspamd_log->log_func = file_log_function;
			break;
	}

	rspamd_log->cfg = cfg;
	/* Set up buffer */
	if (cfg->log_buffered) {
		if (cfg->log_buf_size != 0) {
			rspamd_log->io_buf.size = cfg->log_buf_size;
		}
		else {
			rspamd_log->io_buf.size = BUFSIZ;
		}
		rspamd_log->is_buffered = TRUE;
		rspamd_log->io_buf.buf = g_malloc (rspamd_log->io_buf.size);
	}
	/* Set up conditional logging */
	if (cfg->debug_ip_map != NULL) {
		/* Try to add it as map first of all */
		if (rspamd_log->debug_ip) {
			radix_tree_free (rspamd_log->debug_ip);
		}
		rspamd_log->debug_ip = radix_tree_create ();
		if (!add_map (cfg->debug_ip_map, read_radix_list, fin_radix_list, (void **)&rspamd_log->debug_ip)) {
			/* Try to parse it as list */
			strvec = g_strsplit_set (cfg->debug_ip_map, ",; ", 0);
			num = g_strv_length (strvec);

			for (i = 0; i < num; i++) {
				g_strstrip (strvec[i]);

				if ((p = strchr (strvec[i], '/')) != NULL) {
					/* Try to extract mask */
					*p = '\0';
					p ++;
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
					radix32tree_insert (rspamd_log->debug_ip, ntohl (addr.s_addr), mask, 1);
				}
			}
			g_strfreev (strvec);
		}
	}
	else if (rspamd_log->debug_ip) {
		radix_tree_free (rspamd_log->debug_ip);
		rspamd_log->debug_ip = NULL;
	}
}

int
reopen_log (void)
{
	close_log ();
	if (open_log () == 0) {
		msg_info ("log file reopened");
		return 0;
	}

	return -1;
}

void
update_log_pid (enum process_type ptype)
{
	rspamd_log->pid = getpid ();
	rspamd_log->process_type = ptype;
}

void
flush_log_buf (void)
{
	if (rspamd_log->is_buffered && (rspamd_log->type == RSPAMD_LOG_CONSOLE || rspamd_log->type == RSPAMD_LOG_FILE)) {
		direct_write_log_line (rspamd_log->io_buf.buf, rspamd_log->io_buf.used, FALSE);
		rspamd_log->io_buf.used = 0;
	}
}


void
rspamd_common_log_function (GLogLevelFlags log_level, const char *function, const char *fmt, ...)
{
	static char                     logbuf[BUFSIZ];
	va_list                         vp;
    u_char                         *end;

	if (log_level <= rspamd_log->cfg->log_level) {
		va_start (vp, fmt);
		end = rspamd_vsnprintf (logbuf, sizeof (logbuf), fmt, vp);
		*end = '\0';
		va_end (vp);
		rspamd_log->log_func (NULL, function, log_level, logbuf, FALSE, rspamd_log->cfg);
	}
}


/* Fill buffer with message (limits must be checked BEFORE this call) */
static void
fill_buffer (const struct iovec *iov, int iovcnt)
{
	int                            i;

	for (i = 0; i < iovcnt; i ++) {
		memcpy (rspamd_log->io_buf.buf + rspamd_log->io_buf.used, iov[i].iov_base, iov[i].iov_len);
		rspamd_log->io_buf.used += iov[i].iov_len;
	}

}

/* Write message to buffer or to file */
static void
file_log_helper (const struct iovec *iov, int iovcnt)
{
	size_t                         len = 0;
	int                            i;

	if (! rspamd_log->is_buffered) {
		/* Write string directly */
		direct_write_log_line ((void *)iov, iovcnt, TRUE);
	}
	else {
		/* Calculate total length */
		for (i = 0; i < iovcnt; i ++) {
			len += iov[i].iov_len;
		}
		/* Fill buffer */
		if (rspamd_log->io_buf.size < len) {
			/* Buffer is too small to hold this string, so write it dirrectly */
			flush_log_buf ();
			direct_write_log_line ((void *)iov, iovcnt, TRUE);
		}
		else if (rspamd_log->io_buf.used + len >= rspamd_log->io_buf.size) {
			/* Buffer is full, try to write it dirrectly */
			flush_log_buf ();
			fill_buffer (iov, iovcnt);
		}
		else {
			/* Copy incoming string to buffer */
			fill_buffer (iov, iovcnt);
		}
	}
}

static void
syslog_log_function (const gchar * log_domain, const gchar *function, GLogLevelFlags log_level, const gchar * message, gboolean forced, gpointer arg)
{
	struct config_file             *cfg = (struct config_file *)arg;

	if (! rspamd_log->enabled) {
		return;
	}
	if (function == NULL) {
		if (forced || log_level <= cfg->log_level) {
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
		if (forced || log_level <= cfg->log_level) {
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

static void
file_log_function (const gchar * log_domain, const gchar *function, GLogLevelFlags log_level, const gchar * message, gboolean forced, gpointer arg)
{
	char                            tmpbuf[256], timebuf[32];
	time_t                          now;
	struct tm                      *tms;
	struct iovec                    iov[3];
	int                             r;
	uint32_t                        cksum;
	size_t                          mlen;
	const char                     *cptype = NULL;
	gboolean                        got_time = FALSE;

	if (! rspamd_log->enabled) {
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
				/* Do not try to write to file too often while throtling */
				return;
			}
		}
		/* Check repeats */
		mlen = strlen (message);
		cksum = rspamd_log_calculate_cksum (message, mlen);
		if (cksum == rspamd_log->last_line_cksum) {
			rspamd_log->repeats ++;
			if (rspamd_log->repeats > REPEATS_MIN && rspamd_log->repeats < REPEATS_MAX) {
				/* Do not log anything */
				if (rspamd_log->saved_message == 0) {
					rspamd_log->saved_message = g_strdup (message);
					rspamd_log->saved_function = g_strdup (function);
				}
				return;
			}
			else if (rspamd_log->repeats > REPEATS_MAX) {
				rspamd_snprintf (tmpbuf, sizeof (tmpbuf), "Last message repeated %ud times", rspamd_log->repeats);
				rspamd_log->repeats = 0;
				/* It is safe to use temporary buffer here as it is not static */
				if (rspamd_log->saved_message) {
					file_log_function (log_domain, rspamd_log->saved_function, log_level, rspamd_log->saved_message, forced, arg);
				}	
				file_log_function (log_domain, __FUNCTION__, log_level, tmpbuf, forced, arg);
				file_log_function (log_domain, function, log_level, message, forced, arg);
				rspamd_log->repeats = REPEATS_MIN + 1;
				return;
			}
		}
		else {
			rspamd_log->last_line_cksum = cksum;
			if (rspamd_log->repeats > REPEATS_MIN) {
				rspamd_snprintf (tmpbuf, sizeof (tmpbuf), "Last message repeated %ud times", rspamd_log->repeats);
				rspamd_log->repeats = 0;
				if (rspamd_log->saved_message) {
					file_log_function (log_domain, rspamd_log->saved_function, log_level, rspamd_log->saved_message, forced, arg);
					g_free (rspamd_log->saved_message);
					g_free (rspamd_log->saved_function);
					rspamd_log->saved_message = NULL;
					rspamd_log->saved_function = NULL;
				}	
				file_log_function (log_domain, __FUNCTION__, log_level, tmpbuf, forced, arg);
				/* It is safe to use temporary buffer here as it is not static */
				file_log_function (log_domain, function, log_level, message, forced, arg);
				return;
			}
			else {
				rspamd_log->repeats = 0;
			}
		}

		if (! got_time) {
			now = time (NULL);
		}

		tms = localtime (&now);

		strftime (timebuf, sizeof (timebuf), "%F %H:%M:%S", tms);
		switch (rspamd_log->process_type) {
			case TYPE_MAIN:
				cptype = "main";
				break;
			case TYPE_WORKER:
				cptype = "worker";
				break;
			case TYPE_CONTROLLER:
				cptype = "controller";
				break;
			case TYPE_LMTP:
				cptype = "lmtp";
				break;
			case TYPE_SMTP:
				cptype = "smtp";
				break;
			case TYPE_FUZZY:
				cptype = "fuzzy";
				break;
			case TYPE_GREYLIST:
				cptype = "greylist";
				break;
		}
		if (function == NULL) {
			r = rspamd_snprintf (tmpbuf, sizeof (tmpbuf), "%s #%P(%s) ", timebuf, rspamd_log->pid, cptype);
		}
		else {
			r = rspamd_snprintf (tmpbuf, sizeof (tmpbuf), "%s #%P(%s) %s: ", timebuf, rspamd_log->pid, cptype, function);
		}
		iov[0].iov_base = tmpbuf;
		iov[0].iov_len = r;
		iov[1].iov_base = (void *)message;
		iov[1].iov_len = mlen;
		iov[2].iov_base = (void *)&lf_chr;
		iov[2].iov_len = 1;
		
		file_log_helper (iov, 3);
	}
}

void
rspamd_conditional_debug (uint32_t addr, const char *function, const char *fmt, ...) 
{
	static char                     logbuf[BUFSIZ];
	va_list                         vp;
    u_char                         *end;

	if (rspamd_log->cfg->log_level >= G_LOG_LEVEL_DEBUG || rspamd_log->is_debug ||
			(rspamd_log->debug_ip != NULL && radix32tree_find (rspamd_log->debug_ip, ntohl (addr)) != RADIX_NO_VALUE)) {

		va_start (vp, fmt);
		end = rspamd_vsnprintf (logbuf, sizeof (logbuf), fmt, vp);
		*end = '\0';
		va_end (vp);
		rspamd_log->log_func (NULL, function, G_LOG_LEVEL_DEBUG, logbuf, TRUE, rspamd_log->cfg);
	}
} 

void
rspamd_glib_log_function (const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer arg)
{
	if (rspamd_log->enabled) {
		rspamd_log->log_func (log_domain, NULL, log_level, message, FALSE, rspamd_log->cfg);
	}
}

void
rspamd_log_debug ()
{
	rspamd_log->is_debug = TRUE;
}

void
rspamd_log_nodebug ()
{
	rspamd_log->is_debug = FALSE;
}
