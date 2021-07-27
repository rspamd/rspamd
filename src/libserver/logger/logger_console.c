/*-
 * Copyright 2020 Vsevolod Stakhov
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
#include "logger.h"
#include "libserver/cfg_file.h"
#include "libcryptobox/cryptobox.h"
#include "unix-std.h"

#include "logger_private.h"

#define CONSOLE_LOG_QUARK g_quark_from_static_string ("console_logger")

static const gchar lf_chr = '\n';
struct rspamd_console_logger_priv {
	gint fd;
	gint crit_fd;
	gboolean log_severity;
	gboolean log_color;
	gboolean log_rspamadm;
	gboolean log_tty;
};

/* Copy & paste :( */
static inline void
log_time (gdouble now, rspamd_logger_t *rspamd_log, gchar *timebuf,
		  size_t len)
{
	time_t sec = (time_t)now;
	gsize r;
	struct tm tms;

	rspamd_localtime (sec, &tms);
	r = strftime (timebuf, len, "%F %H:%M:%S", &tms);

	if (rspamd_log->flags & RSPAMD_LOG_FLAG_USEC) {
		gchar usec_buf[16];

		rspamd_snprintf (usec_buf, sizeof (usec_buf), "%.5f",
				now - (gdouble)sec);
		rspamd_snprintf (timebuf + r, len - r,
				"%s", usec_buf + 1);
	}
}

void *
rspamd_log_console_init (rspamd_logger_t *logger, struct rspamd_config *cfg,
								uid_t uid, gid_t gid, GError **err)
{
	struct rspamd_console_logger_priv *priv;

	priv = g_malloc0 (sizeof (*priv));
	priv->log_color = (logger->flags & RSPAMD_LOG_FLAG_COLOR);
	priv->log_severity = (logger->flags & RSPAMD_LOG_FLAG_SEVERITY);
	priv->log_rspamadm = (logger->flags & RSPAMD_LOG_FLAG_RSPAMADM);

	if (priv->log_rspamadm) {
		priv->fd = dup (STDOUT_FILENO);
		priv->crit_fd = dup (STDERR_FILENO);
	}
	else {
		priv->fd = dup (STDERR_FILENO);
		priv->crit_fd = priv->fd;
	}

	if (priv->fd == -1) {
		g_set_error (err, CONSOLE_LOG_QUARK, errno,
				"open_log: cannot dup console fd: %s\n",
				strerror (errno));
		rspamd_log_console_dtor (logger, priv);

		return NULL;
	}

	if (isatty (priv->fd)) {
		priv->log_tty = true;
	}
	else if (priv->log_color) {
		/* Disable colors for not a tty */
		priv->log_color = false;
	}

	return priv;
}

void *
rspamd_log_console_reload (rspamd_logger_t *logger, struct rspamd_config *cfg,
								  gpointer arg, uid_t uid, gid_t gid, GError **err)
{
	struct rspamd_console_logger_priv *npriv;

	npriv = rspamd_log_console_init (logger, cfg, uid, gid, err);

	if (npriv) {
		/* Close old */
		rspamd_log_console_dtor (logger, arg);
	}

	return npriv;
}

void
rspamd_log_console_dtor (rspamd_logger_t *logger, gpointer arg)
{
	struct rspamd_console_logger_priv *priv = (struct rspamd_console_logger_priv *)arg;

	if (priv->fd != -1) {
		if (priv->fd != priv->crit_fd) {
			/* Two different FD case */
			if (close (priv->crit_fd) == -1) {
				rspamd_fprintf (stderr, "cannot close log crit_fd %d: %s\n",
						priv->crit_fd, strerror (errno));
			}
		}

		if (close (priv->fd) == -1) {
			rspamd_fprintf (stderr, "cannot close log fd %d: %s\n",
					priv->fd, strerror (errno));
		}

		/* Avoid the next if to be executed as crit_fd is equal to fd */
		priv->crit_fd = -1;
	}

	if (priv->crit_fd != -1) {
		if (close (priv->crit_fd) == -1) {
			rspamd_fprintf (stderr, "cannot close log crit_fd %d: %s\n",
					priv->crit_fd, strerror (errno));
		}
	}

	g_free (priv);
}

bool
rspamd_log_console_log (const gchar *module, const gchar *id,
							 const gchar *function,
							 gint level_flags,
							 const gchar *message,
							 gsize mlen,
							 rspamd_logger_t *rspamd_log,
							 gpointer arg)
{
	struct rspamd_console_logger_priv *priv = (struct rspamd_console_logger_priv *)arg;
	static gchar timebuf[64], modulebuf[64];
	gchar tmpbuf[256];
	gchar *m;
	struct iovec iov[6];
	gulong r = 0, mr = 0;
	size_t mremain;
	gint fd, niov = 0;

	if (level_flags & G_LOG_LEVEL_CRITICAL) {
		fd = priv->crit_fd;
	}
	else {
		if (priv->log_rspamadm && (level_flags & G_LOG_LEVEL_WARNING)) {
			fd = priv->crit_fd;
		}
		else {
			fd = priv->fd;
		}
	}

#ifndef DISABLE_PTHREAD_MUTEX
	if (rspamd_log->mtx) {
		rspamd_mempool_lock_mutex (rspamd_log->mtx);
	}
	else {
		rspamd_file_lock (fd, FALSE);
	}
#else
	rspamd_file_lock (fd, FALSE);
#endif

	if (!(rspamd_log->flags & RSPAMD_LOG_FLAG_SYSTEMD)) {
		log_time (rspamd_get_calendar_ticks (),
				rspamd_log, timebuf, sizeof (timebuf));
	}

	if (priv->log_color) {
		if (level_flags & (G_LOG_LEVEL_INFO|G_LOG_LEVEL_MESSAGE)) {
			/* White */
			r = rspamd_snprintf (tmpbuf, sizeof (tmpbuf), "\033[0;37m");
		}
		else if (level_flags & G_LOG_LEVEL_WARNING) {
			/* Magenta */
			r = rspamd_snprintf (tmpbuf, sizeof (tmpbuf), "\033[0;32m");
		}
		else if (level_flags & G_LOG_LEVEL_CRITICAL) {
			/* Red */
			r = rspamd_snprintf (tmpbuf, sizeof (tmpbuf), "\033[1;31m");
		}
	}
	else {
		r = 0;
	}

	if (priv->log_rspamadm) {
		if (rspamd_log->log_level == G_LOG_LEVEL_DEBUG) {
			log_time (rspamd_get_calendar_ticks (),
					rspamd_log, timebuf, sizeof (timebuf));
			iov[niov].iov_base = (void *) timebuf;
			iov[niov++].iov_len = strlen (timebuf);
			iov[niov].iov_base = (void *) " ";
			iov[niov++].iov_len = 1;
		}

		iov[niov].iov_base = (void *) message;
		iov[niov++].iov_len = mlen;
		iov[niov].iov_base = (void *) &lf_chr;
		iov[niov++].iov_len = 1;
	}
	else {
		if (!(rspamd_log->flags & RSPAMD_LOG_FLAG_SYSTEMD)) {
			if (priv->log_severity) {
				r += rspamd_snprintf(tmpbuf + r,
						sizeof(tmpbuf) - r,
						"%s [%s] #%P(%s) ",
						timebuf,
						rspamd_get_log_severity_string (level_flags),
						rspamd_log->pid,
						rspamd_log->process_type);
			}
			else {
				r += rspamd_snprintf(tmpbuf + r,
						sizeof(tmpbuf) - r,
						"%s #%P(%s) ",
						timebuf,
						rspamd_log->pid,
						rspamd_log->process_type);
			}
		} else {
			r += rspamd_snprintf (tmpbuf + r,
					sizeof (tmpbuf) - r,
					"#%P(%s) ",
					rspamd_log->pid,
					rspamd_log->process_type);
		}

		modulebuf[0] = '\0';
		mremain = sizeof (modulebuf);
		m = modulebuf;

		if (id != NULL) {
			guint slen = strlen (id);
			slen = MIN (RSPAMD_LOG_ID_LEN, slen);
			mr = rspamd_snprintf (m, mremain, "<%*.s>; ", slen,
					id);
			m += mr;
			mremain -= mr;
		}
		if (module != NULL) {
			mr = rspamd_snprintf (m, mremain, "%s; ", module);
			m += mr;
			mremain -= mr;
		}
		if (function != NULL) {
			mr = rspamd_snprintf (m, mremain, "%s: ", function);
			m += mr;
			mremain -= mr;
		}
		else {
			mr = rspamd_snprintf (m, mremain, ": ");
			m += mr;
			mremain -= mr;
		}

		/* Ensure that we have a space at the end */
		if (m > modulebuf && *(m - 1) != ' ') {
			*(m - 1) = ' ';
		}

		iov[niov].iov_base = tmpbuf;
		iov[niov++].iov_len = r;
		iov[niov].iov_base = modulebuf;
		iov[niov++].iov_len = m - modulebuf;
		iov[niov].iov_base = (void *) message;
		iov[niov++].iov_len = mlen;
		iov[niov].iov_base = (void *) &lf_chr;
		iov[niov++].iov_len = 1;
	}

	if (priv->log_color) {
		iov[niov].iov_base = "\033[0m";
		iov[niov++].iov_len = sizeof ("\033[0m") - 1;
	}

again:
	r = writev (fd, iov, niov);

	if (r == -1) {
		if (errno == EAGAIN || errno == EINTR) {
			goto again;
		}

		if (rspamd_log->mtx) {
			rspamd_mempool_unlock_mutex (rspamd_log->mtx);
		}
		else {
			rspamd_file_unlock (fd, FALSE);
		}

		return false;
	}

	if (rspamd_log->mtx) {
		rspamd_mempool_unlock_mutex (rspamd_log->mtx);
	}
	else {
		rspamd_file_unlock (fd, FALSE);
	}

	return true;
}