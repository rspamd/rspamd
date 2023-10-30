/*
 * Copyright 2023 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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

#define CONSOLE_LOG_QUARK g_quark_from_static_string("console_logger")

static const gchar lf_chr = '\n';
struct rspamd_console_logger_priv {
	gint fd;
	gint crit_fd;
};

/* Copy & paste :( */
static inline void
log_time(gdouble now, rspamd_logger_t *rspamd_log, gchar *timebuf,
		 size_t len)
{
	time_t sec = (time_t) now;
	gsize r;
	struct tm tms;

	rspamd_localtime(sec, &tms);
	r = strftime(timebuf, len, "%F %H:%M:%S", &tms);

	if (rspamd_log->flags & RSPAMD_LOG_FLAG_USEC) {
		gchar usec_buf[16];

		rspamd_snprintf(usec_buf, sizeof(usec_buf), "%.5f",
						now - (gdouble) sec);
		rspamd_snprintf(timebuf + r, len - r,
						"%s", usec_buf + 1);
	}
}

void *
rspamd_log_console_init(rspamd_logger_t *logger, struct rspamd_config *cfg,
						uid_t uid, gid_t gid, GError **err)
{
	struct rspamd_console_logger_priv *priv;

	priv = g_malloc0(sizeof(*priv));

	if (logger->flags & RSPAMD_LOG_FLAG_RSPAMADM) {
		priv->fd = dup(STDOUT_FILENO);
		priv->crit_fd = dup(STDERR_FILENO);
	}
	else {
		priv->fd = dup(STDERR_FILENO);
		priv->crit_fd = priv->fd;
	}

	if (priv->fd == -1) {
		g_set_error(err, CONSOLE_LOG_QUARK, errno,
					"open_log: cannot dup console fd: %s\n",
					strerror(errno));
		rspamd_log_console_dtor(logger, priv);

		return NULL;
	}

	if (!isatty(priv->fd)) {
		if (logger->flags & RSPAMD_LOG_FLAG_COLOR) {
			/* Disable colors for not a tty */
			logger->flags &= ~RSPAMD_LOG_FLAG_COLOR;
		}
	}

	return priv;
}

void *
rspamd_log_console_reload(rspamd_logger_t *logger, struct rspamd_config *cfg,
						  gpointer arg, uid_t uid, gid_t gid, GError **err)
{
	struct rspamd_console_logger_priv *npriv;

	npriv = rspamd_log_console_init(logger, cfg, uid, gid, err);

	if (npriv) {
		/* Close old */
		rspamd_log_console_dtor(logger, arg);
	}

	return npriv;
}

void rspamd_log_console_dtor(rspamd_logger_t *logger, gpointer arg)
{
	struct rspamd_console_logger_priv *priv = (struct rspamd_console_logger_priv *) arg;

	if (priv->fd != -1) {
		if (priv->fd != priv->crit_fd) {
			/* Two different FD case */
			if (close(priv->crit_fd) == -1) {
				rspamd_fprintf(stderr, "cannot close log crit_fd %d: %s\n",
							   priv->crit_fd, strerror(errno));
			}
		}

		if (close(priv->fd) == -1) {
			rspamd_fprintf(stderr, "cannot close log fd %d: %s\n",
						   priv->fd, strerror(errno));
		}

		/* Avoid the next if to be executed as crit_fd is equal to fd */
		priv->crit_fd = -1;
	}

	if (priv->crit_fd != -1) {
		if (close(priv->crit_fd) == -1) {
			rspamd_fprintf(stderr, "cannot close log crit_fd %d: %s\n",
						   priv->crit_fd, strerror(errno));
		}
	}

	g_free(priv);
}

bool rspamd_log_console_log(const gchar *module, const gchar *id,
							const gchar *function,
							gint level_flags,
							const gchar *message,
							gsize mlen,
							rspamd_logger_t *rspamd_log,
							gpointer arg)
{
	struct rspamd_console_logger_priv *priv = (struct rspamd_console_logger_priv *) arg;
	gint fd, r;
	double now;

	if (level_flags & G_LOG_LEVEL_CRITICAL) {
		fd = priv->crit_fd;
	}
	else {
		/* Use stderr if we are in rspamadm mode and severity is more than WARNING */
		if ((rspamd_log->flags & RSPAMD_LOG_FLAG_RSPAMADM) && (level_flags & G_LOG_LEVEL_WARNING)) {
			fd = priv->crit_fd;
		}
		else {
			fd = priv->fd;
		}
	}

#ifndef DISABLE_PTHREAD_MUTEX
	if (rspamd_log->mtx) {
		rspamd_mempool_lock_mutex(rspamd_log->mtx);
	}
	else {
		rspamd_file_lock(fd, FALSE);
	}
#else
	rspamd_file_lock(fd, FALSE);
#endif

	now = rspamd_get_calendar_ticks();
	gsize niov = rspamd_log_fill_iov(NULL, now, module, id,
									 function, level_flags, message,
									 mlen, rspamd_log);
	struct iovec *iov = g_alloca(sizeof(struct iovec) * niov);
	rspamd_log_fill_iov(iov, now, module, id, function, level_flags, message,
						mlen, rspamd_log);

again:
	r = writev(fd, iov, niov);

	if (r == -1) {
		if (errno == EAGAIN || errno == EINTR) {
			goto again;
		}

		if (rspamd_log->mtx) {
			rspamd_mempool_unlock_mutex(rspamd_log->mtx);
		}
		else {
			rspamd_file_unlock(fd, FALSE);
		}

		return false;
	}

	if (rspamd_log->mtx) {
		rspamd_mempool_unlock_mutex(rspamd_log->mtx);
	}
	else {
		rspamd_file_unlock(fd, FALSE);
	}

	return true;
}