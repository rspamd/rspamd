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

#define FILE_LOG_QUARK g_quark_from_static_string ("file_logger")

static const gchar lf_chr = '\n';

struct rspamd_file_logger_priv {
	gint fd;
	struct {
		guint32 size;
		guint32 used;
		u_char *buf;
	} io_buf;
	gboolean throttling;
	gchar *log_file;
	gboolean is_buffered;
	gboolean log_severity;
	time_t throttling_time;
	guint32 repeats;
	guint64 last_line_cksum;
	gchar *saved_message;
	gsize saved_mlen;
	gchar *saved_function;
	gchar *saved_module;
	gchar *saved_id;
	guint saved_loglevel;
};

/**
 * Calculate checksum for log line (used for repeating logic)
 */
static inline guint64
rspamd_log_calculate_cksum (const gchar *message, size_t mlen)
{
	return rspamd_cryptobox_fast_hash (message, mlen, rspamd_hash_seed ());
}

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


/*
 * Write a line to log file (unbuffered)
 */
static bool
direct_write_log_line (rspamd_logger_t *rspamd_log,
					   struct rspamd_file_logger_priv *priv,
					   void *data,
					   gsize count,
					   gboolean is_iov,
					   gint level_flags)
{
	struct iovec *iov;
	const gchar *line;
	glong r;
	gint fd;
	gboolean locked = FALSE;

	iov = (struct iovec *) data;
	fd = priv->fd;

	if (!rspamd_log->no_lock) {
		gsize tlen;

		if (is_iov) {
			tlen = 0;

			for (guint i = 0; i < count; i ++) {
				tlen += iov[i].iov_len;
			}
		}
		else {
			tlen = count;
		}

		if (tlen > PIPE_BUF) {
			locked = TRUE;

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
		}
	}

	if (is_iov) {
		r = writev (fd, iov, count);
	}
	else {
		line = (const gchar *) data;
		r = write (fd, line, count);
	}

	if (locked) {
#ifndef DISABLE_PTHREAD_MUTEX
		if (rspamd_log->mtx) {
			rspamd_mempool_unlock_mutex (rspamd_log->mtx);
		}
		else {
			rspamd_file_unlock (fd, FALSE);
		}
#else
		rspamd_file_unlock (fd, FALSE);
#endif
	}

	if (r == -1) {
		/* We cannot write message to file, so we need to detect error and make decision */
		if (errno == EINTR) {
			/* Try again */
			return direct_write_log_line (rspamd_log, priv, data, count, is_iov, level_flags);
		}

		if (errno == EFAULT || errno == EINVAL || errno == EFBIG ||
			errno == ENOSPC) {
			/* Rare case */
			priv->throttling = TRUE;
			priv->throttling_time = time (NULL);
		}
		else if (errno == EPIPE || errno == EBADF) {
			/* We write to some pipe and it disappears, disable logging or we has opened bad file descriptor */
			rspamd_log->enabled = FALSE;
		}

		return false;
	}
	else if (priv->throttling) {
		priv->throttling = FALSE;
	}

	return true;
}

/**
 * Fill buffer with message (limits must be checked BEFORE this call)
 */
static void
fill_buffer (rspamd_logger_t *rspamd_log,
			 struct rspamd_file_logger_priv *priv,
			 const struct iovec *iov, gint iovcnt)
{
	gint i;

	for (i = 0; i < iovcnt; i++) {
		memcpy (priv->io_buf.buf + priv->io_buf.used,
				iov[i].iov_base,
				iov[i].iov_len);
		priv->io_buf.used += iov[i].iov_len;
	}

}

static void
rspamd_log_flush (rspamd_logger_t *rspamd_log, struct rspamd_file_logger_priv *priv)
{
	if (priv->is_buffered) {
		direct_write_log_line (rspamd_log,
				priv,
				priv->io_buf.buf,
				priv->io_buf.used,
				FALSE,
				rspamd_log->log_level);
		priv->io_buf.used = 0;
	}
}

/*
 * Write message to buffer or to file (using direct_write_log_line function)
 */
static bool
file_log_helper (rspamd_logger_t *rspamd_log,
				 struct rspamd_file_logger_priv *priv,
				 const struct iovec *iov,
				 guint iovcnt,
				 gint level_flags)
{
	size_t len = 0;
	guint i;

	if (!priv->is_buffered) {
		/* Write string directly */
		return direct_write_log_line (rspamd_log, priv, (void *) iov, iovcnt,
				TRUE, level_flags);
	}
	else {
		/* Calculate total length */
		for (i = 0; i < iovcnt; i++) {
			len += iov[i].iov_len;
		}
		/* Fill buffer */
		if (priv->io_buf.size < len) {
			/* Buffer is too small to hold this string, so write it directly */
			rspamd_log_flush (rspamd_log, priv);
			return direct_write_log_line (rspamd_log, priv, (void *) iov, iovcnt,
					TRUE, level_flags);
		}
		else if (priv->io_buf.used + len >= priv->io_buf.size) {
			/* Buffer is full, try to write it directly */
			rspamd_log_flush (rspamd_log, priv);
			fill_buffer (rspamd_log, priv, iov, iovcnt);
		}
		else {
			/* Copy incoming string to buffer */
			fill_buffer (rspamd_log, priv, iov, iovcnt);
		}
	}

	return true;
}

static void
rspamd_log_reset_repeated (rspamd_logger_t *rspamd_log,
						   struct rspamd_file_logger_priv *priv)
{
	gchar tmpbuf[256];
	gssize r;

	if (priv->repeats > REPEATS_MIN) {
		r = rspamd_snprintf (tmpbuf,
				sizeof (tmpbuf),
				"Last message repeated %ud times",
				priv->repeats - REPEATS_MIN);
		priv->repeats = 0;

		if (priv->saved_message) {
			rspamd_log_file_log (priv->saved_module,
					priv->saved_id,
					priv->saved_function,
					priv->saved_loglevel | RSPAMD_LOG_FORCED,
					priv->saved_message,
					priv->saved_mlen,
					rspamd_log,
					priv);

			g_free (priv->saved_message);
			g_free (priv->saved_function);
			g_free (priv->saved_module);
			g_free (priv->saved_id);
			priv->saved_message = NULL;
			priv->saved_function = NULL;
			priv->saved_module = NULL;
			priv->saved_id = NULL;
		}

		/* It is safe to use temporary buffer here as it is not static */
		rspamd_log_file_log (NULL, NULL,
				G_STRFUNC,
				priv->saved_loglevel | RSPAMD_LOG_FORCED,
				tmpbuf,
				r,
				rspamd_log,
				priv);
		rspamd_log_flush (rspamd_log, priv);
	}
}

static gint
rspamd_try_open_log_fd (rspamd_logger_t *rspamd_log,
						struct rspamd_file_logger_priv *priv,
						uid_t uid, gid_t gid,
						GError **err)
{
	gint fd;

	fd = open (priv->log_file,
			O_CREAT | O_WRONLY | O_APPEND,
			S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
	if (fd == -1) {
		g_set_error (err, FILE_LOG_QUARK, errno,
				"open_log: cannot open desired log file: %s, %s\n",
				priv->log_file, strerror (errno));
		return -1;
	}

	if (uid != -1 || gid != -1) {
		if (fchown (fd, uid, gid) == -1) {
			g_set_error (err, FILE_LOG_QUARK, errno,
					"open_log: cannot chown desired log file: %s, %s\n",
					priv->log_file, strerror (errno));
			close (fd);

			return -1;
		}
	}

	return fd;
}

void *
rspamd_log_file_init (rspamd_logger_t *logger, struct rspamd_config *cfg,
					  uid_t uid, gid_t gid, GError **err)
{
	struct rspamd_file_logger_priv *priv;

	if (!cfg || !cfg->cfg_name) {
		g_set_error (err, FILE_LOG_QUARK, EINVAL,
				"no log file specified");
		return NULL;
	}

	priv = g_malloc0 (sizeof (*priv));

	if (cfg->log_buffered) {
		if (cfg->log_buf_size != 0) {
			priv->io_buf.size = cfg->log_buf_size;
		}
		else {
			priv->io_buf.size = LOGBUF_LEN;
		}
		priv->is_buffered = TRUE;
		priv->io_buf.buf = g_malloc (priv->io_buf.size);
	}

	if (cfg->log_file) {
		priv->log_file = g_strdup (cfg->log_file);
	}

	priv->log_severity = (logger->flags & RSPAMD_LOG_FLAG_SEVERITY);
	priv->fd = rspamd_try_open_log_fd (logger, priv, uid, gid, err);

	if (priv->fd == -1) {
		rspamd_log_file_dtor (logger, priv);

		return NULL;
	}

	return priv;
}

void
rspamd_log_file_dtor (rspamd_logger_t *logger, gpointer arg)
{
	struct rspamd_file_logger_priv *priv = (struct rspamd_file_logger_priv *)arg;

	rspamd_log_reset_repeated (logger, priv);
	rspamd_log_flush (logger, priv);

	if (priv->fd != -1) {
		if (close (priv->fd) == -1) {
			rspamd_fprintf (stderr, "cannot close log fd %d: %s; log file = %s\n",
					priv->fd, strerror (errno), priv->log_file);
		}
	}

	g_free (priv->log_file);
	g_free (priv);
}

bool
rspamd_log_file_log (const gchar *module, const gchar *id,
				   const gchar *function,
				   gint level_flags,
				   const gchar *message,
				   gsize mlen,
				   rspamd_logger_t *rspamd_log,
				   gpointer arg)
{
	struct rspamd_file_logger_priv *priv = (struct rspamd_file_logger_priv *)arg;
	static gchar timebuf[64], modulebuf[64];
	gchar tmpbuf[256];
	gchar *m;
	gdouble now;
	struct iovec iov[6];
	gulong r = 0, mr = 0;
	guint64 cksum;
	size_t mremain;
	const gchar *cptype = NULL;
	gboolean got_time = FALSE;


	if (!(level_flags & RSPAMD_LOG_FORCED) && !rspamd_log->enabled) {
		return false;
	}

	/* Check throttling due to write errors */
	if (!(level_flags & RSPAMD_LOG_FORCED) && priv->throttling) {
		now = rspamd_get_calendar_ticks ();

		if (priv->throttling_time != now) {
			priv->throttling_time = now;
			got_time = TRUE;
		}
		else {
			/* Do not try to write to file too often while throttling */
			return false;
		}
	}

	/* Check repeats */
	cksum = rspamd_log_calculate_cksum (message, mlen);

	if (cksum == priv->last_line_cksum) {
		priv->repeats++;

		if (priv->repeats > REPEATS_MIN && priv->repeats <
												 REPEATS_MAX) {
			/* Do not log anything but save message for future */
			if (priv->saved_message == NULL) {
				priv->saved_function = g_strdup (function);
				priv->saved_mlen = mlen;
				priv->saved_message = g_malloc (mlen);
				memcpy (priv->saved_message, message, mlen);

				if (module) {
					priv->saved_module = g_strdup (module);
				}

				if (id) {
					priv->saved_id = g_strdup (id);
				}

				priv->saved_loglevel = level_flags;
			}

			return true;
		}
		else if (priv->repeats > REPEATS_MAX) {
			rspamd_log_reset_repeated (rspamd_log, priv);

			bool ret = rspamd_log_file_log (module, id,
					function,
					level_flags,
					message,
					mlen,
					rspamd_log,
					priv);

			/* Probably we have more repeats in future */
			priv->repeats = REPEATS_MIN + 1;

			return ret;
		}
	}
	else {
		/* Reset counter if new message differs from saved message */
		priv->last_line_cksum = cksum;

		if (priv->repeats > REPEATS_MIN) {
			rspamd_log_reset_repeated (rspamd_log, priv);
			return rspamd_log_file_log (module, id,
					function,
					level_flags,
					message,
					mlen,
					rspamd_log,
					arg);
		}
		else {
			priv->repeats = 0;
		}
	}
	if (!got_time) {
		now = rspamd_get_calendar_ticks ();
	}

	/* Format time */
	if (!(rspamd_log->flags & RSPAMD_LOG_FLAG_SYSTEMD)) {
		log_time (now, rspamd_log, timebuf, sizeof (timebuf));
	}

	cptype = rspamd_log->process_type;
	r = 0;

	if (!(rspamd_log->flags & RSPAMD_LOG_FLAG_SYSTEMD)) {
		if (priv->log_severity) {
			r += rspamd_snprintf(tmpbuf + r,
					sizeof(tmpbuf) - r,
					"%s [%s] #%P(%s) ",
					timebuf,
					rspamd_get_log_severity_string (level_flags),
					rspamd_log->pid,
					cptype);
		}
		else {
			r += rspamd_snprintf(tmpbuf + r,
					sizeof(tmpbuf) - r,
					"%s #%P(%s) ",
					timebuf,
					rspamd_log->pid,
					cptype);
		}
	}
	else {
		r += rspamd_snprintf (tmpbuf + r,
				sizeof (tmpbuf) - r,
				"(%s) ",
				cptype);
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

	/* Construct IOV for log line */
	iov[0].iov_base = tmpbuf;
	iov[0].iov_len = r;
	iov[1].iov_base = modulebuf;
	iov[1].iov_len = m - modulebuf;
	iov[2].iov_base = (void *) message;
	iov[2].iov_len = mlen;
	iov[3].iov_base = (void *) &lf_chr;
	iov[3].iov_len = 1;

	return file_log_helper (rspamd_log, priv, iov, 4, level_flags);
}

void *
rspamd_log_file_reload (rspamd_logger_t *logger, struct rspamd_config *cfg,
						gpointer arg, uid_t uid, gid_t gid, GError **err)
{
	struct rspamd_file_logger_priv *npriv;

	if (!cfg->cfg_name) {
		g_set_error (err, FILE_LOG_QUARK, EINVAL,
				"no log file specified");
		return NULL;
	}

	npriv = rspamd_log_file_init (logger, cfg, uid, gid, err);

	if (npriv) {
		/* Close old */
		rspamd_log_file_dtor (logger, arg);
	}

	return npriv;
}

bool
rspamd_log_file_on_fork (rspamd_logger_t *logger, struct rspamd_config *cfg,
							  gpointer arg, GError **err)
{
	struct rspamd_file_logger_priv *priv = (struct rspamd_file_logger_priv *)arg;

	rspamd_log_reset_repeated (logger, priv);
	rspamd_log_flush (logger, priv);

	return true;
}