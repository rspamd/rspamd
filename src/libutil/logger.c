/*-
 * Copyright 2016 Vsevolod Stakhov
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
#include "util.h"
#include "rspamd.h"
#include "map.h"
#include "cryptobox.h"
#include "ottery.h"
#include "keypair.h"
#include "unix-std.h"

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

/* How much message should be repeated before it is count to be repeated one */
#define REPEATS_MIN 3
#define REPEATS_MAX 300
#define LOG_ID 6
#define RSPAMD_LOGBUF_SIZE 8192

/**
 * Static structure that store logging parameters
 * It is NOT shared between processes and is created by main process
 */
struct rspamd_logger_s {
	rspamd_log_func_t log_func;
	struct rspamd_config *cfg;
	struct rspamd_cryptobox_pubkey *pk;
	struct rspamd_cryptobox_keypair *keypair;
	struct {
		guint32 size;
		guint32 used;
		u_char *buf;
	} io_buf;
	gint fd;
	gboolean is_buffered;
	gboolean enabled;
	gboolean is_debug;
	gboolean throttling;
	gboolean no_lock;
	time_t throttling_time;
	enum rspamd_log_type type;
	pid_t pid;
	guint32 repeats;
	GQuark process_type;
	radix_compressed_t *debug_ip;
	guint64 last_line_cksum;
	gchar *saved_message;
	gchar *saved_function;
	gchar *saved_module;
	gchar *saved_id;
	guint saved_loglevel;
	guint64 log_cnt[4];
};

static const gchar lf_chr = '\n';

static rspamd_logger_t *default_logger = NULL;

static void syslog_log_function (const gchar *module,
		const gchar *id, const gchar *function,
		gint log_level, const gchar *message,
		gpointer arg);

static void
		file_log_function (const gchar *module,
		const gchar *id, const gchar *function,
		gint log_level, const gchar *message,
		gpointer arg);

/**
 * Calculate checksum for log line (used for repeating logic)
 */
static inline guint64
rspamd_log_calculate_cksum (const gchar *message, size_t mlen)
{
	return rspamd_cryptobox_fast_hash (message, mlen, rspamd_hash_seed ());
}

/*
 * Write a line to log file (unbuffered)
 */
static void
direct_write_log_line (rspamd_logger_t *rspamd_log,
		void *data,
		gsize count,
		gboolean is_iov)
{
	gchar errmsg[128];
	struct iovec *iov;
	const gchar *line;
	glong r;

	if (rspamd_log->enabled) {
		if (!rspamd_log->no_lock) {
			rspamd_file_lock (rspamd_log->fd, FALSE);
		}

		if (is_iov) {
			iov = (struct iovec *) data;
			r = writev (rspamd_log->fd, iov, count);
		}
		else {
			line = (const gchar *) data;
			r = write (rspamd_log->fd, line, count);
		}

		if (!rspamd_log->no_lock) {
			rspamd_file_unlock (rspamd_log->fd, FALSE);
		}

		if (r == -1) {
			/* We cannot write message to file, so we need to detect error and make decision */
			if (errno == EINTR) {
				/* Try again */
				direct_write_log_line (rspamd_log, data, count, is_iov);
				return;
			}

			r = rspamd_snprintf (errmsg,
					sizeof (errmsg),
					"direct_write_log_line: cannot write log line: %s",
					strerror (errno));
			if (errno == EFAULT || errno == EINVAL || errno == EFBIG ||
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
	guchar *p = (guchar *) str;

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
rspamd_log_open_priv (rspamd_logger_t *rspamd_log, uid_t uid, gid_t gid)
{
	switch (rspamd_log->cfg->log_type) {
		case RSPAMD_LOG_CONSOLE:
			/* Do nothing with console */
			rspamd_log->enabled = TRUE;
			return 0;
		case RSPAMD_LOG_SYSLOG:
#ifdef HAVE_SYSLOG_H
			openlog ("rspamd", LOG_NDELAY | LOG_PID,
					rspamd_log->cfg->log_facility);
			rspamd_log->enabled = TRUE;
#endif
			return 0;
		case RSPAMD_LOG_FILE:
			rspamd_log->fd = open (rspamd_log->cfg->log_file,
					O_CREAT | O_WRONLY | O_APPEND,
					S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
			if (rspamd_log->fd == -1) {
				fprintf (stderr,
						"open_log: cannot open desired log file: %s, %s",
						rspamd_log->cfg->log_file, strerror (errno));
				return -1;
			}
			if (fchown (rspamd_log->fd, uid, gid) == -1) {
				fprintf (stderr,
						"open_log: cannot chown desired log file: %s, %s",
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
rspamd_log_close_priv (rspamd_logger_t *rspamd_log, uid_t uid, gid_t gid)
{
	gchar tmpbuf[256];
	rspamd_log_flush (rspamd_log);

	switch (rspamd_log->type) {
		case RSPAMD_LOG_CONSOLE:
			/* Do nothing special */
			break;
		case RSPAMD_LOG_SYSLOG:
#ifdef HAVE_SYSLOG_H
			closelog ();
#endif
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
						file_log_function (rspamd_log->saved_module,
								rspamd_log->saved_id,
								rspamd_log->saved_function,
								rspamd_log->saved_loglevel | RSPAMD_LOG_FORCED,
								rspamd_log->saved_message,
								rspamd_log);

						g_free (rspamd_log->saved_message);
						g_free (rspamd_log->saved_function);
						g_free (rspamd_log->saved_module);
						g_free (rspamd_log->saved_id);
						rspamd_log->saved_message = NULL;
						rspamd_log->saved_function = NULL;
						rspamd_log->saved_module = NULL;
						rspamd_log->saved_id = NULL;
					}
					/* It is safe to use temporary buffer here as it is not static */
					file_log_function (NULL, NULL,
							G_STRFUNC,
							rspamd_log->saved_loglevel | RSPAMD_LOG_FORCED,
							tmpbuf,
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
rspamd_log_reopen_priv (rspamd_logger_t *rspamd_log, uid_t uid, gid_t gid)
{
	rspamd_log_close_priv (rspamd_log, uid, gid);
	if (rspamd_log_open_priv (rspamd_log, uid, gid) == 0) {
		msg_info ("log file reopened");
		return 0;
	}

	return -1;
}

/**
 * Open log file or initialize other structures
 */
gint
rspamd_log_open (rspamd_logger_t *logger)
{
	return rspamd_log_open_priv (logger, -1, -1);
}

/**
 * Close log file or destroy other structures
 */
void
rspamd_log_close (rspamd_logger_t *logger)
{
	rspamd_log_close_priv (logger, -1, -1);
}

/**
 * Close and open log again
 */
gint
rspamd_log_reopen (rspamd_logger_t *logger)
{
	return rspamd_log_reopen_priv (logger, -1, -1);
}

/*
 * Setup logger
 */
void
rspamd_set_logger (struct rspamd_config *cfg,
		GQuark ptype,
		struct rspamd_main *rspamd)
{
	rspamd_logger_t *logger;

	if (rspamd->logger == NULL) {
		rspamd->logger = g_slice_alloc0 (sizeof (rspamd_logger_t));
	}

	logger = rspamd->logger;

	logger->type = cfg->log_type;
	logger->pid = getpid ();
	logger->process_type = ptype;

	switch (cfg->log_type) {
		case RSPAMD_LOG_CONSOLE:
			logger->log_func = file_log_function;
			logger->fd = STDERR_FILENO;
			break;
		case RSPAMD_LOG_SYSLOG:
			logger->log_func = syslog_log_function;
			break;
		case RSPAMD_LOG_FILE:
			logger->log_func = file_log_function;
			break;
	}

	logger->cfg = cfg;

	/* Set up buffer */
	if (cfg->log_buffered) {
		if (cfg->log_buf_size != 0) {
			logger->io_buf.size = cfg->log_buf_size;
		}
		else {
			logger->io_buf.size = BUFSIZ;
		}
		logger->is_buffered = TRUE;
		logger->io_buf.buf = g_malloc (logger->io_buf.size);
	}
	/* Set up conditional logging */
	if (cfg->debug_ip_map != NULL) {
		/* Try to add it as map first of all */
		if (logger->debug_ip) {
			radix_destroy_compressed (logger->debug_ip);
		}

		logger->debug_ip = NULL;
		rspamd_config_radix_from_ucl (cfg,
				cfg->debug_ip_map,
				"IP addresses for which debug logs are enabled",
				&logger->debug_ip, NULL);
	}
	else if (logger->debug_ip) {
		radix_destroy_compressed (logger->debug_ip);
		logger->debug_ip = NULL;
	}

	if (logger->pk) {
		rspamd_pubkey_unref (logger->pk);
	}
	logger->pk = NULL;

	if (logger->keypair) {
		rspamd_keypair_unref (logger->keypair);
	}
	logger->keypair = NULL;

	if (cfg->log_encryption_key) {
		logger->pk = rspamd_pubkey_ref (cfg->log_encryption_key);
		logger->keypair = rspamd_keypair_new (RSPAMD_KEYPAIR_KEX,
				RSPAMD_CRYPTOBOX_MODE_25519);
		rspamd_pubkey_calculate_nm (logger->pk, logger->keypair);
	}

	default_logger = logger;
}

/**
 * Used after fork() for updating structure params
 */
void
rspamd_log_update_pid (GQuark ptype, rspamd_logger_t *rspamd_log)
{
	rspamd_log->pid = getpid ();
	rspamd_log->process_type = ptype;

	/* We also need to clear all messages pending */
	if (rspamd_log->repeats > 0) {
		rspamd_log->repeats = 0;
		if (rspamd_log->saved_message) {
			g_free (rspamd_log->saved_message);
			g_free (rspamd_log->saved_function);
			g_free (rspamd_log->saved_module);
			g_free (rspamd_log->saved_id);
			rspamd_log->saved_message = NULL;
			rspamd_log->saved_function = NULL;
			rspamd_log->saved_module = NULL;
			rspamd_log->saved_id = NULL;
		}
	}
}

/**
 * Flush logging buffer
 */
void
rspamd_log_flush (rspamd_logger_t *rspamd_log)
{
	if (rspamd_log->is_buffered &&
		(rspamd_log->type == RSPAMD_LOG_CONSOLE ||
		 rspamd_log->type == RSPAMD_LOG_FILE)) {
		direct_write_log_line (rspamd_log,
				rspamd_log->io_buf.buf,
				rspamd_log->io_buf.used,
				FALSE);
		rspamd_log->io_buf.used = 0;
	}
}

static inline gboolean
rspamd_logger_need_log (rspamd_logger_t *rspamd_log, GLogLevelFlags log_level,
		const gchar *module)
{
	g_assert (rspamd_log != NULL);

	if (log_level <= rspamd_log->cfg->log_level) {
		return TRUE;
	}

	if (rspamd_log->cfg->debug_modules != NULL && module != NULL &&
		g_hash_table_size (rspamd_log->cfg->debug_modules) > 0 &&
		g_hash_table_lookup (rspamd_log->cfg->debug_modules, module)) {

		return TRUE;
	}

	return FALSE;
}

static gchar *
rspamd_log_encrypt_message (const gchar *begin, const gchar *end,
		rspamd_logger_t *rspamd_log)
{
	guchar *out;
	gchar *b64;
	guchar *p, *nonce, *mac;
	const guchar *comp;
	guint len, inlen;

	g_assert (end > begin);
	/* base64 (pubkey | nonce | message) */
	inlen = rspamd_cryptobox_nonce_bytes (RSPAMD_CRYPTOBOX_MODE_25519) +
			rspamd_cryptobox_pk_bytes (RSPAMD_CRYPTOBOX_MODE_25519) +
			rspamd_cryptobox_mac_bytes (RSPAMD_CRYPTOBOX_MODE_25519) +
			(end - begin);
	out = g_malloc (inlen);

	p = out;
	comp = rspamd_pubkey_get_pk (rspamd_log->pk, &len);
	memcpy (p, comp, len);
	p += len;
	ottery_rand_bytes (p, rspamd_cryptobox_nonce_bytes (RSPAMD_CRYPTOBOX_MODE_25519));
	nonce = p;
	p += rspamd_cryptobox_nonce_bytes (RSPAMD_CRYPTOBOX_MODE_25519);
	mac = p;
	p += rspamd_cryptobox_mac_bytes (RSPAMD_CRYPTOBOX_MODE_25519);
	memcpy (p, begin, end - begin);
	comp = rspamd_pubkey_get_nm (rspamd_log->pk);
	g_assert (comp != NULL);
	rspamd_cryptobox_encrypt_nm_inplace (p, end - begin, nonce, comp, mac,
			RSPAMD_CRYPTOBOX_MODE_25519);
	b64 = rspamd_encode_base64 (out, inlen, 0, NULL);
	g_free (out);

	return b64;
}

void
rspamd_common_logv (rspamd_logger_t *rspamd_log, gint level_flags,
		const gchar *module, const gchar *id, const gchar *function,
		const gchar *fmt, va_list args)
{
	gchar logbuf[RSPAMD_LOGBUF_SIZE], *end;
	gint level = level_flags & (RSPAMD_LOG_LEVEL_MASK & G_LOG_LEVEL_MASK);

	if (rspamd_log == NULL) {
		rspamd_log = default_logger;
	}

	if (rspamd_log == NULL) {
		/* Just fprintf message to stderr */
		if (level >= G_LOG_LEVEL_INFO) {
			rspamd_vsnprintf (logbuf, sizeof (logbuf), fmt, args);
			fprintf (stderr, "%s\n", logbuf);
		}
	}
	else {
		if (rspamd_logger_need_log (rspamd_log, level, module)) {
			end = rspamd_vsnprintf (logbuf, sizeof (logbuf), fmt, args);

			if ((level_flags & RSPAMD_LOG_ENCRYPTED) && rspamd_log->pk) {
				gchar *encrypted;

				encrypted = rspamd_log_encrypt_message (logbuf, end, rspamd_log);
				rspamd_log->log_func (module, id,
						function,
						level_flags,
						encrypted,
						rspamd_log);
				g_free (encrypted);
			}
			else {
				rspamd_log->log_func (module, id,
						function,
						level_flags,
						logbuf,
						rspamd_log);
			}

			switch (level) {
			case G_LOG_LEVEL_CRITICAL:
				rspamd_log->log_cnt[0] ++;
				break;
			case G_LOG_LEVEL_WARNING:
				rspamd_log->log_cnt[1]++;
				break;
			case G_LOG_LEVEL_INFO:
				rspamd_log->log_cnt[2]++;
				break;
			case G_LOG_LEVEL_DEBUG:
				rspamd_log->log_cnt[3]++;
				break;
			default:
				break;
			}
		}
	}
}

/**
 * This log functions select real logger and write message if level is less or equal to configured log level
 */
void
rspamd_common_log_function (rspamd_logger_t *rspamd_log,
		gint level_flags,
		const gchar *module, const gchar *id,
		const gchar *function,
		const gchar *fmt,
		...)
{
	va_list vp;

	va_start (vp, fmt);
	rspamd_common_logv (rspamd_log, level_flags, module, id, function, fmt, vp);
	va_end (vp);
}

void
rspamd_default_logv (gint level_flags, const gchar *module, const gchar *id,
		const gchar *function,
		const gchar *fmt, va_list args)
{
	rspamd_common_logv (NULL, level_flags, module, id, function, fmt, args);
}

void
rspamd_default_log_function (gint level_flags,
		const gchar *module, const gchar *id,
		const gchar *function, const gchar *fmt, ...)
{

	va_list vp;

	va_start (vp, fmt);
	rspamd_default_logv (level_flags, module, id, function, fmt, vp);
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
		guint iovcnt)
{
	size_t len = 0;
	guint i;

	if (!rspamd_log->is_buffered) {
		/* Write string directly */
		direct_write_log_line (rspamd_log, (void *) iov, iovcnt, TRUE);
	}
	else {
		/* Calculate total length */
		for (i = 0; i < iovcnt; i++) {
			len += iov[i].iov_len;
		}
		/* Fill buffer */
		if (rspamd_log->io_buf.size < len) {
			/* Buffer is too small to hold this string, so write it dirrectly */
			rspamd_log_flush (rspamd_log);
			direct_write_log_line (rspamd_log, (void *) iov, iovcnt, TRUE);
		}
		else if (rspamd_log->io_buf.used + len >= rspamd_log->io_buf.size) {
			/* Buffer is full, try to write it dirrectly */
			rspamd_log_flush (rspamd_log);
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
syslog_log_function (const gchar *module, const gchar *id,
		const gchar *function,
		gint level_flags,
		const gchar *message,
		gpointer arg)
{
	rspamd_logger_t *rspamd_log = arg;
#ifdef HAVE_SYSLOG_H
	struct {
		GLogLevelFlags glib_level;
		gint syslog_level;
	} levels_match[] = {
			{G_LOG_LEVEL_DEBUG, LOG_DEBUG},
			{G_LOG_LEVEL_INFO, LOG_INFO},
			{G_LOG_LEVEL_WARNING, LOG_WARNING},
			{G_LOG_LEVEL_CRITICAL, LOG_ERR}
	};
	unsigned i;
	gint syslog_level;

	if (!rspamd_log->enabled) {
		return;
	}
	/* Detect level */
	syslog_level = LOG_DEBUG;

	for (i = 0; i < G_N_ELEMENTS (levels_match); i ++) {
		if (level_flags & levels_match[i].glib_level) {
			syslog_level = levels_match[i].syslog_level;
			break;
		}
	}

	syslog (syslog_level, "<%.*s>; %s; %s: %s",
			LOG_ID, id != NULL ? id : "",
			module != NULL ? module : "",
			function != NULL ? function : "",
			message);
#endif
}

/**
 * Main file interface for logging
 */
static void
file_log_function (const gchar *module, const gchar *id,
		const gchar *function,
		gint level_flags,
		const gchar *message,
		gpointer arg)
{
	gchar tmpbuf[256], timebuf[32], modulebuf[64];
	gchar *m;
	time_t now;
	struct tm *tms;
	struct iovec iov[5];
	gulong r = 0, mr = 0;
	guint64 cksum;
	size_t mlen, mremain;
	const gchar *cptype = NULL;
	gboolean got_time = FALSE;
	rspamd_logger_t *rspamd_log = arg;

	if (!rspamd_log->enabled) {
		return;
	}

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
			if (rspamd_log->saved_message == NULL) {
				rspamd_log->saved_message = g_strdup (message);
				rspamd_log->saved_function = g_strdup (function);

				if (module) {
					rspamd_log->saved_module = g_strdup (module);
				}

				if (id) {
					rspamd_log->saved_id = g_strdup (id);
				}

				rspamd_log->saved_loglevel = level_flags;
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
				file_log_function (rspamd_log->saved_module,
						rspamd_log->saved_id,
						rspamd_log->saved_function,
						rspamd_log->saved_loglevel,
						rspamd_log->saved_message,
						arg);

				g_free (rspamd_log->saved_message);
				g_free (rspamd_log->saved_function);
				g_free (rspamd_log->saved_module);
				g_free (rspamd_log->saved_id);
				rspamd_log->saved_message = NULL;
				rspamd_log->saved_function = NULL;
				rspamd_log->saved_module = NULL;
				rspamd_log->saved_id = NULL;
			}

			file_log_function ("logger", NULL,
					G_STRFUNC,
					rspamd_log->saved_loglevel,
					tmpbuf,
					arg);
			file_log_function (module, id,
					function,
					level_flags,
					message,
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
				file_log_function (rspamd_log->saved_module,
						rspamd_log->saved_id,
						rspamd_log->saved_function,
						rspamd_log->saved_loglevel,
						rspamd_log->saved_message,
						arg);

				g_free (rspamd_log->saved_message);
				g_free (rspamd_log->saved_function);
				g_free (rspamd_log->saved_module);
				g_free (rspamd_log->saved_id);
				rspamd_log->saved_message = NULL;
				rspamd_log->saved_function = NULL;
				rspamd_log->saved_module = NULL;
				rspamd_log->saved_id = NULL;
			}

			file_log_function ("logger", NULL,
					G_STRFUNC,
					level_flags,
					tmpbuf,
					arg);
			/* It is safe to use temporary buffer here as it is not static */
			file_log_function (module, id,
					function,
					level_flags,
					message,
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
		if (!rspamd_log->cfg->log_systemd) {
			tms = localtime (&now);

			strftime (timebuf, sizeof (timebuf), "%F %H:%M:%S", tms);
		}

		cptype = g_quark_to_string (rspamd_log->process_type);

		if (rspamd_log->cfg->log_color) {
			if (level_flags & G_LOG_LEVEL_INFO) {
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

		if (!rspamd_log->cfg->log_systemd) {
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
					"(%s) ",
					cptype);
		}

		modulebuf[0] = '\0';
		mremain = sizeof (modulebuf);
		m = modulebuf;

		if (id != NULL) {
			mr = rspamd_snprintf (m, mremain, "<%*.s>; ", LOG_ID,
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

		/* Construct IOV for log line */
		iov[0].iov_base = tmpbuf;
		iov[0].iov_len = r;
		iov[1].iov_base = modulebuf;
		iov[1].iov_len = m - modulebuf;
		iov[2].iov_base = (void *) message;
		iov[2].iov_len = mlen;
		iov[3].iov_base = (void *) &lf_chr;
		iov[3].iov_len = 1;

		if (rspamd_log->cfg->log_color) {
			iov[4].iov_base = "\033[0m";
			iov[4].iov_len = sizeof ("\033[0m") - 1;
			/* Call helper (for buffering) */
			file_log_helper (rspamd_log, iov, 5);
		}
		else {
			/* Call helper (for buffering) */
			file_log_helper (rspamd_log, iov, 4);
		}
	}
	else {
		iov[0].iov_base = (void *) message;
		iov[0].iov_len = mlen;
		iov[1].iov_base = (void *) &lf_chr;
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

/**
 * Write log line depending on ip
 */
void
rspamd_conditional_debug (rspamd_logger_t *rspamd_log,
		rspamd_inet_addr_t *addr, const gchar *module, const gchar *id,
		const gchar *function, const gchar *fmt, ...)
{
	static gchar logbuf[BUFSIZ];
	va_list vp;
	u_char *end;

	if (rspamd_log == NULL) {
		rspamd_log = default_logger;
	}

	if (rspamd_logger_need_log (rspamd_log, G_LOG_LEVEL_DEBUG, module) ||
		rspamd_log->is_debug) {
		if (rspamd_log->debug_ip && addr != NULL) {
			if (radix_find_compressed_addr (rspamd_log->debug_ip, addr)
				== RADIX_NO_VALUE) {
				return;
			}
		}

		va_start (vp, fmt);
		end = rspamd_vsnprintf (logbuf, sizeof (logbuf), fmt, vp);
		*end = '\0';
		va_end (vp);
		rspamd_log->log_func (module, id,
				function,
				G_LOG_LEVEL_DEBUG | RSPAMD_LOG_FORCED,
				logbuf,
				rspamd_log);
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

	if (rspamd_log->enabled &&
			rspamd_logger_need_log (rspamd_log, log_level, NULL)) {
		rspamd_log->log_func ("glib", NULL,
				NULL,
				log_level,
				message,
				rspamd_log);
	}
}

void
rspamd_glib_printerr_function (const gchar *message)
{
	rspamd_common_log_function (NULL, G_LOG_LEVEL_CRITICAL, "glib",
			NULL, G_STRFUNC,
			"%s", message);
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

const guint64 *
rspamd_log_counters (rspamd_logger_t *logger)
{
	if (logger) {
		return logger->log_cnt;
	}

	return NULL;
}

void
rspamd_log_nolock (rspamd_logger_t *logger)
{
	if (logger) {
		logger->no_lock = TRUE;
	}
}

void
rspamd_log_lock (rspamd_logger_t *logger)
{
	if (logger) {
		logger->no_lock = FALSE;
	}
}
