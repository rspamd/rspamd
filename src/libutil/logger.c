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
#include "rspamd.h"
#include "map.h"
#include "map_helpers.h"
#include "ottery.h"
#include "unix-std.h"
#include "logger_private.h"

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif


static rspamd_logger_t *default_logger = NULL;
static struct rspamd_log_modules *log_modules = NULL;

guint rspamd_task_log_id = (guint)-1;
RSPAMD_CONSTRUCTOR(rspamd_task_log_init)
{
	rspamd_task_log_id = rspamd_logger_add_debug_module("task");
}


/* Logging utility functions */
gint
rspamd_log_open_priv (rspamd_logger_t *rspamd_log, uid_t uid, gid_t gid)
{
	gint nfd;

	if (!rspamd_log->opened) {

		switch (rspamd_log->log_type) {
		case RSPAMD_LOG_CONSOLE:
			/* Dup stderr fd to simplify processing */
			nfd = dup (STDERR_FILENO);

			if (nfd == -1) {
				return -1;
			}
			if (rspamd_log->fd != -1) {
				/*
				 * Postponed closing (e.g. when we switch from
				 * LOG_FILE to LOG_CONSOLE)
				 */
				close (rspamd_log->fd);
			}

			rspamd_log->fd = nfd;

			if (isatty (STDERR_FILENO)) {
				rspamd_log->flags |= RSPAMD_LOG_FLAG_TTY;
			}
			break;
		case RSPAMD_LOG_SYSLOG:
#ifdef HAVE_SYSLOG_H
			openlog ("rspamd", LOG_NDELAY | LOG_PID,
					rspamd_log->log_facility);
			rspamd_log->no_lock = TRUE;
			if (rspamd_log->fd != -1) {
				/*
				 * Postponed closing (e.g. when we switch from
				 * LOG_FILE to LOG_SYSLOG)
				 */
				close (rspamd_log->fd);
			}
#else
			return -1;
#endif
			break;
		case RSPAMD_LOG_FILE:
			nfd = rspamd_try_open_log_fd (rspamd_log, uid, gid);

			if (nfd == -1) {
				return -1;
			}

			if (rspamd_log->fd != -1) {
				/*
				 * Postponed closing (e.g. when we switch from
				 * LOG_CONSOLE to LOG_FILE)
				 */
				close (rspamd_log->fd);
			}

			rspamd_log->fd = nfd;
			rspamd_log->no_lock = TRUE;
			break;
		default:
			return -1;
		}

		rspamd_log->opened = TRUE;
		rspamd_log->enabled = TRUE;
	}

	return 0;
}


void
rspamd_log_close_priv (rspamd_logger_t *rspamd_log, gboolean termination, uid_t uid, gid_t gid)
{

	rspamd_log_flush (rspamd_log);
	rspamd_log_reset_repeated (rspamd_log);

	if (rspamd_log->opened) {
		switch (rspamd_log->type) {
		case RSPAMD_LOG_SYSLOG:
#ifdef HAVE_SYSLOG_H
			closelog ();
#endif
			break;
		case RSPAMD_LOG_FILE:
			if (rspamd_log->fd != -1) {
#if _POSIX_SYNCHRONIZED_IO > 0
				if (fdatasync (rspamd_log->fd) == -1) {
					msg_err ("error syncing log file: %s", strerror (errno));
				}
#else
				if (fsync (rspamd_log->fd) == -1) {
					msg_err ("error syncing log file: %s", strerror (errno));
				}
#endif
				close (rspamd_log->fd);
				rspamd_log->fd = -1;
			}
			break;
		case RSPAMD_LOG_CONSOLE:
			/*
			 * Console logging is special: it is usually a last resort when
			 * we have errors or something like that.
			 *
			 * Hence, we need to postpone it's closing to the moment
			 * when we open (in a reliable matter!) a new logging
			 * facility.
			 */
			break;
		}

		rspamd_log->enabled = FALSE;
		rspamd_log->opened = FALSE;
	}

	if (termination) {
		g_free (rspamd_log->log_file);
		rspamd_log->log_file = NULL;
		g_free (rspamd_log);
	}
}

gint
rspamd_log_reopen_priv (rspamd_logger_t *rspamd_log, uid_t uid, gid_t gid)
{
	if (rspamd_log->type == RSPAMD_LOG_FILE) {
		rspamd_log_flush (rspamd_log);
		rspamd_log_reset_repeated (rspamd_log);

		gint newfd = rspamd_try_open_log_fd (rspamd_log, uid, gid);

		if (newfd != -1) {
			rspamd_log_close_priv (rspamd_log, FALSE, uid, gid);
			rspamd_log->fd = newfd;

			rspamd_log->opened = TRUE;
			rspamd_log->enabled = TRUE;
		}

		/* Do nothing, use old settings */
	}
	else {
		/* Straightforward */
		rspamd_log_close_priv (rspamd_log, FALSE, uid, gid);

		if (rspamd_log_open_priv (rspamd_log, uid, gid) == 0) {
			return 0;
		}
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
rspamd_log_close (rspamd_logger_t *logger, gboolean termination)
{
	rspamd_log_close_priv (logger, termination, -1, -1);
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
		rspamd_logger_t **plogger,
		rspamd_mempool_t *pool)
{
	rspamd_logger_t *logger;

	if (plogger == NULL || *plogger == NULL) {
		logger = g_malloc0 (sizeof (rspamd_logger_t));
		logger->fd = -1;

		if (cfg->log_error_elts > 0 && pool) {
			logger->errlog = rspamd_mempool_alloc0_shared (pool,
					sizeof (*logger->errlog));
			logger->errlog->pool = pool;
			logger->errlog->max_elts = cfg->log_error_elts;
			logger->errlog->elt_len = cfg->log_error_elt_maxlen;
			logger->errlog->elts = rspamd_mempool_alloc0_shared (pool,
					sizeof (struct rspamd_logger_error_elt) * cfg->log_error_elts +
					cfg->log_error_elt_maxlen * cfg->log_error_elts);
		}

		if (pool) {
			logger->mtx = rspamd_mempool_get_mutex (pool);
		}

		if (plogger) {
			*plogger = logger;
		}
	}
	else {
		logger = *plogger;
	}

	logger->type = cfg->log_type;
	logger->pid = getpid ();
	logger->process_type = ptype;

	switch (cfg->log_type) {
		case RSPAMD_LOG_CONSOLE:
			logger->log_func = file_log_function;
			break;
		case RSPAMD_LOG_SYSLOG:
			logger->log_func = syslog_log_function;
			break;
		case RSPAMD_LOG_FILE:
			logger->log_func = file_log_function;
			break;
	}

	logger->log_type = cfg->log_type;
	logger->log_facility = cfg->log_facility;

	if (!(logger->flags & RSPAMD_LOG_FLAG_ENFORCED)) {
		logger->log_level = cfg->log_level;
	}

	logger->log_buffered = cfg->log_buffered;
	logger->log_silent_workers = cfg->log_silent_workers;
	logger->log_buf_size = cfg->log_buf_size;

	if (logger->log_file) {
		g_free (logger->log_file);
		logger->log_file = NULL;
	}
	if (cfg->log_file) {
		logger->log_file = g_strdup (cfg->log_file);
	}

	logger->flags = cfg->log_flags;


	/* Set up conditional logging */
	if (cfg->debug_ip_map != NULL) {
		/* Try to add it as map first of all */
		if (logger->debug_ip) {
			rspamd_map_helper_destroy_radix (logger->debug_ip);
		}

		logger->debug_ip = NULL;
		rspamd_config_radix_from_ucl (cfg,
				cfg->debug_ip_map,
				"IP addresses for which debug logs are enabled",
				&logger->debug_ip,
				NULL,
				NULL);
	}
	else if (logger->debug_ip) {
		rspamd_map_helper_destroy_radix (logger->debug_ip);
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
				FALSE, rspamd_log->log_level);
		rspamd_log->io_buf.used = 0;
	}
}

static inline gboolean
rspamd_logger_need_log (rspamd_logger_t *rspamd_log, GLogLevelFlags log_level,
		guint module_id)
{
	g_assert (rspamd_log != NULL);

	if ((log_level & RSPAMD_LOG_FORCED) ||
			(log_level & (RSPAMD_LOG_LEVEL_MASK & G_LOG_LEVEL_MASK)) <= rspamd_log->log_level) {
		return TRUE;
	}

	if (module_id != (guint)-1 && isset (log_modules->bitset, module_id)) {
		return TRUE;
	}

	return FALSE;
}

static gchar *
rspamd_log_encrypt_message (const gchar *begin, const gchar *end, gsize *enc_len,
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
	comp = rspamd_pubkey_get_nm (rspamd_log->pk, rspamd_log->keypair);
	g_assert (comp != NULL);
	rspamd_cryptobox_encrypt_nm_inplace (p, end - begin, nonce, comp, mac,
			RSPAMD_CRYPTOBOX_MODE_25519);
	b64 = rspamd_encode_base64 (out, inlen, 0, enc_len);
	g_free (out);

	return b64;
}

static void
rspamd_log_write_ringbuffer (rspamd_logger_t *rspamd_log,
		const gchar *module, const gchar *id,
		const gchar *data, glong len)
{
	guint32 row_num;
	struct rspamd_logger_error_log *elog;
	struct rspamd_logger_error_elt *elt;

	if (!rspamd_log->errlog) {
		return;
	}

	elog = rspamd_log->errlog;

	g_atomic_int_compare_and_exchange (&elog->cur_row, elog->max_elts, 0);
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	row_num = g_atomic_int_add (&elog->cur_row, 1);
#else
	row_num = g_atomic_int_exchange_and_add (&elog->cur_row, 1);
#endif

	if (row_num < elog->max_elts) {
		elt = (struct rspamd_logger_error_elt *)(((guchar *)elog->elts) +
				(sizeof (*elt) + elog->elt_len) * row_num);
		g_atomic_int_set (&elt->completed, 0);
	}
	else {
		/* Race condition */
		elog->cur_row = 0;
		return;
	}

	elt->pid = rspamd_log->pid;
	elt->ptype = rspamd_log->process_type;
	elt->ts = rspamd_get_calendar_ticks ();

	if (id) {
		rspamd_strlcpy (elt->id, id, sizeof (elt->id));
	}
	else {
		rspamd_strlcpy (elt->id, "", sizeof (elt->id));
	}

	if (module) {
		rspamd_strlcpy (elt->module, module, sizeof (elt->module));
	}
	else {
		rspamd_strlcpy (elt->module, "", sizeof (elt->module));
	}

	rspamd_strlcpy (elt->message, data, MIN (len + 1, elog->elt_len));
	g_atomic_int_set (&elt->completed, 1);
}

void
rspamd_common_logv (rspamd_logger_t *rspamd_log, gint level_flags,
		const gchar *module, const gchar *id, const gchar *function,
		const gchar *fmt, va_list args)
{
	gchar logbuf[RSPAMD_LOGBUF_SIZE], *end;
	gint level = level_flags & (RSPAMD_LOG_LEVEL_MASK & G_LOG_LEVEL_MASK), mod_id;

	if (G_UNLIKELY (rspamd_log == NULL)) {
		rspamd_log = default_logger;
	}

	if (G_UNLIKELY (rspamd_log == NULL)) {
		/* Just fprintf message to stderr */
		if (level >= G_LOG_LEVEL_INFO) {
			end = rspamd_vsnprintf (logbuf, sizeof (logbuf), fmt, args);
			rspamd_fprintf (stderr, "%*s\n", (gint)(end - logbuf), logbuf);
		}
	}
	else {
		if (level == G_LOG_LEVEL_DEBUG) {
			mod_id = rspamd_logger_add_debug_module (module);
		}
		else {
			mod_id = -1;
		}

		if (rspamd_logger_need_log (rspamd_log, level_flags, mod_id)) {
			end = rspamd_vsnprintf (logbuf, sizeof (logbuf), fmt, args);

			if ((level_flags & RSPAMD_LOG_ENCRYPTED) && rspamd_log->pk) {
				gchar *encrypted;
				gsize enc_len;

				encrypted = rspamd_log_encrypt_message (logbuf, end, &enc_len,
						rspamd_log);
				rspamd_log->log_func (module, id,
						function,
						level_flags,
						encrypted,
						enc_len,
						rspamd_log,
						rspamd_log->log_arg);
				g_free (encrypted);
			}
			else {
				rspamd_log->log_func (module, id,
						function,
						level_flags,
						logbuf,
						end - logbuf,
						rspamd_log,
						rspamd_log->log_arg);
			}

			switch (level) {
			case G_LOG_LEVEL_CRITICAL:
				rspamd_log->log_cnt[0] ++;
				rspamd_log_write_ringbuffer (rspamd_log, module, id, logbuf,
						end - logbuf);
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
 * Syslog interface for logging
 */
static void
syslog_log_function (const gchar *module, const gchar *id,
		const gchar *function,
		gint level_flags,
		const gchar *message,
		gsize mlen,
		rspamd_logger_t *rspamd_log,
		gpointer arg)
{
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

	if (!(level_flags & RSPAMD_LOG_FORCED) && !rspamd_log->enabled) {
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

	syslog (syslog_level, "<%.*s>; %s; %s: %*.s",
			LOG_ID, id != NULL ? id : "",
			module != NULL ? module : "",
			function != NULL ? function : "",
			(gint)mlen, message);
#endif
}

/**
 * Main file interface for logging
 */
/**
 * Write log line depending on ip
 */
void
rspamd_conditional_debug (rspamd_logger_t *rspamd_log,
		rspamd_inet_addr_t *addr, const gchar *module, const gchar *id,
		const gchar *function, const gchar *fmt, ...)
{
	static gchar logbuf[LOGBUF_LEN];
	va_list vp;
	gchar *end;
	guint mod_id;

	if (rspamd_log == NULL) {
		rspamd_log = default_logger;
	}

	mod_id = rspamd_logger_add_debug_module (module);

	if (rspamd_logger_need_log (rspamd_log, G_LOG_LEVEL_DEBUG, mod_id) ||
		rspamd_log->is_debug) {
		if (rspamd_log->debug_ip && addr != NULL) {
			if (rspamd_match_radix_map_addr (rspamd_log->debug_ip,
					addr) == NULL) {
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
				end - logbuf,
				rspamd_log,
				rspamd_log->log_arg);
	}
}

void
rspamd_conditional_debug_fast (rspamd_logger_t *rspamd_log,
		rspamd_inet_addr_t *addr,
		guint mod_id, const gchar *module, const gchar *id,
		const gchar *function, const gchar *fmt, ...)
{
	static gchar logbuf[LOGBUF_LEN];
	va_list vp;
	gchar *end;

	if (rspamd_log == NULL) {
		rspamd_log = default_logger;
	}

	if (rspamd_logger_need_log (rspamd_log, G_LOG_LEVEL_DEBUG, mod_id) ||
			rspamd_log->is_debug) {
		if (rspamd_log->debug_ip && addr != NULL) {
			if (rspamd_match_radix_map_addr (rspamd_log->debug_ip, addr)
					== NULL) {
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
				end - logbuf,
				rspamd_log,
				rspamd_log->log_arg);
	}
}

void
rspamd_conditional_debug_fast_num_id (rspamd_logger_t *rspamd_log,
							   rspamd_inet_addr_t *addr,
							   guint mod_id, const gchar *module, guint64 id,
							   const gchar *function, const gchar *fmt, ...)
{
	static gchar logbuf[LOGBUF_LEN], idbuf[64];
	va_list vp;
	gchar *end;

	if (rspamd_log == NULL) {
		rspamd_log = default_logger;
	}

	if (rspamd_logger_need_log (rspamd_log, G_LOG_LEVEL_DEBUG, mod_id) ||
		rspamd_log->is_debug) {
		if (rspamd_log->debug_ip && addr != NULL) {
			if (rspamd_match_radix_map_addr (rspamd_log->debug_ip, addr)
				== NULL) {
				return;
			}
		}

		rspamd_snprintf (idbuf, sizeof (idbuf), "%XuL", id);
		va_start (vp, fmt);
		end = rspamd_vsnprintf (logbuf, sizeof (logbuf), fmt, vp);
		*end = '\0';
		va_end (vp);
		rspamd_log->log_func (module, idbuf,
				function,
				G_LOG_LEVEL_DEBUG | RSPAMD_LOG_FORCED,
				logbuf,
				end - logbuf,
				rspamd_log,
				rspamd_log->log_arg);
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
	rspamd_logger_t *rspamd_log = (rspamd_logger_t *)arg;

	if (rspamd_log->enabled &&
			rspamd_logger_need_log (rspamd_log, log_level, -1)) {
		rspamd_log->log_func ("glib", NULL,
				NULL,
				log_level,
				message,
				strlen (message),
				rspamd_log,
				rspamd_log->log_arg);
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

static gint
rspamd_log_errlog_cmp (const ucl_object_t **o1, const ucl_object_t **o2)
{
	const ucl_object_t *ts1, *ts2;

	ts1 = ucl_object_lookup (*o1, "ts");
	ts2 = ucl_object_lookup (*o2, "ts");

	if (ts1 && ts2) {
		gdouble t1 = ucl_object_todouble (ts1), t2 = ucl_object_todouble (ts2);

		if (t1 > t2) {
			return -1;
		}
		else if (t2 > t1) {
			return 1;
		}
	}

	return 0;
}

ucl_object_t *
rspamd_log_errorbuf_export (const rspamd_logger_t *logger)
{
	struct rspamd_logger_error_elt *cpy, *cur;
	ucl_object_t *top = ucl_object_typed_new (UCL_ARRAY);
	guint i;

	if (logger->errlog == NULL) {
		return top;
	}

	cpy = g_malloc0_n (logger->errlog->max_elts,
			sizeof (*cpy) + logger->errlog->elt_len);
	memcpy (cpy, logger->errlog->elts, logger->errlog->max_elts *
			(sizeof (*cpy) + logger->errlog->elt_len));

	for (i = 0; i < logger->errlog->max_elts; i ++) {
		cur = (struct rspamd_logger_error_elt *)((guchar *)cpy +
				i * ((sizeof (*cpy) + logger->errlog->elt_len)));
		if (cur->completed) {
			ucl_object_t *obj = ucl_object_typed_new (UCL_OBJECT);

			ucl_object_insert_key (obj, ucl_object_fromdouble (cur->ts),
					"ts", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromint (cur->pid),
					"pid", 0, false);
			ucl_object_insert_key (obj,
					ucl_object_fromstring (g_quark_to_string (cur->ptype)),
					"type", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromstring (cur->id),
					"id", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromstring (cur->module),
					"module", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromstring (cur->message),
					"message", 0, false);

			ucl_array_append (top, obj);
		}
	}

	ucl_object_array_sort (top, rspamd_log_errlog_cmp);
	g_free (cpy);

	return top;
}

static guint
rspamd_logger_allocate_mod_bit (void)
{
	if (log_modules->bitset_allocated * NBBY > log_modules->bitset_len + 1) {
		log_modules->bitset_len ++;
		return log_modules->bitset_len - 1;
	}
	else {
		/* Need to expand */
		log_modules->bitset_allocated *= 2;
		log_modules->bitset = g_realloc (log_modules->bitset,
				log_modules->bitset_allocated);

		return rspamd_logger_allocate_mod_bit ();
	}
}

RSPAMD_DESTRUCTOR (rspamd_debug_modules_dtor)
{
	if (log_modules) {
		g_hash_table_unref (log_modules->modules);
		g_free (log_modules->bitset);
		g_free (log_modules);
	}
}

guint
rspamd_logger_add_debug_module (const gchar *mname)
{
	struct rspamd_log_module *m;

	if (mname == NULL) {
		return (guint)-1;
	}

	if (log_modules == NULL) {
		/*
		 * This is usually called from constructors, so we call init check
		 * each time to avoid dependency issues between ctors calls
		 */
		log_modules = g_malloc0 (sizeof (*log_modules));
		log_modules->modules = g_hash_table_new_full (rspamd_strcase_hash,
				rspamd_strcase_equal, g_free, g_free);
		log_modules->bitset_allocated = 16;
		log_modules->bitset_len = 0;
		log_modules->bitset = g_malloc0 (log_modules->bitset_allocated);
	}

	if ((m = g_hash_table_lookup (log_modules->modules, mname)) == NULL) {
		m = g_malloc0 (sizeof (*m));
		m->mname = g_strdup (mname);
		m->id = rspamd_logger_allocate_mod_bit ();
		clrbit (log_modules->bitset, m->id);
		g_hash_table_insert (log_modules->modules, m->mname, m);
	}

	return m->id;
}

void
rspamd_logger_configure_modules (GHashTable *mods_enabled)
{
	GHashTableIter it;
	gpointer k, v;
	guint id;

	/* On first iteration, we go through all modules enabled and add missing ones */
	g_hash_table_iter_init (&it, mods_enabled);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		rspamd_logger_add_debug_module ((const gchar *)k);
	}

	g_hash_table_iter_init (&it, mods_enabled);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		id = rspamd_logger_add_debug_module ((const gchar *)k);

		if (isclr (log_modules->bitset, id)) {
			msg_info ("enable debugging for module %s (%d)", (const gchar *) k,
					id);
			setbit (log_modules->bitset, id);
		}
	}
}

rspamd_logger_t*
rspamd_logger_get_singleton (void)
{
	return default_logger;
}

struct rspamd_logger_funcs*
rspamd_logger_set_log_function (rspamd_logger_t *logger,
								struct rspamd_logger_funcs *nfuncs);
{
	if (logger == NULL) {
		logger = default_logger;
	}

	g_assert (logger != NULL);

	rspamd_log_func_t old_func = logger->log_func;

	logger->log_func = nfunc;
	logger->log_arg = narg;

	return old_func;
}