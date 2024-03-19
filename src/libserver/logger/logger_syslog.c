/*
 * Copyright 2024 Vsevolod Stakhov
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
#include "logger_private.h"

#define SYSLOG_LOG_QUARK g_quark_from_static_string("syslog_logger")

struct rspamd_syslog_logger_priv {
	int log_facility;
};

#ifdef HAVE_SYSLOG_H
#include <syslog.h>

void *
rspamd_log_syslog_init(rspamd_logger_t *logger, struct rspamd_config *cfg,
					   uid_t uid, gid_t gid, GError **err)
{
	struct rspamd_syslog_logger_priv *priv;

	if (!cfg) {
		g_set_error(err, SYSLOG_LOG_QUARK, EINVAL,
					"no log config specified");
		return NULL;
	}

	priv = g_malloc0(sizeof(*priv));

	priv->log_facility = cfg->log_facility;
	openlog("rspamd", LOG_CONS | LOG_NDELAY | LOG_PID, priv->log_facility);

	return priv;
}

void rspamd_log_syslog_dtor(rspamd_logger_t *logger, gpointer arg)
{
	struct rspamd_syslog_logger_priv *priv = (struct rspamd_syslog_logger_priv *) arg;

	closelog();
	g_free(priv);
}
bool rspamd_log_syslog_log(const char *module, const char *id,
						   const char *function,
						   int level_flags,
						   const char *message,
						   gsize mlen,
						   rspamd_logger_t *rspamd_log,
						   gpointer arg)
{
	static const struct {
		GLogLevelFlags glib_level;
		int syslog_level;
	} levels_match[] = {
		{G_LOG_LEVEL_DEBUG, LOG_DEBUG},
		{G_LOG_LEVEL_INFO, LOG_INFO},
		{G_LOG_LEVEL_WARNING, LOG_WARNING},
		{G_LOG_LEVEL_CRITICAL, LOG_ERR}};
	unsigned i;
	int syslog_level;

	if (!(level_flags & RSPAMD_LOG_FORCED) && !rspamd_log->enabled) {
		return false;
	}

	/* Detect level */
	syslog_level = LOG_DEBUG;

	for (i = 0; i < G_N_ELEMENTS(levels_match); i++) {
		if (level_flags & levels_match[i].glib_level) {
			syslog_level = levels_match[i].syslog_level;
			break;
		}
	}

	bool log_json = (rspamd_log->flags & RSPAMD_LOG_FLAG_JSON);

	/* Ensure safety as %.*s is used */
	char idbuf[RSPAMD_LOG_ID_LEN + 1];

	if (id != NULL) {
		rspamd_strlcpy(idbuf, id, RSPAMD_LOG_ID_LEN + 1);
	}
	else {
		idbuf[0] = '\0';
	}

	if (log_json) {
		long now = rspamd_get_calendar_ticks();
		if (rspamd_memcspn(message, "\"\\\r\n\b\t\v", mlen) == mlen) {
			/* Fast path */
			syslog(syslog_level, "{\"ts\": %ld, "
								 "\"pid\": %d, "
								 "\"severity\": \"%s\", "
								 "\"worker_type\": \"%s\", "
								 "\"id\": \"%s\", "
								 "\"module\": \"%s\", "
								 "\"function\": \"%s\", "
								 "\"message\": \"%.*s\"}",
				   now,
				   (int) rspamd_log->pid,
				   rspamd_get_log_severity_string(level_flags),
				   rspamd_log->process_type,
				   idbuf,
				   module != NULL ? module : "",
				   function != NULL ? function : "",
				   (int) mlen, message);
		}
		else {
			/* Escaped version */
			/* We need to do JSON escaping of the quotes */
			const char *p, *end = message + mlen;
			long escaped_len;

			for (p = message, escaped_len = 0; p < end; p++, escaped_len++) {
				switch (*p) {
				case '\v':
				case '\0':
					escaped_len += 5;
					break;
				case '\\':
				case '"':
				case '\n':
				case '\r':
				case '\b':
				case '\t':
					escaped_len++;
					break;
				default:
					break;
				}
			}


			char *dst = g_malloc(escaped_len + 1);
			char *d;

			for (p = message, d = dst; p < end; p++, d++) {
				switch (*p) {
				case '\n':
					*d++ = '\\';
					*d = 'n';
					break;
				case '\r':
					*d++ = '\\';
					*d = 'r';
					break;
				case '\b':
					*d++ = '\\';
					*d = 'b';
					break;
				case '\t':
					*d++ = '\\';
					*d = 't';
					break;
				case '\f':
					*d++ = '\\';
					*d = 'f';
					break;
				case '\0':
					*d++ = '\\';
					*d++ = 'u';
					*d++ = '0';
					*d++ = '0';
					*d++ = '0';
					*d = '0';
					break;
				case '\v':
					*d++ = '\\';
					*d++ = 'u';
					*d++ = '0';
					*d++ = '0';
					*d++ = '0';
					*d = 'B';
					break;
				case '\\':
					*d++ = '\\';
					*d = '\\';
					break;
				case '"':
					*d++ = '\\';
					*d = '"';
					break;
				default:
					*d = *p;
					break;
				}
			}

			*d = '\0';

			syslog(syslog_level, "{\"ts\": %ld, "
								 "\"pid\": %d, "
								 "\"severity\": \"%s\", "
								 "\"worker_type\": \"%s\", "
								 "\"id\": \"%s\", "
								 "\"module\": \"%s\", "
								 "\"function\": \"%s\", "
								 "\"message\": \"%s\"}",
				   now,
				   (int) rspamd_log->pid,
				   rspamd_get_log_severity_string(level_flags),
				   rspamd_log->process_type,
				   idbuf,
				   module != NULL ? module : "",
				   function != NULL ? function : "",
				   dst);
			g_free(dst);
		}
	}
	else {
		syslog(syslog_level, "<%s>; %s; %s: %.*s",
			   idbuf,
			   module != NULL ? module : "",
			   function != NULL ? function : "",
			   (int) mlen, message);
	}

	return true;
}

#else

void *
rspamd_log_syslog_init(rspamd_logger_t *logger, struct rspamd_config *cfg,
					   uid_t uid, gid_t gid, GError **err)
{
	g_set_error(err, SYSLOG_LOG_QUARK, EINVAL, "syslog support is not compiled in");

	return NULL;
}

bool rspamd_log_syslog_log(const char *module, const char *id,
						   const char *function,
						   int level_flags,
						   const char *message,
						   gsize mlen,
						   rspamd_logger_t *rspamd_log,
						   gpointer arg)
{
	return false;
}

void rspamd_log_syslog_dtor(rspamd_logger_t *logger, gpointer arg)
{
	/* Left blank intentionally */
}

#endif

void *
rspamd_log_syslog_reload(rspamd_logger_t *logger, struct rspamd_config *cfg,
						 gpointer arg, uid_t uid, gid_t gid, GError **err)
{
	struct rspamd_syslog_logger_priv *npriv;

	npriv = rspamd_log_syslog_init(logger, cfg, uid, gid, err);

	if (npriv) {
		/* Close old */
		rspamd_log_syslog_dtor(logger, arg);
	}

	return npriv;
}
