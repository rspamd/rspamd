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
#include "logger_private.h"

#define SYSLOG_LOG_QUARK g_quark_from_static_string ("syslog_logger")

struct rspamd_syslog_logger_priv {
	gint log_facility;
};

#ifdef HAVE_SYSLOG_H
#include <syslog.h>

void *
rspamd_log_syslog_init (rspamd_logger_t *logger, struct rspamd_config *cfg,
							   uid_t uid, gid_t gid, GError **err)
{
	struct rspamd_syslog_logger_priv *priv;

	if (!cfg) {
		g_set_error (err, SYSLOG_LOG_QUARK, EINVAL,
				"no log config specified");
		return NULL;
	}

	priv = g_malloc0 (sizeof (*priv));

	priv->log_facility = cfg->log_facility;
	openlog ("rspamd", LOG_NDELAY | LOG_PID, priv->log_facility);

	return priv;
}

void
rspamd_log_syslog_dtor (rspamd_logger_t *logger, gpointer arg)
{
	struct rspamd_syslog_logger_priv *priv = (struct rspamd_syslog_logger_priv *)arg;

	closelog ();
	g_free (priv);
}
bool
rspamd_log_syslog_log (const gchar *module, const gchar *id,
							const gchar *function,
							gint level_flags,
							const gchar *message,
							gsize mlen,
							rspamd_logger_t *rspamd_log,
							gpointer arg)
{
	static const struct {
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
		return false;
	}

	/* Detect level */
	syslog_level = LOG_DEBUG;

	for (i = 0; i < G_N_ELEMENTS (levels_match); i ++) {
		if (level_flags & levels_match[i].glib_level) {
			syslog_level = levels_match[i].syslog_level;
			break;
		}
	}

	syslog (syslog_level, "<%.*s>; %s; %s: %.*s",
			RSPAMD_LOG_ID_LEN, id != NULL ? id : "",
			module != NULL ? module : "",
			function != NULL ? function : "",
			(gint)mlen, message);

	return true;
}

#else

void *
rspamd_log_syslog_init (rspamd_logger_t *logger, struct rspamd_config *cfg,
							   uid_t uid, gid_t gid, GError **err)
{
	g_set_error (err, SYSLOG_LOG_QUARK, EINVAL, "syslog support is not compiled in");

	return NULL;
}

bool
rspamd_log_syslog_log (const gchar *module, const gchar *id,
							const gchar *function,
							gint level_flags,
							const gchar *message,
							gsize mlen,
							rspamd_logger_t *rspamd_log,
							gpointer arg)
{
	return false;
}

void
rspamd_log_syslog_dtor (rspamd_logger_t *logger, gpointer arg)
{
	/* Left blank intentionally */
}

#endif

void *
rspamd_log_syslog_reload (rspamd_logger_t *logger, struct rspamd_config *cfg,
						  gpointer arg, uid_t uid, gid_t gid, GError **err)
{
	struct rspamd_syslog_logger_priv *npriv;

	npriv = rspamd_log_syslog_init (logger, cfg, uid, gid, err);

	if (npriv) {
		/* Close old */
		rspamd_log_syslog_dtor (logger, arg);
	}

	return npriv;
}
