#ifndef RSPAMD_LOGGER_H
#define RSPAMD_LOGGER_H

#include "config.h"
#include "cfg_file.h"
#include "radix.h"
#include "util.h"


typedef void (*rspamd_log_func_t)(const gchar * log_domain,
	const gchar *function,
	GLogLevelFlags log_level, const gchar * message,
	gboolean forced, gpointer arg);

typedef struct rspamd_logger_s rspamd_logger_t;
/**
 * Init logger
 */
void rspamd_set_logger (struct rspamd_config *cfg,
	GQuark ptype,
	struct rspamd_main *main);
/**
 * Open log file or initialize other structures
 */
gint rspamd_log_open (rspamd_logger_t *logger);
/**
 * Close log file or destroy other structures
 */
void rspamd_log_close (rspamd_logger_t *logger);
/**
 * Close and open log again
 */
gint rspamd_log_reopen (rspamd_logger_t *logger);

/**
 * Open log file or initialize other structures for privileged processes
 */
gint rspamd_log_open_priv (rspamd_logger_t *logger, uid_t uid, gid_t gid);
/**
 * Close log file or destroy other structures for privileged processes
 */
void rspamd_log_close_priv (rspamd_logger_t *logger, uid_t uid, gid_t gid);
/**
 * Close and open log again for privileged processes
 */
gint rspamd_log_reopen_priv (rspamd_logger_t *logger, uid_t uid, gid_t gid);

/**
 * Set log pid
 */
void rspamd_log_update_pid (GQuark ptype, rspamd_logger_t *logger);

/**
 * Flush log buffer for some types of logging
 */
void rspamd_log_flush (rspamd_logger_t *logger);
/**
 * Log function that is compatible for glib messages
 */
void rspamd_glib_log_function (const gchar *log_domain,
	GLogLevelFlags log_level, const gchar *message, gpointer arg);

/**
 * Function with variable number of arguments support
 */
void rspamd_common_log_function (rspamd_logger_t *logger,
	GLogLevelFlags log_level, const gchar *function, const gchar *fmt, ...);

void rspamd_common_logv (rspamd_logger_t *logger,
	GLogLevelFlags log_level,
	const gchar *function,
	const gchar *fmt,
	va_list args);

/**
 * Conditional debug function
 */
void rspamd_conditional_debug (rspamd_logger_t *logger,
	rspamd_inet_addr_t *addr, const gchar *function, const gchar *fmt, ...);

/**
 * Function with variable number of arguments support that uses static default logger
 */
void rspamd_default_log_function (GLogLevelFlags log_level,
	const gchar *function,
	const gchar *fmt,
	...);

/**
 * Varargs version of default log function
 * @param log_level
 * @param function
 * @param fmt
 * @param args
 */
void rspamd_default_logv (GLogLevelFlags log_level,
	const gchar *function,
	const gchar *fmt,
	va_list args);

/**
 * Temporary turn on debug
 */
void rspamd_log_debug (rspamd_logger_t *logger);

/**
 * Turn off debug
 */
void rspamd_log_nodebug (rspamd_logger_t *logger);

/* Typical functions */

/* Logging in postfix style */
#if defined(RSPAMD_MAIN)
#define msg_err(...)    rspamd_common_log_function (rspamd_main->logger, \
		G_LOG_LEVEL_CRITICAL, \
		G_STRFUNC, \
		__VA_ARGS__)
#define msg_warn(...)   rspamd_common_log_function (rspamd_main->logger, \
		G_LOG_LEVEL_WARNING, \
		G_STRFUNC, \
		__VA_ARGS__)
#define msg_info(...)   rspamd_common_log_function (rspamd_main->logger, \
		G_LOG_LEVEL_INFO, \
		G_STRFUNC, \
		__VA_ARGS__)
#define msg_debug(...)  rspamd_conditional_debug (rspamd_main->logger, \
		NULL, \
		G_STRFUNC, \
		__VA_ARGS__)
#define debug_task(...) rspamd_conditional_debug (rspamd_main->logger, \
		task->from_addr, \
		G_STRFUNC, \
		__VA_ARGS__)
#else
#define msg_err(...)    rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
		G_STRFUNC, \
		__VA_ARGS__)
#define msg_warn(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
		G_STRFUNC, \
		__VA_ARGS__)
#define msg_info(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
		G_STRFUNC, \
		__VA_ARGS__)
#define msg_debug(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
		G_STRFUNC, \
		__VA_ARGS__)
#define debug_task(...) rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
		G_STRFUNC, \
		__VA_ARGS__)
#endif

#endif
