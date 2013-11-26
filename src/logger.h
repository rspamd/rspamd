#ifndef RSPAMD_LOGGER_H
#define RSPAMD_LOGGER_H

#include "config.h"
#include "cfg_file.h"
#include "radix.h"
#include "util.h"


typedef void (*rspamd_log_func_t)(const gchar * log_domain, const gchar *function,
								  GLogLevelFlags log_level, const gchar * message, 
								  gboolean forced, gpointer arg);

typedef struct rspamd_logger_s rspamd_logger_t;
/**
 * Init logger
 */
void rspamd_set_logger (enum rspamd_log_type type, GQuark ptype, struct rspamd_main *main);
/**
 * Open log file or initialize other structures
 */
gint open_log (rspamd_logger_t *logger);
/**
 * Close log file or destroy other structures
 */
void close_log (rspamd_logger_t *logger);
/**
 * Close and open log again
 */
gint reopen_log (rspamd_logger_t *logger);

/**
 * Open log file or initialize other structures for privileged processes
 */
gint open_log_priv (rspamd_logger_t *logger, uid_t uid, gid_t gid);
/**
 * Close log file or destroy other structures for privileged processes
 */
void close_log_priv (rspamd_logger_t *logger, uid_t uid, gid_t gid);
/**
 * Close and open log again for privileged processes
 */
gint reopen_log_priv (rspamd_logger_t *logger, uid_t uid, gid_t gid);

/**
 * Set log pid
 */
void update_log_pid (GQuark ptype, rspamd_logger_t *logger);

/**
 * Flush log buffer for some types of logging
 */
void flush_log_buf (rspamd_logger_t *logger);
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

/**
 * Conditional debug function
 */
void rspamd_conditional_debug (rspamd_logger_t *logger,
		guint32 addr, const gchar *function, const gchar *fmt, ...) ;

/**
 * Function with variable number of arguments support that uses static default logger
 */
void rspamd_default_log_function (GLogLevelFlags log_level, const gchar *function,
		const gchar *fmt, ...);

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
#define msg_err(...)	rspamd_common_log_function(rspamd_main->logger, G_LOG_LEVEL_CRITICAL, __FUNCTION__, __VA_ARGS__)
#define msg_warn(...)	rspamd_common_log_function(rspamd_main->logger, G_LOG_LEVEL_WARNING, __FUNCTION__, __VA_ARGS__)
#define msg_info(...)	rspamd_common_log_function(rspamd_main->logger, G_LOG_LEVEL_INFO, __FUNCTION__, __VA_ARGS__)
#define msg_debug(...)	rspamd_conditional_debug(rspamd_main->logger, -1, __FUNCTION__, __VA_ARGS__)
#ifdef HAVE_INET_PTON
# define debug_task(...) rspamd_conditional_debug(rspamd_main->logger, task->from_addr.d.in4.s_addr, __FUNCTION__, __VA_ARGS__)
#else
# define debug_task(...) rspamd_conditional_debug(rspamd_main->logger, task->from_addr.s_addr, __FUNCTION__, __VA_ARGS__)
#endif
#else
#define msg_err(...)	rspamd_default_log_function(G_LOG_LEVEL_CRITICAL, __FUNCTION__, __VA_ARGS__)
#define msg_warn(...)	rspamd_default_log_function(G_LOG_LEVEL_WARNING, __FUNCTION__, __VA_ARGS__)
#define msg_info(...)	rspamd_default_log_function(G_LOG_LEVEL_INFO, __FUNCTION__, __VA_ARGS__)
#define msg_debug(...)	rspamd_default_log_function(G_LOG_LEVEL_DEBUG, __FUNCTION__, __VA_ARGS__)
#define debug_task(...) do {} while(0)
#endif

#endif
