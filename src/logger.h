#ifndef RSPAMD_LOGGER_H
#define RSPAMD_LOGGER_H

#include "config.h"
#include "cfg_file.h"
#include "radix.h"
#include "util.h"

/** 
 * Process type: main or worker
 */
enum process_type {
	TYPE_MAIN,
	TYPE_WORKER,
	TYPE_CONTROLLER,
	TYPE_LMTP,
	TYPE_SMTP,
	TYPE_FUZZY,
	TYPE_GREYLIST
};

typedef void (*rspamd_log_func_t)(const gchar * log_domain, const gchar *function,
								  GLogLevelFlags log_level, const gchar * message, 
								  gboolean forced, gpointer arg);

/**
 * Init logger
 */
void rspamd_set_logger (enum rspamd_log_type type, enum process_type ptype, struct config_file *cfg);
/**
 * Open log file or initialize other structures
 */
gint open_log (void);
/**
 * Close log file or destroy other structures
 */
void close_log (void);
/**
 * Close and open log again
 */
gint reopen_log (void);
/**
 * Set log pid
 */
void update_log_pid (enum process_type ptype);

/**
 * Flush log buffer for some types of logging
 */
void flush_log_buf (void);
/**
 * Log function that is compatible for glib messages
 */
void rspamd_glib_log_function (const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer arg);

/**
 * Function with variable number of arguments support 
 */
void rspamd_common_log_function (GLogLevelFlags log_level, const gchar *function, const gchar *fmt, ...);

/**
 * Conditional debug function
 */
void rspamd_conditional_debug (guint32 addr, const gchar *function, const gchar *fmt, ...) ;

/**
 * Temporary turn on debug
 */
void rspamd_log_debug ();

/**
 * Turn off debug
 */
void rspamd_log_nodebug ();

/* Typical functions */

/* Logging in postfix style */
#if (defined(RSPAMD_MAIN) || defined(RSPAMD_LIB) || defined(RSPAMD_TEST))
#define msg_err(...)	rspamd_common_log_function(G_LOG_LEVEL_CRITICAL, __FUNCTION__, __VA_ARGS__)
#define msg_warn(...)	rspamd_common_log_function(G_LOG_LEVEL_WARNING, __FUNCTION__, __VA_ARGS__)
#define msg_info(...)	rspamd_common_log_function(G_LOG_LEVEL_INFO, __FUNCTION__, __VA_ARGS__)
#define msg_debug(...)	rspamd_conditional_debug(-1, __FUNCTION__, __VA_ARGS__)
#define debug_task(...) rspamd_conditional_debug(task->from_addr.s_addr, __FUNCTION__, __VA_ARGS__)

#else
#define msg_err(...)	rspamd_fprintf(stderr, __VA_ARGS__)
#define msg_warn(...)	rspamd_fprintf(stderr, __VA_ARGS__)
#define msg_info(...)	rspamd_fprintf(stderr, __VA_ARGS__)
#define msg_debug(...)	rspamd_fprintf(stderr, __VA_ARGS__)
#define debug_task(...) rspamd_fprintf(stderr, __VA_ARGS__)
#endif

#endif
