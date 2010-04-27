#ifndef RSPAMD_LOGGER_H
#define RSPAMD_LOGGER_H

#include "config.h"
#include "cfg_file.h"
#include "radix.h"

/* Forwarded declaration */
enum process_type;

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
int open_log (void);
/**
 * Close log file or destroy other structures
 */
void close_log (void);
/**
 * Close and open log again
 */
int reopen_log (void);
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
void rspamd_common_log_function (GLogLevelFlags log_level, const char *function, const char *fmt, ...);

/**
 * Conditional debug function
 */
void rspamd_conditional_debug (uint32_t addr, const char *function, const char *fmt, ...) ;


/* Typical functions */

/* Logging in postfix style */
#if (defined(RSPAMD_MAIN) || defined(RSPAMD_LIB))
#define msg_err(args...)	rspamd_common_log_function(G_LOG_LEVEL_CRITICAL, __FUNCTION__, ##args)
#define msg_warn(args...)	rspamd_common_log_function(G_LOG_LEVEL_WARNING, __FUNCTION__, ##args)
#define msg_info(args...)	rspamd_common_log_function(G_LOG_LEVEL_INFO, __FUNCTION__, ##args)
#define msg_debug(args...)	rspamd_common_log_function(G_LOG_LEVEL_DEBUG, __FUNCTION__, ##args)
#define debug_task(args...) rspamd_conditional_debug(task->from_addr.s_addr, __FUNCTION__, ##args)
#define debug_ip(ip, args...) rspamd_conditional_debug((ip), __FUNCTION__, ##args)
#else
#define msg_err(args...)	fprintf(stderr, ##args)
#define msg_warn(args...)	fprintf(stderr, ##args)
#define msg_info(args...)	fprintf(stderr, ##args)
#define msg_debug(args...)	fprintf(stderr, ##args)
#define debug_task(args...) fprintf(stderr, ##args)
#endif

#endif
