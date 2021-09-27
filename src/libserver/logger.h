#ifndef RSPAMD_LOGGER_H
#define RSPAMD_LOGGER_H

#include "config.h"
#include "radix.h"
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef G_LOG_LEVEL_USER_SHIFT
#define G_LOG_LEVEL_USER_SHIFT 8
#endif

#define RSPAMD_LOG_ID_LEN 6

struct rspamd_config;

enum rspamd_log_flags {
	RSPAMD_LOG_FORCED = (1 << G_LOG_LEVEL_USER_SHIFT),
	RSPAMD_LOG_ENCRYPTED = (1 << (G_LOG_LEVEL_USER_SHIFT + 1)),
	RSPAMD_LOG_LEVEL_MASK = ~(RSPAMD_LOG_FORCED | RSPAMD_LOG_ENCRYPTED)
};

typedef struct rspamd_logger_s rspamd_logger_t;
typedef bool (*rspamd_log_func_t) (const gchar *module, const gchar *id,
								   const gchar *function,
								   gint level_flags,
								   const gchar *message,
								   gsize mlen,
								   rspamd_logger_t *logger,
								   gpointer arg);
typedef void * (*rspamd_log_init_func) (rspamd_logger_t *logger,
										struct rspamd_config *cfg,
										uid_t uid, gid_t gid,
										GError **err);
typedef bool (*rspamd_log_on_fork_func) (rspamd_logger_t *logger,
										 struct rspamd_config *cfg,
										 gpointer arg,
										 GError **err);
typedef void* (*rspamd_log_reload_func) (rspamd_logger_t *logger,
										struct rspamd_config *cfg,
										gpointer arg,
										uid_t uid, gid_t gid,
										GError **err);
typedef void (*rspamd_log_dtor_func) (rspamd_logger_t *logger,
										gpointer arg);

struct rspamd_logger_funcs {
	rspamd_log_init_func init;
	rspamd_log_reload_func reload;
	rspamd_log_dtor_func dtor;
	rspamd_log_func_t log;
	rspamd_log_on_fork_func on_fork;
	gpointer specific;
};

#if defined(__x86_64) || defined(__x86_64__) || defined(__amd64) || defined(_M_X64)
#define RSPAMD_LOGBUF_SIZE 8192
#else
/* Use a smaller buffer */
#define RSPAMD_LOGBUF_SIZE 2048
#endif

/**
 * Opens a new (initial) logger with console type
 * This logger is also used as an emergency logger
 * @return new rspamd logger object
 */
rspamd_logger_t * rspamd_log_open_emergency (rspamd_mempool_t *pool, gint flags);

/**
 * Open specific (configured logging)
 * @param pool
 * @param config
 * @param uid
 * @param gid
 * @return
 */
rspamd_logger_t * rspamd_log_open_specific (rspamd_mempool_t *pool,
											struct rspamd_config *config,
											const gchar *ptype,
											uid_t uid, gid_t gid);

/**
 * Set log level (from GLogLevelFlags)
 * @param logger
 * @param level
 */
void rspamd_log_set_log_level (rspamd_logger_t *logger, gint level);
gint rspamd_log_get_log_level (rspamd_logger_t *logger);
const gchar *rspamd_get_log_severity_string(gint level_flags);
/**
 * Set log flags (from enum rspamd_log_flags)
 * @param logger
 * @param flags
 */
void rspamd_log_set_log_flags (rspamd_logger_t *logger, gint flags);

/**
 * Close log file or destroy other structures
 */
void rspamd_log_close (rspamd_logger_t *logger);



rspamd_logger_t * rspamd_log_default_logger (void);
rspamd_logger_t * rspamd_log_emergency_logger (void);

/**
 * Close and open log again for privileged processes
 */
bool rspamd_log_reopen (rspamd_logger_t *logger, struct rspamd_config *cfg,
						uid_t uid, gid_t gid);

/**
 * Set log pid
 */
void rspamd_log_on_fork (GQuark ptype, struct rspamd_config *cfg,
						 rspamd_logger_t *logger);

/**
 * Log function that is compatible for glib messages
 */
void rspamd_glib_log_function (const gchar *log_domain,
							   GLogLevelFlags log_level,
							   const gchar *message,
							   gpointer arg);

/**
 * Log function for printing glib assertions
 */
void rspamd_glib_printerr_function (const gchar *message);

/**
 * Function with variable number of arguments support
 */
bool rspamd_common_log_function (rspamd_logger_t *logger,
								 gint level_flags,
								 const gchar *module, const gchar *id,
								 const gchar *function, const gchar *fmt, ...);

bool rspamd_common_logv (rspamd_logger_t *logger, gint level_flags,
						 const gchar *module, const gchar *id, const gchar *function,
						 const gchar *fmt, va_list args);

/**
 * Add new logging module, returns module ID
 * @param mod
 * @return
 */
gint rspamd_logger_add_debug_module (const gchar *mod);

/*
 * Macro to use for faster debug modules
 */
#define INIT_LOG_MODULE(mname) \
    static gint rspamd_##mname##_log_id = -1; \
    RSPAMD_CONSTRUCTOR(rspamd_##mname##_log_init) { \
        rspamd_##mname##_log_id = rspamd_logger_add_debug_module(#mname); \
}


#define INIT_LOG_MODULE_PUBLIC(mname) \
    gint rspamd_##mname##_log_id = -1; \
    RSPAMD_CONSTRUCTOR(rspamd_##mname##_log_init) { \
        rspamd_##mname##_log_id = rspamd_logger_add_debug_module(#mname); \
}

void rspamd_logger_configure_modules (GHashTable *mods_enabled);

/**
 * Conditional debug function
 */
bool rspamd_conditional_debug (rspamd_logger_t *logger,
							   rspamd_inet_addr_t *addr, const gchar *module, const gchar *id,
							   const gchar *function, const gchar *fmt, ...);

bool rspamd_conditional_debug_fast (rspamd_logger_t *logger,
									rspamd_inet_addr_t *addr,
									gint mod_id,
									const gchar *module, const gchar *id,
									const gchar *function, const gchar *fmt, ...);
bool rspamd_conditional_debug_fast_num_id (rspamd_logger_t *logger,
									rspamd_inet_addr_t *addr,
									gint mod_id,
									const gchar *module, guint64 id,
									const gchar *function, const gchar *fmt, ...);
gboolean rspamd_logger_need_log (rspamd_logger_t *rspamd_log,
								 GLogLevelFlags log_level,
								 gint module_id);

/**
 * Function with variable number of arguments support that uses static default logger
 */
bool rspamd_default_log_function (gint level_flags,
								  const gchar *module, const gchar *id,
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
bool rspamd_default_logv (gint level_flags,
						  const gchar *module, const gchar *id,
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

/**
 * Return array of counters (4 numbers):
 * 0 - errors
 * 1 - warnings
 * 2 - info messages
 * 3 - debug messages
 */
const guint64 *rspamd_log_counters (rspamd_logger_t *logger);

/**
 * Returns errors ring buffer as ucl array
 * @param logger
 * @return
 */
ucl_object_t *rspamd_log_errorbuf_export (const rspamd_logger_t *logger);

/**
 * Sets new logger functions and initialise logging if needed
 * @param logger
 * @param nfuncs
 * @return static pointer to the old functions (so this function is not reentrant)
 */
struct rspamd_logger_funcs* rspamd_logger_set_log_function (rspamd_logger_t *logger,
															struct rspamd_logger_funcs *nfuncs);

/* Typical functions */

extern guint rspamd_task_log_id;
#ifdef __cplusplus
#define RSPAMD_LOG_FUNC __FUNCTION__
#else
#define RSPAMD_LOG_FUNC G_STRFUNC
#endif

/* Logging in postfix style */
#define msg_err(...)    rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        NULL, NULL, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_warn(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        NULL, NULL, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_info(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        NULL, NULL, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_notice(...)   rspamd_default_log_function (G_LOG_LEVEL_MESSAGE, \
        NULL, NULL, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_debug(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
        NULL, NULL, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)

#define debug_task(...) rspamd_conditional_debug_fast (NULL, \
        task->from_addr, \
        rspamd_task_log_id, "task", task->task_pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)

/* Use the following macros if you have `task` in the function */
#define msg_err_task(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        task->task_pool->tag.tagname, task->task_pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_warn_task(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        task->task_pool->tag.tagname, task->task_pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_notice_task(...)   rspamd_default_log_function (G_LOG_LEVEL_MESSAGE, \
        task->task_pool->tag.tagname, task->task_pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_info_task(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        task->task_pool->tag.tagname, task->task_pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_debug_task(...)  rspamd_conditional_debug_fast (NULL,  task->from_addr, \
        rspamd_task_log_id, "task", task->task_pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_err_task_encrypted(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL|RSPAMD_LOG_ENCRYPTED, \
        task->task_pool->tag.tagname, task->task_pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_warn_task_encrypted(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING|RSPAMD_LOG_ENCRYPTED, \
        task->task_pool->tag.tagname, task->task_pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_notice_task_encrypted(...) rspamd_default_log_function (G_LOG_LEVEL_MESSAGE|RSPAMD_LOG_ENCRYPTED, \
        task->task_pool->tag.tagname, task->task_pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_info_task_encrypted(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO|RSPAMD_LOG_ENCRYPTED, \
        task->task_pool->tag.tagname, task->task_pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
/* Check for NULL pointer first */
#define msg_err_task_check(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        task ? task->task_pool->tag.tagname : NULL, task ? task->task_pool->tag.uid : NULL, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_warn_task_check(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        task ? task->task_pool->tag.tagname : NULL, task ? task->task_pool->tag.uid : NULL, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_info_task_check(...)   rspamd_default_log_function (G_LOG_LEVEL_MESSAGE, \
        task ? task->task_pool->tag.tagname : NULL, task ? task->task_pool->tag.uid : NULL, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_notice_task_check(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        task ? task->task_pool->tag.tagname : NULL, task ? task->task_pool->tag.uid : NULL, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_debug_task_check(...)  rspamd_conditional_debug_fast (NULL, \
        task ? task->from_addr : NULL, \
        rspamd_task_log_id, "task", task ? task->task_pool->tag.uid : NULL, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)

/* Use the following macros if you have `pool` in the function */
#define msg_err_pool(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        pool->tag.tagname, pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_warn_pool(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        pool->tag.tagname, pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_info_pool(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        pool->tag.tagname, pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_debug_pool(...)  rspamd_conditional_debug (NULL, NULL, \
        pool->tag.tagname, pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
/* Check for NULL pointer first */
#define msg_err_pool_check(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        pool ? pool->tag.tagname : NULL, pool ? pool->tag.uid : NULL, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_warn_pool_check(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        pool ? pool->tag.tagname : NULL, pool ? pool->tag.uid : NULL, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_info_pool_check(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        pool ? pool->tag.tagname : NULL, pool ? pool->tag.uid : NULL, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_debug_pool_check(...)  rspamd_conditional_debug (NULL, NULL, \
        pool ? pool->tag.tagname : NULL, pool ? pool->tag.uid : NULL, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)

#ifdef  __cplusplus
}
#endif

#endif
