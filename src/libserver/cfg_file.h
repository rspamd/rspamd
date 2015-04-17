/**
 * @file cfg_file.h
 * Config file parser and config routines API
 */

#ifndef CFG_FILE_H
#define CFG_FILE_H

#include "config.h"
#include "mem_pool.h"
#include "upstream.h"
#include "symbols_cache.h"
#include "cfg_rcl.h"
#include "ucl.h"
#include "regexp.h"

#define DEFAULT_BIND_PORT 11333
#define DEFAULT_CONTROL_PORT 11334

struct expression;
struct tokenizer;
struct rspamd_stat_classifier;

enum { VAL_UNDEF=0, VAL_TRUE, VAL_FALSE };

/**
 * Type of time configuration parameter
 */
enum time_type {
	TIME_SECONDS = 0,
	TIME_MILLISECONDS,
	TIME_MINUTES,
	TIME_HOURS
};
/**
 * Types of rspamd bind lines
 */
enum rspamd_cred_type {
	CRED_NORMAL,
	CRED_CONTROL,
	CRED_LMTP,
	CRED_DELIVERY
};

/**
 * Logging type
 */
enum rspamd_log_type {
	RSPAMD_LOG_CONSOLE,
	RSPAMD_LOG_SYSLOG,
	RSPAMD_LOG_FILE
};

/**
 * script module list item
 */
struct script_module {
	gchar *name;                                    /**< name of module                                     */
	gchar *path;                                    /**< path to module										*/
};

/**
 * Type of lua variable
 */
enum lua_var_type {
	LUA_VAR_NUM,
	LUA_VAR_BOOLEAN,
	LUA_VAR_STRING,
	LUA_VAR_FUNCTION,
	LUA_VAR_UNKNOWN
};

/**
 * Symbols group
 */
struct rspamd_symbol_def;
struct rspamd_symbols_group {
	gchar *name;
	struct rspamd_symbol_def *symbols;
	gdouble max_score;
};

/**
 * Symbol definition
 */
struct rspamd_symbol_def {
	gchar *name;
	gchar *description;
	gdouble *weight_ptr;
	struct rspamd_symbols_group *gr;
	gboolean one_shot;
	struct rspamd_symbol_def *next;
};


typedef double (*statfile_normalize_func)(struct rspamd_config *cfg,
	long double score, void *params);

/**
 * Statfile config definition
 */
struct rspamd_statfile_config {
	gchar *symbol;                                  /**< symbol of statfile									*/
	gchar *label;                                   /**< label of this statfile								*/
	ucl_object_t *opts;                             /**< other options										*/
	gboolean is_spam;                               /**< spam flag											*/
	const gchar *backend;							/**< name of statfile's backend							*/
	struct rspamd_classifier_config *clcf;			/**< parent pointer of classifier configuration			*/
	gpointer data;									/**< opaque data 										*/
};

struct rspamd_tokenizer_config {
	const ucl_object_t *opts;                        /**< other options										*/
	const gchar *name;								/**< name of tokenizer									*/
};

/**
 * Classifier config definition
 */
struct rspamd_classifier_config {
	GList *statfiles;                               /**< statfiles list                                     */
	GHashTable *labels;                             /**< statfiles with labels								*/
	gchar *metric;                                  /**< metric of this classifier                          */
	gchar *classifier;                  			/**< classifier interface                               */
	struct rspamd_tokenizer_config *tokenizer;      /**< tokenizer used for classifier						*/
	ucl_object_t *opts;                             /**< other options                                      */
	GList *pre_callbacks;                           /**< list of callbacks that are called before classification */
	GList *post_callbacks;                          /**< list of callbacks that are called after classification */
	gchar *name;									/**< unique name of classifier							*/
	guint32 min_tokens;								/**< minimal number of tokens to process classifier 	*/
	guint32 max_tokens;								/**< maximum number of tokens							*/
};

struct rspamd_worker_bind_conf {
	GPtrArray *addrs;
	guint cnt;
	gchar *name;
	gboolean is_systemd;
	struct rspamd_worker_bind_conf *next;
};

/**
 * Config params for rspamd worker
 */
struct rspamd_worker_conf {
	worker_t *worker;                               /**< pointer to worker type								*/
	GQuark type;                                    /**< type of worker										*/
	struct rspamd_worker_bind_conf *bind_conf;      /**< bind configuration									*/
	guint16 count;                                  /**< number of workers									*/
	GList *listen_socks;                            /**< listening sockets desctiptors						*/
	guint32 rlimit_nofile;                          /**< max files limit									*/
	guint32 rlimit_maxcore;                         /**< maximum core file size								*/
	GHashTable *params;                             /**< params for worker									*/
	GQueue *active_workers;                         /**< linked list of spawned workers						*/
	gboolean has_socket;                            /**< whether we should make listening socket in main process */
	gpointer *ctx;                                  /**< worker's context									*/
	ucl_object_t *options;                  /**< other worker's options								*/
};

/**
 * Structure that stores all config data
 */
struct rspamd_config {
	gchar *rspamd_user;                             /**< user to run as										*/
	gchar *rspamd_group;                            /**< group to run as									*/
	rspamd_mempool_t *cfg_pool;                     /**< memory pool for config								*/
	gchar *cfg_name;                                /**< name of config file								*/
	gchar *pid_file;                                /**< name of pid file									*/
	gchar *temp_dir;                                /**< dir for temp files									*/
#ifdef WITH_GPERF_TOOLS
	gchar *profile_path;
#endif

	gboolean no_fork;                               /**< if 1 do not call daemon()							*/
	gboolean config_test;                           /**< if TRUE do only config file test					*/
	gboolean raw_mode;                              /**< work in raw mode instead of utf one				*/
	gboolean one_shot_mode;                         /**< rules add only one symbol							*/
	gboolean check_text_attachements;               /**< check text attachements as text					*/
	gboolean convert_config;                        /**< convert config to XML format						*/
	gboolean strict_protocol_headers;               /**< strictly check protocol headers					*/
	gboolean check_all_filters;                     /**< check all filters									*/

	gsize max_diff;                                 /**< maximum diff size for text parts					*/

	enum rspamd_log_type log_type;                  /**< log type											*/
	gint log_facility;                              /**< log facility in case of syslog						*/
	gint log_level;                                 /**< log level trigger									*/
	gchar *log_file;                                /**< path to logfile in case of file logging			*/
	gboolean log_buffered;                          /**< whether logging is buffered						*/
	guint32 log_buf_size;                           /**< length of log buffer								*/
	gchar *debug_ip_map;                            /**< turn on debugging for specified ip addresses       */
	gboolean log_urls;                              /**< whether we should log URLs                         */
	GList *debug_symbols;                           /**< symbols to debug									*/
	gboolean log_color;                             /**< output colors for console output                   */
	gboolean log_extended;                          /**< log extended information							*/

	gboolean mlock_statfile_pool;                   /**< use mlock (2) for locking statfiles				*/

	gboolean delivery_enable;                       /**< is delivery agent is enabled						*/
	gchar *deliver_host;                            /**< host for mail deliviring							*/
	struct in_addr deliver_addr;                    /**< its address										*/
	guint16 deliver_port;                           /**< port for deliviring								*/
	guint16 deliver_family;                         /**< socket family for delivirnig						*/
	gchar *deliver_agent_path;                      /**< deliver to pipe instead of socket					*/
	gboolean deliver_lmtp;                          /**< use LMTP instead of SMTP							*/

	GList *script_modules;                          /**< linked list of script modules to load				*/

	GList *filters;                                 /**< linked list of all filters							*/
	GList *workers;                                 /**< linked list of all workers params					*/
	struct rspamd_worker_cfg_parser *wrk_parsers;   /**< hash for worker config parsers, indexed by worker quarks */
	ucl_object_t *rcl_obj;                  /**< rcl object											*/
	GHashTable * metrics;                            /**< hash of metrics indexed by metric name				*/
	GHashTable * symbols_groups;                     /**< groups of symbols									*/
	GList * metrics_list;                            /**< linked list of metrics								*/
	GHashTable * metrics_symbols;                    /**< hash table of metrics indexed by symbol			*/
	GHashTable * c_modules;                          /**< hash of c modules indexed by module name			*/
	GHashTable * composite_symbols;                  /**< hash of composite symbols indexed by its name		*/
	GList *classifiers;                             /**< list of all classifiers defined                    */
	GList *statfiles;                               /**< list of all statfiles in config file order         */
	GHashTable *classifiers_symbols;                /**< hashtable indexed by symbol name of classifiers    */
	GHashTable * cfg_params;                         /**< all cfg params indexed by its name in this structure */
	GList *pre_filters;                             /**< list of pre-processing lua filters					*/
	GList *post_filters;                            /**< list of post-processing lua filters				*/
	gchar *dynamic_conf;                            /**< path to dynamic configuration						*/
	ucl_object_t *current_dynamic_conf;              /**< currently loaded dynamic configuration				*/
	GHashTable * domain_settings;                    /**< settings per-domains                               */
	GHashTable * user_settings;                      /**< settings per-user                                  */
	gchar * domain_settings_str;                     /**< string representation of settings					*/
	gchar * user_settings_str;
	gint clock_res;                                 /**< resolution of clock used							*/

	GList *maps;                                    /**< maps active										*/
	rspamd_mempool_t *map_pool;                     /**< static maps pool									*/
	gdouble map_timeout;                            /**< maps watch timeout									*/

	struct symbols_cache *cache;                    /**< symbols cache object								*/
	gchar *cache_filename;                          /**< filename of cache file								*/
	struct metric *default_metric;                  /**< default metric										*/

	gchar * checksum;                               /**< real checksum of config file						*/
	gchar * dump_checksum;                          /**< dump checksum of config file						*/
	gpointer lua_state;                             /**< pointer to lua state								*/

	gchar * rrd_file;                               /**< rrd file to store statistics						*/

	gchar * history_file;                           /**< file to save rolling history						*/

	gchar * tld_file;								/**< file to load effective tld list from				*/

	gdouble dns_timeout;                            /**< timeout in milliseconds for waiting for dns reply	*/
	guint32 dns_retransmits;                        /**< maximum retransmits count							*/
	guint32 dns_throttling_errors;                  /**< maximum errors for starting resolver throttling	*/
	guint32 dns_throttling_time;                    /**< time in seconds for DNS throttling					*/
	guint32 dns_io_per_server;                      /**< number of sockets per DNS server					*/
	GList *nameservers;                             /**< list of nameservers or NULL to parse resolv.conf	*/

	guint upstream_max_errors;						/**< upstream max errors before shutting off			*/
	gdouble upstream_error_time;					/**< rate of upstream errors							*/
	gdouble upstream_revive_time;					/**< revive timeout for upstreams						*/

	guint32 min_word_len;							/**< minimum length of the word to be considered		*/
};


/**
 * Parse bind credits
 * @param cf config file to use
 * @param str line that presents bind line
 * @param type type of credits
 * @return 1 if line was successfully parsed and 0 in case of error
 */
gboolean rspamd_parse_bind_line (struct rspamd_config *cfg,
	struct rspamd_worker_conf *cf, const gchar *str);

/**
 * Init default values
 * @param cfg config file
 */
void rspamd_config_defaults (struct rspamd_config *cfg);

/**
 * Free memory used by config structure
 * @param cfg config file
 */
void rspamd_config_free (struct rspamd_config *cfg);

/**
 * Gets module option with specified name
 * @param cfg config file
 * @param module_name name of module
 * @param opt_name name of option to get
 * @return module value or NULL if option does not defined
 */
const ucl_object_t * rspamd_config_get_module_opt (struct rspamd_config *cfg,
	const gchar *module_name,
	const gchar *opt_name);

/**
 * Parse limit
 * @param limit string representation of limit (eg. 1M)
 * @return numeric value of limit
 */
guint64 rspamd_config_parse_limit (const gchar *limit, guint len);

/**
 * Parse flag
 * @param str string representation of flag (eg. 'on')
 * @return numeric value of flag (0 or 1)
 */
gchar rspamd_config_parse_flag (const gchar *str);

/**
 * Do post load actions for config
 * @param cfg config file
 */
void rspamd_config_post_load (struct rspamd_config *cfg);

/**
 * Calculate checksum for config file
 * @param cfg config file
 */
gboolean rspamd_config_calculate_checksum (struct rspamd_config *cfg);


/**
 * Replace all \" with a single " in given string
 * @param line input string
 */
void rspamd_config_unescape_quotes (gchar *line);

/*
 * Convert comma separated string to a list of strings
 */
GList * rspamd_config_parse_comma_list (rspamd_mempool_t *pool,
	const gchar *line);

/*
 * Return a new classifier_config structure, setting default and non-conflicting attributes
 */
struct rspamd_classifier_config * rspamd_config_new_classifier (
	struct rspamd_config *cfg,
	struct rspamd_classifier_config *c);
/*
 * Return a new worker_conf structure, setting default and non-conflicting attributes
 */
struct rspamd_worker_conf * rspamd_config_new_worker (struct rspamd_config *cfg,
	struct rspamd_worker_conf *c);
/*
 * Return a new metric structure, setting default and non-conflicting attributes
 */
struct metric * rspamd_config_new_metric (struct rspamd_config *cfg,
	struct metric *c);
/*
 * Return a new statfile structure, setting default and non-conflicting attributes
 */
struct rspamd_statfile_config * rspamd_config_new_statfile (
	struct rspamd_config *cfg,
	struct rspamd_statfile_config *c);

/*
 * Read XML configuration file
 */
gboolean rspamd_config_read (struct rspamd_config *cfg,
	const gchar *filename, const gchar *convert_to,
	rspamd_rcl_section_fin_t logger_fin, gpointer logger_ud);

/*
 * Register symbols of classifiers inside metrics
 */
void rspamd_config_insert_classify_symbols (struct rspamd_config *cfg);

/*
 * Check statfiles inside a classifier
 */
gboolean rspamd_config_check_statfiles (struct rspamd_classifier_config *cf);

/*
 * Find classifier config by name
 */
struct rspamd_classifier_config * rspamd_config_find_classifier (
	struct rspamd_config *cfg,
	const gchar *name);

void rspamd_ucl_add_conf_macros (struct ucl_parser *parser,
	struct rspamd_config *cfg);

void rspamd_ucl_add_conf_variables (struct ucl_parser *parser);

/**
 * Initialize rspamd filtering system (lua and C filters)
 * @param cfg
 * @param reconfig
 * @return
 */
gboolean rspamd_init_filters (struct rspamd_config *cfg, bool reconfig);

#endif /* ifdef CFG_FILE_H */
/*
 * vi:ts=4
 */
