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

#define DEFAULT_BIND_PORT 11333
#define DEFAULT_CONTROL_PORT 11334

struct expression;
struct tokenizer;
struct classifier;

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
 * Regexp type: /H - header, /M - mime, /U - url /X - raw header
 */
enum rspamd_regexp_type {
	REGEXP_NONE = 0,
	REGEXP_HEADER,
	REGEXP_MIME,
	REGEXP_MESSAGE,
	REGEXP_URL,
	REGEXP_RAW_HEADER
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
 * Regexp structure
 */
struct rspamd_regexp {
	enum rspamd_regexp_type type;                   /**< regexp type										*/
	gchar *regexp_text;                             /**< regexp text representation							*/
	GRegex *regexp;                                 /**< glib regexp structure								*/
	GRegex *raw_regexp;                             /**< glib regexp structure for raw matching				*/
	gchar *header;                                  /**< header name for header regexps						*/
	gboolean is_test;                               /**< true if this expression must be tested				*/
	gboolean is_raw;                                /**< true if this regexp is done by raw matching		*/
	gboolean is_strong;                             /**< true if headers search must be case sensitive		*/
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
 * Module option
 */
struct rspamd_module_opt {
	gchar *param;                                   /**< parameter name										*/
	gchar *value;                                   /**< parameter value									*/
	gchar *description;                             /**< parameter description								*/
	gchar *group;                                   /**< parameter group									*/
	gpointer actual_data;                           /**< parsed data										*/
	gboolean is_lua;                                /**< actually this is lua variable						*/
	enum lua_var_type lua_type;                     /**< type of lua variable								*/
};

/**
 * Symbol definition
 */
struct rspamd_symbol_def {
	gchar *name;
	gchar *description;
	gdouble *weight_ptr;
	gboolean one_shot;
};

/**
 * Symbols group
 */
struct rspamd_symbols_group {
	gchar *name;
	GList *symbols;
};

/**
 * Statfile section definition
 */
struct rspamd_statfile_section {
	guint32 code;                                   /**< section's code										*/
	guint64 size;                                   /**< size of section									*/
	double weight;                                  /**< weight coefficient for section						*/
};

/**
 * Statfile autolearn parameters
 */
struct statfile_autolearn_params {
	const gchar *metric;                            /**< metric name for autolearn triggering               */
	double threshold_min;                           /**< threshold mark										*/
	double threshold_max;                           /**< threshold mark										*/
	GList *symbols;                                 /**< list of symbols									*/
};

/**
 * Sync affinity
 */
enum sync_affinity {
	AFFINITY_NONE = 0,
	AFFINITY_MASTER,
	AFFINITY_SLAVE
};

/**
 * Binlog params
 */
struct statfile_binlog_params {
	enum sync_affinity affinity;
	time_t rotate_time;
	gchar *master_addr;
	guint16 master_port;
};

typedef double (*statfile_normalize_func)(struct rspamd_config *cfg,
	long double score, void *params);

/**
 * Statfile config definition
 */
struct rspamd_statfile_config {
	gchar *symbol;                                  /**< symbol of statfile									*/
	gchar *path;                                    /**< filesystem pattern (with %r or %f)					*/
	gchar *label;                                   /**< label of this statfile								*/
	gsize size;                                     /**< size of statfile									*/
	GList *sections;                                /**< list of sections in statfile						*/
	struct statfile_autolearn_params *autolearn;    /**< autolearn params									*/
	struct statfile_binlog_params *binlog;          /**< binlog params										*/
	statfile_normalize_func normalizer;             /**< function that is used as normaliser                */
	void *normalizer_data;                          /**< normalizer function params                         */
	gchar *normalizer_str;                          /**< source string (for dump)							*/
	ucl_object_t *opts;                             /**< other options										*/
	gboolean is_spam;                               /**< spam flag											*/
};

/**
 * Classifier config definition
 */
struct rspamd_classifier_config {
	GList *statfiles;                               /**< statfiles list                                     */
	GHashTable *labels;                             /**< statfiles with labels								*/
	gchar *metric;                                  /**< metric of this classifier                          */
	struct classifier *classifier;                  /**< classifier interface                               */
	struct tokenizer *tokenizer;                    /**< tokenizer used for classifier						*/
	GHashTable *opts;                               /**< other options                                      */
	GList *pre_callbacks;                           /**< list of callbacks that are called before classification */
	GList *post_callbacks;                          /**< list of callbacks that are called after classification */
};

struct rspamd_worker_bind_conf {
	rspamd_inet_addr_t *addrs;
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

	guint32 statfile_sync_interval;                 /**< synchronization interval							*/
	guint32 statfile_sync_timeout;                  /**< synchronization timeout							*/
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
	gchar *filters_str;                             /**< string of filters									*/
	ucl_object_t *rcl_obj;                  /**< rcl object											*/
	GHashTable * metrics;                            /**< hash of metrics indexed by metric name				*/
	GList * symbols_groups;                          /**< groups of symbols									*/
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

	gchar * checksum;                                /**< real checksum of config file						*/
	gchar * dump_checksum;                           /**< dump checksum of config file						*/
	gpointer lua_state;                             /**< pointer to lua state								*/

	gchar * rrd_file;                                /**< rrd file to store statistics						*/

	gchar * history_file;                            /**< file to save rolling history						*/

	gdouble dns_timeout;                            /**< timeout in milliseconds for waiting for dns reply	*/
	guint32 dns_retransmits;                        /**< maximum retransmits count							*/
	guint32 dns_throttling_errors;                  /**< maximum errors for starting resolver throttling	*/
	guint32 dns_throttling_time;                    /**< time in seconds for DNS throttling					*/
	guint32 dns_io_per_server;                      /**< number of sockets per DNS server					*/
	GList *nameservers;                             /**< list of nameservers or NULL to parse resolv.conf	*/
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

#endif /* ifdef CFG_FILE_H */
/*
 * vi:ts=4
 */
