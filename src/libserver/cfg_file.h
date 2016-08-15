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
#include "libserver/re_cache.h"
#include "ref.h"
#include "libutil/radix.h"

#define DEFAULT_BIND_PORT 11333
#define DEFAULT_CONTROL_PORT 11334

/* Default metric name */
#define DEFAULT_METRIC "default"

struct expression;
struct tokenizer;
struct rspamd_stat_classifier;
struct module_s;
struct worker_s;
struct rspamd_external_libs_ctx;

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
	GHashTable *symbols;
	gdouble max_score;
	gboolean disabled;
	gboolean one_shot;
};

#define RSPAMD_SYMBOL_FLAG_ONESHOT (1 << 0)
#define RSPAMD_SYMBOL_FLAG_IGNORE (1 << 1)

/**
 * Symbol definition
 */
struct rspamd_symbol_def {
	gchar *name;
	gchar *description;
	gdouble *weight_ptr;
	gdouble score;
	guint priority;
	struct rspamd_symbols_group *gr;
	GList *groups;
	guint flags;
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
	struct rspamd_classifier_config *clcf;			/**< parent pointer of classifier configuration			*/
	gpointer data;									/**< opaque data 										*/
};

struct rspamd_tokenizer_config {
	const ucl_object_t *opts;                        /**< other options										*/
	const gchar *name;								/**< name of tokenizer									*/
};


/* Classifier has all integer values (e.g. bayes) */
#define RSPAMD_FLAG_CLASSIFIER_INTEGER (1 << 0)
/*
 * Set if backend for a classifier is intended to increment and not set values
 * (e.g. redis)
 */
#define RSPAMD_FLAG_CLASSIFIER_INCREMENTING_BACKEND (1 << 1)

/**
 * Classifier config definition
 */
struct rspamd_classifier_config {
	GList *statfiles;                               /**< statfiles list                                     */
	GHashTable *labels;                             /**< statfiles with labels								*/
	gchar *metric;                                  /**< metric of this classifier                          */
	gchar *classifier;                  			/**< classifier interface                               */
	struct rspamd_tokenizer_config *tokenizer;      /**< tokenizer used for classifier						*/
	const gchar *backend;							/**< name of statfile's backend							*/
	ucl_object_t *opts;                             /**< other options                                      */
	GList *pre_callbacks;                           /**< list of callbacks that are called before classification */
	GList *post_callbacks;                          /**< list of callbacks that are called after classification */
	GList *learn_conditions;						/**< list of learn condition callbacks					*/
	gchar *name;									/**< unique name of classifier							*/
	guint32 min_tokens;								/**< minimal number of tokens to process classifier 	*/
	guint32 max_tokens;								/**< maximum number of tokens							*/
	guint min_learns;								/**< minimum number of learns for each statfile			*/
	guint flags;
};

struct rspamd_worker_bind_conf {
	GPtrArray *addrs;
	guint cnt;
	gchar *name;
	gboolean is_systemd;
	struct rspamd_worker_bind_conf *next;
};

struct rspamd_worker_lua_script {
	gint cbref;
	struct rspamd_worker_lua_script *prev, *next;
};

/**
 * Config params for rspamd worker
 */
struct rspamd_worker_conf {
	struct worker_s *worker;                        /**< pointer to worker type								*/
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
	ucl_object_t *options;                          /**< other worker's options								*/
	struct rspamd_worker_lua_script *scripts;       /**< registered lua scripts								*/
};

enum rspamd_log_format_type {
	RSPAMD_LOG_STRING = 0,
	RSPAMD_LOG_MID,
	RSPAMD_LOG_QID,
	RSPAMD_LOG_USER,
	RSPAMD_LOG_ISSPAM,
	RSPAMD_LOG_ACTION,
	RSPAMD_LOG_SCORES,
	RSPAMD_LOG_SYMBOLS,
	RSPAMD_LOG_IP,
	RSPAMD_LOG_LEN,
	RSPAMD_LOG_DNS_REQ,
	RSPAMD_LOG_SMTP_FROM,
	RSPAMD_LOG_MIME_FROM,
	RSPAMD_LOG_SMTP_RCPT,
	RSPAMD_LOG_MIME_RCPT,
	RSPAMD_LOG_SMTP_RCPTS,
	RSPAMD_LOG_MIME_RCPTS,
	RSPAMD_LOG_TIME_REAL,
	RSPAMD_LOG_TIME_VIRTUAL,
	RSPAMD_LOG_LUA,
	RSPAMD_LOG_DIGEST,
};

enum rspamd_log_format_flags {
	RSPAMD_LOG_FLAG_DEFAULT = 0,
	RSPAMD_LOG_FLAG_OPTIONAL = (1 << 0),
	RSPAMD_LOG_FLAG_MIME_ALTERNATIVE = (1 << 1),
	RSPAMD_LOG_FLAG_CONDITION = (1 << 2),
	RSPAMD_LOG_FLAG_SYMBOLS_SCORES = (1 << 3),
	RSPAMD_LOG_FLAG_SYMBOLS_PARAMS = (1 << 4)
};

struct rspamd_log_format {
	enum rspamd_log_format_type type;
	guint flags;
	gsize len;
	gpointer data;
	struct rspamd_log_format *prev, *next;
};

enum rspamd_metric_action {
	METRIC_ACTION_REJECT = 0,
	METRIC_ACTION_SOFT_REJECT,
	METRIC_ACTION_REWRITE_SUBJECT,
	METRIC_ACTION_ADD_HEADER,
	METRIC_ACTION_GREYLIST,
	METRIC_ACTION_NOACTION,
	METRIC_ACTION_MAX
};

struct metric_action {
	enum rspamd_metric_action action;
	gdouble score;
	guint priority;
};

/**
 * Common definition of metric
 */
struct metric {
	const gchar *name;                              /**< name of metric									*/
	gchar *func_name;                               /**< name of consolidation function					*/
	gboolean accept_unknown_symbols;                /**< if true unknown symbols are registered here	*/
	gdouble unknown_weight;                         /**< weight of unknown symbols						*/
	gdouble grow_factor;                            /**< grow factor for metric							*/
	GHashTable *symbols;                            /**< weights of symbols in metric					*/
	gchar *subject;                                 /**< subject rewrite string							*/
	GHashTable * groups; 		                    /**< groups of symbols								*/
	struct metric_action actions[METRIC_ACTION_MAX]; /**< all actions of the metric						*/
};

struct rspamd_config_post_load_script {
	gint cbref;
	struct rspamd_config_post_load_script *prev, *next;
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
	gchar *control_socket_path;                     /**< path to the control socket							*/
	const ucl_object_t *local_addrs;                /**< tree of local addresses							*/
#ifdef WITH_GPERF_TOOLS
	gchar *profile_path;
#endif

	gboolean raw_mode;                              /**< work in raw mode instead of utf one				*/
	gboolean one_shot_mode;                         /**< rules add only one symbol							*/
	gboolean check_text_attachements;               /**< check text attachements as text					*/
	gboolean convert_config;                        /**< convert config to XML format						*/
	gboolean strict_protocol_headers;               /**< strictly check protocol headers					*/
	gboolean check_all_filters;                     /**< check all filters									*/
	gboolean allow_raw_input;                       /**< scan messages with invalid mime					*/
	gboolean disable_hyperscan;                     /**< disable hyperscan usage							*/
	gboolean vectorized_hyperscan;                  /**< use vectorized hyperscan matching					*/
	gboolean enable_shutdown_workaround;            /**< enable workaround for legacy SA clients (exim)		*/
	gboolean ignore_received;                       /**< Ignore data from the first received header			*/

	gsize max_diff;                                 /**< maximum diff size for text parts					*/
	gsize max_cores_size;                           /**< maximum size occupied by rspamd core files			*/
	gsize max_cores_count;                          /**< maximum number of core files						*/
	gchar *cores_dir;                               /**< directory for core files							*/
	gsize max_message;                              /**< maximum size for messages							*/

	enum rspamd_log_type log_type;                  /**< log type											*/
	gint log_facility;                              /**< log facility in case of syslog						*/
	gint log_level;                                 /**< log level trigger									*/
	gchar *log_file;                                /**< path to logfile in case of file logging			*/
	gboolean log_buffered;                          /**< whether logging is buffered						*/
	guint32 log_buf_size;                           /**< length of log buffer								*/
	const ucl_object_t *debug_ip_map;               /**< turn on debugging for specified ip addresses       */
	gboolean log_urls;                              /**< whether we should log URLs                         */
	GList *debug_symbols;                           /**< symbols to debug									*/
	GHashTable *debug_modules;                      /**< logging modules to debug							*/
	gboolean log_color;                             /**< output colors for console output                   */
	gboolean log_extended;                          /**< log extended information							*/
	gboolean log_systemd;                           /**< special case for systemd logger					*/
	gboolean log_re_cache;                          /**< show statistics about regexps						*/

	gboolean mlock_statfile_pool;                   /**< use mlock (2) for locking statfiles				*/

	gboolean delivery_enable;                       /**< is delivery agent is enabled						*/
	gchar *deliver_host;                            /**< host for mail deliviring							*/
	struct in_addr deliver_addr;                    /**< its address										*/
	guint16 deliver_port;                           /**< port for deliviring								*/
	guint16 deliver_family;                         /**< socket family for delivirnig						*/
	gchar *deliver_agent_path;                      /**< deliver to pipe instead of socket					*/
	gboolean deliver_lmtp;                          /**< use LMTP instead of SMTP							*/

	GList *script_modules;                          /**< linked list of script modules to load				*/
	GHashTable *explicit_modules;                   /**< modules that should be always loaded				*/

	GList *filters;                                 /**< linked list of all filters							*/
	GList *workers;                                 /**< linked list of all workers params					*/
	GHashTable *wrk_parsers;                        /**< hash for worker config parsers, indexed by worker quarks */
	ucl_object_t *rcl_obj;                          /**< rcl object											*/
	ucl_object_t *config_comments;                  /**< comments saved from the config						*/
	ucl_object_t *doc_strings;                      /**< documentation strings for config options			*/
	GHashTable * metrics;                           /**< hash of metrics indexed by metric name				*/
	GList * metrics_list;                           /**< linked list of metrics								*/
	GHashTable * metrics_symbols;                   /**< hash table of metrics indexed by symbol			*/
	GHashTable * c_modules;                         /**< hash of c modules indexed by module name			*/
	GHashTable * composite_symbols;                 /**< hash of composite symbols indexed by its name		*/
	GList *classifiers;                             /**< list of all classifiers defined                    */
	GList *statfiles;                               /**< list of all statfiles in config file order         */
	GHashTable *classifiers_symbols;                /**< hashtable indexed by symbol name of classifiers    */
	GHashTable * cfg_params;                        /**< all cfg params indexed by its name in this structure */
	gchar *dynamic_conf;                            /**< path to dynamic configuration						*/
	ucl_object_t *current_dynamic_conf;             /**< currently loaded dynamic configuration				*/
	GHashTable * domain_settings;                   /**< settings per-domains                               */
	GHashTable * user_settings;                     /**< settings per-user                                  */
	gchar * domain_settings_str;                    /**< string representation of settings					*/
	gchar * user_settings_str;
	gint clock_res;                                 /**< resolution of clock used							*/

	GList *maps;                                    /**< maps active										*/
	gdouble map_timeout;                            /**< maps watch timeout									*/

	struct symbols_cache *cache;                    /**< symbols cache object								*/
	gchar *cache_filename;                          /**< filename of cache file								*/
	struct metric *default_metric;                  /**< default metric										*/

	gchar * checksum;                               /**< real checksum of config file						*/
	gchar * dump_checksum;                          /**< dump checksum of config file						*/
	gpointer lua_state;                             /**< pointer to lua state								*/

	gchar * rrd_file;                               /**< rrd file to store statistics						*/

	gchar * history_file;                           /**< file to save rolling history						*/

	gchar * tld_file;                               /**< file to load effective tld list from				*/

	gchar * hs_cache_dir;                           /**< directory to save hyperscan databases				*/

	gchar * magic_file;                             /**< file to initialize libmagic						*/

	gdouble dns_timeout;                            /**< timeout in milliseconds for waiting for dns reply	*/
	guint32 dns_retransmits;                        /**< maximum retransmits count							*/
	guint32 dns_throttling_errors;                  /**< maximum errors for starting resolver throttling	*/
	guint32 dns_throttling_time;                    /**< time in seconds for DNS throttling					*/
	guint32 dns_io_per_server;                      /**< number of sockets per DNS server					*/
	const ucl_object_t *nameservers;                /**< list of nameservers or NULL to parse resolv.conf	*/
	guint32 dns_max_requests;                       /**< limit of DNS requests per task 					*/

	guint upstream_max_errors;						/**< upstream max errors before shutting off			*/
	gdouble upstream_error_time;					/**< rate of upstream errors							*/
	gdouble upstream_revive_time;					/**< revive timeout for upstreams						*/
	struct upstream_ctx *ups_ctx;					/**< upstream context									*/

	guint min_word_len;								/**< minimum length of the word to be considered		*/
	guint max_word_len;								/**< maximum length of the word to be considered		*/
	guint words_decay;								/**< limit for words for starting adaptive ignoring		*/
	guint history_rows;								/**< number of history rows stored						*/

	GList *classify_headers;						/**< list of headers using for statistics				*/
	struct module_s **compiled_modules;				/**< list of compiled C modules							*/
	struct worker_s **compiled_workers;				/**< list of compiled C modules							*/
	GList *dynamic_modules;							/**< list of dynamic C modules							*/
	GList *dynamic_workers;							/**< list of dynamic C modules							*/
	struct rspamd_log_format *log_format;			/**< parsed log format									*/
	gchar *log_format_str;							/**< raw log format string								*/

	struct rspamd_external_libs_ctx *libs_ctx;		/**< context for external libraries						*/

	struct rspamd_re_cache *re_cache;				/**< static regexp cache								*/

	GHashTable *trusted_keys;						/**< list of trusted public keys						*/

	struct rspamd_config_post_load_script *on_load;	/**< list of scripts executed on config load			*/

	gchar *ssl_ca_path;								/**< path to CA certs									*/
	gchar *ssl_ciphers;							/**< set of preferred ciphers							*/

	ref_entry_t ref;								/**< reference counter									*/
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
struct rspamd_config *rspamd_config_new (void);

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
 * Parse flag
 * @param str string representation of flag (eg. 'on')
 * @return numeric value of flag (0 or 1)
 */
gchar rspamd_config_parse_flag (const gchar *str, guint len);

enum rspamd_post_load_options {
	RSPAMD_CONFIG_INIT_URL = 1 << 0,
	RSPAMD_CONFIG_INIT_LIBS = 1 << 1,
	RSPAMD_CONFIG_INIT_SYMCACHE = 1 << 2,
	RSPAMD_CONFIG_INIT_VALIDATE = 1 << 3
};

#define RSPAMD_CONFIG_LOAD_ALL (RSPAMD_CONFIG_INIT_URL|RSPAMD_CONFIG_INIT_LIBS|RSPAMD_CONFIG_INIT_SYMCACHE|RSPAMD_CONFIG_INIT_VALIDATE)

/**
 * Do post load actions for config
 * @param cfg config file
 */
gboolean rspamd_config_post_load (struct rspamd_config *cfg,
		enum rspamd_post_load_options opts);

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
	struct metric *c, const gchar *name);

/*
 * Return new symbols group definition
 */
struct rspamd_symbols_group * rspamd_config_new_group (
		struct rspamd_config *cfg, struct metric *metric,
		const gchar *name);
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
	rspamd_rcl_section_fin_t logger_fin, gpointer logger_ud,
	GHashTable *vars);

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

void rspamd_ucl_add_conf_variables (struct ucl_parser *parser, GHashTable *vars);

/**
 * Initialize rspamd filtering system (lua and C filters)
 * @param cfg
 * @param reconfig
 * @return
 */
gboolean rspamd_init_filters (struct rspamd_config *cfg, bool reconfig);

/**
 * Add new symbol to the metric
 * @param cfg
 * @param metric metric's name (or NULL for the default metric)
 * @param symbol symbol's name
 * @param score symbol's score
 * @param description optional description
 * @param group optional group name
 * @param one_shot TRUE if symbol can add its score once
 * @param rewrite_existing TRUE if we need to rewrite the existing symbol
 * @param priority use the following priority for a symbol
 * @return TRUE if symbol has been inserted or FALSE if symbol already exists with higher priority
 */
gboolean rspamd_config_add_metric_symbol (struct rspamd_config *cfg,
		const gchar *metric,
		const gchar *symbol, gdouble score, const gchar *description,
		const gchar *group, guint flags,
		guint priority);

/**
 * Sets action score for a specified metric with the specified priority
 * @param cfg config file
 * @param metric metric name (or NULL for default metric)
 * @param action_name symbolic name of action
 * @param score score limit
 * @param priority priority for action
 * @return TRUE if symbol has been inserted or FALSE if action already exists with higher priority
 */
gboolean rspamd_config_set_action_score (struct rspamd_config *cfg,
		const gchar *metric,
		const gchar *action_name,
		gdouble score,
		guint priority);

/**
 * Checks if a specified C or lua module is enabled or disabled in the config.
 * The logic of check is the following:
 *
 * - For C modules, we check `filters` line and enable module only if it is found there
 * - For LUA modules we check the corresponding configuration section:
 *   - if section exists, then we check `enabled` key and check its value
 *   - if section is absent, we consider module as disabled
 * - For both C and LUA modules we check if the group with the module name is disabled in the default metric
 * @param cfg config file
 * @param module_name module name
 * @return TRUE if a module is enabled
 */
gboolean rspamd_config_is_module_enabled (struct rspamd_config *cfg,
		const gchar *module_name);

/**
 * Parse radix tree or radix map from ucl object
 * @param cfg configuration object
 * @param obj ucl object with parameter
 * @param target target radix tree
 * @param err error pointer
 * @return
 */
gboolean rspamd_config_radix_from_ucl (struct rspamd_config *cfg,
		const ucl_object_t *obj,
		const gchar *description,
		radix_compressed_t **target,
		GError **err);

#define msg_err_config(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        cfg->cfg_pool->tag.tagname, cfg->checksum, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_config(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        cfg->cfg_pool->tag.tagname, cfg->checksum, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_config(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        cfg->cfg_pool->tag.tagname, cfg->checksum, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_config(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
        cfg->cfg_pool->tag.tagname, cfg->checksum, \
        G_STRFUNC, \
        __VA_ARGS__)

#endif /* ifdef CFG_FILE_H */
/*
 * vi:ts=4
 */
