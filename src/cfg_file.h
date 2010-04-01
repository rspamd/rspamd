/**
 * @file cfg_file.h
 * Config file parser and config routines API
 */

#ifndef CFG_FILE_H
#define CFG_FILE_H

#include "config.h"
#include "mem_pool.h"
#include "upstream.h"
#include "memcached.h"

#define DEFAULT_BIND_PORT 768
#define DEFAULT_CONTROL_PORT 7608
#define DEFAULT_LMTP_PORT 7609
#define MAX_MEMCACHED_SERVERS 48
#define DEFAULT_MEMCACHED_PORT 11211
/* Memcached timeouts */
#define DEFAULT_MEMCACHED_CONNECT_TIMEOUT 1000
/* Upstream timeouts */
#define DEFAULT_UPSTREAM_ERROR_TIME 10
#define DEFAULT_UPSTREAM_ERROR_TIME 10
#define DEFAULT_UPSTREAM_DEAD_TIME 300
#define DEFAULT_UPSTREAM_MAXERRORS 10
/* Statfile pool size, 50Mb */
#define DEFAULT_STATFILE_SIZE 52428800L

/* 1 worker by default */
#define DEFAULT_WORKERS_NUM 1

#define DEFAULT_SCORE 10.0
#define DEFAULT_REJECT_SCORE 999.0

#define yyerror parse_err
#define yywarn parse_warn

struct expression;
struct tokenizer;
struct classifier;

enum { VAL_UNDEF=0, VAL_TRUE, VAL_FALSE };

/**
 * Types of rspamd bind lines
 */
enum rspamd_cred_type {
	CRED_NORMAL,
	CRED_CONTROL,
	CRED_LMTP,
	CRED_DELIVERY,
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
	REGEXP_RAW_HEADER,
};

/**
 * Logging type
 */
enum rspamd_log_type {
	RSPAMD_LOG_CONSOLE,
	RSPAMD_LOG_SYSLOG,
	RSPAMD_LOG_FILE,
};

/**
 * Regexp structure
 */
struct rspamd_regexp {
	enum rspamd_regexp_type type;					/**< regexp type										*/
	gchar *regexp_text;								/**< regexp text representation							*/
	GRegex *regexp;									/**< glib regexp structure								*/
	GRegex *raw_regexp;								/**< glib regexp structure for raw matching				*/
	gchar *header;									/**< header name for header regexps						*/
};

/**
 * Memcached server object
 */
struct memcached_server {
	struct upstream up;								/**< common upstream base								*/
	struct in_addr addr;							/**< address of server									*/
	uint16_t port;									/**< port to connect									*/
	short alive;									/**< is this server alive								*/
	short int num;									/**< number of servers in case of mirror				*/
};

/**
 * script module list item
 */
struct script_module {
    gchar *name;                                     /**< name of module                                     */
	gchar *path;										/**< path to module										*/
};

/**
 * Module option
 */
struct module_opt {
	gchar *param;									/**< parameter name										*/
	gchar *value;									/**< paramater value									*/
};

/**
 * Statfile section definition
 */
struct statfile_section {
	uint32_t code;									/**< section's code										*/
	uint64_t size;									/**< size of section									*/
	double weight;									/**< weight coefficient for section						*/
};

/**
 * Statfile autolearn parameters
 */
struct statfile_autolearn_params {
	const gchar *metric;							/**< metric name for autolearn triggering 				*/
	double threshold_min;							/**< threshold mark										*/
	double threshold_max;							/**< threshold mark										*/
	GList *symbols;									/**< list of symbols									*/
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
	struct in_addr master_addr;
	uint16_t master_port;
};

typedef double (*statfile_normalize_func)(double score, void *params);

/**
 * Statfile config definition
 */
struct statfile {
	gchar *symbol;									/**< symbol of statfile									*/
	gchar *path; 									/**< filesystem pattern (with %r or %f)					*/
	gsize size;									/**< size of statfile									*/
	GList *sections;								/**< list of sections in statfile						*/
	struct statfile_autolearn_params *autolearn;	/**< autolearn params									*/
	struct statfile_binlog_params *binlog;			/**< binlog params										*/
    statfile_normalize_func normalizer;             /**< function that is used as normaliser                */
    void *normalizer_data;                          /**< normalizer function params                         */
};

/**
 * Classifier config definition
 */
struct classifier_config {
    GList *statfiles;                               /**< statfiles list                                     */
    gchar *metric;                                  /**< metric of this classifier                          */
    struct classifier *classifier;                  /**< classifier interface                               */
	struct tokenizer *tokenizer;					/**< tokenizer used for classifier						*/
    GHashTable *opts;                               /**< other options                                      */
	GList *pre_callbacks;							/**< list of callbacks that are called before classification */
	GList *post_callbacks;							/**< list of callbacks that are called after classification */
};

/**
 * Config option for importing to script module
 */
struct config_scalar {
    void *pointer;									/**< pointer to data									*/
    enum {
        SCALAR_TYPE_INT,
        SCALAR_TYPE_UINT,
        SCALAR_TYPE_STR,
        SCALAR_TYPE_SIZE,
    } type;											/**< type of data										*/
};


/**
 * Config params for rspamd worker
 */
struct worker_conf {
	int type;										/**< worker type										*/
	gchar *bind_host;								/**< bind line											*/
	struct in_addr bind_addr;						/**< bind address in case of TCP socket					*/
	uint16_t bind_port;								/**< bind port in case of TCP socket					*/
	uint16_t bind_family;							/**< bind type (AF_UNIX or AF_INET)						*/
	uint16_t count;									/**< number of workers									*/
	int listen_sock;								/**< listening socket desctiptor						*/
	uint32_t rlimit_nofile;							/**< max files limit									*/
	uint32_t rlimit_maxcore;						/**< maximum core file size								*/
	GHashTable *params;								/**< params for worker									*/
	GQueue *active_workers;							/**< linked list of spawned workers						*/
	gboolean has_socket;							/**< whether we should make listening socket in main process */
};

/**
 * Structure that stores all config data
 */
struct config_file {
	gchar *rspamd_user;								/**< user to run as										*/
	gchar *rspamd_group;							/**< group to run as									*/
	memory_pool_t *cfg_pool;						/**< memory pool for config								*/
	gchar *cfg_name;								/**< name of config file								*/
	gchar *pid_file;								/**< name of pid file									*/
	gchar *temp_dir;								/**< dir for temp files									*/
#ifdef WITH_GPERF_TOOLS
	gchar *profile_path;
#endif

	gboolean no_fork;								/**< if 1 do not call daemon()							*/
	gboolean config_test;							/**< if TRUE do only config file test					*/
	gboolean raw_mode;								/**< work in raw mode instead of utf one				*/

	enum rspamd_log_type log_type;					/**< log type											*/
	int log_facility;								/**< log facility in case of syslog						*/
	int log_level;									/**< log level trigger									*/
	gchar *log_file;								/**< path to logfile in case of file logging			*/
	gboolean log_buffered;							/**< whether logging is buffered						*/
	uint32_t log_buf_size;							/**< length of log buffer								*/
	gchar *debug_ip_map;						    /**< turn on debugging for specified ip addresses       */
	gboolean log_urls;								/**< whether we should log URLs                         */

	gsize max_statfile_size;						/**< maximum size for statfile							*/

	struct memcached_server memcached_servers[MAX_MEMCACHED_SERVERS];	/**< memcached servers				*/
	gsize memcached_servers_num;					/**< number of memcached servers						*/
	memc_proto_t memcached_protocol;				/**< memcached protocol									*/
	unsigned int memcached_error_time;				/**< memcached error time (see upstream documentation)	*/
	unsigned int memcached_dead_time;				/**< memcached dead time								*/
	unsigned int memcached_maxerrors;				/**< maximum number of errors							*/
	unsigned int memcached_connect_timeout;			/**< connection timeout									*/

	gboolean delivery_enable;						/**< is delivery agent is enabled						*/
	gchar *deliver_host;							/**< host for mail deliviring							*/
	struct in_addr deliver_addr;					/**< its address										*/
	uint16_t deliver_port;							/**< port for deliviring								*/
	uint16_t deliver_family;						/**< socket family for delivirnig						*/
	gchar *deliver_agent_path;						/**< deliver to pipe instead of socket					*/
	gboolean deliver_lmtp;							/**< use LMTP instead of SMTP							*/

	GList *script_modules;							/**< linked list of script modules to load				*/

	GList *filters;									/**< linked list of all filters							*/
	GList *workers;									/**< linked list of all workers params					*/
	gchar *filters_str;								/**< string of filters									*/
	GHashTable* modules_opts;						/**< hash for module options indexed by module name		*/
	GHashTable* variables;							/**< hash of $variables defined in config, indexed by variable name */
	GHashTable* metrics;							/**< hash of metrics indexed by metric name				*/
	GList* metrics_list;	 						/**< linked list of metrics								*/
	GHashTable* factors;							/**< hash of factors indexed by symbol name				*/
	GHashTable* c_modules;							/**< hash of c modules indexed by module name			*/
	GHashTable* composite_symbols;					/**< hash of composite symbols indexed by its name		*/
	GList *classifiers;                             /**< list of all classifiers defined                    */
	GList *statfiles;                               /**< list of all statfiles in config file order         */
	GHashTable *classifiers_symbols;                /**< hashtable indexed by symbol name of classifiers    */
	GHashTable* cfg_params;							/**< all cfg params indexed by its name in this structure */
	int clock_res;									/**< resolution of clock used							*/
	double grow_factor;								/**< grow factor for consolidation callback				*/
	GList *views;									/**< views												*/
	GHashTable* domain_settings;                    /**< settings per-domains                               */
	GHashTable* user_settings;                      /**< settings per-user                                  */
	
	gchar* checksum;								/**< real checksum of config file						*/ 
	gchar* dump_checksum;							/**< dump checksum of config file						*/ 
};

/**
 * Add memcached server to config
 * @param cf config file to use
 * @param str line that describes server's credits
 * @return 1 if line was successfully parsed and 0 in case of error
 */
int add_memcached_server (struct config_file *cf, gchar *str);

/**
 * Parse host:port line
 * @param ina host address
 * @param port port
 * @return TRUE if string was parsed
 */
gboolean parse_host_port (const gchar *str, struct in_addr *ina, uint16_t *port);

/**
 * Parse bind credits
 * @param cf config file to use
 * @param str line that presents bind line
 * @param type type of credits
 * @return 1 if line was successfully parsed and 0 in case of error
 */
int parse_bind_line (struct config_file *cfg, struct worker_conf *cf, gchar *str);

/**
 * Init default values
 * @param cfg config file
 */
void init_defaults (struct config_file *cfg);

/**
 * Free memory used by config structure
 * @param cfg config file
 */
void free_config (struct config_file *cfg);

/**
 * Gets module option with specified name
 * @param cfg config file
 * @param module_name name of module
 * @param opt_name name of option to get
 * @return module value or NULL if option does not defined
 */
gchar* get_module_opt (struct config_file *cfg, gchar *module_name, gchar *opt_name);

/**
 * Parse limit
 * @param limit string representation of limit (eg. 1M)
 * @return numeric value of limit
 */
gsize parse_limit (const gchar *limit);

/**
 * Parse seconds
 * @param t string representation of seconds (eg. 1D)
 * @return numeric value of string
 */
unsigned int parse_seconds (const gchar *t);

/**
 * Parse flag
 * @param str string representation of flag (eg. 'on')
 * @return numeric value of flag (0 or 1)
 */
gchar parse_flag (const gchar *str);

/**
 * Substitutes variable in specified string, may be recursive (eg. ${var1${var2}})
 * @param cfg config file
 * @param name variable's name
 * @param str incoming string
 * @param recursive whether do recursive scanning
 * @return new string with substituted variables (uses cfg memory pool for allocating)
 */
gchar* substitute_variable (struct config_file *cfg, gchar *name, gchar *str, guchar recursive);

/**
 * Do post load actions for config
 * @param cfg config file
 */
void post_load_config (struct config_file *cfg);

/**
 * Calculate checksum for config file
 * @param cfg config file
 */
gboolean get_config_checksum (struct config_file *cfg);


/**
 * Replace all \" with a single " in given string
 * @param line input string
 */
void unescape_quotes (gchar *line);

GList* parse_comma_list (memory_pool_t *pool, gchar *line);
struct classifier_config* check_classifier_cfg (struct config_file *cfg, struct classifier_config *c);
struct worker_conf* check_worker_conf (struct config_file *cfg, struct worker_conf *c);
gboolean parse_normalizer (struct config_file *cfg, struct statfile *st, const gchar *line);
gboolean read_xml_config (struct config_file *cfg, const gchar *filename);

int yylex (void);
int yyparse (void);
void yyrestart (FILE *);
void parse_err (const gchar *fmt, ...);
void parse_warn (const gchar *fmt, ...);

#endif /* ifdef CFG_FILE_H */
/* 
 * vi:ts=4 
 */
