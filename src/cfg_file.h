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
	char *regexp_text;								/**< regexp text representation							*/
	GRegex *regexp;									/**< glib regexp structure								*/
	GRegex *raw_regexp;								/**< glib regexp structure for raw matching				*/
	char *header;									/**< header name for header regexps						*/
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
    char *name;                                     /**< name of module                                     */
	char *path;										/**< path to module										*/
};

/**
 * Module option
 */
struct module_opt {
	char *param;									/**< parameter name										*/
	char *value;									/**< paramater value									*/
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
	const char *metric;								/**< metric name for autolearn triggering 				*/
	double threshold_min;							/**< threshold mark										*/
	double threshold_max;							/**< threshold mark										*/
	GList *symbols;									/**< list of symbols									*/
};

/**
 * Statfile config definition
 */
struct statfile {
	char *alias;									/**< alias of statfile									*/
	char *pattern;									/**< filesystem pattern (with %r or %f)					*/
	double weight;									/**< weight scale										*/
	char *metric;									/**< metric name										*/
	size_t size;									/**< size of statfile									*/
	struct tokenizer *tokenizer;					/**< tokenizer used for statfile						*/
	GList *sections;								/**< list of sections in statfile						*/
	struct statfile_autolearn_params *autolearn;	/**< autolearn params									*/
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
	char *bind_host;								/**< bind line											*/
	struct in_addr bind_addr;						/**< bind address in case of TCP socket					*/
	uint16_t bind_port;								/**< bind port in case of TCP socket					*/
	uint16_t bind_family;							/**< bind type (AF_UNIX or AF_INET)						*/
	int count;										/**< number of workers									*/
	GHashTable *params;								/**< params for worker									*/
	int listen_sock;								/**< listening socket desctiptor						*/
};

/**
 * Structure that stores all config data
 */
struct config_file {
	char *rspamd_user;								/**< user to run as										*/
	char *rspamd_group;								/**< group to run as									*/
	memory_pool_t *cfg_pool;						/**< memory pool for config								*/
	char *cfg_name;									/**< name of config file								*/
	char *pid_file;									/**< name of pid file									*/
	char *temp_dir;									/**< dir for temp files									*/
#ifdef WITH_GPERF_TOOLS
	char *profile_path;
#endif

	gboolean no_fork;								/**< if 1 do not call daemon()							*/
	gboolean config_test;							/**< if TRUE do only config file test					*/
	gboolean raw_mode;								/**< work in raw mode instead of utf one				*/

	enum rspamd_log_type log_type;					/**< log type											*/
	int log_facility;								/**< log facility in case of syslog						*/
	int log_level;									/**< log level trigger									*/
	char *log_file;									/**< path to logfile in case of file logging			*/
	int log_fd;										/**< log descriptor in case of file logging				*/
	FILE *logf;

	size_t max_statfile_size;						/**< maximum size for statfile							*/

	struct memcached_server memcached_servers[MAX_MEMCACHED_SERVERS];	/**< memcached servers				*/
	size_t memcached_servers_num;					/**< number of memcached servers						*/
	memc_proto_t memcached_protocol;				/**< memcached protocol									*/
	unsigned int memcached_error_time;				/**< memcached error time (see upstream documentation)	*/
	unsigned int memcached_dead_time;				/**< memcached dead time								*/
	unsigned int memcached_maxerrors;				/**< maximum number of errors							*/
	unsigned int memcached_connect_timeout;			/**< connection timeout									*/

	gboolean delivery_enable;						/**< is delivery agent is enabled						*/
	char *deliver_host;								/**< host for mail deliviring							*/
	struct in_addr deliver_addr;					/**< its address										*/
	uint16_t deliver_port;							/**< port for deliviring								*/
	uint16_t deliver_family;						/**< socket family for delivirnig						*/
	char *deliver_agent_path;						/**< deliver to pipe instead of socket					*/
	gboolean deliver_lmtp;							/**< use LMTP instead of SMTP							*/

	GList *script_modules;							/**< linked list of script modules to load				*/

	GList *filters;									/**< linked list of all filters							*/
	GList *workers;									/**< linked list of all workers params					*/
	char *filters_str;								/**< string of filters									*/
	GHashTable* modules_opts;						/**< hash for module options indexed by module name		*/
	GHashTable* variables;							/**< hash of $variables defined in config, indexed by variable name */
	GHashTable* metrics;							/**< hash of metrics indexed by metric name				*/
	GList* metrics_list;	 						/**< linked list of metrics								*/
	GHashTable* factors;							/**< hash of factors indexed by symbol name				*/
	GHashTable* c_modules;							/**< hash of c modules indexed by module name			*/
	GHashTable* composite_symbols;					/**< hash of composite symbols indexed by its name		*/
	GHashTable* statfiles;							/**< hash of defined statfiles indexed by alias			*/
    GHashTable* cfg_params;							/**< all cfg params indexed by its name in this structure */
	int clock_res;									/**< resolution of clock used							*/
	GList *views;									/**< views												*/
};

/**
 * Add memcached server to config
 * @param cf config file to use
 * @param str line that describes server's credits
 * @return 1 if line was successfully parsed and 0 in case of error
 */
int add_memcached_server (struct config_file *cf, char *str);

/**
 * Parse bind credits
 * @param cf config file to use
 * @param str line that presents bind line
 * @param type type of credits
 * @return 1 if line was successfully parsed and 0 in case of error
 */
int parse_bind_line (struct config_file *cfg, struct worker_conf *cf, char *str);

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
char* get_module_opt (struct config_file *cfg, char *module_name, char *opt_name);

/**
 * Parse limit
 * @param limit string representation of limit (eg. 1M)
 * @return numeric value of limit
 */
size_t parse_limit (const char *limit);

/**
 * Parse seconds
 * @param t string representation of seconds (eg. 1D)
 * @return numeric value of string
 */
unsigned int parse_seconds (const char *t);

/**
 * Parse flag
 * @param str string representation of flag (eg. 'on')
 * @return numeric value of flag (0 or 1)
 */
char parse_flag (const char *str);

/**
 * Substitutes variable in specified string, may be recursive (eg. ${var1${var2}})
 * @param cfg config file
 * @param name variable's name
 * @param str incoming string
 * @param recursive whether do recursive scanning
 * @return new string with substituted variables (uses cfg memory pool for allocating)
 */
char* substitute_variable (struct config_file *cfg, char *name, char *str, u_char recursive);

/**
 * Do post load actions for config
 * @param cfg config file
 */
void post_load_config (struct config_file *cfg);


/**
 * Replace all \" with a single " in given string
 * @param line input string
 */
void unescape_quotes (char *line);

GList* parse_comma_list (memory_pool_t *pool, char *line);


int yylex (void);
int yyparse (void);
void yyrestart (FILE *);
void parse_err (const char *fmt, ...);
void parse_warn (const char *fmt, ...);

#endif /* ifdef CFG_FILE_H */
/* 
 * vi:ts=4 
 */
