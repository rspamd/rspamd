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
#include "filter.h"

#define DEFAULT_BIND_PORT 768
#define DEFAULT_CONTROL_PORT 7608
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
 * Regexp type: /H - header, /M - mime, /U - url
 */
enum rspamd_regexp_type {
	REGEXP_NONE = 0,
	REGEXP_HEADER,
	REGEXP_MIME,
	REGEXP_MESSAGE,
	REGEXP_URL,
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
 * Perl module list item
 */
struct perl_module {
	char *path;										/**< path to module										*/
	LIST_ENTRY (perl_module) next;					/**< chain link											*/
};

/**
 * Module option
 */
struct module_opt {
	char *param;									/**< parameter name										*/
	char *value;									/**< paramater value									*/
	LIST_ENTRY (module_opt) next;					
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
};

/**
 * Config option for importing to perl module
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
 * Structure that stores all config data
 */
struct config_file {
	memory_pool_t *cfg_pool;						/**< memory pool for config								*/
	char *cfg_name;									/**< name of config file								*/
	char *pid_file;									/**< name of pid file									*/
	char *temp_dir;									/**< dir for temp files									*/

	char *bind_host;								/**< bind line											*/
	struct in_addr bind_addr;						/**< bind address in case of TCP socket					*/
	uint16_t bind_port;								/**< bind port in case of TCP socket					*/
	uint16_t bind_family;							/**< bind type (AF_UNIX or AF_INET)						*/

	char *control_host;								/**< bind line for controller							*/
	struct in_addr control_addr;					/**< bind address for controller						*/
	uint16_t control_port;							/**< bind port for controller							*/
	uint16_t control_family;						/**< bind family for controller							*/
	int controller_enabled;							/**< whether controller is enabled						*/
	char *control_password;							/**< controller password								*/

	int no_fork;									/**< if 1 do not call daemon()							*/
	unsigned int workers_number;					/**< number of workers									*/

	enum rspamd_log_type log_type;					/**< log type											*/
	int log_facility;								/**< log facility in case of syslog						*/
	int log_level;									/**< log level trigger									*/
	char *log_file;									/**< path to logfile in case of file logging			*/
	int log_fd;										/**< log descriptor in case of file logging				*/

	size_t max_statfile_size;						/**< maximum size for statfile							*/

	struct memcached_server memcached_servers[MAX_MEMCACHED_SERVERS];	/**< memcached servers				*/
	size_t memcached_servers_num;					/**< number of memcached servers						*/
	memc_proto_t memcached_protocol;				/**< memcached protocol									*/
	unsigned int memcached_error_time;				/**< memcached error time (see upstream documentation)	*/
	unsigned int memcached_dead_time;				/**< memcached dead time								*/
	unsigned int memcached_maxerrors;				/**< maximum number of errors							*/
	unsigned int memcached_connect_timeout;			/**< connection timeout									*/

	LIST_HEAD (modulesq, perl_module) perl_modules;	/**< linked list of perl modules to load				*/

	LIST_HEAD (headersq, filter) header_filters;	/**< linked list of all header's filters				*/
	LIST_HEAD (mimesq, filter) mime_filters;		/**< linked list of all mime filters					*/
	LIST_HEAD (messagesq, filter) message_filters;	/**< linked list of all message's filters				*/
	LIST_HEAD (urlsq, filter) url_filters;			/**< linked list of all url's filters					*/
	char *header_filters_str;						/**< string of header's filters							*/
	char *mime_filters_str;							/**< string of mime's filters							*/
	char *message_filters_str;						/**< string of message's filters						*/
	char *url_filters_str;							/**< string for url's filters							*/
	GHashTable* modules_opts;						/**< hash for module options indexed by module name		*/
	GHashTable* variables;							/**< hash of $variables defined in config, indexed by variable name */
	GHashTable* metrics;							/**< hash of metrics indexed by metric name				*/
	GHashTable* factors;							/**< hash of factors indexed by symbol name				*/
	GHashTable* c_modules;							/**< hash of c modules indexed by module name			*/
	GHashTable* composite_symbols;					/**< hash of composite symbols indexed by its name		*/
	GHashTable* statfiles;							/**< hash of defined statfiles indexed by alias			*/
    GHashTable* cfg_params;							/**< all cfg params indexed by its name in this structure */
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
 * @param is_control flag that defines whether this credits are for controller
 * @return 1 if line was successfully parsed and 0 in case of error
 */
int parse_bind_line (struct config_file *cf, char *str, char is_control);

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
 * @param str incoming string
 * @param recursive whether do recursive scanning
 * @return new string with substituted variables (uses cfg memory pool for allocating)
 */
char* substitute_variable (struct config_file *cfg, char *str, u_char recursive);

/**
 * Do post load actions for config
 * @param cfg config file
 */
void post_load_config (struct config_file *cfg);

/**
 * Parse regexp line to regexp structure
 * @param pool memory pool to use
 * @param line incoming line
 * @return regexp structure or NULL in case of error
 */
struct rspamd_regexp* parse_regexp (memory_pool_t *pool, char *line);

/**
 * Parse composites line to composites structure (eg. "SYMBOL1&SYMBOL2|!SYMBOL3")
 * @param pool memory pool to use
 * @param line incoming line
 * @return expression structure or NULL in case of error
 */
struct expression* parse_expression (memory_pool_t *pool, char *line);

int yylex (void);
int yyparse (void);
void yyrestart (FILE *);
void parse_err (const char *fmt, ...);
void parse_warn (const char *fmt, ...);

#endif /* ifdef CFG_FILE_H */
/* 
 * vi:ts=4 
 */
