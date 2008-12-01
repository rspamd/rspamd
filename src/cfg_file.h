/*
 * $Id$
 */


#ifndef CFG_FILE_H
#define CFG_FILE_H

#include "config.h"
#include <sys/types.h>
#ifndef HAVE_OWN_QUEUE_H
#include <sys/queue.h>
#else
#include "queue.h"
#endif
#include <netinet/in.h>
#include <sys/un.h>
#include <event.h>
#include <glib.h>
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

/* 1 worker by default */
#define DEFAULT_WORKERS_NUM 1

#define yyerror(fmt, ...) \
		fprintf (stderr, "Config file parse error!\non line: %d\n", yylineno); \
		fprintf (stderr, "while reading text: %s\nreason: ", yytext); \
		fprintf (stderr, fmt, ##__VA_ARGS__); \
		fprintf (stderr, "\n")
#define yywarn(fmt, ...) \
		fprintf (stderr, "Config file parse warning!\non line %d\n", yylineno); \
		fprintf (stderr, "while reading text: %s\nreason: ", yytext); \
		fprintf (stderr, fmt, ##__VA_ARGS__); \
		fprintf (stderr, "\n")

struct expression;

enum { VAL_UNDEF=0, VAL_TRUE, VAL_FALSE };

enum rspamd_regexp_type {
	REGEXP_NONE = 0,
	REGEXP_HEADER,
	REGEXP_MIME,
	REGEXP_MESSAGE,
	REGEXP_URL,
};

enum rspamd_log_type {
	RSPAMD_LOG_CONSOLE,
	RSPAMD_LOG_SYSLOG,
	RSPAMD_LOG_FILE,
};

struct rspamd_regexp {
	enum rspamd_regexp_type type;
	char *regexp_text;
	GRegex *regexp;
	char *header;
};

struct memcached_server {
	struct upstream up;
	struct in_addr addr;
	uint16_t port;
	short alive;
	short int num;
};

struct perl_module {
	char *path;
	LIST_ENTRY (perl_module) next;
};

struct module_opt {
	char *param;
	char *value;
	LIST_ENTRY (module_opt) next;
};

struct statfile {
	char *alias;
	char *pattern;
	double weight;	
};

struct config_file {
	memory_pool_t *cfg_pool;
	char *cfg_name;
	char *pid_file;
	char *temp_dir;

	char *bind_host;
	struct in_addr bind_addr;
	uint16_t bind_port;
	uint16_t bind_family;

	char *control_host;
	struct in_addr control_addr;
	uint16_t control_port;
	uint16_t control_family;
	int controller_enabled;
	char *control_password;

	int no_fork;
	unsigned int workers_number;

	enum rspamd_log_type log_type;
	int log_facility;
	int log_level;
	char *log_file;
	int log_fd;

	struct memcached_server memcached_servers[MAX_MEMCACHED_SERVERS];
	size_t memcached_servers_num;
	memc_proto_t memcached_protocol;	
	unsigned int memcached_error_time;
	unsigned int memcached_dead_time;
	unsigned int memcached_maxerrors;
	unsigned int memcached_connect_timeout;

	LIST_HEAD (modulesq, perl_module) perl_modules;
	LIST_HEAD (headersq, filter) header_filters;
	LIST_HEAD (mimesq, filter) mime_filters;
	LIST_HEAD (messagesq, filter) message_filters;
	LIST_HEAD (urlsq, filter) url_filters;
	char *header_filters_str;
	char *mime_filters_str;
	char *message_filters_str;
	char *url_filters_str;
	GHashTable* modules_opts;
	GHashTable* variables;
	GHashTable* metrics;
	GHashTable* factors;
	GHashTable* c_modules;
	GHashTable* composite_symbols;
	GHashTable* statfiles;
};

int add_memcached_server (struct config_file *cf, char *str);
int parse_bind_line (struct config_file *cf, char *str, char is_control);
void init_defaults (struct config_file *cfg);
void free_config (struct config_file *cfg);
char* get_module_opt (struct config_file *cfg, char *module_name, char *opt_name);
size_t parse_limit (const char *limit);
unsigned int parse_seconds (const char *t);
char parse_flag (const char *str);
char* substitute_variable (struct config_file *cfg, char *str, u_char recursive);
void post_load_config (struct config_file *cfg);
struct rspamd_regexp* parse_regexp (memory_pool_t *pool, char *line);
struct expression* parse_expression (memory_pool_t *pool, char *line);

int yylex (void);
int yyparse (void);
void yyrestart (FILE *);

#endif /* ifdef CFG_FILE_H */
/* 
 * vi:ts=4 
 */
