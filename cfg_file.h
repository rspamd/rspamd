/*
 * $Id$
 */


#ifndef CFG_FILE_H
#define CFG_FILE_H

#include "config.h"
#include <sys/types.h>
#ifndef OWN_QUEUE_H
#include <sys/queue.h>
#else
#include "queue.h"
#endif
#include <netinet/in.h>
#include <sys/un.h>
#include <event.h>
#include <glib.h>
#include "upstream.h"
#include "memcached.h"
#include "filter.h"

#define DEFAULT_BIND_PORT 768
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


enum { VAL_UNDEF=0, VAL_TRUE, VAL_FALSE };

enum script_type {
	SCRIPT_HEADER,
	SCRIPT_MIME,
	SCRIPT_URL,
	SCRIPT_MESSAGE,
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

struct config_file {
	char *cfg_name;
	char *pid_file;
	char *temp_dir;

	char *bind_host;
	struct in_addr bind_addr;
	uint16_t bind_port;
	uint16_t bind_family;

	char no_fork;
	unsigned int workers_number;

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
};

int add_memcached_server (struct config_file *cf, char *str);
int parse_bind_line (struct config_file *cf, char *str);
void init_defaults (struct config_file *cfg);
void free_config (struct config_file *cfg);
char* get_module_opt (struct config_file *cfg, char *module_name, char *opt_name);
size_t parse_limit (const char *limit);
unsigned int parse_seconds (const char *t);
char parse_flag (const char *str);
char* substitute_variable (struct config_file *cfg, char *str, u_char recursive);
void post_load_config (struct config_file *cfg);

int yylex (void);
int yyparse (void);
void yyrestart (FILE *);

#endif /* ifdef CFG_FILE_H */
/* 
 * vi:ts=4 
 */
