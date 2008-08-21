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
#include "main.h"

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
	SCRIPT_CHAIN,
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

struct script_param {
	char *symbol;
	char *function;
	enum script_type type;
	LIST_ENTRY (script_param) next;
};

struct filter_chain {
	unsigned int metric;
	unsigned int scripts_number;
	LIST_HEAD (scriptq, script_param) *scripts;
	LIST_ENTRY (filter_chain) next;
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

	LIST_HEAD (perlq, filter_chain) filters;
	LIST_HEAD (modulesq, perl_module) perl_modules;
	LIST_HEAD (cmodulesq, c_module) c_modules;
};

int add_memcached_server (struct config_file *cf, char *str);
int parse_bind_line (struct config_file *cf, char *str);
void init_defaults (struct config_file *cfg);
void free_config (struct config_file *cfg);
int parse_script (char *str, struct script_param *param, enum script_type type);

int yylex (void);
int yyparse (void);
void yyrestart (FILE *);

#endif /* ifdef CFG_FILE_H */
/* 
 * vi:ts=4 
 */
