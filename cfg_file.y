/* $Id$ */

%{

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <glib.h>

#include "cfg_file.h"

#define YYDEBUG 1

extern struct config_file *cfg;
extern int yylineno;
extern char *yytext;

struct scriptq *cur_scripts;

%}

%union 
{
	char *string;
	size_t limit;
	char flag;
	unsigned int seconds;
	unsigned int number;
	struct script_param *param;
}

%token	ERROR STRING QUOTEDSTRING FLAG
%token  FILENAME REGEXP QUOTE SEMICOLON OBRACE EBRACE COMMA EQSIGN
%token  BINDSOCK SOCKCRED DOMAIN IPADDR IPNETWORK HOSTPORT NUMBER CHECK_TIMEOUT
%token  MAXSIZE SIZELIMIT SECONDS BEANSTALK MYSQL USER PASSWORD DATABASE
%token  TEMPDIR PIDFILE SERVERS ERROR_TIME DEAD_TIME MAXERRORS CONNECT_TIMEOUT PROTOCOL RECONNECT_TIMEOUT
%token  READ_SERVERS WRITE_SERVER DIRECTORY_SERVERS MAILBOX_QUERY USERS_QUERY LASTLOGIN_QUERY
%token  MEMCACHED WORKERS REQUIRE MODULE
%token  FILTER METRIC SCRIPT_HEADER SCRIPT_MIME SCRIPT_MESSAGE SCRIPT_URL SCRIPT_CHAIN SCRIPT_PARAM

%type	<string>	STRING
%type	<string>	QUOTEDSTRING
%type	<string>	FILENAME 
%type   <string>  	SOCKCRED
%type	<string>	IPADDR IPNETWORK
%type	<string>	HOSTPORT
%type	<string>	DOMAIN
%type	<string>	SCRIPT_PARAM
%type	<limit>		SIZELIMIT
%type	<flag>		FLAG
%type	<seconds>	SECONDS
%type	<number>	NUMBER
%type 	<string>	memcached_hosts bind_cred
%type	<number>	metric
%type	<param>		filter_param
%%

file	: /* empty */
	|  file command SEMICOLON { }
	;

command	: 
	bindsock
	| tempdir
	| pidfile
	| memcached
	| workers
	| require
	| filter
	;

tempdir :
	TEMPDIR EQSIGN QUOTEDSTRING {
		struct stat st;
		
		if (stat ($3, &st) == -1) {
			yyerror ("yyparse: cannot stat directory \"%s\": %s", $3, strerror (errno)); 
			YYERROR;
		}
		if (!S_ISDIR (st.st_mode)) {
			yyerror ("yyparse: \"%s\" is not a directory", $3); 
			YYERROR;
		}
		cfg->temp_dir = $3;
	}
	;

pidfile :
	PIDFILE EQSIGN QUOTEDSTRING {
		cfg->pid_file = $3;
	}
	;

bindsock:
	BINDSOCK EQSIGN bind_cred {
		if (!parse_bind_line (cfg, $3)) {
			yyerror ("yyparse: parse_bind_line");
			YYERROR;
		}		
		free ($3);
	}
	;

bind_cred:
	STRING {
		$$ = $1;
	}
	| IPADDR{
		$$ = $1;
	}
	| DOMAIN {
		$$ = $1;
	}
	| HOSTPORT {
		$$ = $1;
	}
	| QUOTEDSTRING {
		$$ = $1;
	}
	;

memcached:
	BEANSTALK OBRACE memcachedbody EBRACE
	;

memcachedbody:
	memcachedcmd SEMICOLON
	| memcachedbody memcachedcmd SEMICOLON
	;

memcachedcmd:
	memcached_servers
	| memcached_connect_timeout
	| memcached_error_time
	| memcached_dead_time
	| memcached_maxerrors
	| memcached_protocol
	;

memcached_servers:
	SERVERS EQSIGN memcached_server
	;

memcached_server:
	memcached_params
	| memcached_server COMMA memcached_params
	;

memcached_params:
	memcached_hosts {
		if (!add_memcached_server (cfg, $1)) {
			yyerror ("yyparse: add_memcached_server");
			YYERROR;
		}
		free ($1);
	}
	;
memcached_hosts:
	STRING
	| IPADDR
	| DOMAIN
	| HOSTPORT
	;
memcached_error_time:
	ERROR_TIME EQSIGN NUMBER {
		cfg->memcached_error_time = $3;
	}
	;
memcached_dead_time:
	DEAD_TIME EQSIGN NUMBER {
		cfg->memcached_dead_time = $3;
	}
	;
memcached_maxerrors:
	MAXERRORS EQSIGN NUMBER {
		cfg->memcached_maxerrors = $3;
	}
	;
memcached_connect_timeout:
	CONNECT_TIMEOUT EQSIGN SECONDS {
		cfg->memcached_connect_timeout = $3;
	}
	;

memcached_protocol:
	PROTOCOL EQSIGN STRING {
		if (strncasecmp ($3, "udp", sizeof ("udp") - 1) == 0) {
			cfg->memcached_protocol = UDP_TEXT;
		}
		else if (strncasecmp ($3, "tcp", sizeof ("tcp") - 1) == 0) {
			cfg->memcached_protocol = TCP_TEXT;
		}
		else {
			yyerror ("yyparse: cannot recognize protocol: %s", $3);
			YYERROR;
		}
	}
	;
workers:
	WORKERS EQSIGN NUMBER {
		cfg->workers_number = $3;
	}
	;

filter:
	FILTER OBRACE filterbody EBRACE
	;

filterbody:
	metric SEMICOLON filter_chain {
		struct filter_chain *cur_chain;
		cur_chain = (struct filter_chain *) g_malloc (sizeof (struct filter_chain));
		if (cur_chain == NULL) {
			yyerror ("yyparse: g_malloc: %s", strerror (errno));
			YYERROR;
		}

		cur_chain->metric = $1;
		cur_chain->scripts = cur_scripts;
		LIST_INSERT_HEAD (&cfg->filters, cur_chain, next);

	}
	;

metric:
	METRIC EQSIGN NUMBER {
		$$ = $3;
	}
	;

filter_chain:
	filter_param SEMICOLON	{
		cur_scripts = (struct scriptq *)g_malloc (sizeof (struct scriptq));
		if (cur_scripts == NULL) {
			yyerror ("yyparse: g_malloc: %s", strerror (errno));
			YYERROR;
		}
		LIST_INIT (cur_scripts);
		if ($1 == NULL) {
			yyerror ("yyparse: g_malloc: %s", strerror(errno));
			YYERROR;
		}
		LIST_INSERT_HEAD (cur_scripts, $1, next);
	}
	| filter_chain filter_param SEMICOLON	{
		if ($2 == NULL) {
			yyerror ("yyparse: g_malloc: %s", strerror(errno));
			YYERROR;
		}
		LIST_INSERT_HEAD (cur_scripts, $2, next);
	}
	;

filter_param:
	SCRIPT_HEADER EQSIGN SCRIPT_PARAM {
		struct script_param *cur;

		cur = g_malloc (sizeof (struct script_param));
		if (cur == NULL) {
			yyerror ("yyparse: g_malloc: %s", strerror(errno));
			YYERROR;
		}
		if (parse_script ($3, cur, SCRIPT_HEADER) == -1) {
			yyerror ("yyparse: cannot parse filter param %s", $3);
			YYERROR;
		}

		$$ = cur;
		free ($3);
	}
	| SCRIPT_MIME EQSIGN SCRIPT_PARAM {
		struct script_param *cur;

		cur = g_malloc (sizeof (struct script_param));
		if (cur == NULL) {
			yyerror ("yyparse: g_malloc: %s", strerror(errno));
			YYERROR;
		}
		if (parse_script ($3, cur, SCRIPT_MIME) == -1) {
			yyerror ("yyparse: cannot parse filter param %s", $3);
			YYERROR;
		}

		$$ = cur;
		free ($3);
	}
	| SCRIPT_MESSAGE EQSIGN SCRIPT_PARAM {
		struct script_param *cur;

		cur = g_malloc (sizeof (struct script_param));
		if (cur == NULL) {
			yyerror ("yyparse: g_malloc: %s", strerror(errno));
			YYERROR;
		}
		if (parse_script ($3, cur, SCRIPT_MESSAGE) == -1) {
			yyerror ("yyparse: cannot parse filter param %s", $3);
			YYERROR;
		}

		$$ = cur;
		free ($3);
	}
	| SCRIPT_URL EQSIGN SCRIPT_PARAM {
		struct script_param *cur;

		cur = g_malloc (sizeof (struct script_param));
		if (cur == NULL) {
			yyerror ("yyparse: g_malloc: %s", strerror(errno));
			YYERROR;
		}
		if (parse_script ($3, cur, SCRIPT_URL) == -1) {
			yyerror ("yyparse: cannot parse filter param %s", $3);
			YYERROR;
		}

		$$ = cur;
		free ($3);
	}
	| SCRIPT_CHAIN EQSIGN SCRIPT_PARAM {
		struct script_param *cur;

		cur = g_malloc (sizeof (struct script_param));
		if (cur == NULL) {
			yyerror ("yyparse: g_malloc: %s", strerror(errno));
			YYERROR;
		}
		if (parse_script ($3, cur, SCRIPT_CHAIN) == -1) {
			yyerror ("yyparse: cannot parse filter param %s", $3);
			YYERROR;
		}

		$$ = cur;
		free ($3);
	}
	;

require:
	REQUIRE OBRACE requirebody EBRACE
	;

requirebody:
	requirecmd SEMICOLON
	| requirebody requirecmd SEMICOLON
	;

requirecmd:
	MODULE EQSIGN QUOTEDSTRING {
		struct stat st;
		struct perl_module *cur;
		if (stat ($3, &st) == -1) {
			yyerror ("yyparse: cannot stat file %s, %m", $3);
			YYERROR;
		}
		cur = g_malloc (sizeof (struct perl_module));
		if (cur == NULL) {
			yyerror ("yyparse: g_malloc: %s", strerror(errno));
			YYERROR;
		}
		cur->path = $3;
		LIST_INSERT_HEAD (&cfg->modules, cur, next);
	}
	;

%%
/* 
 * vi:ts=4 
 */
