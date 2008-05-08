/* $Id$ */

%{

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cfg_file.h"

#define YYDEBUG 0

extern struct config_file *cfg;
extern int yylineno;
extern char *yytext;


%}
%union 
{
	char *string;
	size_t limit;
	char flag;
	unsigned int seconds;
	unsigned int number;
}

%token	ERROR STRING QUOTEDSTRING FLAG
%token  FILENAME REGEXP QUOTE SEMICOLON OBRACE EBRACE COMMA EQSIGN
%token  BINDSOCK SOCKCRED DOMAIN IPADDR IPNETWORK HOSTPORT NUMBER CHECK_TIMEOUT
%token  MAXSIZE SIZELIMIT SECONDS BEANSTALK MYSQL USER PASSWORD DATABASE
%token  TEMPDIR PIDFILE SERVERS ERROR_TIME DEAD_TIME MAXERRORS CONNECT_TIMEOUT PROTOCOL RECONNECT_TIMEOUT
%token  READ_SERVERS WRITE_SERVER DIRECTORY_SERVERS MAILBOX_QUERY USERS_QUERY LASTLOGIN_QUERY
%token  MEMCACHED WORKERS

%type	<string>	STRING
%type	<string>	QUOTEDSTRING
%type	<string>	FILENAME
%type   <string>  	SOCKCRED
%type	<string>	IPADDR IPNETWORK
%type	<string>	HOSTPORT
%type	<string>	DOMAIN
%type	<limit>		SIZELIMIT
%type	<flag>		FLAG
%type	<seconds>	SECONDS
%type	<number>	NUMBER
%type 	<string>	memcached_hosts bind_cred
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
	;

tempdir :
	TEMPDIR EQSIGN FILENAME {
		cfg->temp_dir = $3;
	}
	;

pidfile :
	PIDFILE EQSIGN FILENAME {
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
	| FILENAME {
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
%%
/* 
 * vi:ts=4 
 */
