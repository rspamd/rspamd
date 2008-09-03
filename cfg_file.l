%x incl
%x module

%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include "cfg_file.h"
#include "cfg_yacc.h"

#define MAX_INCLUDE_DEPTH 10
YY_BUFFER_STATE include_stack[MAX_INCLUDE_DEPTH];
int include_stack_ptr = 0;

%}

%option noyywrap
%option yylineno

%%
^[ \t]*#.*						/* ignore comments */;
.include						BEGIN(incl);
.module							BEGIN(module);
tempdir							return TEMPDIR;
pidfile							return PIDFILE;
workers							return WORKERS;
error_time                      return ERROR_TIME;
dead_time                       return DEAD_TIME;
maxerrors                       return MAXERRORS;
reconnect_timeout				return RECONNECT_TIMEOUT;
connect_timeout					return CONNECT_TIMEOUT;
protocol						return PROTOCOL;
memcached						return MEMCACHED;
bind_socket						return BINDSOCK;
servers							return SERVERS;
require							return REQUIRE;
module							return MODULE;
filter							return FILTER;
metric							return METRIC;
script_header					return SCRIPT_HEADER;
script_mime						return SCRIPT_MIME;
script_message					return SCRIPT_MESSAGE;
script_url						return SCRIPT_URL;
script_chain					return SCRIPT_CHAIN;


\{								return OBRACE;
\}								return EBRACE;
;								return SEMICOLON;
,								return COMMA;
=								return EQSIGN;
yes|YES|no|NO|[yY]|[nN]			yylval.flag=parse_flag(yytext); return FLAG;
\n								/* ignore EOL */;
[ \t]+							/* ignore whitespace */;
\"[^"]+\"						yylval.string=strdup(yytext + 1); yylval.string[strlen(yylval.string) - 1] = '\0'; return QUOTEDSTRING;
\"								return QUOTE;
[0-9]+							yylval.number=strtol(yytext, NULL, 10); return NUMBER;
[0-9]+[kKmMgG]?					yylval.limit=parse_limit(yytext); return SIZELIMIT;
[0-9]+[sS]|[0-9]+[mM][sS]		yylval.seconds=parse_seconds(yytext); return SECONDS;
[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}	yylval.string=strdup(yytext); return IPADDR;
[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}	yylval.string=strdup(yytext); return IPNETWORK;
[a-zA-Z0-9.-]+:[0-9]{1,5}		yylval.string=strdup(yytext); return HOSTPORT;
[a-zA-Z0-9]+:[a-zA-Z0-9_:]+		yylval.string=strdup(yytext); return SCRIPT_PARAM;		
[a-zA-Z<][a-zA-Z@+>_-]*         yylval.string=strdup(yytext); return STRING;
\/[^/\n]+\/						yylval.string=strdup(yytext); return REGEXP;
[a-zA-Z0-9].[a-zA-Z0-9\/.-]+	yylval.string=strdup(yytext); return DOMAIN;
<incl>[ \t]*      /* eat the whitespace */
<incl>[^ \t\n]+   { /* got the include file name */
        if ( include_stack_ptr >= MAX_INCLUDE_DEPTH ) {
            yyerror ("yylex: includes nested too deeply" );
            return -1;
        }

        include_stack[include_stack_ptr++] =
            YY_CURRENT_BUFFER;

        yyin = fopen( yytext, "r" );

        if ( ! yyin ) {
            yyerror("yylex: cannot open include file");
			return -1;
		}

        yy_switch_to_buffer(
            yy_create_buffer( yyin, YY_BUF_SIZE ) );

        BEGIN(INITIAL);
        }

<<EOF>> {
        if ( --include_stack_ptr < 0 )
            {
            yyterminate();
            }

        else
            {
            yy_delete_buffer( YY_CURRENT_BUFFER );
            yy_switch_to_buffer(
                 include_stack[include_stack_ptr] );
            }
        }

<module>\n								/* ignore EOL */;
<module>[ \t]+							/* ignore whitespace */;
<module>\'[a-zA-Z0-9_-]\'	yylval.string=strdup(yytext + 1); yylval.string[strlen(yylval.string) - 1] = '\0'; return MODULE_OPT; 
<module>\{	return OBRACE;
<module>\}  return EBRACE;
<module>\;	return SEMICOLON;
<module>[a-zA-Z0-9_-]	yylval.string=strdup(yytext); return PARAM;
<module>\"[^"]+\"	yylval.string=strdup(yytext + 1); yylval.string[strlen(yylval.string) - 1] = '\0'; return QUOTEDSTRING;

%%
/* 
 * vi:ts=4 
 */
