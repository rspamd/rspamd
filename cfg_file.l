%x incl

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

static size_t
parse_limit (const char *limit)
{
	size_t result = 0;
	char *err_str;

	if (!limit || *limit == '\0') return 0;

	result = strtoul (limit, &err_str, 10);

	if (*err_str != '\0') {
		/* Megabytes */
		if (*err_str == 'm' || *err_str == 'M') {
			result *= 1048576L;
		}
		/* Kilobytes */
		else if (*err_str == 'k' || *err_str == 'K') {
			result *= 1024;
		}
		/* Gigabytes */
		else if (*err_str == 'g' || *err_str == 'G') {
			result *= 1073741824L;
		}
	}

	return result;
}

static unsigned int
parse_seconds (const char *t)
{
	unsigned int result = 0;
	char *err_str;

	if (!t || *t == '\0') return 0;

	result = strtoul (t, &err_str, 10);

	if (*err_str != '\0') {
		/* Seconds */
		if (*err_str == 's' || *err_str == 'S') {
			result *= 1000;
		}
	}

	return result;
}

static char
parse_flag (const char *str)
{
	if (!str || !*str) return -1;

	if ((*str == 'Y' || *str == 'y') && *(str + 1) == '\0') {
		return 1;
	}

	if ((*str == 'Y' || *str == 'y') &&
		(*(str + 1) == 'E' || *(str + 1) == 'e') &&
		(*(str + 2) == 'S' || *(str + 2) == 's') &&
		*(str + 3) == '\0') {
		return 1;		
	}

	if ((*str == 'N' || *str == 'n') && *(str + 1) == '\0') {
		return 0;
	}

	if ((*str == 'N' || *str == 'n') &&
		(*(str + 1) == 'O' || *(str + 1) == 'o') &&
		*(str + 2) == '\0') {
		return 0;		
	}

	return -1;
}

%}

%option noyywrap
%option yylineno

%%
^[ \t]*#.*						/* ignore comments */;
.include						BEGIN(incl);
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
[a-zA-Z<][a-zA-Z@+>_-]*         yylval.string=strdup(yytext); return STRING;
\/[^/\n]+\/						yylval.string=strdup(yytext); return REGEXP;
[a-zA-Z0-9].[a-zA-Z0-9\/.-]+	yylval.string=strdup(yytext); return DOMAIN;
[a-zA-Z0-9.-]+:[0-9]{1,5}		yylval.string=strdup(yytext); return HOSTPORT;
[a-zA-Z0-9\/.-]+				yylval.string=strdup(yytext); return FILENAME;
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

%%
/* 
 * vi:ts=4 
 */
