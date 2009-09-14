%x incl
%x module
%x lua
%x worker
%x classifier

%{

#define NO_GMIME
#include "config.h"
#include "cfg_file.h"
#include "cfg_yacc.h"
#ifdef WITH_LUA
extern void add_luabuf (const char *line);
#else 
#define add_luabuf(x) yyerror ("lua support diabled")
#endif

#define ECHO do {} while(0)

#define MAX_INCLUDE_DEPTH 10
YY_BUFFER_STATE include_stack[MAX_INCLUDE_DEPTH];
int line_stack[MAX_INCLUDE_DEPTH];
int include_stack_ptr = 0;
int nested_depth = 0;
extern struct config_file *cfg;

%}

%option noyywrap
%option yylineno

%%
[ \t]*#.*						/* ignore comments */;
.include						BEGIN(incl);
.module							BEGIN(module);
.lua							BEGIN(lua);
worker							BEGIN(worker); return WORKER;
composites						return COMPOSITES;
tempdir							return TEMPDIR;
pidfile							return PIDFILE;

view							return VIEW;
ip								return IP;
from							return FROM;
symbols							return SYMBOLS;

error_time                      return ERROR_TIME;
dead_time                       return DEAD_TIME;
maxerrors                       return MAXERRORS;
reconnect_timeout				return RECONNECT_TIMEOUT;
connect_timeout					return CONNECT_TIMEOUT;
protocol						return PROTOCOL;
memcached						return MEMCACHED;
servers							return SERVERS;

modules							return MODULES;
module_path                     return MODULE_PATH;

settings                        return SETTINGS;
user_settings                   return USER_SETTINGS;
domain_settings                 return DOMAIN_SETTINGS;

filters							return FILTERS;
factors							return FACTORS;
metric							return METRIC;
name							return NAME;
required_score					return REQUIRED_SCORE;
function						return FUNCTION;
cache_file						return CACHE_FILE;
control							return CONTROL;
password						return PASSWORD;
lmtp							return LMTP;
raw_mode						return RAW_MODE;
enabled							return ENABLED;
delivery						return DELIVERY;
agent							return AGENT;

classifier						BEGIN(classifier); return CLASSIFIER;

logging							return LOGGING;

log_type						return LOG_TYPE;
console							return LOG_TYPE_CONSOLE;
syslog							return LOG_TYPE_SYSLOG;
file							return LOG_TYPE_FILE;

log_level						return LOG_LEVEL;
DEBUG							return LOG_LEVEL_DEBUG;
INFO							return LOG_LEVEL_INFO;
WARNING							return LOG_LEVEL_WARNING;
ERROR							return LOG_LEVEL_ERROR;
log_facility					return LOG_FACILITY;
log_file						return LOG_FILENAME;
profile_file					return PROFILE_FILE;

statfile_pool_size				return STATFILE_POOL_SIZE;

\{								return OBRACE;
\}								return EBRACE;
;								return SEMICOLON;
,								return COMMA;
=								return EQSIGN;
yes|YES|no|NO|[yY]|[nN]			yylval.flag=parse_flag(yytext); return FLAG;
\n								/* ignore EOL */;
[ \t]+							/* ignore whitespace */;
\".+[^\\]\"						yylval.string=strdup(yytext + 1); yylval.string[strlen(yylval.string) - 1] = '\0'; unescape_quotes(yylval.string); return QUOTEDSTRING;
\"								return QUOTE;
\$[a-zA-Z_][a-zA-Z0-9_]+		yylval.string=strdup(yytext + 1); return VARIABLE;
[0-9]+							yylval.number=strtol(yytext, NULL, 10); return NUMBER;
-?[0-9]+\.?[0-9]*				yylval.fract=strtod(yytext, NULL); return FRACT;
[0-9]+[kKmMgG]?					yylval.limit=parse_limit(yytext); return SIZELIMIT;
[0-9]+[sS]|[0-9]+[mM][sS]		yylval.seconds=parse_seconds(yytext); return SECONDS;
[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}	yylval.string=strdup(yytext); return IPADDR;
[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}	yylval.string=strdup(yytext); return IPNETWORK;
[*a-zA-Z0-9.-]+:[0-9]{1,5}		yylval.string=strdup(yytext); return HOSTPORT;
[a-zA-Z<][a-zA-Z@+>_-]*         yylval.string=strdup(yytext); return STRING;
\/[^/\n]+\/						yylval.string=strdup(yytext); return REGEXP;
[a-zA-Z0-9].[a-zA-Z0-9\/.-]+	yylval.string=strdup(yytext); return DOMAINNAME;
<incl>[ \t]*      /* eat the whitespace */
<incl>[^ \t\n]+   { /* got the include file name */
		/* got the include file name */
		if ( include_stack_ptr >= MAX_INCLUDE_DEPTH ) {
			yyerror ("yylex: includes nested too deeply" );
			return -1;
		}

		line_stack[include_stack_ptr] = yylineno;
		include_stack[include_stack_ptr++] = YY_CURRENT_BUFFER;

		yylineno = 1;
		yyin = fopen (yytext, "r");

		if (!yyin) {
			yyerror ("yylex: cannot open include file");
			return -1;
		}

		yy_switch_to_buffer (yy_create_buffer (yyin, YY_BUF_SIZE));

		BEGIN(INITIAL);
}

<<EOF>> {
		if ( --include_stack_ptr < 0 ) {
			include_stack_ptr = 0;
			yylineno = 1;
			post_load_config (cfg);
			yyterminate ();
		}
		else {
			yy_delete_buffer (YY_CURRENT_BUFFER);
			yy_switch_to_buffer (include_stack[include_stack_ptr] );
			yylineno = line_stack[include_stack_ptr];
		}
}

<module>\n								/* ignore EOL */;
<module>[ \t]+							/* ignore whitespace */;
<module>[ \t]*#.*						/* ignore comments */;
<module>\'[a-zA-Z0-9_-]+\'	yylval.string=strdup(yytext + 1); yylval.string[strlen(yylval.string) - 1] = '\0'; return MODULE_OPT; 
<module>\{	nested_depth ++; return OBRACE;
<module>\}  if (--nested_depth == 0) { BEGIN(INITIAL); } return EBRACE;
<module>\;	return SEMICOLON;
<module>=	return EQSIGN;
<module>\$[a-zA-Z_][a-zA-Z0-9_]+		yylval.string=strdup(yytext + 1); return VARIABLE;
<module>[a-zA-Z0-9_%-]+	yylval.string=strdup(yytext); return PARAM;
<module>\".+[^\\]\"	yylval.string=strdup(yytext + 1); yylval.string[strlen(yylval.string) - 1] = '\0'; unescape_quotes(yylval.string); return QUOTEDSTRING;

<worker>\n								/* ignore EOL */;
<worker>[ \t]+							/* ignore whitespace */;
<worker>[ \t]*#.*						/* ignore comments */;
<worker>\{	nested_depth ++; return OBRACE;
<worker>\}  if (--nested_depth == 0) { BEGIN(INITIAL); } return EBRACE;
<worker>\;	return SEMICOLON;
<worker>=	return EQSIGN;
<worker>type							return TYPE;
<worker>bind_socket						return BINDSOCK;
<worker>count							return COUNT;
<worker>[0-9]+							yylval.number=strtol(yytext, NULL, 10); return NUMBER;
<worker>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}	yylval.string=strdup(yytext); return IPADDR;
<worker>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}	yylval.string=strdup(yytext); return IPNETWORK;
<worker>[*a-zA-Z0-9.-]+:[0-9]{1,5}		yylval.string=strdup(yytext); return HOSTPORT;
<worker>[a-zA-Z<][a-zA-Z@+>_-]*         yylval.string=strdup(yytext); return STRING;
<worker>\$[a-zA-Z_][a-zA-Z0-9_]+		yylval.string=strdup(yytext + 1); return VARIABLE;
<worker>\".+[^\\]\"	yylval.string=strdup(yytext + 1); yylval.string[strlen(yylval.string) - 1] = '\0'; unescape_quotes(yylval.string); return QUOTEDSTRING;

<classifier>\n								/* ignore EOL */;
<classifier>[ \t]+							/* ignore whitespace */;
<classifier>[ \t]*#.*						/* ignore comments */;
<classifier>\{	                            nested_depth ++; return OBRACE;
<classifier>\}                              if (--nested_depth == 0) { BEGIN(INITIAL); } return EBRACE;
<classifier>\;	                            return SEMICOLON;
<classifier>=	                            return EQSIGN;
<classifier>type							return TYPE;
<classifier>bind_socket						return BINDSOCK;
<classifier>count							return COUNT;
<classifier>statfile						return STATFILE;
<classifier>symbol							return SYMBOL;
<classifier>path							return PATH;
<classifier>size							return SIZE;
<classifier>tokenizer						return TOKENIZER;
<classifier>section							return SECTION;
<classifier>autolearn						return AUTOLEARN;
<classifier>min_mark						return MIN_MARK;
<classifier>max_mark						return MAX_MARK;
<classifier>[0-9]+							yylval.number=strtol(yytext, NULL, 10); return NUMBER;
<classifier>-?[0-9]+\.?[0-9]*				yylval.fract=strtod(yytext, NULL); return FRACT;
<classifier>[0-9]+[kKmMgG]?					yylval.limit=parse_limit(yytext); return SIZELIMIT;
<classifier>\$[a-zA-Z_][a-zA-Z0-9_]+		yylval.string=strdup(yytext + 1); return VARIABLE;
<classifier>[a-zA-Z0-9_%-]+	                yylval.string=strdup(yytext); return PARAM;
<classifier>\".+[^\\]\"	yylval.string=strdup(yytext + 1); yylval.string[strlen(yylval.string) - 1] = '\0'; unescape_quotes(yylval.string); return QUOTEDSTRING;

<lua>\n									/* ignore EOL */;
<lua>[ \t]+								/* ignore whitespace */;
<lua>[ \t]*#.*							/* ignore comments */;
<lua>^.endlua$							BEGIN(INITIAL);
<lua>.*									add_luabuf(yytext); return LUACODE;

%%
/* 
 * vi:ts=4 
 */
