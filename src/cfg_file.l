%x incl
%x module_lex_state
%x lua_lex_state
%x worker_lex_state
%x classifier_lex_state

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
.module							BEGIN(module_lex_state);
.lua							BEGIN(lua_lex_state);
worker							BEGIN(worker_lex_state); return WORKER;
composites						BEGIN(module_lex_state);return COMPOSITES;
tempdir							return TEMPDIR;
pidfile							return PIDFILE;

view							return VIEW;
ip								return IP;
client_ip						return CLIENT_IP;
from							return FROM;
symbols							return SYMBOLS;
skip_check						return SKIP_CHECK;

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

maxfiles						return MAXFILES;
maxcore							return MAXCORE;

filters							return FILTERS;
factors							return FACTORS;
grow_factor						return GROW_FACTOR;
metric							return METRIC;
name							return NAME;
required_score					return REQUIRED_SCORE;
reject_score					return REJECT_SCORE;
function						return FUNCTION;
cache_file						return CACHE_FILE;
control							return CONTROL;
password						return PASSWORD;
lmtp							return LMTP;
raw_mode						return RAW_MODE;
enabled							return ENABLED;
delivery						return DELIVERY;
agent							return AGENT;

classifier						BEGIN(classifier_lex_state); return CLASSIFIER;

logging							return LOGGING;

log_type						return LOG_TYPE;
console							return LOG_TYPE_CONSOLE;
syslog							return LOG_TYPE_SYSLOG;
file							return LOG_TYPE_FILE;
log_urls						return LOG_URLS;

log_level						return LOG_LEVEL;
DEBUG							return LOG_LEVEL_DEBUG;
INFO							return LOG_LEVEL_INFO;
WARNING							return LOG_LEVEL_WARNING;
ERROR							return LOG_LEVEL_ERROR;
log_facility					return LOG_FACILITY;
log_file						return LOG_FILENAME;
log_buffer                      return LOG_BUFFER;
debug_ip                        return DEBUG_IP;
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
[0-9]+[mMsShHdD]?				yylval.seconds=parse_seconds(yytext); return SECONDS;
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

<module_lex_state>\n								/* ignore EOL */;
<module_lex_state>[ \t]+							/* ignore whitespace */;
<module_lex_state>[ \t]*#.*						/* ignore comments */;
<module_lex_state>\'[a-zA-Z0-9_-]+\'	yylval.string=strdup(yytext + 1); yylval.string[strlen(yylval.string) - 1] = '\0'; return MODULE_OPT; 
<module_lex_state>\{	nested_depth ++; return OBRACE;
<module_lex_state>\}  if (--nested_depth == 0) { BEGIN(INITIAL); } return EBRACE;
<module_lex_state>\;	return SEMICOLON;
<module_lex_state>=	return EQSIGN;
<module_lex_state>\$[a-zA-Z_][a-zA-Z0-9_]+		yylval.string=strdup(yytext + 1); return VARIABLE;
<module_lex_state>[a-zA-Z0-9_%-]+	yylval.string=strdup(yytext); return PARAM;
<module_lex_state>\".+[^\\]\"	yylval.string=strdup(yytext + 1); yylval.string[strlen(yylval.string) - 1] = '\0'; unescape_quotes(yylval.string); return QUOTEDSTRING;

<worker_lex_state>\n								/* ignore EOL */;
<worker_lex_state>[ \t]+							/* ignore whitespace */;
<worker_lex_state>[ \t]*#.*						/* ignore comments */;
<worker_lex_state>\{	nested_depth ++; return OBRACE;
<worker_lex_state>\}  if (--nested_depth == 0) { BEGIN(INITIAL); } return EBRACE;
<worker_lex_state>\;	return SEMICOLON;
<worker_lex_state>=	return EQSIGN;
<worker_lex_state>type							return TYPE;
<worker_lex_state>bind_socket						return BINDSOCK;
<worker_lex_state>count							return COUNT;
<worker_lex_state>[0-9]+							yylval.number=strtol(yytext, NULL, 10); return NUMBER;
<worker_lex_state>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}	yylval.string=strdup(yytext); return IPADDR;
<worker_lex_state>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}	yylval.string=strdup(yytext); return IPNETWORK;
<worker_lex_state>[*a-zA-Z0-9.-]+:[0-9]{1,5}		yylval.string=strdup(yytext); return HOSTPORT;
<worker_lex_state>[a-zA-Z<][a-zA-Z@+>_-]*         yylval.string=strdup(yytext); return STRING;
<worker_lex_state>\$[a-zA-Z_][a-zA-Z0-9_]+		yylval.string=strdup(yytext + 1); return VARIABLE;
<worker_lex_state>\".+[^\\]\"	yylval.string=strdup(yytext + 1); yylval.string[strlen(yylval.string) - 1] = '\0'; unescape_quotes(yylval.string); return QUOTEDSTRING;

<classifier_lex_state>\n							/* ignore EOL */;
<classifier_lex_state>[ \t]+						/* ignore whitespace */;
<classifier_lex_state>[ \t]*#.*						/* ignore comments */;
<classifier_lex_state>\{	                        nested_depth ++; return OBRACE;
<classifier_lex_state>\}                            if (--nested_depth == 0) { BEGIN(INITIAL); } return EBRACE;
<classifier_lex_state>\;                            return SEMICOLON;
<classifier_lex_state>=	                            return EQSIGN;
<classifier_lex_state>type							return TYPE;
<classifier_lex_state>bind_socket					return BINDSOCK;
<classifier_lex_state>count							return COUNT;
<classifier_lex_state>statfile						return STATFILE;
<classifier_lex_state>symbol						return SYMBOL;
<classifier_lex_state>path							return PATH;
<classifier_lex_state>size							return SIZE;
<classifier_lex_state>tokenizer						return TOKENIZER;
<classifier_lex_state>section						return SECTION;
<classifier_lex_state>autolearn						return AUTOLEARN;
<classifier_lex_state>min_mark						return MIN_MARK;
<classifier_lex_state>max_mark						return MAX_MARK;
<classifier_lex_state>binlog						return BINLOG;
<classifier_lex_state>binlog_master					return BINLOG_MASTER;
<classifier_lex_state>binlog_rotate					return BINLOG_ROTATE;
<classifier_lex_state>normalizer					return NORMALIZER;
<classifier_lex_state>[0-9]+							yylval.number=strtol(yytext, NULL, 10); return NUMBER;
<classifier_lex_state>-?[0-9]+\.?[0-9]*				yylval.fract=strtod(yytext, NULL); return FRACT;
<classifier_lex_state>[0-9]+[kKmMgG]?					yylval.limit=parse_limit(yytext); return SIZELIMIT;
<classifier_lex_state>[0-9]+[mMsShHdD]?				yylval.seconds=parse_seconds(yytext); return SECONDS;
<classifier_lex_state>\$[a-zA-Z_][a-zA-Z0-9_]+		yylval.string=strdup(yytext + 1); return VARIABLE;
<classifier_lex_state>[a-zA-Z0-9_%-]+	                yylval.string=strdup(yytext); return PARAM;
<classifier_lex_state>\".+[^\\]\"	yylval.string=strdup(yytext + 1); yylval.string[strlen(yylval.string) - 1] = '\0'; unescape_quotes(yylval.string); return QUOTEDSTRING;

<lua_lex_state>\n									/* ignore EOL */;
<lua_lex_state>[ \t]+								/* ignore whitespace */;
<lua_lex_state>[ \t]*#.*							/* ignore comments */;
<lua_lex_state>^.endlua$							BEGIN(INITIAL);
<lua_lex_state>.*									add_luabuf(yytext); return LUACODE;

%%
/* 
 * vi:ts=4 
 */
