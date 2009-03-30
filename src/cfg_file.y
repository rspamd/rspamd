/* $Id$ */

%{

#include "config.h"
#include "cfg_file.h"
#include "main.h"
#include "expressions.h"
#include "classifiers/classifiers.h"
#include "tokenizers/tokenizers.h"
#ifdef WITH_LUA
#include "lua-rspamd.h"
#else
#include "perl.h"
#endif

extern struct config_file *cfg;
extern int yylineno;
extern char *yytext;

LIST_HEAD (moduleoptq, module_opt) *cur_module_opt = NULL;
struct metric *cur_metric = NULL;
struct statfile *cur_statfile = NULL;
struct statfile_section *cur_section = NULL;

%}

%union 
{
	char *string;
	size_t limit;
	char flag;
	unsigned int seconds;
	unsigned int number;
	double fract;
}

%token	ERROR STRING QUOTEDSTRING FLAG
%token  FILENAME REGEXP QUOTE SEMICOLON OBRACE EBRACE COMMA EQSIGN
%token  BINDSOCK SOCKCRED DOMAINNAME IPADDR IPNETWORK HOSTPORT NUMBER CHECK_TIMEOUT
%token  MAXSIZE SIZELIMIT SECONDS BEANSTALK MYSQL USER PASSWORD DATABASE
%token  TEMPDIR PIDFILE SERVERS ERROR_TIME DEAD_TIME MAXERRORS CONNECT_TIMEOUT PROTOCOL RECONNECT_TIMEOUT
%token  READ_SERVERS WRITE_SERVER DIRECTORY_SERVERS MAILBOX_QUERY USERS_QUERY LASTLOGIN_QUERY
%token  MEMCACHED WORKERS REQUIRE MODULE
%token  MODULE_OPT PARAM VARIABLE
%token  HEADER_FILTERS MIME_FILTERS MESSAGE_FILTERS URL_FILTERS FACTORS METRIC NAME
%token  REQUIRED_SCORE FUNCTION FRACT COMPOSITES CONTROL PASSWORD
%token  LOGGING LOG_TYPE LOG_TYPE_CONSOLE LOG_TYPE_SYSLOG LOG_TYPE_FILE
%token  LOG_LEVEL LOG_LEVEL_DEBUG LOG_LEVEL_INFO LOG_LEVEL_WARNING LOG_LEVEL_ERROR LOG_FACILITY LOG_FILENAME
%token  STATFILE ALIAS PATTERN WEIGHT STATFILE_POOL_SIZE SIZE TOKENIZER CLASSIFIER
%token	DELIVERY LMTP ENABLED AGENT SECTION

%type	<string>	STRING
%type	<string>	VARIABLE
%type	<string>	QUOTEDSTRING MODULE_OPT PARAM
%type	<string>	FILENAME 
%type   <string>  	SOCKCRED
%type	<string>	IPADDR IPNETWORK
%type	<string>	HOSTPORT
%type	<string>	DOMAINNAME
%type	<limit>		SIZELIMIT
%type	<flag>		FLAG
%type	<seconds>	SECONDS
%type	<number>	NUMBER
%type 	<string>	memcached_hosts bind_cred
%type	<fract>		FRACT
%%

file	: /* empty */
	|  file command SEMICOLON { }
	;

command	: 
	bindsock
	| control
	| tempdir
	| pidfile
	| memcached
	| workers
	| require
	| header_filters
	| mime_filters
	| message_filters
	| url_filters
	| module_opt
	| variable
	| factors
	| metric
	| composites
	| logging
	| statfile
	| statfile_pool_size
	| lmtp
	| delivery
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
		cfg->temp_dir = memory_pool_strdup (cfg->cfg_pool, $3);
		free ($3);
	}
	;

pidfile :
	PIDFILE EQSIGN QUOTEDSTRING {
		cfg->pid_file = $3;
	}
	;

control:
	CONTROL OBRACE controlbody EBRACE
	;

controlbody:
	controlcmd SEMICOLON
	| controlbody controlcmd SEMICOLON
	;

controlcmd:
	controlsock
	| controlpassword
	;

controlsock:
	BINDSOCK EQSIGN bind_cred {
		if (!parse_bind_line (cfg, $3, CRED_CONTROL)) {
			yyerror ("yyparse: parse_bind_line");
			YYERROR;
		}
		cfg->controller_enabled = 1;
		free ($3);
	}
	;
controlpassword:
	PASSWORD EQSIGN QUOTEDSTRING {
		cfg->control_password = memory_pool_strdup (cfg->cfg_pool, $3);
	}
	;

bindsock:
	BINDSOCK EQSIGN bind_cred {
		if (!parse_bind_line (cfg, $3, CRED_NORMAL)) {
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
	| DOMAINNAME {
		$$ = $1;
	}
	| HOSTPORT {
		$$ = $1;
	}
	| QUOTEDSTRING {
		$$ = $1;
	}
	;

header_filters:
	HEADER_FILTERS EQSIGN QUOTEDSTRING {
		cfg->header_filters_str = memory_pool_strdup (cfg->cfg_pool, $3);
		free ($3);
	}
	;

mime_filters:
	MIME_FILTERS EQSIGN QUOTEDSTRING {
		cfg->mime_filters_str = memory_pool_strdup (cfg->cfg_pool, $3);
		free ($3);
	}
	;

message_filters:
	MESSAGE_FILTERS EQSIGN QUOTEDSTRING {
		cfg->message_filters_str = memory_pool_strdup (cfg->cfg_pool, $3);
		free ($3);
	}
	;

url_filters:
	URL_FILTERS EQSIGN QUOTEDSTRING {
		cfg->url_filters_str = memory_pool_strdup (cfg->cfg_pool, $3);
		free ($3);
	}
	;

memcached:
	MEMCACHED OBRACE memcachedbody EBRACE
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
	| DOMAINNAME
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

metric:
	METRIC OBRACE metricbody EBRACE {
		if (cur_metric == NULL || cur_metric->name == NULL) {
			yyerror ("yyparse: not enough arguments in metric definition");
			YYERROR;
		}
		if (cur_metric->classifier == NULL) {
			cur_metric->classifier = get_classifier ("winnow");
		}
		g_hash_table_insert (cfg->metrics, cur_metric->name, cur_metric);
		cur_metric = NULL;
	}
	;

metricbody:
	| metriccmd SEMICOLON
	| metricbody metriccmd SEMICOLON
	;
metriccmd:
	| metricname
	| metricfunction
	| metricscore
	| metricclassifier
	;
	
metricname:
	NAME EQSIGN QUOTEDSTRING {
		if (cur_metric == NULL) {
			cur_metric = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct metric));
		}
		cur_metric->name = memory_pool_strdup (cfg->cfg_pool, $3);
	}
	;

metricfunction:
	FUNCTION EQSIGN QUOTEDSTRING {
		if (cur_metric == NULL) {
			cur_metric = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct metric));
		}
		cur_metric->func_name = memory_pool_strdup (cfg->cfg_pool, $3);
#ifdef WITH_LUA
		cur_metric->func = lua_consolidation_func;
#elif !defined(WITHOUT_PERL)
		cur_metric->func = perl_consolidation_func;
#else
		yyerror ("yyparse: rspamd is not compiled with perl or lua, so it is not possible to use custom consolidation functions");
#endif
	}
	;

metricscore:
	REQUIRED_SCORE EQSIGN NUMBER {
		if (cur_metric == NULL) {
			cur_metric = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct metric));
		}
		cur_metric->required_score = $3;
	}
	| REQUIRED_SCORE EQSIGN FRACT {
		if (cur_metric == NULL) {
			cur_metric = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct metric));
		}
		cur_metric->required_score = $3;
	}
	;

metricclassifier:
	CLASSIFIER EQSIGN QUOTEDSTRING {
		if (cur_metric == NULL) {
			cur_metric = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct metric));
		}
		if ((cur_metric->classifier = get_classifier ($3)) == NULL) {
			yyerror ("yyparse: unknown classifier %s", $3);
			YYERROR;
		}
	}
	;

factors:
	FACTORS OBRACE factorsbody EBRACE
	;

factorsbody:
	factorparam SEMICOLON
	| factorsbody factorparam SEMICOLON
	;

factorparam:
	QUOTEDSTRING EQSIGN FRACT {
		double *tmp = memory_pool_alloc (cfg->cfg_pool, sizeof (double));
		*tmp = $3;
		g_hash_table_insert (cfg->factors, $1, tmp);
	}
	| QUOTEDSTRING EQSIGN NUMBER {
		double *tmp = memory_pool_alloc (cfg->cfg_pool, sizeof (double));
		*tmp = $3;
		g_hash_table_insert (cfg->factors, $1, tmp);
	};

require:
	REQUIRE OBRACE requirebody EBRACE
	;

requirebody:
	requirecmd SEMICOLON
	| requirebody requirecmd SEMICOLON
	;

requirecmd:
	MODULE EQSIGN QUOTEDSTRING {
#if !defined(WITHOUT_PERL) || defined(WITH_LUA)
		struct stat st;
		struct perl_module *cur;
		if (stat ($3, &st) == -1) {
			yyerror ("yyparse: cannot stat file %s, %s", $3, strerror (errno));
			YYERROR;
		}
		cur = memory_pool_alloc (cfg->cfg_pool, sizeof (struct perl_module));
		if (cur == NULL) {
			yyerror ("yyparse: g_malloc: %s", strerror(errno));
			YYERROR;
		}
		cur->path = $3;
		LIST_INSERT_HEAD (&cfg->perl_modules, cur, next);
#else
		yyerror ("require command is not available when perl support is not compiled");
		YYERROR;
#endif
	}
	;

composites:
	COMPOSITES OBRACE compositesbody EBRACE
	;

compositesbody:
	compositescmd SEMICOLON
	| compositesbody compositescmd SEMICOLON
	;

compositescmd:
	QUOTEDSTRING EQSIGN QUOTEDSTRING {
		struct expression *expr;
		if ((expr = parse_expression (cfg->cfg_pool, $3)) == NULL) {
			yyerror ("yyparse: cannot parse composite expression: %s", $3);
			YYERROR;
		}
		g_hash_table_insert (cfg->composite_symbols, $1, expr);
	}
	;
module_opt:
	MODULE_OPT OBRACE moduleoptbody EBRACE {
		g_hash_table_insert (cfg->modules_opts, $1, cur_module_opt);
		cur_module_opt = NULL;
	}
	;

moduleoptbody:
	optcmd SEMICOLON
	| moduleoptbody optcmd SEMICOLON
	;

optcmd:
	PARAM EQSIGN QUOTEDSTRING {
		struct module_opt *mopt;
		if (cur_module_opt == NULL) {
			cur_module_opt = g_malloc (sizeof (cur_module_opt));
			LIST_INIT (cur_module_opt);
		}
		mopt = memory_pool_alloc (cfg->cfg_pool, sizeof (struct module_opt));
		mopt->param = $1;
		mopt->value = $3;
		LIST_INSERT_HEAD (cur_module_opt, mopt, next);
	}
	| VARIABLE EQSIGN QUOTEDSTRING {
		g_hash_table_insert (cfg->variables, $1, $3);
	}
	;

variable:
	VARIABLE EQSIGN QUOTEDSTRING {
		g_hash_table_insert (cfg->variables, $1, $3);
	}
	;

logging:
	LOGGING OBRACE loggingbody EBRACE
	;

loggingbody:
	loggingcmd SEMICOLON
	| loggingbody loggingcmd SEMICOLON
	;

loggingcmd:
	loggingtype
	| logginglevel
	| loggingfacility
	| loggingfile
	;

loggingtype:
	LOG_TYPE EQSIGN LOG_TYPE_CONSOLE {
		cfg->log_type = RSPAMD_LOG_CONSOLE;
	}
	| LOG_TYPE EQSIGN LOG_TYPE_SYSLOG {
		cfg->log_type = RSPAMD_LOG_SYSLOG;
	}
	| LOG_TYPE EQSIGN LOG_TYPE_FILE {
		cfg->log_type = RSPAMD_LOG_FILE;
	}
	;

logginglevel:
	LOG_LEVEL EQSIGN LOG_LEVEL_DEBUG {
		cfg->log_level = G_LOG_LEVEL_DEBUG;
	}
	| LOG_LEVEL EQSIGN LOG_LEVEL_INFO {
		cfg->log_level = G_LOG_LEVEL_INFO | G_LOG_LEVEL_MESSAGE;
	}
	| LOG_LEVEL EQSIGN LOG_LEVEL_WARNING {
		cfg->log_level = G_LOG_LEVEL_WARNING;
	}
	| LOG_LEVEL EQSIGN LOG_LEVEL_ERROR {
		cfg->log_level = G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL;
	}
	;

loggingfacility:
	LOG_FACILITY EQSIGN QUOTEDSTRING {
		if (strncasecmp ($3, "LOG_AUTH", sizeof ("LOG_AUTH") - 1) == 0) {
			cfg->log_facility = LOG_AUTH;
		}
		else if (strncasecmp ($3, "LOG_CRON", sizeof ("LOG_CRON") - 1) == 0) {
			cfg->log_facility = LOG_CRON;
		}
		else if (strncasecmp ($3, "LOG_DAEMON", sizeof ("LOG_DAEMON") - 1) == 0) {
			cfg->log_facility = LOG_DAEMON;
		}
		else if (strncasecmp ($3, "LOG_MAIL", sizeof ("LOG_MAIL") - 1) == 0) {
			cfg->log_facility = LOG_MAIL;
		}
		else if (strncasecmp ($3, "LOG_USER", sizeof ("LOG_USER") - 1) == 0) {
			cfg->log_facility = LOG_USER;
		}
		else if (strncasecmp ($3, "LOG_LOCAL0", sizeof ("LOG_LOCAL0") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL0;
		}
		else if (strncasecmp ($3, "LOG_LOCAL1", sizeof ("LOG_LOCAL1") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL1;
		}
		else if (strncasecmp ($3, "LOG_LOCAL2", sizeof ("LOG_LOCAL2") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL2;
		}
		else if (strncasecmp ($3, "LOG_LOCAL3", sizeof ("LOG_LOCAL3") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL3;
		}
		else if (strncasecmp ($3, "LOG_LOCAL4", sizeof ("LOG_LOCAL4") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL4;
		}
		else if (strncasecmp ($3, "LOG_LOCAL5", sizeof ("LOG_LOCAL5") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL5;
		}
		else if (strncasecmp ($3, "LOG_LOCAL6", sizeof ("LOG_LOCAL6") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL6;
		}
		else if (strncasecmp ($3, "LOG_LOCAL7", sizeof ("LOG_LOCAL7") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL7;
		}
		else {
			yyerror ("yyparse: invalid logging facility: %s", $3);
			YYERROR;
		}

		free ($3);
	}
	;

loggingfile:
	LOG_FILENAME EQSIGN QUOTEDSTRING {
		cfg->log_file = memory_pool_strdup (cfg->cfg_pool, $3);

		free ($3);
	}
	;

statfile:
	STATFILE OBRACE statfilebody EBRACE {
		if (cur_statfile == NULL || cur_statfile->alias == NULL || cur_statfile->pattern == NULL 
			|| cur_statfile->weight == 0 || cur_statfile->size == 0) {
			yyerror ("yyparse: not enough arguments in statfile definition");
			YYERROR;
		}
		if (cur_statfile->metric == NULL) {
			cur_statfile->metric = memory_pool_strdup (cfg->cfg_pool, "default");
		}
		if (cur_statfile->tokenizer == NULL) {
			cur_statfile->tokenizer = get_tokenizer ("osb-text");
		}
		g_hash_table_insert (cfg->statfiles, cur_statfile->alias, cur_statfile);
		cur_statfile = NULL;
	}
	;

statfilebody:
	| statfilecmd SEMICOLON
	| statfilebody statfilecmd SEMICOLON
	;

statfilecmd:
	| statfilealias
	| statfilepattern
	| statfileweight
	| statfilesize
	| statfilemetric
	| statfiletokenizer
	| statfilesection
	;
	
statfilealias:
	ALIAS EQSIGN QUOTEDSTRING {
		if (cur_statfile == NULL) {
			cur_statfile = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile));
		}
		cur_statfile->alias = memory_pool_strdup (cfg->cfg_pool, $3);
	}
	;

statfilepattern:
	PATTERN EQSIGN QUOTEDSTRING {
		if (cur_statfile == NULL) {
			cur_statfile = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile));
		}
		cur_statfile->pattern = memory_pool_strdup (cfg->cfg_pool, $3);
	}
	;

statfileweight:
	WEIGHT EQSIGN NUMBER {
		if (cur_statfile == NULL) {
			cur_statfile = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile));
		}
		cur_statfile->weight = $3;
	}
	| WEIGHT EQSIGN FRACT {
		if (cur_statfile == NULL) {
			cur_statfile = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile));
		}
		cur_statfile->weight = $3;
	}
	;

statfilesize:
	SIZE EQSIGN NUMBER {
		if (cur_statfile == NULL) {
			cur_statfile = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile));
		}
		cur_statfile->size = $3;
	}
	| SIZE EQSIGN SIZELIMIT {
		if (cur_statfile == NULL) {
			cur_statfile = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile));
		}
		cur_statfile->size = $3;
	}
	;

statfilemetric:
	METRIC EQSIGN QUOTEDSTRING {
		if (cur_statfile == NULL) {
			cur_statfile = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile));
		}
		cur_statfile->metric = memory_pool_strdup (cfg->cfg_pool, $3);
	}
	;

statfiletokenizer:
	TOKENIZER EQSIGN QUOTEDSTRING {
		if (cur_statfile == NULL) {
			cur_statfile = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile));
		}
		if ((cur_statfile->tokenizer = get_tokenizer ($3)) == NULL) {
			yyerror ("yyparse: unknown tokenizer %s", $3);
			YYERROR;
		}
	}
	;

statfilesection:
	SECTION OBRACE sectionbody EBRACE {
		if (cur_statfile == NULL) {
			cur_statfile = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile));
		}
		if (cur_section == NULL || cur_section->code == 0) {
			yyerror ("yyparse: error in section definition");
			YYERROR;
		}
		cur_statfile->sections = g_list_prepend (cur_statfile->sections, cur_section);
		cur_section = NULL;
	}
	;

sectionbody:
	sectioncmd SEMICOLON
	| sectionbody sectioncmd SEMICOLON
	;

sectioncmd:
	sectionname
	| sectionsize
	| sectionweight
	;

sectionname:
	NAME EQSIGN QUOTEDSTRING {
		if (cur_section == NULL) {
			cur_section = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile_section));
		}
		cur_section->code = statfile_get_section_by_name ($3);
	}
	;

sectionsize:
	SIZE EQSIGN NUMBER {
		if (cur_section == NULL) {
			cur_section = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile_section));
		}
		cur_section->size = $3;
	}
	| SIZE EQSIGN SIZELIMIT {
		if (cur_section == NULL) {
			cur_section = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile_section));
		}
		cur_section->size = $3;
	}
	;

sectionweight:
	WEIGHT EQSIGN NUMBER {
		if (cur_section == NULL) {
			cur_section = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile_section));
		}
		cur_section->weight = $3;
	}
	| WEIGHT EQSIGN FRACT {
		if (cur_section == NULL) {
			cur_section = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile_section));
		}
		cur_section->weight = $3;
	}
	;

statfile_pool_size:
	STATFILE_POOL_SIZE EQSIGN SIZELIMIT {
		cfg->max_statfile_size = $3;
	}
	| STATFILE_POOL_SIZE EQSIGN NUMBER {
		cfg->max_statfile_size = $3;
	}
	;

lmtp:
	LMTP OBRACE lmtpbody EBRACE
	;

lmtpbody:
	lmtpcmd SEMICOLON
	| lmtpbody lmtpcmd SEMICOLON
	;

lmtpcmd:
	lmtpenabled
	| lmtpsock
	| lmtpmetric
	| lmtpworkers
	;

lmtpenabled:
	ENABLED EQSIGN FLAG {
		cfg->lmtp_enable = $3;
	}
	;

lmtpsock:
	BINDSOCK EQSIGN bind_cred {
		if (!parse_bind_line (cfg, $3, CRED_LMTP)) {
			yyerror ("yyparse: parse_bind_line");
			YYERROR;
		}
		free ($3);
	}
	;
lmtpmetric:
	METRIC EQSIGN QUOTEDSTRING {
		cfg->lmtp_metric = memory_pool_strdup (cfg->cfg_pool, $3);
	}
	;
lmtpworkers:
	WORKERS EQSIGN NUMBER {
		cfg->lmtp_workers_number = $3;
	}
	;

delivery:
	DELIVERY OBRACE deliverybody EBRACE
	;

deliverybody:
	deliverycmd SEMICOLON
	| deliverybody deliverycmd SEMICOLON
	;

deliverycmd:
	deliveryenabled
	| deliverysock
	| deliveryagent
	| deliverylmtp
	;

deliveryenabled:
	ENABLED EQSIGN FLAG {
		cfg->delivery_enable = $3;
	}
	;

deliverysock:
	BINDSOCK EQSIGN bind_cred {
		if (!parse_bind_line (cfg, $3, CRED_DELIVERY)) {
			yyerror ("yyparse: parse_bind_line");
			YYERROR;
		}
		free ($3);
	}
	;
deliverylmtp:
	LMTP EQSIGN FLAG {
		cfg->deliver_lmtp = $3;
	}
	;
deliveryagent:
	AGENT EQSIGN QUOTEDSTRING {
		cfg->deliver_agent_path = memory_pool_strdup (cfg->cfg_pool, $3);
	}
	;

%%
/* 
 * vi:ts=4 
 */
