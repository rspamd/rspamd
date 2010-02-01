/* $Id$ */

%{

#include "config.h"
#include "cfg_file.h"
#include "main.h"
#include "expressions.h"
#include "classifiers/classifiers.h"
#include "tokenizers/tokenizers.h"
#include "view.h"
#include "settings.h"
#ifdef WITH_LUA
#include "lua/lua_common.h"
#else
#include "perl.h"
#endif
#define YYDEBUG 1

extern struct config_file *cfg;
extern int yylineno;
extern char *yytext;

GList *cur_module_opt = NULL;
struct metric *cur_metric = NULL;
struct classifier_config *cur_classifier = NULL;
struct statfile *cur_statfile = NULL;
struct statfile_section *cur_section = NULL;
struct statfile_autolearn_params *cur_autolearn = NULL;
struct worker_conf *cur_worker = NULL;

struct rspamd_view *cur_view = NULL;

%}

%union 
{
	char *string;
	size_t limit;
	gboolean flag;
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
%token  MEMCACHED WORKER TYPE MODULES MODULE_PATH
%token  MODULE_OPT PARAM VARIABLE
%token  FILTERS FACTORS METRIC NAME CACHE_FILE
%token  REQUIRED_SCORE REJECT_SCORE FUNCTION FRACT COMPOSITES CONTROL PASSWORD
%token  LOGGING LOG_TYPE LOG_TYPE_CONSOLE LOG_TYPE_SYSLOG LOG_TYPE_FILE
%token  LOG_LEVEL LOG_LEVEL_DEBUG LOG_LEVEL_INFO LOG_LEVEL_WARNING LOG_LEVEL_ERROR LOG_FACILITY LOG_FILENAME LOG_URLS
%token  STATFILE ALIAS PATTERN WEIGHT STATFILE_POOL_SIZE SIZE TOKENIZER CLASSIFIER BINLOG BINLOG_MASTER BINLOG_ROTATE
%token	DELIVERY LMTP ENABLED AGENT SECTION LUACODE RAW_MODE PROFILE_FILE COUNT
%token  VIEW IP FROM SYMBOLS CLIENT_IP
%token  AUTOLEARN MIN_MARK MAX_MARK MAXFILES MAXCORE
%token  SETTINGS USER_SETTINGS DOMAIN_SETTINGS SYMBOL PATH SKIP_CHECK GROW_FACTOR
%token  LOG_BUFFER DEBUG_IP NORMALIZER HEADER_ONLY

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
	| tempdir
	| pidfile
	| memcached
	| worker
	| modules
	| filters
	| module_opt
	| variable
	| factors
	| metric
	| composites
	| logging
    | classifier
	| statfile_pool_size
	| luacode
	| raw_mode
	| profile_file
	| view
    | settings
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
		if (cfg->pid_file == NULL) {
			/* Allow override this value from command line */
			cfg->pid_file = $3;
		}
	}
	;


filters:
	FILTERS EQSIGN QUOTEDSTRING {
		cfg->filters_str = memory_pool_strdup (cfg->cfg_pool, $3);
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

/* Workers section */
worker:
	WORKER OBRACE workerbody EBRACE {
		cfg->workers = g_list_prepend (cfg->workers, cur_worker);
		cur_worker = NULL;
	}
	;

workerbody:
	workercmd SEMICOLON
	| workerbody workercmd SEMICOLON
	;

workercmd:
	| bindsock
	| workertype
	| workercount
	| workerlimitfiles
	| workerlimitcore
	| workerparam
	;

bindsock:
	BINDSOCK EQSIGN bind_cred {
		cur_worker = check_worker_conf (cfg, cur_worker);

		if (!parse_bind_line (cfg, cur_worker, $3)) {
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

workertype:
	TYPE EQSIGN QUOTEDSTRING {
		cur_worker = check_worker_conf (cfg, cur_worker);
		if (g_ascii_strcasecmp ($3, "normal") == 0) {
			cur_worker->type = TYPE_WORKER;
			cur_worker->has_socket = TRUE;
		}
		else if (g_ascii_strcasecmp ($3, "controller") == 0) {
			cur_worker->type = TYPE_CONTROLLER;
			cur_worker->has_socket = TRUE;
		}
		else if (g_ascii_strcasecmp ($3, "lmtp") == 0) {
			cur_worker->type = TYPE_LMTP;
			cur_worker->has_socket = TRUE;
		}
		else if (g_ascii_strcasecmp ($3, "fuzzy") == 0) {
			cur_worker->type = TYPE_FUZZY;
			cur_worker->has_socket = FALSE;
		}
		else {
			yyerror ("yyparse: unknown worker type: %s", $3);
			YYERROR;
		}
	}
	;

workercount:
	COUNT EQSIGN NUMBER {
		cur_worker = check_worker_conf (cfg, cur_worker);

		if ($3 > 0) {
			cur_worker->count = $3;
		}
		else {
			yyerror ("yyparse: invalid number of workers: %d", $3);
			YYERROR;
		}
	}
	;

workerlimitfiles:
	MAXFILES EQSIGN NUMBER {
		cur_worker = check_worker_conf (cfg, cur_worker);
		cur_worker->rlimit_nofile = $3;
	}
	;

workerlimitcore:
	MAXCORE EQSIGN NUMBER  {
		cur_worker = check_worker_conf (cfg, cur_worker);
		cur_worker->rlimit_maxcore = $3;
	}
	;

workerparam:
	STRING EQSIGN QUOTEDSTRING {
		cur_worker = check_worker_conf (cfg, cur_worker);
		
		g_hash_table_insert (cur_worker->params, $1, $3);
	}

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
		cfg->metrics_list = g_list_prepend (cfg->metrics_list, cur_metric);
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
	| metricrjscore
	| metriccache
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

metricrjscore:
	REJECT_SCORE EQSIGN NUMBER {
		if (cur_metric == NULL) {
			cur_metric = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct metric));
		}
		cur_metric->reject_score = $3;
	}
	| REJECT_SCORE EQSIGN FRACT {
		if (cur_metric == NULL) {
			cur_metric = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct metric));
		}
		cur_metric->reject_score = $3;
	}
	;

metriccache:
	CACHE_FILE EQSIGN QUOTEDSTRING {
		if (cur_metric == NULL) {
			cur_metric = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct metric));
		}
		cur_metric->cache_filename = memory_pool_strdup (cfg->cfg_pool, $3);
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
	}
	| GROW_FACTOR EQSIGN FRACT {
		cfg->grow_factor = $3;
	}
	| GROW_FACTOR EQSIGN NUMBER {
		cfg->grow_factor = $3;
	}

modules:
	MODULES OBRACE modulesbody EBRACE
	;

modulesbody:
	modulescmd SEMICOLON
	| modulesbody modulescmd SEMICOLON
	;

modulescmd:
	MODULE_PATH EQSIGN QUOTEDSTRING {
#if !defined(WITHOUT_PERL) || defined(WITH_LUA)
		struct stat st;
		struct script_module *cur;
        glob_t globbuf;
        char *pattern;
        size_t len;
        int i;

		if (stat ($3, &st) == -1) {
			yyerror ("yyparse: cannot stat path %s, %s", $3, strerror (errno));
			YYERROR;
		}

        globbuf.gl_offs = 0;
        #ifdef WITH_LUA
        len = strlen ($3) + sizeof ("*.lua");
        pattern = g_malloc (len);
        snprintf (pattern, len, "%s%s", $3, "*.lua");
        #else
        len = strlen ($3) + sizeof ("*.pl")
        pattern = g_malloc (len);
        snprintf (pattern, len, "%s%s", $3, "*.pl");
        #endif

        if (glob(pattern, GLOB_DOOFFS, NULL, &globbuf) == 0) {
            for (i = 0; i < globbuf.gl_pathc; i ++) {
                cur = memory_pool_alloc (cfg->cfg_pool, sizeof (struct script_module));
                if (cur == NULL) {
                    yyerror ("yyparse: g_malloc: %s", strerror(errno));
                    YYERROR;
                }
                cur->path = memory_pool_strdup (cfg->cfg_pool, globbuf.gl_pathv[i]);
                cfg->script_modules = g_list_prepend (cfg->script_modules, cur);
            }
            globfree (&globbuf);
        }
        else {
            yyerror ("yyparse: glob: %s", strerror (errno));
            YYERROR;
        }
        g_free (pattern);
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
	PARAM EQSIGN QUOTEDSTRING {
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
		mopt = memory_pool_alloc (cfg->cfg_pool, sizeof (struct module_opt));
		mopt->param = $1;
		mopt->value = $3;
		cur_module_opt = g_list_prepend (cur_module_opt, mopt);
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
	| loggingurls
	| loggingbuffer
	| loggingdebugip
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

loggingurls:
	LOG_URLS EQSIGN FLAG {
		if ($3 != 0) {
			cfg->log_urls = TRUE;
		}
	}
	;

loggingbuffer:
	LOG_BUFFER EQSIGN NUMBER
	| LOG_BUFFER EQSIGN SIZELIMIT {
		cfg->log_buf_size = $3;
		cfg->log_buffered = TRUE;
	}
	;

loggingdebugip:
	DEBUG_IP EQSIGN QUOTEDSTRING {
		cfg->debug_ip_map = $3;
	}
	;

classifier:
    CLASSIFIER OBRACE classifierbody EBRACE {
        if (cur_classifier == NULL || cur_classifier->classifier == NULL) {
            yyerror ("yyparse: invalid classifier definition");
            YYERROR;
        }
        if (cur_classifier->metric == NULL) {
            cur_classifier->metric = DEFAULT_METRIC;
        }
		if (cur_classifier->tokenizer == NULL) {
			cur_classifier->tokenizer = get_tokenizer ("osb-text");
		}

        cfg->classifiers = g_list_prepend (cfg->classifiers, cur_classifier);
        cur_classifier = NULL;
    }
    ;

classifierbody:
    | classifiercmd SEMICOLON
    | classifierbody classifiercmd SEMICOLON
    ;

classifiercmd:
    | statfile
    | classifiertype
    | classifiermetric
	| classifiertokenizer
    | classifieroption
    ;

classifiertype:
    TYPE EQSIGN QUOTEDSTRING {
        cur_classifier = check_classifier_cfg (cfg, cur_classifier);
        if ((cur_classifier->classifier = get_classifier ($3)) == NULL) {
            yyerror ("yyparse: unknown classifier type: %s", $3);
            YYERROR;
        }
    }
    ;
classifiertokenizer:
	TOKENIZER EQSIGN QUOTEDSTRING {
        cur_classifier = check_classifier_cfg (cfg, cur_classifier);
		if ((cur_classifier->tokenizer = get_tokenizer ($3)) == NULL) {
			yyerror ("yyparse: unknown tokenizer %s", $3);
			YYERROR;
		}
	}
	;

classifiermetric:
    METRIC EQSIGN QUOTEDSTRING {
        cur_classifier = check_classifier_cfg (cfg, cur_classifier);
        cur_classifier->metric = $3;
        memory_pool_add_destructor (cfg->cfg_pool, g_free, cur_classifier->metric);
    }
    ;

classifieroption:
    PARAM EQSIGN QUOTEDSTRING {
        cur_classifier = check_classifier_cfg (cfg, cur_classifier);
        g_hash_table_insert (cur_classifier->opts, $1, $3);
        memory_pool_add_destructor (cfg->cfg_pool, g_free, $1);
        memory_pool_add_destructor (cfg->cfg_pool, g_free, $3);
    };

statfile:
	STATFILE OBRACE statfilebody EBRACE {
		if (cur_statfile == NULL || cur_statfile->path == NULL || cur_statfile->size == 0) {
			yyerror ("yyparse: not enough arguments in statfile definition");
			YYERROR;
		}
        cur_classifier = check_classifier_cfg (cfg, cur_classifier);
		cur_classifier->statfiles = g_list_prepend (cur_classifier->statfiles, cur_statfile);
        cfg->statfiles = g_list_prepend (cfg->statfiles, cur_statfile);
		cur_statfile = NULL;
	}
	;

statfilebody:
	| statfilecmd SEMICOLON
	| statfilebody statfilecmd SEMICOLON
	;

statfilecmd:
	| statfilesymbol
	| statfilepath
	| statfilesize
	| statfilesection
	| statfileautolearn
	| statfilebinlog
	| statfilebinlogrotate
	| statfilebinlogmaster
    | statfilenormalizer
	;
	
statfilesymbol:
	SYMBOL EQSIGN QUOTEDSTRING {
        cur_classifier = check_classifier_cfg (cfg, cur_classifier);
		if (cur_statfile == NULL) {
			cur_statfile = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile));
		}
		cur_statfile->symbol = memory_pool_strdup (cfg->cfg_pool, $3);
        g_hash_table_insert (cfg->classifiers_symbols, $3, cur_classifier);
	}
	;

statfilepath:
	PATH EQSIGN QUOTEDSTRING {
		if (cur_statfile == NULL) {
			cur_statfile = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile));
		}
		cur_statfile->path = memory_pool_strdup (cfg->cfg_pool, $3);
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

statfileautolearn:
	AUTOLEARN OBRACE autolearnbody EBRACE {
		if (cur_statfile == NULL) {
			cur_statfile = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile));
		}
		if (cur_autolearn == NULL) {
			yyerror ("yyparse: error in autolearn definition");
			YYERROR;
		}
		cur_statfile->autolearn = cur_autolearn;
		cur_autolearn = NULL;
	}
	;

autolearnbody:
	autolearncmd SEMICOLON
	| autolearnbody autolearncmd SEMICOLON
	;

autolearncmd:
	autolearnmetric
	| autolearnmin
	| autolearnmax
	| autolearnsymbols
	;

autolearnmetric:
	METRIC EQSIGN QUOTEDSTRING {
		if (cur_autolearn == NULL) {
			cur_autolearn = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile_autolearn_params));
		}
		cur_autolearn->metric = memory_pool_strdup (cfg->cfg_pool, $3);
	}
	;

autolearnmin:
	MIN_MARK EQSIGN NUMBER {
		if (cur_autolearn == NULL) {
			cur_autolearn = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile_autolearn_params));
		}
		cur_autolearn->threshold_min = $3;
	}
	| MIN_MARK EQSIGN FRACT {
		if (cur_autolearn == NULL) {
			cur_autolearn = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile_autolearn_params));
		}
		cur_autolearn->threshold_min = $3;
	}
	;

autolearnmax:
	MAX_MARK EQSIGN NUMBER {
		if (cur_autolearn == NULL) {
			cur_autolearn = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile_autolearn_params));
		}
		cur_autolearn->threshold_max = $3;
	}
	| MAX_MARK EQSIGN FRACT {
		if (cur_autolearn == NULL) {
			cur_autolearn = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile_autolearn_params));
		}
		cur_autolearn->threshold_max = $3;
	}
	;

autolearnsymbols:
	SYMBOLS EQSIGN QUOTEDSTRING {
		if (cur_autolearn == NULL) {
			cur_autolearn = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile_autolearn_params));
		}
		cur_autolearn->symbols = parse_comma_list (cfg->cfg_pool, $3);
	}
	;

statfilebinlog:
	BINLOG EQSIGN QUOTEDSTRING {
		if (cur_statfile == NULL) {
			cur_statfile = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile));
		}
		if (cur_statfile->binlog == NULL) {
			cur_statfile->binlog = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile_binlog_params));
		}
		if (g_ascii_strcasecmp ($3, "master") == 0) {
			cur_statfile->binlog->affinity = AFFINITY_MASTER;
		}
		else if (g_ascii_strcasecmp ($3, "slave") == 0) {
			cur_statfile->binlog->affinity = AFFINITY_SLAVE;
		}
		else {
			cur_statfile->binlog->affinity = AFFINITY_NONE;
		}
	}
	;

statfilebinlogrotate:
	BINLOG_ROTATE EQSIGN QUOTEDSTRING {
		if (cur_statfile == NULL) {
			cur_statfile = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile));
		}
		if (cur_statfile->binlog == NULL) {
			cur_statfile->binlog = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile_binlog_params));
		}
		cur_statfile->binlog->rotate_time = parse_seconds ($3);
	}
	;

statfilebinlogmaster:
	BINLOG_MASTER EQSIGN QUOTEDSTRING {
		if (cur_statfile == NULL) {
			cur_statfile = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile));
		}
		if (cur_statfile->binlog == NULL) {
			cur_statfile->binlog = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile_binlog_params));
		}
		if (!parse_host_port ($3, &cur_statfile->binlog->master_addr, &cur_statfile->binlog->master_port)) {
			YYERROR;
		}
	}
	;

statfilenormalizer:
    NORMALIZER EQSIGN QUOTEDSTRING {
        if (!parse_normalizer (cfg, cur_statfile, $3)) {
            yyerror ("cannot parse normalizer string: %s", $3);
            YYERROR;
        }
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


luacode:
	LUACODE
	;

raw_mode:
	RAW_MODE EQSIGN FLAG {
		cfg->raw_mode = $3;
	}
	;

profile_file:
	PROFILE_FILE EQSIGN QUOTEDSTRING {
#ifdef WITH_GPREF_TOOLS
		cfg->profile_path = $3;
#else
		yywarn ("yyparse: profile_file directive is ignored as gperf support is not enabled");
#endif
	}
	;

view:
	VIEW OBRACE viewbody EBRACE {
		if (cur_view == NULL) {
			yyerror ("yyparse: not enough arguments in view definition");
			YYERROR;
		}
		cfg->views = g_list_prepend (cfg->views, cur_view);
		cur_view = NULL;
	}
	;

viewbody:
	| viewcmd SEMICOLON
	| viewbody viewcmd SEMICOLON
	;

viewcmd:
	| viewip
	| viewclientip
	| viewfrom
	| viewsymbols
	| viewskipcheck
	;
	
viewip:
	IP EQSIGN QUOTEDSTRING {
		if (cur_view == NULL) {
			cur_view = init_view (cfg->cfg_pool);
		}
		if (!add_view_ip (cur_view, $3)) {
			yyerror ("yyparse: invalid ip line in view definition: ip = '%s'", $3);
			YYERROR;
		}
	}
	;

viewclientip:
	CLIENT_IP EQSIGN QUOTEDSTRING {
		if (cur_view == NULL) {
			cur_view = init_view (cfg->cfg_pool);
		}
		if (!add_view_client_ip (cur_view, $3)) {
			yyerror ("yyparse: invalid ip line in view definition: ip = '%s'", $3);
			YYERROR;
		}
	}
	;

viewfrom:
	FROM EQSIGN QUOTEDSTRING {
		if (cur_view == NULL) {
			cur_view = init_view (cfg->cfg_pool);
		}
		if (!add_view_from (cur_view, $3)) {
			yyerror ("yyparse: invalid from line in view definition: from = '%s'", $3);
			YYERROR;
		}
	}
	;
viewsymbols:
	SYMBOLS EQSIGN QUOTEDSTRING {
		if (cur_view == NULL) {
			cur_view = init_view (cfg->cfg_pool);
		}
		if (!add_view_symbols (cur_view, $3)) {
			yyerror ("yyparse: invalid symbols line in view definition: symbols = '%s'", $3);
			YYERROR;
		}
	}
	;
viewskipcheck:
	SKIP_CHECK EQSIGN FLAG {
		if (cur_view == NULL) {
			cur_view = init_view (cfg->cfg_pool);
		}
		cur_view->skip_check = $3;
	}
	;

settings:
	SETTINGS OBRACE settingsbody EBRACE
	;

settingsbody:
	| settingscmd SEMICOLON
	| settingsbody settingscmd SEMICOLON
	;

settingscmd:
	| usersettings
	| domainsettings
	;

usersettings:
    USER_SETTINGS EQSIGN QUOTEDSTRING {
        if (!read_settings ($3, cfg, cfg->user_settings)) {
            yyerror ("yyparse: cannot read settings %s", $3);
            YYERROR;
        }
    }
    ;
domainsettings:
    DOMAIN_SETTINGS EQSIGN QUOTEDSTRING {
        if (!read_settings ($3, cfg, cfg->domain_settings)) {
            yyerror ("yyparse: cannot read settings %s", $3);
            YYERROR;
        }
    }
    ;
%%
/* 
 * vi:ts=4 
 */
