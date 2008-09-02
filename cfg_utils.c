#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <netdb.h>
#include <math.h>
#include "config.h"
#ifndef HAVE_OWN_QUEUE_H
#include <sys/queue.h>
#else
#include "queue.h"
#endif

#include "cfg_file.h"
#include "memcached.h"

extern int yylineno;
extern char *yytext;

static void 
clean_hash_bucket (gpointer key, gpointer value, gpointer unused)
{
	LIST_HEAD (moduleoptq, module_opt) *cur_module_opt = (struct moduleoptq *)value;
	struct module_opt *cur, *tmp;

	LIST_FOREACH_SAFE (cur, cur_module_opt, next, tmp) {
		if (cur->param) {
			free (cur->param);
		}
		if (cur->value) {
			free (cur->value);
		}
		LIST_REMOVE (cur, next);
		free (cur);
	}
}

int
add_memcached_server (struct config_file *cf, char *str)
{
	char *cur_tok, *err_str;
	struct memcached_server *mc;
	struct hostent *hent;
	uint16_t port;

	if (str == NULL) return 0;

	cur_tok = strsep (&str, ":");

	if (cur_tok == NULL || *cur_tok == '\0') return 0;

	if(cf->memcached_servers_num == MAX_MEMCACHED_SERVERS) {
		yywarn ("yyparse: maximum number of memcached servers is reached %d", MAX_MEMCACHED_SERVERS);
	}
	
	mc = &cf->memcached_servers[cf->memcached_servers_num];
	if (mc == NULL) return 0;
	/* cur_tok - server name, str - server port */
	if (str == NULL) {
		port = DEFAULT_MEMCACHED_PORT;
	}
	else {
		port = (uint16_t)strtoul (str, &err_str, 10);
		if (*err_str != '\0') {
			return 0;
		}
	}

	if (!inet_aton (cur_tok, &mc->addr)) {
		/* Try to call gethostbyname */
		hent = gethostbyname (cur_tok);
		if (hent == NULL) {
			return 0;
		}
		else {
			memcpy((char *)&mc->addr, hent->h_addr, sizeof(struct in_addr));
		}
	}
	mc->port = port;
	cf->memcached_servers_num++;
	return 1;
}

int
parse_bind_line (struct config_file *cf, char *str)
{
	char *cur_tok, *err_str;
	struct hostent *hent;
	size_t s;
	
	if (str == NULL) return 0;
	cur_tok = strsep (&str, ":");
	
	if (cur_tok[0] == '/' || cur_tok[0] == '.') {
		cf->bind_host = strdup (cur_tok);
		cf->bind_family = AF_UNIX;
		return 1;

	} else {
		if (str == '\0') {
			cf->bind_port = DEFAULT_BIND_PORT;
		}
		else {
			cf->bind_port = (uint16_t)strtoul (str, &err_str, 10);
			if (*err_str != '\0') {
				return 0;
			}
		}

		if (!inet_aton (cur_tok, &cf->bind_addr)) {
			/* Try to call gethostbyname */
			hent = gethostbyname (cur_tok);
			if (hent == NULL) {
				return 0;
			}
			else {
				cf->bind_host = strdup (cur_tok);
				memcpy((char *)&cf->bind_addr, hent->h_addr, sizeof(struct in_addr));
				s = strlen (cur_tok) + 1;
			}
		}

		cf->bind_family = AF_INET;

		return 1;
	}

	return 0;
}

void
init_defaults (struct config_file *cfg)
{
	cfg->memcached_error_time = DEFAULT_UPSTREAM_ERROR_TIME;
	cfg->memcached_dead_time = DEFAULT_UPSTREAM_DEAD_TIME;
	cfg->memcached_maxerrors = DEFAULT_UPSTREAM_MAXERRORS;
	cfg->memcached_protocol = TCP_TEXT;

	cfg->workers_number = DEFAULT_WORKERS_NUM;
	cfg->modules_opts = g_hash_table_new (g_str_hash, g_str_equal);

	LIST_INIT (&cfg->filters);
	LIST_INIT (&cfg->perl_modules);
	LIST_INIT (&cfg->c_modules);
}

void
free_config (struct config_file *cfg)
{
	struct filter_chain *chain, *tmp_chain;
	struct script_param *param, *tmp_param;
	struct perl_module *module, *tmp_module;
	struct c_module *cmodule, *tmp_cmodule;

	if (cfg->pid_file) {
		g_free (cfg->pid_file);
	}
	if (cfg->temp_dir) {
		g_free (cfg->temp_dir);
	}
	if (cfg->bind_host) {
		g_free (cfg->bind_host);
	}

	LIST_FOREACH_SAFE (chain, &cfg->filters, next, tmp_chain) {
		LIST_FOREACH_SAFE (param, chain->scripts, next, tmp_param) {
			if (param->symbol) {
				free (param->symbol);
			}
			if (param->function) {
				free (param->function);
			}
			LIST_REMOVE (param, next);
			free (param);
		}
		LIST_REMOVE (chain, next);
		free (chain);
	}
	LIST_FOREACH_SAFE (module, &cfg->perl_modules, next, tmp_module) {
		if (module->path) {
			free (module->path);
		}
		LIST_REMOVE (module, next);
		free (module);
	}

	LIST_FOREACH_SAFE (cmodule, &cfg->c_modules, next, tmp_cmodule) {
		if (cmodule->ctx) {
			free (cmodule->ctx);
		}
		free (cmodule);
	}

	g_hash_table_foreach (cfg->modules_opts, clean_hash_bucket, NULL);
	g_hash_table_remove_all (cfg->modules_opts);
	g_hash_table_unref (cfg->modules_opts);
}

int
parse_script (char *str, struct script_param *param, enum script_type type)
{
	char *cur_tok;
	
	bzero (param, sizeof (struct script_param));
	param->type = type;
	
	/* symbol:path:function -> cur_tok - symbol, str -> function */
	cur_tok = strsep (&str, ":");

	if (str == NULL || cur_tok == NULL || *cur_tok == '\0') return -1;
	
	param->symbol = strdup (cur_tok);
	param->function = strdup (str);

	return 0;
}

/*
 * vi:ts=4
 */
