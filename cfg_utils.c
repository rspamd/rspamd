#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libmilter/mfapi.h>
#include <sys/queue.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <netdb.h>
#include <math.h>

#include "cfg_file.h"
#include "memcached.h"

extern int yylineno;
extern char *yytext;


int
add_memcached_server (struct config_file *cf, char *str)
{
	char *cur_tok, *err_str;
	struct memcached_server *mc;
	struct hostent *he;
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
		he = gethostbyname (cur_tok);
		if (he == NULL) {
			return 0;
		}
		else {
			memcpy((char *)&mc->addr, he->h_addr, sizeof(struct in_addr));
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
	struct hostent *he;
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
			he = gethostbyname (cur_tok);
			if (he == NULL) {
				return 0;
			}
			else {
				cf->bind_host = strdup (cur_tok);
				memcpy((char *)&cf->bind_addr, he->h_addr, sizeof(struct in_addr));
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
}

void
free_config (struct config_file *cfg)
{
	if (cfg->pid_file) {
		g_free (cfg->pid_file);
	}
	if (cfg->temp_dir) {
		g_free (cfg->temp_dir);
	}
	if (cfg->bind_host) {
		g_free (cfg->bind_host);
	}
}

/*
 * vi:ts=4
 */
