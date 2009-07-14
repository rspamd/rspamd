/*
 * Copyright (c) 2009, Rambler media
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include "config.h"
#include <math.h>

#include "cfg_file.h"
#include "main.h"
#include "filter.h"
#include "classifiers/classifiers.h"

#define DEFAULT_SCORE 10.0

extern int yylineno;
extern char *yytext;

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
parse_bind_line (struct config_file *cfg, struct worker_conf *cf, char *str)
{
	char *cur_tok, *err_str;
	struct hostent *hent;
	size_t s;
	char **host;
	int16_t *family, *port;
	struct in_addr *addr;
	
	if (str == NULL) return 0;
	cur_tok = strsep (&str, ":");

	host = &cf->bind_host;
	port = &cf->bind_port;
	*port = DEFAULT_BIND_PORT;
	family = &cf->bind_family;
	addr = &cf->bind_addr;
	
	if (cur_tok[0] == '/' || cur_tok[0] == '.') {
#ifdef HAVE_DIRNAME
		/* Try to check path of bind credit */
		struct stat st;
		int fd;
		char *copy = memory_pool_strdup (cfg->cfg_pool, cur_tok);
		if (stat (copy, &st) == -1) {
			if (errno == ENOENT) {
				if ((fd = open (cur_tok, O_RDWR | O_TRUNC | O_CREAT, S_IWUSR | S_IRUSR)) == -1) {
					yyerror ("parse_bind_line: cannot open path %s for making socket, %s", cur_tok, strerror (errno));
					return 0;
				}
				else {
					close (fd);
					unlink (cur_tok);
				}
			}
			else {
				yyerror ("parse_bind_line: cannot stat path %s for making socket, %s", cur_tok, strerror (errno));
				return 0;
			}
		}
		else {
			if (unlink (cur_tok) == -1) {
				yyerror ("parse_bind_line: cannot remove path %s for making socket, %s", cur_tok, strerror (errno));
				return 0;
			}
		}
#endif
		*host = memory_pool_strdup (cfg->cfg_pool, cur_tok);
		*family = AF_UNIX;
		return 1;

	} else {
		if (*str != '\0') {
			*port = (uint16_t)strtoul (str, &err_str, 10);
			if (*err_str != '\0') {
				yyerror ("parse_bind_line: cannot read numeric value: %s", err_str);
				return 0;
			}
		}
		if (strcmp (cur_tok, "*") == 0) {
			*host = memory_pool_strdup (cfg->cfg_pool, cur_tok);
			addr->s_addr = htonl (INADDR_ANY);
		} else if (!inet_aton (cur_tok, addr)) {
			/* Try to call gethostbyname */
			hent = gethostbyname (cur_tok);
			if (hent == NULL) {
				return 0;
			}
			else {
				*host = memory_pool_strdup (cfg->cfg_pool, cur_tok);
				memcpy((char *)addr, hent->h_addr, sizeof(struct in_addr));
				s = strlen (cur_tok) + 1;
			}
		}
		else {
			*host = memory_pool_strdup (cfg->cfg_pool, cur_tok);
		}
		*family = AF_INET;

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


	cfg->max_statfile_size = DEFAULT_STATFILE_SIZE;
	cfg->modules_opts = g_hash_table_new (g_str_hash, g_str_equal);
	cfg->variables = g_hash_table_new (g_str_hash, g_str_equal);
	cfg->metrics = g_hash_table_new (g_str_hash, g_str_equal);
	cfg->factors = g_hash_table_new (g_str_hash, g_str_equal);
	cfg->c_modules = g_hash_table_new (g_str_hash, g_str_equal);
	cfg->composite_symbols = g_hash_table_new (g_str_hash, g_str_equal);
	cfg->statfiles = g_hash_table_new (g_str_hash, g_str_equal);
	cfg->cfg_params = g_hash_table_new (g_str_hash, g_str_equal);

}

void
free_config (struct config_file *cfg)
{
	g_hash_table_remove_all (cfg->modules_opts);
	g_hash_table_unref (cfg->modules_opts);
	g_hash_table_remove_all (cfg->variables);
	g_hash_table_unref (cfg->variables);
	g_hash_table_remove_all (cfg->metrics);
	g_hash_table_unref (cfg->metrics);
	g_hash_table_remove_all (cfg->factors);
	g_hash_table_unref (cfg->factors);
	g_hash_table_remove_all (cfg->c_modules);
	g_hash_table_unref (cfg->c_modules);
	g_hash_table_remove_all (cfg->composite_symbols);
	g_hash_table_unref (cfg->composite_symbols);
	g_hash_table_remove_all (cfg->statfiles);
	g_hash_table_unref (cfg->statfiles);
	g_hash_table_remove_all (cfg->cfg_params);
	g_hash_table_unref (cfg->cfg_params);
	g_list_free (cfg->metrics_list);
	memory_pool_delete (cfg->cfg_pool);
}

char* 
get_module_opt (struct config_file *cfg, char *module_name, char *opt_name)
{
	GList *cur_opt;
	struct module_opt *cur;
	
	cur_opt = g_hash_table_lookup (cfg->modules_opts, module_name);
	if (cur_opt == NULL) {
		return NULL;
	}
	
	while (cur_opt) {
		cur = cur_opt->data;
		if (strcmp (cur->param, opt_name) == 0) {
			return cur->value;
		}
		cur_opt = g_list_next (cur_opt);
	}

	return NULL;
}

size_t
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

unsigned int
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

char
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

/*
 * Try to substitute all variables in given string
 * Return: newly allocated string with substituted variables (original string may be freed if variables are found)
 */
char *
substitute_variable (struct config_file *cfg, char *name, char *str, u_char recursive)
{
	char *var, *new, *v_begin, *v_end, *p, t;
	size_t len;
	gboolean changed = FALSE;

	if (str == NULL) {
		yywarn ("substitute_variable: trying to substitute variable in NULL string");
		return NULL;
	}
	
	p = str;
	while ((v_begin = strstr (p, "${")) != NULL) {
		len = strlen (str);
		*v_begin = '\0';
		v_begin += 2;
		if ((v_end = strstr (v_begin, "}")) == NULL) {
			/* Not a variable, skip */
			p = v_begin;
			continue;
		}
		t = *v_end;
		*v_end = '\0';
		var = g_hash_table_lookup (cfg->variables, v_begin);
		if (var == NULL) {
			yywarn ("substitute_variable: variable %s is not defined", v_begin);
			*v_end = t;
			p = v_end + 1;
			continue;
		}
		else if (recursive) {
			var = substitute_variable (cfg, v_begin, var, recursive);
		}
		/* Allocate new string */
		new = memory_pool_alloc (cfg->cfg_pool, len - strlen (v_begin) + strlen (var) + 3);

		snprintf (new, len - strlen (v_begin) + strlen (var) + 3, "%s(%s)%s",
						str, var, v_end + 1);
		p = new;
		str = new;
		changed = TRUE;
	}
	
	if (changed && name != NULL) {
		g_hash_table_insert (cfg->variables, name, str);
	}

	return str;
}

static void
substitute_module_variables (gpointer key, gpointer value, gpointer data)
{
	struct config_file *cfg = (struct config_file *)data;
	GList *cur_opt = (GList *)value;
	struct module_opt *cur;

	while (cur_opt) {
		cur = cur_opt->data;
		if (cur->value) {
			cur->value = substitute_variable (cfg, NULL, cur->value, 1);
		}
		cur_opt = g_list_next (cur_opt);
	}
}

static void
substitute_all_variables (gpointer key, gpointer value, gpointer data)
{
	struct config_file *cfg = (struct config_file *)data;

	/* Do recursive substitution */
	(void)substitute_variable (cfg, (char *)key, (char *)value, 1);
}

static void
parse_filters_str (struct config_file *cfg, const char *str)
{
	gchar **strvec, **p;
	struct filter *cur;
	int i;
	
	if (str == NULL) {
		return;	
	}

	strvec = g_strsplit (str, ",", 0);
	if (strvec == NULL) {
		return;
	}

	p = strvec;
	while (*p) {
		cur = NULL;
		/* Search modules from known C modules */
		for (i = 0; i < MODULES_NUM; i++) {
			if (strcasecmp (modules[i].name, *p) == 0) {
				cur = memory_pool_alloc (cfg->cfg_pool, sizeof (struct filter));
				cur->type = C_FILTER;
				msg_debug ("parse_filters_str: found C filter %s", *p);
				cur->func_name = memory_pool_strdup (cfg->cfg_pool, *p);
				cfg->filters = g_list_prepend (cfg->filters, cur);

				break;
			}	
		}
		if (cur != NULL) {
			/* Go to next iteration */
			p++;
			continue;
		}
		cur = memory_pool_alloc (cfg->cfg_pool, sizeof (struct filter));
		cur->type = PERL_FILTER;
		cur->func_name = memory_pool_strdup (cfg->cfg_pool, *p);
		cfg->filters = g_list_prepend (cfg->filters, cur);
		p ++;
	}

	g_strfreev (strvec);
}

/*
 * Place pointers to cfg_file structure to hash cfg_params
 */
static void
fill_cfg_params (struct config_file *cfg)
{
    struct config_scalar *scalars;

    scalars = memory_pool_alloc (cfg->cfg_pool, 10 * sizeof (struct config_scalar));

    scalars[0].type = SCALAR_TYPE_STR;
    scalars[0].pointer = &cfg->cfg_name;
    g_hash_table_insert (cfg->cfg_params, "cfg_name", &scalars[0]);
    scalars[1].type = SCALAR_TYPE_STR;
    scalars[1].pointer = &cfg->pid_file;
    g_hash_table_insert (cfg->cfg_params, "pid_file", &scalars[1]);
    scalars[2].type = SCALAR_TYPE_STR;
    scalars[2].pointer = &cfg->temp_dir;
    g_hash_table_insert (cfg->cfg_params, "temp_dir", &scalars[2]);
    scalars[3].type = SCALAR_TYPE_SIZE;
    scalars[3].pointer = &cfg->max_statfile_size;
    g_hash_table_insert (cfg->cfg_params, "max_statfile_size", &scalars[3]);

}

/* 
 * Perform post load actions
 */
void
post_load_config (struct config_file *cfg)
{
	struct timespec ts;
	struct metric *def_metric;

	g_hash_table_foreach (cfg->variables, substitute_all_variables, cfg);
	g_hash_table_foreach (cfg->modules_opts, substitute_module_variables, cfg);
	parse_filters_str (cfg, cfg->filters_str);
    fill_cfg_params (cfg);

#ifdef HAVE_CLOCK_PROCESS_CPUTIME_ID
	clock_getres (CLOCK_PROCESS_CPUTIME_ID, &ts);
#elif defined(HAVE_CLOCK_VIRTUAL)
	clock_getres (CLOCK_VIRTUAL, &ts);
#else
	clock_getres (CLOCK_REALTIME, &ts);
#endif
	cfg->clock_res = (int)log10 (1000000 / ts.tv_nsec);
	if (cfg->clock_res < 0) {
		cfg->clock_res = 0;
	}
	if (cfg->clock_res > 3) {
		cfg->clock_res = 3;
	}

	if (g_hash_table_lookup (cfg->metrics, DEFAULT_METRIC) == NULL) {
		def_metric = memory_pool_alloc (cfg->cfg_pool, sizeof (struct metric));
		def_metric->name = DEFAULT_METRIC;
		def_metric->func_name = "factors";
		def_metric->func = factor_consolidation_func;
		def_metric->required_score = DEFAULT_SCORE;
		def_metric->classifier = get_classifier ("winnow");
		cfg->metrics_list = g_list_prepend (cfg->metrics_list, def_metric);
		g_hash_table_insert (cfg->metrics, DEFAULT_METRIC, def_metric);
	}

}


void
parse_err (const char *fmt, ...)
{
	va_list aq;
	char logbuf[BUFSIZ], readbuf[32];
	int r;
	
	va_start (aq, fmt);
	g_strlcpy (readbuf, yytext, sizeof (readbuf));

	r = snprintf (logbuf, sizeof (logbuf), "config file parse error! line: %d, text: %s, reason: ", yylineno, readbuf);
	r += vsnprintf (logbuf + r, sizeof (logbuf) - r, fmt, aq);

	va_end (aq);
	g_critical ("%s", logbuf);
}

void
parse_warn (const char *fmt, ...)
{
	va_list aq;
	char logbuf[BUFSIZ], readbuf[32];
	int r;
	
	va_start (aq, fmt);
	g_strlcpy (readbuf, yytext, sizeof (readbuf));

	r = snprintf (logbuf, sizeof (logbuf), "config file parse warning! line: %d, text: %s, reason: ", yylineno, readbuf);
	r += vsnprintf (logbuf + r, sizeof (logbuf) - r, fmt, aq);

	va_end (aq);
	g_warning ("%s", logbuf);
}

void
unescape_quotes (char *line)
{
	char *c = line, *t;

	while (*c) {
		if (*c == '\\' && *(c + 1) == '"') {
			t = c;
			while (*t) {
				*t = *(t + 1);
				t ++;
			}
		}
		c ++;
	}
}

GList *
parse_comma_list (memory_pool_t *pool, char *line)
{
	GList *res = NULL;
	char *c, *p, *str;
	
	c = line;
	p = c;

	while (*p) {
		if (*p == ',' && *c != *p) {
			str = memory_pool_alloc (pool, p - c + 1);
			g_strlcpy (str, c, p - c + 1);
			res = g_list_prepend (res, str);
			/* Skip spaces */
			while (g_ascii_isspace (*(++p)));
			c = p;
			continue;
		}
		p ++;
	}
	if (res != NULL) {
		memory_pool_add_destructor (pool, (pool_destruct_func)g_list_free, res);
	}

	return res;
}

/*
 * vi:ts=4
 */
