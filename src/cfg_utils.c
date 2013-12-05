/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include "config.h"

#include "cfg_file.h"
#include "main.h"
#include "filter.h"
#include "settings.h"
#include "classifiers/classifiers.h"
#include "cfg_xml.h"
#include "lua/lua_common.h"
#include "kvstorage_config.h"
#include "map.h"
#include "dynamic_cfg.h"

#define DEFAULT_SCORE 10.0

#define DEFAULT_RLIMIT_NOFILE 2048
#define DEFAULT_RLIMIT_MAXCORE 0
#define DEFAULT_MAP_TIMEOUT 10


gboolean
parse_host_port_priority (memory_pool_t *pool, const gchar *str, gchar **addr, guint16 *port, guint *priority)
{
	gchar                          **tokens, *err_str, *cur_tok;
	struct addrinfo                 hints, *res;
	guint                           port_parsed, priority_parsed, saved_errno = errno;
	gint							r;
	union {
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	}                               addr_holder;

	tokens = g_strsplit_set (str, ":", 0);
	if (!tokens || !tokens[0]) {
		return FALSE;
	}
	
	/* Now try to parse host and write address to ina */
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* Type of the socket */
	hints.ai_flags = 0;
	hints.ai_protocol = 0;           /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	if (strcmp (tokens[0], "*") == 0) {
		/* XXX: actually we still cannot listen on multiply protocols */
		if (pool != NULL) {
			*addr = memory_pool_alloc (pool, INET_ADDRSTRLEN + 1);
		}
		rspamd_strlcpy (*addr, "0.0.0.0", INET_ADDRSTRLEN + 1);
		goto port_parse;
	}
	else {
		cur_tok = tokens[0];
	}

	if ((r = getaddrinfo (cur_tok, NULL, &hints, &res)) == 0) {
		memcpy (&addr_holder, res->ai_addr, MIN (sizeof (addr_holder), res->ai_addrlen));
		if (res->ai_family == AF_INET) {
			if (pool != NULL) {
				*addr = memory_pool_alloc (pool, INET_ADDRSTRLEN + 1);
			}
			inet_ntop (res->ai_family, &addr_holder.v4.sin_addr, *addr, INET_ADDRSTRLEN + 1);
		}
		else {
			if (pool != NULL) {
				*addr = memory_pool_alloc (pool, INET6_ADDRSTRLEN + 1);
			}
			inet_ntop (res->ai_family, &addr_holder.v6.sin6_addr, *addr, INET6_ADDRSTRLEN + 1);
		}
		freeaddrinfo (res);
	}
	else {
		msg_err ("address resolution for %s failed: %s", tokens[0], gai_strerror (r));
		goto err;
	}

port_parse:
	if (tokens[1] != NULL) {
		/* Port part */
		if (port != NULL) {
			errno = 0;
			port_parsed = strtoul (tokens[1], &err_str, 10);
			if (*err_str != '\0' || errno != 0) {
				msg_warn ("cannot parse port: %s, at symbol %c, error: %s", tokens[1], *err_str, strerror (errno));
				goto err;
			}
			if (port_parsed > G_MAXUINT16) {
				errno = ERANGE;
				msg_warn ("cannot parse port: %s, error: %s", tokens[1], *err_str, strerror (errno));
				goto err;
			}
			*port = port_parsed;
		}
		if (priority != NULL) {
			if (port != NULL) {
				cur_tok = tokens[2];
			}
			else {
				cur_tok = tokens[1];
			}
			if (cur_tok != NULL) {
				/* Priority part */
				errno = 0;
				priority_parsed = strtoul (cur_tok, &err_str, 10);
				if (*err_str != '\0' || errno != 0) {
					msg_warn ("cannot parse priority: %s, at symbol %c, error: %s", tokens[1], *err_str, strerror (errno));
					goto err;
				}
				*priority = priority_parsed;
			}
		}
	}
	
	/* Restore errno */
	errno = saved_errno;
	g_strfreev (tokens);
	return TRUE;

err:
	errno = saved_errno;
	g_strfreev (tokens);
	return FALSE;
}

gboolean
parse_host_port (memory_pool_t *pool, const gchar *str, gchar **addr, guint16 *port)
{
	return parse_host_port_priority (pool, str, addr, port, NULL);
}

gboolean
parse_host_priority (memory_pool_t *pool, const gchar *str, gchar **addr, guint *priority)
{
	return parse_host_port_priority (pool, str, addr, NULL, priority);
}

gboolean
parse_bind_line (struct config_file *cfg, struct worker_conf *cf, const gchar *str)
{
	struct rspamd_worker_bind_conf *cnf;

	if (str == NULL)
		return 0;

	cnf = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct rspamd_worker_bind_conf));
	cnf->bind_port = DEFAULT_BIND_PORT;

	if (str[0] == '/' || str[0] == '.') {
#ifdef HAVE_DIRNAME
		/* Try to check path of bind credit */
		struct stat                     st;
		gint                            fd;
		gchar                           *copy = memory_pool_strdup (cfg->cfg_pool, str);
		if (stat (copy, &st) == -1) {
			if (errno == ENOENT) {
				if ((fd = open (str, O_RDWR | O_TRUNC | O_CREAT, S_IWUSR | S_IRUSR)) == -1) {
					msg_err ("cannot open path %s for making socket, %s", str, strerror (errno));
					return FALSE;
				}
				else {
					close (fd);
					unlink (str);
				}
			}
			else {
				msg_err ("cannot stat path %s for making socket, %s", str, strerror (errno));
				return 0;
			}
		}
		else {
			if (unlink (str) == -1) {
				msg_err ("cannot remove path %s for making socket, %s", str, strerror (errno));
				return 0;
			}
		}
#endif
		cnf->bind_host = memory_pool_strdup (cfg->cfg_pool, str);
		cnf->is_unix = TRUE;
		LL_PREPEND (cf->bind_conf, cnf);
		return TRUE;
	}
	else {
		cnf->bind_host = memory_pool_strdup (cfg->cfg_pool, str);
		if (parse_host_port (cfg->cfg_pool, str, &cnf->bind_host, &cnf->bind_port)) {
			LL_PREPEND (cf->bind_conf, cnf);
			return TRUE;
		}
	}

	return FALSE;
}

void
init_defaults (struct config_file *cfg)
{

	cfg->memcached_error_time = DEFAULT_UPSTREAM_ERROR_TIME;
	cfg->memcached_dead_time = DEFAULT_UPSTREAM_DEAD_TIME;
	cfg->memcached_maxerrors = DEFAULT_UPSTREAM_MAXERRORS;
	cfg->memcached_protocol = TCP_TEXT;

	cfg->dns_timeout = 1000;
	cfg->dns_retransmits = 5;
	/* After 20 errors do throttling for 10 seconds */
	cfg->dns_throttling_errors = 20;
	cfg->dns_throttling_time = 10000;

	cfg->statfile_sync_interval = 60000;
	cfg->statfile_sync_timeout = 20000;

	/* 20 Kb */
	cfg->max_diff = 20480;

	cfg->max_statfile_size = DEFAULT_STATFILE_SIZE;
	cfg->metrics = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	cfg->c_modules = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	cfg->composite_symbols = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	cfg->classifiers_symbols = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	cfg->cfg_params = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	cfg->metrics_symbols = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);

	cfg->map_timeout = DEFAULT_MAP_TIMEOUT;

	cfg->log_level = G_LOG_LEVEL_WARNING;
	cfg->log_extended = TRUE;

	init_settings (cfg);

}

void
free_config (struct config_file *cfg)
{
	GList							*cur;
	struct symbols_group			*gr;

	remove_all_maps (cfg);
	ucl_obj_unref (cfg->rcl_obj);
	g_hash_table_remove_all (cfg->metrics);
	g_hash_table_unref (cfg->metrics);
	g_hash_table_remove_all (cfg->c_modules);
	g_hash_table_unref (cfg->c_modules);
	g_hash_table_remove_all (cfg->composite_symbols);
	g_hash_table_unref (cfg->composite_symbols);
	g_hash_table_remove_all (cfg->cfg_params);
	g_hash_table_unref (cfg->cfg_params);
	g_hash_table_destroy (cfg->metrics_symbols);
	g_hash_table_destroy (cfg->classifiers_symbols);
	/* Free symbols groups */
	cur = cfg->symbols_groups;
	while (cur) {
		gr = cur->data;
		if (gr->symbols) {
			g_list_free (gr->symbols);
		}
		cur = g_list_next (cur);
	}
	if (cfg->symbols_groups) {
		g_list_free (cfg->symbols_groups);
	}

	if (cfg->checksum) {
		g_free (cfg->checksum);
	}
	g_list_free (cfg->classifiers);
	g_list_free (cfg->metrics_list);
	memory_pool_delete (cfg->cfg_pool);
}

ucl_object_t        *
get_module_opt (struct config_file *cfg, const gchar *module_name, const gchar *opt_name)
{
	ucl_object_t *res = NULL, *sec;

	sec = ucl_obj_get_key (cfg->rcl_obj, module_name);
	if (sec != NULL) {
		res = ucl_obj_get_key (sec, opt_name);
	}

	return res;
}

guint64
parse_limit (const gchar *limit, guint len)
{
	guint64                        result = 0;
	const gchar                   *err_str;

	if (!limit || *limit == '\0' || len == 0) {
		return 0;
	}

	errno = 0;
	result = strtoull (limit, (gchar **)&err_str, 10);

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
		else if (len > 0 && err_str - limit != (gint)len) {
			msg_warn ("invalid limit value '%s' at position '%s'", limit, err_str);
			result = 0;
		}
	}

	return result;
}

gchar
parse_flag (const gchar *str)
{
	guint							 len;
	gchar							 c;

	if (!str || !*str) {
		return -1;
	}

	len = strlen (str);

	switch (len) {
	case 1:
		c = g_ascii_tolower (*str);
		if (c == 'y' || c == '1') {
			return 1;
		}
		else if (c == 'n' || c == '0') {
			return 0;
		}
		break;
	case 2:
		if (g_ascii_strncasecmp (str, "no", len) == 0) {
			return 0;
		}
		else if (g_ascii_strncasecmp (str, "on", len) == 0) {
			return 1;
		}
		break;
	case 3:
		if (g_ascii_strncasecmp (str, "yes", len) == 0) {
			return 1;
		}
		else if (g_ascii_strncasecmp (str, "off", len) == 0) {
			return 0;
		}
		break;
	case 4:
		if (g_ascii_strncasecmp (str, "true", len) == 0) {
			return 1;
		}
		break;
	case 5:
		if (g_ascii_strncasecmp (str, "false", len) == 0) {
			return 0;
		}
		break;
	}

	return -1;
}

gboolean
get_config_checksum (struct config_file *cfg) 
{
	gint                            fd;
	void                           *map;
	struct stat                     st;

	/* Compute checksum for config file that should be used by xml dumper */
	if ((fd = open (cfg->cfg_name, O_RDONLY)) == -1) {
		msg_err ("config file %s is no longer available, cannot calculate checksum");
		return FALSE;
	}
	if (stat (cfg->cfg_name, &st) == -1) {
		msg_err ("cannot stat %s: %s", cfg->cfg_name, strerror (errno));
		return FALSE;
	}

	/* Now mmap this file to simplify reading process */
	if ((map = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		msg_err ("cannot mmap %s: %s", cfg->cfg_name, strerror (errno));
		close (fd);
		return FALSE;
	}
	close (fd);
	
	/* Get checksum for a file */
	cfg->checksum = g_compute_checksum_for_string (G_CHECKSUM_MD5, map, st.st_size);
	munmap (map, st.st_size);
	
	return TRUE;
}
/* 
 * Perform post load actions
 */
void
post_load_config (struct config_file *cfg)
{
#ifdef HAVE_CLOCK_GETTIME
	struct timespec                 ts;
#endif
	struct metric                  *def_metric;

#ifdef HAVE_CLOCK_GETTIME
#ifdef HAVE_CLOCK_PROCESS_CPUTIME_ID
	clock_getres (CLOCK_PROCESS_CPUTIME_ID, &ts);
# elif defined(HAVE_CLOCK_VIRTUAL)
	clock_getres (CLOCK_VIRTUAL, &ts);
# else
	clock_getres (CLOCK_REALTIME, &ts);
# endif

	cfg->clock_res = (gint)log10 (1000000 / ts.tv_nsec);
	if (cfg->clock_res < 0) {
		cfg->clock_res = 0;
	}
	if (cfg->clock_res > 3) {
		cfg->clock_res = 3;
	}
#else 
	/* For gettimeofday */
	cfg->clock_res = 1;
#endif

	if ((def_metric = g_hash_table_lookup (cfg->metrics, DEFAULT_METRIC)) == NULL) {
		def_metric = check_metric_conf (cfg, NULL);
		def_metric->name = DEFAULT_METRIC;
		def_metric->actions[METRIC_ACTION_REJECT].score = DEFAULT_SCORE;
		cfg->metrics_list = g_list_prepend (cfg->metrics_list, def_metric);
		g_hash_table_insert (cfg->metrics, DEFAULT_METRIC, def_metric);
	}

	cfg->default_metric = def_metric;

	/* Lua options */
	(void)lua_post_load_config (cfg);
	init_dynamic_config (cfg);
}

#if 0
void
parse_err (const gchar *fmt, ...)
{
	va_list                         aq;
	gchar                            logbuf[BUFSIZ], readbuf[32];
	gint                            r;

	va_start (aq, fmt);
	rspamd_strlcpy (readbuf, yytext, sizeof (readbuf));

	r = snprintf (logbuf, sizeof (logbuf), "config file parse error! line: %d, text: %s, reason: ", yylineno, readbuf);
	r += vsnprintf (logbuf + r, sizeof (logbuf) - r, fmt, aq);

	va_end (aq);
	g_critical ("%s", logbuf);
}

void
parse_warn (const gchar *fmt, ...)
{
	va_list                         aq;
	gchar                            logbuf[BUFSIZ], readbuf[32];
	gint                            r;

	va_start (aq, fmt);
	rspamd_strlcpy (readbuf, yytext, sizeof (readbuf));

	r = snprintf (logbuf, sizeof (logbuf), "config file parse warning! line: %d, text: %s, reason: ", yylineno, readbuf);
	r += vsnprintf (logbuf + r, sizeof (logbuf) - r, fmt, aq);

	va_end (aq);
	g_warning ("%s", logbuf);
}
#endif

void
unescape_quotes (gchar *line)
{
	gchar                           *c = line, *t;

	while (*c) {
		if (*c == '\\' && *(c + 1) == '"') {
			t = c;
			while (*t) {
				*t = *(t + 1);
				t++;
			}
		}
		c++;
	}
}

GList                          *
parse_comma_list (memory_pool_t * pool, const gchar *line)
{
	GList                          *res = NULL;
	const gchar                    *c, *p;
	gchar                          *str;

	c = line;
	p = c;

	while (*p) {
		if (*p == ',' && *c != *p) {
			str = memory_pool_alloc (pool, p - c + 1);
			rspamd_strlcpy (str, c, p - c + 1);
			res = g_list_prepend (res, str);
			/* Skip spaces */
			while (g_ascii_isspace (*(++p)));
			c = p;
			continue;
		}
		p++;
	}
	if (res != NULL) {
		memory_pool_add_destructor (pool, (pool_destruct_func) g_list_free, res);
	}

	return res;
}

struct classifier_config       *
check_classifier_conf (struct config_file *cfg, struct classifier_config *c)
{
	if (c == NULL) {
		c = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct classifier_config));
	}
	if (c->opts == NULL) {
		c->opts = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
		memory_pool_add_destructor (cfg->cfg_pool, (pool_destruct_func) g_hash_table_destroy, c->opts);
	}
	if (c->labels == NULL) {
		c->labels = g_hash_table_new_full (rspamd_str_hash, rspamd_str_equal, NULL, (GDestroyNotify)g_list_free);
		memory_pool_add_destructor (cfg->cfg_pool, (pool_destruct_func) g_hash_table_destroy, c->labels);
	}

	return c;
}

struct statfile*
check_statfile_conf (struct config_file *cfg, struct statfile *c)
{
	if (c == NULL) {
		c = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile));
	}

	return c;
}

struct metric *
check_metric_conf (struct config_file *cfg, struct metric *c)
{
	int i;
	if (c == NULL) {
		c = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct metric));
		c->grow_factor = 1.0;
		c->symbols = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
		c->descriptions = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
		for (i = METRIC_ACTION_REJECT; i < METRIC_ACTION_MAX; i ++) {
			c->actions[i].score = -1.0;
		}
		memory_pool_add_destructor (cfg->cfg_pool, (pool_destruct_func) g_hash_table_destroy, c->symbols);
		memory_pool_add_destructor (cfg->cfg_pool, (pool_destruct_func) g_hash_table_destroy, c->descriptions);
	}

	return c;
}

struct worker_conf *
check_worker_conf (struct config_file *cfg, struct worker_conf *c)
{
	if (c == NULL) {
		c = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct worker_conf));
		c->params = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
		c->active_workers = g_queue_new ();
		memory_pool_add_destructor (cfg->cfg_pool, (pool_destruct_func)g_hash_table_destroy, c->params);
		memory_pool_add_destructor (cfg->cfg_pool, (pool_destruct_func)g_queue_free, c->active_workers);
#ifdef HAVE_SC_NPROCESSORS_ONLN
		c->count = sysconf (_SC_NPROCESSORS_ONLN);
#else
		c->count = DEFAULT_WORKERS_NUM;
#endif
		c->rlimit_nofile = DEFAULT_RLIMIT_NOFILE;
		c->rlimit_maxcore = DEFAULT_RLIMIT_MAXCORE;
	}
	
	return c;
}

static double
internal_normalizer_func (struct config_file *cfg, long double score, void *data)
{
    long double max = *(double *)data;

    if (score < 0) {
    	return score;
    }
#ifdef HAVE_TANHL
    return max * tanhl (score / max);
#elif defined(HAVE_TANHL)
    /*
     * As some implementations of libm does not support tanhl, try to use
     * tanh
     */
    return max * tanh ((double) (score / max));
#else
    return score < max ? score / max : max;
#endif
}

static gboolean
parse_internal_normalizer (struct config_file *cfg, struct statfile *st, const gchar *line)
{
    double *max;
    gchar *err;

    /* Line contains maximum value for internal normalizer */
    max = memory_pool_alloc (cfg->cfg_pool, sizeof (double));

    errno = 0;
    *max = strtod (line, &err);
    
    if (errno != 0 || *err != '\0') {
        msg_err ("cannot parse max number for internal normalizer");
        return FALSE;
    }

    st->normalizer = internal_normalizer_func;
    st->normalizer_data = (void *)max;
    return TRUE;
}

#ifdef WITH_LUA
static gboolean
parse_lua_normalizer (struct config_file *cfg, struct statfile *st, const gchar *line)
{
    gchar *code_begin;
    GList *params = NULL;
    gint                            len;

    code_begin = strchr (line, ':');
    
    if (code_begin == NULL) {
        /* Just function name without code */
        params = g_list_prepend (g_list_prepend (NULL, NULL), memory_pool_strdup (cfg->cfg_pool, line));
    }
    else {
        /* Postpone actual code load as lua libraries are not loaded */
        /* Put code to list */
        params = g_list_prepend (NULL, code_begin + 1);
        /* Put function name */
        len = code_begin - line;
        code_begin = memory_pool_alloc (cfg->cfg_pool, len + 1);
        rspamd_strlcpy (code_begin, line, len + 1);
        params = g_list_prepend (params, code_begin);
    }
    memory_pool_add_destructor (cfg->cfg_pool, (pool_destruct_func)g_list_free, params);
    st->normalizer = lua_normalizer_func;
    st->normalizer_data = params;
    return TRUE;
}
#endif


gboolean 
parse_normalizer (struct config_file *cfg, struct statfile *st, const gchar *line)
{
    gchar *params_begin;

    params_begin = strchr (line, ':');
    if (params_begin == NULL) {
        msg_err ("no parameters are specified for normalizer %s", line);
        return FALSE;
    }

    /* Try to guess normalizer */
    if (g_ascii_strncasecmp (line, "internal", sizeof ("points")) == 0) {
        return parse_internal_normalizer (cfg, st, params_begin + 1);
    }
#ifdef WITH_LUA
    else if (g_ascii_strncasecmp (line, "points", sizeof ("points")) == 0) {
        return parse_lua_normalizer (cfg, st, params_begin + 1);
    }
#endif
    
    msg_err ("unknown normalizer %s", line);
    return FALSE;
}

static GMarkupParser xml_parser = {
	.start_element = rspamd_xml_start_element,
	.end_element = rspamd_xml_end_element,
	.passthrough = NULL,
	.text = rspamd_xml_text,
	.error = rspamd_xml_error,
};

static const char*
get_filename_extension (const char *filename)
{
	const char *dot_pos = strrchr (filename, '.');

	if (dot_pos != NULL) {
		return (dot_pos + 1);
	}

	return NULL;
}


/*
 * Variables:
 * $CONFDIR - configuration directory
 * $RUNDIR - local states directory
 * $DBDIR - databases dir
 * $LOGDIR - logs dir
 * $PLUGINSDIR - pluggins dir
 * $PREFIX - installation prefix
 * $VERSION - rspamd version
 */

#define RSPAMD_CONFDIR_MACRO "CONFDIR"
#define RSPAMD_RUNDIR_MACRO "RUNDIR"
#define RSPAMD_DBDIR_MACRO "DBDIR"
#define RSPAMD_LOGDIR_MACRO "LOGDIR"
#define RSPAMD_PLUGINSDIR_MACRO "PLUGINSDIR"
#define RSPAMD_PREFIX_MACRO "PREFIX"
#define RSPAMD_VERSION_MACRO "VERSION"

static void
rspamd_ucl_add_conf_variables (struct ucl_parser *parser)
{
	ucl_parser_register_variable (parser, RSPAMD_CONFDIR_MACRO, RSPAMD_CONFDIR);
	ucl_parser_register_variable (parser, RSPAMD_RUNDIR_MACRO, RSPAMD_RUNDIR);
	ucl_parser_register_variable (parser, RSPAMD_DBDIR_MACRO, RSPAMD_DBDIR);
	ucl_parser_register_variable (parser, RSPAMD_LOGDIR_MACRO, RSPAMD_LOGDIR);
	ucl_parser_register_variable (parser, RSPAMD_PLUGINSDIR_MACRO, RSPAMD_PLUGINSDIR);
	ucl_parser_register_variable (parser, RSPAMD_PREFIX_MACRO, RSPAMD_PREFIX);
	ucl_parser_register_variable (parser, RSPAMD_VERSION_MACRO, RVERSION);
}

gboolean
read_rspamd_config (struct config_file *cfg, const gchar *filename,
		const gchar *convert_to, rspamd_rcl_section_fin_t logger_fin,
		gpointer logger_ud)
{
	struct stat                     st;
	gint                            fd;
	gchar                          *data, *rcl;
	const gchar                    *ext;
	GMarkupParseContext            *ctx;
	GError                         *err = NULL;
	struct rspamd_rcl_section     *top, *logger;
	gboolean res, is_xml = FALSE;
	struct rspamd_xml_userdata ud;
	struct ucl_parser *parser;

	if (stat (filename, &st) == -1) {
		msg_err ("cannot stat %s: %s", filename, strerror (errno));
		return FALSE;
	}
	if ((fd = open (filename, O_RDONLY)) == -1) {
		msg_err ("cannot open %s: %s", filename, strerror (errno));
		return FALSE;
	
	}
	/* Now mmap this file to simplify reading process */
	if ((data = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		msg_err ("cannot mmap %s: %s", filename, strerror (errno));
		close (fd);
		return FALSE;
	}
	close (fd);
	
	if (convert_to != NULL) {
		is_xml = TRUE;
	}
	else {
		ext = get_filename_extension (filename);
		if (ext != NULL && strcmp (ext, "xml") == 0) {
			is_xml = TRUE;
		}
	}

	if (is_xml) {
		/* Prepare xml parser */
		memset (&ud, 0, sizeof (ud));
		ud.cfg = cfg;
		ud.state = 0;
		ctx = g_markup_parse_context_new (&xml_parser, G_MARKUP_TREAT_CDATA_AS_TEXT, &ud, NULL);
		res = g_markup_parse_context_parse (ctx, data, st.st_size, &err);

		munmap (data, st.st_size);
	}
	else {
		parser = ucl_parser_new (0);
		rspamd_ucl_add_conf_variables (parser);
		if (!ucl_parser_add_chunk (parser, data, st.st_size)) {
			msg_err ("ucl parser error: %s", ucl_parser_get_error (parser));
			munmap (data, st.st_size);
			return FALSE;
		}
		munmap (data, st.st_size);
		cfg->rcl_obj = ucl_parser_get_object (parser);
		res = TRUE;
	}

	if (!res) {
		return FALSE;
	}

	if (is_xml && convert_to != NULL) {
		/* Convert XML config to UCL */
		rcl = ucl_object_emit (cfg->rcl_obj, UCL_EMIT_CONFIG);
		if (rcl != NULL) {
			fd = open (convert_to, O_CREAT|O_TRUNC|O_WRONLY, 00644);
			if (fd == -1) {
				msg_err ("cannot open %s: %s", convert_to, strerror (errno));
			}
			else if (write (fd, rcl, strlen (rcl)) == -1) {
				msg_err ("cannot write rcl %s: %s", convert_to, strerror (errno));
			}
			else {
				msg_info ("dumped xml configuration %s to ucl configuration %s",
						filename, convert_to);
			}
			close (fd);
			free (rcl);
		}
	}

	top = rspamd_rcl_config_init ();
	err = NULL;

	HASH_FIND_STR(top, "logging", logger);
	if (logger != NULL) {
		logger->fin = logger_fin;
		logger->fin_ud = logger_ud;
	}

	if (!rspamd_read_rcl_config (top, cfg, cfg->rcl_obj, &err)) {
		msg_err ("rcl parse error: %s", err->message);
		return FALSE;
	}

	return TRUE;
}

static void
symbols_classifiers_callback (gpointer key, gpointer value, gpointer ud)
{
	struct config_file             *cfg = ud;

	register_virtual_symbol (&cfg->cache, key, 1.0);
}

void
insert_classifier_symbols (struct config_file *cfg)
{
	g_hash_table_foreach (cfg->classifiers_symbols, symbols_classifiers_callback, cfg);
}

struct classifier_config*
find_classifier_conf (struct config_file *cfg, const gchar *name)
{
	GList                          *cur;
	struct classifier_config       *cf;

	if (name == NULL) {
		return NULL;
	}

	cur = cfg->classifiers;
	while (cur) {
		cf = cur->data;

		if (g_ascii_strcasecmp (cf->classifier->name, name) == 0) {
			return cf;
		}

		cur = g_list_next (cur);
	}

	return NULL;
}

gboolean
check_classifier_statfiles (struct classifier_config *cf)
{
	struct statfile                *st;
	gboolean                        has_other = FALSE, res = FALSE, cur_class;
	GList                          *cur;

	/* First check classes directly */
	cur = cf->statfiles;
	while (cur) {
		st = cur->data;
		if (!has_other) {
			cur_class = st->is_spam;
			has_other = TRUE;
		}
		else {
			if (cur_class != st->is_spam) {
				return TRUE;
			}
		}

		cur = g_list_next (cur);
	}

	if (!has_other) {
		/* We have only one statfile */
		return FALSE;
	}
	/* We have not detected any statfile that has different class, so turn on euristic based on symbol's name */
	has_other = FALSE;
	cur = cf->statfiles;
	while (cur) {
		st = cur->data;
		if (rspamd_strncasestr (st->symbol, "spam", -1) != NULL) {
			st->is_spam = TRUE;
		}
		else if (rspamd_strncasestr (st->symbol, "ham", -1) != NULL) {
			st->is_spam = FALSE;
		}

		if (!has_other) {
			cur_class = st->is_spam;
			has_other = TRUE;
		}
		else {
			if (cur_class != st->is_spam) {
				res = TRUE;
			}
		}

		cur = g_list_next (cur);
	}

	return res;
}

/*
 * vi:ts=4
 */
