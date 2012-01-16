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

#include "cfg_file.h"
#include "main.h"
#include "filter.h"
#include "settings.h"
#include "classifiers/classifiers.h"
#include "cfg_xml.h"
#include "lua/lua_common.h"
#include "kvstorage_config.h"

#define DEFAULT_SCORE 10.0

#define DEFAULT_RLIMIT_NOFILE 2048
#define DEFAULT_RLIMIT_MAXCORE 0


gboolean
parse_host_port (const gchar *str, struct in_addr *ina, guint16 *port)
{
	gchar                           **tokens, *err_str;
	struct hostent                 *hent;
	guint                           port_parsed, saved_errno = errno;

	tokens = g_strsplit_set (str, ":", 0);
	if (!tokens || !tokens[0]) {
		return FALSE;
	}
	
	/* Now try to parse host and write address to ina */
	if (!inet_aton (tokens[0], ina)) {
		if (strcmp (tokens[0], "*") == 0) {
			/* Special case */
			ina->s_addr = htonl (INADDR_ANY);
		}
		else {
			/* Try to call gethostbyname */
			hent = gethostbyname (tokens[0]);
			if (hent == NULL) {
				msg_warn ("cannot resolve %s", tokens[0]);
				goto err;
			}
			else {
				memcpy (ina, hent->h_addr, sizeof (struct in_addr));	
			}
		}
	}
	if (tokens[1] != NULL) {
		/* Port part */
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
	
	/* Restore errno */
	errno = saved_errno;
	g_strfreev (tokens);
	return TRUE;

err:
	errno = saved_errno;
	g_strfreev (tokens);
	return FALSE;
}

gint
parse_bind_line (struct config_file *cfg, struct worker_conf *cf, gchar *str)
{
	gchar                          **host;
	guint16                        *family, *port;
	struct in_addr                 *addr;

	if (str == NULL)
		return 0;

	host = &cf->bind_host;
	port = &cf->bind_port;
	*port = DEFAULT_BIND_PORT;
	family = &cf->bind_family;
	addr = &cf->bind_addr;

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
					return 0;
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
		*host = memory_pool_strdup (cfg->cfg_pool, str);
		*family = AF_UNIX;
		return 1;
	}
	else {
		if (parse_host_port (str, addr, port)) {
			*host = memory_pool_strdup (cfg->cfg_pool, str);
			*family = AF_INET;

			return 1;
		}
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
	cfg->modules_opts = g_hash_table_new (g_str_hash, g_str_equal);
	cfg->variables = g_hash_table_new (g_str_hash, g_str_equal);
	cfg->metrics = g_hash_table_new (g_str_hash, g_str_equal);
	cfg->c_modules = g_hash_table_new (g_str_hash, g_str_equal);
	cfg->composite_symbols = g_hash_table_new (g_str_hash, g_str_equal);
	cfg->classifiers_symbols = g_hash_table_new (g_str_hash, g_str_equal);
	cfg->cfg_params = g_hash_table_new (g_str_hash, g_str_equal);
	cfg->metrics_symbols = g_hash_table_new (g_str_hash, g_str_equal);

	cfg->log_level = G_LOG_LEVEL_WARNING;
	cfg->log_extended = TRUE;

	init_settings (cfg);

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
	g_hash_table_remove_all (cfg->c_modules);
	g_hash_table_unref (cfg->c_modules);
	g_hash_table_remove_all (cfg->composite_symbols);
	g_hash_table_unref (cfg->composite_symbols);
	g_hash_table_remove_all (cfg->cfg_params);
	g_hash_table_unref (cfg->cfg_params);
	g_hash_table_destroy (cfg->metrics_symbols);
	g_hash_table_destroy (cfg->classifiers_symbols);
	if (cfg->checksum) {
		g_free (cfg->checksum);
	}
	g_list_free (cfg->classifiers);
	g_list_free (cfg->metrics_list);
	memory_pool_delete (cfg->cfg_pool);
}

gchar                           *
get_module_opt (struct config_file *cfg, gchar *module_name, gchar *opt_name)
{
	GList                          *cur_opt;
	struct module_opt              *cur;
	static gchar                     numbuf[64];

	cur_opt = g_hash_table_lookup (cfg->modules_opts, module_name);
	if (cur_opt == NULL) {
		return NULL;
	}

	while (cur_opt) {
		cur = cur_opt->data;
		if (strcmp (cur->param, opt_name) == 0) {
			/* Check if it is lua variable */
			if (! cur->is_lua) {
				/* Plain variable */
				return cur->value;
			}
			else {
				/* Check type */
				switch (cur->lua_type) {
					case LUA_VAR_NUM:
						/* numbuf is static, so it is safe to return it "as is" */
						snprintf (numbuf, sizeof (numbuf), "%f", *(double *)cur->actual_data);
						return numbuf;
					case LUA_VAR_BOOLEAN:
						snprintf (numbuf, sizeof (numbuf), "%s", *(gboolean *)cur->actual_data ? "yes" : "no");
						return numbuf;
					case LUA_VAR_STRING:
						return (gchar *)cur->actual_data;
					case LUA_VAR_FUNCTION:
						msg_info ("option %s is dynamic, so it cannot be aqquired statically", opt_name);
						return NULL;
					case LUA_VAR_UNKNOWN:
						msg_info ("option %s has unknown type, maybe there is error in LUA code", opt_name);
						return NULL;
				}
			}
		}
		cur_opt = g_list_next (cur_opt);
	}

	return NULL;
}

gsize
parse_limit (const gchar *limit, guint len)
{
	gsize                          result = 0;
	const gchar                   *err_str;

	if (!limit || *limit == '\0' || len == 0) {
		return 0;
	}

	errno = 0;
	result = strtoul (limit, (gchar **)&err_str, 10);

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
		else if (len > 0 && err_str - limit != len) {
			msg_warn ("invalid limit value '%s' at position '%s'", limit, err_str);
			result = 0;
		}
	}

	return result;
}

guint
cfg_parse_time (const gchar *t, enum time_type default_type)
{
	union {
		guint                       i;
		double                      d;
	}                               result;
	gboolean                        use_double = FALSE;
	gchar                           *err_str;

	if (!t || *t == '\0')
		return 0;

	errno = 0;
	result.i = strtoul (t, &err_str, 10);

	if (*err_str != '\0') {
		if (*err_str == '.') {
			/* Try to handle decimal point */
			errno = 0;
			result.d = strtod (t, &err_str);
			use_double = TRUE;
		}
		/* Seconds */
		if (*err_str == 's' || *err_str == 'S') {
			if (use_double) {
				result.d *= 1000.;
			}
			else {
				result.i *= 1000;
			}
		}
		/* Minutes */
		else if (*err_str == 'm' || *err_str == 'M') {
			/* Handle ms correctly */
			if (*(err_str + 1) != 's' && *(err_str + 1) != 'S') {
				if (use_double) {
					result.d *= 60. * 1000.;
				}
				else {
					result.i *= 60 * 1000;
				}
			}
		}
		/* Hours */
		else if (*err_str == 'h' || *err_str == 'H') {
			if (use_double) {
				result.d *= 60. * 60. * 1000.;
			}
			else {
				result.i *= 60 * 60 * 1000;
			}
		}
		/* Days */
		else if (*err_str == 'd' || *err_str == 'D') {
			if (use_double) {
				result.d *= 24. * 60. * 60. * 1000.;
			}
			else {
				result.i *= 24 * 60 * 60 * 1000;
			}
		}
		else {
			msg_warn ("invalid time value '%s' at position '%s'", t, err_str);
			if (use_double) {
				result.d = 0.;
			}
			else {
				result.i = 0;
			}
		}
	}
	else {
		/* Switch to default time multiplier */
		switch (default_type) {
		case TIME_HOURS:
			if (use_double) {
				result.d *= 60. * 60. * 1000.;
			}
			else {
				result.i *= 60 * 60 * 1000;
			}
			break;
		case TIME_MINUTES:
			if (use_double) {
				result.d *= 60. * 1000.;
			}
			else {
				result.i *= 60 * 1000;
			}
			break;
		case TIME_SECONDS:
			if (use_double) {
				result.d *= 1000.;
			}
			else {
				result.i *= 1000;
			}
			break;
		case TIME_MILLISECONDS:
			break;
		}
	}
	if (use_double) {
		return rint (result.d);
	}
	else {
		return result.i;
	}
}

gchar
parse_flag (const gchar *str)
{
	if (!str || !*str)
		return -1;

	if ((*str == 'Y' || *str == 'y')) {
		return 1;
	}

	if ((*str == 'Y' || *str == 'y') && (*(str + 1) == 'E' || *(str + 1) == 'e') && (*(str + 2) == 'S' || *(str + 2) == 's')) {
		return 1;
	}

	if ((*str == 'N' || *str == 'n')) {
		return 0;
	}

	if ((*str == 'N' || *str == 'n') && (*(str + 1) == 'O' || *(str + 1) == 'o')) {
		return 0;
	}

	return -1;
}

/*
 * Try to substitute all variables in given string
 * Return: newly allocated string with substituted variables (original string may be freed if variables are found)
 */
gchar                           *
substitute_variable (struct config_file *cfg, gchar *name, gchar *str, guchar recursive)
{
	gchar                           *var, *new, *v_begin, *v_end, *p, t;
	gsize                          len;
	gboolean                        changed = FALSE;

	if (str == NULL) {
		msg_warn ("trying to substitute variable in NULL string");
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
			msg_warn ("variable %s is not defined", v_begin);
			*v_end = t;
			p = v_end + 1;
			continue;
		}
		else if (recursive) {
			var = substitute_variable (cfg, v_begin, var, recursive);
		}
		/* Allocate new string */
		new = memory_pool_alloc (cfg->cfg_pool, len - strlen (v_begin) + strlen (var) + 3);

		snprintf (new, len - strlen (v_begin) + strlen (var) + 3, "%s(%s)%s", str, var, v_end + 1);
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
	struct config_file             *cfg = (struct config_file *)data;
	GList                          *cur_opt = (GList *) value;
	struct module_opt              *cur;

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
	struct config_file             *cfg = (struct config_file *)data;

	/* Do recursive substitution */
	(void)substitute_variable (cfg, (gchar *)key, (gchar *)value, 1);
}

static void
parse_filters_str (struct config_file *cfg, const gchar *str)
{
	gchar                         **strvec, **p;
	struct filter                  *cur;
	module_t					  **pmodule;

	if (str == NULL) {
		return;
	}

	strvec = g_strsplit_set (str, ",", 0);
	if (strvec == NULL) {
		return;
	}

	p = strvec;
	while (*p) {
		cur = NULL;
		/* Search modules from known C modules */
		pmodule = &modules[0];
		while (*pmodule) {
			g_strstrip (*p);
			if ((*pmodule)->name != NULL && g_ascii_strcasecmp ((*pmodule)->name, *p) == 0) {
				cur = memory_pool_alloc (cfg->cfg_pool, sizeof (struct filter));
				cur->type = C_FILTER;
				msg_debug ("found C filter %s", *p);
				cur->func_name = memory_pool_strdup (cfg->cfg_pool, *p);
				cur->module = (*pmodule);
				cfg->filters = g_list_prepend (cfg->filters, cur);

				break;
			}
			pmodule ++;
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
		p++;
	}

	g_strfreev (strvec);
}

/*
 * Place pointers to cfg_file structure to hash cfg_params
 */
static void
fill_cfg_params (struct config_file *cfg)
{
	struct config_scalar           *scalars;

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

	g_hash_table_foreach (cfg->variables, substitute_all_variables, cfg);
	g_hash_table_foreach (cfg->modules_opts, substitute_module_variables, cfg);
	parse_filters_str (cfg, cfg->filters_str);
	fill_cfg_params (cfg);

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
		def_metric->required_score = DEFAULT_SCORE;
		def_metric->reject_score = DEFAULT_REJECT_SCORE;
		cfg->metrics_list = g_list_prepend (cfg->metrics_list, def_metric);
		g_hash_table_insert (cfg->metrics, DEFAULT_METRIC, def_metric);
	}

	cfg->default_metric = def_metric;

	/* Lua options */
	(void)lua_post_load_config (cfg);
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
parse_comma_list (memory_pool_t * pool, gchar *line)
{
	GList                          *res = NULL;
	gchar                           *c, *p, *str;

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
		c->opts = g_hash_table_new (g_str_hash, g_str_equal);
		memory_pool_add_destructor (cfg->cfg_pool, (pool_destruct_func) g_hash_table_destroy, c->opts);
	}

	return c;
}

struct statfile*
check_statfile_conf (struct config_file *cfg, struct statfile *c)
{
	if (c == NULL) {
		c = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile));
	}
	if (c->opts == NULL) {
		c->opts = g_hash_table_new (g_str_hash, g_str_equal);
		memory_pool_add_destructor (cfg->cfg_pool, (pool_destruct_func) g_hash_table_destroy, c->opts);
	}

	return c;
}

struct metric *
check_metric_conf (struct config_file *cfg, struct metric *c)
{
	if (c == NULL) {
		c = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct metric));
		c->action = METRIC_ACTION_REJECT;
		c->grow_factor = 1.0;
		c->symbols = g_hash_table_new (g_str_hash, g_str_equal);
		c->descriptions = g_hash_table_new (g_str_hash, g_str_equal);
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
		c->params = g_hash_table_new (g_str_hash, g_str_equal);
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
#else
    /*
     * As some implementations of libm does not support tanhl, try to use
     * tanh
     */
    return max * tanh ((double) (score / max));
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

gboolean
read_xml_config (struct config_file *cfg, const gchar *filename)
{
	struct stat                     st;
	gint                            fd;
	gchar                          *data;
	gboolean                        res;
	GMarkupParseContext            *ctx;
	GError                         *err = NULL;

	struct rspamd_xml_userdata ud;

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
	
	/* Prepare xml parser */
	ud.cfg = cfg;
	ud.state = XML_READ_START;
	ud.if_stack = g_queue_new ();

	ctx = g_markup_parse_context_new (&xml_parser, G_MARKUP_TREAT_CDATA_AS_TEXT, &ud, NULL);
	init_kvstorage_config ();
	res = g_markup_parse_context_parse (ctx, data, st.st_size, &err);

	if (g_queue_get_length (ud.if_stack) != 0) {
		msg_err ("unexpected nesting for if arguments");
		res = FALSE;
	}

	munmap (data, st.st_size);

	return res;
}

static void
modules_config_callback (gpointer key, gpointer value, gpointer ud)
{
	extern GHashTable              *module_options;
	GHashTable                     *cur_module;
	GList                          *cur;
	struct module_opt              *opt;
	const gchar                    *mname = key;
	gboolean                       *res = ud;

	if ((cur_module = g_hash_table_lookup (module_options, mname)) == NULL) {
		msg_warn ("module %s has not registered any options but is presented in configuration", mname);
		*res = FALSE;
		return;
	}

	cur = value;
	while (cur) {
		opt = cur->data;

		if (!opt->is_lua && !check_module_option (mname, opt->param, opt->value)) {
			*res = FALSE;
			return;
		}

		cur = g_list_next (cur);
	}
}

gboolean
check_modules_config (struct config_file *cfg)
{
	gboolean                        res = TRUE;

	g_hash_table_foreach (cfg->modules_opts, modules_config_callback, &res);
	return res;
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
