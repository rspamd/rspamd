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

struct rspamd_ucl_map_cbdata {
	struct config_file *cfg;
	GString *buf;
};
static gchar* rspamd_ucl_read_cb (memory_pool_t * pool, gchar * chunk, gint len, struct map_cb_data *data);
static void rspamd_ucl_fin_cb (memory_pool_t * pool, struct map_cb_data *data);

static gboolean
parse_host_port_priority_strv (memory_pool_t *pool, gchar **tokens,
		gchar **addr, guint16 *port, guint *priority, guint default_port)
{
	gchar                          *err_str, portbuf[8];
	const gchar                    *cur_tok, *cur_port;
	struct addrinfo                hints, *res;
	guint                           port_parsed, priority_parsed, saved_errno = errno;
	gint							r;
	union {
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	}                               addr_holder;

	/* Now try to parse host and write address to ina */
	memset (&hints, 0, sizeof (hints));
	hints.ai_socktype = SOCK_STREAM; /* Type of the socket */
	hints.ai_flags = AI_NUMERICSERV;

	cur_tok = tokens[0];

	if (strcmp (cur_tok, "*v6") == 0) {
		hints.ai_family = AF_INET6;
		hints.ai_flags |= AI_PASSIVE;
		cur_tok = NULL;
	}
	else if (strcmp (cur_tok, "*v4") == 0) {
		hints.ai_family = AF_INET;
		hints.ai_flags |= AI_PASSIVE;
		cur_tok = NULL;
	}
	else {
		hints.ai_family = AF_UNSPEC;
	}

	if (tokens[1] != NULL) {
		/* Port part */
		rspamd_strlcpy (portbuf, tokens[1], sizeof (portbuf));
		cur_port = portbuf;
		if (port != NULL) {
			errno = 0;
			port_parsed = strtoul (tokens[1], &err_str, 10);
			if (*err_str != '\0' || errno != 0) {
				msg_warn ("cannot parse port: %s, at symbol %c, error: %s", tokens[1], *err_str, strerror (errno));
				hints.ai_flags ^= AI_NUMERICSERV;
			}
			else if (port_parsed > G_MAXUINT16) {
				errno = ERANGE;
				msg_warn ("cannot parse port: %s, error: %s", tokens[1], *err_str, strerror (errno));
				hints.ai_flags ^= AI_NUMERICSERV;
			}
			else {
				*port = port_parsed;
			}
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
				}
				else {
					*priority = priority_parsed;
				}
			}
		}
	}
	else if (default_port != 0) {
		rspamd_snprintf (portbuf, sizeof (portbuf), "%ud", default_port);
		cur_port = portbuf;
	}
	else {
		cur_port = NULL;
	}

	if ((r = getaddrinfo (cur_tok, cur_port, &hints, &res)) == 0) {
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

	/* Restore errno */
	errno = saved_errno;
	return TRUE;

err:
	errno = saved_errno;
	return FALSE;
}

gboolean
parse_host_port_priority (memory_pool_t *pool, const gchar *str, gchar **addr, guint16 *port, guint *priority)
{
	gchar                          **tokens;
	gboolean                         ret;

	tokens = g_strsplit_set (str, ":", 0);
	if (!tokens || !tokens[0]) {
		return FALSE;
	}

	ret = parse_host_port_priority_strv (pool, tokens, addr, port, priority, 0);

	g_strfreev (tokens);

	return ret;
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
	gchar **tokens, *tmp, *err;
	gboolean ret = TRUE;

	if (str == NULL) {
		return FALSE;
	}

	tokens = g_strsplit_set (str, ":", 0);
	if (!tokens || !tokens[0]) {
		return FALSE;
	}

	cnf = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct rspamd_worker_bind_conf));
	cnf->bind_port = DEFAULT_BIND_PORT;
	cnf->bind_host = memory_pool_strdup (cfg->cfg_pool, str);
	cnf->ai = AF_UNSPEC;

	if (*tokens[0] == '/' || *tokens[0] == '.') {
		cnf->ai = AF_UNIX;
		LL_PREPEND (cf->bind_conf, cnf);
		return TRUE;
	}
	else if (strcmp (tokens[0], "*") == 0) {
		/* We need to add two listen entries: one for ipv4 and one for ipv6 */
		tmp = tokens[0];
		tokens[0] = "*v4";
		cnf->ai = AF_INET;
		if ((ret = parse_host_port_priority_strv (cfg->cfg_pool, tokens,
				&cnf->bind_host, &cnf->bind_port, NULL, DEFAULT_BIND_PORT))) {
			LL_PREPEND (cf->bind_conf, cnf);
		}
		cnf = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct rspamd_worker_bind_conf));
		cnf->bind_port = DEFAULT_BIND_PORT;
		cnf->bind_host = memory_pool_strdup (cfg->cfg_pool, str);
		cnf->ai = AF_INET6;
		tokens[0] = "*v6";
		if ((ret &= parse_host_port_priority_strv (cfg->cfg_pool, tokens,
				&cnf->bind_host, &cnf->bind_port, NULL, DEFAULT_BIND_PORT))) {
			LL_PREPEND (cf->bind_conf, cnf);
		}
		tokens[0] = tmp;
	}
	else if (strcmp (tokens[0], "systemd") == 0) {
		/* The actual socket will be passed by systemd environment */
		cnf->bind_host = memory_pool_strdup (cfg->cfg_pool, str);
		cnf->ai = strtoul (tokens[1], &err, 10);
		cnf->is_systemd = TRUE;
		if (err == NULL || *err == '\0') {
			LL_PREPEND (cf->bind_conf, cnf);
		}
	}
	else {
		if ((ret = parse_host_port_priority_strv (cfg->cfg_pool, tokens,
				&cnf->bind_host, &cnf->bind_port, NULL, DEFAULT_BIND_PORT))) {
			LL_PREPEND (cf->bind_conf, cnf);
		}
	}

	g_strfreev (tokens);

	return ret;
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
	/* 16 sockets per DNS server */
	cfg->dns_io_per_server = 16;

	cfg->statfile_sync_interval = 60000;
	cfg->statfile_sync_timeout = 20000;

	/* 20 Kb */
	cfg->max_diff = 20480;

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

const ucl_object_t        *
get_module_opt (struct config_file *cfg, const gchar *module_name, const gchar *opt_name)
{
	const ucl_object_t *res = NULL, *sec;

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

static bool
rspamd_include_map_handler (const guchar *data, gsize len, void* ud)
{
	struct config_file *cfg = (struct config_file *)ud;
	struct rspamd_ucl_map_cbdata *cbdata, **pcbdata;
	gchar *map_line;

	map_line = memory_pool_alloc (cfg->cfg_pool, len + 1);
	rspamd_strlcpy (map_line, data, len + 1);

	cbdata = g_malloc (sizeof (struct rspamd_ucl_map_cbdata));
	pcbdata = g_malloc (sizeof (struct rspamd_ucl_map_cbdata *));
	cbdata->buf = NULL;
	cbdata->cfg = cfg;
	*pcbdata = cbdata;

	return add_map (cfg, map_line, "ucl include", rspamd_ucl_read_cb, rspamd_ucl_fin_cb, (void **)pcbdata);
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

static void
rspamd_ucl_add_conf_macros (struct ucl_parser *parser, struct config_file *cfg)
{
	ucl_parser_register_macro (parser, "include_map", rspamd_include_map_handler, cfg);
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
		rspamd_ucl_add_conf_macros (parser, cfg);
		if (!ucl_parser_add_chunk (parser, data, st.st_size)) {
			msg_err ("ucl parser error: %s", ucl_parser_get_error (parser));
			ucl_parser_free (parser);
			munmap (data, st.st_size);
			return FALSE;
		}
		munmap (data, st.st_size);
		cfg->rcl_obj = ucl_parser_get_object (parser);
		ucl_parser_free (parser);
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

static gchar*
rspamd_ucl_read_cb (memory_pool_t * pool, gchar * chunk, gint len, struct map_cb_data *data)
{
	struct rspamd_ucl_map_cbdata *cbdata = data->cur_data, *prev;

	if (cbdata == NULL) {
		cbdata = g_malloc (sizeof (struct rspamd_ucl_map_cbdata));
		prev = data->prev_data;
		cbdata->buf = g_string_sized_new (BUFSIZ);
		cbdata->cfg = prev->cfg;
		data->cur_data = cbdata;
	}
	g_string_append_len (cbdata->buf, chunk, len);

	/* Say not to copy any part of this buffer */
	return NULL;
}

static void
rspamd_ucl_fin_cb (memory_pool_t * pool, struct map_cb_data *data)
{
	struct rspamd_ucl_map_cbdata *cbdata = data->cur_data, *prev = data->prev_data;
	ucl_object_t *obj;
	struct ucl_parser *parser;
	guint32 checksum;

	if (prev != NULL) {
		if (prev->buf != NULL) {
			g_string_free (prev->buf, TRUE);
		}
		g_free (prev);
	}

	if (cbdata == NULL) {
		msg_err ("map fin error: new data is NULL");
		return;
	}

	checksum = murmur32_hash (cbdata->buf->str, cbdata->buf->len);
	if (data->map->checksum != checksum) {
		/* New data available */
		parser = ucl_parser_new (0);
		if (!ucl_parser_add_chunk (parser, cbdata->buf->str, cbdata->buf->len)) {
			msg_err ("cannot parse map %s: %s", data->map->uri, ucl_parser_get_error (parser));
			ucl_parser_free (parser);
		}
		else {
			obj = ucl_parser_get_object (parser);
			ucl_parser_free (parser);
			/* XXX: add replace objects code */
			ucl_object_unref (obj);
			data->map->checksum = checksum;
		}
	}
	else {
		msg_info ("do not reload map %s, checksum is the same: %d", data->map->uri, checksum);
	}
}

gboolean
rspamd_parse_ip_list (const gchar *ip_list, radix_tree_t **tree)
{
	gchar                           **strvec, **cur;
	struct in_addr                   ina;
	guint32                           mask;

	strvec = g_strsplit_set (ip_list, ",", 0);
	cur = strvec;

	while (*cur != NULL) {
		/* XXX: handle only ipv4 addresses */
		if (parse_ipmask_v4 (*cur, &ina, &mask)) {
			if (*tree == NULL) {
				*tree = radix_tree_create ();
			}
			radix32tree_add (*tree, htonl (ina.s_addr), mask, 1);
		}
		cur ++;
	}

	return (*tree != NULL);
}

/*
 * vi:ts=4
 */
