/* Copyright (c) 2010-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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
#include "libserver/dynamic_cfg.h"
#include "libutil/rrd.h"
#include "libutil/map.h"
#include "main.h"

#ifdef WITH_GPERF_TOOLS
#   include <glib/gprintf.h>
#endif

/* 60 seconds for worker's IO */
#define DEFAULT_WORKER_IO_TIMEOUT 60000

/* HTTP paths */
#define PATH_AUTH "/auth"
#define PATH_SYMBOLS "/symbols"
#define PATH_ACTIONS "/actions"
#define PATH_MAPS "/maps"
#define PATH_GET_MAP "/getmap"
#define PATH_GRAPH "/graph"
#define PATH_PIE_CHART "/pie"
#define PATH_HISTORY "/history"
#define PATH_LEARN_SPAM "/learnspam"
#define PATH_LEARN_HAM "/learnham"
#define PATH_SAVE_ACTIONS "/saveactions"
#define PATH_SAVE_SYMBOLS "/savesymbols"
#define PATH_SAVE_MAP "/savemap"
#define PATH_SCAN "/scan"
#define PATH_CHECK "/check"
#define PATH_STAT "/stat"
#define PATH_STAT_RESET "/statreset"
#define PATH_COUNTERS "/counters"

/* Graph colors */
#define COLOR_CLEAN "#58A458"
#define COLOR_PROBABLE_SPAM "#D67E7E"
#define COLOR_GREYLIST "#A0A0A0"
#define COLOR_REJECT "#CB4B4B"
#define COLOR_TOTAL "#9440ED"

gpointer init_controller_worker (struct rspamd_config *cfg);
void start_controller_worker (struct rspamd_worker *worker);

worker_t controller_worker = {
	"controller",                   /* Name */
	init_controller_worker,         /* Init function */
	start_controller_worker,        /* Start function */
	TRUE,                   /* Has socket */
	TRUE,                   /* Non unique */
	FALSE,                  /* Non threaded */
	TRUE,                   /* Killable */
	SOCK_STREAM             /* TCP socket */
};
/*
 * Worker's context
 */
struct rspamd_controller_worker_ctx {
	guint32 timeout;
	struct timeval io_tv;
	/* DNS resolver */
	struct rspamd_dns_resolver *resolver;
	/* Events base */
	struct event_base *ev_base;
	/* Whether we use ssl for this server */
	gboolean use_ssl;
	/* Webui password */
	gchar *password;
	/* Privilleged password */
	gchar *enable_password;
	/* HTTP server */
	struct rspamd_http_connection_router *http;
	/* Server's start time */
	time_t start_time;
	/* Main server */
	struct rspamd_main *srv;
	/* Configuration */
	struct rspamd_config *cfg;
	/* SSL cert */
	gchar *ssl_cert;
	/* SSL private key */
	gchar *ssl_key;
	/* A map of secure IP */
	gchar *secure_ip;
	radix_compressed_t *secure_map;

	/* Static files dir */
	gchar *static_files_dir;

	/* Custom commands registered by plugins */
	GHashTable *custom_commands;

	/* Worker */
	struct rspamd_worker *worker;
};

struct rspamd_controller_session {
	struct rspamd_controller_worker_ctx *ctx;
	rspamd_mempool_t *pool;
	struct rspamd_task *task;
	struct rspamd_classifier_config *cl;
	rspamd_inet_addr_t from_addr;
	gboolean is_spam;
};

/* Check for password if it is required by configuration */
static gboolean
rspamd_controller_check_password (struct rspamd_http_connection_entry *entry,
	struct rspamd_controller_session *session, struct rspamd_http_message *msg,
	gboolean is_enable)
{
	const gchar *password, *check;
	struct rspamd_controller_worker_ctx *ctx = session->ctx;
	gboolean ret = TRUE;

	/* Access list logic */
	if (!session->from_addr.af == AF_UNIX) {
		msg_info ("allow unauthorized connection from a unix socket");
		return TRUE;
	}
	else if (ctx->secure_map && radix_find_compressed_addr (ctx->secure_map,
		&session->from_addr) != RADIX_NO_VALUE) {
		msg_info ("allow unauthorized connection from a trusted IP %s",
			rspamd_inet_address_to_string (&session->from_addr));
		return TRUE;
	}

	/* Password logic */
	if (is_enable) {
		/* For privileged commands we strictly require enable password */
		password = rspamd_http_message_find_header (msg, "Password");
		if (ctx->enable_password == NULL) {
			/* Use just a password (legacy mode) */
			msg_info (
				"using password as enable_password for a privileged command");
			check = ctx->password;
		}
		else {
			check = ctx->enable_password;
		}
		if (check != NULL) {
			if (password == NULL || strcmp (password, check) != 0) {
				msg_info ("incorrect or absent password has been specified");
				ret = FALSE;
			}
		}
		else {
			msg_warn (
				"no password to check while executing a privileged command");
			if (ctx->secure_map) {
				msg_info ("deny unauthorized connection");
				ret = FALSE;
			}
		}
	}
	else {
		password = rspamd_http_message_find_header (msg, "Password");
		if (ctx->password != NULL) {
			/* Accept both normal and enable passwords */
			check = ctx->password;
			if (password == NULL) {
				msg_info ("absent password has been specified");
				ret = FALSE;
			}
			else if (strcmp (password, check) != 0) {
				if (ctx->enable_password != NULL) {
					check = ctx->enable_password;
					if (strcmp (password, check) != 0) {
						msg_info ("incorrect password has been specified");
						ret = FALSE;
					}
				}
				else {
					msg_info ("incorrect or absent password has been specified");
					ret = FALSE;
				}
			}
		}
		/* No password specified, allowing this command */
	}


	if (!ret) {
		rspamd_controller_send_error (entry, 403, "Unauthorized");
	}

	return ret;
}

/* Command handlers */

/*
 * Auth command handler:
 * request: /auth
 * headers: Password
 * reply: json {"auth": "ok", "version": "0.5.2", "uptime": "some uptime", "error": "none"}
 */
static int
rspamd_controller_handle_auth (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_stat *st;
	int64_t uptime;
	gulong data[4];
	ucl_object_t *obj;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	obj = ucl_object_typed_new (UCL_OBJECT);
	st = session->ctx->srv->stat;
	data[0] = st->actions_stat[METRIC_ACTION_NOACTION];
	data[1] = st->actions_stat[METRIC_ACTION_ADD_HEADER] +
		st->actions_stat[METRIC_ACTION_REWRITE_SUBJECT];
	data[2] = st->actions_stat[METRIC_ACTION_GREYLIST];
	data[3] = st->actions_stat[METRIC_ACTION_REJECT];

	/* Get uptime */
	uptime = time (NULL) - session->ctx->start_time;

	ucl_object_insert_key (obj, ucl_object_fromstring (
			RVERSION),			   "version",  0, false);
	ucl_object_insert_key (obj, ucl_object_fromstring (
			"ok"),				   "auth",	   0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			uptime),			   "uptime",   0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			data[0]),			   "clean",	   0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			data[1]),			   "probable", 0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			data[2]),			   "greylist", 0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			data[3]),			   "reject",   0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			st->messages_scanned), "scanned",  0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			st->messages_learned), "learned",  0, false);

	rspamd_controller_send_ucl (conn_ent, obj);
	ucl_object_unref (obj);

	return 0;
}

/*
 * Symbols command handler:
 * request: /symbols
 * reply: json [{
 *  "name": "group_name",
 *  "symbols": [
 *      {
 *      "name": "name",
 *      "weight": 0.1,
 *      "description": "description of symbol"
 *      },
 *      {...}
 * },
 * {...}]
 */
static int
rspamd_controller_handle_symbols (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	GList *cur_gr, *cur_sym;
	struct rspamd_symbols_group *gr;
	struct rspamd_symbol_def *sym;
	ucl_object_t *obj, *top, *sym_obj;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);

	/* Go through all symbols groups */
	cur_gr = session->ctx->cfg->symbols_groups;
	while (cur_gr) {
		gr = cur_gr->data;
		obj = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (obj, ucl_object_fromstring (
				gr->name), "group", 0, false);
		/* Iterate through all symbols */
		cur_sym = gr->symbols;
		while (cur_sym) {
			sym_obj = ucl_object_typed_new (UCL_OBJECT);
			sym = cur_sym->data;

			ucl_object_insert_key (sym_obj, ucl_object_fromstring (sym->name),
				"symbol", 0, false);
			ucl_object_insert_key (sym_obj,
				ucl_object_fromdouble (*sym->weight_ptr),
				"weight", 0, false);
			if (sym->description) {
				ucl_object_insert_key (sym_obj,
					ucl_object_fromstring (sym->description),
					"description", 0, false);
			}

			ucl_object_insert_key (obj, sym_obj, "rules", 0, false);
			cur_sym = g_list_next (cur_sym);
		}
		cur_gr = g_list_next (cur_gr);
		ucl_array_append (top, obj);
	}

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

/*
 * Actions command handler:
 * request: /actions
 * reply: json [{
 *  "action": "no action",
 *  "value": 1.1
 * },
 * {...}]
 */
static int
rspamd_controller_handle_actions (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct metric *metric;
	struct metric_action *act;
	gint i;
	ucl_object_t *obj, *top;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);

	/* Get actions for default metric */
	metric = g_hash_table_lookup (session->ctx->cfg->metrics, DEFAULT_METRIC);
	if (metric != NULL) {
		for (i = METRIC_ACTION_REJECT; i < METRIC_ACTION_MAX; i++) {
			act = &metric->actions[i];
			if (act->score >= 0) {
				obj = ucl_object_typed_new (UCL_OBJECT);
				ucl_object_insert_key (obj,
					ucl_object_fromstring (rspamd_action_to_str (
						act->action)), "action", 0, false);
				ucl_object_insert_key (obj, ucl_object_fromdouble (
						act->score), "value", 0, false);
				ucl_array_append (top, obj);
			}
		}
	}

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}
/*
 * Maps command handler:
 * request: /maps
 * headers: Password
 * reply: json [
 *      {
 *      "map": "name",
 *      "description": "description",
 *      "editable": true
 *      },
 *      {...}
 * ]
 */
static int
rspamd_controller_handle_maps (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	GList *cur, *tmp = NULL;
	struct rspamd_map *map;
	gboolean editable;
	ucl_object_t *obj, *top;


	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);
	/* Iterate over all maps */
	cur = session->ctx->cfg->maps;
	while (cur) {
		map = cur->data;
		if (map->protocol == MAP_PROTO_FILE) {
			if (access (map->uri, R_OK) == 0) {
				tmp = g_list_prepend (tmp, map);
			}
		}
		cur = g_list_next (cur);
	}
	/* Iterate over selected maps */
	cur = tmp;
	while (cur) {
		map = cur->data;
		editable = (access (map->uri, W_OK) == 0);

		obj = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (obj,	   ucl_object_fromint (map->id),
			"map", 0, false);
		if (map->description) {
			ucl_object_insert_key (obj, ucl_object_fromstring (map->description),
					"description", 0, false);
		}
		ucl_object_insert_key (obj,	  ucl_object_frombool (editable),
			"editable", 0, false);
		ucl_array_append (top, obj);

		cur = g_list_next (cur);
	}

	if (tmp) {
		g_list_free (tmp);
	}

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

/*
 * Get map command handler:
 * request: /getmap
 * headers: Password, Map
 * reply: plain-text
 */
static int
rspamd_controller_handle_get_map (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	GList *cur;
	struct rspamd_map *map;
	const gchar *idstr;
	gchar *errstr;
	struct stat st;
	gint fd;
	guint32 id;
	gboolean found = FALSE;
	struct rspamd_http_message *reply;


	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	idstr = rspamd_http_message_find_header (msg, "Map");

	if (idstr == NULL) {
		msg_info ("absent map id");
		rspamd_controller_send_error (conn_ent, 400, "400 id header missing");
		return 0;
	}

	id = strtoul (idstr, &errstr, 10);
	if (*errstr != '\0') {
		msg_info ("invalid map id");
		rspamd_controller_send_error (conn_ent, 400, "400 invalid map id");
		return 0;
	}

	/* Now let's be sure that we have map defined in configuration */
	cur = session->ctx->cfg->maps;
	while (cur) {
		map = cur->data;
		if (map->id == id && map->protocol == MAP_PROTO_FILE) {
			found = TRUE;
			break;
		}
		cur = g_list_next (cur);
	}

	if (!found) {
		msg_info ("map not found");
		rspamd_controller_send_error (conn_ent, 404, "404 map not found");
		return 0;
	}

	if (stat (map->uri, &st) == -1 || (fd = open (map->uri, O_RDONLY)) == -1) {
		msg_err ("cannot open map %s: %s", map->uri, strerror (errno));
		rspamd_controller_send_error (conn_ent, 500, "500 map open error");
		return 0;
	}

	reply = rspamd_http_new_message (HTTP_RESPONSE);
	reply->date = time (NULL);
	reply->code = 200;
	reply->body = g_string_sized_new (st.st_size);

	/* Read the whole buffer */
	if (read (fd, reply->body->str, st.st_size) == -1) {
		rspamd_http_message_free (reply);
		msg_err ("cannot read map %s: %s", map->uri, strerror (errno));
		rspamd_controller_send_error (conn_ent, 500, "500 map read error");
		return 0;
	}

	reply->body->len = st.st_size;
	reply->body->str[reply->body->len] = '\0';

	close (fd);

	rspamd_http_connection_reset (conn_ent->conn);
	rspamd_http_connection_write_message (conn_ent->conn, reply, NULL,
		"text/plain", conn_ent, conn_ent->conn->fd,
		conn_ent->rt->ptv, conn_ent->rt->ev_base);
	conn_ent->is_reply = TRUE;

	return 0;
}

static ucl_object_t *
rspamd_controller_pie_element (enum rspamd_metric_action action,
		const char *label, gdouble data)
{
	ucl_object_t *res = ucl_object_typed_new (UCL_OBJECT);
	const char *colors[METRIC_ACTION_MAX] = {
		[METRIC_ACTION_REJECT] = "#993300",
		[METRIC_ACTION_SOFT_REJECT] = "#cc9966",
		[METRIC_ACTION_REWRITE_SUBJECT] = "#ff6600",
		[METRIC_ACTION_ADD_HEADER] = "#ffcc66",
		[METRIC_ACTION_GREYLIST] = "#6666cc",
		[METRIC_ACTION_NOACTION] = "#66cc00"
	};

	ucl_object_insert_key (res, ucl_object_fromstring (colors[action]),
			"color", 0, false);
	ucl_object_insert_key (res, ucl_object_fromstring (label), "label", 0, false);
	ucl_object_insert_key (res, ucl_object_fromdouble (data), "data", 0, false);

	return res;
}

/*
 * Pie chart command handler:
 * request: /pie
 * headers: Password
 * reply: json [
 *      { label: "Foo", data: 11 },
 *      { label: "Bar", data: 20 },
 *      {...}
 * ]
 */
static int
rspamd_controller_handle_pie_chart (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	gdouble data[5], total;
	ucl_object_t *top;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);
	total = ctx->srv->stat->messages_scanned;
	if (total != 0) {

		data[0] = ctx->srv->stat->actions_stat[METRIC_ACTION_NOACTION] / total *
			100.;
		data[1] = ctx->srv->stat->actions_stat[METRIC_ACTION_SOFT_REJECT] / total *
			100.;
		data[2] = (ctx->srv->stat->actions_stat[METRIC_ACTION_ADD_HEADER] +
			ctx->srv->stat->actions_stat[METRIC_ACTION_REWRITE_SUBJECT]) /
			total * 100.;
		data[3] = ctx->srv->stat->actions_stat[METRIC_ACTION_GREYLIST] / total *
			100.;
		data[4] = ctx->srv->stat->actions_stat[METRIC_ACTION_REJECT] / total *
			100.;
	}
	else {
		memset (data, 0, sizeof (data));
	}
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_NOACTION, "Clean", data[0]));
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_SOFT_REJECT, "Temporary rejected", data[1]));
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_ADD_HEADER, "Probable spam", data[2]));
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_GREYLIST, "Greylisted", data[3]));
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_REJECT, "Rejected", data[4]));

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

/*
 * History command handler:
 * request: /history
 * headers: Password
 * reply: json [
 *      { label: "Foo", data: 11 },
 *      { label: "Bar", data: 20 },
 *      {...}
 * ]
 */
static int
rspamd_controller_handle_history (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	struct roll_history_row *row;
	struct roll_history copied_history;
	gint i, rows_proc, row_num;
	struct tm *tm;
	gchar timebuf[32];
	ucl_object_t *top, *obj;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);

	/* Set lock on history */
	rspamd_mempool_lock_mutex (ctx->srv->history->mtx);
	ctx->srv->history->need_lock = TRUE;
	/* Copy locked */
	memcpy (&copied_history, ctx->srv->history, sizeof (copied_history));
	rspamd_mempool_unlock_mutex (ctx->srv->history->mtx);

	/* Go through all rows */
	row_num = copied_history.cur_row;
	for (i = 0, rows_proc = 0; i < HISTORY_MAX_ROWS; i++, row_num++) {
		if (row_num == HISTORY_MAX_ROWS) {
			row_num = 0;
		}
		row = &copied_history.rows[row_num];
		/* Get only completed rows */
		if (row->completed) {
			tm = localtime (&row->tv.tv_sec);
			strftime (timebuf, sizeof (timebuf) - 1, "%Y-%m-%d %H:%M:%S", tm);
			obj = ucl_object_typed_new (UCL_OBJECT);
			ucl_object_insert_key (obj, ucl_object_fromstring (
					timebuf),		  "time", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromstring (
					row->message_id), "id",	  0, false);
			ucl_object_insert_key (obj, ucl_object_fromstring (
					rspamd_inet_address_to_string (&row->from_addr)),
					"ip", 0, false);
			ucl_object_insert_key (obj,
				ucl_object_fromstring (rspamd_action_to_str (
					row->action)), "action", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromdouble (
					row->score),		  "score",			0, false);
			ucl_object_insert_key (obj,
				ucl_object_fromdouble (
					row->required_score), "required_score", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromstring (
					row->symbols),		  "symbols",		0, false);
			ucl_object_insert_key (obj,	   ucl_object_fromint (
					row->len),			  "size",			0, false);
			ucl_object_insert_key (obj,	   ucl_object_fromint (
					row->scan_time),	  "scan_time",		0, false);
			if (row->user[0] != '\0') {
				ucl_object_insert_key (obj, ucl_object_fromstring (
						row->user), "user", 0, false);
			}
			ucl_array_append (top, obj);
			rows_proc++;
		}
	}

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

static gboolean
rspamd_controller_learn_fin_task (void *ud)
{
	struct rspamd_task *task = ud;
	struct rspamd_controller_session *session;
	struct rspamd_http_connection_entry *conn_ent;
	GError *err = NULL;

	conn_ent = task->fin_arg;
	session = conn_ent->ud;

	if (!rspamd_learn_task_spam (session->cl, task, session->is_spam, &err)) {
		rspamd_controller_send_error (conn_ent, 500 + err->code, err->message);
		return TRUE;
	}
	/* Successful learn */
	msg_info ("<%s> learned message: %s",
		rspamd_inet_address_to_string (&session->from_addr),
		task->message_id);
	rspamd_controller_send_string (conn_ent, "{\"success\":true}");

	return TRUE;
}

static gboolean
rspamd_controller_check_fin_task (void *ud)
{
	struct rspamd_task *task = ud;
	struct rspamd_http_connection_entry *conn_ent;
	struct rspamd_http_message *msg;

	rspamd_process_statistics (task);
	conn_ent = task->fin_arg;
	msg = rspamd_http_new_message (HTTP_RESPONSE);
	msg->date = time (NULL);
	msg->code = 200;
	rspamd_protocol_http_reply (msg, task);
	rspamd_http_connection_reset (conn_ent->conn);
	rspamd_http_connection_write_message (conn_ent->conn, msg, NULL,
		"application/json", conn_ent, conn_ent->conn->fd, conn_ent->rt->ptv,
		conn_ent->rt->ev_base);
	conn_ent->is_reply = TRUE;

	return TRUE;
}

static int
rspamd_controller_handle_learn_common (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg,
	gboolean is_spam)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	struct rspamd_classifier_config *cl;
	struct rspamd_task *task;
	const gchar *classifier;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	if (msg->body == NULL || msg->body->len == 0) {
		msg_err ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	if ((classifier =
		rspamd_http_message_find_header (msg, "Classifier")) == NULL) {
		classifier = "bayes";
	}

	cl = rspamd_config_find_classifier (ctx->cfg, classifier);
	if (cl == NULL) {
		rspamd_controller_send_error (conn_ent, 400, "Classifier not found");
		return 0;
	}

	task = rspamd_task_new (session->ctx->worker);
	task->msg = msg->body;

	task->resolver = ctx->resolver;
	task->ev_base = ctx->ev_base;


	task->s = new_async_session (session->pool,
			rspamd_controller_learn_fin_task,
			NULL,
			rspamd_task_free_hard,
			task);
	task->s->wanna_die = TRUE;
	task->fin_arg = conn_ent;
	task->http_conn = rspamd_http_connection_ref (conn_ent->conn);;
	task->sock = conn_ent->conn->fd;


	if (!rspamd_task_process (task, msg, NULL, FALSE)) {
		msg_warn ("filters cannot be processed for %s", task->message_id);
		rspamd_controller_send_error (conn_ent, 500, task->last_error);
		destroy_session (task->s);
		return 0;
	}

	session->task = task;
	session->cl = cl;
	session->is_spam = is_spam;
	check_session_pending (task->s);

	return 0;
}

/*
 * Learn spam command handler:
 * request: /learnspam
 * headers: Password
 * input: plaintext data
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_learnspam (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	return rspamd_controller_handle_learn_common (conn_ent, msg, TRUE);
}
/*
 * Learn ham command handler:
 * request: /learnham
 * headers: Password
 * input: plaintext data
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_learnham (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	return rspamd_controller_handle_learn_common (conn_ent, msg, FALSE);
}

/*
 * Scan command handler:
 * request: /scan
 * headers: Password
 * input: plaintext data
 * reply: json {scan data} or {"error":"error message"}
 */
static int
rspamd_controller_handle_scan (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	struct rspamd_task *task;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	if (msg->body == NULL || msg->body->len == 0) {
		msg_err ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	task = rspamd_task_new (session->ctx->worker);
	task->ev_base = session->ctx->ev_base;
	task->msg = msg->body;

	task->resolver = ctx->resolver;
	task->ev_base = ctx->ev_base;

	task->s = new_async_session (session->pool,
			rspamd_controller_check_fin_task,
			NULL,
			rspamd_task_free_hard,
			task);
	task->s->wanna_die = TRUE;
	task->fin_arg = conn_ent;
	task->http_conn = rspamd_http_connection_ref (conn_ent->conn);
	task->sock = conn_ent->conn->fd;

	if (!rspamd_task_process (task, msg, NULL, FALSE)) {
		msg_warn ("filters cannot be processed for %s", task->message_id);
		rspamd_controller_send_error (conn_ent, 500, task->last_error);
		destroy_session (task->s);
		return 0;
	}

	session->task = task;
	check_session_pending (task->s);

	return 0;
}

/*
 * Save actions command handler:
 * request: /saveactions
 * headers: Password
 * input: json array [<spam>,<probable spam>,<greylist>]
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_saveactions (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct ucl_parser *parser;
	struct metric *metric;
	ucl_object_t *obj;
	const ucl_object_t *cur;
	struct rspamd_controller_worker_ctx *ctx;
	const gchar *error;
	gdouble score;
	gint i, added = 0;
	enum rspamd_metric_action act;
	ucl_object_iter_t it = NULL;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	if (msg->body == NULL || msg->body->len == 0) {
		msg_err ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	metric = g_hash_table_lookup (ctx->cfg->metrics, DEFAULT_METRIC);
	if (metric == NULL) {
		msg_err ("cannot find default metric");
		rspamd_controller_send_error (conn_ent, 500,
			"Default metric is absent");
		return 0;
	}

	/* Now check for dynamic config */
	if (!ctx->cfg->dynamic_conf) {
		msg_err ("dynamic conf has not been defined");
		rspamd_controller_send_error (conn_ent,
			500,
			"No dynamic_rules setting defined");
		return 0;
	}

	parser = ucl_parser_new (0);
	ucl_parser_add_chunk (parser, msg->body->str, msg->body->len);

	if ((error = ucl_parser_get_error (parser)) != NULL) {
		msg_err ("cannot parse input: %s", error);
		rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
		ucl_parser_free (parser);
		return 0;
	}

	obj = ucl_parser_get_object (parser);
	ucl_parser_free (parser);

	if (obj->type != UCL_ARRAY || obj->len != 3) {
		msg_err ("input is not an array of 3 elements");
		rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
		ucl_object_unref (obj);
		return 0;
	}

	for (i = 0; i < 3; i++) {
		cur = ucl_iterate_object (obj, &it, TRUE);
		if (cur == NULL) {
			break;
		}
		switch (i) {
		case 0:
			act = METRIC_ACTION_REJECT;
			break;
		case 1:
			act = METRIC_ACTION_ADD_HEADER;
			break;
		case 2:
			act = METRIC_ACTION_GREYLIST;
			break;
		}
		score = ucl_object_todouble (cur);
		if (metric->actions[act].score != score) {
			add_dynamic_action (ctx->cfg, DEFAULT_METRIC, act, score);
			added ++;
		}
	}

	dump_dynamic_config (ctx->cfg);
	msg_info ("<%s> modified %d actions",
		rspamd_inet_address_to_string (&session->from_addr),
		added);

	rspamd_controller_send_string (conn_ent, "{\"success\":true}");

	return 0;
}

/*
 * Save symbols command handler:
 * request: /savesymbols
 * headers: Password
 * input: json data
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_savesymbols (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct ucl_parser *parser;
	struct metric *metric;
	ucl_object_t *obj;
	const ucl_object_t *cur, *jname, *jvalue;
	ucl_object_iter_t iter = NULL;
	struct rspamd_controller_worker_ctx *ctx;
	const gchar *error;
	gdouble val;
	struct rspamd_symbol_def *sym;
	int added = 0;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	if (msg->body == NULL || msg->body->len == 0) {
		msg_err ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	metric = g_hash_table_lookup (ctx->cfg->metrics, DEFAULT_METRIC);
	if (metric == NULL) {
		msg_err ("cannot find default metric");
		rspamd_controller_send_error (conn_ent, 500,
			"Default metric is absent");
		return 0;
	}

	/* Now check for dynamic config */
	if (!ctx->cfg->dynamic_conf) {
		msg_err ("dynamic conf has not been defined");
		rspamd_controller_send_error (conn_ent,
			500,
			"No dynamic_rules setting defined");
		return 0;
	}

	parser = ucl_parser_new (0);
	ucl_parser_add_chunk (parser, msg->body->str, msg->body->len);

	if ((error = ucl_parser_get_error (parser)) != NULL) {
		msg_err ("cannot parse input: %s", error);
		rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
		ucl_parser_free (parser);
		return 0;
	}

	obj = ucl_parser_get_object (parser);
	ucl_parser_free (parser);

	if (obj->type != UCL_ARRAY) {
		msg_err ("input is not an array");
		rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
		ucl_object_unref (obj);
		return 0;
	}

	while ((cur = ucl_iterate_object (obj, &iter, true))) {
		if (cur->type != UCL_OBJECT) {
			msg_err ("json array data error");
			rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
			ucl_object_unref (obj);
			return 0;
		}
		jname = ucl_object_find_key (cur, "name");
		jvalue = ucl_object_find_key (cur, "value");
		val = ucl_object_todouble (jvalue);
		sym =
			g_hash_table_lookup (metric->symbols, ucl_object_tostring (jname));
		if (sym && fabs (*sym->weight_ptr - val) > 0.01) {
			if (!add_dynamic_symbol (ctx->cfg, DEFAULT_METRIC,
				ucl_object_tostring (jname), val)) {
				msg_err ("add symbol failed for %s",
					ucl_object_tostring (jname));
				rspamd_controller_send_error (conn_ent, 506,
					"Add symbol failed");
				ucl_object_unref (obj);
				return 0;
			}
			added ++;
		}
	}

	dump_dynamic_config (ctx->cfg);
	msg_info ("<%s> modified %d symbols",
			rspamd_inet_address_to_string (&session->from_addr),
			added);

	rspamd_controller_send_string (conn_ent, "{\"success\":true}");

	return 0;
}

/*
 * Save map command handler:
 * request: /savemap
 * headers: Password, Map
 * input: plaintext data
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_savemap (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	GList *cur;
	struct rspamd_map *map;
	struct rspamd_controller_worker_ctx *ctx;
	const gchar *idstr;
	gchar *errstr;
	guint32 id;
	gboolean found = FALSE;
	gint fd;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	if (msg->body == NULL || msg->body->len == 0) {
		msg_err ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	idstr = rspamd_http_message_find_header (msg, "Map");

	if (idstr == NULL) {
		msg_info ("absent map id");
		rspamd_controller_send_error (conn_ent, 400, "Map id not specified");
		return 0;
	}

	id = strtoul (idstr, &errstr, 10);
	if (*errstr != '\0') {
		msg_info ("invalid map id");
		rspamd_controller_send_error (conn_ent, 400, "Map id is invalid");
		return 0;
	}

	/* Now let's be sure that we have map defined in configuration */
	cur = ctx->cfg->maps;
	while (cur) {
		map = cur->data;
		if (map->id == id && map->protocol == MAP_PROTO_FILE) {
			found = TRUE;
			break;
		}
		cur = g_list_next (cur);
	}

	if (!found) {
		msg_info ("map not found: %d", id);
		rspamd_controller_send_error (conn_ent, 404, "Map id not found");
		return 0;
	}

	if (g_atomic_int_get (map->locked)) {
		msg_info ("map locked: %s", map->uri);
		rspamd_controller_send_error (conn_ent, 404, "Map is locked");
		return 0;
	}

	/* Set lock */
	g_atomic_int_set (map->locked, 1);
	fd = open (map->uri, O_WRONLY | O_TRUNC);
	if (fd == -1) {
		g_atomic_int_set (map->locked, 0);
		msg_info ("map %s open error: %s", map->uri, strerror (errno));
		rspamd_controller_send_error (conn_ent, 404, "Map id not found");
		return 0;
	}

	if (write (fd, msg->body->str, msg->body->len) == -1) {
		msg_info ("map %s write error: %s", map->uri, strerror (errno));
		close (fd);
		g_atomic_int_set (map->locked, 0);
		rspamd_controller_send_error (conn_ent, 500, "Map write error");
		return 0;
	}

	msg_info ("<%s>, map %s saved",
		rspamd_inet_address_to_string (&session->from_addr),
		map->uri);
	/* Close and unlock */
	close (fd);
	g_atomic_int_set (map->locked, 0);

	rspamd_controller_send_string (conn_ent, "{\"success\":true}");

	return 0;
}

/*
 * Stat command handler:
 * request: /stat (/resetstat)
 * headers: Password
 * reply: json data
 */
static int
rspamd_controller_handle_stat_common (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg,
	gboolean do_reset)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	ucl_object_t *top, *sub;
	gint i;
	guint64 used, total, rev, ham = 0, spam = 0;
	time_t ti;
	rspamd_mempool_stat_t mem_st;
	struct rspamd_classifier_config *ccf;
	struct rspamd_statfile_config *st;
	GList *cur_cl, *cur_st;
	struct rspamd_stat *stat, stat_copy;

	rspamd_mempool_stat (&mem_st);
	memcpy (&stat_copy, session->ctx->worker->srv->stat, sizeof (stat_copy));
	stat = &stat_copy;
	top = ucl_object_typed_new (UCL_OBJECT);

	ucl_object_insert_key (top, ucl_object_fromint (
			stat->messages_scanned), "scanned", 0, false);
	if (stat->messages_scanned > 0) {
		sub = ucl_object_typed_new (UCL_OBJECT);
		for (i = METRIC_ACTION_REJECT; i <= METRIC_ACTION_NOACTION; i++) {
			ucl_object_insert_key (sub,
				ucl_object_fromint (stat->actions_stat[i]),
				rspamd_action_to_str (i), 0, false);
			if (i < METRIC_ACTION_GREYLIST) {
				spam += stat->actions_stat[i];
			}
			else {
				ham += stat->actions_stat[i];
			}
			if (do_reset) {
				session->ctx->worker->srv->stat->actions_stat[i] = 0;
			}
		}
		ucl_object_insert_key (top, sub, "actions", 0, false);
	}

	ucl_object_insert_key (top, ucl_object_fromint (
			spam), "spam_count", 0, false);
	ucl_object_insert_key (top, ucl_object_fromint (
			ham),  "ham_count",	 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (stat->messages_learned), "learned", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (stat->connections_count), "connections", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (stat->control_connections_count),
		"control_connections", 0, false);

	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.pools_allocated), "pools_allocated", 0,
		false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.pools_freed), "pools_freed", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.bytes_allocated), "bytes_allocated", 0,
		false);
	ucl_object_insert_key (top,
		ucl_object_fromint (
			mem_st.chunks_allocated), "chunks_allocated", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.shared_chunks_allocated),
		"shared_chunks_allocated", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.chunks_freed), "chunks_freed", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (
			mem_st.oversized_chunks), "chunks_oversized", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (stat->fuzzy_hashes), "fuzzy_stored", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (
			stat->fuzzy_hashes_expired), "fuzzy_expired", 0, false);

	/* Now write statistics for each statfile */
	cur_cl = g_list_first (session->ctx->cfg->classifiers);
	sub = ucl_object_typed_new (UCL_ARRAY);
	while (cur_cl) {
		ccf = cur_cl->data;
		/* XXX: add statistics for the modern system */
		cur_cl = g_list_next (cur_cl);
	}

	ucl_object_insert_key (top, sub, "statfiles", 0, false);

	if (do_reset) {
		session->ctx->srv->stat->messages_scanned = 0;
		session->ctx->srv->stat->messages_learned = 0;
		session->ctx->srv->stat->connections_count = 0;
		session->ctx->srv->stat->control_connections_count = 0;
		rspamd_mempool_stat_reset ();
	}

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

static int
rspamd_controller_handle_stat (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	return rspamd_controller_handle_stat_common (conn_ent, msg, FALSE);
}

static int
rspamd_controller_handle_statreset (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	msg_info ("<%s> reset stat",
			rspamd_inet_address_to_string (&session->from_addr));
	return rspamd_controller_handle_stat_common (conn_ent, msg, TRUE);
}

static ucl_object_t *
rspamd_controller_cache_item_to_ucl (struct cache_item *item)
{
	ucl_object_t *obj;

	obj = ucl_object_typed_new (UCL_OBJECT);
	ucl_object_insert_key (obj, ucl_object_fromstring (item->s->symbol),
		"symbol", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromdouble (item->s->weight),
		"weight", 0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (item->s->frequency),
		"frequency", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromdouble (item->s->avg_time),
		"time", 0, false);

	return obj;
}

/*
 * Counters command handler:
 * request: /counters
 * headers: Password
 * reply: json array of all counters
 */
static int
rspamd_controller_handle_counters (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	ucl_object_t *top;
	GList *cur;
	struct cache_item *item;
	struct symbols_cache *cache;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	cache = session->ctx->cfg->cache;
	top = ucl_object_typed_new (UCL_ARRAY);
	if (cache != NULL) {
		cur = cache->negative_items;
		while (cur) {
			item = cur->data;
			if (!item->is_callback) {
				ucl_array_append (top, rspamd_controller_cache_item_to_ucl (
						item));
			}
			cur = g_list_next (cur);
		}
		cur = cache->static_items;
		while (cur) {
			item = cur->data;
			if (!item->is_callback) {
				ucl_array_append (top, rspamd_controller_cache_item_to_ucl (
						item));
			}
			cur = g_list_next (cur);
		}
	}
	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

static int
rspamd_controller_handle_custom (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_custom_controller_command *cmd;

	cmd = g_hash_table_lookup (session->ctx->custom_commands, msg->url->str);
	if (cmd == NULL || cmd->handler == NULL) {
		msg_err ("custom command %V has not been found", msg->url);
		rspamd_controller_send_error (conn_ent, 404, "No command associated");
		return 0;
	}

	if (!rspamd_controller_check_password (conn_ent, session, msg,
		cmd->privilleged)) {
		return 0;
	}
	if (cmd->require_message && (msg->body == NULL || msg->body->len == 0)) {
		msg_err ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	return cmd->handler (conn_ent, msg, cmd->ctx);
}

static void
rspamd_controller_error_handler (struct rspamd_http_connection_entry *conn_ent,
	GError *err)
{
	msg_err ("http error occurred: %s", err->message);
}

static void
rspamd_controller_finish_handler (struct rspamd_http_connection_entry *conn_ent)
{
	struct rspamd_controller_session *session = conn_ent->ud;

	session->ctx->worker->srv->stat->control_connections_count++;
	if (session->task != NULL) {
		destroy_session (session->task->s);
	}
	if (session->pool) {
		rspamd_mempool_delete (session->pool);
	}

	g_slice_free1 (sizeof (struct rspamd_controller_session), session);
}

static void
rspamd_controller_accept_socket (gint fd, short what, void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *) arg;
	struct rspamd_controller_worker_ctx *ctx;
	struct rspamd_controller_session *nsession;
	rspamd_inet_addr_t addr;
	gint nfd;

	ctx = worker->ctx;

	if ((nfd =
		rspamd_accept_from_socket (fd, &addr)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		return;
	}

	nsession = g_slice_alloc0 (sizeof (struct rspamd_controller_session));
	nsession->pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());
	nsession->ctx = ctx;

	memcpy (&nsession->from_addr, &addr, sizeof (addr));

	rspamd_http_router_handle_socket (ctx->http, nfd, nsession);
}

gpointer
init_controller_worker (struct rspamd_config *cfg)
{
	struct rspamd_controller_worker_ctx *ctx;
	GQuark type;

	type = g_quark_try_string ("controller");

	ctx = g_malloc0 (sizeof (struct rspamd_controller_worker_ctx));

	ctx->timeout = DEFAULT_WORKER_IO_TIMEOUT;

	rspamd_rcl_register_worker_option (cfg, type, "password",
		rspamd_rcl_parse_struct_string, ctx,
		G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, password), 0);

	rspamd_rcl_register_worker_option (cfg, type, "enable_password",
		rspamd_rcl_parse_struct_string, ctx,
		G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, password), 0);

	rspamd_rcl_register_worker_option (cfg, type, "ssl",
		rspamd_rcl_parse_struct_boolean, ctx,
		G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, use_ssl), 0);

	rspamd_rcl_register_worker_option (cfg, type, "ssl_cert",
		rspamd_rcl_parse_struct_string, ctx,
		G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, ssl_cert), 0);

	rspamd_rcl_register_worker_option (cfg, type, "ssl_key",
		rspamd_rcl_parse_struct_string, ctx,
		G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, ssl_key), 0);
	rspamd_rcl_register_worker_option (cfg, type, "timeout",
		rspamd_rcl_parse_struct_time, ctx,
		G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx,
		timeout), RSPAMD_CL_FLAG_TIME_INTEGER);

	rspamd_rcl_register_worker_option (cfg, type, "secure_ip",
		rspamd_rcl_parse_struct_string, ctx,
		G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, secure_ip), 0);

	rspamd_rcl_register_worker_option (cfg, type, "static_dir",
		rspamd_rcl_parse_struct_string, ctx,
		G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx,
		static_files_dir), 0);

	return ctx;
}

/*
 * Start worker process
 */
void
start_controller_worker (struct rspamd_worker *worker)
{
	struct rspamd_controller_worker_ctx *ctx = worker->ctx;
	GList *cur;
	struct filter *f;
	struct module_ctx *mctx;
	GHashTableIter iter;
	gpointer key, value;


	ctx->ev_base = rspamd_prepare_worker (worker,
			"controller",
			rspamd_controller_accept_socket);
	msec_to_tv (ctx->timeout, &ctx->io_tv);

	ctx->start_time = time (NULL);
	ctx->worker = worker;
	ctx->cfg = worker->srv->cfg;
	ctx->srv = worker->srv;
	ctx->custom_commands = g_hash_table_new (rspamd_strcase_hash,
			rspamd_strcase_equal);
	if (ctx->secure_ip != NULL) {
		if (!rspamd_map_add (worker->srv->cfg, ctx->secure_ip,
			"Allow webui access from the specified IP",
			rspamd_radix_read, rspamd_radix_fin, (void **)&ctx->secure_map)) {
			if (!radix_add_generic_iplist (ctx->secure_ip,
				&ctx->secure_map)) {
				msg_warn ("cannot load or parse ip list from '%s'",
					ctx->secure_ip);
			}
		}
	}
	/* Accept event */
	ctx->http = rspamd_http_router_new (rspamd_controller_error_handler,
			rspamd_controller_finish_handler, &ctx->io_tv, ctx->ev_base,
			ctx->static_files_dir);

	/* Add callbacks for different methods */
	rspamd_http_router_add_path (ctx->http,
				PATH_AUTH,
		rspamd_controller_handle_auth);
	rspamd_http_router_add_path (ctx->http,
			 PATH_SYMBOLS,
		rspamd_controller_handle_symbols);
	rspamd_http_router_add_path (ctx->http,
			 PATH_ACTIONS,
		rspamd_controller_handle_actions);
	rspamd_http_router_add_path (ctx->http,
				PATH_MAPS,
		rspamd_controller_handle_maps);
	rspamd_http_router_add_path (ctx->http,
			 PATH_GET_MAP,
		rspamd_controller_handle_get_map);
	rspamd_http_router_add_path (ctx->http,
		   PATH_PIE_CHART,
		rspamd_controller_handle_pie_chart);
	rspamd_http_router_add_path (ctx->http,
			 PATH_HISTORY,
		rspamd_controller_handle_history);
	rspamd_http_router_add_path (ctx->http,
		  PATH_LEARN_SPAM,
		rspamd_controller_handle_learnspam);
	rspamd_http_router_add_path (ctx->http,
		   PATH_LEARN_HAM,
		rspamd_controller_handle_learnham);
	rspamd_http_router_add_path (ctx->http,
		PATH_SAVE_ACTIONS,
		rspamd_controller_handle_saveactions);
	rspamd_http_router_add_path (ctx->http,
		PATH_SAVE_SYMBOLS,
		rspamd_controller_handle_savesymbols);
	rspamd_http_router_add_path (ctx->http,
			PATH_SAVE_MAP,
		rspamd_controller_handle_savemap);
	rspamd_http_router_add_path (ctx->http,
				PATH_SCAN,
		rspamd_controller_handle_scan);
	rspamd_http_router_add_path (ctx->http,
			   PATH_CHECK,
		rspamd_controller_handle_scan);
	rspamd_http_router_add_path (ctx->http,
				PATH_STAT,
		rspamd_controller_handle_stat);
	rspamd_http_router_add_path (ctx->http,
		  PATH_STAT_RESET,
		rspamd_controller_handle_statreset);
	rspamd_http_router_add_path (ctx->http,
			PATH_COUNTERS,
		rspamd_controller_handle_counters);

	/* Attach plugins */
	cur = g_list_first (ctx->cfg->filters);
	while (cur) {
		f = cur->data;
		mctx = g_hash_table_lookup (ctx->cfg->c_modules, f->module->name);
		if (mctx != NULL && f->module->module_attach_controller_func != NULL) {
			f->module->module_attach_controller_func (mctx,
				ctx->custom_commands);
		}
		cur = g_list_next (cur);
	}

	g_hash_table_iter_init (&iter, ctx->custom_commands);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		rspamd_http_router_add_path (ctx->http,
			key,
			rspamd_controller_handle_custom);
	}

	ctx->resolver = dns_resolver_init (worker->srv->logger,
			ctx->ev_base,
			worker->srv->cfg);

	rspamd_upstreams_library_init (ctx->resolver->r, ctx->ev_base);
	rspamd_upstreams_library_config (worker->srv->cfg);
	/* Maps events */
	rspamd_map_watch (worker->srv->cfg, ctx->ev_base);

	event_base_loop (ctx->ev_base, 0);

	g_mime_shutdown ();
	rspamd_log_close (rspamd_main->logger);
	exit (EXIT_SUCCESS);
}
