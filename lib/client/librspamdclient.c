/*
 * Copyright (c) 2011, Vsevolod Stakhov
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
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "librspamdclient.h"
#include "config.h"
#include "upstream.h"
#include "util.h"
#include "cfg_file.h"
#include "logger.h"

#define MAX_RSPAMD_SERVERS 255
#define DEFAULT_CONNECT_TIMEOUT 500
#define DEFAULT_READ_TIMEOUT 5000
/* Default connect timeout for sync sockets */
#define CONNECT_TIMEOUT 3
#define G_RSPAMD_ERROR rspamd_error_quark ()

#ifndef CRLF
# define CRLF "\r\n"
#endif

struct rspamd_server {
	struct upstream up;
	struct in_addr addr;
	guint16 client_port;
	guint16 controller_port;
	gchar *name;
	gchar *controller_name;
};

struct rspamd_client {
	struct rspamd_server servers[MAX_RSPAMD_SERVERS];
	guint servers_num;
	guint connect_timeout;
	guint read_timeout;
	struct in_addr *bind_addr;
};

struct rspamd_connection {
	struct rspamd_server *server;
	struct rspamd_client *client;
	time_t connection_time;
	gint socket;
	union {
		struct {
			struct rspamd_result *result;
			struct rspamd_metric *cur_metric;
		} normal;
		struct {
			struct rspamd_controller_result *result;
			enum {
				CONTROLLER_READ_REPLY,
				CONTROLLER_READ_HEADER,
				CONTROLLER_READ_DATA
			} state;
		} controller;
	} res;
	gboolean is_controller;
	GString *in_buf;
	gint version;
};

/** Util functions **/
gint
make_socket_nonblocking (gint fd)
{
	gint                            ofl;

	ofl = fcntl (fd, F_GETFL, 0);

	if (fcntl (fd, F_SETFL, ofl | O_NONBLOCK) == -1) {
		msg_warn ("fcntl failed: %d, '%s'", errno, strerror (errno));
		return -1;
	}
	return 0;
}

gint
make_socket_blocking (gint fd)
{
	gint                            ofl;

	ofl = fcntl (fd, F_GETFL, 0);

	if (fcntl (fd, F_SETFL, ofl & (~O_NONBLOCK)) == -1) {
		msg_warn ("fcntl failed: %d, '%s'", errno, strerror (errno));
		return -1;
	}
	return 0;
}

gint
poll_sync_socket (gint fd, gint timeout, short events)
{
	gint                            r;
	struct pollfd                   fds[1];

	fds->fd = fd;
	fds->events = events;
	fds->revents = 0;
	while ((r = poll (fds, 1, timeout)) < 0) {
		if (errno != EINTR) {
			break;
		}
	}

	return r;
}

static gint
lib_make_inet_socket (gint family, struct in_addr *addr, struct in_addr *local_addr,
		u_short port, gboolean is_server, gboolean async)
{
	gint                            fd, r, optlen, on = 1, s_error;
	gint                            serrno;
	struct sockaddr_in              sin, local;

	/* Create socket */
	fd = socket (AF_INET, family, 0);
	if (fd == -1) {
		msg_warn ("socket failed: %d, '%s'", errno, strerror (errno));
		return -1;
	}

	if (make_socket_nonblocking (fd) < 0) {
		goto out;
	}

	/* Set close on exec */
	if (fcntl (fd, F_SETFD, FD_CLOEXEC) == -1) {
		msg_warn ("fcntl failed: %d, '%s'", errno, strerror (errno));
		goto out;
	}

	memset (&sin, 0, sizeof (sin));

	/* Bind options */
	sin.sin_family = AF_INET;
	sin.sin_port = htons (port);
	sin.sin_addr.s_addr = addr->s_addr;

	if (!is_server && local_addr != NULL) {
		/* Bind to local addr */
		memset (&local, 0, sizeof (struct sockaddr_in));
		memcpy (&local.sin_addr,local_addr, sizeof (struct in_addr));
		local.sin_family = AF_INET;
		setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, sizeof (gint));
		if (bind (fd, (struct sockaddr *)&local, sizeof (local)) == -1) {
			msg_warn ("bind/connect failed: %d, '%s'", errno, strerror (errno));
			goto out;
		}
	}

	if (is_server) {
		setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, sizeof (gint));
		r = bind (fd, (struct sockaddr *)&sin, sizeof (struct sockaddr_in));
	}
	else {
		r = connect (fd, (struct sockaddr *)&sin, sizeof (struct sockaddr_in));
	}

	if (r == -1) {
		if (errno != EINPROGRESS) {
			msg_warn ("bind/connect failed: %d, '%s'", errno, strerror (errno));
			goto out;
		}
		if (!async) {
			/* Try to poll */
			if (poll_sync_socket (fd, CONNECT_TIMEOUT * 1000, POLLOUT) <= 0) {
				errno = ETIMEDOUT;
				msg_warn ("bind/connect failed: timeout");
				goto out;
			}
			else {
				/* Make synced again */
				if (make_socket_blocking (fd) < 0) {
					goto out;
				}
			}
		}
	}
	else {
		/* Still need to check SO_ERROR on socket */
		optlen = sizeof (s_error);
		getsockopt (fd, SOL_SOCKET, SO_ERROR, (void *)&s_error, &optlen);
		if (s_error) {
			errno = s_error;
			goto out;
		}
	}


	return (fd);

  out:
	serrno = errno;
	close (fd);
	errno = serrno;
	return (-1);
}

static gint
lib_make_tcp_socket (struct in_addr *addr, struct in_addr *local_addr, u_short port, gboolean is_server, gboolean async)
{
	return lib_make_inet_socket (SOCK_STREAM, addr, local_addr, port, is_server, async);
}

/** Private functions **/
static inline                   GQuark
rspamd_error_quark (void)
{
	return g_quark_from_static_string ("g-rspamd-error-quark");
}

static void
metric_free_func (gpointer arg)
{
	struct rspamd_metric            *m = arg;

	g_hash_table_destroy (m->symbols);
	g_free (m);
}

static void
symbol_free_func (gpointer arg)
{
	struct rspamd_symbol            *s = arg;
	GList                           *cur = s->options;

	while (cur) {
		g_free (cur->data);
		cur = g_list_next (cur);
	}
	g_list_free (s->options);
	g_free (s);
}

static struct rspamd_connection *
rspamd_connect_specific_server (struct rspamd_client *client, gboolean is_control, GError **err, struct rspamd_server *serv)
{
	struct rspamd_connection        *new;

	/* Allocate connection */
	new = g_malloc0 (sizeof (struct rspamd_connection));
	new->server = serv;
	new->connection_time = time (NULL);
	new->client = client;
	/* Create socket */
	new->socket = lib_make_tcp_socket (&serv->addr, client->bind_addr,
			is_control ? serv->controller_port : serv->client_port,
					FALSE, TRUE);
	if (new->socket == -1) {
		goto err;
	}
	/* Poll waiting for writing */
	if (poll_sync_socket (new->socket, client->connect_timeout , POLLOUT) <= 0) {
		errno = ETIMEDOUT;
		goto err;
	}

	new->in_buf = g_string_sized_new (BUFSIZ);
	return new;

	err:
	if (*err == NULL) {
		*err = g_error_new (G_RSPAMD_ERROR, errno, "Could not connect to server %s: %s",
				serv->name, strerror (errno));
	}
	upstream_fail (&serv->up, time (NULL));
	g_free (new);
	return NULL;
}

static struct rspamd_connection *
rspamd_connect_random_server (struct rspamd_client *client, gboolean is_control, GError **err)
{
	struct rspamd_server            *selected = NULL;

	if (client->servers_num == 0) {
		errno = EINVAL;
		if (*err == NULL) {
			*err = g_error_new (G_RSPAMD_ERROR, 1, "No servers can be reached");
		}
		return NULL;
	}
	/* Select random server */
	selected = (struct rspamd_server *)get_random_upstream (client->servers,
			client->servers_num, sizeof (struct rspamd_server),
			time (NULL), DEFAULT_UPSTREAM_ERROR_TIME, DEFAULT_UPSTREAM_DEAD_TIME, DEFAULT_UPSTREAM_MAXERRORS);
	if (selected == NULL) {
		errno = EINVAL;
		if (*err == NULL) {
			*err = g_error_new (G_RSPAMD_ERROR, 1, "No servers can be reached");
		}
		return NULL;
	}

	return rspamd_connect_specific_server (client, is_control, err, selected);
}

static struct rspamd_metric *
rspamd_create_metric (const gchar *begin, guint len)
{
	struct rspamd_metric            *new;

	new = g_malloc0 (sizeof (struct rspamd_metric));
	new->symbols = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, symbol_free_func);
	new->name = g_malloc (len + 1);
	memcpy (new->name, begin, len);
	new->name[len] = '\0';

	return new;
}

static struct rspamd_result *
rspamd_create_result (struct rspamd_connection *c)
{
	struct rspamd_result           *new;

	new = g_malloc (sizeof (struct rspamd_result));
	new->conn = c;
	new->headers = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	new->metrics = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, metric_free_func);
	new->is_ok = FALSE;

	return new;
}

static struct rspamd_controller_result *
rspamd_create_controller_result (struct rspamd_connection *c)
{
	struct rspamd_controller_result  *new;

	new = g_malloc (sizeof (struct rspamd_controller_result));
	new->conn = c;
	new->headers = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	new->data = NULL;
	new->result = g_string_new (NULL);
	new->code = 0;

	return new;
}

/*
 * Parse line like RSPAMD/{version} {code} {message}
 */
static gboolean
parse_rspamd_first_line (struct rspamd_connection *conn, guint len, GError **err)
{
	gchar                           *b = conn->in_buf->str + sizeof("RSPAMD/") - 1, *p, *c;
	guint                            remain = len - sizeof("RSPAMD/") + 1, state = 0, next_state = 0;
	gdouble                          dver;

	p = b;
	c = p;
	while (p - b <= (gint)remain) {
		switch (state) {
		case 0:
			/* Read version */
			if (g_ascii_isspace (*p)) {
				state = 99;
				next_state = 1;
				dver = strtod (c, NULL);
				conn->version = floor (dver * 10 + 0.5);
			}
			else if (!g_ascii_isdigit (*p) && *p != '.') {
				goto err;
			}
			p ++;
			break;
		case 1:
			/* Read code */
			if (g_ascii_isspace (*p)) {
				state = 99;
				next_state = 2;
				if (*c == '0') {
					conn->res.normal.result->is_ok = TRUE;
				}
			}
			else if (!g_ascii_isdigit (*p)) {
				goto err;
			}
			p ++;
			break;
		case 2:
			/* Read message */
			if (g_ascii_isspace (*p) || p - b == (gint)remain) {
				state = 99;
				next_state = 3;
			}
			p ++;
			break;
		case 3:
			goto err;
		case 99:
			/* Skip spaces */
			if (!g_ascii_isspace (*p)) {
				state = next_state;
				c = p;
			}
			else {
				p ++;
			}
			break;
		}
	}

	if (state != 99) {
		goto err;
	}

	return TRUE;
err:
	if (*err == NULL) {
		*err = g_error_new (G_RSPAMD_ERROR, errno, "Invalid protocol line: %*s at pos: %d",
				remain, b, (int)(p - b));
	}
	upstream_fail (&conn->server->up, conn->connection_time);
	return FALSE;
}

/*
 * Parse line like Metric: <name>; <True|False|Skip>; <score> / <required_score>[ / <reject_score>]
 */
static gboolean
parse_rspamd_metric_line (struct rspamd_connection *conn, guint len, GError **err)
{
	gchar                           *b = conn->in_buf->str + sizeof("Metric:") - 1, *p, *c, *err_str;
	guint                            remain = len - sizeof("Metric:") + 1, state = 0, next_state = 0;
	struct rspamd_metric            *new = NULL;

	p = b;

	while (g_ascii_isspace (*p)) {
		p ++;
	}
	c = p;

	while (p - b <= (gint)remain) {
		switch (state) {
		case 0:
			/* Read metric's name */
			if (*p == ';') {
				if (p - c <= 1) {
					/* Empty metric name */
					goto err;
				}
				else {
					/* Create new metric */
					new = rspamd_create_metric (c, p - c);
					if (g_hash_table_lookup (conn->res.normal.result->metrics, new->name) != NULL) {
						/* Duplicate metric */
						metric_free_func (new);
						goto err;
					}
					g_hash_table_insert (conn->res.normal.result->metrics, new->name, new);
					conn->res.normal.cur_metric = new;
					state = 99;
					next_state = 1;
				}
			}
			p ++;
			break;
		case 1:
			/* Read boolean result */
			if (*p == ';') {
				if (p - c >= (gint)sizeof("Skip")) {
					if (memcmp (c, "Skip", p - c - 1) == 0) {
						new->is_skipped = TRUE;
					}
				}
				state = 99;
				next_state = 2;
			}
			p ++;
			break;
		case 2:
			/* Read score */
			if (g_ascii_isspace (*p)) {
				new->score = strtod (c, &err_str);
				if (*err_str != *p) {
					/* Invalid score */
					goto err;
				}
				state = 99;
				next_state = 3;
			}
			p ++;
			break;
		case 3:
			/* Read / */
			if (g_ascii_isspace (*p)) {
				state = 99;
				next_state = 4;
			}
			else if (*p != '/') {
				goto err;
			}
			p ++;
			break;
		case 4:
			/* Read required score */
			if (g_ascii_isspace (*p) || p - b == (gint)remain) {
				new->required_score = strtod (c, &err_str);
				if (*err_str != *p && *err_str != *(p + 1)) {
					/* Invalid score */
					goto err;
				}
				state = 99;
				next_state = 5;
			}
			p ++;
			break;
		case 5:
			/* Read / if it exists */
			if (g_ascii_isspace (*p)) {
				state = 99;
				next_state = 6;
			}
			else if (*p != '/') {
				goto err;
			}
			p ++;
			break;
		case 6:
			/* Read reject score */
			if (g_ascii_isspace (*p) || p - b == (gint)remain) {
				new->reject_score = strtod (c, &err_str);
				if (*err_str != *p && *err_str != *(p + 1)) {
					/* Invalid score */
					goto err;
				}
				state = 99;
			}
			p ++;
			break;
		case 99:
			/* Skip spaces */
			if (!g_ascii_isspace (*p)) {
				state = next_state;
				c = p;
			}
			else {
				p ++;
			}
			break;
		}
	}

	if (state != 99) {
		goto err;
	}
	return TRUE;

err:
	if (*err == NULL) {
		*err = g_error_new (G_RSPAMD_ERROR, errno, "Invalid metric line: %*s at pos: %d, state: %d",
			remain, b, (int)(p - b), state);
	}
	upstream_fail (&conn->server->up, conn->connection_time);
	return FALSE;
}

/*
 * Parse line like Symbol: <name>[(score)]; [option1, [option2 ...]]
 */
static gboolean
parse_rspamd_symbol_line (struct rspamd_connection *conn, guint len, GError **err)
{
	gchar                           *b = conn->in_buf->str + sizeof("Symbol:") - 1, *p, *c, *err_str, *sym;
	guint                            remain = len - sizeof("Symbol:") + 1, state = 0, next_state = 0, l;
	struct rspamd_symbol            *new = NULL;

	p = b;
	while (g_ascii_isspace (*p)) {
		p ++;
	}
	c = p;
	while (p - b < (gint)remain) {
		switch (state) {
		case 0:
			/* Read symbol's name */
			if (p - b == (gint)remain - 1 || *p == ';' || *p == '(') {
				if (p - c <= 1) {
					/* Empty symbol name */
					goto err;
				}
				else {
					if (p - b == (gint)remain) {
						l = p - c + 1;
					}
					else {
						if (*p == '(') {
							next_state = 1;
						}
						else if (*p == ';' ) {
							next_state = 2;
						}
						l = p - c;
					}
					/* Create new symbol */
					sym = g_malloc (l + 1);
					sym[l] = '\0';
					memcpy (sym, c, l);

					if (g_hash_table_lookup (conn->res.normal.cur_metric->symbols, sym) != NULL) {
						/* Duplicate symbol */
						g_free (sym);
						goto err;
					}
					new = g_malloc0 (sizeof (struct rspamd_symbol));
					new->name = sym;
					g_hash_table_insert (conn->res.normal.cur_metric->symbols, sym, new);
					state = 99;
				}
			}
			p ++;
			break;
		case 1:
			/* Read symbol's weight */
			if (*p == ')') {
				new->weight = strtod (c, &err_str);
				if (*err_str != *p) {
					/* Invalid weight */
					goto err;
				}
				if (*(p + 1) == ';') {
					p ++;
				}
				state = 99;
				if (conn->version >= 13) {
					next_state = 2;
				}
				else {
					next_state = 3;
				}
			}
			p ++;
			break;
		case 2:
			/* Read description */
			if (*p == ';' || p - b == (gint)remain - 1) {
				if (*p == ';') {
					l = p - c;
				}
				else {
					l = p - c + 1;
				}

				if (l > 0) {
					sym = g_malloc (l + 1);
					sym[l] = '\0';
					memcpy (sym, c, l);
					new->description = sym;
				}
				state = 99;
				next_state = 3;
			}
			p ++;
			break;
		case 3:
			/* Read option */
			if (*p == ',' || p - b == (gint)remain - 1) {
				/* Insert option into linked list */
				l = p - c;
				if (p - b == (gint)remain - 1) {
					l ++;
				}
				sym = g_malloc (l + 1);
				sym[l] = '\0';
				memcpy (sym, c, l);
				new->options = g_list_prepend (new->options, sym);
				state = 99;
				next_state = 2;
			}
			p ++;
			break;
		case 99:
			/* Skip spaces */
			if (!g_ascii_isspace (*p)) {
				state = next_state;
				c = p;
			}
			else {
				p ++;
			}
			break;
		}
	}

	if (state != 99) {
		goto err;
	}
	return TRUE;

	err:
	if (*err == NULL) {
		*err = g_error_new (G_RSPAMD_ERROR, errno, "Invalid symbol line: %*s at pos: %d, at state: %d",
				remain, b, (int)(p - b), state);
	}
	upstream_fail (&conn->server->up, conn->connection_time);
	return FALSE;
}

/*
 * Parse line like Action: <action>
 */
static gboolean
parse_rspamd_action_line (struct rspamd_connection *conn, guint len, GError **err)
{
	gchar                           *b = conn->in_buf->str + sizeof("Action:") - 1, *p, *c, *sym;
	guint                            remain = len - sizeof("Action:") + 1, state = 0, next_state = 0;

	p = b;
	c = b;
	while (p - b <= (gint)remain) {
		switch (state) {
		case 0:
			/* Read action */
			if (g_ascii_isspace (*p)) {
				state = 99;
				next_state = 1;
			}
			else {
				state = 1;
			}
			break;
		case 1:
			if (p - b == (gint)remain) {
				if (p - c <= 1) {
					/* Empty action name */
					goto err;
				}
				else {
					/* Create new action */
					sym = g_malloc (p - c + 2);
					sym[p - c + 1] = '\0';
					memcpy (sym, c, p - c + 1);
					conn->res.normal.cur_metric->action = sym;
					state = 99;
				}
			}
			p ++;
			break;
		case 99:
			/* Skip spaces */
			if (!g_ascii_isspace (*p)) {
				state = next_state;
				c = p;
			}
			else {
				p ++;
			}
			break;
		}
	}

	if (state != 99) {
		goto err;
	}
	return TRUE;

	err:
	if (*err == NULL) {
		*err = g_error_new (G_RSPAMD_ERROR, errno, "Invalid action line: %*s at pos: %d",
				remain, b, (int)(p - b));
	}
	upstream_fail (&conn->server->up, conn->connection_time);
	return FALSE;
}

/*
 * Parse line like Header: <value>
 */
static gboolean
parse_rspamd_header_line (struct rspamd_connection *conn, guint len, GError **err)
{
	gchar                           *b = conn->in_buf->str, *p, *c, *hname = NULL, *hvalue = NULL;
	guint                            remain = len, state = 0, next_state = 0, clen;

	p = b;
	c = b;
	while (p - b <= (gint)remain) {
		switch (state) {
		case 0:
			/* Read header name */
			if (*p == ':') {
				if (p - c <= 1) {
					/* Empty header name */
					goto err;
				}
				else {
					/* Create header name */
					hname = g_malloc (p - c + 1);
					hname[p - c] = '\0';
					memcpy (hname, c, p - c);
					next_state = 1;
					state = 99;
				}
			}
			p ++;
			break;
		case 1:
			if (p - b == (gint)remain) {
				if (p - c <= 1) {
					/* Empty action name */
					goto err;
				}
				else {
					/* Create header value */
					hvalue = g_malloc (p - c + 2);
					hvalue[p - c + 1] = '\0';
					memcpy (hvalue, c, p - c + 1);
					if (conn->is_controller) {
						if (g_ascii_strcasecmp (hname, "Content-Length") == 0) {
							/* Preallocate data buffer */
							errno = 0;
							clen = strtoul (hvalue, NULL, 10);
							if (errno == 0 && clen > 0) {
								conn->res.controller.result->data = g_string_sized_new (clen);
							}
						}
						g_hash_table_replace (conn->res.controller.result->headers, hname, hvalue);
					}
					else {
						g_hash_table_replace (conn->res.normal.result->headers, hname, hvalue);
					}
					state = 99;
				}
			}
			p ++;
			break;
		case 99:
			/* Skip spaces */
			if (!g_ascii_isspace (*p)) {
				state = next_state;
				c = p;
			}
			else {
				p ++;
			}
			break;
		}
	}

	if (state != 99) {
		goto err;
	}
	return TRUE;

err:
	if (*err == NULL) {
		g_assert (0);
		*err = g_error_new (G_RSPAMD_ERROR, errno, "Invalid header line: %*s at pos: %d",
				remain, b, (int)(p - b));
	}
	if (hname) {
		g_free (hname);
	}
	if (hvalue) {
		g_free (hvalue);
	}
	upstream_fail (&conn->server->up, conn->connection_time);
	return FALSE;
}

static gboolean
parse_rspamd_controller_reply (struct rspamd_connection *conn, guint len, GError **err)
{
	gchar                           *b = conn->in_buf->str, *p, *c;
	const gchar						 http_rep[] = "HTTP/1.0 ";
	guint                            remain = len, state = 0, next_state = 0;

	/* First of all skip "HTTP/1.0 " line */
	if (len < sizeof (http_rep) || memcmp (b, http_rep, sizeof (http_rep) - 1) != 0) {
		g_set_error (err, G_RSPAMD_ERROR, -1, "Invalid reply line");
		return FALSE;
	}
	b += sizeof (http_rep) - 1;
	p = b;
	c = b;
	remain -= sizeof (http_rep) - 1;

	while (p - b <= (gint)remain) {
		switch (state) {
		case 0:
			/* Try to get code */
			if (g_ascii_isdigit (*p)) {
				p ++;
			}
			else if (g_ascii_isspace (*p)) {
				conn->res.controller.result->code = atoi (c);
				next_state = 1;
				state = 99;
			}
			else {
				goto err;
			}
			break;
		case 1:
			/* Get reply string */
			if (p - b == (gint)remain) {
				if (p - c <= 0) {
					/* Empty action name */
					goto err;
				}
				else {
					/* Create header value */
					conn->res.controller.result->result = g_string_sized_new (p - c + 1);
					g_string_append_len (conn->res.controller.result->result, c, p - c);
					state = 99;
				}
			}
			p ++;
			break;
		case 99:
			/* Skip spaces */
			if (!g_ascii_isspace (*p)) {
				state = next_state;
				c = p;
			}
			else {
				p ++;
			}
			break;
		}
	}

	if (state != 99) {
		goto err;
	}

	conn->res.controller.state = CONTROLLER_READ_HEADER;

	return TRUE;

err:
	if (*err == NULL) {
		*err = g_error_new (G_RSPAMD_ERROR, errno, "Invalid reply line: %*s at pos: %d",
				remain, b, (int)(p - b));
	}
	return FALSE;
}

static gboolean
parse_rspamd_reply_line (struct rspamd_connection *c, guint len, GError **err)
{
	gchar                           *p = c->in_buf->str;

	if (c->is_controller) {
		switch (c->res.controller.state) {
		case CONTROLLER_READ_REPLY:
			return parse_rspamd_controller_reply (c, len, err);
			break;
		case CONTROLLER_READ_HEADER:
			if (len == 0) {
				/* End of headers */
				c->res.controller.state = CONTROLLER_READ_DATA;
				if (c->res.controller.result->data == NULL) {
					/* Cannot detect size as controller didn't send Content-Length header, so guess it */
					c->res.controller.result->data = g_string_new (NULL);
				}
				return TRUE;
			}
			else {
				return parse_rspamd_header_line (c, len, err);
			}
			break;
		case CONTROLLER_READ_DATA:
			g_string_append_len (c->res.controller.result->data, p, len);
			g_string_append_len (c->res.controller.result->data, CRLF, 2);
			return TRUE;
			break;
		}
	}
	else {
		/*
		 * In fact we have 3 states of parsing:
		 * 1) we have current metric and parse symbols
		 * 2) we have no current metric and skip everything to headers hash
		 * 3) we have current metric but got not symbol but header -> put it into headers hash
		 * Line is parsed using specific state machine
		 */
		if (len > 0) {
			if (c->res.normal.cur_metric == NULL) {
				if (len > sizeof ("RSPAMD/") && memcmp (p, "RSPAMD/", sizeof ("RSPAMD/") - 1) == 0) {
					return parse_rspamd_first_line (c, len, err);
				}
				else if (len > sizeof ("Metric:") && memcmp (p, "Metric:", sizeof("Metric:") - 1) == 0) {
					return parse_rspamd_metric_line (c, len, err);
				}
				else {
					return parse_rspamd_header_line (c, len, err);
				}
			}
			else {
				if (len > sizeof ("Metric:") && memcmp (p, "Metric:", sizeof("Metric:") - 1) == 0) {
					return parse_rspamd_metric_line (c, len, err);
				}
				else if (len > sizeof ("Symbol:") && memcmp (p, "Symbol:", sizeof("Symbol:") - 1) == 0) {
					return parse_rspamd_symbol_line (c, len, err);
				}
				else if (len > sizeof ("Action:") && memcmp (p, "Action:", sizeof("Action:") - 1) == 0) {
					return parse_rspamd_action_line (c, len, err);
				}
				else {
					return parse_rspamd_header_line (c, len, err);
				}
			}
		}
		else {
			/* TODO: here we should parse commands that contains data, like PROCESS */
			return TRUE;
		}
	}

	/* Not reached */
	return FALSE;
}

static gboolean
read_rspamd_reply_line (struct rspamd_connection *c, GError **err)
{
	gint                             len, r;
	char                             p;

	/* Try to obtain string from the input buffer */
	if (c->in_buf->len > 0) {
		len = 0;
		while (len < (gint)c->in_buf->len) {
			p = c->in_buf->str[len];
			if (p == '\n') {
				if (parse_rspamd_reply_line (c, len - 1, err)) {
					/* Move remaining buffer to the begin of string */
					c->in_buf = g_string_erase (c->in_buf, 0, len + 1);
					len = 0;
				}
				else {
					return FALSE;
				}
			}
			len ++;
		}
	}
	/* Poll socket */
	if ((r = poll_sync_socket (c->socket, c->client->read_timeout, POLL_IN)) <= 0) {
		if (*err == NULL) {
			if (r == 0) {
				errno = ETIMEDOUT;
			}
			*err = g_error_new (G_RSPAMD_ERROR, errno, "Cannot read reply from controller %s: %s",
					c->server->name, strerror (errno));
		}
		upstream_fail (&c->server->up, c->connection_time);
		return FALSE;
	}
	if (c->in_buf->allocated_len - c->in_buf->len < BUFSIZ / 2) {
		/* Grow buffer */
		c->in_buf = g_string_set_size (c->in_buf, c->in_buf->allocated_len * 2);
	}
	/* Read new data to a string */
	if ((r = read (c->socket,
			c->in_buf->str + c->in_buf->len,
			c->in_buf->allocated_len - c->in_buf->len)) > 0) {
		/* Try to parse remaining data */
		c->in_buf->len += r;
		return read_rspamd_reply_line (c, err);
	}

	return FALSE;
}

/*
 * More or less portable version of sendfile
 */
static gboolean
rspamd_sendfile (gint sock, gint fd, GError **err)
{

	/* Make socket blocking for further operations */
	make_socket_blocking (sock);
#ifdef HAVE_SENDFILE
# if defined(FREEBSD) || defined(DARWIN)
	off_t                           off = 0;
#  if defined(FREEBSD)
	/* FreeBSD version */
	if (sendfile (fd, sock, 0, 0, NULL, &off, 0) != 0) {
#  elif defined(DARWIN)
	/* Darwin version */
	if (sendfile (fd, sock, 0, &off, NULL, 0) != 0) {
#  endif
		goto err;
	}
# else
	ssize_t                         r;
	off_t                           off = 0;
	struct stat                     st;

	fstat (fd, &st);
	/* Linux version */
	r = sendfile (sock, fd, &off, st.st_size);
	if (r == -1) {
		goto err;
	}
# endif
#else
	/* Emulating version */
	ssize_t                         r;
	gchar                           buf[BUFSIZ];

	while ((r = read (fd, buf, sizeof (buf))) > 0) {
		if ((r = write (sock, buf, r)) != r) {
			goto err;
		}
	}
#endif
	make_socket_nonblocking (sock);

	return TRUE;

err:
	if (*err == NULL) {
		*err = g_error_new (G_RSPAMD_ERROR, errno, "Sendfile error: %s",
			strerror (errno));
	}
	return FALSE;
}

struct hash_iter_cb {
	gchar *buf;
	gsize size;
	gsize pos;
};

static void
rspamd_hash_iter_cb (gpointer key, gpointer value, gpointer ud)
{
	struct hash_iter_cb            *cd = ud;

	cd->pos += snprintf (cd->buf + cd->pos, cd->size - cd->pos,
			"%s: %s\r\n", (const gchar *)key, (const gchar *)value);
}

static gboolean
rspamd_send_normal_command (struct rspamd_connection *c, const gchar *command,
		gsize clen, GHashTable *headers, GError **err)
{
	gchar                           outbuf[16384];
	gint                            r;
	struct hash_iter_cb             cbdata;

	/* Write command */
	r = snprintf (outbuf, sizeof (outbuf), "%s RSPAMC/1.3\r\n", command);
	r += snprintf (outbuf + r, sizeof (outbuf) - r, "Content-Length: %lu\r\n", (unsigned long)clen);
	/* Iterate through headers */
	if (headers != NULL) {
		cbdata.size = sizeof (outbuf);
		cbdata.pos = r;
		cbdata.buf = outbuf;
		g_hash_table_foreach (headers, rspamd_hash_iter_cb, &cbdata);
		r = cbdata.pos;
	}
	r += snprintf (outbuf + r, sizeof (outbuf) - r, "\r\n");

	if ((r = write (c->socket, outbuf, r)) == -1) {
		if (*err == NULL) {
			*err = g_error_new (G_RSPAMD_ERROR, errno, "Write error: %s",
				strerror (errno));
		}
		return FALSE;
	}

	return TRUE;
}

static void
rspamd_free_connection (struct rspamd_connection *c)
{
	make_socket_blocking (c->socket);
	(void)close (c->socket);
	g_string_free (c->in_buf, TRUE);

	g_free (c);
}



static gboolean
rspamd_send_controller_command (struct rspamd_connection *c, const gchar *command, const gchar *password, GHashTable *in_headers, gint fd, GByteArray *data, GError **err)
{
	struct iovec						 iov[2];
	gchar								 outbuf[BUFSIZ];
	gint								 r;
	struct stat							 st;
	struct hash_iter_cb             	 cbdata;

	/* Form a request */
	r = rspamd_snprintf (outbuf, sizeof (outbuf), "GET / HTTP/1.0" CRLF "Command: %s" CRLF, command);
	/* Content length */
	if (fd != -1) {
		if (fstat (fd, &st) == -1) {
			g_set_error (err, G_RSPAMD_ERROR, errno, "Stat error: %s", strerror (errno));
			goto err;
		}
		r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, "Content-Length: %z" CRLF, st.st_size);
	}
	else if (data && data->len > 0) {
		r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, "Content-Length: %z" CRLF, data->len);
	}
	/* Password */
	if (password != NULL) {
		r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, "Password: %s" CRLF, password);
	}
	/* Other headers */
	if (in_headers != NULL) {
		cbdata.size = sizeof (outbuf);
		cbdata.pos = r;
		cbdata.buf = outbuf;
		g_hash_table_foreach (in_headers, rspamd_hash_iter_cb, &cbdata);
		r = cbdata.pos;
	}
	r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, CRLF);


	/* Assume that a socket is in blocking mode */
	if (fd != -1) {
#ifdef LINUX
		if (send (c->socket, outbuf, r, MSG_MORE) == -1) {
			g_set_error (err, G_RSPAMD_ERROR, errno, "Send error: %s", strerror (errno));
			goto err;
		}
#else
		if (send (c->socket, outbuf, r, 0) == -1) {
			g_set_error (err, G_RSPAMD_ERROR, errno, "Send error: %s", strerror (errno));
			goto err;
		}
#endif
		if (!rspamd_sendfile (c->socket, fd, err)) {
			goto err;
		}
	}
	else if (data && data->len > 0) {
		/* Use iovec */
		iov[0].iov_base = outbuf;
		iov[0].iov_len = r;
		iov[1].iov_base = data->data;
		iov[1].iov_len = data->len;

		if (writev (c->socket, iov, G_N_ELEMENTS (iov)) == -1) {
			g_set_error (err, G_RSPAMD_ERROR, errno, "Writev error: %s", strerror (errno));
			goto err;
		}
	}
	else {
		/* Just write request */
		if (send (c->socket, outbuf, r, 0) == -1) {
			g_set_error (err, G_RSPAMD_ERROR, errno, "Send error: %s", strerror (errno));
			goto err;
		}
	}

	return TRUE;
err:
	return FALSE;
}

/** Public API **/

/*
 * Init rspamd client library
 */
struct rspamd_client*
rspamd_client_init_binded (const struct in_addr *addr)
{
	struct rspamd_client           *client;

	client = g_malloc0 (sizeof (struct rspamd_client));
	client->read_timeout = DEFAULT_READ_TIMEOUT;
	client->connect_timeout = DEFAULT_CONNECT_TIMEOUT;

	if (addr != NULL) {
		client->bind_addr = g_malloc (sizeof (struct in_addr));
		memcpy (client->bind_addr, addr, sizeof (struct in_addr));
	}

	return client;
}

struct rspamd_client*
rspamd_client_init (void)
{
	return rspamd_client_init_binded (NULL);
}

/*
 * Add rspamd server
 */
gboolean
rspamd_add_server (struct rspamd_client *client, const gchar *host, guint16 port,
		guint16 controller_port, GError **err)
{
	struct rspamd_server           *new;
	struct hostent                 *hent;
	gint							nlen;

	g_assert (client != NULL);
	if (client->servers_num >= MAX_RSPAMD_SERVERS) {
		if (*err == NULL) {
			*err = g_error_new (G_RSPAMD_ERROR, 1, "Maximum number of servers reached: %d", MAX_RSPAMD_SERVERS);
		}
		return FALSE;
	}
	new = &client->servers[client->servers_num];

	if (!inet_aton (host, &new->addr)) {
		/* Try to call gethostbyname */
		hent = gethostbyname (host);
		if (hent == NULL) {
			if (*err == NULL) {
				*err = g_error_new (G_RSPAMD_ERROR, 1, "Cannot resolve: %s", host);
			}
			return FALSE;
		}
		else {
			memcpy (&new->addr, hent->h_addr, sizeof (struct in_addr));
		}
	}
	new->client_port = port;
	new->controller_port = controller_port;
	nlen = strlen (host) + sizeof ("65535") + 1;
	new->name = g_malloc (nlen);
	new->controller_name = g_malloc (nlen);
	rspamd_snprintf (new->name, nlen, "%s:%d", host, (gint)port);
	rspamd_snprintf (new->controller_name, nlen, "%s:%d", host, (gint)controller_port);

	client->servers_num ++;
	return TRUE;
}

/*
 * Set timeouts (values in milliseconds)
 */
void
rspamd_set_timeout (struct rspamd_client *client, guint connect_timeout, guint read_timeout)
{
	g_assert (client != NULL);

	if (connect_timeout > 0) {
		client->connect_timeout = connect_timeout;
	}
	if (read_timeout > 0) {
		client->read_timeout = read_timeout;
	}
}

/*
 * Scan message from memory
 */
struct rspamd_result *
rspamd_scan_memory (struct rspamd_client *client, const guchar *message, gsize length, GHashTable *headers, GError **err)
{
	struct rspamd_connection             *c;
	struct rspamd_result                 *res = NULL;

	g_assert (client != NULL);
	g_assert (length > 0);

	/* Connect to server */
	c = rspamd_connect_random_server (client, FALSE, err);

	if (c == NULL) {
		return NULL;
	}

	/* Set socket blocking for writing */
	make_socket_blocking (c->socket);
	/* Send command */
	if (!rspamd_send_normal_command (c, "SYMBOLS", length, headers, err)) {
		return NULL;
	}

	/* Send message */
	if (write (c->socket, message, length) == -1) {
		if (*err == NULL) {
			*err = g_error_new (G_RSPAMD_ERROR, errno, "Write error: %s",
					strerror (errno));
		}
		return NULL;
	}

	/* Create result structure */
	res = rspamd_create_result (c);
	c->res.normal.result = res;
	c->is_controller = FALSE;
	/* Restore non-blocking mode for reading operations */
	make_socket_nonblocking (c->socket);

	/* Read result cycle */
	while (read_rspamd_reply_line (c, err));

	upstream_ok (&c->server->up, c->connection_time);
	return res;
}

/*
 * Scan message from file
 */
struct rspamd_result *
rspamd_scan_file (struct rspamd_client *client, const guchar *filename, GHashTable *headers, GError **err)
{
	gint                                 fd;
	g_assert (client != NULL);

	/* Open file */
	if ((fd = open (filename, O_RDONLY)) == -1) {
		if (*err == NULL) {
			*err = g_error_new (G_RSPAMD_ERROR, errno, "Open error for file %s: %s",
					filename, strerror (errno));
		}
		return NULL;
	}

	return rspamd_scan_fd (client, fd, headers, err);
}

/*
 * Scan message from fd
 */
struct rspamd_result *
rspamd_scan_fd (struct rspamd_client *client, int fd, GHashTable *headers, GError **err)
{
	struct rspamd_connection             *c;
	struct rspamd_result                 *res = NULL;
	struct stat                           st;

	g_assert (client != NULL);

	/* Connect to server */
	c = rspamd_connect_random_server (client, FALSE, err);

	if (c == NULL) {
		return NULL;
	}

	/* Get length */
	if (fstat (fd, &st) == -1) {
		if (*err == NULL) {
			*err = g_error_new (G_RSPAMD_ERROR, errno, "Stat error: %s",
					strerror (errno));
		}
		return NULL;
	}
	if (st.st_size == 0) {
		if (*err == NULL) {
			*err = g_error_new (G_RSPAMD_ERROR, -1, "File has zero length");
		}
		return NULL;
	}
	/* Set socket blocking for writing */
	make_socket_blocking (c->socket);
	/* Send command */
	if (!rspamd_send_normal_command (c, "SYMBOLS", (gsize)st.st_size, headers, err)) {
		return NULL;
	}

	/* Send message */
	if (!rspamd_sendfile (c->socket, fd, err)) {
		return NULL;
	}

	/* Create result structure */
	res = rspamd_create_result (c);
	c->is_controller = FALSE;
	c->res.normal.result = res;
	/* Restore non-blocking mode for reading operations */
	make_socket_nonblocking (c->socket);

	/* Read result cycle */
	while (read_rspamd_reply_line (c, err));

	upstream_ok (&c->server->up, c->connection_time);
	return res;
}

/*
 * Send a common controller command to all servers
 */
static void
rspamd_controller_command_single (struct rspamd_client* client, const gchar *command, const gchar *password,
		GHashTable *in_headers, GByteArray *mem, gint fd, GError **err,
		struct rspamd_controller_result *res, struct rspamd_server *serv)
{
	struct rspamd_connection             *c;

	/* Connect to server */
	c = rspamd_connect_specific_server (client, FALSE, err, serv);

	if (c == NULL) {
		return;
	}

	res->conn = c;
	/* Set socket blocking for writing */
	make_socket_blocking (c->socket);

	/* Send command */
	if (!rspamd_send_controller_command (c, command, password, in_headers, fd, mem, err)) {
		res->result = g_string_new (*err != NULL ? (*err)->message : "unknown error");
		res->code = 500;
		return;
	}
	c->is_controller = TRUE;
	c->res.controller.result = res;

	/* Restore non-blocking mode for reading operations */
	make_socket_nonblocking (c->socket);

	/* Read result cycle */
	while (read_rspamd_reply_line (c, err));

	upstream_ok (&c->server->up, c->connection_time);
}

/*
 * Send a common controller command to all servers
 */
static GList*
rspamd_controller_command_common (struct rspamd_client* client, const gchar *command, const gchar *password,
		GHashTable *in_headers, GByteArray *mem, gint fd, GError **err)
{
	struct rspamd_server				*serv;
	struct rspamd_controller_result		*res;
	GList								*res_list = NULL;
	guint								 i;

	g_assert (client != NULL);

	for (i = 0; i < client->servers_num; i ++) {
		serv = &client->servers[i];
		res = rspamd_create_controller_result (NULL);
		res->server_name = serv->controller_name;
		res_list = g_list_prepend (res_list, res);
		/* Fill result */
		rspamd_controller_command_single (client, command, password, in_headers, mem, fd, err, res, serv);
	}

	return res_list;
}

/**
 * Perform a simple controller command on all rspamd servers
 * @param client  rspamd client
 * @param command command to send
 * @param password password (NULL if no password required)
 * @param in_headers custom in headers, specific for this command (or NULL)
 * @param err error object (should be pointer to NULL object)
 * @return list of rspamd_controller_result structures for each server
 */
GList*
rspamd_controller_command_simple (struct rspamd_client* client, const gchar *command, const gchar *password,
		GHashTable *in_headers, GError **err)
{
	return rspamd_controller_command_common (client, command, password, in_headers, NULL, -1, err);
}

/**
 * Perform a controller command on all rspamd servers with in memory argument
 * @param client  rspamd client
 * @param command command to send
 * @param password password (NULL if no password required)
 * @param in_headers custom in headers, specific for this command (or NULL)
 * @param message data to pass to the controller
 * @param length its length
 * @param err error object (should be pointer to NULL object)
 * @return list of rspamd_controller_result structures for each server
 */
GList*
rspamd_controller_command_memory (struct rspamd_client* client, const gchar *command, const gchar *password,
		GHashTable *in_headers, const guchar *message, gsize length, GError **err)
{
	GByteArray								ba;
	ba.data = (guint8 *)message;
	ba.len = length;
	return rspamd_controller_command_common (client, command, password, in_headers, &ba, -1, err);
}

/**
 * Perform a controller command on all rspamd servers with descriptor argument
 * @param client  rspamd client
 * @param command command to send
 * @param password password (NULL if no password required)
 * @param in_headers custom in headers, specific for this command (or NULL)
 * @param fd file descriptor of data
 * @param err error object (should be pointer to NULL object)
 * @return list of rspamd_controller_result structures for each server
 */
GList*
rspamd_controller_command_fd (struct rspamd_client* client, const gchar *command, const gchar *password,
		GHashTable *in_headers, gint fd, GError **err)
{
	return rspamd_controller_command_common (client, command, password, in_headers, NULL, fd, err);
}

/**
 * Perform a controller command on all rspamd servers with descriptor argument
 * @param client  rspamd client
 * @param command command to send
 * @param password password (NULL if no password required)
 * @param in_headers custom in headers, specific for this command (or NULL)
 * @param filename filename of data
 * @param err error object (should be pointer to NULL object)
 * @return list of rspamd_controller_result structures for each server
 */
GList*
rspamd_controller_command_file (struct rspamd_client* client, const gchar *command, const gchar *password,
		GHashTable *in_headers, const gchar *filename, GError **err)
{
	gint									fd;

	/* Open file */
	if ((fd = open (filename, O_RDONLY)) == -1) {
		if (*err == NULL) {
			*err = g_error_new (G_RSPAMD_ERROR, errno, "Open error for file %s: %s",
					filename, strerror (errno));
		}
		return NULL;
	}
	return rspamd_controller_command_common (client, command, password, in_headers, NULL, fd, err);
}


/*
 * Free results
 */
void
rspamd_free_result (struct rspamd_result *result)
{
	g_assert (result != NULL);

	g_hash_table_destroy (result->headers);
	g_hash_table_destroy (result->metrics);
	rspamd_free_connection (result->conn);
}

void
rspamd_free_controller_result (struct rspamd_controller_result *result)
{
	g_assert (result != NULL);

	g_hash_table_destroy (result->headers);
	g_string_free (result->result, TRUE);
	if (result->data) {
		g_string_free (result->data, TRUE);
	}
	rspamd_free_connection (result->conn);
}

/*
 * Close library and free associated resources
 */
void
rspamd_client_close (struct rspamd_client *client)
{
	struct rspamd_server			*serv;
	guint							 i;

	if (client->bind_addr) {
		g_free (client->bind_addr);
	}

	/* Cleanup servers */
	for (i = 0; i < client->servers_num; i ++) {
		serv = &client->servers[i];
		g_free (serv->name);
		g_free (serv->controller_name);
	}

	g_free (client);
}
