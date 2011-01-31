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

#define MAX_RSPAMD_SERVERS 255
#define DEFAULT_CONNECT_TIMEOUT 500
#define DEFAULT_READ_TIMEOUT 5000
#define G_RSPAMD_ERROR rspamd_error_quark ()

struct rspamd_server {
	struct upstream up;
	struct in_addr addr;
	guint16 client_port;
	guint16 controller_port;
	gchar *name;
};

struct rspamd_client {
	struct rspamd_server servers[MAX_RSPAMD_SERVERS];
	guint servers_num;
	guint connect_timeout;
	guint read_timeout;
};

struct rspamd_connection {
	struct rspamd_server *server;
	time_t connection_time;
	gint socket;
	struct rspamd_result *result;
	GString *in_buf;
	struct rspamd_metric *cur_metric;
};

static struct rspamd_client *client = NULL;

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
	g_free (m->name);
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
	g_free (s->name);
	g_free (s);
}

static struct rspamd_connection *
rspamd_connect_random_server (gboolean is_control, GError **err)
{
	struct rspamd_server            *selected = NULL;
	struct rspamd_connection        *new;
	time_t                           now;

	if (client->servers_num == 0) {
		errno = EINVAL;
		if (*err == NULL) {
			*err = g_error_new (G_RSPAMD_ERROR, 1, "No servers can be reached");
		}
		return NULL;
	}
	/* Select random server */
	now = time (NULL);
	selected = (struct rspamd_server *)get_random_upstream (client->servers,
			client->servers_num, sizeof (struct rspamd_server),
			now, DEFAULT_UPSTREAM_ERROR_TIME, DEFAULT_UPSTREAM_DEAD_TIME, DEFAULT_UPSTREAM_MAXERRORS);
	if (selected == NULL) {
		errno = EINVAL;
		if (*err == NULL) {
			*err = g_error_new (G_RSPAMD_ERROR, 1, "No servers can be reached");
		}
		return NULL;
	}
	/* Allocate connection */
	new = g_malloc (sizeof (struct rspamd_connection));
	new->server = selected;
	new->connection_time = now;
	/* Create socket */
	new->socket = make_tcp_socket (&selected->addr,
								is_control ? selected->controller_port : selected->client_port,
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
			selected->name, strerror (errno));
	}
	upstream_fail (&selected->up, now);
	g_free (new);
	return NULL;
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

/*
 * Parse line like RSPAMD/{version} {code} {message}
 */
static gboolean
parse_rspamd_first_line (struct rspamd_connection *conn, guint len, GError **err)
{
	gchar                           *b = conn->in_buf->str + sizeof("RSPAMD/") - 1, *p, *c;
	guint                            remain = len - sizeof("RSPAMD/") + 1, state = 0, next_state;

	p = b;
	while (p - b < remain) {
		switch (state) {
		case 0:
			/* Read version */
			if (g_ascii_isspace (*p)) {
				state = 99;
				next_state = 1;
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
					conn->result->is_ok = TRUE;
				}
			}
			else if (!g_ascii_isdigit (*p)) {
				goto err;
			}
			p ++;
			break;
		case 2:
			/* Read message */
			if (g_ascii_isspace (*p) || p - b == remain - 1) {
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
	guint                            remain = len - sizeof("Metric:") + 1, state = 0, next_state;
	struct rspamd_metric            *new;

	p = b;
	c = b;
	while (p - b < remain) {
		switch (state) {
		case 0:
			/* Read metric's name */
			if (g_ascii_isspace (*p)) {
				state = 99;
				next_state = 0;
			}
			else if (*p == ';') {
				if (p - c <= 1) {
					/* Empty metric name */
					goto err;
				}
				else {
					/* Create new metric */
					new = rspamd_create_metric (c, p - c);
					if (g_hash_table_lookup (conn->result->metrics, new->name) != NULL) {
						/* Duplicate metric */
						metric_free_func (new);
						goto err;
					}
					g_hash_table_insert (conn->result->metrics, new->name, new);
					conn->cur_metric = new;
					state = 99;
					next_state = 1;
				}
			}
			p ++;
			break;
		case 1:
			/* Read boolean result */
			if (*p == ';') {
				if (p - c >= sizeof("Skip")) {
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
			if (g_ascii_isspace (*p) || p - b == remain - 1) {
				new->required_score = strtod (c, &err_str);
				if (*err_str != *p) {
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
			if (g_ascii_isspace (*p) || p - b == remain - 1) {
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
	guint                            remain = len - sizeof("Symbol:") + 1, state = 0, next_state, l;
	struct rspamd_symbol            *new;

	p = b;
	c = b;
	while (p - b < remain) {
		switch (state) {
		case 0:
			/* Read symbol's name */
			if (g_ascii_isspace (*p)) {
				state = 99;
				next_state = 0;
			}
			else if (*p == ';' || *p == '(') {
				if (p - c <= 1) {
					/* Empty symbol name */
					goto err;
				}
				else {
					/* Create new symbol */
					sym = g_malloc (p - c + 1);
					sym[p - c] = '\0';
					memcpy (sym, c, p - c);

					if (g_hash_table_lookup (conn->cur_metric->symbols, sym) != NULL) {
						/* Duplicate symbol */
						g_free (sym);
						goto err;
					}
					new = g_malloc0 (sizeof (struct rspamd_symbol));
					new->name = sym;
					g_hash_table_insert (conn->cur_metric->symbols, sym, new);
					state = 99;
					if (*p == '(') {
						next_state = 1;
						new->weight = 0;
					}
					else {
						next_state = 2;
					}
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
				next_state = 2;
			}
			p ++;
			break;
		case 2:
			/* Read option */
			if (*p == ',' || p - b == remain - 1) {
				/* Insert option into linked list */
				l = p - c;
				if (p - b == remain - 1) {
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
		*err = g_error_new (G_RSPAMD_ERROR, errno, "Invalid symbol line: %*s at pos: %d",
				remain, b, (int)(p - b));
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
	guint                            remain = len - sizeof("Action:") + 1, state = 0, next_state;

	p = b;
	c = b;
	while (p - b < remain) {
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
			if (p - b == remain - 1) {
				if (p - c <= 1) {
					/* Empty action name */
					goto err;
				}
				else {
					/* Create new action */
					sym = g_malloc (p - c + 2);
					sym[p - c + 1] = '\0';
					memcpy (sym, c, p - c + 1);

					conn->cur_metric->action = sym;
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
	guint                            remain = len, state = 0, next_state;

	p = b;
	c = b;
	while (p - b < remain) {
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
			if (p - b == remain - 1) {
				if (p - c <= 1) {
					/* Empty action name */
					goto err;
				}
				else {
					/* Create header value */
					hvalue = g_malloc (p - c + 1);
					hvalue[p - c] = '\0';
					memcpy (hvalue, c, p - c);
					g_hash_table_replace (conn->result->headers, hname, hvalue);
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
parse_rspamd_reply_line (struct rspamd_connection *c, guint len, GError **err)
{
	gchar                           *p = c->in_buf->str;

	g_assert (len > 0);

	/*
	 * In fact we have 3 states of parsing:
	 * 1) we have current metric and parse symbols
	 * 2) we have no current metric and skip everything to headers hash
	 * 3) we have current metric but got not symbol but header -> put it into headers hash
	 * Line is parsed using specific state machine
	 */
	if (c->cur_metric == NULL) {
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
		while (len < c->in_buf->len) {
			p = c->in_buf->str[len];
			if (p == '\r' || p == '\n') {
				if (parse_rspamd_reply_line (c, len, err)) {
					/* Strip '\r\n' */
					while (len < c->in_buf->len && (p == '\r' || p == '\n')) {
						p = c->in_buf->str[++len];
					}
					/* Move remaining buffer to the begin of string */
					c->in_buf = g_string_erase (c->in_buf, 0, len);
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
	if (poll_sync_socket (c->socket, client->read_timeout, POLL_IN) == -1) {
		if (*err == NULL) {
			*err = g_error_new (G_RSPAMD_ERROR, errno, "Could not connect to server %s: %s",
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
	if (sendfile (sock, fd, 0, 0, NULL, &off, 0) != 0) {
#  elif defined(DARWIN)
	/* Darwin version */
	if (sendfile (sock, fd, 0, &off, NULL, 0) != 0) {
#  endif
		goto err;
	}
# else
	ssize_t                         r;
	off_t                           off = 0;
	struct stat                     st;

	fstat (fd, &st);
	/* Linux version */
	r = sendfile (fd, sock, &off, st.st_size);
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

static gboolean
rspamd_send_normal_command (struct rspamd_connection *c, const gchar *command,
		gsize clen, GHashTable *headers, GError **err)
{
	static gchar                    outbuf[16384];
	GHashTableIter                  it;
	gpointer                        key, value;
	gint                            r;

	/* Write command */
	r = rspamd_snprintf (outbuf, sizeof (outbuf), "%s RSPAMC/1.2\r\n", command);
	r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, "Content-Length: %uz\r\n", clen);
	/* Iterate through headers */
	if (headers != NULL) {
		g_hash_table_iter_init (&it, headers);
		while (g_hash_table_iter_next (&it, &key, &value)) {
			r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, "%s: %s\r\n", key, value);
		}
	}
	r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, "\r\n");

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

/** Public API **/

/*
 * Init rspamd client library
 */
void
rspamd_client_init (void)
{
	if (client != NULL) {
		rspamd_client_close ();
	}
	client = g_malloc0 (sizeof (struct rspamd_client));
	client->read_timeout = DEFAULT_READ_TIMEOUT;
	client->connect_timeout = DEFAULT_CONNECT_TIMEOUT;
}

/*
 * Add rspamd server
 */
gboolean
rspamd_add_server (const gchar *host, guint16 port, guint16 controller_port, GError **err)
{
	struct rspamd_server           *new;
	struct hostent                 *hent;

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
	new->name = g_strdup (host);

	client->servers_num ++;
	return TRUE;
}

/*
 * Set timeouts (values in milliseconds)
 */
void
rspamd_set_timeout (guint connect_timeout, guint read_timeout)
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
rspamd_scan_memory (const guchar *message, gsize length, GHashTable *headers, GError **err)
{
	struct rspamd_connection             *c;
	struct rspamd_result                 *res = NULL;

	g_assert (client != NULL);

	/* Connect to server */
	c = rspamd_connect_random_server (FALSE, err);

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
	c->result = res;
	/* Restore non-blocking mode for reading operations */
	make_socket_nonblocking (c->socket);

	/* Read result cycle */
	while (read_rspamd_reply_line (c, err));

	return res;
}

/*
 * Scan message from file
 */
struct rspamd_result *
rspamd_scan_file (const guchar *filename, GHashTable *headers, GError **err)
{
	gint                                 fd;
	g_assert (client != NULL);

	/* Open file */
	if ((fd = open (filename, O_RDONLY | O_CLOEXEC)) == -1) {
		if (*err == NULL) {
			*err = g_error_new (G_RSPAMD_ERROR, errno, "Open error for file %s: %s",
					filename, strerror (errno));
		}
		return NULL;
	}

	return rspamd_scan_fd (fd, headers, err);
}

/*
 * Scan message from fd
 */
struct rspamd_result *
rspamd_scan_fd (int fd, GHashTable *headers, GError **err)
{
	struct rspamd_connection             *c;
	struct rspamd_result                 *res = NULL;
	struct stat                           st;

	g_assert (client != NULL);

	/* Connect to server */
	c = rspamd_connect_random_server (FALSE, err);

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
	c->result = res;
	/* Restore non-blocking mode for reading operations */
	make_socket_nonblocking (c->socket);

	/* Read result cycle */
	while (read_rspamd_reply_line (c, err));

	return res;
}

/*
 * Learn message from memory
 */
gboolean
rspamd_learn_memory (const guchar *message, gsize length, const gchar *symbol, GError **err)
{
	g_assert (client != NULL);

}

/*
 * Learn message from file
 */
gboolean
rspamd_learn_file (const guchar *filename, const gchar *symbol, GError **err)
{
	g_assert (client != NULL);

}

/*
 * Learn message from fd
 */
gboolean
rspamd_learn_fd (int fd, const gchar *symbol, GError **err)
{
	g_assert (client != NULL);

}

/*
 * Free results
 */
void
rspamd_free_result (struct rspamd_result *result)
{
	g_assert (client != NULL);

}

/*
 * Close library and free associated resources
 */
void
rspamd_client_close (void)
{
	g_assert (client != NULL);
}
