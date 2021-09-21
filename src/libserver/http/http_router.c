/*-
 * Copyright 2019 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "http_router.h"
#include "http_connection.h"
#include "http_private.h"
#include "libutil/regexp.h"
#include "libutil/printf.h"
#include "libserver/logger.h"
#include "utlist.h"
#include "unix-std.h"

enum http_magic_type {
	HTTP_MAGIC_PLAIN = 0,
	HTTP_MAGIC_HTML,
	HTTP_MAGIC_CSS,
	HTTP_MAGIC_JS,
	HTTP_MAGIC_PNG,
	HTTP_MAGIC_JPG
};

static const struct _rspamd_http_magic {
	const gchar *ext;
	const gchar *ct;
} http_file_types[] = {
		[HTTP_MAGIC_PLAIN] = { "txt", "text/plain" },
		[HTTP_MAGIC_HTML] = { "html", "text/html" },
		[HTTP_MAGIC_CSS] = { "css", "text/css" },
		[HTTP_MAGIC_JS] = { "js", "application/javascript" },
		[HTTP_MAGIC_PNG] = { "png", "image/png" },
		[HTTP_MAGIC_JPG] = { "jpg", "image/jpeg" },
};

/*
 * HTTP router functions
 */

static void
rspamd_http_entry_free (struct rspamd_http_connection_entry *entry)
{
	if (entry != NULL) {
		close (entry->conn->fd);
		rspamd_http_connection_unref (entry->conn);
		if (entry->rt->finish_handler) {
			entry->rt->finish_handler (entry);
		}

		DL_DELETE (entry->rt->conns, entry);
		g_free (entry);
	}
}

static void
rspamd_http_router_error_handler (struct rspamd_http_connection *conn,
								  GError *err)
{
	struct rspamd_http_connection_entry *entry = conn->ud;
	struct rspamd_http_message *msg;

	if (entry->is_reply) {
		/* At this point we need to finish this session and close owned socket */
		if (entry->rt->error_handler != NULL) {
			entry->rt->error_handler (entry, err);
		}
		rspamd_http_entry_free (entry);
	}
	else {
		/* Here we can write a reply to a client */
		if (entry->rt->error_handler != NULL) {
			entry->rt->error_handler (entry, err);
		}
		msg = rspamd_http_new_message (HTTP_RESPONSE);
		msg->date = time (NULL);
		msg->code = err->code;
		rspamd_http_message_set_body (msg, err->message, strlen (err->message));
		rspamd_http_connection_reset (entry->conn);
		rspamd_http_connection_write_message (entry->conn,
				msg,
				NULL,
				"text/plain",
				entry,
				entry->rt->timeout);
		entry->is_reply = TRUE;
	}
}

static const gchar *
rspamd_http_router_detect_ct (const gchar *path)
{
	const gchar *dot;
	guint i;

	dot = strrchr (path, '.');
	if (dot == NULL) {
		return http_file_types[HTTP_MAGIC_PLAIN].ct;
	}
	dot++;

	for (i = 0; i < G_N_ELEMENTS (http_file_types); i++) {
		if (strcmp (http_file_types[i].ext, dot) == 0) {
			return http_file_types[i].ct;
		}
	}

	return http_file_types[HTTP_MAGIC_PLAIN].ct;
}

static gboolean
rspamd_http_router_is_subdir (const gchar *parent, const gchar *sub)
{
	if (parent == NULL || sub == NULL || *parent == '\0') {
		return FALSE;
	}

	while (*parent != '\0') {
		if (*sub != *parent) {
			return FALSE;
		}
		parent++;
		sub++;
	}

	parent--;
	if (*parent == G_DIR_SEPARATOR) {
		return TRUE;
	}

	return (*sub == G_DIR_SEPARATOR || *sub == '\0');
}

static gboolean
rspamd_http_router_try_file (struct rspamd_http_connection_entry *entry,
							 rspamd_ftok_t *lookup, gboolean expand_path)
{
	struct stat st;
	gint fd;
	gchar filebuf[PATH_MAX], realbuf[PATH_MAX], *dir;
	struct rspamd_http_message *reply_msg;

	rspamd_snprintf (filebuf, sizeof (filebuf), "%s%c%T",
			entry->rt->default_fs_path, G_DIR_SEPARATOR, lookup);

	if (realpath (filebuf, realbuf) == NULL ||
		lstat (realbuf, &st) == -1) {
		return FALSE;
	}

	if (S_ISDIR (st.st_mode) && expand_path) {
		/* Try to append 'index.html' to the url */
		rspamd_fstring_t *nlookup;
		rspamd_ftok_t tok;
		gboolean ret;

		nlookup = rspamd_fstring_sized_new (lookup->len + sizeof ("index.html"));
		rspamd_printf_fstring (&nlookup, "%T%c%s", lookup, G_DIR_SEPARATOR,
				"index.html");
		tok.begin = nlookup->str;
		tok.len = nlookup->len;
		ret = rspamd_http_router_try_file (entry, &tok, FALSE);
		rspamd_fstring_free (nlookup);

		return ret;
	}
	else if (!S_ISREG (st.st_mode)) {
		return FALSE;
	}

	/* We also need to ensure that file is inside the defined dir */
	rspamd_strlcpy (filebuf, realbuf, sizeof (filebuf));
	dir = dirname (filebuf);

	if (dir == NULL ||
		!rspamd_http_router_is_subdir (entry->rt->default_fs_path,
				dir)) {
		return FALSE;
	}

	fd = open (realbuf, O_RDONLY);
	if (fd == -1) {
		return FALSE;
	}

	reply_msg = rspamd_http_new_message (HTTP_RESPONSE);
	reply_msg->date = time (NULL);
	reply_msg->code = 200;
	rspamd_http_router_insert_headers (entry->rt, reply_msg);

	if (!rspamd_http_message_set_body_from_fd (reply_msg, fd)) {
		rspamd_http_message_free (reply_msg);
		close (fd);
		return FALSE;
	}

	close (fd);

	rspamd_http_connection_reset (entry->conn);

	msg_debug ("requested file %s", realbuf);
	rspamd_http_connection_write_message (entry->conn, reply_msg, NULL,
			rspamd_http_router_detect_ct (realbuf), entry,
			entry->rt->timeout);

	return TRUE;
}

static void
rspamd_http_router_send_error (GError *err,
							   struct rspamd_http_connection_entry *entry)
{
	struct rspamd_http_message *err_msg;

	err_msg = rspamd_http_new_message (HTTP_RESPONSE);
	err_msg->date = time (NULL);
	err_msg->code = err->code;
	rspamd_http_message_set_body (err_msg, err->message,
			strlen (err->message));
	entry->is_reply = TRUE;
	err_msg->status = rspamd_fstring_new_init (err->message, strlen (err->message));
	rspamd_http_router_insert_headers (entry->rt, err_msg);
	rspamd_http_connection_reset (entry->conn);
	rspamd_http_connection_write_message (entry->conn,
			err_msg,
			NULL,
			"text/plain",
			entry,
			entry->rt->timeout);
}


static int
rspamd_http_router_finish_handler (struct rspamd_http_connection *conn,
								   struct rspamd_http_message *msg)
{
	struct rspamd_http_connection_entry *entry = conn->ud;
	rspamd_http_router_handler_t handler = NULL;
	gpointer found;

	GError *err;
	rspamd_ftok_t lookup;
	const rspamd_ftok_t *encoding;
	struct http_parser_url u;
	guint i;
	rspamd_regexp_t *re;
	struct rspamd_http_connection_router *router;
	gchar *pathbuf = NULL;

	G_STATIC_ASSERT (sizeof (rspamd_http_router_handler_t) ==
					 sizeof (gpointer));

	memset (&lookup, 0, sizeof (lookup));
	router = entry->rt;

	if (entry->is_reply) {
		/* Request is finished, it is safe to free a connection */
		rspamd_http_entry_free (entry);
	}
	else {
		if (G_UNLIKELY (msg->method != HTTP_GET && msg->method != HTTP_POST)) {
			if (router->unknown_method_handler) {
				return router->unknown_method_handler (entry, msg);
			}
			else {
				err = g_error_new (HTTP_ERROR, 500,
						"Invalid method");
				if (entry->rt->error_handler != NULL) {
					entry->rt->error_handler (entry, err);
				}

				rspamd_http_router_send_error (err, entry);
				g_error_free (err);

				return 0;
			}
		}

		/* Search for path */
		if (msg->url != NULL && msg->url->len != 0) {

			http_parser_parse_url (msg->url->str, msg->url->len, TRUE, &u);

			if (u.field_set & (1 << UF_PATH)) {
				gsize unnorm_len;

				pathbuf = g_malloc (u.field_data[UF_PATH].len);
				memcpy (pathbuf, msg->url->str + u.field_data[UF_PATH].off,
						u.field_data[UF_PATH].len);
				lookup.begin = pathbuf;
				lookup.len = u.field_data[UF_PATH].len;

				rspamd_http_normalize_path_inplace (pathbuf,
						lookup.len,
						&unnorm_len);
				lookup.len = unnorm_len;
			}
			else {
				lookup.begin = msg->url->str;
				lookup.len = msg->url->len;
			}

			found = g_hash_table_lookup (entry->rt->paths, &lookup);
			memcpy (&handler, &found, sizeof (found));
			msg_debug ("requested known path: %T", &lookup);
		}
		else {
			err = g_error_new (HTTP_ERROR, 404,
					"Empty path requested");
			if (entry->rt->error_handler != NULL) {
				entry->rt->error_handler (entry, err);
			}

			rspamd_http_router_send_error (err, entry);
			g_error_free (err);

			return 0;
		}

		entry->is_reply = TRUE;

		encoding = rspamd_http_message_find_header (msg, "Accept-Encoding");

		if (encoding && rspamd_substring_search (encoding->begin, encoding->len,
				"gzip", 4) != -1) {
			entry->support_gzip = TRUE;
		}

		if (handler != NULL) {
			if (pathbuf) {
				g_free (pathbuf);
			}

			return handler (entry, msg);
		}
		else {
			/* Try regexps */
			for (i = 0; i < router->regexps->len; i ++) {
				re = g_ptr_array_index (router->regexps, i);
				if (rspamd_regexp_match (re, lookup.begin, lookup.len,
						TRUE)) {
					found = rspamd_regexp_get_ud (re);
					memcpy (&handler, &found, sizeof (found));

					if (pathbuf) {
						g_free (pathbuf);
					}

					return handler (entry, msg);
				}
			}

			/* Now try plain file */
			if (entry->rt->default_fs_path == NULL || lookup.len == 0 ||
				!rspamd_http_router_try_file (entry, &lookup, TRUE)) {

				err = g_error_new (HTTP_ERROR, 404,
						"Not found");
				if (entry->rt->error_handler != NULL) {
					entry->rt->error_handler (entry, err);
				}

				msg_info ("path: %T not found", &lookup);
				rspamd_http_router_send_error (err, entry);
				g_error_free (err);
			}
		}
	}

	if (pathbuf) {
		g_free (pathbuf);
	}

	return 0;
}

struct rspamd_http_connection_router *
rspamd_http_router_new (rspamd_http_router_error_handler_t eh,
						rspamd_http_router_finish_handler_t fh,
						ev_tstamp timeout,
						const char *default_fs_path,
						struct rspamd_http_context *ctx)
{
	struct rspamd_http_connection_router *nrouter;
	struct stat st;

	nrouter = g_malloc0 (sizeof (struct rspamd_http_connection_router));
	nrouter->paths = g_hash_table_new_full (rspamd_ftok_icase_hash,
			rspamd_ftok_icase_equal, rspamd_fstring_mapped_ftok_free, NULL);
	nrouter->regexps = g_ptr_array_new ();
	nrouter->conns = NULL;
	nrouter->error_handler = eh;
	nrouter->finish_handler = fh;
	nrouter->response_headers = g_hash_table_new_full (rspamd_strcase_hash,
			rspamd_strcase_equal, g_free, g_free);
	nrouter->event_loop = ctx->event_loop;
	nrouter->timeout = timeout;
	nrouter->default_fs_path = NULL;

	if (default_fs_path != NULL) {
		if (stat (default_fs_path, &st) == -1) {
			msg_err ("cannot stat %s", default_fs_path);
		}
		else {
			if (!S_ISDIR (st.st_mode)) {
				msg_err ("path %s is not a directory", default_fs_path);
			}
			else {
				nrouter->default_fs_path = realpath (default_fs_path, NULL);
			}
		}
	}

	nrouter->ctx = ctx;

	return nrouter;
}

void
rspamd_http_router_set_key (struct rspamd_http_connection_router *router,
							struct rspamd_cryptobox_keypair *key)
{
	g_assert (key != NULL);

	router->key = rspamd_keypair_ref (key);
}

void
rspamd_http_router_add_path (struct rspamd_http_connection_router *router,
							 const gchar *path, rspamd_http_router_handler_t handler)
{
	gpointer ptr;
	rspamd_ftok_t *key;
	rspamd_fstring_t *storage;
	G_STATIC_ASSERT (sizeof (rspamd_http_router_handler_t) ==
					 sizeof (gpointer));

	if (path != NULL && handler != NULL && router != NULL) {
		memcpy (&ptr, &handler, sizeof (ptr));
		storage = rspamd_fstring_new_init (path, strlen (path));
		key = g_malloc0 (sizeof (*key));
		key->begin = storage->str;
		key->len = storage->len;
		g_hash_table_insert (router->paths, key, ptr);
	}
}

void
rspamd_http_router_set_unknown_handler (struct rspamd_http_connection_router *router,
										rspamd_http_router_handler_t handler)
{
	if (router != NULL) {
		router->unknown_method_handler = handler;
	}
}

void
rspamd_http_router_add_header (struct rspamd_http_connection_router *router,
							   const gchar *name, const gchar *value)
{
	if (name != NULL && value != NULL && router != NULL) {
		g_hash_table_replace (router->response_headers, g_strdup (name),
				g_strdup (value));
	}
}

void
rspamd_http_router_insert_headers (struct rspamd_http_connection_router *router,
								   struct rspamd_http_message *msg)
{
	GHashTableIter it;
	gpointer k, v;

	if (router && msg) {
		g_hash_table_iter_init (&it, router->response_headers);

		while (g_hash_table_iter_next (&it, &k, &v)) {
			rspamd_http_message_add_header (msg, k, v);
		}
	}
}

void
rspamd_http_router_add_regexp (struct rspamd_http_connection_router *router,
							   struct rspamd_regexp_s *re, rspamd_http_router_handler_t handler)
{
	gpointer ptr;
	G_STATIC_ASSERT (sizeof (rspamd_http_router_handler_t) ==
					 sizeof (gpointer));

	if (re != NULL && handler != NULL && router != NULL) {
		memcpy (&ptr, &handler, sizeof (ptr));
		rspamd_regexp_set_ud (re, ptr);
		g_ptr_array_add (router->regexps, rspamd_regexp_ref (re));
	}
}

void
rspamd_http_router_handle_socket (struct rspamd_http_connection_router *router,
								  gint fd, gpointer ud)
{
	struct rspamd_http_connection_entry *conn;

	conn = g_malloc0 (sizeof (struct rspamd_http_connection_entry));
	conn->rt = router;
	conn->ud = ud;
	conn->is_reply = FALSE;

	conn->conn = rspamd_http_connection_new_server (router->ctx,
			fd,
			NULL,
			rspamd_http_router_error_handler,
			rspamd_http_router_finish_handler,
			0);

	if (router->key) {
		rspamd_http_connection_set_key (conn->conn, router->key);
	}

	rspamd_http_connection_read_message (conn->conn, conn, router->timeout);
	DL_PREPEND (router->conns, conn);
}

void
rspamd_http_router_free (struct rspamd_http_connection_router *router)
{
	struct rspamd_http_connection_entry *conn, *tmp;
	rspamd_regexp_t *re;
	guint i;

	if (router) {
		DL_FOREACH_SAFE (router->conns, conn, tmp) {
			rspamd_http_entry_free (conn);
		}

		if (router->key) {
			rspamd_keypair_unref (router->key);
		}

		if (router->default_fs_path != NULL) {
			g_free (router->default_fs_path);
		}

		for (i = 0; i < router->regexps->len; i ++) {
			re = g_ptr_array_index (router->regexps, i);
			rspamd_regexp_unref (re);
		}

		g_ptr_array_free (router->regexps, TRUE);
		g_hash_table_unref (router->paths);
		g_hash_table_unref (router->response_headers);
		g_free (router);
	}
}