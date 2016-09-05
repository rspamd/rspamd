/*-
 * Copyright 2016 Vsevolod Stakhov
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

#include "config.h"
#include "ref.h"
#include "fuzzy_backend.h"
#include "fuzzy_backend_redis.h"
#include "redis_pool.h"
#include "cryptobox.h"
#include "str_util.h"
#include "upstream.h"
#include "contrib/hiredis/hiredis.h"
#include "contrib/hiredis/async.h"

#define REDIS_DEFAULT_PORT 6379
#define REDIS_DEFAULT_OBJECT "fuzzy"
#define REDIS_DEFAULT_TIMEOUT 2.0

struct rspamd_fuzzy_backend_redis {
	struct upstream_list *read_servers;
	struct upstream_list *write_servers;
	const gchar *redis_object;
	const gchar *password;
	const gchar *dbname;
	gchar *id;
	struct rspamd_redis_pool *pool;
	gdouble timeout;
	ref_entry_t ref;
};

struct rspamd_fuzzy_redis_session {
	struct rspamd_fuzzy_backend_redis *backend;
	redisAsyncContext *ctx;
	struct event timeout;
	const struct rspamd_fuzzy_cmd *cmd;
	struct event_base *ev_base;
	float prob;
	gboolean shingles_checked;

	enum {
		RSPAMD_FUZZY_REDIS_COMMAND_COUNT,
		RSPAMD_FUZZY_REDIS_COMMAND_VERSION,
		RSPAMD_FUZZY_REDIS_COMMAND_UPDATES,
		RSPAMD_FUZZY_REDIS_COMMAND_CHECK
	} command;
	guint nargs;

	union {
		rspamd_fuzzy_check_cb cb_check;
		rspamd_fuzzy_update_cb cb_update;
		rspamd_fuzzy_version_cb cb_version;
		rspamd_fuzzy_count_cb cb_count;
	} callback;
	void *cbdata;

	gchar **argv;
	gsize *argv_lens;
	struct upstream *up;
};

static inline void
rspamd_fuzzy_redis_session_free_args (struct rspamd_fuzzy_redis_session *session)
{
	guint i;

	if (session->argv) {
		for (i = 0; i < session->nargs; i ++) {
			g_free (session->argv[i]);
		}

		g_free (session->argv);
		g_free (session->argv_lens);
	}
}
static void
rspamd_fuzzy_redis_session_dtor (struct rspamd_fuzzy_redis_session *session)
{
	redisAsyncContext *ac;


	if (session->ctx) {
		ac = session->ctx;
		session->ctx = NULL;
		rspamd_redis_pool_release_connection (session->backend->pool,
				ac, FALSE);
	}

	if (event_get_base (&session->timeout)) {
		event_del (&session->timeout);
	}

	rspamd_fuzzy_redis_session_free_args (session);

	REF_RELEASE (session->backend);
	g_slice_free1 (sizeof (*session), session);
}

static gboolean
rspamd_fuzzy_backend_redis_try_ucl (struct rspamd_fuzzy_backend_redis *backend,
		const ucl_object_t *obj,
		struct rspamd_config *cfg)
{
	const ucl_object_t *elt, *relt;

	elt = ucl_object_lookup_any (obj, "read_servers", "servers", NULL);

	if (elt == NULL) {
		return FALSE;
	}

	backend->read_servers = rspamd_upstreams_create (cfg->ups_ctx);
	if (!rspamd_upstreams_from_ucl (backend->read_servers, elt,
			REDIS_DEFAULT_PORT, NULL)) {
		msg_err_config ("cannot get read servers configuration");
		return FALSE;
	}

	relt = elt;

	elt = ucl_object_lookup (obj, "write_servers");
	if (elt == NULL) {
		/* Use read servers as write ones */
		g_assert (relt != NULL);
		backend->write_servers = rspamd_upstreams_create (cfg->ups_ctx);
		if (!rspamd_upstreams_from_ucl (backend->write_servers, relt,
				REDIS_DEFAULT_PORT, NULL)) {
			msg_err_config ("cannot get write servers configuration");
			return FALSE;
		}
	}
	else {
		backend->write_servers = rspamd_upstreams_create (cfg->ups_ctx);
		if (!rspamd_upstreams_from_ucl (backend->write_servers, elt,
				REDIS_DEFAULT_PORT, NULL)) {
			msg_err_config ("cannot get write servers configuration");
			rspamd_upstreams_destroy (backend->write_servers);
			backend->write_servers = NULL;
		}
	}

	elt = ucl_object_lookup (obj, "prefix");
	if (elt == NULL || ucl_object_type (elt) != UCL_STRING) {
		backend->redis_object = REDIS_DEFAULT_OBJECT;
	}
	else {
		backend->redis_object = ucl_object_tostring (elt);
	}

	elt = ucl_object_lookup (obj, "timeout");
	if (elt) {
		backend->timeout = ucl_object_todouble (elt);
	}
	else {
		backend->timeout = REDIS_DEFAULT_TIMEOUT;
	}

	elt = ucl_object_lookup (obj, "password");
	if (elt) {
		backend->password = ucl_object_tostring (elt);
	}
	else {
		backend->password = NULL;
	}

	elt = ucl_object_lookup_any (obj, "db", "database", "dbname", NULL);
	if (elt) {
		backend->dbname = ucl_object_tostring (elt);
	}
	else {
		backend->dbname = NULL;
	}

	return TRUE;
}

static void
rspamd_fuzzy_backend_redis_dtor (struct rspamd_fuzzy_backend_redis *backend)
{
	if (backend->read_servers) {
		rspamd_upstreams_destroy (backend->read_servers);
	}
	if (backend->write_servers) {
		rspamd_upstreams_destroy (backend->read_servers);
	}

	if (backend->id) {
		g_free (backend->id);
	}

	g_slice_free1 (sizeof (*backend), backend);
}

void*
rspamd_fuzzy_backend_init_redis (struct rspamd_fuzzy_backend *bk,
		const ucl_object_t *obj, struct rspamd_config *cfg, GError **err)
{
	struct rspamd_fuzzy_backend_redis *backend;
	const ucl_object_t *elt;
	gboolean ret = FALSE;
	guchar id_hash[rspamd_cryptobox_HASHBYTES];
	rspamd_cryptobox_hash_state_t st;

	backend = g_slice_alloc0 (sizeof (*backend));

	backend->timeout = REDIS_DEFAULT_TIMEOUT;
	backend->redis_object = REDIS_DEFAULT_OBJECT;

	ret = rspamd_fuzzy_backend_redis_try_ucl (backend, obj, cfg);

	/* Now try global redis settings */
	if (!ret) {
		elt = ucl_object_lookup (cfg->rcl_obj, "redis");

		if (elt) {
			const ucl_object_t *specific_obj;

			specific_obj = ucl_object_lookup_any (elt, "fuzzy", "fuzzy_storage",
					NULL);

			if (specific_obj) {
				ret = rspamd_fuzzy_backend_redis_try_ucl (backend, specific_obj,
						cfg);
			}
			else {
				ret = rspamd_fuzzy_backend_redis_try_ucl (backend, elt, cfg);
			}
		}
	}

	if (!ret) {
		msg_err_config ("cannot init redis backend for fuzzy storage");
		g_slice_free1 (sizeof (*backend), backend);
		return NULL;
	}

	REF_INIT_RETAIN (backend, rspamd_fuzzy_backend_redis_dtor);
	backend->pool = cfg->redis_pool;
	rspamd_cryptobox_hash_init (&st, NULL, 0);
	rspamd_cryptobox_hash_update (&st, backend->redis_object,
			strlen (backend->redis_object));

	if (backend->dbname) {
		rspamd_cryptobox_hash_update (&st, backend->dbname,
				strlen (backend->dbname));
	}

	if (backend->password) {
		rspamd_cryptobox_hash_update (&st, backend->password,
				strlen (backend->password));
	}

	rspamd_cryptobox_hash_final (&st, id_hash);
	backend->id = rspamd_encode_base32 (id_hash, sizeof (id_hash));

	return backend;
}

static void
rspamd_fuzzy_redis_timeout (gint fd, short what, gpointer priv)
{
	struct rspamd_fuzzy_redis_session *session = priv;
	redisAsyncContext *ac;

	if (session->ctx) {
		ac = session->ctx;
		session->ctx = NULL;
		ac->err = REDIS_ERR_IO;

		/* This will cause session closing */
		rspamd_redis_pool_release_connection (session->backend->pool,
				ac, TRUE);
	}
}

static void rspamd_fuzzy_redis_check_callback (redisAsyncContext *c, gpointer r,
		gpointer priv);

struct _rspamd_fuzzy_shingles_helper {
	guchar digest[64];
	guint found;
};

static gint
rspamd_fuzzy_backend_redis_shingles_cmp (const void *a, const void *b)
{
	const struct _rspamd_fuzzy_shingles_helper *sha = a,
			*shb = b;

	return memcmp (sha->digest, shb->digest, sizeof (sha->digest));
}

static void
rspamd_fuzzy_redis_shingles_callback (redisAsyncContext *c, gpointer r,
		gpointer priv)
{
	struct rspamd_fuzzy_redis_session *session = priv;
	redisReply *reply = r, *cur;
	struct rspamd_fuzzy_reply rep;
	struct timeval tv;
	GString *key;
	struct _rspamd_fuzzy_shingles_helper *shingles, *prev = NULL, *sel = NULL;
	guint i, found = 0, max_found = 0, cur_found = 0;

	event_del (&session->timeout);
	memset (&rep, 0, sizeof (rep));

	if (c->err == 0) {
		rspamd_upstream_ok (session->up);

		if (reply->type == REDIS_REPLY_ARRAY &&
				reply->elements == RSPAMD_SHINGLE_SIZE) {
			shingles = g_alloca (sizeof (struct _rspamd_fuzzy_shingles_helper) *
					RSPAMD_SHINGLE_SIZE);

			for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
				cur = reply->element[i];

				if (cur->type == REDIS_REPLY_STRING) {
					shingles[i].found = 1;
					memcpy (shingles[i].digest, cur->str, MIN (64, cur->len));
					found ++;
				}
				else {
					memset (shingles[i].digest, 0, sizeof (shingles[i].digest));
					shingles[i].found = 0;
				}
			}

			session->prob = ((float)found) / RSPAMD_SHINGLE_SIZE;
			rep.prob = session->prob;

			if (found > RSPAMD_SHINGLE_SIZE / 2) {
				/* Now sort to find the most frequent element */
				qsort (shingles, RSPAMD_SHINGLE_SIZE,
						sizeof (struct _rspamd_fuzzy_shingles_helper),
						rspamd_fuzzy_backend_redis_shingles_cmp);

				prev = &shingles[0];

				for (i = 1; i < RSPAMD_SHINGLE_SIZE; i ++) {
					if (!shingles[i].found) {
						continue;
					}

					if (memcmp (shingles[i].digest, prev->digest, 64) == 0) {
						cur_found ++;

						if (cur_found > max_found) {
							max_found = cur_found;
							sel = &shingles[i];
						}
					}
					else {
						cur_found = 1;
						prev = &shingles[i];
					}
				}

				g_assert (sel != NULL);

				/* Prepare new check command */
				rspamd_fuzzy_redis_session_free_args (session);
				session->nargs = 4;
				session->argv = g_malloc (sizeof (gchar *) * session->nargs);
				session->argv_lens = g_malloc (sizeof (gsize) * session->nargs);

				key = g_string_new (session->backend->redis_object);
				g_string_append_len (key, sel->digest, sizeof (sel->digest));
				session->argv[0] = g_strdup ("HMGET");
				session->argv_lens[0] = 5;
				session->argv[1] = key->str;
				session->argv_lens[1] = key->len;
				session->argv[2] = g_strdup ("V");
				session->argv_lens[2] = 1;
				session->argv[3] = g_strdup ("F");
				session->argv_lens[3] = 1;
				g_string_free (key, FALSE); /* Do not free underlying array */

				g_assert (session->ctx != NULL);
				if (redisAsyncCommandArgv (session->ctx, rspamd_fuzzy_redis_check_callback,
						session, session->nargs,
						(const gchar **)session->argv, session->argv_lens) != REDIS_OK) {
					if (session->callback.cb_check) {
						memset (&rep, 0, sizeof (rep));
						session->callback.cb_check (&rep, session->cbdata);
					}

					rspamd_fuzzy_redis_session_dtor (session);
				}
				else {
					/* Add timeout */
					event_set (&session->timeout, -1, EV_TIMEOUT, rspamd_fuzzy_redis_timeout,
							session);
					event_base_set (session->ev_base, &session->timeout);
					double_to_tv (session->backend->timeout, &tv);
					event_add (&session->timeout, &tv);
				}

				return;
			}
		}

		if (session->callback.cb_check) {
			session->callback.cb_check (&rep, session->cbdata);
		}
	}
	else {
		if (session->callback.cb_check) {
			session->callback.cb_check (&rep, session->cbdata);
		}

		rspamd_upstream_fail (session->up);
	}

	rspamd_fuzzy_redis_session_dtor (session);
}

static void
rspamd_fuzzy_backend_check_shingles (struct rspamd_fuzzy_redis_session *session)
{
	struct timeval tv;
	struct rspamd_fuzzy_reply rep;
	const struct rspamd_fuzzy_shingle_cmd *shcmd;
	GString *key;
	guint i;

	rspamd_fuzzy_redis_session_free_args (session);
	/* First of all check digest */
	session->nargs = 2 * session->cmd->shingles_count;
	session->argv = g_malloc (sizeof (gchar *) * session->nargs);
	session->argv_lens = g_malloc (sizeof (gsize) * session->nargs);
	shcmd = (const struct rspamd_fuzzy_shingle_cmd *)session->cmd;

	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
		key = g_string_new (session->backend->redis_object);
		rspamd_printf_gstring (key, "_%d_%uL", i, shcmd->sgl.hashes[i]);
		session->argv[i * 2] = g_strdup ("GET");
		session->argv_lens[i * 2] = 3;
		session->argv[i * 2 + 1] = key->str;
		session->argv_lens[i * 2 + 1] = key->len;
		g_string_free (key, FALSE); /* Do not free underlying array */
	}

	session->shingles_checked = TRUE;

	g_assert (session->ctx != NULL);


	if (redisAsyncCommandArgv (session->ctx, rspamd_fuzzy_redis_shingles_callback,
			session, session->nargs,
			(const gchar **)session->argv, session->argv_lens) != REDIS_OK) {
		if (session->callback.cb_check) {
			memset (&rep, 0, sizeof (rep));
			session->callback.cb_check (&rep, session->cbdata);
		}

		rspamd_fuzzy_redis_session_dtor (session);
	}
	else {
		/* Add timeout */
		event_set (&session->timeout, -1, EV_TIMEOUT, rspamd_fuzzy_redis_timeout,
				session);
		event_base_set (session->ev_base, &session->timeout);
		double_to_tv (session->backend->timeout, &tv);
		event_add (&session->timeout, &tv);
	}
}

static void
rspamd_fuzzy_redis_check_callback (redisAsyncContext *c, gpointer r,
		gpointer priv)
{
	struct rspamd_fuzzy_redis_session *session = priv;
	redisReply *reply = r, *cur;
	struct rspamd_fuzzy_reply rep;
	gulong value;
	guint found_elts = 0;

	event_del (&session->timeout);
	memset (&rep, 0, sizeof (rep));

	if (c->err == 0) {
		rspamd_upstream_ok (session->up);

		if (reply->type == REDIS_REPLY_ARRAY && reply->elements == 2) {
			cur = reply->element[0];

			if (cur->type == REDIS_REPLY_STRING) {
				value = strtoul (cur->str, NULL, 10);
				rep.value = value;
				found_elts ++;
			}

			cur = reply->element[1];

			if (cur->type == REDIS_REPLY_STRING) {
				value = strtoul (cur->str, NULL, 10);
				rep.flag = value;
				found_elts ++;
			}

			if (found_elts == 2) {
				rep.prob = session->prob;
			}
		}

		if (found_elts != 2) {
			if (session->cmd->shingles_count > 0 && !session->shingles_checked) {
				/* We also need to check all shingles here */
				rspamd_fuzzy_backend_check_shingles (session);
				/* Do not free session */
				return;
			}
			else {
				if (session->callback.cb_check) {
					session->callback.cb_check (&rep, session->cbdata);
				}
			}
		}
		else {
			if (session->callback.cb_check) {
				session->callback.cb_check (&rep, session->cbdata);
			}
		}
	}
	else {
		if (session->callback.cb_check) {
			session->callback.cb_check (&rep, session->cbdata);
		}

		rspamd_upstream_fail (session->up);
	}

	rspamd_fuzzy_redis_session_dtor (session);
}

void
rspamd_fuzzy_backend_check_redis (struct rspamd_fuzzy_backend *bk,
		const struct rspamd_fuzzy_cmd *cmd,
		rspamd_fuzzy_check_cb cb, void *ud,
		void *subr_ud)
{
	struct rspamd_fuzzy_backend_redis *backend = subr_ud;
	struct rspamd_fuzzy_redis_session *session;
	struct upstream *up;
	struct timeval tv;
	rspamd_inet_addr_t *addr;
	struct rspamd_fuzzy_reply rep;
	GString *key;

	g_assert (backend != NULL);

	session = g_slice_alloc0 (sizeof (*session));
	session->backend = backend;
	REF_RETAIN (session->backend);

	session->callback.cb_check = cb;
	session->cbdata = ud;
	session->command = RSPAMD_FUZZY_REDIS_COMMAND_CHECK;
	session->cmd = cmd;
	session->prob = 1.0;
	session->ev_base = rspamd_fuzzy_backend_event_base (bk);

	/* First of all check digest */
	session->nargs = 4;
	session->argv = g_malloc (sizeof (gchar *) * session->nargs);
	session->argv_lens = g_malloc (sizeof (gsize) * session->nargs);

	key = g_string_new (backend->redis_object);
	g_string_append_len (key, cmd->digest, sizeof (cmd->digest));
	session->argv[0] = g_strdup ("HMGET");
	session->argv_lens[0] = 5;
	session->argv[1] = key->str;
	session->argv_lens[1] = key->len;
	session->argv[2] = g_strdup ("V");
	session->argv_lens[2] = 1;
	session->argv[3] = g_strdup ("F");
	session->argv_lens[3] = 1;
	g_string_free (key, FALSE); /* Do not free underlying array */

	up = rspamd_upstream_get (backend->read_servers,
			RSPAMD_UPSTREAM_ROUND_ROBIN,
			NULL,
			0);

	session->up = up;
	addr = rspamd_upstream_addr (up);
	g_assert (addr != NULL);
	session->ctx = rspamd_redis_pool_connect (backend->pool,
			backend->dbname, backend->password,
			rspamd_inet_address_to_string (addr),
			rspamd_inet_address_get_port (addr));

	if (session->ctx == NULL) {
		rspamd_fuzzy_redis_session_dtor (session);

		if (cb) {
			memset (&rep, 0, sizeof (rep));
			cb (&rep, subr_ud);
		}
	}
	else {
		if (redisAsyncCommandArgv (session->ctx, rspamd_fuzzy_redis_check_callback,
				session, session->nargs,
				(const gchar **)session->argv, session->argv_lens) != REDIS_OK) {
			rspamd_fuzzy_redis_session_dtor (session);

			if (cb) {
				memset (&rep, 0, sizeof (rep));
				cb (&rep, subr_ud);
			}
		}
		else {
			/* Add timeout */
			event_set (&session->timeout, -1, EV_TIMEOUT, rspamd_fuzzy_redis_timeout,
					session);
			event_base_set (session->ev_base, &session->timeout);
			double_to_tv (backend->timeout, &tv);
			event_add (&session->timeout, &tv);
		}
	}
}

void
rspamd_fuzzy_backend_update_redis (struct rspamd_fuzzy_backend *bk,
		GQueue *updates, const gchar *src,
		rspamd_fuzzy_update_cb cb, void *ud,
		void *subr_ud)
{
	struct rspamd_fuzzy_backend_redis *backend = subr_ud;
}

static void
rspamd_fuzzy_redis_count_callback (redisAsyncContext *c, gpointer r,
		gpointer priv)
{
	struct rspamd_fuzzy_redis_session *session = priv;
	redisReply *reply = r;
	gulong nelts;

	event_del (&session->timeout);

	if (c->err == 0) {
		rspamd_upstream_ok (session->up);

		if (reply->type == REDIS_REPLY_INTEGER) {
			if (session->callback.cb_count) {
				session->callback.cb_count (reply->integer, session->cbdata);
			}
		}
		else if (reply->type == REDIS_REPLY_STRING) {
			nelts = strtoul (reply->str, NULL, 10);

			if (session->callback.cb_count) {
				session->callback.cb_count (nelts, session->cbdata);
			}
		}
		else {
			if (session->callback.cb_count) {
				session->callback.cb_count (0, session->cbdata);
			}
		}
	}
	else {
		if (session->callback.cb_count) {
			session->callback.cb_count (0, session->cbdata);
		}
		rspamd_upstream_fail (session->up);
	}

	rspamd_fuzzy_redis_session_dtor (session);
}

void
rspamd_fuzzy_backend_count_redis (struct rspamd_fuzzy_backend *bk,
		rspamd_fuzzy_count_cb cb, void *ud,
		void *subr_ud)
{
	struct rspamd_fuzzy_backend_redis *backend = subr_ud;
	struct rspamd_fuzzy_redis_session *session;
	struct upstream *up;
	struct timeval tv;
	rspamd_inet_addr_t *addr;
	GString *key;

	g_assert (backend != NULL);

	session = g_slice_alloc0 (sizeof (*session));
	session->backend = backend;
	REF_RETAIN (session->backend);

	session->callback.cb_count = cb;
	session->cbdata = ud;
	session->command = RSPAMD_FUZZY_REDIS_COMMAND_COUNT;
	session->ev_base = rspamd_fuzzy_backend_event_base (bk);

	session->nargs = 2;
	session->argv = g_malloc (sizeof (gchar *) * 2);
	session->argv_lens = g_malloc (sizeof (gsize) * 2);
	key = g_string_new (backend->redis_object);
	g_string_append (key, "_count");
	session->argv[0] = g_strdup ("GET");
	session->argv_lens[0] = 3;
	session->argv[1] = key->str;
	session->argv_lens[1] = key->len;
	g_string_free (key, FALSE); /* Do not free underlying array */

	up = rspamd_upstream_get (backend->read_servers,
			RSPAMD_UPSTREAM_ROUND_ROBIN,
			NULL,
			0);

	session->up = up;
	addr = rspamd_upstream_addr (up);
	g_assert (addr != NULL);
	session->ctx = rspamd_redis_pool_connect (backend->pool,
			backend->dbname, backend->password,
			rspamd_inet_address_to_string (addr),
			rspamd_inet_address_get_port (addr));

	if (session->ctx == NULL) {
		rspamd_fuzzy_redis_session_dtor (session);

		if (cb) {
			cb (0, subr_ud);
		}
	}
	else {
		if (redisAsyncCommandArgv (session->ctx, rspamd_fuzzy_redis_count_callback,
				session, session->nargs,
				(const gchar **)session->argv, session->argv_lens) != REDIS_OK) {
			rspamd_fuzzy_redis_session_dtor (session);

			if (cb) {
				cb (0, subr_ud);
			}
		}
		else {
			/* Add timeout */
			event_set (&session->timeout, -1, EV_TIMEOUT, rspamd_fuzzy_redis_timeout,
					session);
			event_base_set (session->ev_base, &session->timeout);
			double_to_tv (backend->timeout, &tv);
			event_add (&session->timeout, &tv);
		}
	}
}

void
rspamd_fuzzy_backend_version_redis (struct rspamd_fuzzy_backend *bk,
		const gchar *src,
		rspamd_fuzzy_version_cb cb, void *ud,
		void *subr_ud)
{
	struct rspamd_fuzzy_backend_redis *backend = subr_ud;

	g_assert (backend != NULL);
}

const gchar*
rspamd_fuzzy_backend_id_redis (struct rspamd_fuzzy_backend *bk,
		void *subr_ud)
{
	struct rspamd_fuzzy_backend_redis *backend = subr_ud;
	g_assert (backend != NULL);

	return backend->id;
}

void
rspamd_fuzzy_backend_expire_redis (struct rspamd_fuzzy_backend *bk,
		void *subr_ud)
{
	struct rspamd_fuzzy_backend_redis *backend = subr_ud;

	g_assert (backend != NULL);
}

void
rspamd_fuzzy_backend_close_redis (struct rspamd_fuzzy_backend *bk,
		void *subr_ud)
{
	struct rspamd_fuzzy_backend_redis *backend = subr_ud;

	g_assert (backend != NULL);

	REF_RELEASE (backend);
}
