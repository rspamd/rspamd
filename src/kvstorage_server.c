/* Copyright (c) 2010, Vsevolod Stakhov
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
#include "kvstorage.h"
#include "kvstorage_config.h"
#include "kvstorage_server.h"
#include "cfg_file.h"
#include "cfg_xml.h"
#include "main.h"

#define ERROR_COMMON "ERROR" CRLF
#define ERROR_UNKNOWN_COMMAND "CLIENT_ERROR unknown command" CRLF
#define ERROR_NOT_STORED "NOT_STORED" CRLF
#define ERROR_EXISTS "EXISTS" CRLF
#define ERROR_NOT_FOUND "NOT_FOUND" CRLF
#define ERROR_INVALID_KEYSTORAGE "CLIENT_ERROR storage does not exists" CRLF

#define ERROR_REDIS_OK "+OK" CRLF


static sig_atomic_t wanna_die = 0;
static sig_atomic_t do_reopen_log = 0;
static sig_atomic_t soft_wanna_die = 0;

/* Logging functions */
#define thr_err(...)	do {																			\
	g_static_mutex_lock (thr->log_mtx);																\
	rspamd_common_log_function(rspamd_main->logger, G_LOG_LEVEL_CRITICAL, __FUNCTION__, __VA_ARGS__);	\
	g_static_mutex_unlock (thr->log_mtx);																\
} while (0)

#define thr_warn(...)	do {																			\
	g_static_mutex_lock (thr->log_mtx);																\
	rspamd_common_log_function(rspamd_main->logger, G_LOG_LEVEL_WARNING, __FUNCTION__, __VA_ARGS__);	\
	g_static_mutex_unlock (thr->log_mtx);																\
} while (0)

#define thr_info(...)	do {																			\
	g_static_mutex_lock (thr->log_mtx);																\
	rspamd_common_log_function(rspamd_main->logger, G_LOG_LEVEL_INFO, __FUNCTION__, __VA_ARGS__);	\
	g_static_mutex_unlock (thr->log_mtx);																\
} while (0)

#ifndef HAVE_SA_SIGINFO
static void
sig_handler (gint signo)
#else
static void
sig_handler (gint signo, siginfo_t *info, void *unused)
#endif
{
	switch (signo) {
	case SIGUSR1:
		do_reopen_log = 1;
		break;
	case SIGINT:
	case SIGTERM:
		wanna_die = 1;
		break;
	case SIGUSR2:
		soft_wanna_die = 1;
		break;
	}
}

gpointer
init_kvstorage_worker (void)
{
	struct kvstorage_worker_ctx         *ctx;

	ctx = g_malloc0 (sizeof (struct kvstorage_worker_ctx));
	ctx->pool = memory_pool_new (memory_pool_get_size ());

	/* Set default values */
	ctx->timeout_raw = 300000;

	register_worker_opt (TYPE_KVSTORAGE, "timeout", xml_handle_seconds, ctx,
					G_STRUCT_OFFSET (struct kvstorage_worker_ctx, timeout_raw));
	register_worker_opt (TYPE_KVSTORAGE, "redis", xml_handle_boolean, ctx,
						G_STRUCT_OFFSET (struct kvstorage_worker_ctx, is_redis));
	return ctx;
}

/* Make post-init configuration */
static gboolean
config_kvstorage_worker (struct rspamd_worker *worker)
{
	struct kvstorage_worker_ctx         *ctx = worker->ctx;

	/* Init timeval */
	msec_to_tv (ctx->timeout_raw, &ctx->io_timeout);

	return TRUE;
}

/*
 * Free kvstorage session
 */
static void
free_kvstorage_session (struct kvstorage_session *session)
{
	rspamd_remove_dispatcher (session->dispather);
	memory_pool_delete (session->pool);
	close (session->sock);
	g_slice_free1 (sizeof (struct kvstorage_session), session);
}

/*
 * Parse kvstorage command
 */
static gboolean
parse_kvstorage_command (struct kvstorage_session *session, gchar *c, guint len)
{
	if (len == 3) {
		/* Set or get command */
		if ((c[0] == 'g' || c[0] == 'G') &&
				(c[1] == 'e' || c[1] == 'E') &&
				(c[2] == 't' || c[2] == 'T')) {
			session->command = KVSTORAGE_CMD_GET;
		}
		else if ((c[0] == 's' || c[0] == 'S') &&
				(c[1] == 'e' || c[1] == 'E') &&
				(c[2] == 't' || c[2] == 'T')) {
			session->command = KVSTORAGE_CMD_SET;
		}
		else if ((c[0] == 'd' || c[0] == 'D') &&
				(c[1] == 'e' || c[1] == 'E') &&
				(c[2] == 'l' || c[2] == 'L')) {
			session->command = KVSTORAGE_CMD_DELETE;
		}
		else {
			/* Error */
			return FALSE;
		}
	}
	else if (len == 4) {
		if ((c[0] == 'i' || c[0] == 'I')     &&
				(c[1] == 'n' || c[1] == 'N') &&
				(c[2] == 'c' || c[2] == 'C') &&
				(c[3] == 'r' || c[3] == 'R')) {
			session->command = KVSTORAGE_CMD_INCR;
			session->arg_data.value = 1;
		}
		else if ((c[0] == 'd' || c[0] == 'D') &&
				(c[1] == 'e' || c[1] == 'E')  &&
				(c[2] == 'c' || c[2] == 'C')  &&
				(c[3] == 'r' || c[3] == 'R')) {
			session->command = KVSTORAGE_CMD_DECR;
			session->arg_data.value = -1;
		}
		else if (g_ascii_strncasecmp (c, "quit", 4) == 0) {
			session->command = KVSTORAGE_CMD_QUIT;
		}
		else if (g_ascii_strncasecmp (c, "sync", 4) == 0 || g_ascii_strncasecmp (c, "save", 4) == 0) {
			session->command = KVSTORAGE_CMD_SYNC;
		}
	}
	else if (len == 6) {
		if ((c[0] == 'i' || c[0] == 'I')     &&
				(c[1] == 'n' || c[1] == 'N') &&
				(c[2] == 'c' || c[2] == 'C') &&
				(c[3] == 'r' || c[3] == 'R') &&
				(c[4] == 'b' || c[4] == 'B') &&
				(c[5] == 'y' || c[5] == 'Y')) {
			session->command = KVSTORAGE_CMD_INCR;
			session->arg_data.value = 1;
		}
		else if ((c[0] == 'd' || c[0] == 'D') &&
				(c[1] == 'e' || c[1] == 'E')  &&
				(c[2] == 'c' || c[2] == 'C')  &&
				(c[3] == 'r' || c[3] == 'R')  &&
				(c[4] == 'b' || c[4] == 'B')  &&
				(c[5] == 'y' || c[5] == 'Y')) {
			session->command = KVSTORAGE_CMD_DECR;
			session->arg_data.value = -1;
		}
		else if ((c[0] == 'd' || c[0] == 'D') &&
				(c[1] == 'e' || c[1] == 'E')  &&
				(c[2] == 'l' || c[2] == 'L')  &&
				(c[3] == 'e' || c[3] == 'E')  &&
				(c[4] == 't' || c[4] == 'T')  &&
				(c[5] == 'e' || c[5] == 'E')) {
			session->command = KVSTORAGE_CMD_DELETE;
		}
		else if (g_ascii_strncasecmp (c, "select", 6) == 0) {
			session->command = KVSTORAGE_CMD_SELECT;
		}
		else {
			return FALSE;
		}
	}

	return TRUE;
}

/**
 * Parse kvstorage line
 */
static gboolean
parse_kvstorage_line (struct kvstorage_session *session, f_str_t *in)
{
	gchar								*p, *c, *end;
	gint								 state = 0, next_state;
	gboolean							 is_redis;

	p = in->begin;
	end = in->begin + in->len;
	c = p;
	is_redis = session->thr->ctx->is_redis;

	/* State machine for parsing */
	while (p <= end) {
		switch (state) {
		case 0:
			/* At this state we try to read identifier of storage */
			if (g_ascii_isdigit (*p)) {
				p ++;
			}
			else {
				if (g_ascii_isspace (*p) && p != c) {
					/* We have some digits, so parse id */
					session->id = strtoul (c, NULL, 10);
					state = 99;
					next_state = 1;
				}
				else if (c == p) {
					if (*p != '*') {
						/* We have some character, so assume id as 0 and parse command */
						session->id = 0;
						state = 1;
					}
					else {
						/* In fact it is redis number of commands */
						c = ++p;
						state = 7;
						session->id = 0;
					}
				}
				else {
					/* We have something wrong here (like some digits and then come non-digits) */
					return FALSE;
				}
			}
			break;
		case 1:
			/* At this state we parse command */
			if (g_ascii_isalpha (*p) && p != end) {
				p ++;
			}
			else {
				if (parse_kvstorage_command (session, c, p - c)) {
					switch (session->command) {

					case KVSTORAGE_CMD_QUIT:
					case KVSTORAGE_CMD_SYNC:
						/* Single argument command */
						state = 100;
						break;
					case KVSTORAGE_CMD_SELECT:
						/* Select command, read id next */
						state = 99;
						next_state = 6;
						break;
					default:
						/* Normal command, read key */
						state = 99;
						next_state = 2;
					}
				}
				else {
					/* Some error */
					return FALSE;
				}
			}
			break;
		case 2:
			/* Read and store key */
			if (!g_ascii_isspace (*p) && end != p) {
				p ++;
			}
			else {
				if (p == c) {
					return FALSE;
				}
				else {
					session->key = memory_pool_alloc (session->pool, p - c + 1);
					rspamd_strlcpy (session->key, c, p - c + 1);
					session->keylen = p - c;
					/* Now we must select next state based on command */
					if (session->command == KVSTORAGE_CMD_SET ||
							session->command == KVSTORAGE_CMD_INCR ||
							session->command == KVSTORAGE_CMD_DECR) {
						/* Read flags */
						state = 99;
						if (is_redis) {
							next_state = 5;
							session->flags = 0;
							session->expire = 0;
						}
						else {
							if (session->command == KVSTORAGE_CMD_SET) {
								next_state = 3;
							}
							else {
								next_state = 5;
							}
						}
					}
					else {
						/* Nothing to read for other commands */
						state = 100;
					}
				}
			}
			break;
		case 3:
			/* Read flags */
			if (g_ascii_isdigit (*p)) {
				p ++;
			}
			else {
				if (g_ascii_isspace (*p)) {
					session->flags = strtoul (c, NULL, 10);
					state = 99;
					if (session->command == KVSTORAGE_CMD_SET) {
						next_state = 4;
					}
					else {
						/* INCR and DECR */
						next_state = 5;
					}
				}
				else {
					return FALSE;
				}
			}
			break;
		case 4:
			/* Read exptime */
			if (g_ascii_isdigit (*p)) {
				p ++;
			}
			else {
				if (g_ascii_isspace (*p)) {
					session->expire = strtoul (c, NULL, 10);
					state = 99;
					next_state = 5;
				}
				else {
					return FALSE;
				}
			}
			break;
		case 5:
			/* Read size or incr/decr values */
			if (g_ascii_isdigit (*p)) {
				p ++;
			}
			else {
				if (g_ascii_isspace (*p) || p >= end - 1) {
					if (session->command == KVSTORAGE_CMD_SET) {
						session->arg_data.length = strtoul (c, NULL, 10);
					}
					else {
						if (p != c) {
							session->arg_data.value = strtoul (c, NULL, 10);
							if (session->command == KVSTORAGE_CMD_DECR) {
								session->arg_data.value = -session->arg_data.value;
							}
						}
						else if (session->command == KVSTORAGE_CMD_INCR) {
							session->arg_data.value = 1;
						}
						else {
							session->arg_data.value = -1;
						}
					}
					state = 100;
				}
				else {
					return FALSE;
				}
			}
			break;
		case 6:
			/* Read index of storage */
			if (g_ascii_isdigit (*p)) {
				p ++;
			}
			else {
				if (g_ascii_isspace (*p) || end == p) {
					session->id = strtoul (c, NULL, 10);
					state = 100;
				}
				else {
					return FALSE;
				}
			}
			break;
		case 7:
			/* Read arguments count */
			if (g_ascii_isdigit (*p)) {
				p ++;
			}
			else {
				if (g_ascii_isspace (*p) || end == p) {
					session->argc = strtoul (c, NULL, 10);
					session->argnum = 0;
					state = 100;
					/* Switch to arglen state */
					session->state = KVSTORAGE_STATE_READ_ARGLEN;
				}
				else {
					return FALSE;
				}
			}
			break;
		case 99:
			/* Skip spaces state */
			if (g_ascii_isspace (*p)) {
				p ++;
			}
			else {
				c = p;
				state = next_state;
			}
			break;
		case 100:
			/* Successful state */
			return TRUE;
			break;
		}
	}

	return state == 100;
}

/* Process normal kvstorage command */
static gboolean
kvstorage_process_command (struct kvstorage_session *session, gboolean is_redis)
{
	gint								 r;
	gchar								 outbuf[BUFSIZ], intbuf[sizeof ("9223372036854775807")];
	gboolean							 res;
	struct rspamd_kv_element			*elt;
	guint								 eltlen;
	glong								 longval;

	if (session->command == KVSTORAGE_CMD_SET) {
		session->state = KVSTORAGE_STATE_READ_DATA;
		rspamd_set_dispatcher_policy (session->dispather, BUFFER_CHARACTER, session->arg_data.length);
	}
	else if (session->command == KVSTORAGE_CMD_GET) {
		g_static_rw_lock_reader_lock (&session->cf->storage->rwlock);
		elt = rspamd_kv_storage_lookup (session->cf->storage, session->key, session->keylen, session->now);
		if (elt == NULL) {
			g_static_rw_lock_reader_unlock (&session->cf->storage->rwlock);
			if (!is_redis) {
				return rspamd_dispatcher_write (session->dispather, ERROR_NOT_FOUND,
						sizeof (ERROR_NOT_FOUND) - 1, FALSE, TRUE);
			}
			else {
				return rspamd_dispatcher_write (session->dispather, "$-1" CRLF,
						sizeof ("$-1" CRLF) - 1, FALSE, TRUE);
			}
		}
		else {
			session->elt = elt;
			if (elt->flags & KV_ELT_INTEGER) {
				eltlen = rspamd_snprintf (intbuf, sizeof (intbuf), "%l", ELT_LONG (elt));

			}
			else {
				eltlen = elt->size;
			}

			if (!is_redis) {
				r = rspamd_snprintf (outbuf, sizeof (outbuf), "VALUE %s %ud %ud" CRLF,
						ELT_KEY (elt), elt->flags, eltlen);
			}
			else {
				r = rspamd_snprintf (outbuf, sizeof (outbuf), "$%ud" CRLF,
						eltlen);
			}
			if (!rspamd_dispatcher_write (session->dispather, outbuf,
					r, TRUE, FALSE)) {
				g_static_rw_lock_reader_unlock (&session->cf->storage->rwlock);
				return FALSE;
			}
			if (elt->flags & KV_ELT_INTEGER) {
				if (!rspamd_dispatcher_write (session->dispather, intbuf, eltlen, TRUE, TRUE)) {
					g_static_rw_lock_reader_unlock (&session->cf->storage->rwlock);
					return FALSE;
				}
			}
			else {
				if (!rspamd_dispatcher_write (session->dispather, ELT_DATA(elt), eltlen, TRUE, TRUE)) {
					g_static_rw_lock_reader_unlock (&session->cf->storage->rwlock);
					return FALSE;
				}
			}
			if (!is_redis) {
				res = rspamd_dispatcher_write (session->dispather, CRLF "END" CRLF,
						sizeof (CRLF "END" CRLF) - 1, FALSE, TRUE);
			}
			else {
				res = rspamd_dispatcher_write (session->dispather, CRLF,
						sizeof (CRLF) - 1, FALSE, TRUE);
			}
			if (!res) {
				g_static_rw_lock_reader_unlock (&session->cf->storage->rwlock);
			}

			return res;
		}
	}
	else if (session->command == KVSTORAGE_CMD_DELETE) {
		g_static_rw_lock_writer_lock (&session->cf->storage->rwlock);
		elt = rspamd_kv_storage_delete (session->cf->storage, session->key, session->keylen);
		if (elt != NULL) {
			if ((elt->flags & KV_ELT_DIRTY) == 0) {
				/* Free memory if backend has deleted this element */
				g_slice_free1 (ELT_SIZE (elt), elt);
			}
			g_static_rw_lock_writer_unlock (&session->cf->storage->rwlock);
			if (!is_redis) {
				return rspamd_dispatcher_write (session->dispather, "DELETED" CRLF,
						sizeof ("DELETED" CRLF) - 1, FALSE, TRUE);
			}
			else {
				return rspamd_dispatcher_write (session->dispather, ":1" CRLF,
						sizeof (":1" CRLF) - 1, FALSE, TRUE);
			}
		}
		else {
			g_static_rw_lock_writer_unlock (&session->cf->storage->rwlock);
			if (!is_redis) {
				return rspamd_dispatcher_write (session->dispather, ERROR_NOT_FOUND,
						sizeof (ERROR_NOT_FOUND) - 1, FALSE, TRUE);
			}
			else {
				return rspamd_dispatcher_write (session->dispather, ":0" CRLF,
						sizeof (":0" CRLF) - 1, FALSE, TRUE);
			}
		}
	}
	else if (session->command == KVSTORAGE_CMD_INCR || session->command == KVSTORAGE_CMD_DECR) {
		g_static_rw_lock_writer_lock (&session->cf->storage->rwlock);
		longval = session->arg_data.value;
		if (!rspamd_kv_storage_increment (session->cf->storage, session->key, session->keylen, &longval)) {
			g_static_rw_lock_writer_unlock (&session->cf->storage->rwlock);
			if (!is_redis) {
				return rspamd_dispatcher_write (session->dispather, ERROR_NOT_FOUND,
						sizeof (ERROR_NOT_FOUND) - 1, FALSE, TRUE);
			}
			else {
				return rspamd_dispatcher_write (session->dispather, "-ERR not found" CRLF,
						sizeof ("-ERR not found" CRLF) - 1, FALSE, TRUE);
			}
		}
		else {
			g_static_rw_lock_writer_unlock (&session->cf->storage->rwlock);
			if (!is_redis) {
				r = rspamd_snprintf (outbuf, sizeof (outbuf), "%l" CRLF,
						longval);
			}
			else {
				r = rspamd_snprintf (outbuf, sizeof (outbuf), "$%l" CRLF,
						longval);
			}
			if (!rspamd_dispatcher_write (session->dispather, outbuf,
					r, FALSE, FALSE)) {
				return FALSE;
			}
		}
	}
	else if (session->command == KVSTORAGE_CMD_SYNC) {
		if (session->cf->storage->backend == NULL || session->cf->storage->backend->sync_func == NULL) {
			if (!is_redis) {
				return rspamd_dispatcher_write (session->dispather, ERROR_COMMON,
						sizeof (ERROR_COMMON) - 1, FALSE, TRUE);
			}
			else {
				return rspamd_dispatcher_write (session->dispather, "-ERR unsupported" CRLF,
						sizeof ("-ERR unsupported" CRLF) - 1, FALSE, TRUE);
			}
		}
		else {
			if (session->cf->storage->backend->sync_func (session->cf->storage->backend)) {
				if (!is_redis) {
					return rspamd_dispatcher_write (session->dispather, "SYNCED" CRLF,
							sizeof ("SYNCED" CRLF) - 1, FALSE, TRUE);
				}
				else {
					return rspamd_dispatcher_write (session->dispather, "+OK" CRLF,
							sizeof ("+OK" CRLF) - 1, FALSE, TRUE);
				}
			}
			else {
				if (!is_redis) {
					return rspamd_dispatcher_write (session->dispather, "NOT_SYNCED" CRLF,
							sizeof ("NOT_SYNCED" CRLF) - 1, FALSE, TRUE);
				}
				else {
					return rspamd_dispatcher_write (session->dispather, "-ERR not synced" CRLF,
							sizeof ("-ERR not synced" CRLF) - 1, FALSE, TRUE);
				}
			}
		}
		g_static_rw_lock_writer_lock (&session->cf->storage->rwlock);
	}
	else if (session->command == KVSTORAGE_CMD_SELECT) {
		if (!is_redis) {
			return rspamd_dispatcher_write (session->dispather, "SELECTED" CRLF,
					sizeof ("SELECTED" CRLF) - 1, FALSE, TRUE);
		}
		else {
			return rspamd_dispatcher_write (session->dispather, "+OK" CRLF,
					sizeof ("+OK" CRLF) - 1, FALSE, TRUE);
		}
	}
	else if (session->command == KVSTORAGE_CMD_QUIT) {
		/* Quit session */
		free_kvstorage_session (session);
		return FALSE;
	}

	return TRUE;
}

static gboolean
kvstorage_read_arglen (f_str_t *in, guint *len)
{
	gchar								*p = in->begin, *end = in->begin + in->len, *c;
	gint								 state = 0;

	while (p < end) {
		switch (state) {
		case 0:
			if (*p != '$') {
				return FALSE;
			}
			else {
				p ++;
				c = p;
				state = 1;
			}
			break;
		case 1:
			if (g_ascii_isdigit (*p) && p != end - 1) {
				p ++;
			}
			else {
				if (p != end - 1) {
					return FALSE;
				}
				else {
					*len = strtoul (c, NULL, 10);
					return TRUE;
				}
			}
			break;
		}
	}

	return TRUE;
}

/*
 * Check number of arguments for a command
 */
static gboolean
kvstorage_check_argnum (struct kvstorage_session *session)
{
	switch (session->command) {
	case KVSTORAGE_CMD_QUIT:
	case KVSTORAGE_CMD_SYNC:
		return session->argc == 1;
	case KVSTORAGE_CMD_SET:
		return session->argc == 3;
	case KVSTORAGE_CMD_INCR:
	case KVSTORAGE_CMD_DECR:
		return session->argc == 1 || session->argc == 2;
	default:
		return session->argc == 2;
	}

	/* Unreachable */
	return FALSE;
}

/**
 * Dispatcher callbacks
 */

/*
 * Callback that is called when there is data to read in buffer
 */
static gboolean
kvstorage_read_socket (f_str_t * in, void *arg)
{
	struct kvstorage_session			*session = (struct kvstorage_session *) arg;
	struct kvstorage_worker_thread		*thr;
	gint								 r;
	guint								 arglen;
	gchar								 outbuf[BUFSIZ];
	gboolean							 is_redis;

	if (in->len == 0) {
		/* Skip empty commands */
		return TRUE;
	}
	thr = session->thr;
	is_redis = thr->ctx->is_redis;

	switch (session->state) {
	case KVSTORAGE_STATE_READ_CMD:
		/* Update timestamp */
		session->now = time (NULL);
		if (! parse_kvstorage_line (session, in)) {
			thr_info ("%ud: unknown command: %V", thr->id, in);
			if (!is_redis) {
				return rspamd_dispatcher_write (session->dispather, ERROR_UNKNOWN_COMMAND,
						sizeof (ERROR_UNKNOWN_COMMAND) - 1, FALSE, TRUE);
			}
			else {
				r = rspamd_snprintf (outbuf, sizeof (outbuf), "-ERR unknown command '%V'" CRLF, in);
				return rspamd_dispatcher_write (session->dispather, outbuf,
								r, FALSE, TRUE);
			}
		}
		else {
			session->cf = get_kvstorage_config (session->id);
			if (session->cf == NULL) {
				thr_info ("%ud: bad keystorage: %ud", thr->id, session->id);
				if (!is_redis) {
					return rspamd_dispatcher_write (session->dispather, ERROR_INVALID_KEYSTORAGE,
						sizeof (ERROR_INVALID_KEYSTORAGE) - 1, FALSE, TRUE);
				}
				else {
					return rspamd_dispatcher_write (session->dispather, "-ERR unknown keystorage" CRLF,
						sizeof ("-ERR unknown keystorage" CRLF) - 1, FALSE, TRUE);
				}
			}
			if (session->state != KVSTORAGE_STATE_READ_ARGLEN) {
				return kvstorage_process_command (session, is_redis);
			}
		}
		break;
	case KVSTORAGE_STATE_READ_ARGLEN:
		if (! kvstorage_read_arglen (in, &arglen)) {
			session->state = KVSTORAGE_STATE_READ_CMD;
			r = rspamd_snprintf (outbuf, sizeof (outbuf), "-ERR unknown arglen '%V'" CRLF, in);
			return rspamd_dispatcher_write (session->dispather, outbuf,
					r, FALSE, TRUE);
		}
		else {
			session->state = KVSTORAGE_STATE_READ_ARG;
			rspamd_set_dispatcher_policy (session->dispather, BUFFER_CHARACTER, arglen);
		}
		break;
	case KVSTORAGE_STATE_READ_ARG:
		if (session->argnum == 0) {
			/* Read command */
			if (! parse_kvstorage_command (session, in->begin, in->len)) {
				session->state = KVSTORAGE_STATE_READ_CMD;
				r = rspamd_snprintf (outbuf, sizeof (outbuf), "-ERR unknown command '%V'" CRLF, in);
				return rspamd_dispatcher_write (session->dispather, outbuf,
						r, FALSE, TRUE);
			}
			else {
				if (! kvstorage_check_argnum (session)) {
					session->state = KVSTORAGE_STATE_READ_CMD;
					r = rspamd_snprintf (outbuf, sizeof (outbuf), "-ERR invalid argnum for command '%V': %ud" CRLF,
							in, session->argc);
					return rspamd_dispatcher_write (session->dispather, outbuf,
							r, FALSE, TRUE);
				}
				else {
					if (session->argnum == session->argc - 1) {
						session->state = KVSTORAGE_STATE_READ_CMD;
						rspamd_set_dispatcher_policy (session->dispather, BUFFER_LINE, -1);
						return kvstorage_process_command (session, TRUE);
					}
					else {
						session->argnum ++;
						session->state = KVSTORAGE_STATE_READ_ARGLEN;
						rspamd_set_dispatcher_policy (session->dispather, BUFFER_LINE, -1);
					}
				}
			}
		}
		else if (session->argnum == 1) {
			if (session->command != KVSTORAGE_CMD_SELECT) {
				/* This argument is a key for normal command */
				session->key = memory_pool_fstrdup (session->pool, in);
				session->keylen = in->len;
				if (session->argnum == session->argc - 1) {
					session->state = KVSTORAGE_STATE_READ_CMD;
					rspamd_set_dispatcher_policy (session->dispather, BUFFER_LINE, -1);
					return kvstorage_process_command (session, TRUE);
				}
				else {
					session->argnum ++;
					session->state = KVSTORAGE_STATE_READ_ARGLEN;
					rspamd_set_dispatcher_policy (session->dispather, BUFFER_LINE, -1);
				}
			}
			else {
				/* Special case for select command */
				session->state = KVSTORAGE_STATE_READ_CMD;
				rspamd_strlcpy (outbuf, in->begin, MIN (sizeof (outbuf), in->len));
				session->id = strtoul (outbuf, NULL, 10);
				rspamd_set_dispatcher_policy (session->dispather, BUFFER_LINE, -1);
				return kvstorage_process_command (session, TRUE);
			}
		}
		else if (session->argnum == 2) {
			/* We get datablock for set command */
			if (session->command == KVSTORAGE_CMD_SET) {
				session->state = KVSTORAGE_STATE_READ_CMD;
				rspamd_set_dispatcher_policy (session->dispather, BUFFER_LINE, -1);
				g_static_rw_lock_writer_lock (&session->cf->storage->rwlock);
				if (rspamd_kv_storage_insert (session->cf->storage, session->key, session->keylen,
						in->begin, in->len,
						session->flags, session->expire)) {
					g_static_rw_lock_writer_unlock (&session->cf->storage->rwlock);
					return rspamd_dispatcher_write (session->dispather, "+OK" CRLF,
							sizeof ("+OK" CRLF) - 1, FALSE, TRUE);
				}
				else {
					g_static_rw_lock_writer_unlock (&session->cf->storage->rwlock);
					return rspamd_dispatcher_write (session->dispather, "-ERR not stored" CRLF,
							sizeof ("-ERR not stored" CRLF) - 1, FALSE, TRUE);
				}
			}
			else {
				session->state = KVSTORAGE_STATE_READ_CMD;
				rspamd_strtol (in->begin, in->len, &session->arg_data.value);
				if (session->command == KVSTORAGE_CMD_DECR) {
					session->arg_data.value = -session->arg_data.value;
				}
				rspamd_set_dispatcher_policy (session->dispather, BUFFER_LINE, -1);
				return kvstorage_process_command (session, TRUE);
			}
		}
		break;
	case KVSTORAGE_STATE_READ_DATA:
		session->state = KVSTORAGE_STATE_READ_CMD;
		rspamd_set_dispatcher_policy (session->dispather, BUFFER_LINE, -1);
		g_static_rw_lock_writer_lock (&session->cf->storage->rwlock);
		if (rspamd_kv_storage_insert (session->cf->storage, session->key, session->keylen,
				in->begin, in->len,
				session->flags, session->expire)) {
			g_static_rw_lock_writer_unlock (&session->cf->storage->rwlock);
			if (!is_redis) {
				return rspamd_dispatcher_write (session->dispather, "STORED" CRLF,
						sizeof ("STORED" CRLF) - 1, FALSE, TRUE);
			}
			else {
				return rspamd_dispatcher_write (session->dispather, "+OK" CRLF,
						sizeof ("+OK" CRLF) - 1, FALSE, TRUE);
			}
		}
		else {
			g_static_rw_lock_writer_unlock (&session->cf->storage->rwlock);
			if (!is_redis) {
				return rspamd_dispatcher_write (session->dispather, ERROR_NOT_STORED,
						sizeof (ERROR_NOT_STORED) - 1, FALSE, TRUE);
			}
			else {
				return rspamd_dispatcher_write (session->dispather, "-ERR not stored" CRLF,
						sizeof ("-ERR not stored" CRLF) - 1, FALSE, TRUE);
			}
		}

		break;
	}

	return TRUE;
}

/*
 * Called if buffers were written
 */
static gboolean
kvstorage_write_socket (void *arg)
{
	struct kvstorage_session			*session = (struct kvstorage_session *) arg;

	if (session->elt) {
		g_static_rw_lock_reader_unlock (&session->cf->storage->rwlock);
		session->elt = NULL;
	}

	return TRUE;
}

/*
 * Called if something goes wrong
 */
static void
kvstorage_err_socket (GError * err, void *arg)
{
	struct kvstorage_session			*session = (struct kvstorage_session *) arg;
	struct kvstorage_worker_thread		*thr;

	thr = session->thr;
	if (err->code != -1) {
		thr_info ("%ud: abnormally closing connection from: %s, error: %s",
			thr->id, inet_ntoa (session->client_addr), err->message);
	}
	g_error_free (err);
	free_kvstorage_session (session);
}

/**
 * Accept function
 */
static void
thr_accept_socket (gint fd, short what, void *arg)
{
	struct kvstorage_worker_thread		*thr = (struct kvstorage_worker_thread *)arg;
	union sa_union                 		 su;
	socklen_t                       	 addrlen = sizeof (su.ss);
	gint                            	 nfd;
	struct kvstorage_session			*session;

	g_static_mutex_lock (thr->accept_mtx);
	if ((nfd = accept_from_socket (fd, (struct sockaddr *)&su.ss, &addrlen)) == -1) {
		thr_warn ("%ud: accept failed: %s", thr->id, strerror (errno));
		g_static_mutex_unlock (thr->accept_mtx);
		return;
	}
	g_static_mutex_unlock (thr->accept_mtx);
	/* Check for EAGAIN */
	if (nfd == 0) {
		return;
	}

	session = g_slice_alloc (sizeof (struct kvstorage_session));
	session->pool = memory_pool_new (memory_pool_get_size ());
	session->state = KVSTORAGE_STATE_READ_CMD;
	session->thr = thr;
	session->sock = nfd;
	session->dispather = rspamd_create_dispatcher (thr->ev_base, nfd, BUFFER_LINE,
			kvstorage_read_socket, kvstorage_write_socket,
			kvstorage_err_socket, thr->tv, session);
	session->elt = NULL;

	if (su.ss.ss_family == AF_UNIX) {
		session->client_addr.s_addr = INADDR_NONE;
	}
	else if (su.ss.ss_family == AF_INET) {
		memcpy (&session->client_addr, &su.s4.sin_addr,
						sizeof (struct in_addr));
	}
}

/**
 * Thread main worker function
 */
static gpointer
kvstorage_thread (gpointer ud)
{
	struct kvstorage_worker_thread		*thr = ud;

	/* Block signals as it is dispatcher deity */
	sigprocmask (SIG_BLOCK, thr->signals, NULL);
	/* Init thread specific events */
	thr->ev_base = event_init ();
	event_set (&thr->bind_ev, thr->worker->cf->listen_sock, EV_READ | EV_PERSIST, thr_accept_socket, (void *)thr);
	event_base_set (thr->ev_base, &thr->bind_ev);
	event_add (&thr->bind_ev, NULL);

	event_base_loop (thr->ev_base, 0);

	return NULL;
}

/**
 * Create new thread, set it detached
 */
static struct kvstorage_worker_thread *
create_kvstorage_thread (struct rspamd_worker *worker, struct kvstorage_worker_ctx *ctx, guint id, sigset_t *signals)
{
	struct kvstorage_worker_thread 		*new;
	GError								*err = NULL;

	new = memory_pool_alloc (ctx->pool, sizeof (struct kvstorage_worker_thread));
	new->ctx = ctx;
	new->worker = worker;
	new->tv = &ctx->io_timeout;
	new->log_mtx = &ctx->log_mtx;
	new->accept_mtx = &ctx->accept_mtx;
	new->id = id;
	new->thr = g_thread_create (kvstorage_thread, new, FALSE, &err);
	new->ev_base = NULL;
	new->signals = signals;

	if (new->thr == NULL) {
		msg_err ("cannot create thread: %s", err->message);
	}

	return new;
}

/*
 * Start worker process
 */
void
start_kvstorage_worker (struct rspamd_worker *worker)
{
	struct sigaction                	 signals;
	struct kvstorage_worker_ctx         *ctx = worker->ctx;
	guint								 i;
	struct kvstorage_worker_thread 		*thr;
	struct timeval						 tv;
	GList								*cur;

	gperf_profiler_init (worker->srv->cfg, "kvstorage");

	if (!g_thread_supported ()) {
		msg_err ("threads support is not supported on your system so kvstorage is not functionable");
		exit (EXIT_SUCCESS);
	}
	/* Create socketpair */
	if (make_socketpair (ctx->s_pair) == -1) {
		msg_err ("cannot create socketpair, exiting");
		exit (EXIT_SUCCESS);
	}
	worker->srv->pid = getpid ();
	ctx->threads = NULL;

	g_thread_init (NULL);
#if _EVENT_NUMERIC_VERSION > 0x02000000
	if (evthread_use_pthreads () == -1) {
		msg_err ("threads support is not supported in your libevent so kvstorage is not functionable");
		exit (EXIT_SUCCESS);
	}
#endif

	/* Set kvstorage options */
	if ( !config_kvstorage_worker (worker)) {
		msg_err ("cannot configure kvstorage worker, exiting");
		exit (EXIT_SUCCESS);
	}

	init_signals (&signals, sig_handler);
	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);

	/* Set umask */
	umask (S_IWGRP | S_IWOTH | S_IROTH | S_IRGRP);

	/* Start workers threads */
	g_static_mutex_init (&ctx->log_mtx);
	g_static_mutex_init (&ctx->accept_mtx);
	for (i = 0; i < worker->cf->count; i ++) {
		thr = create_kvstorage_thread (worker, ctx, i, &signals.sa_mask);
		ctx->threads = g_list_prepend (ctx->threads, thr);
	}

	sigprocmask (SIG_BLOCK, &signals.sa_mask, NULL);
	/* Signal processing cycle */
	for (;;) {
		msg_debug ("calling sigsuspend");
		sigemptyset (&signals.sa_mask);
		sigsuspend (&signals.sa_mask);
		if (wanna_die == 1) {
			wanna_die = 0;
			tv.tv_sec = 0;
			tv.tv_usec = 0;
			msg_info ("worker's immediately shutdown is requested");
			cur = ctx->threads;
			while (cur) {
				thr = cur->data;
				if (thr->ev_base != NULL) {
					event_del (&thr->bind_ev);
					event_base_loopexit (thr->ev_base, &tv);
				}
				cur = g_list_next (cur);
			}
			break;
		}
		else if (soft_wanna_die == 1) {
			soft_wanna_die = 0;
			tv.tv_sec = SOFT_SHUTDOWN_TIME;
			tv.tv_usec = 0;
			msg_info ("worker's shutdown is pending in %d sec", SOFT_SHUTDOWN_TIME);
			cur = ctx->threads;
			while (cur) {
				thr = cur->data;
				if (thr->ev_base != NULL) {
					event_del (&thr->bind_ev);
					event_base_loopexit (thr->ev_base, &tv);
				}
				cur = g_list_next (cur);
			}
			break;
		}
		else if (do_reopen_log == 1) {
			do_reopen_log = 0;
			reopen_log (rspamd_main->logger);
		}
	}

	msg_info ("syncing storages");
	destroy_kvstorage_config ();
	close_log (rspamd_main->logger);
	exit (EXIT_SUCCESS);
}
