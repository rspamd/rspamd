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
#include "task.h"
#include "rspamd.h"
#include "filter.h"
#include "protocol.h"
#include "message.h"
#include "lua/lua_common.h"
#include "email_addr.h"
#include "composites.h"
#include "stat_api.h"
#include "unix-std.h"
#include "utlist.h"
#include "contrib/zstd/zstd.h"
#include "libserver/mempool_vars_internal.h"
#include "libmime/lang_detection.h"
#include <math.h>

/*
 * Do not print more than this amount of elts
 */
static const int max_log_elts = 7;

static GQuark
rspamd_task_quark (void)
{
	return g_quark_from_static_string ("task-error");
}

static void
rspamd_request_header_dtor (gpointer p)
{
	GPtrArray *ar = p;
	guint i;
	rspamd_ftok_t *tok;

	if (ar) {
		for (i = 0; i < ar->len; i ++) {
			tok = g_ptr_array_index (ar, i);
			rspamd_fstring_mapped_ftok_free (tok);
		}

		g_ptr_array_free (ar, TRUE);
	}
}

/*
 * Create new task
 */
struct rspamd_task *
rspamd_task_new (struct rspamd_worker *worker, struct rspamd_config *cfg,
				 rspamd_mempool_t *pool,
				 struct rspamd_lang_detector *lang_det,
				 struct event_base *ev_base)
{
	struct rspamd_task *new_task;

	new_task = g_malloc0 (sizeof (struct rspamd_task));
	new_task->worker = worker;
	new_task->lang_det = lang_det;

	if (cfg) {
		new_task->cfg = cfg;
		REF_RETAIN (cfg);

		if (cfg->check_all_filters) {
			new_task->flags |= RSPAMD_TASK_FLAG_PASS_ALL;
		}


		if (cfg->re_cache) {
			new_task->re_rt = rspamd_re_cache_runtime_new (cfg->re_cache);
		}

		if (new_task->lang_det == NULL && cfg->lang_det != NULL) {
			new_task->lang_det = cfg->lang_det;
		}
	}

	new_task->ev_base = ev_base;

#ifdef HAVE_EVENT_NO_CACHE_TIME_FUNC
	if (ev_base) {
		event_base_update_cache_time (ev_base);
		event_base_gettimeofday_cached (ev_base, &new_task->tv);
		new_task->time_real = tv_to_double (&new_task->tv);
	}
	else {
		gettimeofday (&new_task->tv, NULL);
		new_task->time_real = tv_to_double (&new_task->tv);
	}
#else
	gettimeofday (&new_task->tv, NULL);
	new_task->time_real = tv_to_double (&new_task->tv);
#endif

	new_task->time_virtual = rspamd_get_virtual_ticks ();
	new_task->time_real_finish = NAN;
	new_task->time_virtual_finish = NAN;

	if (pool == NULL) {
		new_task->task_pool =
				rspamd_mempool_new (rspamd_mempool_suggest_size (), "task");
		new_task->flags |= RSPAMD_TASK_FLAG_OWN_POOL;
	}
	else {
		new_task->task_pool = pool;
	}

	new_task->raw_headers = g_hash_table_new_full (rspamd_strcase_hash,
			rspamd_strcase_equal, NULL, rspamd_ptr_array_free_hard);
	new_task->headers_order = g_queue_new ();
	new_task->request_headers = g_hash_table_new_full (rspamd_ftok_icase_hash,
			rspamd_ftok_icase_equal, rspamd_fstring_mapped_ftok_free,
			rspamd_request_header_dtor);
	rspamd_mempool_add_destructor (new_task->task_pool,
		(rspamd_mempool_destruct_t) g_hash_table_unref,
		new_task->request_headers);
	new_task->reply_headers = g_hash_table_new_full (rspamd_ftok_icase_hash,
			rspamd_ftok_icase_equal, rspamd_fstring_mapped_ftok_free,
			rspamd_fstring_mapped_ftok_free);
	rspamd_mempool_add_destructor (new_task->task_pool,
			(rspamd_mempool_destruct_t) g_hash_table_unref,
			new_task->reply_headers);
	rspamd_mempool_add_destructor (new_task->task_pool,
			(rspamd_mempool_destruct_t) g_hash_table_unref,
			new_task->raw_headers);
	rspamd_mempool_add_destructor (new_task->task_pool,
			(rspamd_mempool_destruct_t) g_queue_free,
			new_task->headers_order);
	new_task->emails = g_hash_table_new (rspamd_email_hash, rspamd_emails_cmp);
	rspamd_mempool_add_destructor (new_task->task_pool,
			(rspamd_mempool_destruct_t) g_hash_table_unref,
			new_task->emails);
	new_task->urls = g_hash_table_new (rspamd_url_hash, rspamd_urls_cmp);
	rspamd_mempool_add_destructor (new_task->task_pool,
			(rspamd_mempool_destruct_t) g_hash_table_unref,
			new_task->urls);
	new_task->parts = g_ptr_array_sized_new (4);
	rspamd_mempool_add_destructor (new_task->task_pool,
			rspamd_ptr_array_free_hard, new_task->parts);
	new_task->text_parts = g_ptr_array_sized_new (2);
	rspamd_mempool_add_destructor (new_task->task_pool,
			rspamd_ptr_array_free_hard, new_task->text_parts);
	new_task->received = g_ptr_array_sized_new (8);
	rspamd_mempool_add_destructor (new_task->task_pool,
			rspamd_ptr_array_free_hard, new_task->received);

	new_task->sock = -1;
	new_task->flags |= (RSPAMD_TASK_FLAG_MIME|RSPAMD_TASK_FLAG_JSON);
	new_task->result = rspamd_create_metric_result (new_task);

	new_task->message_id = new_task->queue_id = "undef";
	new_task->messages = ucl_object_typed_new (UCL_OBJECT);
	new_task->lua_cache = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);

	return new_task;
}


static void
rspamd_task_reply (struct rspamd_task *task)
{
	if (task->fin_callback) {
		task->fin_callback (task, task->fin_arg);
	}
	else {
		rspamd_protocol_write_reply (task);
	}
}

/*
 * Called if all filters are processed
 * @return TRUE if session should be terminated
 */
gboolean
rspamd_task_fin (void *arg)
{
	struct rspamd_task *task = (struct rspamd_task *) arg;

	/* Task is already finished or skipped */
	if (RSPAMD_TASK_IS_PROCESSED (task)) {
		rspamd_task_reply (task);
		return TRUE;
	}

	if (!rspamd_task_process (task, RSPAMD_TASK_PROCESS_ALL)) {
		rspamd_task_reply (task);
		return TRUE;
	}

	if (RSPAMD_TASK_IS_PROCESSED (task)) {
		rspamd_task_reply (task);
		return TRUE;
	}

	/* One more iteration */
	return FALSE;
}

/*
 * Called if session was restored inside fin callback
 */
void
rspamd_task_restore (void *arg)
{
	/* XXX: not needed now ? */
}

/*
 * Free all structures of worker_task
 */
void
rspamd_task_free (struct rspamd_task *task)
{
	struct rspamd_mime_part *p;
	struct rspamd_mime_text_part *tp;
	struct rspamd_email_address *addr;
	struct rspamd_lua_cached_entry *entry;
	GHashTableIter it;
	gpointer k, v;
	guint i;

	if (task) {
		debug_task ("free pointer %p", task);

		for (i = 0; i < task->parts->len; i ++) {
			p = g_ptr_array_index (task->parts, i);

			if (p->raw_headers) {
				g_hash_table_unref (p->raw_headers);
			}

			if (p->headers_order) {
				g_queue_free (p->headers_order);
			}

			if (IS_CT_MULTIPART (p->ct)) {
				if (p->specific.mp->children) {
					g_ptr_array_free (p->specific.mp->children, TRUE);
				}
			}
		}

		for (i = 0; i < task->text_parts->len; i ++) {
			tp = g_ptr_array_index (task->text_parts, i);

			if (tp->utf_words) {
				g_array_free (tp->utf_words, TRUE);
			}
			if (tp->normalized_hashes) {
				g_array_free (tp->normalized_hashes, TRUE);
			}
			if (tp->languages) {
				g_ptr_array_unref (tp->languages);
			}
		}

		if (task->rcpt_envelope) {
			for (i = 0; i < task->rcpt_envelope->len; i ++) {
				addr = g_ptr_array_index (task->rcpt_envelope, i);
				rspamd_email_address_free (addr);
			}

			g_ptr_array_free (task->rcpt_envelope, TRUE);
		}

		if (task->from_envelope) {
			rspamd_email_address_free (task->from_envelope);
		}

		if (task->meta_words) {
			g_array_free (task->meta_words, TRUE);
		}

		ucl_object_unref (task->messages);

		if (task->re_rt) {
			rspamd_re_cache_runtime_destroy (task->re_rt);
		}

		if (task->http_conn != NULL) {
			rspamd_http_connection_reset (task->http_conn);
			rspamd_http_connection_unref (task->http_conn);
		}

		if (task->settings != NULL) {
			ucl_object_unref (task->settings);
		}

		if (task->client_addr) {
			rspamd_inet_address_free (task->client_addr);
		}

		if (task->from_addr) {
			rspamd_inet_address_free (task->from_addr);
		}

		if (task->err) {
			g_error_free (task->err);
		}

		if (rspamd_event_pending (&task->timeout_ev, EV_TIMEOUT)) {
			event_del (&task->timeout_ev);
		}

		if (task->guard_ev) {
			event_del (task->guard_ev);
		}

		if (task->sock != -1) {
			close (task->sock);
		}

		if (task->cfg) {
			if (task->lua_cache) {
				g_hash_table_iter_init (&it, task->lua_cache);

				while (g_hash_table_iter_next (&it, &k, &v)) {
					entry = (struct rspamd_lua_cached_entry *)v;
					luaL_unref (task->cfg->lua_state,
							LUA_REGISTRYINDEX, entry->ref);
				}

				g_hash_table_unref (task->lua_cache);
			}

			REF_RELEASE (task->cfg);
		}

		if (task->flags & RSPAMD_TASK_FLAG_OWN_POOL) {
			rspamd_mempool_delete (task->task_pool);
		}

		g_free (task);
	}
}

struct rspamd_task_map {
	gpointer begin;
	gulong len;
};

static void
rspamd_task_unmapper (gpointer ud)
{
	struct rspamd_task_map *m = ud;

	munmap (m->begin, m->len);
}

gboolean
rspamd_task_load_message (struct rspamd_task *task,
	struct rspamd_http_message *msg, const gchar *start, gsize len)
{
	guint control_len, r;
	struct ucl_parser *parser;
	ucl_object_t *control_obj;
	gchar filepath[PATH_MAX], *fp;
	gint fd, flen;
	gulong offset = 0, shmem_size = 0;
	rspamd_ftok_t *tok;
	gpointer map;
	struct stat st;
	struct rspamd_task_map *m;
	const gchar *ft;

#ifdef HAVE_SANE_SHMEM
	ft = "shm";
#else
	ft = "file";
#endif

	if (msg) {
		rspamd_protocol_handle_headers (task, msg);
	}

	tok = rspamd_task_get_request_header (task, "shm");

	if (tok) {
		/* Shared memory part */
		r = rspamd_strlcpy (filepath, tok->begin,
				MIN (sizeof (filepath), tok->len + 1));

		rspamd_url_decode (filepath, filepath, r + 1);
		flen = strlen (filepath);

		if (filepath[0] == '"' && flen > 2) {
			/* We need to unquote filepath */
			fp = &filepath[1];
			fp[flen - 2] = '\0';
		}
		else {
			fp = &filepath[0];
		}
#ifdef HAVE_SANE_SHMEM
		fd = shm_open (fp, O_RDONLY, 00600);
#else
		fd = open (fp, O_RDONLY, 00600);
#endif
		if (fd == -1) {
			g_set_error (&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"Cannot open %s segment (%s): %s", ft, fp, strerror (errno));
			return FALSE;
		}

		if (fstat (fd, &st) == -1) {
			g_set_error (&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"Cannot stat %s segment (%s): %s", ft, fp, strerror (errno));
			close (fd);

			return FALSE;
		}

		map = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);

		if (map == MAP_FAILED) {
			close (fd);
			g_set_error (&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"Cannot mmap %s (%s): %s", ft, fp, strerror (errno));
			return FALSE;
		}

		close (fd);

		tok = rspamd_task_get_request_header (task, "shm-offset");

		if (tok) {
			rspamd_strtoul (tok->begin, tok->len, &offset);

			if (offset > (gulong)st.st_size) {
				msg_err_task ("invalid offset %ul (%ul available) for shm "
						"segment %s", offset, st.st_size, fp);
				munmap (map, st.st_size);

				return FALSE;
			}
		}

		tok = rspamd_task_get_request_header (task, "shm-length");
		shmem_size = st.st_size;


		if (tok) {
			rspamd_strtoul (tok->begin, tok->len, &shmem_size);

			if (shmem_size > (gulong)st.st_size) {
				msg_err_task ("invalid length %ul (%ul available) for %s "
						"segment %s", shmem_size, st.st_size, ft, fp);
				munmap (map, st.st_size);

				return FALSE;
			}
		}

		task->msg.begin = ((guchar *)map) + offset;
		task->msg.len = shmem_size;
		m = rspamd_mempool_alloc (task->task_pool, sizeof (*m));
		m->begin = map;
		m->len = st.st_size;

		msg_info_task ("loaded message from shared memory %s (%ul size, %ul offset)",
				fp, shmem_size, offset);

		rspamd_mempool_add_destructor (task->task_pool, rspamd_task_unmapper, m);

		return TRUE;
	}

	tok = rspamd_task_get_request_header (task, "file");

	if (tok == NULL) {
		tok = rspamd_task_get_request_header (task, "path");
	}

	if (tok) {
		debug_task ("want to scan file %T", tok);

		r = rspamd_strlcpy (filepath, tok->begin,
				MIN (sizeof (filepath), tok->len + 1));

		rspamd_url_decode (filepath, filepath, r + 1);
		flen = strlen (filepath);

		if (filepath[0] == '"' && flen > 2) {
			/* We need to unquote filepath */
			fp = &filepath[1];
			fp[flen - 2] = '\0';
		}
		else {
			fp = &filepath[0];
		}

		if (stat (fp, &st) == -1) {
			g_set_error (&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"Invalid file (%s): %s", fp, strerror (errno));
			return FALSE;
		}

		if (G_UNLIKELY (st.st_size == 0)) {
			/* Empty file */
			task->flags |= RSPAMD_TASK_FLAG_EMPTY;
			task->msg.begin = rspamd_mempool_strdup (task->task_pool, "");
			task->msg.len = 0;
		}
		else {
			fd = open (fp, O_RDONLY);

			if (fd == -1) {
				g_set_error (&task->err, rspamd_task_quark (),
						RSPAMD_PROTOCOL_ERROR,
						"Cannot open file (%s): %s", fp, strerror (errno));
				return FALSE;
			}

			map = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);


			if (map == MAP_FAILED) {
				close (fd);
				g_set_error (&task->err, rspamd_task_quark (),
						RSPAMD_PROTOCOL_ERROR,
						"Cannot mmap file (%s): %s", fp, strerror (errno));
				return FALSE;
			}

			close (fd);
			task->msg.begin = map;
			task->msg.len = st.st_size;
			m = rspamd_mempool_alloc (task->task_pool, sizeof (*m));
			m->begin = map;
			m->len = st.st_size;

			rspamd_mempool_add_destructor (task->task_pool, rspamd_task_unmapper, m);
		}

		task->msg.fpath = rspamd_mempool_strdup (task->task_pool, fp);
		task->flags |= RSPAMD_TASK_FLAG_FILE;

		msg_info_task ("loaded message from file %s", fp);

		return TRUE;
	}

	/* Plain data */
	debug_task ("got input of length %z", task->msg.len);

	/* Check compression */
	tok = rspamd_task_get_request_header (task, "compression");

	if (tok) {
		/* Need to uncompress */
		rspamd_ftok_t t;

		t.begin = "zstd";
		t.len = 4;

		if (rspamd_ftok_casecmp (tok, &t) == 0) {
			ZSTD_DStream *zstream;
			ZSTD_inBuffer zin;
			ZSTD_outBuffer zout;
			guchar *out;
			gsize outlen, r;
			gulong dict_id;

			if (!rspamd_libs_reset_decompression (task->cfg->libs_ctx)) {
				g_set_error (&task->err, rspamd_task_quark(),
						RSPAMD_PROTOCOL_ERROR,
						"Cannot decompress, decompressor init failed");

				return FALSE;
			}

			tok = rspamd_task_get_request_header (task, "dictionary");

			if (tok != NULL) {
				/* We need to use custom dictionary */
				if (!rspamd_strtoul (tok->begin, tok->len, &dict_id)) {
					g_set_error (&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
							"Non numeric dictionary");

					return FALSE;
				}

				if (!task->cfg->libs_ctx->in_dict) {
					g_set_error (&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
							"Unknown dictionary, undefined locally");

					return FALSE;
				}

				if (task->cfg->libs_ctx->in_dict->id != dict_id) {
					g_set_error (&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
							"Unknown dictionary, invalid dictionary id");

					return FALSE;
				}
			}

			zstream = task->cfg->libs_ctx->in_zstream;

			zin.pos = 0;
			zin.src = start;
			zin.size = len;

			if ((outlen = ZSTD_getDecompressedSize (start, len)) == 0) {
				outlen = ZSTD_DStreamOutSize ();
			}

			out = g_malloc (outlen);
			zout.dst = out;
			zout.pos = 0;
			zout.size = outlen;

			while (zin.pos < zin.size) {
				r = ZSTD_decompressStream (zstream, &zout, &zin);

				if (ZSTD_isError (r)) {
					g_set_error (&task->err, rspamd_task_quark(),
							RSPAMD_PROTOCOL_ERROR,
							"Decompression error: %s", ZSTD_getErrorName (r));

					return FALSE;
				}

				if (zout.pos == zout.size) {
					/* We need to extend output buffer */
					zout.size = zout.size * 1.5 + 1.0;
					zout.dst = g_realloc (zout.dst, zout.size);
				}
			}

			rspamd_mempool_add_destructor (task->task_pool, g_free, zout.dst);
			task->msg.begin = zout.dst;
			task->msg.len = zout.pos;
			task->flags |= RSPAMD_TASK_FLAG_COMPRESSED;

			msg_info_task ("loaded message from zstd compressed stream; "
					"compressed: %ul; uncompressed: %ul",
					(gulong)zin.size, (gulong)zout.pos);

		}
		else {
			g_set_error (&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"Invalid compression method");
			return FALSE;
		}
	}
	else {
		task->msg.begin = start;
		task->msg.len = len;
	}

	if (task->msg.len == 0) {
		task->flags |= RSPAMD_TASK_FLAG_EMPTY;
	}

	if (task->flags & RSPAMD_TASK_FLAG_HAS_CONTROL) {
		/* We have control chunk, so we need to process it separately */
		if (task->msg.len < task->message_len) {
			msg_warn_task ("message has invalid message length: %ul and total len: %ul",
					task->message_len, task->msg.len);
			g_set_error (&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"Invalid length");
			return FALSE;
		}
		control_len = task->msg.len - task->message_len;

		if (control_len > 0) {
			parser = ucl_parser_new (UCL_PARSER_KEY_LOWERCASE);

			if (!ucl_parser_add_chunk (parser, task->msg.begin, control_len)) {
				msg_warn_task ("processing of control chunk failed: %s",
						ucl_parser_get_error (parser));
				ucl_parser_free (parser);
			}
			else {
				control_obj = ucl_parser_get_object (parser);
				ucl_parser_free (parser);
				rspamd_protocol_handle_control (task, control_obj);
				ucl_object_unref (control_obj);
			}

			task->msg.begin += control_len;
			task->msg.len -= control_len;
		}
	}

	return TRUE;
}

static gint
rspamd_task_select_processing_stage (struct rspamd_task *task, guint stages)
{
	gint st, mask;

	mask = task->processed_stages;

	if (mask == 0) {
		st = 0;
	}
	else {
		for (st = 1; mask != 1; st ++) {
			mask = (unsigned int)mask >> 1;
		}
	}

	st = 1 << st;

	if (stages & st) {
		return st;
	}
	else if (st < RSPAMD_TASK_STAGE_DONE) {
		/* We assume that the stage that was not requested is done */
		task->processed_stages |= st;
		return rspamd_task_select_processing_stage (task, stages);
	}

	/* We are done */
	return RSPAMD_TASK_STAGE_DONE;
}

gboolean
rspamd_task_process (struct rspamd_task *task, guint stages)
{
	gint st;
	gboolean ret = TRUE;
	GError *stat_error = NULL;

	/* Avoid nested calls */
	if (task->flags & RSPAMD_TASK_FLAG_PROCESSING) {
		return TRUE;
	}

	if (RSPAMD_TASK_IS_PROCESSED (task)) {
		return TRUE;
	}

	task->flags |= RSPAMD_TASK_FLAG_PROCESSING;

	st = rspamd_task_select_processing_stage (task, stages);

	switch (st) {
	case RSPAMD_TASK_STAGE_READ_MESSAGE:
		if (!rspamd_message_parse (task)) {
			ret = FALSE;
		}
		break;

	case RSPAMD_TASK_STAGE_PRE_FILTERS:
		rspamd_symcache_process_symbols (task, task->cfg->cache,
				RSPAMD_TASK_STAGE_PRE_FILTERS);
		break;

	case RSPAMD_TASK_STAGE_PROCESS_MESSAGE:
		if (!(task->flags & RSPAMD_TASK_FLAG_SKIP_PROCESS)) {
			rspamd_message_process (task);
		}
		break;

	case RSPAMD_TASK_STAGE_FILTERS:
		rspamd_symcache_process_symbols (task, task->cfg->cache,
				RSPAMD_TASK_STAGE_FILTERS);
		break;

	case RSPAMD_TASK_STAGE_CLASSIFIERS:
	case RSPAMD_TASK_STAGE_CLASSIFIERS_PRE:
	case RSPAMD_TASK_STAGE_CLASSIFIERS_POST:
		if (!RSPAMD_TASK_IS_EMPTY (task)) {
			if (rspamd_stat_classify (task, task->cfg->lua_state, st, &stat_error) ==
					RSPAMD_STAT_PROCESS_ERROR) {
				msg_err_task ("classify error: %e", stat_error);
				g_error_free (stat_error);
			}
		}
		break;

	case RSPAMD_TASK_STAGE_COMPOSITES:
		rspamd_make_composites (task);
		break;

	case RSPAMD_TASK_STAGE_POST_FILTERS:
		rspamd_symcache_process_symbols (task, task->cfg->cache,
				RSPAMD_TASK_STAGE_POST_FILTERS);

		if ((task->flags & RSPAMD_TASK_FLAG_LEARN_AUTO) &&
				!RSPAMD_TASK_IS_EMPTY (task) &&
				!(task->flags & (RSPAMD_TASK_FLAG_LEARN_SPAM|RSPAMD_TASK_FLAG_LEARN_HAM))) {
			rspamd_stat_check_autolearn (task);
		}
		break;

	case RSPAMD_TASK_STAGE_LEARN:
	case RSPAMD_TASK_STAGE_LEARN_PRE:
	case RSPAMD_TASK_STAGE_LEARN_POST:
		if (task->flags & (RSPAMD_TASK_FLAG_LEARN_SPAM|RSPAMD_TASK_FLAG_LEARN_HAM)) {
			if (task->err == NULL) {
				if (!rspamd_stat_learn (task,
						task->flags & RSPAMD_TASK_FLAG_LEARN_SPAM,
						task->cfg->lua_state, task->classifier,
						st, &stat_error)) {

					if (stat_error == NULL) {
						g_set_error (&stat_error,
								g_quark_from_static_string ("stat"), 500,
								"Unknown statistics error");
					}

					msg_err_task ("learn error: %e", stat_error);

					if (!(task->flags & RSPAMD_TASK_FLAG_LEARN_AUTO)) {
						task->err = stat_error;
						task->processed_stages |= RSPAMD_TASK_STAGE_DONE;
					}
					else {
						/* Do not skip idempotent in case of learn error */
						if (stat_error) {
							g_error_free (stat_error);
						}

						task->processed_stages |= RSPAMD_TASK_STAGE_LEARN|
								RSPAMD_TASK_STAGE_LEARN_PRE|
								RSPAMD_TASK_STAGE_LEARN_POST;
					}
				}
			}
		}
		break;
	case RSPAMD_TASK_STAGE_COMPOSITES_POST:
		/* Second run of composites processing before idempotent filters */
		rspamd_make_composites (task);
		break;
	case RSPAMD_TASK_STAGE_IDEMPOTENT:
		rspamd_symcache_process_symbols (task, task->cfg->cache,
				RSPAMD_TASK_STAGE_IDEMPOTENT);
		break;

	case RSPAMD_TASK_STAGE_DONE:
		task->processed_stages |= RSPAMD_TASK_STAGE_DONE;
		break;

	default:
		/* TODO: not implemented stage */
		break;
	}

	if (RSPAMD_TASK_IS_SKIPPED (task)) {
		/* Set all bits except idempotent filters */
		task->processed_stages |= 0x7FFF;
	}

	task->flags &= ~RSPAMD_TASK_FLAG_PROCESSING;

	if (!ret || RSPAMD_TASK_IS_PROCESSED (task)) {
		if (!ret) {
			/* Set processed flags */
			task->processed_stages |= RSPAMD_TASK_STAGE_DONE;
		}

		msg_debug_task ("task is processed");

		return ret;
	}

	if (rspamd_session_events_pending (task->s) != 0) {
		/* We have events pending, so we consider this stage as incomplete */
		msg_debug_task ("need more work on stage %d", st);
	}
	else {
		/* Mark the current stage as done and go to the next stage */
		msg_debug_task ("completed stage %d", st);
		task->processed_stages |= st;

		/* Tail recursion */
		return rspamd_task_process (task, stages);
	}

	return ret;
}

struct rspamd_email_address*
rspamd_task_get_sender (struct rspamd_task *task)
{
	return task->from_envelope;
}

static const gchar *
rspamd_task_cache_principal_recipient (struct rspamd_task *task,
		const gchar *rcpt, gsize len)
{
	gchar *rcpt_lc;

	if (rcpt == NULL) {
		return NULL;
	}

	rcpt_lc = rspamd_mempool_alloc (task->task_pool, len + 1);
	rspamd_strlcpy (rcpt_lc, rcpt, len + 1);
	rspamd_str_lc (rcpt_lc, len);

	rspamd_mempool_set_variable (task->task_pool,
			RSPAMD_MEMPOOL_PRINCIPAL_RECIPIENT, rcpt_lc, NULL);

	return rcpt_lc;
}

const gchar *
rspamd_task_get_principal_recipient (struct rspamd_task *task)
{
	const gchar *val;
	struct rspamd_email_address *addr;

	val = rspamd_mempool_get_variable (task->task_pool,
			RSPAMD_MEMPOOL_PRINCIPAL_RECIPIENT);

	if (val) {
		return val;
	}

	if (task->deliver_to) {
		return rspamd_task_cache_principal_recipient (task, task->deliver_to,
				strlen (task->deliver_to));
	}
	if (task->rcpt_envelope != NULL) {
		addr = g_ptr_array_index (task->rcpt_envelope, 0);

		if (addr->addr) {
			return rspamd_task_cache_principal_recipient (task, addr->addr,
					addr->addr_len);
		}
	}

	if (task->rcpt_mime != NULL && task->rcpt_mime->len > 0) {
		addr = g_ptr_array_index (task->rcpt_mime, 0);

		if (addr->addr) {
			return rspamd_task_cache_principal_recipient (task, addr->addr,
					addr->addr_len);
		}
	}

	return NULL;
}

gboolean
rspamd_learn_task_spam (struct rspamd_task *task,
	gboolean is_spam,
	const gchar *classifier,
	GError **err)
{
	if (is_spam) {
		task->flags |= RSPAMD_TASK_FLAG_LEARN_SPAM;
	}
	else {
		task->flags |= RSPAMD_TASK_FLAG_LEARN_HAM;
	}

	task->classifier = classifier;

	return TRUE;
}

static gboolean
rspamd_task_log_check_condition (struct rspamd_task *task,
		struct rspamd_log_format *lf)
{
	gboolean ret = FALSE;

	switch (lf->type) {
	case RSPAMD_LOG_MID:
		if (task->message_id && strcmp (task->message_id, "undef") != 0) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_QID:
		if (task->queue_id && strcmp (task->queue_id, "undef") != 0) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_USER:
		if (task->user) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_IP:
		if (task->from_addr && rspamd_ip_is_valid (task->from_addr)) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_SMTP_RCPT:
	case RSPAMD_LOG_SMTP_RCPTS:
		if (task->rcpt_envelope && task->rcpt_envelope->len > 0) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_MIME_RCPT:
	case RSPAMD_LOG_MIME_RCPTS:
		if (task->rcpt_mime && task->rcpt_mime->len > 0) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_SMTP_FROM:
		if (task->from_envelope) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_MIME_FROM:
		if (task->from_mime && task->from_mime->len > 0) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_FILENAME:
		if (task->msg.fpath) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_FORCED_ACTION:
		if (task->result->passthrough_result) {
			ret = TRUE;
		}
		break;
	default:
		ret = TRUE;
		break;
	}

	return ret;
}

/*
 * Sort by symbol's score -> name
 */
static gint
rspamd_task_compare_log_sym (gconstpointer a, gconstpointer b)
{
	const struct rspamd_symbol_result *s1 = *(const struct rspamd_symbol_result **)a,
			*s2 = *(const struct rspamd_symbol_result **)b;
	gdouble w1, w2;


	w1 = fabs (s1->score);
	w2 = fabs (s2->score);

	if (w1 == w2 && s1->name && s2->name) {
		return strcmp (s1->name, s2->name);
	}

	return (w2 - w1) * 1000.0;
}

static rspamd_ftok_t
rspamd_task_log_metric_res (struct rspamd_task *task,
		struct rspamd_log_format *lf)
{
	static gchar scorebuf[32];
	rspamd_ftok_t res = {.begin = NULL, .len = 0};
	struct rspamd_metric_result *mres;
	gboolean first = TRUE;
	rspamd_fstring_t *symbuf;
	struct rspamd_symbol_result *sym;
	GPtrArray *sorted_symbols;
	enum rspamd_action_type act;
	guint i, j;

	mres = task->result;
	act = rspamd_check_action_metric (task, mres);

	if (mres != NULL) {
		switch (lf->type) {
		case RSPAMD_LOG_ISSPAM:
			if (RSPAMD_TASK_IS_SKIPPED (task)) {
				res.begin = "S";
			}
			else if (act == METRIC_ACTION_REJECT) {
				res.begin = "T";
			}
			else {
				res.begin = "F";
			}

			res.len = 1;
			break;
		case RSPAMD_LOG_ACTION:
			res.begin = rspamd_action_to_str (act);
			res.len = strlen (res.begin);
			break;
		case RSPAMD_LOG_SCORES:
			res.len = rspamd_snprintf (scorebuf, sizeof (scorebuf), "%.2f/%.2f",
					mres->score, rspamd_task_get_required_score (task, mres));
			res.begin = scorebuf;
			break;
		case RSPAMD_LOG_SYMBOLS:
			symbuf = rspamd_fstring_sized_new (128);
			sorted_symbols = g_ptr_array_sized_new (kh_size (mres->symbols));

			kh_foreach_value_ptr (mres->symbols, sym, {
				if (!(sym->flags & RSPAMD_SYMBOL_RESULT_IGNORED)) {
					g_ptr_array_add (sorted_symbols, (gpointer)sym);
				}
			});

			g_ptr_array_sort (sorted_symbols, rspamd_task_compare_log_sym);

			for (i = 0; i < sorted_symbols->len; i ++) {
				sym = g_ptr_array_index (sorted_symbols, i);

				if (first) {
					rspamd_printf_fstring (&symbuf, "%s", sym->name);
				}
				else {
					rspamd_printf_fstring (&symbuf, ",%s", sym->name);
				}

				if (lf->flags & RSPAMD_LOG_FMT_FLAG_SYMBOLS_SCORES) {
					rspamd_printf_fstring (&symbuf, "(%.2f)", sym->score);
				}

				if (lf->flags & RSPAMD_LOG_FMT_FLAG_SYMBOLS_PARAMS) {
					rspamd_printf_fstring (&symbuf, "{");

					if (sym->options) {
						struct rspamd_symbol_option *opt;

						j = 0;

						DL_FOREACH (sym->opts_head, opt) {
							rspamd_printf_fstring (&symbuf, "%s;", opt->option);

							if (j >= max_log_elts) {
								rspamd_printf_fstring (&symbuf, "...;");
								break;
							}

							j ++;
						}
					}

					rspamd_printf_fstring (&symbuf, "}");
				}

				first = FALSE;
			}

			g_ptr_array_free (sorted_symbols, TRUE);

			rspamd_mempool_add_destructor (task->task_pool,
					(rspamd_mempool_destruct_t)rspamd_fstring_free,
					symbuf);
			res.begin = symbuf->str;
			res.len = symbuf->len;
			break;
		default:
			break;
		}
	}

	return res;
}

static rspamd_fstring_t *
rspamd_task_log_write_var (struct rspamd_task *task, rspamd_fstring_t *logbuf,
		const rspamd_ftok_t *var, const rspamd_ftok_t *content)
{
	rspamd_fstring_t *res = logbuf;
	const gchar *p, *c, *end;

	if (content == NULL) {
		/* Just output variable */
		res = rspamd_fstring_append (res, var->begin, var->len);
	}
	else {
		/* Replace $ with variable value */
		p = content->begin;
		c = p;
		end = p + content->len;

		while (p < end) {
			if (*p == '$') {
				if (p > c) {
					res = rspamd_fstring_append (res, c, p - c);
				}

				res = rspamd_fstring_append (res, var->begin, var->len);
				p ++;
				c = p;
			}
			else {
				p ++;
			}
		}

		if (p > c) {
			res = rspamd_fstring_append (res, c, p - c);
		}
	}

	return res;
}

static rspamd_fstring_t *
rspamd_task_write_ialist (struct rspamd_task *task,
		GPtrArray *addrs, gint lim,
		struct rspamd_log_format *lf,
		rspamd_fstring_t *logbuf)
{
	rspamd_fstring_t *res = logbuf, *varbuf;
	rspamd_ftok_t var = {.begin = NULL, .len = 0};
	struct rspamd_email_address *addr;
	gint i, nchars = 0, cur_chars;

	if (lim <= 0) {
		lim = addrs->len;
	}

	varbuf = rspamd_fstring_new ();

	PTR_ARRAY_FOREACH (addrs, i, addr) {
		if (i >= lim) {
			break;
		}
		cur_chars = addr->addr_len;
		varbuf = rspamd_fstring_append (varbuf, addr->addr,
				cur_chars);
		nchars += cur_chars;

		if (varbuf->len > 0) {
			if (i != lim - 1) {
				varbuf = rspamd_fstring_append (varbuf, ",", 1);
			}
		}

		if (i >= max_log_elts || nchars >= max_log_elts * 10) {
			varbuf = rspamd_fstring_append (varbuf, "...", 3);
			break;
		}
	}

	if (varbuf->len > 0) {
		var.begin = varbuf->str;
		var.len = varbuf->len;
		res = rspamd_task_log_write_var (task, logbuf,
				&var, (const rspamd_ftok_t *) lf->data);
	}

	rspamd_fstring_free (varbuf);

	return res;
}

static rspamd_fstring_t *
rspamd_task_write_addr_list (struct rspamd_task *task,
		GPtrArray *addrs, gint lim,
		struct rspamd_log_format *lf,
		rspamd_fstring_t *logbuf)
{
	rspamd_fstring_t *res = logbuf, *varbuf;
	rspamd_ftok_t var = {.begin = NULL, .len = 0};
	struct rspamd_email_address *addr;
	gint i;

	if (lim <= 0) {
		lim = addrs->len;
	}

	varbuf = rspamd_fstring_new ();

	for (i = 0; i < lim; i++) {
		addr = g_ptr_array_index (addrs, i);

		if (addr->addr) {
			varbuf = rspamd_fstring_append (varbuf, addr->addr, addr->addr_len);
		}

		if (varbuf->len > 0) {
			if (i != lim - 1) {
				varbuf = rspamd_fstring_append (varbuf, ",", 1);
			}
		}

		if (i >= max_log_elts) {
			varbuf = rspamd_fstring_append (varbuf, "...", 3);
			break;
		}
	}

	if (varbuf->len > 0) {
		var.begin = varbuf->str;
		var.len = varbuf->len;
		res = rspamd_task_log_write_var (task, logbuf,
				&var, (const rspamd_ftok_t *) lf->data);
	}

	rspamd_fstring_free (varbuf);

	return res;
}

static rspamd_fstring_t *
rspamd_task_log_variable (struct rspamd_task *task,
		struct rspamd_log_format *lf, rspamd_fstring_t *logbuf)
{
	rspamd_fstring_t *res = logbuf;
	rspamd_ftok_t var = {.begin = NULL, .len = 0};
	static gchar numbuf[128];
	static const gchar undef[] = "undef";

	switch (lf->type) {
	/* String vars */
	case RSPAMD_LOG_MID:
		if (task->message_id) {
			var.begin = task->message_id;
			var.len = strlen (var.begin);
		}
		else {
			var.begin = undef;
			var.len = sizeof (undef) - 1;
		}
		break;
	case RSPAMD_LOG_QID:
		if (task->queue_id) {
			var.begin = task->queue_id;
			var.len = strlen (var.begin);
		}
		else {
			var.begin = undef;
			var.len = sizeof (undef) - 1;
		}
		break;
	case RSPAMD_LOG_USER:
		if (task->user) {
			var.begin = task->user;
			var.len = strlen (var.begin);
		}
		else {
			var.begin = undef;
			var.len = sizeof (undef) - 1;
		}
		break;
	case RSPAMD_LOG_IP:
		if (task->from_addr && rspamd_ip_is_valid (task->from_addr)) {
			var.begin = rspamd_inet_address_to_string (task->from_addr);
			var.len = strlen (var.begin);
		}
		else {
			var.begin = undef;
			var.len = sizeof (undef) - 1;
		}
		break;
	/* Numeric vars */
	case RSPAMD_LOG_LEN:
		var.len = rspamd_snprintf (numbuf, sizeof (numbuf), "%uz",
				task->msg.len);
		var.begin = numbuf;
		break;
	case RSPAMD_LOG_DNS_REQ:
		var.len = rspamd_snprintf (numbuf, sizeof (numbuf), "%uD",
				task->dns_requests);
		var.begin = numbuf;
		break;
	case RSPAMD_LOG_TIME_REAL:
		var.begin = rspamd_log_check_time (task->time_real,
				task->time_real_finish,
				task->cfg->clock_res);
		var.len = strlen (var.begin);
		break;
	case RSPAMD_LOG_TIME_VIRTUAL:
		var.begin = rspamd_log_check_time (task->time_virtual,
				task->time_virtual_finish,
				task->cfg->clock_res);
		var.len = strlen (var.begin);
		break;
	/* InternetAddress vars */
	case RSPAMD_LOG_SMTP_FROM:
		if (task->from_envelope) {
			var.begin = task->from_envelope->addr;
			var.len = task->from_envelope->addr_len;
		}
		break;
	case RSPAMD_LOG_MIME_FROM:
		if (task->from_mime) {
			return rspamd_task_write_ialist (task, task->from_mime, 1, lf,
					logbuf);
		}
		break;
	case RSPAMD_LOG_SMTP_RCPT:
		if (task->rcpt_envelope) {
			return rspamd_task_write_addr_list (task, task->rcpt_envelope, 1, lf,
					logbuf);
		}
		break;
	case RSPAMD_LOG_MIME_RCPT:
		if (task->rcpt_mime) {
			return rspamd_task_write_ialist (task, task->rcpt_mime, 1, lf,
					logbuf);
		}
		break;
	case RSPAMD_LOG_SMTP_RCPTS:
		if (task->rcpt_envelope) {
			return rspamd_task_write_addr_list (task, task->rcpt_envelope, -1, lf,
					logbuf);
		}
		break;
	case RSPAMD_LOG_MIME_RCPTS:
		if (task->rcpt_mime) {
			return rspamd_task_write_ialist (task, task->rcpt_mime, -1, lf,
					logbuf);
		}
		break;
	case RSPAMD_LOG_DIGEST:
		var.len = rspamd_snprintf (numbuf, sizeof (numbuf), "%*xs",
				(gint)sizeof (task->digest), task->digest);
		var.begin = numbuf;
		break;
	case RSPAMD_LOG_FILENAME:
		if (task->msg.fpath) {
			var.len = strlen (task->msg.fpath);
			var.begin = task->msg.fpath;
		}
		else {
			var.begin = undef;
			var.len = sizeof (undef) - 1;
		}
		break;
	case RSPAMD_LOG_FORCED_ACTION:
		if (task->result->passthrough_result) {
			struct rspamd_passthrough_result *pr = task->result->passthrough_result;

			if (!isnan (pr->target_score)) {
				var.len = rspamd_snprintf (numbuf, sizeof (numbuf),
						"%s \"%s\"; score=%.2f (set by %s)",
						rspamd_action_to_str (pr->action),
						pr->message, pr->target_score, pr->module);
			}
			else {
				var.len = rspamd_snprintf (numbuf, sizeof (numbuf),
						"%s \"%s\"; score=nan (set by %s)",
						rspamd_action_to_str (pr->action),
						pr->message, pr->module);
			}
			var.begin = numbuf;
		}
		else {
			var.begin = undef;
			var.len = sizeof (undef) - 1;
		}
		break;
	default:
		var = rspamd_task_log_metric_res (task, lf);
		break;
	}

	if (var.len > 0) {
		res = rspamd_task_log_write_var (task, logbuf,
				&var, (const rspamd_ftok_t *)lf->data);
	}

	return res;
}

void
rspamd_task_write_log (struct rspamd_task *task)
{
	rspamd_fstring_t *logbuf;
	struct rspamd_log_format *lf;
	struct rspamd_task **ptask;
	const gchar *lua_str;
	gsize lua_str_len;
	lua_State *L;

	g_assert (task != NULL);

	if (task->cfg->log_format == NULL ||
			(task->flags & RSPAMD_TASK_FLAG_NO_LOG)) {
		return;
	}

	logbuf = rspamd_fstring_sized_new (1000);

	DL_FOREACH (task->cfg->log_format, lf) {
		switch (lf->type) {
		case RSPAMD_LOG_STRING:
			logbuf = rspamd_fstring_append (logbuf, lf->data, lf->len);
			break;
		case RSPAMD_LOG_LUA:
			L = task->cfg->lua_state;
			lua_rawgeti (L, LUA_REGISTRYINDEX, GPOINTER_TO_INT (lf->data));
			ptask = lua_newuserdata (L, sizeof (*ptask));
			rspamd_lua_setclass (L, "rspamd{task}", -1);
			*ptask = task;

			if (lua_pcall (L, 1, 1, 0) != 0) {
				msg_err_task ("call to log function failed: %s",
						lua_tostring (L, -1));
				lua_pop (L, 1);
			}
			else {
				lua_str = lua_tolstring (L, -1, &lua_str_len);

				if (lua_str != NULL) {
					logbuf = rspamd_fstring_append (logbuf, lua_str, lua_str_len);
				}
				lua_pop (L, 1);
			}
			break;
		default:
			/* We have a variable in log format */
			if (lf->flags & RSPAMD_LOG_FMT_FLAG_CONDITION) {
				if (!rspamd_task_log_check_condition (task, lf)) {
					continue;
				}
			}

			logbuf = rspamd_task_log_variable (task, lf, logbuf);
			break;
		}
	}

	msg_notice_task ("%V", logbuf);

	rspamd_fstring_free (logbuf);
}

gdouble
rspamd_task_get_required_score (struct rspamd_task *task, struct rspamd_metric_result *m)
{
	guint i;

	if (m == NULL) {
		m = task->result;

		if (m == NULL) {
			return NAN;
		}
	}

	for (i = METRIC_ACTION_REJECT; i < METRIC_ACTION_NOACTION; i ++) {
		if (!isnan (m->actions_limits[i])) {
			return m->actions_limits[i];
		}
	}

	return NAN;
}

rspamd_ftok_t *
rspamd_task_get_request_header (struct rspamd_task *task,
		const gchar *name)
{
	GPtrArray *ret;
	rspamd_ftok_t srch;

	srch.begin = (gchar *)name;
	srch.len = strlen (name);

	ret = g_hash_table_lookup (task->request_headers, &srch);

	if (ret) {
		return (rspamd_ftok_t *)g_ptr_array_index (ret, 0);
	}

	return NULL;
}

GPtrArray*
rspamd_task_get_request_header_multiple (struct rspamd_task *task,
		const gchar *name)
{
	GPtrArray *ret;
	rspamd_ftok_t srch;

	srch.begin = (gchar *)name;
	srch.len = strlen (name);

	ret = g_hash_table_lookup (task->request_headers, &srch);

	return ret;
}


void
rspamd_task_add_request_header (struct rspamd_task *task,
		rspamd_ftok_t *name, rspamd_ftok_t *value)
{
	GPtrArray *ret;

	ret = g_hash_table_lookup (task->request_headers, name);

	if (ret) {
		g_ptr_array_add (ret, value);

		/* We need to free name token */
		rspamd_fstring_mapped_ftok_free (name);
	}
	else {
		ret = g_ptr_array_sized_new (2);
		g_ptr_array_add (ret, value);
		g_hash_table_replace (task->request_headers, name, ret);
	}
}


void
rspamd_task_profile_set (struct rspamd_task *task, const gchar *key,
		gdouble value)
{
	GHashTable *tbl;
	gdouble *pval;

	if (key == NULL) {
		return;
	}

	tbl = rspamd_mempool_get_variable (task->task_pool, RSPAMD_MEMPOOL_PROFILE);

	if (tbl == NULL) {
		tbl = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
		rspamd_mempool_set_variable (task->task_pool, RSPAMD_MEMPOOL_PROFILE,
				tbl, (rspamd_mempool_destruct_t)g_hash_table_unref);
	}

	pval = g_hash_table_lookup (tbl, key);

	if (pval == NULL) {
		pval = rspamd_mempool_alloc (task->task_pool, sizeof (*pval));
		*pval = value;
		g_hash_table_insert (tbl, (void *)key, pval);
	}
	else {
		*pval = value;
	}
}

gdouble*
rspamd_task_profile_get (struct rspamd_task *task, const gchar *key)
{
	GHashTable *tbl;
	gdouble *pval = NULL;

	tbl = rspamd_mempool_get_variable (task->task_pool, RSPAMD_MEMPOOL_PROFILE);

	if (tbl != NULL) {
		pval = g_hash_table_lookup (tbl, key);
	}

	return pval;
}


gboolean
rspamd_task_set_finish_time (struct rspamd_task *task)
{
	struct timeval tv;

	if (isnan (task->time_real_finish)) {

#ifdef HAVE_EVENT_NO_CACHE_TIME_FUNC
		if (task->ev_base) {
			event_base_update_cache_time (task->ev_base);
			event_base_gettimeofday_cached (task->ev_base, &tv);
			task->time_real_finish = tv_to_double (&tv);
		}
		else {
			gettimeofday (&tv, NULL);
			task->time_real_finish = tv_to_double (&tv);
		}
#else
		gettimeofday (&tv, NULL);
		task->time_real_finish = tv_to_double (&tv);
#endif
		task->time_virtual_finish = rspamd_get_virtual_ticks ();

		return TRUE;
	}

	return FALSE;
}