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
#include "scan_result.h"
#include "libserver/protocol.h"
#include "libserver/protocol_internal.h"
#include "message.h"
#include "lua/lua_common.h"
#include "email_addr.h"
#include "src/libserver/composites/composites.h"
#include "stat_api.h"
#include "unix-std.h"
#include "utlist.h"
#include "libserver/mempool_vars_internal.h"
#include "libserver/cfg_file_private.h"
#include "libmime/lang_detection.h"
#include "libmime/scan_result_private.h"

#ifdef WITH_JEMALLOC
#include <jemalloc/jemalloc.h>
#else
# if defined(__GLIBC__) && defined(_GNU_SOURCE)
#  include <malloc.h>
# endif
#endif

#include <math.h>

#ifdef SYS_ZSTD
#  include "zstd.h"
#else
#  include "contrib/zstd/zstd.h"
#endif

__KHASH_IMPL (rspamd_req_headers_hash, static inline,
		rspamd_ftok_t *, struct rspamd_request_header_chain *, 1,
				rspamd_ftok_icase_hash, rspamd_ftok_icase_equal)

/*
 * Do not print more than this amount of elts
 */
static const int max_log_elts = 7;

static GQuark
rspamd_task_quark (void)
{
	return g_quark_from_static_string ("task-error");
}

/*
 * Create new task
 */
struct rspamd_task *
rspamd_task_new (struct rspamd_worker *worker,
				 struct rspamd_config *cfg,
				 rspamd_mempool_t *pool,
				 struct rspamd_lang_detector *lang_det,
				 struct ev_loop *event_loop,
				 gboolean debug_mem)
{
	struct rspamd_task *new_task;
	rspamd_mempool_t *task_pool;
	guint flags = 0;

	if (pool == NULL) {
		task_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
				"task", debug_mem ? RSPAMD_MEMPOOL_DEBUG : 0);
		flags |= RSPAMD_TASK_FLAG_OWN_POOL;
	}
	else {
		task_pool = pool;
	}

	new_task = rspamd_mempool_alloc0 (task_pool, sizeof (struct rspamd_task));
	new_task->task_pool = task_pool;
	new_task->flags = flags;
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

	new_task->event_loop = event_loop;
	new_task->task_timestamp = ev_time ();
	new_task->time_real_finish = NAN;

	new_task->request_headers = kh_init (rspamd_req_headers_hash);
	new_task->sock = -1;
	new_task->flags |= (RSPAMD_TASK_FLAG_MIME);
	/* Default results chain */
	rspamd_create_metric_result (new_task, NULL, -1);

	new_task->queue_id = "undef";
	new_task->messages = ucl_object_typed_new (UCL_OBJECT);
	new_task->lua_cache = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);

	return new_task;
}


static void
rspamd_task_reply (struct rspamd_task *task)
{
	const ev_tstamp write_timeout = 5.0;

	if (task->fin_callback) {
		task->fin_callback (task, task->fin_arg);
	}
	else {
		if (!(task->processed_stages & RSPAMD_TASK_STAGE_REPLIED)) {
			rspamd_protocol_write_reply (task, write_timeout);
		}
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
	struct rspamd_email_address *addr;
	struct rspamd_lua_cached_entry *entry;
	static guint free_iters = 0;
	GHashTableIter it;
	gpointer k, v;
	guint i;

	if (task) {
		debug_task ("free pointer %p", task);

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

		if (task->from_envelope_orig) {
			rspamd_email_address_free (task->from_envelope_orig);
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

		if (task->settings_elt != NULL) {
			REF_RELEASE (task->settings_elt);
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

		ev_timer_stop (task->event_loop, &task->timeout_ev);
		ev_io_stop (task->event_loop, &task->guard_ev);

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

			if (task->cfg->full_gc_iters && (++free_iters > task->cfg->full_gc_iters)) {
				/* Perform more expensive cleanup cycle */
				gsize allocated = 0, active = 0, metadata = 0,
						resident = 0, mapped = 0, old_lua_mem = 0;
				gdouble t1, t2;

				old_lua_mem = lua_gc (task->cfg->lua_state, LUA_GCCOUNT, 0);
				t1 = rspamd_get_ticks (FALSE);

#ifdef WITH_JEMALLOC
				gsize sz = sizeof (gsize);
				mallctl ("stats.allocated", &allocated, &sz, NULL, 0);
				mallctl ("stats.active", &active, &sz, NULL, 0);
				mallctl ("stats.metadata", &metadata, &sz, NULL, 0);
				mallctl ("stats.resident", &resident, &sz, NULL, 0);
				mallctl ("stats.mapped", &mapped, &sz, NULL, 0);
#else
# if defined(__GLIBC__) && defined(_GNU_SOURCE)
				malloc_trim (0);
# endif
#endif
				lua_gc (task->cfg->lua_state, LUA_GCCOLLECT, 0);
				t2 = rspamd_get_ticks (FALSE);

				msg_notice_task ("perform full gc cycle; memory stats: "
								 "%Hz allocated, %Hz active, %Hz metadata, %Hz resident, %Hz mapped;"
								 " lua memory: %z kb -> %d kb; %f ms for gc iter",
						allocated, active, metadata, resident, mapped,
						old_lua_mem, lua_gc (task->cfg->lua_state, LUA_GCCOUNT, 0),
						(t2 - t1) * 1000.0);
				free_iters = rspamd_time_jitter (0,
						(gdouble)task->cfg->full_gc_iters / 2);
			}

			REF_RELEASE (task->cfg);
		}

		kh_destroy (rspamd_req_headers_hash, task->request_headers);
		rspamd_message_unref (task->message);

		if (task->flags & RSPAMD_TASK_FLAG_OWN_POOL) {
			rspamd_mempool_delete (task->task_pool);
		}
	}
}

struct rspamd_task_map {
	gpointer begin;
	gulong len;
	gint fd;
};

static void
rspamd_task_unmapper (gpointer ud)
{
	struct rspamd_task_map *m = ud;

	munmap (m->begin, m->len);
	close (m->fd);
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

		tok = rspamd_task_get_request_header (task, "shm-offset");

		if (tok) {
			rspamd_strtoul (tok->begin, tok->len, &offset);

			if (offset > (gulong)st.st_size) {
				msg_err_task ("invalid offset %ul (%ul available) for shm "
							  "segment %s", offset, (gulong)st.st_size, fp);
				munmap (map, st.st_size);
				close (fd);

				return FALSE;
			}
		}

		tok = rspamd_task_get_request_header (task, "shm-length");
		shmem_size = st.st_size;


		if (tok) {
			rspamd_strtoul (tok->begin, tok->len, &shmem_size);

			if (shmem_size > (gulong)st.st_size) {
				msg_err_task ("invalid length %ul (%ul available) for %s "
							  "segment %s", shmem_size, (gulong)st.st_size, ft, fp);
				munmap (map, st.st_size);
				close (fd);

				return FALSE;
			}
		}

		task->msg.begin = ((guchar *)map) + offset;
		task->msg.len = shmem_size;
		m = rspamd_mempool_alloc (task->task_pool, sizeof (*m));
		m->begin = map;
		m->len = st.st_size;
		m->fd = fd;

		msg_info_task ("loaded message from shared memory %s (%ul size, %ul offset), fd=%d",
				fp, shmem_size, offset, fd);

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

			task->msg.begin = map;
			task->msg.len = st.st_size;
			m = rspamd_mempool_alloc (task->task_pool, sizeof (*m));
			m->begin = map;
			m->len = st.st_size;
			m->fd = fd;

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
					zout.size = zout.size * 2 + 1;
					zout.dst = g_realloc (zout.dst, zout.size);
				}
			}

			rspamd_mempool_add_destructor (task->task_pool, g_free, zout.dst);
			task->msg.begin = zout.dst;
			task->msg.len = zout.pos;
			task->protocol_flags |= RSPAMD_TASK_PROTOCOL_FLAG_COMPRESSED;

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

	if (task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_HAS_CONTROL) {
		rspamd_ftok_t *hv = rspamd_task_get_request_header (task, MLEN_HEADER);
		gulong message_len = 0;

		if (!hv || !rspamd_strtoul (hv->begin, hv->len, &message_len) ||
				task->msg.len < message_len) {
			msg_warn_task ("message has invalid message length: %ul and total len: %ul",
					message_len, task->msg.len);
			g_set_error (&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"Invalid length");
			return FALSE;
		}

		control_len = task->msg.len - message_len;

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
	gboolean ret = TRUE, all_done = TRUE;
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
	case RSPAMD_TASK_STAGE_CONNFILTERS:
		all_done = rspamd_symcache_process_symbols (task, task->cfg->cache, st);
		break;

	case RSPAMD_TASK_STAGE_READ_MESSAGE:
		if (!rspamd_message_parse (task)) {
			ret = FALSE;
		}
		break;

	case RSPAMD_TASK_STAGE_PROCESS_MESSAGE:
		if (!(task->flags & RSPAMD_TASK_FLAG_SKIP_PROCESS)) {
			rspamd_message_process (task);
		}
		break;

	case RSPAMD_TASK_STAGE_PRE_FILTERS:
	case RSPAMD_TASK_STAGE_FILTERS:
		all_done = rspamd_symcache_process_symbols (task, task->cfg->cache, st);
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
		rspamd_composites_process_task (task);
		task->result->nresults_postfilters = task->result->nresults;
		break;

	case RSPAMD_TASK_STAGE_POST_FILTERS:
		all_done = rspamd_symcache_process_symbols (task, task->cfg->cache,
				st);

		if (all_done && (task->flags & RSPAMD_TASK_FLAG_LEARN_AUTO) &&
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
								"Unknown statistics error, found on stage %s;"
								" classifier: %s",
								rspamd_task_stage_name (st), task->classifier);
					}

					if (stat_error->code >= 400) {
						msg_err_task ("learn error: %e", stat_error);
					}
					else {
						msg_notice_task ("skip learning: %e", stat_error);
					}

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
		/* Second run of composites processing before idempotent filters (if needed) */
		if (task->result->nresults_postfilters != task->result->nresults) {
			rspamd_composites_process_task (task);
		}
		else {
			msg_debug_task ("skip second run of composites as the result has not been changed");
		}
		break;

	case RSPAMD_TASK_STAGE_IDEMPOTENT:
		/* Stop task timeout */
		if (ev_can_stop (&task->timeout_ev)) {
			ev_timer_stop (task->event_loop, &task->timeout_ev);
		}

		all_done = rspamd_symcache_process_symbols (task, task->cfg->cache, st);
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

	if (ret) {
		if (rspamd_session_events_pending (task->s) != 0) {
			/* We have events pending, so we consider this stage as incomplete */
			msg_debug_task ("need more work on stage %d", st);
		}
		else {
			if (all_done) {
				/* Mark the current stage as done and go to the next stage */
				msg_debug_task ("completed stage %d", st);
				task->processed_stages |= st;
			}
			else {
				msg_debug_task ("need more processing on stage %d", st);
			}

			/* Tail recursion */
			return rspamd_task_process (task, stages);
		}
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
	guint i;

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

		PTR_ARRAY_FOREACH (task->rcpt_envelope, i, addr) {
			if (addr->addr && !(addr->flags & RSPAMD_EMAIL_ADDR_ORIGINAL)) {
				return rspamd_task_cache_principal_recipient (task, addr->addr,
						addr->addr_len);
			}
		}
	}

	GPtrArray *rcpt_mime = MESSAGE_FIELD_CHECK (task, rcpt_mime);
	if (rcpt_mime != NULL && rcpt_mime->len > 0) {
		PTR_ARRAY_FOREACH (rcpt_mime, i, addr) {
			if (addr->addr && !(addr->flags & RSPAMD_EMAIL_ADDR_ORIGINAL)) {
				return rspamd_task_cache_principal_recipient (task, addr->addr,
						addr->addr_len);
			}
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
		if (MESSAGE_FIELD_CHECK (task, message_id) &&
			strcmp (MESSAGE_FIELD (task, message_id) , "undef") != 0) {
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
		if (MESSAGE_FIELD_CHECK (task, rcpt_mime) &&
			MESSAGE_FIELD (task, rcpt_mime)->len > 0) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_SMTP_FROM:
		if (task->from_envelope) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_MIME_FROM:
		if (MESSAGE_FIELD_CHECK (task, from_mime) &&
			MESSAGE_FIELD (task, from_mime)->len > 0) {
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
	case RSPAMD_LOG_SETTINGS_ID:
		if (task->settings_elt) {
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

static gint
rspamd_task_compare_log_group (gconstpointer a, gconstpointer b)
{
	const struct rspamd_symbols_group *s1 = *(const struct rspamd_symbols_group **)a,
			*s2 = *(const struct rspamd_symbols_group **)b;

	return strcmp (s1->name, s2->name);
}


static rspamd_ftok_t
rspamd_task_log_metric_res (struct rspamd_task *task,
		struct rspamd_log_format *lf)
{
	static gchar scorebuf[32];
	rspamd_ftok_t res = {.begin = NULL, .len = 0};
	struct rspamd_scan_result *mres;
	gboolean first = TRUE;
	rspamd_fstring_t *symbuf;
	struct rspamd_symbol_result *sym;
	GPtrArray *sorted_symbols;
	struct rspamd_action *act;
	struct rspamd_symbols_group *gr;
	guint i, j;
	khiter_t k;

	mres = task->result;
	act = rspamd_check_action_metric (task, NULL, NULL);

	if (mres != NULL) {
		switch (lf->type) {
		case RSPAMD_LOG_ISSPAM:
			if (RSPAMD_TASK_IS_SKIPPED (task)) {
				res.begin = "S";
			}
			else if (!(act->flags & RSPAMD_ACTION_HAM)) {
				res.begin = "T";
			}
			else {
				res.begin = "F";
			}

			res.len = 1;
			break;
		case RSPAMD_LOG_ACTION:
			res.begin = act->name;
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

			kh_foreach_value (mres->symbols, sym, {
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
							rspamd_printf_fstring (&symbuf, "%*s;",
									(gint)opt->optlen, opt->option);

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
			rspamd_mempool_notify_alloc (task->task_pool, symbuf->len);
			res.begin = symbuf->str;
			res.len = symbuf->len;
			break;

		case RSPAMD_LOG_GROUPS:
		case RSPAMD_LOG_PUBLIC_GROUPS:

			symbuf = rspamd_fstring_sized_new (128);
			sorted_symbols = g_ptr_array_sized_new (kh_size (mres->sym_groups));

			kh_foreach_key (mres->sym_groups, gr,{
				if (!(gr->flags & RSPAMD_SYMBOL_GROUP_PUBLIC)) {
					if (lf->type == RSPAMD_LOG_PUBLIC_GROUPS) {
						continue;
					}
				}

				g_ptr_array_add (sorted_symbols, gr);
			});

			g_ptr_array_sort (sorted_symbols, rspamd_task_compare_log_group);

			for (i = 0; i < sorted_symbols->len; i++) {
				gr = g_ptr_array_index (sorted_symbols, i);

				if (first) {
					rspamd_printf_fstring (&symbuf, "%s", gr->name);
				}
				else {
					rspamd_printf_fstring (&symbuf, ",%s", gr->name);
				}

				k = kh_get (rspamd_symbols_group_hash, mres->sym_groups, gr);

				rspamd_printf_fstring (&symbuf, "(%.2f)",
						kh_value (mres->sym_groups, k));

				first = FALSE;
			}

			g_ptr_array_free (sorted_symbols, TRUE);

			rspamd_mempool_add_destructor (task->task_pool,
					(rspamd_mempool_destruct_t) rspamd_fstring_free,
					symbuf);
			rspamd_mempool_notify_alloc (task->task_pool, symbuf->len);
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
	gint i, nchars = 0, wr = 0, cur_chars;
	gboolean has_orig = FALSE;

	if (addrs && lim <= 0) {
		lim = addrs->len;
	}

	PTR_ARRAY_FOREACH (addrs, i, addr) {
		if (addr->flags & RSPAMD_EMAIL_ADDR_ORIGINAL) {
			has_orig = TRUE;
			break;
		}
	}

	varbuf = rspamd_fstring_new ();

	PTR_ARRAY_FOREACH (addrs, i, addr) {
		if (wr >= lim) {
			break;
		}

		if (has_orig) {
			/* Report merely original addresses */
			if (!(addr->flags & RSPAMD_EMAIL_ADDR_ORIGINAL)) {
				continue;
			}
		}

		cur_chars = addr->addr_len;
		varbuf = rspamd_fstring_append (varbuf, addr->addr,
				cur_chars);
		nchars += cur_chars;
		wr ++;

		if (varbuf->len > 0) {
			if (i != lim - 1) {
				varbuf = rspamd_fstring_append (varbuf, ",", 1);
			}
		}

		if (wr >= max_log_elts || nchars >= max_log_elts * 10) {
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
		if (MESSAGE_FIELD_CHECK (task, message_id)) {
			var.begin = MESSAGE_FIELD (task, message_id);
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
		var.begin = rspamd_log_check_time (task->task_timestamp,
				task->time_real_finish,
				task->cfg->clock_res);
		var.len = strlen (var.begin);
		break;
	case RSPAMD_LOG_TIME_VIRTUAL:
		var.begin = rspamd_log_check_time (task->task_timestamp,
				task->time_real_finish,
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
		if (MESSAGE_FIELD_CHECK (task, from_mime)) {
			return rspamd_task_write_ialist (task,
					MESSAGE_FIELD (task, from_mime),
					1,
					lf,
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
		if (MESSAGE_FIELD_CHECK (task, rcpt_mime)) {
			return rspamd_task_write_ialist (task,
					MESSAGE_FIELD (task, rcpt_mime),
					1,
					lf,
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
		if (MESSAGE_FIELD_CHECK (task, rcpt_mime)) {
			return rspamd_task_write_ialist (task,
					MESSAGE_FIELD (task, rcpt_mime),
					-1, /* All addresses */
					lf,
					logbuf);
		}
		break;
	case RSPAMD_LOG_DIGEST:
		if (task->message) {
			var.len = rspamd_snprintf (numbuf, sizeof (numbuf), "%*xs",
					(gint) sizeof (MESSAGE_FIELD (task, digest)),
					MESSAGE_FIELD (task, digest));
			var.begin = numbuf;
		}
		else {
			var.begin = undef;
			var.len = sizeof (undef) - 1;
		}
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
						pr->action->name,
						pr->message,
						pr->target_score,
						pr->module);
			}
			else {
				var.len = rspamd_snprintf (numbuf, sizeof (numbuf),
						"%s \"%s\"; score=nan (set by %s)",
						pr->action->name,
						pr->message,
						pr->module);
			}
			var.begin = numbuf;
		}
		else {
			var.begin = undef;
			var.len = sizeof (undef) - 1;
		}
		break;
	case RSPAMD_LOG_SETTINGS_ID:
		if (task->settings_elt) {
			var.begin = task->settings_elt->name;
			var.len = strlen (task->settings_elt->name);
		}
		else {
			var.begin = undef;
			var.len = sizeof (undef) - 1;
		}
		break;
	case RSPAMD_LOG_MEMPOOL_SIZE:
		var.len = rspamd_snprintf (numbuf, sizeof (numbuf),
				"%Hz",
				rspamd_mempool_get_used_size (task->task_pool));
		var.begin = numbuf;
		break;
	case RSPAMD_LOG_MEMPOOL_WASTE:
		var.len = rspamd_snprintf (numbuf, sizeof (numbuf),
				"%Hz",
				rspamd_mempool_get_wasted_size (task->task_pool));
		var.begin = numbuf;
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
		msg_debug_task ("skip logging due to no log flag");
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
rspamd_task_get_required_score (struct rspamd_task *task, struct rspamd_scan_result *m)
{
	gint i;

	if (m == NULL) {
		m = task->result;

		if (m == NULL) {
			return NAN;
		}
	}

	for (i = m->nactions - 1; i >= 0; i --) {
		struct rspamd_action_result *action_lim = &m->actions_limits[i];


		if (!isnan (action_lim->cur_limit) &&
				!(action_lim->action->flags & (RSPAMD_ACTION_NO_THRESHOLD|RSPAMD_ACTION_HAM))) {
			return m->actions_limits[i].cur_limit;
		}
	}

	return NAN;
}

rspamd_ftok_t *
rspamd_task_get_request_header (struct rspamd_task *task,
		const gchar *name)
{
	struct rspamd_request_header_chain *ret =
			rspamd_task_get_request_header_multiple (task, name);

	if (ret) {
		return ret->hdr;
	}

	return NULL;
}

struct rspamd_request_header_chain *
rspamd_task_get_request_header_multiple (struct rspamd_task *task,
		const gchar *name)
{
	struct rspamd_request_header_chain *ret = NULL;
	rspamd_ftok_t srch;
	khiter_t k;

	srch.begin = (gchar *)name;
	srch.len = strlen (name);

	k = kh_get (rspamd_req_headers_hash, task->request_headers,
			&srch);

	if (k != kh_end (task->request_headers)) {
		ret = kh_value (task->request_headers, k);
	}

	return ret;
}


void
rspamd_task_add_request_header (struct rspamd_task *task,
		rspamd_ftok_t *name, rspamd_ftok_t *value)
{

	khiter_t k;
	gint res;
	struct rspamd_request_header_chain *chain, *nchain;

	k = kh_put (rspamd_req_headers_hash, task->request_headers,
		name, &res);

	if (res == 0) {
		/* Existing name */
		nchain = rspamd_mempool_alloc (task->task_pool, sizeof (*nchain));
		nchain->hdr = value;
		nchain->next = NULL;
		chain = kh_value (task->request_headers, k);

		/* Slow but OK here */
		LL_APPEND (chain, nchain);
	}
	else {
		nchain = rspamd_mempool_alloc (task->task_pool, sizeof (*nchain));
		nchain->hdr = value;
		nchain->next = NULL;

		kh_value (task->request_headers, k) = nchain;
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
	if (isnan (task->time_real_finish)) {
		task->time_real_finish = ev_time ();

		return TRUE;
	}

	return FALSE;
}

const gchar *
rspamd_task_stage_name (enum rspamd_task_stage stg)
{
	const gchar *ret = "unknown stage";

	switch (stg) {
	case RSPAMD_TASK_STAGE_CONNECT:
		ret = "connect";
		break;
	case RSPAMD_TASK_STAGE_CONNFILTERS:
		ret = "connection_filter";
		break;
	case RSPAMD_TASK_STAGE_READ_MESSAGE:
		ret = "read_message";
		break;
	case RSPAMD_TASK_STAGE_PRE_FILTERS:
		ret = "prefilters";
		break;
	case RSPAMD_TASK_STAGE_PROCESS_MESSAGE:
		ret = "process_message";
		break;
	case RSPAMD_TASK_STAGE_FILTERS:
		ret = "filters";
		break;
	case RSPAMD_TASK_STAGE_CLASSIFIERS_PRE:
		ret = "classifiers_pre";
		break;
	case RSPAMD_TASK_STAGE_CLASSIFIERS:
		ret = "classifiers";
		break;
	case RSPAMD_TASK_STAGE_CLASSIFIERS_POST:
		ret = "classifiers_post";
		break;
	case RSPAMD_TASK_STAGE_COMPOSITES:
		ret = "composites";
		break;
	case RSPAMD_TASK_STAGE_POST_FILTERS:
		ret = "postfilters";
		break;
	case RSPAMD_TASK_STAGE_LEARN_PRE:
		ret = "learn_pre";
		break;
	case RSPAMD_TASK_STAGE_LEARN:
		ret = "learn";
		break;
	case RSPAMD_TASK_STAGE_LEARN_POST:
		ret = "learn_post";
		break;
	case RSPAMD_TASK_STAGE_COMPOSITES_POST:
		ret = "composites_post";
		break;
	case RSPAMD_TASK_STAGE_IDEMPOTENT:
		ret = "idempotent";
		break;
	case RSPAMD_TASK_STAGE_DONE:
		ret = "done";
		break;
	case RSPAMD_TASK_STAGE_REPLIED:
		ret = "replied";
		break;
	default:
		break;
	}

	return ret;
}

void
rspamd_task_timeout (EV_P_ ev_timer *w, int revents)
{
	struct rspamd_task *task = (struct rspamd_task *)w->data;

	if (!(task->processed_stages & RSPAMD_TASK_STAGE_FILTERS)) {
		ev_now_update_if_cheap (task->event_loop);
		msg_info_task ("processing of task time out: %.1fs spent; %.1fs limit; "
					   "forced processing",
				ev_now (task->event_loop) - task->task_timestamp,
				w->repeat);

		if (task->cfg->soft_reject_on_timeout) {
			struct rspamd_action *action, *soft_reject;

			action = rspamd_check_action_metric (task, NULL, NULL);

			if (action->action_type != METRIC_ACTION_REJECT) {
				soft_reject = rspamd_config_get_action_by_type (task->cfg,
						METRIC_ACTION_SOFT_REJECT);
				rspamd_add_passthrough_result (task,
						soft_reject,
						0,
						NAN,
						"timeout processing message",
						"task timeout",
						0, NULL);
			}
		}

		ev_timer_again (EV_A_ w);
		task->processed_stages |= RSPAMD_TASK_STAGE_FILTERS;
		rspamd_session_cleanup (task->s);
		rspamd_task_process (task, RSPAMD_TASK_PROCESS_ALL);
		rspamd_session_pending (task->s);
	}
	else {
		/* Postprocessing timeout */
		msg_info_task ("post-processing of task time out: %.1f second spent; forced processing",
				ev_now (task->event_loop) - task->task_timestamp);

		if (task->cfg->soft_reject_on_timeout) {
			struct rspamd_action *action, *soft_reject;

			action = rspamd_check_action_metric (task, NULL, NULL);

			if (action->action_type != METRIC_ACTION_REJECT) {
				soft_reject = rspamd_config_get_action_by_type (task->cfg,
						METRIC_ACTION_SOFT_REJECT);
				rspamd_add_passthrough_result (task,
						soft_reject,
						0,
						NAN,
						"timeout post-processing message",
						"task timeout",
						0, NULL);
			}
		}

		ev_timer_stop (EV_A_ w);
		task->processed_stages |= RSPAMD_TASK_STAGE_DONE;
		rspamd_session_cleanup (task->s);
		rspamd_task_process (task, RSPAMD_TASK_PROCESS_ALL);
		rspamd_session_pending (task->s);
	}
}

void
rspamd_worker_guard_handler (EV_P_ ev_io *w, int revents)
{
	struct rspamd_task *task = (struct rspamd_task *)w->data;
	gchar fake_buf[1024];
	gssize r;

	r = read (w->fd, fake_buf, sizeof (fake_buf));

	if (r > 0) {
		msg_warn_task ("received extra data after task is loaded, ignoring");
	}
	else {
		if (r == 0) {
			/*
			 * Poor man approach, that might break things in case of
			 * shutdown (SHUT_WR) but sockets are so bad that there's no
			 * reliable way to distinguish between shutdown(SHUT_WR) and
			 * close.
			 */
			if (task->cmd != CMD_CHECK_V2 && task->cfg->enable_shutdown_workaround) {
				msg_info_task ("workaround for shutdown enabled, please update "
							   "your client, this support might be removed in future");
				shutdown (w->fd, SHUT_RD);
				ev_io_stop (task->event_loop, &task->guard_ev);
			}
			else {
				msg_err_task ("the peer has closed connection unexpectedly");
				rspamd_session_destroy (task->s);
			}
		}
		else if (errno != EAGAIN) {
			msg_err_task ("the peer has closed connection unexpectedly: %s",
					strerror (errno));
			rspamd_session_destroy (task->s);
		}
		else {
			return;
		}
	}
}
