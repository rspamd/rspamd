/*
 * Copyright 2025 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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
#include "lua/lua_classnames.h"

#ifdef WITH_JEMALLOC
#include <jemalloc/jemalloc.h>
#else
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
#include <malloc.h>
#endif
#endif

#include <math.h>

#include "libutil/compression.h"

__KHASH_IMPL(rspamd_req_headers_hash, static inline,
			 rspamd_ftok_t *, struct rspamd_request_header_chain *, 1,
			 rspamd_ftok_icase_hash, rspamd_ftok_icase_equal)

/* Task pointer set for validating Lua task references */
KHASH_SET_INIT_INT(rspamd_task_set);

static khash_t(rspamd_task_set) *task_registry = NULL;

#define TASK_REGISTRY_INITIAL_SIZE 16

/*
 * Mix 64-bit pointer to 32-bit hash using Fibonacci hashing.
 * Multiply by golden ratio and take high bits for good distribution.
 * kh_int_hash_func is identity, so we do all mixing here.
 */
static inline khint32_t
rspamd_task_hash_ptr(struct rspamd_task *task)
{
	uint64_t p = (uint64_t) (uintptr_t) task;
	return (khint32_t) ((p * 11400714819323198485ULL) >> 32);
}

void rspamd_task_registry_init(void)
{
	if (task_registry == NULL) {
		task_registry = kh_init(rspamd_task_set);
		kh_resize(rspamd_task_set, task_registry, TASK_REGISTRY_INITIAL_SIZE);
	}
}

void rspamd_task_registry_destroy(void)
{
	if (task_registry != NULL) {
		kh_destroy(rspamd_task_set, task_registry);
		task_registry = NULL;
	}
}

gboolean
rspamd_task_is_valid(struct rspamd_task *task)
{
	if (task_registry == NULL || task == NULL) {
		return FALSE;
	}

	khiter_t k = kh_get(rspamd_task_set, task_registry, rspamd_task_hash_ptr(task));
	return k != kh_end(task_registry);
}

static inline void
rspamd_task_registry_add(struct rspamd_task *task)
{
	if (task_registry == NULL) {
		rspamd_task_registry_init();
	}

	int ret;
	kh_put(rspamd_task_set, task_registry, rspamd_task_hash_ptr(task), &ret);
}

static inline void
rspamd_task_registry_remove(struct rspamd_task *task)
{
	if (task_registry == NULL) {
		return;
	}

	khiter_t k = kh_get(rspamd_task_set, task_registry, rspamd_task_hash_ptr(task));
	if (k != kh_end(task_registry)) {
		kh_del(rspamd_task_set, task_registry, k);
	}
}

static GQuark
rspamd_task_quark(void)
{
	return g_quark_from_static_string("task-error");
}

/*
 * Create new task
 */
struct rspamd_task *
rspamd_task_new(struct rspamd_worker *worker,
				struct rspamd_config *cfg,
				rspamd_mempool_t *pool,
				struct rspamd_lang_detector *lang_det,
				struct ev_loop *event_loop,
				gboolean debug_mem)
{
	struct rspamd_task *new_task;
	rspamd_mempool_t *task_pool;
	unsigned int flags = RSPAMD_TASK_FLAG_LEARN_AUTO;

	if (pool == NULL) {
		task_pool = rspamd_mempool_new_(rspamd_mempool_suggest_size_(G_STRLOC),
										"task",
										RSPAMD_MEMPOOL_SHORT_LIVED | (debug_mem ? RSPAMD_MEMPOOL_DEBUG : 0),
										G_STRLOC);
		flags |= RSPAMD_TASK_FLAG_OWN_POOL;
	}
	else {
		task_pool = pool;
	}

	new_task = rspamd_mempool_alloc0(task_pool, sizeof(struct rspamd_task));
	new_task->task_pool = task_pool;
	new_task->flags = flags;
	new_task->worker = worker;
	new_task->lang_det = lang_det;

	if (cfg) {
		new_task->cfg = cfg;
		CFG_REF_RETAIN(cfg);

		if (cfg->check_all_filters) {
			new_task->flags |= RSPAMD_TASK_FLAG_PASS_ALL;
		}


		if (cfg->re_cache) {
			new_task->re_rt = rspamd_re_cache_runtime_new(cfg->re_cache);
		}

		if (new_task->lang_det == NULL && cfg->lang_det != NULL) {
			new_task->lang_det = cfg->lang_det;
		}
	}

	new_task->event_loop = event_loop;
	new_task->task_timestamp = ev_time();
	new_task->time_real_finish = NAN;
	rspamd_uuid_v7(new_task->task_uuid, new_task->task_pool->tag.uid,
				   sizeof(new_task->task_pool->tag.uid), new_task->task_timestamp);

	new_task->request_headers = kh_init(rspamd_req_headers_hash);
	new_task->sock = -1;
	new_task->flags |= (RSPAMD_TASK_FLAG_MIME);
	/*
	 * Tasks that are not created by a network worker (rspamadm, Lua, embedded
	 * users) are local and trusted, so privileged message sources are allowed
	 * by default. The network workers clear this flag for every connection
	 * that is not permitted to use them.
	 */
	new_task->protocol_flags |= RSPAMD_TASK_PROTOCOL_FLAG_ALLOW_FILE_SHM_INPUT;
	/* Default results chain */
	rspamd_create_metric_result(new_task, NULL, -1);

	new_task->queue_id = "undef";
	new_task->messages = ucl_object_typed_new(UCL_OBJECT);
	kh_static_init(rspamd_task_lua_cache, &new_task->lua_cache);

	/* Initialize ESMTP arguments fields */
	new_task->mail_esmtp_args = NULL;
	new_task->rcpt_esmtp_args = NULL;

	rspamd_task_registry_add(new_task);

	return new_task;
}


static void
rspamd_task_reply(struct rspamd_task *task)
{
	const ev_tstamp write_timeout = 5.0;

	if (task->fin_callback) {
		task->fin_callback(task, task->fin_arg);
	}
	else {
		if (!(task->processed_stages & RSPAMD_TASK_STAGE_REPLIED)) {
			rspamd_protocol_write_reply(task, write_timeout, task->worker->srv);
		}
	}
}

/*
 * Called if all filters are processed
 * @return TRUE if session should be terminated
 */
gboolean
rspamd_task_fin(void *arg)
{
	struct rspamd_task *task = (struct rspamd_task *) arg;

	/* Task is already finished or skipped */
	if (RSPAMD_TASK_IS_PROCESSED(task)) {
		rspamd_task_reply(task);
		return TRUE;
	}

	if (!rspamd_task_process(task, RSPAMD_TASK_PROCESS_ALL)) {
		rspamd_task_reply(task);
		return TRUE;
	}

	if (RSPAMD_TASK_IS_PROCESSED(task)) {
		rspamd_task_reply(task);
		return TRUE;
	}

	/* One more iteration */
	return FALSE;
}

/*
 * Free all structures of worker_task
 */
void rspamd_task_free(struct rspamd_task *task)
{
	struct rspamd_email_address *addr;
	static unsigned int free_iters = 0;
	unsigned int i;

	if (task) {
		rspamd_task_registry_remove(task);

		debug_task("free pointer %p", task);

		if (task->rcpt_envelope) {
			for (i = 0; i < task->rcpt_envelope->len; i++) {
				addr = g_ptr_array_index(task->rcpt_envelope, i);
				rspamd_email_address_free(addr);
			}

			g_ptr_array_free(task->rcpt_envelope, TRUE);
		}

		if (task->from_envelope) {
			rspamd_email_address_free(task->from_envelope);
		}

		if (task->from_envelope_orig) {
			rspamd_email_address_free(task->from_envelope_orig);
		}

		if (task->meta_words.a) {
			kv_destroy(task->meta_words);
		}

		ucl_object_unref(task->messages);

		if (task->re_rt) {
			rspamd_re_cache_runtime_destroy(task->re_rt);
		}

		if (task->http_conn != NULL) {
			rspamd_http_connection_reset(task->http_conn);
			rspamd_http_connection_unref(task->http_conn);
		}

		if (task->settings != NULL) {
			ucl_object_unref(task->settings);
		}

		if (task->meta != NULL) {
			ucl_object_unref(task->meta);
		}

		if (task->settings_elt != NULL) {
			REF_RELEASE(task->settings_elt);
		}

		if (task->client_addr) {
			rspamd_inet_address_free(task->client_addr);
		}

		if (task->from_addr) {
			rspamd_inet_address_free(task->from_addr);
		}

		if (task->err) {
			g_error_free(task->err);
		}

		ev_timer_stop(task->event_loop, &task->timeout_ev);
		ev_io_stop(task->event_loop, &task->guard_ev);

		if (task->sock != -1) {
			close(task->sock);
		}

		if (task->cfg) {


			struct rspamd_lua_cached_entry entry;

			kh_foreach_value(&task->lua_cache, entry, {
				luaL_unref(task->cfg->lua_state,
						   LUA_REGISTRYINDEX, entry.ref);
			});
			kh_static_destroy(rspamd_task_lua_cache, &task->lua_cache);

			if (task->cfg->full_gc_iters && (++free_iters > task->cfg->full_gc_iters)) {
				/* Perform more expensive cleanup cycle */
				gsize allocated = 0, active = 0, metadata = 0,
					  resident = 0, mapped = 0, old_lua_mem = 0;
				double t1, t2;

				old_lua_mem = lua_gc(task->cfg->lua_state, LUA_GCCOUNT, 0);
				t1 = rspamd_get_ticks(FALSE);

#ifdef WITH_JEMALLOC
				gsize sz = sizeof(gsize);
				mallctl("stats.allocated", &allocated, &sz, NULL, 0);
				mallctl("stats.active", &active, &sz, NULL, 0);
				mallctl("stats.metadata", &metadata, &sz, NULL, 0);
				mallctl("stats.resident", &resident, &sz, NULL, 0);
				mallctl("stats.mapped", &mapped, &sz, NULL, 0);
#else
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
				malloc_trim(0);
#endif
#endif
				lua_gc(task->cfg->lua_state, LUA_GCCOLLECT, 0);
				t2 = rspamd_get_ticks(FALSE);

				msg_notice_task("perform full gc cycle; memory stats: "
								"%Hz allocated, %Hz active, %Hz metadata, %Hz resident, %Hz mapped;"
								" lua memory: %z kb -> %d kb; %f ms for gc iter",
								allocated, active, metadata, resident, mapped,
								old_lua_mem, lua_gc(task->cfg->lua_state, LUA_GCCOUNT, 0),
								(t2 - t1) * 1000.0);
				free_iters = rspamd_time_jitter(0,
												(double) task->cfg->full_gc_iters / 2);
			}

			CFG_REF_RELEASE(task->cfg);
		}

		kh_destroy(rspamd_req_headers_hash, task->request_headers);
		rspamd_message_unref(task->message);

		if (task->flags & RSPAMD_TASK_FLAG_OWN_POOL) {
			rspamd_mempool_destructors_enforce(task->task_pool);

			if (task->symcache_runtime) {
				rspamd_symcache_runtime_destroy(task);
			}

			rspamd_mempool_delete(task->task_pool);
		}
		else if (task->symcache_runtime) {
			rspamd_symcache_runtime_destroy(task);
		}
	}
}

/*
 * Sanitise a client supplied path (or a POSIX shared memory object name) and
 * copy it into `dst` which is `dstlen` bytes long.
 *
 * On success `dst` holds a NUL terminated, url decoded and unquoted string that
 * is guaranteed to be non empty, to contain neither embedded NULs nor control
 * characters, and to have been copied without truncation. Everything else is
 * rejected here, before any syscall touches the name.
 *
 * `what` is used in the error messages only, e.g. "file path".
 */
static gboolean
rspamd_task_sanitize_path(const rspamd_ftok_t *tok, char *dst, gsize dstlen,
						  const char *what, GError **err)
{
	gsize len, i;

	if (tok == NULL || tok->len == 0) {
		g_set_error(err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"empty %s", what);
		return FALSE;
	}

	/*
	 * rspamd_strlcpy truncates silently, and operating on a truncated path is
	 * strictly worse than refusing it, so check the source length upfront
	 */
	if ((gsize) tok->len >= dstlen) {
		g_set_error(err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"too long %s: %zu bytes, maximum is %zu", what,
					(gsize) tok->len, (gsize) (dstlen - 1));
		return FALSE;
	}

	/* An embedded NUL would silently cut the name short */
	if (memchr(tok->begin, '\0', tok->len) != NULL) {
		g_set_error(err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"%s contains a NUL byte", what);
		return FALSE;
	}

	rspamd_strlcpy(dst, tok->begin, tok->len + 1);
	/* Decoding never expands the input, so it is safe to do it in place */
	len = rspamd_url_decode(dst, dst, tok->len);
	dst[len] = '\0';

	if (len > 2 && dst[0] == '"' && dst[len - 1] == '"') {
		/* Unquote in place, so that the caller always uses `dst` itself */
		memmove(dst, dst + 1, len - 2);
		len -= 2;
		dst[len] = '\0';
	}

	if (len == 0) {
		g_set_error(err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"empty %s after decoding", what);
		return FALSE;
	}

	/*
	 * A name is a single printable token, anything else is a mistake; this also
	 * catches a NUL that has been produced by the decoding step above
	 */
	for (i = 0; i < len; i++) {
		if ((unsigned char) dst[i] < ' ' || (unsigned char) dst[i] == 0x7f) {
			g_set_error(err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
						"invalid character at position %zu in %s", i, what);
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * Read up to `len` bytes from `fd` into `buf`, dealing with short reads and
 * EINTR. `*read_len` is set to the number of bytes that were actually available:
 * an object that has shrunk under us yields less than `len` bytes instead of
 * faulting, and an object that has grown is simply truncated to `len`.
 */
static gboolean
rspamd_task_read_snapshot(int fd, char *buf, gsize len, gsize *read_len)
{
	gsize total = 0;

	while (total < len) {
		ssize_t r = read(fd, buf + total, len - total);

		if (r > 0) {
			total += (gsize) r;
		}
		else if (r == 0) {
			/* Truncated under us, whatever we have got is all there is */
			break;
		}
		else if (errno == EINTR) {
			continue;
		}
		else {
			*read_len = total;

			return FALSE;
		}
	}

	*read_len = total;

	return TRUE;
}

enum rspamd_snapshot_result {
	RSPAMD_SNAPSHOT_OK = 0,
	RSPAMD_SNAPSHOT_ERROR,
	/* This descriptor does not support positional reads at all */
	RSPAMD_SNAPSHOT_UNSUPPORTED,
};

/*
 * Reads `len` bytes at `offset` into `buf`, coping with short reads and EINTR.
 *
 * Unlike a copy out of a mapping, a read can never fault: if the object is
 * truncated while we are reading it we merely get fewer bytes than we asked
 * for, which the caller reflects in the payload length.
 */
static enum rspamd_snapshot_result
rspamd_task_pread_snapshot(int fd, char *buf, gsize len, off_t offset,
						   gsize *read_len)
{
	gsize total = 0;

	while (total < len) {
		ssize_t r = pread(fd, buf + total, len - total,
						  offset + (off_t) total);

		if (r > 0) {
			total += (gsize) r;
		}
		else if (r == 0) {
			/* Truncated under us, whatever we have got is all there is */
			break;
		}
		else if (errno == EINTR) {
			continue;
		}
		else if (total == 0 && (errno == ESPIPE || errno == ENODEV ||
								errno == EINVAL || errno == ENOTSUP ||
								errno == EOPNOTSUPP)) {
			/*
			 * POSIX shared memory descriptors cannot be read on every platform
			 * (macOS returns ESPIPE, some BSDs ENODEV), so the caller has to
			 * fall back to mapping the window there.
			 */
			return RSPAMD_SNAPSHOT_UNSUPPORTED;
		}
		else {
			*read_len = total;

			return RSPAMD_SNAPSHOT_ERROR;
		}
	}

	*read_len = total;

	return RSPAMD_SNAPSHOT_OK;
}

struct rspamd_shmem_segment *
rspamd_shmem_segment_map(rspamd_mempool_t *pool,
						 const rspamd_ftok_t *name_tok,
						 const rspamd_ftok_t *offset_tok,
						 const rspamd_ftok_t *length_tok,
						 gsize max_size,
						 GError **err)
{
	char namebuf[PATH_MAX];
	const char *name = namebuf;
	gulong offset = 0, length = 0;
	gsize page_size, aligned_offset, delta, map_len, nread = 0;
	struct stat st;
	int fd;
	gpointer map;
	char *data;
	enum rspamd_snapshot_result res;
	struct rspamd_shmem_segment *seg;
#ifdef HAVE_SANE_SHMEM
	const char *ft = "shm";
	const char *what = "shm segment name";
#else
	const char *ft = "file";
	const char *what = "file segment path";
#endif

	if (!rspamd_task_sanitize_path(name_tok, namebuf, sizeof(namebuf), what,
								   err)) {
		return NULL;
	}

	if (offset_tok != NULL &&
		!rspamd_strtoul(offset_tok->begin, offset_tok->len, &offset)) {
		g_set_error(err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"invalid %s segment offset: %.*s", ft,
					(int) offset_tok->len, offset_tok->begin);
		return NULL;
	}

	if (length_tok != NULL &&
		!rspamd_strtoul(length_tok->begin, length_tok->len, &length)) {
		g_set_error(err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"invalid %s segment length: %.*s", ft,
					(int) length_tok->len, length_tok->begin);
		return NULL;
	}

#ifdef HAVE_SANE_SHMEM
	fd = shm_open(name, O_RDONLY, 0);
#else
	/*
	 * O_NONBLOCK is essential here: on platforms without POSIX shmem the name
	 * is an ordinary path, and a name that happens to point to a fifo would
	 * otherwise block the whole worker inside open(2) until somebody opens the
	 * writing end of it
	 */
	fd = open(name, O_RDONLY | O_NONBLOCK);
#endif

	if (fd == -1) {
		g_set_error(err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"cannot open %s segment (%s): %s", ft, name,
					strerror(errno));
		return NULL;
	}

	if (fstat(fd, &st) == -1) {
		g_set_error(err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"cannot stat %s segment (%s): %s", ft, name,
					strerror(errno));
		close(fd);

		return NULL;
	}

	if (!S_ISREG(st.st_mode)) {
		g_set_error(err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"%s segment (%s) is not a regular object", ft, name);
		close(fd);

		return NULL;
	}

	if (st.st_size <= 0) {
		g_set_error(err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"empty %s segment (%s)", ft, name);
		close(fd);

		return NULL;
	}

	if ((uint64_t) st.st_size > (uint64_t) G_MAXSIZE) {
		g_set_error(err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"%s segment (%s) is too large to be mapped", ft, name);
		close(fd);

		return NULL;
	}

	if (offset > (gsize) st.st_size) {
		g_set_error(err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"invalid offset %lu (%llu available) for %s segment %s",
					offset, (unsigned long long) st.st_size, ft, name);
		close(fd);

		return NULL;
	}

	if (length_tok == NULL) {
		/* Everything from the offset to the end of the segment */
		length = (gsize) st.st_size - offset;
	}
	else if (length > (gsize) st.st_size - offset) {
		/*
		 * The critical check: offset and length are validated together, as
		 * either of them alone can fit the segment whilst their sum does not
		 */
		g_set_error(err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"invalid length %lu at offset %lu (%llu available) for "
					"%s segment %s",
					length, offset, (unsigned long long) st.st_size, ft, name);
		close(fd);

		return NULL;
	}

	if (max_size > 0 && length > max_size) {
		g_set_error(err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"too large %s segment %s: %lu, maximum is %zu",
					ft, name, length, max_size);
		close(fd);

		return NULL;
	}

	seg = rspamd_mempool_alloc0(pool, sizeof(*seg));
	seg->name = rspamd_mempool_strdup(pool, name);
	seg->offset = offset;
	seg->data_len = length;
	seg->map = NULL;
	seg->map_len = 0;
	seg->fd = -1;

	if (length == 0) {
		/* An empty window must never map the whole object */
		close(fd);
		seg->data = rspamd_mempool_strdup(pool, "");

		return seg;
	}

	/*
	 * The backing object belongs to the client and it can be truncated or
	 * rewritten at any moment, so the parser must never be handed a live
	 * mapping. Read the window straight into pool storage instead of copying it
	 * out of one: a concurrent ftruncate between the fstat above and the copy
	 * would raise SIGBUS on a mapping and take the whole worker down, whereas a
	 * read merely returns fewer bytes.
	 */
	data = rspamd_mempool_alloc(pool, length);
	res = rspamd_task_pread_snapshot(fd, data, length, (off_t) offset, &nread);

	if (res == RSPAMD_SNAPSHOT_ERROR) {
		g_set_error(err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"cannot read %s segment (%s): %s", ft, name,
					strerror(errno));
		close(fd);

		return NULL;
	}

	if (res == RSPAMD_SNAPSHOT_OK) {
		close(fd);
		/* The object may have shrunk under us, so trust what we really got */
		seg->data_len = nread;
		seg->data = data;

		return seg;
	}

	/*
	 * This descriptor cannot be read positionally, which happens for POSIX
	 * shared memory on some platforms, so fall back to mapping. Map merely the
	 * window that is really needed: the offset is rounded down to a page
	 * boundary and the length is extended by the very same delta, so that a
	 * small payload inside a huge object never maps that whole object.
	 */
	page_size = (gsize) sysconf(_SC_PAGESIZE);

	if (page_size == 0 || page_size == (gsize) -1) {
		page_size = 4096;
	}

	aligned_offset = ((gsize) offset / page_size) * page_size;
	delta = (gsize) offset - aligned_offset;
	map_len = (gsize) length + delta;

	map = mmap(NULL, map_len, PROT_READ, MAP_SHARED, fd, (off_t) aligned_offset);

	if (map == MAP_FAILED) {
		g_set_error(err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
					"cannot mmap %s segment (%s): %s", ft, name,
					strerror(errno));
		close(fd);

		return NULL;
	}

	memcpy(data, (const char *) map + delta, length);
	munmap(map, map_len);
	close(fd);

	seg->data = data;

	return seg;
}

gboolean
rspamd_task_allow_file_shm_input(struct rspamd_task *task)
{
	if (task == NULL) {
		return FALSE;
	}

	return (task->protocol_flags &
			RSPAMD_TASK_PROTOCOL_FLAG_ALLOW_FILE_SHM_INPUT) != 0;
}

gboolean
rspamd_task_has_file_shm_input(struct rspamd_task *task)
{
	/* The lookup hash is case insensitive, so lowercase names are enough */
	static const char *privileged_headers[] = {
		"file",
		"path",
		"shm",
		"shm-offset",
		"shm-length",
	};
	unsigned int i;

	if (task == NULL || task->request_headers == NULL) {
		return FALSE;
	}

	for (i = 0; i < G_N_ELEMENTS(privileged_headers); i++) {
		if (rspamd_task_get_request_header(task, privileged_headers[i]) != NULL) {
			return TRUE;
		}
	}

	return FALSE;
}

gboolean
rspamd_task_load_message(struct rspamd_task *task,
						 struct rspamd_http_message *msg, const char *start, gsize len)
{
	char filepath[PATH_MAX];
	int fd;
	rspamd_ftok_t *tok;
	gsize max_message;
	struct stat st;

	if (msg && task->cmd != CMD_CHECK_V3) {
		/*
		 * Header parsing rejects privileged message source controls that this
		 * connection may not use, so its verdict must be honoured here: it has
		 * already set task->err and the request must not be processed further.
		 */
		if (!rspamd_protocol_handle_headers(task, msg)) {
			return FALSE;
		}
	}

	/*
	 * File and shm inputs make rspamd open an arbitrary local object of the
	 * client's choosing, so they are only honoured on the transports that the
	 * accepting worker has explicitly marked as privileged. This is checked
	 * before any of the values is even looked at, hence no stat/open/mmap and
	 * no shm_open can happen for a connection that is not allowed to use them.
	 */
	if (rspamd_task_has_file_shm_input(task) &&
		!rspamd_task_allow_file_shm_input(task)) {
		msg_info_task("deny file/shm message source from %s: this connection is "
					  "not permitted to use privileged inputs; set "
					  "`allow_file_and_shm_inputs = true` for this worker if all "
					  "of its clients are trusted",
					  rspamd_inet_address_to_string_pretty(task->client_addr));
		g_set_error(&task->err, rspamd_task_quark(), 400,
					"file and shm message sources are not allowed "
					"on this connection");
		/* This is a client error, so report it as a genuine 400 */
		task->protocol_flags |= RSPAMD_TASK_PROTOCOL_FLAG_VERBATIM_ERR_CODE;

		return FALSE;
	}

	max_message = (task->cfg != NULL) ? task->cfg->max_message : 0;

	tok = rspamd_task_get_request_header(task, "shm");

	if (tok) {
		/* Shared memory part */
		struct rspamd_shmem_segment *seg;
		rspamd_ftok_t *off_tok, *len_tok;

		off_tok = rspamd_task_get_request_header(task, "shm-offset");
		len_tok = rspamd_task_get_request_header(task, "shm-length");

		seg = rspamd_shmem_segment_map(task->task_pool, tok, off_tok, len_tok,
									   max_message, &task->err);

		if (seg == NULL) {
			return FALSE;
		}

		task->msg.begin = seg->data;
		task->msg.len = seg->data_len;

		msg_info_task("loaded message from shared memory %s "
					  "(%uz size, %uz offset)",
					  seg->name, seg->data_len, seg->offset);
	}
	else {
		/* Try file */
		tok = rspamd_task_get_request_header(task, "file");

		if (tok == NULL) {
			tok = rspamd_task_get_request_header(task, "path");
		}

		if (tok) {
			debug_task("want to scan file %T", tok);

			if (!rspamd_task_sanitize_path(tok, filepath, sizeof(filepath),
										   "file path", &task->err)) {
				return FALSE;
			}

			/*
			 * Open first and validate the descriptor afterwards: a path based
			 * stat(2) says nothing about the object that is actually opened.
			 * O_NONBLOCK: never block the worker on opening a special file.
			 */
			fd = open(filepath, O_RDONLY | O_NONBLOCK);

			if (fd == -1) {
				g_set_error(&task->err, rspamd_task_quark(),
							RSPAMD_PROTOCOL_ERROR,
							"Cannot open file (%s): %s", filepath,
							strerror(errno));
				return FALSE;
			}

			if (fstat(fd, &st) == -1) {
				g_set_error(&task->err, rspamd_task_quark(),
							RSPAMD_PROTOCOL_ERROR,
							"Cannot stat file (%s): %s", filepath,
							strerror(errno));
				close(fd);

				return FALSE;
			}

			if (!S_ISREG(st.st_mode)) {
				g_set_error(&task->err, rspamd_task_quark(),
							RSPAMD_PROTOCOL_ERROR,
							"Not a regular file (%s)", filepath);
				close(fd);

				return FALSE;
			}

			if (st.st_size < 0 ||
				(uint64_t) st.st_size > (uint64_t) G_MAXSIZE) {
				g_set_error(&task->err, rspamd_task_quark(),
							RSPAMD_PROTOCOL_ERROR,
							"Invalid size of file (%s): %lld", filepath,
							(long long) st.st_size);
				close(fd);

				return FALSE;
			}

			/*
			 * A file input must obey the very same limit as an inline body,
			 * and it has to be enforced before anything is read at all
			 */
			if (max_message > 0 && (gsize) st.st_size > max_message) {
				g_set_error(&task->err, rspamd_task_quark(),
							RSPAMD_PROTOCOL_ERROR,
							"Too large file (%s): %zu, maximum is %zu",
							filepath, (gsize) st.st_size, max_message);
				close(fd);

				return FALSE;
			}

			if (G_UNLIKELY(st.st_size == 0)) {
				/* Empty file, exactly as an empty inline message */
				close(fd);
				task->flags |= RSPAMD_TASK_FLAG_EMPTY;
				task->msg.begin = rspamd_mempool_strdup(task->task_pool, "");
				task->msg.len = 0;
			}
			else {
				/*
				 * The file belongs to the client and it can be truncated at any
				 * moment, which would turn a MAP_SHARED mapping into a fault in
				 * the middle of the parser. Take a bounded snapshot instead, so
				 * that the parser is never given a range that can go away.
				 */
				gsize nread = 0;
				char *buf = rspamd_mempool_alloc(task->task_pool,
												 (gsize) st.st_size);

				if (!rspamd_task_read_snapshot(fd, buf, (gsize) st.st_size,
											   &nread)) {
					g_set_error(&task->err, rspamd_task_quark(),
								RSPAMD_PROTOCOL_ERROR,
								"Cannot read file (%s): %s", filepath,
								strerror(errno));
					close(fd);

					return FALSE;
				}

				close(fd);

				task->msg.begin = buf;
				task->msg.len = nread;
			}

			task->msg.fpath = rspamd_mempool_strdup(task->task_pool, filepath);
			task->flags |= RSPAMD_TASK_FLAG_FILE;

			msg_info_task("loaded message from file %s (%uz bytes)", filepath,
						  task->msg.len);
		}
		else {
			/* Plain data */
			task->msg.begin = start;
			task->msg.len = len;
		}
	}


	debug_task("got input of length %z", task->msg.len);

	/* Check compression */
	tok = rspamd_task_get_request_header(task, COMPRESSION_HEADER);

	if (!tok) {
		tok = rspamd_task_get_request_header(task, CONTENT_ENCODING_HEADER);
	}

	if (tok) {
		/* Need to uncompress */
		rspamd_ftok_t t;

		t.begin = "zstd";
		t.len = 4;

		if (rspamd_ftok_casecmp(tok, &t) == 0) {
			gulong dict_id;

			if (!rspamd_libs_reset_decompression(task->cfg->libs_ctx)) {
				g_set_error(&task->err, rspamd_task_quark(),
							RSPAMD_PROTOCOL_ERROR,
							"Cannot decompress, decompressor init failed");

				return FALSE;
			}

			tok = rspamd_task_get_request_header(task, "dictionary");

			if (tok != NULL) {
				/* We need to use custom dictionary */
				if (!rspamd_strtoul(tok->begin, tok->len, &dict_id)) {
					g_set_error(&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
								"Non numeric dictionary");

					return FALSE;
				}

				if (!task->cfg->libs_ctx->in_dict) {
					g_set_error(&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
								"Unknown dictionary, undefined locally");

					return FALSE;
				}

				if (task->cfg->libs_ctx->in_dict->id != dict_id) {
					g_set_error(&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
								"Unknown dictionary, invalid dictionary id");

					return FALSE;
				}
			}

			GError *derr = NULL;
			gsize compressed_len = task->msg.len;
			rspamd_fstring_t *decompressed;

			decompressed = rspamd_zstd_decompress_bounded(task->cfg->libs_ctx->in_zstream,
														  task->msg.begin, task->msg.len,
														  task->cfg->max_message, &derr);

			if (decompressed == NULL) {
				g_set_error(&task->err, rspamd_task_quark(),
							RSPAMD_PROTOCOL_ERROR,
							"Decompression error: %s",
							derr ? derr->message : "unknown error");
				g_clear_error(&derr);

				return FALSE;
			}

			rspamd_mempool_add_destructor(task->task_pool,
										  (rspamd_mempool_destruct_t) rspamd_fstring_free,
										  decompressed);
			task->msg.begin = decompressed->str;
			task->msg.len = decompressed->len;
			task->protocol_flags |= RSPAMD_TASK_PROTOCOL_FLAG_COMPRESSED;

			msg_info_task("loaded message from zstd compressed stream; "
						  "compressed: %ul; uncompressed: %ul",
						  (gulong) compressed_len, (gulong) decompressed->len);
		}
		else {
			g_set_error(&task->err, rspamd_task_quark(), RSPAMD_PROTOCOL_ERROR,
						"Invalid compression method");
			return FALSE;
		}
	}

	if (task->msg.len == 0) {
		task->flags |= RSPAMD_TASK_FLAG_EMPTY;
	}

	return TRUE;
}

static unsigned int
rspamd_task_select_processing_stage(struct rspamd_task *task, unsigned int stages)
{
	unsigned int st, mask;

	mask = task->processed_stages;

	if (mask == 0) {
		st = 0;
	}
	else {
		for (st = 1; mask != 1; st++) {
			mask = mask >> 1u;
		}
	}

	st = 1 << st;

	if (stages & st) {
		return st;
	}
	else if (st < RSPAMD_TASK_STAGE_DONE) {
		/* We assume that the stage that was not requested is done */
		task->processed_stages |= st;
		return rspamd_task_select_processing_stage(task, stages);
	}

	/* We are done */
	return RSPAMD_TASK_STAGE_DONE;
}

gboolean
rspamd_task_process(struct rspamd_task *task, unsigned int stages)
{
	unsigned int st;
	gboolean ret = TRUE, all_done = TRUE;
	GError *stat_error = NULL;

	/* Avoid nested calls */
	if (task->flags & RSPAMD_TASK_FLAG_PROCESSING) {
		return TRUE;
	}

	if (RSPAMD_TASK_IS_PROCESSED(task)) {
		return TRUE;
	}

	task->flags |= RSPAMD_TASK_FLAG_PROCESSING;

	st = rspamd_task_select_processing_stage(task, stages);

	switch (st) {
	case RSPAMD_TASK_STAGE_CONNFILTERS:
		all_done = rspamd_symcache_process_symbols(task, task->cfg->cache, st);
		break;

	case RSPAMD_TASK_STAGE_READ_MESSAGE:
		if (!rspamd_message_parse(task)) {
			ret = FALSE;
		}
		break;

	case RSPAMD_TASK_STAGE_PROCESS_MESSAGE:
		if (!(task->flags & RSPAMD_TASK_FLAG_SKIP_PROCESS)) {
			rspamd_message_process(task);
		}
		break;

	case RSPAMD_TASK_STAGE_PRE_FILTERS:
	case RSPAMD_TASK_STAGE_FILTERS:
		all_done = rspamd_symcache_process_symbols(task, task->cfg->cache, st);
		break;

	case RSPAMD_TASK_STAGE_CLASSIFIERS:
	case RSPAMD_TASK_STAGE_CLASSIFIERS_PRE:
	case RSPAMD_TASK_STAGE_CLASSIFIERS_POST:
		if (!RSPAMD_TASK_IS_EMPTY(task)) {
			if (rspamd_stat_classify(task, task->cfg->lua_state, st, &stat_error) ==
				RSPAMD_STAT_PROCESS_ERROR) {
				msg_err_task("classify error: %e", stat_error);
				g_error_free(stat_error);
			}
		}
		break;

	case RSPAMD_TASK_STAGE_COMPOSITES:
		rspamd_composites_process_task(task);
		task->result->nresults_postfilters = task->result->nresults;
		break;

	case RSPAMD_TASK_STAGE_POST_FILTERS:
		all_done = rspamd_symcache_process_symbols(task, task->cfg->cache,
												   st);

		if (all_done) {
			rspamd_task_result_adjust_grow_factor(task, task->result, task->cfg->grow_factor);
		}

		if (all_done && (task->flags & RSPAMD_TASK_FLAG_LEARN_AUTO) &&
			!RSPAMD_TASK_IS_EMPTY(task) &&
			!(task->flags & (RSPAMD_TASK_FLAG_LEARN_SPAM | RSPAMD_TASK_FLAG_LEARN_HAM | RSPAMD_TASK_FLAG_LEARN_CLASS))) {
			rspamd_stat_check_autolearn(task);
		}
		break;

	case RSPAMD_TASK_STAGE_LEARN:
	case RSPAMD_TASK_STAGE_LEARN_PRE:
	case RSPAMD_TASK_STAGE_LEARN_POST:
		if (task->flags & (RSPAMD_TASK_FLAG_LEARN_SPAM | RSPAMD_TASK_FLAG_LEARN_HAM | RSPAMD_TASK_FLAG_LEARN_CLASS)) {
			if (task->err == NULL) {
				gboolean learn_result = FALSE;

				if (task->flags & RSPAMD_TASK_FLAG_LEARN_CLASS) {
					/* Multi-class learning */
					const char *autolearn_class = rspamd_task_get_autolearn_class(task);
					if (autolearn_class) {
						learn_result = rspamd_stat_learn_class(task, autolearn_class,
															   task->cfg->lua_state, task->classifier,
															   st, &stat_error);
					}
					else {
						g_set_error(&stat_error, g_quark_from_static_string("stat"), 500,
									"No autolearn class specified for multi-class learning");
					}
				}
				else {
					/* Legacy binary learning */
					learn_result = rspamd_stat_learn(task,
													 task->flags & RSPAMD_TASK_FLAG_LEARN_SPAM,
													 task->cfg->lua_state, task->classifier,
													 st, &stat_error);
				}

				if (!learn_result) {

					if (stat_error == NULL) {
						g_set_error(&stat_error,
									g_quark_from_static_string("stat"), 500,
									"Unknown statistics error, found on stage %s;"
									" classifier: %s",
									rspamd_task_stage_name(st), task->classifier);
					}

					if (stat_error->code >= 400) {
						msg_err_task("learn error: %e", stat_error);
					}
					else {
						msg_notice_task("skip learning: %e", stat_error);
					}

					if (!(task->flags & RSPAMD_TASK_FLAG_LEARN_AUTO)) {
						task->err = stat_error;
						task->processed_stages |= RSPAMD_TASK_STAGE_DONE;
					}
					else {
						/* Do not skip idempotent in case of learn error */
						if (stat_error) {
							g_error_free(stat_error);
						}

						task->processed_stages |= RSPAMD_TASK_STAGE_LEARN |
												  RSPAMD_TASK_STAGE_LEARN_PRE |
												  RSPAMD_TASK_STAGE_LEARN_POST;
					}
				}
			}

			/*
			 * Run registered `learn` symbols (e.g. neural) at the main LEARN
			 * stage of a learning task. They read the learn class via the
			 * autolearn_class mempool variable, exactly like the stat learner
			 * above, and are async-aware via the standard session machinery.
			 * The learn-flag gate on the enclosing block keeps them from firing
			 * on a plain scan.
			 */
			if (st == RSPAMD_TASK_STAGE_LEARN && task->err == NULL) {
				all_done = rspamd_symcache_process_symbols(task, task->cfg->cache, st) &&
						   all_done;
			}
		}
		break;
	case RSPAMD_TASK_STAGE_COMPOSITES_POST:
		/* Second run of composites processing for composites that depend on postfilters/stats */
		rspamd_composites_process_task(task);
		break;

	case RSPAMD_TASK_STAGE_IDEMPOTENT:
		/* Stop task timeout */
		if (ev_can_stop(&task->timeout_ev)) {
			ev_timer_stop(task->event_loop, &task->timeout_ev);
		}

		all_done = rspamd_symcache_process_symbols(task, task->cfg->cache, st);
		break;

	case RSPAMD_TASK_STAGE_DONE:
		task->processed_stages |= RSPAMD_TASK_STAGE_DONE;
		break;

	default:
		/* TODO: not implemented stage */
		break;
	}

	if (RSPAMD_TASK_IS_SKIPPED(task)) {
		/* Set all bits except idempotent filters */
		task->processed_stages |= 0x7FFF;
	}

	task->flags &= ~RSPAMD_TASK_FLAG_PROCESSING;

	if (!ret || RSPAMD_TASK_IS_PROCESSED(task)) {
		if (!ret) {
			/* Set processed flags */
			task->processed_stages |= RSPAMD_TASK_STAGE_DONE;
		}

		msg_debug_task("task is processed");

		return ret;
	}

	if (ret) {
		if (rspamd_session_events_pending(task->s) != 0) {
			/* We have events pending, so we consider this stage as incomplete */
			msg_debug_task("need more work on stage %d", st);
		}
		else {
			if (all_done) {
				/* Mark the current stage as done and go to the next stage */
				msg_debug_task("completed stage %d", st);
				task->processed_stages |= st;
			}
			else {
				msg_debug_task("need more processing on stage %d", st);
			}

			/* Tail recursion */
			return rspamd_task_process(task, stages);
		}
	}

	return ret;
}

struct rspamd_email_address *
rspamd_task_get_sender(struct rspamd_task *task)
{
	return task->from_envelope;
}

struct rspamd_email_address *
rspamd_task_get_original_sender(struct rspamd_task *task)
{
	if (task->from_envelope_orig) {
		return task->from_envelope_orig;
	}

	return task->from_envelope;
}

static const char *
rspamd_task_cache_principal_recipient(struct rspamd_task *task,
									  const char *rcpt, gsize len)
{
	char *rcpt_lc;

	if (rcpt == NULL) {
		return NULL;
	}

	rcpt_lc = rspamd_mempool_alloc(task->task_pool, len + 1);
	rspamd_strlcpy(rcpt_lc, rcpt, len + 1);
	rspamd_str_lc(rcpt_lc, len);

	rspamd_mempool_set_variable(task->task_pool,
								RSPAMD_MEMPOOL_PRINCIPAL_RECIPIENT, rcpt_lc, NULL);

	return rcpt_lc;
}

const char *
rspamd_task_get_principal_recipient(struct rspamd_task *task)
{
	const char *val;
	struct rspamd_email_address *addr;
	unsigned int i;

	val = rspamd_mempool_get_variable(task->task_pool,
									  RSPAMD_MEMPOOL_PRINCIPAL_RECIPIENT);

	if (val) {
		return val;
	}

	if (task->deliver_to) {
		return rspamd_task_cache_principal_recipient(task, task->deliver_to,
													 strlen(task->deliver_to));
	}
	if (task->rcpt_envelope != NULL) {

		PTR_ARRAY_FOREACH(task->rcpt_envelope, i, addr)
		{
			if (addr->addr && !(addr->flags & RSPAMD_EMAIL_ADDR_ORIGINAL)) {
				return rspamd_task_cache_principal_recipient(task, addr->addr,
															 addr->addr_len);
			}
		}
	}

	GPtrArray *rcpt_mime = MESSAGE_FIELD_CHECK(task, rcpt_mime);
	if (rcpt_mime != NULL && rcpt_mime->len > 0) {
		PTR_ARRAY_FOREACH(rcpt_mime, i, addr)
		{
			if (addr->addr && !(addr->flags & RSPAMD_EMAIL_ADDR_ORIGINAL)) {
				return rspamd_task_cache_principal_recipient(task, addr->addr,
															 addr->addr_len);
			}
		}
	}

	return NULL;
}

gboolean
rspamd_learn_task_spam(struct rspamd_task *task,
					   gboolean is_spam,
					   const char *classifier,
					   GError **err)
{
	/* Use unified class-based approach internally */
	const char *class_name = is_spam ? "spam" : "ham";

	/* Disable learn auto flag to avoid bad learn codes */
	task->flags &= ~RSPAMD_TASK_FLAG_LEARN_AUTO;

	/* Use the unified class-based learning approach */
	rspamd_task_set_autolearn_class(task, class_name);

	task->classifier = classifier;

	return TRUE;
}

static gboolean
rspamd_task_log_check_condition(struct rspamd_task *task,
								struct rspamd_log_format *lf)
{
	gboolean ret = FALSE;

	switch (lf->type) {
	case RSPAMD_LOG_MID:
		if (MESSAGE_FIELD_CHECK(task, message_id) &&
			strcmp(MESSAGE_FIELD(task, message_id), "undef") != 0) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_QID:
		if (task->queue_id && strcmp(task->queue_id, "undef") != 0) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_USER:
		if (task->auth_user) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_IP:
		if (task->from_addr && rspamd_ip_is_valid(task->from_addr)) {
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
		if (MESSAGE_FIELD_CHECK(task, rcpt_mime) &&
			MESSAGE_FIELD(task, rcpt_mime)->len > 0) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_SMTP_FROM:
		if (task->from_envelope) {
			ret = TRUE;
		}
		break;
	case RSPAMD_LOG_MIME_FROM:
		if (MESSAGE_FIELD_CHECK(task, from_mime) &&
			MESSAGE_FIELD(task, from_mime)->len > 0) {
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
static int
rspamd_task_compare_log_sym(gconstpointer a, gconstpointer b)
{
	const struct rspamd_symbol_result *s1 = *(const struct rspamd_symbol_result **) a,
									  *s2 = *(const struct rspamd_symbol_result **) b;
	double w1, w2;


	w1 = fabs(s1->score);
	w2 = fabs(s2->score);

	if (w1 == w2 && s1->name && s2->name) {
		return strcmp(s1->name, s2->name);
	}

	return (w2 - w1) * 1000.0;
}

static int
rspamd_task_compare_log_group(gconstpointer a, gconstpointer b)
{
	const struct rspamd_symbols_group *s1 = *(const struct rspamd_symbols_group **) a,
									  *s2 = *(const struct rspamd_symbols_group **) b;

	return strcmp(s1->name, s2->name);
}


static rspamd_ftok_t
rspamd_task_log_metric_res(struct rspamd_task *task,
						   struct rspamd_log_format *lf)
{
	static char scorebuf[32];
	rspamd_ftok_t res = {.begin = NULL, .len = 0};
	struct rspamd_scan_result *mres;
	gboolean first = TRUE;
	rspamd_fstring_t *symbuf;
	struct rspamd_symbol_result *sym;
	GPtrArray *sorted_symbols;
	struct rspamd_action *act;
	struct rspamd_symbols_group *gr;
	unsigned int i, j;
	khiter_t k;
	unsigned int max_log_elts = task->cfg->log_task_max_elts;

	mres = task->result;
	act = rspamd_check_action_metric(task, NULL, NULL);

	if (mres != NULL) {
		switch (lf->type) {
		case RSPAMD_LOG_ISSPAM:
			if (RSPAMD_TASK_IS_SKIPPED(task)) {
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
			res.len = strlen(res.begin);
			break;
		case RSPAMD_LOG_SCORES:
			res.len = rspamd_snprintf(scorebuf, sizeof(scorebuf), "%.2f/%.2f",
									  mres->score, rspamd_task_get_required_score(task, mres));
			res.begin = scorebuf;
			break;
		case RSPAMD_LOG_SYMBOLS:
			symbuf = rspamd_fstring_sized_new(128);
			sorted_symbols = g_ptr_array_sized_new(kh_size(mres->symbols));

			kh_foreach_value(mres->symbols, sym, {
				if (!(sym->flags & RSPAMD_SYMBOL_RESULT_IGNORED)) {
					g_ptr_array_add(sorted_symbols, (gpointer) sym);
				}
			});

			g_ptr_array_sort(sorted_symbols, rspamd_task_compare_log_sym);

			for (i = 0; i < sorted_symbols->len; i++) {
				sym = g_ptr_array_index(sorted_symbols, i);

				if (first) {
					rspamd_printf_fstring(&symbuf, "%s", sym->name);
				}
				else {
					rspamd_printf_fstring(&symbuf, ",%s", sym->name);
				}

				if (lf->flags & RSPAMD_LOG_FMT_FLAG_SYMBOLS_SCORES) {
					rspamd_printf_fstring(&symbuf, "(%.2f)", sym->score);
				}

				if (lf->flags & RSPAMD_LOG_FMT_FLAG_SYMBOLS_PARAMS) {
					rspamd_printf_fstring(&symbuf, "{");

					if (sym->options) {
						struct rspamd_symbol_option *opt;

						j = 0;

						DL_FOREACH(sym->opts_head, opt)
						{
							rspamd_printf_fstring(&symbuf, "%*s;",
												  (int) opt->optlen, opt->option);

							if (j >= max_log_elts && opt->next) {
								rspamd_printf_fstring(&symbuf, "...;");
								break;
							}

							j++;
						}
					}

					rspamd_printf_fstring(&symbuf, "}");
				}

				first = FALSE;
			}

			g_ptr_array_free(sorted_symbols, TRUE);

			rspamd_mempool_add_destructor(task->task_pool,
										  (rspamd_mempool_destruct_t) rspamd_fstring_free,
										  symbuf);
			rspamd_mempool_notify_alloc(task->task_pool, symbuf->len);
			res.begin = symbuf->str;
			res.len = symbuf->len;
			break;

		case RSPAMD_LOG_GROUPS:
		case RSPAMD_LOG_PUBLIC_GROUPS:

			symbuf = rspamd_fstring_sized_new(128);
			sorted_symbols = g_ptr_array_sized_new(kh_size(mres->sym_groups));

			kh_foreach_key(mres->sym_groups, gr, {
				if (!(gr->flags & RSPAMD_SYMBOL_GROUP_PUBLIC)) {
					if (lf->type == RSPAMD_LOG_PUBLIC_GROUPS) {
						continue;
					}
				}

				g_ptr_array_add(sorted_symbols, gr);
			});

			g_ptr_array_sort(sorted_symbols, rspamd_task_compare_log_group);

			for (i = 0; i < sorted_symbols->len; i++) {
				gr = g_ptr_array_index(sorted_symbols, i);

				if (first) {
					rspamd_printf_fstring(&symbuf, "%s", gr->name);
				}
				else {
					rspamd_printf_fstring(&symbuf, ",%s", gr->name);
				}

				k = kh_get(rspamd_symbols_group_hash, mres->sym_groups, gr);

				rspamd_printf_fstring(&symbuf, "(%.2f)",
									  kh_value(mres->sym_groups, k));

				first = FALSE;
			}

			g_ptr_array_free(sorted_symbols, TRUE);

			rspamd_mempool_add_destructor(task->task_pool,
										  (rspamd_mempool_destruct_t) rspamd_fstring_free,
										  symbuf);
			rspamd_mempool_notify_alloc(task->task_pool, symbuf->len);
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
rspamd_task_log_write_var(struct rspamd_task *task, rspamd_fstring_t *logbuf,
						  const rspamd_ftok_t *var, const rspamd_ftok_t *content)
{
	rspamd_fstring_t *res = logbuf;
	const char *p, *c, *end;

	if (content == NULL) {
		/* Just output variable */
		res = rspamd_fstring_append(res, var->begin, var->len);
	}
	else {
		/* Replace $ with variable value */
		p = content->begin;
		c = p;
		end = p + content->len;

		while (p < end) {
			if (*p == '$') {
				if (p > c) {
					res = rspamd_fstring_append(res, c, p - c);
				}

				res = rspamd_fstring_append(res, var->begin, var->len);
				p++;
				c = p;
			}
			else {
				p++;
			}
		}

		if (p > c) {
			res = rspamd_fstring_append(res, c, p - c);
		}
	}

	return res;
}

static rspamd_fstring_t *
rspamd_task_write_ialist(struct rspamd_task *task,
						 GPtrArray *addrs, int lim,
						 struct rspamd_log_format *lf,
						 rspamd_fstring_t *logbuf)
{
	rspamd_fstring_t *res = logbuf, *varbuf;
	rspamd_ftok_t var = {.begin = NULL, .len = 0};
	struct rspamd_email_address *addr;
	int i, nchars = 0, wr = 0, cur_chars;
	gboolean has_orig = FALSE;
	unsigned int max_log_elts = task->cfg->log_task_max_elts;

	if (addrs && lim <= 0) {
		lim = addrs->len;
	}

	PTR_ARRAY_FOREACH(addrs, i, addr)
	{
		if (addr->flags & RSPAMD_EMAIL_ADDR_ORIGINAL) {
			has_orig = TRUE;
			break;
		}
	}

	varbuf = rspamd_fstring_new();

	PTR_ARRAY_FOREACH(addrs, i, addr)
	{
		if (wr >= lim) {
			break;
		}

		if (has_orig) {
			/* Report merely original addresses */
			if (!(addr->flags & RSPAMD_EMAIL_ADDR_ORIGINAL)) {
				continue;
			}
		}

		bool last = i == lim - 1;

		cur_chars = addr->addr_len;
		varbuf = rspamd_fstring_append(varbuf, addr->addr,
									   cur_chars);
		nchars += cur_chars;
		wr++;

		if (varbuf->len > 0 && !last) {
			varbuf = rspamd_fstring_append(varbuf, ",", 1);
		}

		if (!last && (wr >= max_log_elts || nchars >= max_log_elts * 16)) {
			varbuf = rspamd_fstring_append(varbuf, "...", 3);
			break;
		}
	}

	if (varbuf->len > 0) {
		var.begin = varbuf->str;
		var.len = varbuf->len;
		res = rspamd_task_log_write_var(task, logbuf,
										&var, (const rspamd_ftok_t *) lf->data);
	}

	rspamd_fstring_free(varbuf);

	return res;
}

static rspamd_fstring_t *
rspamd_task_write_addr_list(struct rspamd_task *task,
							GPtrArray *addrs, int lim,
							struct rspamd_log_format *lf,
							rspamd_fstring_t *logbuf)
{
	rspamd_fstring_t *res = logbuf, *varbuf;
	rspamd_ftok_t var = {.begin = NULL, .len = 0};
	struct rspamd_email_address *addr;
	unsigned int max_log_elts = task->cfg->log_task_max_elts;
	unsigned int i;

	if (lim <= 0) {
		lim = addrs->len;
	}

	varbuf = rspamd_fstring_new();

	for (i = 0; i < lim; i++) {
		addr = g_ptr_array_index(addrs, i);
		bool last = i == lim - 1;

		if (addr->addr) {
			varbuf = rspamd_fstring_append(varbuf, addr->addr, addr->addr_len);
		}

		if (varbuf->len > 0 && !last) {
			varbuf = rspamd_fstring_append(varbuf, ",", 1);
		}

		if (!last && i >= max_log_elts) {
			varbuf = rspamd_fstring_append(varbuf, "...", 3);
			break;
		}
	}

	if (varbuf->len > 0) {
		var.begin = varbuf->str;
		var.len = varbuf->len;
		res = rspamd_task_log_write_var(task, logbuf,
										&var, (const rspamd_ftok_t *) lf->data);
	}

	rspamd_fstring_free(varbuf);

	return res;
}

static rspamd_fstring_t *
rspamd_task_log_variable(struct rspamd_task *task,
						 struct rspamd_log_format *lf, rspamd_fstring_t *logbuf)
{
	rspamd_fstring_t *res = logbuf;
	rspamd_ftok_t var = {.begin = NULL, .len = 0};
	static char numbuf[128];
	static const char undef[] = "undef";

	switch (lf->type) {
	/* String vars */
	case RSPAMD_LOG_MID:
		if (MESSAGE_FIELD_CHECK(task, message_id)) {
			var.begin = MESSAGE_FIELD(task, message_id);
			var.len = strlen(var.begin);
		}
		else {
			var.begin = undef;
			var.len = sizeof(undef) - 1;
		}
		break;
	case RSPAMD_LOG_QID:
		if (task->queue_id) {
			var.begin = task->queue_id;
			var.len = strlen(var.begin);
		}
		else {
			var.begin = undef;
			var.len = sizeof(undef) - 1;
		}
		break;
	case RSPAMD_LOG_USER:
		if (task->auth_user) {
			var.begin = task->auth_user;
			var.len = strlen(var.begin);
		}
		else {
			var.begin = undef;
			var.len = sizeof(undef) - 1;
		}
		break;
	case RSPAMD_LOG_IP:
		if (task->from_addr && rspamd_ip_is_valid(task->from_addr)) {
			var.begin = rspamd_inet_address_to_string(task->from_addr);
			var.len = strlen(var.begin);
		}
		else {
			var.begin = undef;
			var.len = sizeof(undef) - 1;
		}
		break;
	/* Numeric vars */
	case RSPAMD_LOG_LEN:
		var.len = rspamd_snprintf(numbuf, sizeof(numbuf), "%uz",
								  task->msg.len);
		var.begin = numbuf;
		break;
	case RSPAMD_LOG_DNS_REQ:
		var.len = rspamd_snprintf(numbuf, sizeof(numbuf), "%uD",
								  task->dns_requests);
		var.begin = numbuf;
		break;
	case RSPAMD_LOG_TIME_REAL:
	case RSPAMD_LOG_TIME_VIRTUAL:
		var.begin = rspamd_log_check_time(task->task_timestamp,
										  task->time_real_finish,
										  task->cfg->clock_res);
		var.len = strlen(var.begin);
		break;
	/* InternetAddress vars */
	case RSPAMD_LOG_SMTP_FROM:
		if (task->from_envelope) {
			var.begin = task->from_envelope->addr;
			var.len = task->from_envelope->addr_len;
		}
		break;
	case RSPAMD_LOG_MIME_FROM:
		if (MESSAGE_FIELD_CHECK(task, from_mime)) {
			return rspamd_task_write_ialist(task,
											MESSAGE_FIELD(task, from_mime),
											1,
											lf,
											logbuf);
		}
		break;
	case RSPAMD_LOG_SMTP_RCPT:
		if (task->rcpt_envelope) {
			return rspamd_task_write_addr_list(task, task->rcpt_envelope, 1, lf,
											   logbuf);
		}
		break;
	case RSPAMD_LOG_MIME_RCPT:
		if (MESSAGE_FIELD_CHECK(task, rcpt_mime)) {
			return rspamd_task_write_ialist(task,
											MESSAGE_FIELD(task, rcpt_mime),
											1,
											lf,
											logbuf);
		}
		break;
	case RSPAMD_LOG_SMTP_RCPTS:
		if (task->rcpt_envelope) {
			return rspamd_task_write_addr_list(task, task->rcpt_envelope, -1, lf,
											   logbuf);
		}
		break;
	case RSPAMD_LOG_MIME_RCPTS:
		if (MESSAGE_FIELD_CHECK(task, rcpt_mime)) {
			return rspamd_task_write_ialist(task,
											MESSAGE_FIELD(task, rcpt_mime),
											-1, /* All addresses */
											lf,
											logbuf);
		}
		break;
	case RSPAMD_LOG_DIGEST:
		if (task->message) {
			var.len = rspamd_snprintf(numbuf, sizeof(numbuf), "%*xs",
									  (int) sizeof(MESSAGE_FIELD(task, digest)),
									  MESSAGE_FIELD(task, digest));
			var.begin = numbuf;
		}
		else {
			var.begin = undef;
			var.len = sizeof(undef) - 1;
		}
		break;
	case RSPAMD_LOG_FILENAME:
		if (task->msg.fpath) {
			var.len = strlen(task->msg.fpath);
			var.begin = task->msg.fpath;
		}
		else {
			var.begin = undef;
			var.len = sizeof(undef) - 1;
		}
		break;
	case RSPAMD_LOG_FORCED_ACTION:
		if (task->result->passthrough_result) {
			struct rspamd_passthrough_result *pr = task->result->passthrough_result;

			if (!isnan(pr->target_score)) {
				var.len = rspamd_snprintf(numbuf, sizeof(numbuf),
										  "%s \"%s\"; score=%.2f (set by %s)",
										  pr->action->name,
										  pr->message,
										  pr->target_score,
										  pr->module);
			}
			else {
				var.len = rspamd_snprintf(numbuf, sizeof(numbuf),
										  "%s \"%s\"; score=nan (set by %s)",
										  pr->action->name,
										  pr->message,
										  pr->module);
			}
			var.begin = numbuf;
		}
		else {
			var.begin = undef;
			var.len = sizeof(undef) - 1;
		}
		break;
	case RSPAMD_LOG_SETTINGS_ID:
		if (task->settings_elt) {
			var.begin = task->settings_elt->name;
			var.len = strlen(task->settings_elt->name);
		}
		else {
			var.begin = undef;
			var.len = sizeof(undef) - 1;
		}
		break;
	case RSPAMD_LOG_MEMPOOL_SIZE:
		var.len = rspamd_snprintf(numbuf, sizeof(numbuf),
								  "%Hz",
								  rspamd_mempool_get_used_size(task->task_pool));
		var.begin = numbuf;
		break;
	case RSPAMD_LOG_MEMPOOL_WASTE:
		var.len = rspamd_snprintf(numbuf, sizeof(numbuf),
								  "%Hz",
								  rspamd_mempool_get_wasted_size(task->task_pool));
		var.begin = numbuf;
		break;
	default:
		var = rspamd_task_log_metric_res(task, lf);
		break;
	}

	if (var.len > 0) {
		res = rspamd_task_log_write_var(task, logbuf,
										&var, (const rspamd_ftok_t *) lf->data);
	}

	return res;
}

void rspamd_task_write_log(struct rspamd_task *task)
{
	rspamd_fstring_t *logbuf;
	struct rspamd_log_format *lf;
	struct rspamd_task **ptask;
	const char *lua_str;
	gsize lua_str_len;
	lua_State *L;

	g_assert(task != NULL);

	if (task->cfg->log_format == NULL ||
		(task->flags & RSPAMD_TASK_FLAG_NO_LOG)) {
		msg_debug_task("skip logging due to no log flag");
		return;
	}

	logbuf = rspamd_fstring_sized_new(1000);

	DL_FOREACH(task->cfg->log_format, lf)
	{
		switch (lf->type) {
		case RSPAMD_LOG_STRING:
			logbuf = rspamd_fstring_append(logbuf, lf->data, lf->len);
			break;
		case RSPAMD_LOG_LUA:
			L = task->cfg->lua_state;
			lua_rawgeti(L, LUA_REGISTRYINDEX, GPOINTER_TO_INT(lf->data));
			ptask = lua_newuserdata(L, sizeof(*ptask));
			rspamd_lua_setclass(L, rspamd_task_classname, -1);
			*ptask = task;

			if (lua_pcall(L, 1, 1, 0) != 0) {
				msg_err_task("call to log function failed: %s",
							 lua_tostring(L, -1));
				lua_pop(L, 1);
			}
			else {
				lua_str = lua_tolstring(L, -1, &lua_str_len);

				if (lua_str != NULL) {
					logbuf = rspamd_fstring_append(logbuf, lua_str, lua_str_len);
				}
				lua_pop(L, 1);
			}
			break;
		default:
			/* We have a variable in log format */
			if (lf->flags & RSPAMD_LOG_FMT_FLAG_CONDITION) {
				if (!rspamd_task_log_check_condition(task, lf)) {
					continue;
				}
			}

			logbuf = rspamd_task_log_variable(task, lf, logbuf);
			break;
		}
	}

	msg_notice_task("%V", logbuf);

	rspamd_fstring_free(logbuf);
}

double
rspamd_task_get_required_score(struct rspamd_task *task, struct rspamd_scan_result *m)
{
	if (m == NULL) {
		m = task->result;

		if (m == NULL) {
			return NAN;
		}
	}

	for (unsigned int i = m->nactions; i-- > 0;) {
		struct rspamd_action_config *action_lim = &m->actions_config[i];


		if (!isnan(action_lim->cur_limit) &&
			!(action_lim->action->flags & (RSPAMD_ACTION_NO_THRESHOLD | RSPAMD_ACTION_HAM))) {
			return m->actions_config[i].cur_limit;
		}
	}

	return NAN;
}

rspamd_ftok_t *
rspamd_task_get_request_header(struct rspamd_task *task,
							   const char *name)
{
	struct rspamd_request_header_chain *ret =
		rspamd_task_get_request_header_multiple(task, name);

	if (ret) {
		return ret->hdr;
	}

	return NULL;
}

struct rspamd_request_header_chain *
rspamd_task_get_request_header_multiple(struct rspamd_task *task,
										const char *name)
{
	struct rspamd_request_header_chain *ret = NULL;
	rspamd_ftok_t srch;
	khiter_t k;

	srch.begin = (char *) name;
	srch.len = strlen(name);

	k = kh_get(rspamd_req_headers_hash, task->request_headers,
			   &srch);

	if (k != kh_end(task->request_headers)) {
		ret = kh_value(task->request_headers, k);
	}

	return ret;
}


void rspamd_task_add_request_header(struct rspamd_task *task,
									rspamd_ftok_t *name, rspamd_ftok_t *value)
{

	khiter_t k;
	int res;
	struct rspamd_request_header_chain *chain, *nchain;

	k = kh_put(rspamd_req_headers_hash, task->request_headers,
			   name, &res);

	if (res == 0) {
		/* Existing name */
		nchain = rspamd_mempool_alloc(task->task_pool, sizeof(*nchain));
		nchain->hdr = value;
		nchain->next = NULL;
		chain = kh_value(task->request_headers, k);

		/* Slow but OK here */
		LL_APPEND(chain, nchain);
	}
	else {
		nchain = rspamd_mempool_alloc(task->task_pool, sizeof(*nchain));
		nchain->hdr = value;
		nchain->next = NULL;

		kh_value(task->request_headers, k) = nchain;
	}
}


void rspamd_task_profile_set(struct rspamd_task *task, const char *key,
							 double value)
{
	GHashTable *tbl;
	double *pval;

	if (key == NULL) {
		return;
	}

	tbl = rspamd_mempool_get_variable(task->task_pool, RSPAMD_MEMPOOL_PROFILE);

	if (tbl == NULL) {
		tbl = g_hash_table_new(rspamd_str_hash, rspamd_str_equal);
		rspamd_mempool_set_variable(task->task_pool, RSPAMD_MEMPOOL_PROFILE,
									tbl, (rspamd_mempool_destruct_t) g_hash_table_unref);
	}

	pval = g_hash_table_lookup(tbl, key);

	if (pval == NULL) {
		pval = rspamd_mempool_alloc(task->task_pool, sizeof(*pval));
		*pval = value;
		g_hash_table_insert(tbl, (void *) key, pval);
	}
	else {
		*pval = value;
	}
}

double *
rspamd_task_profile_get(struct rspamd_task *task, const char *key)
{
	GHashTable *tbl;
	double *pval = NULL;

	tbl = rspamd_mempool_get_variable(task->task_pool, RSPAMD_MEMPOOL_PROFILE);

	if (tbl != NULL) {
		pval = g_hash_table_lookup(tbl, key);
	}

	return pval;
}


gboolean
rspamd_task_set_finish_time(struct rspamd_task *task)
{
	if (isnan(task->time_real_finish)) {
		task->time_real_finish = ev_time();

		return TRUE;
	}

	return FALSE;
}

const char *
rspamd_task_stage_name(enum rspamd_task_stage stg)
{
	const char *ret = "unknown stage";

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

static const char *
rspamd_task_session_item_name_resolver(gpointer ud)
{
	struct rspamd_task *task = ud;
	struct rspamd_symcache_dynamic_item *item;

	if (task == NULL) {
		return NULL;
	}

	item = rspamd_symcache_get_cur_item(task);
	if (item == NULL) {
		return NULL;
	}

	return rspamd_symcache_dyn_item_name(task, item);
}

struct rspamd_async_session *
rspamd_task_create_session(struct rspamd_task *task,
						   rspamd_mempool_t *pool,
						   session_finalizer_t fin,
						   event_finalizer_t restore,
						   event_finalizer_t cleanup)
{
	struct rspamd_async_session *s;

	g_assert(task != NULL);

	s = rspamd_session_create(pool, fin, restore, cleanup, task);
	rspamd_session_set_item_name_resolver(s, rspamd_task_session_item_name_resolver);

	return s;
}

static void
rspamd_task_timeout_log_state(struct rspamd_task *task)
{
	GString *pending, *inflight;

	pending = rspamd_session_describe_pending(task->s);
	if (pending != NULL) {
		msg_info_task("pending async events at timeout: %v", pending);
		g_string_free(pending, TRUE);
	}

	inflight = rspamd_symcache_describe_inflight_symbols(task);
	if (inflight != NULL) {
		msg_info_task("inflight symbols at timeout: %v", inflight);
		g_string_free(inflight, TRUE);
	}
}

void rspamd_task_timeout(EV_P_ ev_timer *w, int revents)
{
	struct rspamd_task *task = (struct rspamd_task *) w->data;

	if (!(task->processed_stages & RSPAMD_TASK_STAGE_FILTERS)) {
		ev_now_update_if_cheap(task->event_loop);
		msg_info_task("processing of task time out: %.1fs spent; %.1fs limit; "
					  "forced processing",
					  ev_now(task->event_loop) - task->task_timestamp,
					  w->repeat);
		rspamd_task_timeout_log_state(task);

		if (task->cfg->soft_reject_on_timeout) {
			struct rspamd_action *action, *soft_reject;

			action = rspamd_check_action_metric(task, NULL, NULL);

			if (action->action_type != METRIC_ACTION_REJECT) {
				soft_reject = rspamd_config_get_action_by_type(task->cfg,
															   METRIC_ACTION_SOFT_REJECT);
				rspamd_add_passthrough_result(task,
											  soft_reject,
											  0,
											  NAN,
											  "timeout processing message",
											  "task timeout",
											  0, NULL);
			}
		}

		ev_timer_again(EV_A_ w);
		task->processed_stages |= RSPAMD_TASK_STAGE_FILTERS;
		rspamd_session_cleanup(task->s, true);
		rspamd_task_process(task, RSPAMD_TASK_PROCESS_ALL);
		rspamd_session_pending(task->s);
	}
	else {
		/* Postprocessing timeout */
		msg_info_task("post-processing of task time out: %.1f second spent; forced processing",
					  ev_now(task->event_loop) - task->task_timestamp);
		rspamd_task_timeout_log_state(task);

		if (task->cfg->soft_reject_on_timeout) {
			struct rspamd_action *action, *soft_reject;

			action = rspamd_check_action_metric(task, NULL, NULL);

			if (action->action_type != METRIC_ACTION_REJECT) {
				soft_reject = rspamd_config_get_action_by_type(task->cfg,
															   METRIC_ACTION_SOFT_REJECT);
				rspamd_add_passthrough_result(task,
											  soft_reject,
											  0,
											  NAN,
											  "timeout post-processing message",
											  "task timeout",
											  0, NULL);
			}
		}

		ev_timer_stop(EV_A_ w);
		task->processed_stages |= RSPAMD_TASK_STAGE_DONE;
		rspamd_session_cleanup(task->s, true);
		rspamd_task_process(task, RSPAMD_TASK_PROCESS_ALL);
		rspamd_session_pending(task->s);
	}
}

void rspamd_worker_guard_handler(EV_P_ ev_io *w, int revents)
{
	struct rspamd_task *task = (struct rspamd_task *) w->data;
	char fake_buf[1024];
	gssize r;

	r = read(w->fd, fake_buf, sizeof(fake_buf));

	if (r > 0) {
		msg_warn_task("received extra data after task is loaded, ignoring");
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
				msg_info_task("workaround for shutdown enabled, please update "
							  "your client, this support might be removed in future");
				shutdown(w->fd, SHUT_RD);
				ev_io_stop(task->event_loop, &task->guard_ev);
			}
			else {
				msg_err_task("the peer has closed connection unexpectedly");
				rspamd_session_destroy(task->s);
			}
		}
		else if (errno != EAGAIN) {
			msg_err_task("the peer has closed connection unexpectedly: %s",
						 strerror(errno));
			rspamd_session_destroy(task->s);
		}
		else {
			return;
		}
	}
}

/*
 * ESMTP arguments management functions
 */

void rspamd_task_set_mail_esmtp_args(struct rspamd_task *task, GHashTable *args)
{
	if (task && args) {
		task->mail_esmtp_args = args;
	}
}

void rspamd_task_set_rcpt_esmtp_args(struct rspamd_task *task, GPtrArray *args)
{
	if (task && args) {
		task->rcpt_esmtp_args = args;
	}
}

GHashTable *
rspamd_task_get_mail_esmtp_args(struct rspamd_task *task)
{
	if (task) {
		return task->mail_esmtp_args;
	}
	return NULL;
}

GPtrArray *
rspamd_task_get_rcpt_esmtp_args(struct rspamd_task *task)
{
	if (task) {
		return task->rcpt_esmtp_args;
	}
	return NULL;
}
