/*
 * Copyright 2026 Vsevolod Stakhov
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
#include "config.h"
#include "memory_stat.h"
#include "rspamd.h"
#include "rspamd_control.h"
#include "worker_util.h"
#include "libutil/util.h"
#include "libutil/mem_pool.h"
#include "libutil/printf.h"
#include "libutil/addr.h"
#include "lua/lua_common.h"
#include "logger.h"
#include "ucl.h"
#include "unix-std.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <cerrno>
#include <cstring>

#ifdef WITH_JEMALLOC
#include <jemalloc/jemalloc.h>
#endif

namespace {

void emit_process_info(ucl_object_t *parent)
{
	struct rspamd_proc_mem_info info;

	if (!rspamd_get_process_memory_info(&info)) {
		return;
	}

	auto *obj = ucl_object_typed_new(UCL_OBJECT);

	ucl_object_insert_key(obj, ucl_object_fromint(info.vm_size), "vm_size", 0, false);
	ucl_object_insert_key(obj, ucl_object_fromint(info.vm_rss), "vm_rss", 0, false);

	if (info.vm_data) {
		ucl_object_insert_key(obj, ucl_object_fromint(info.vm_data), "vm_data", 0, false);
	}
	if (info.vm_stack) {
		ucl_object_insert_key(obj, ucl_object_fromint(info.vm_stack), "vm_stack", 0, false);
	}
	if (info.vm_text) {
		ucl_object_insert_key(obj, ucl_object_fromint(info.vm_text), "vm_text", 0, false);
	}
	if (info.vm_lib) {
		ucl_object_insert_key(obj, ucl_object_fromint(info.vm_lib), "vm_lib", 0, false);
	}
	if (info.vm_pte) {
		ucl_object_insert_key(obj, ucl_object_fromint(info.vm_pte), "vm_pte", 0, false);
	}
	if (info.rss_anon) {
		ucl_object_insert_key(obj, ucl_object_fromint(info.rss_anon), "rss_anon", 0, false);
	}
	if (info.rss_file) {
		ucl_object_insert_key(obj, ucl_object_fromint(info.rss_file), "rss_file", 0, false);
	}
	if (info.rss_shmem) {
		ucl_object_insert_key(obj, ucl_object_fromint(info.rss_shmem), "rss_shmem", 0, false);
	}

	ucl_object_insert_key(parent, obj, "process", 0, false);
}

uint64_t
emit_mempool_info(ucl_object_t *parent)
{
	rspamd_mempool_stat_t agg;
	memset(&agg, 0, sizeof(agg));
	rspamd_mempool_stat(&agg);

	auto *mp = ucl_object_typed_new(UCL_OBJECT);

	auto *aggregate = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(aggregate, ucl_object_fromint(agg.pools_allocated),
						  "pools_allocated", 0, false);
	ucl_object_insert_key(aggregate, ucl_object_fromint(agg.pools_freed),
						  "pools_freed", 0, false);
	ucl_object_insert_key(aggregate, ucl_object_fromint(agg.bytes_allocated),
						  "bytes_allocated", 0, false);
	ucl_object_insert_key(aggregate, ucl_object_fromint(agg.chunks_allocated),
						  "chunks_allocated", 0, false);
	ucl_object_insert_key(aggregate, ucl_object_fromint(agg.shared_chunks_allocated),
						  "shared_chunks_allocated", 0, false);
	ucl_object_insert_key(aggregate, ucl_object_fromint(agg.chunks_freed),
						  "chunks_freed", 0, false);
	ucl_object_insert_key(aggregate, ucl_object_fromint(agg.oversized_chunks),
						  "oversized_chunks", 0, false);
	ucl_object_insert_key(aggregate, ucl_object_fromint(agg.fragmented_size),
						  "fragmented_size", 0, false);
	ucl_object_insert_key(mp, aggregate, "aggregate", 0, false);

	auto *entries = ucl_object_typed_new(UCL_ARRAY);
	struct foreach_ctx {
		ucl_object_t *array;
	} ctx{entries};

	rspamd_mempool_entries_foreach(
		[](const rspamd_mempool_entry_stat_t *st, void *ud) {
			auto *c = static_cast<foreach_ctx *>(ud);
			auto *e = ucl_object_typed_new(UCL_OBJECT);

			ucl_object_insert_key(e, ucl_object_fromstring(st->src), "src", 0, false);
			ucl_object_insert_key(e, ucl_object_fromint(st->cur_suggestion),
								  "cur_suggestion", 0, false);
			ucl_object_insert_key(e, ucl_object_fromint(st->cur_elts),
								  "cur_elts", 0, false);
			ucl_object_insert_key(e, ucl_object_fromint(st->cur_vars),
								  "cur_vars", 0, false);
			ucl_object_insert_key(e, ucl_object_fromint(st->cur_dtors),
								  "cur_dtors", 0, false);
			ucl_object_insert_key(e, ucl_object_fromint(st->avg_fragmentation),
								  "avg_fragmentation", 0, false);
			ucl_object_insert_key(e, ucl_object_fromint(st->avg_leftover),
								  "avg_leftover", 0, false);
			ucl_object_insert_key(e, ucl_object_fromint(st->samples),
								  "samples", 0, false);

			ucl_array_append(c->array, e);
		},
		&ctx);

	ucl_object_insert_key(mp, entries, "entries", 0, false);

	ucl_object_insert_key(parent, mp, "mempool", 0, false);

	return agg.bytes_allocated;
}

uint64_t
emit_lua_info(ucl_object_t *parent, struct rspamd_config *cfg)
{
	if (cfg == nullptr || cfg->lua_state == nullptr) {
		return 0;
	}

	auto *L = static_cast<lua_State *>(cfg->lua_state);
	auto used = rspamd_lua_get_memory_used(L);

	auto *obj = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(obj, ucl_object_fromint(used), "used_bytes", 0, false);
	ucl_object_insert_key(parent, obj, "lua", 0, false);

	return used;
}

#ifdef WITH_JEMALLOC
void jemalloc_text_cb(void *ud, const char *msg)
{
	auto *out = static_cast<rspamd_fstring_t **>(ud);
	rspamd_printf_fstring(out, "%s", msg);
}
#endif

uint64_t
emit_jemalloc_info(ucl_object_t *parent)
{
	uint64_t allocated = 0;
#ifdef WITH_JEMALLOC
	auto *obj = ucl_object_typed_new(UCL_OBJECT);

	/*
	 * Refresh internal counters before reading them; without this jemalloc
	 * would return stale values that were captured at the previous epoch.
	 */
	uint64_t epoch = 1;
	size_t epoch_sz = sizeof(epoch);
	(void) mallctl("epoch", &epoch, &epoch_sz, &epoch, epoch_sz);

	auto *stats = ucl_object_typed_new(UCL_OBJECT);

	auto read_size_stat = [&](const char *name, const char *key) {
		size_t val = 0;
		size_t sz = sizeof(val);
		if (mallctl(name, &val, &sz, nullptr, 0) == 0) {
			ucl_object_insert_key(stats, ucl_object_fromint(val), key, 0, false);
			return val;
		}
		return (size_t) 0;
	};

	allocated = read_size_stat("stats.allocated", "allocated");
	read_size_stat("stats.active", "active");
	read_size_stat("stats.metadata", "metadata");
	read_size_stat("stats.resident", "resident");
	read_size_stat("stats.mapped", "mapped");
	read_size_stat("stats.retained", "retained");

	ucl_object_insert_key(obj, stats, "stats", 0, false);

	auto *config = ucl_object_typed_new(UCL_OBJECT);

	{
		unsigned int narenas = 0;
		size_t sz = sizeof(narenas);
		if (mallctl("opt.narenas", &narenas, &sz, nullptr, 0) == 0) {
			ucl_object_insert_key(config, ucl_object_fromint(narenas), "narenas",
								  0, false);
		}
	}

	{
		ssize_t v = 0;
		size_t sz = sizeof(v);
		if (mallctl("opt.dirty_decay_ms", &v, &sz, nullptr, 0) == 0) {
			ucl_object_insert_key(config, ucl_object_fromint(v), "dirty_decay_ms",
								  0, false);
		}
		if (mallctl("opt.muzzy_decay_ms", &v, &sz, nullptr, 0) == 0) {
			ucl_object_insert_key(config, ucl_object_fromint(v), "muzzy_decay_ms",
								  0, false);
		}
	}

	ucl_object_insert_key(obj, config, "config", 0, false);

	/* Capture the human-readable summary as well */
	rspamd_fstring_t *text = rspamd_fstring_sized_new(4096);
	malloc_stats_print(jemalloc_text_cb, &text, "Jmdablxe");
	if (text->len > 0) {
		ucl_object_insert_key(obj,
							  ucl_object_fromlstring(text->str, text->len),
							  "text", 0, false);
	}
	rspamd_fstring_free(text);

	ucl_object_insert_key(parent, obj, "jemalloc", 0, false);
#else
	(void) parent;
#endif
	return allocated;
}

}// namespace

extern "C" gboolean
rspamd_memory_stat_collect_and_send(struct rspamd_main *rspamd_main,
									struct rspamd_worker *worker,
									int fd,
									struct rspamd_control_command *cmd)
{
	struct rspamd_control_reply rep;
	memset(&rep, 0, sizeof(rep));
	rep.type = RSPAMD_CONTROL_MEMORY_STAT;
	rep.id = cmd->id;

	const char *temp_dir = (rspamd_main->cfg && rspamd_main->cfg->temp_dir)
							   ? rspamd_main->cfg->temp_dir
							   : "/tmp";
	char tmppath[PATH_MAX];
	rspamd_snprintf(tmppath, sizeof(tmppath), "%s%c%s-XXXXXXXXXX",
					temp_dir, G_DIR_SEPARATOR, "memstat");

	int outfd = mkstemp(tmppath);
	if (outfd == -1) {
		rep.reply.memory_stat.status = errno;
		msg_err_main("cannot make temporary memstat file: %s", strerror(errno));
		ssize_t r = write(fd, &rep, sizeof(rep));
		if (r != (ssize_t) sizeof(rep)) {
			msg_err_main("cannot write memstat reply: %s", strerror(errno));
		}
		return FALSE;
	}

	auto *root = ucl_object_typed_new(UCL_OBJECT);

	emit_process_info(root);
	uint64_t mempool_bytes = emit_mempool_info(root);
	uint64_t lua_used = emit_lua_info(root, rspamd_main->cfg);
	uint64_t jemalloc_allocated = emit_jemalloc_info(root);

	auto *emit_subr = ucl_object_emit_fd_funcs(outfd);
	ucl_object_emit_full(root, UCL_EMIT_JSON_COMPACT, emit_subr, nullptr);
	ucl_object_emit_funcs_free(emit_subr);
	ucl_object_unref(root);

	close(outfd);

	int read_fd = open(tmppath, O_RDONLY);
	unlink(tmppath);

	struct rspamd_proc_mem_info pm;
	memset(&pm, 0, sizeof(pm));
	rspamd_get_process_memory_info(&pm);

	rep.reply.memory_stat.status = 0;
	rep.reply.memory_stat.rss_kb = pm.vm_rss / 1024;
	rep.reply.memory_stat.lua_kb = lua_used / 1024;
	rep.reply.memory_stat.mempool_bytes = mempool_bytes;
	rep.reply.memory_stat.jemalloc_allocated = jemalloc_allocated;

	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));
	struct iovec iov;
	iov.iov_base = &rep;
	iov.iov_len = sizeof(rep);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	unsigned char fdspace[CMSG_SPACE(sizeof(int))];
	if (read_fd != -1) {
		memset(fdspace, 0, sizeof(fdspace));
		msg.msg_control = fdspace;
		msg.msg_controllen = sizeof(fdspace);
		struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
		if (cm) {
			cm->cmsg_level = SOL_SOCKET;
			cm->cmsg_type = SCM_RIGHTS;
			cm->cmsg_len = CMSG_LEN(sizeof(int));
			memcpy(CMSG_DATA(cm), &read_fd, sizeof(int));
		}
	}

	gboolean ok = TRUE;
	if (sendmsg(fd, &msg, 0) == -1) {
		msg_err_main("cannot send memstat reply: %s", strerror(errno));
		ok = FALSE;
	}

	if (read_fd != -1) {
		close(read_fd);
	}

	(void) worker;

	return ok;
}
