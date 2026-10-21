/* SPDX-License-Identifier: Apache-2.0 */
#include "config.h"
#include "libserver/cfg_file.h"
#include "libserver/worker_util.h"
#include "libserver/rspamd_control.h"
#include "libserver/file_write.h"
#include "libutil/ref.h"
#include "libutil/util.h"
#include "unix-std.h"

static const uint64_t file_helper_magic = 0x6677726974657231ULL;

struct file_helper_ctx {
	uint64_t magic;
	struct ev_loop *event_loop;
	struct rspamd_dns_resolver *resolver;
	struct rspamd_config *cfg;
	/* End of common worker context. */
	struct rspamd_file_writer *writer;
};

static gpointer
init_file_helper(struct rspamd_config *cfg)
{
	struct file_helper_ctx *ctx = rspamd_mempool_alloc0(cfg->cfg_pool, sizeof(*ctx));
	ctx->magic = file_helper_magic;
	ctx->cfg = cfg;
	return ctx;
}

static gboolean
file_helper_accept(struct rspamd_main *srv, struct rspamd_worker *worker,
				   int fd, int attached_fd, struct rspamd_control_command *cmd,
				   gpointer ud)
{
	struct file_helper_ctx *ctx = ud;
	if (worker->state == rspamd_worker_state_running) {
		rspamd_file_writer_accept(ctx->writer, attached_fd);
	}
	else {
		rspamd_file_writer_reject(attached_fd, ESHUTDOWN);
	}
	/* One-way handoff. READY/DONE/error goes directly to the requesting worker;
	 * there is no per-write pending reply in the main process. */
	return TRUE;
}

static void G_GNUC_NORETURN
start_file_helper(struct rspamd_worker *worker)
{
	struct file_helper_ctx *ctx = worker->ctx;
	g_assert(rspamd_worker_check_context(ctx, file_helper_magic));
	ctx->cfg = worker->srv->cfg;
	CFG_REF_RETAIN(ctx->cfg);
	ctx->event_loop = rspamd_prepare_worker(worker, "file_helper", NULL);
	/* Report EFBIG as an operation error instead of killing every pending write. */
#ifdef SIGXFSZ
	signal(SIGXFSZ, SIG_IGN);
#endif
	ctx->writer = rspamd_file_writer_new(ctx->event_loop);
	rspamd_control_worker_add_cmd_handler(worker, RSPAMD_CONTROL_FILE_WRITE,
										  file_helper_accept, ctx);
	ev_run(ctx->event_loop, 0);
	rspamd_worker_block_signals();
	rspamd_file_writer_free(ctx->writer);
	CFG_REF_RELEASE(ctx->cfg);
	CFG_REF_RELEASE(ctx->cfg);
	rspamd_log_close(worker->srv->logger);
	rspamd_unset_crash_handler(worker->srv);
	exit(EXIT_SUCCESS);
}

worker_t file_helper_worker = {
	"file_helper",
	init_file_helper,
	start_file_helper,
	RSPAMD_WORKER_UNIQUE | RSPAMD_WORKER_KILLABLE | RSPAMD_WORKER_ALWAYS_START |
		RSPAMD_WORKER_NO_TERMINATE_DELAY,
	RSPAMD_WORKER_SOCKET_NONE,
	RSPAMD_WORKER_VER};
