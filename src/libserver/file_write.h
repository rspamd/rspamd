/* SPDX-License-Identifier: Apache-2.0 */
#ifndef RSPAMD_FILE_WRITE_H
#define RSPAMD_FILE_WRITE_H

#include "config.h"
#include "contrib/libev/ev.h"

G_BEGIN_DECLS

/* Internal, same-binary protocol over one local stream socket per operation.
 * The header carries exactly one SCM_RIGHTS destination fd. READY/ACK grants
 * permission to send ONE block; DONE is sent only after closing the output.
 * Closing/shutting down the client socket cancels the operation.
 * No path names or message contents go through the main process. */
#define RSPAMD_FILE_WRITE_MAGIC 0x46575231u
#define RSPAMD_FILE_WRITE_BLOCK (64u * 1024u)
#define RSPAMD_FILE_WRITE_MAX_JOBS 256u
#define RSPAMD_FILE_WRITE_WORKER_JOBS 64u

struct rspamd_file_write_header {
	uint64_t length;
	double deadline; /* rspamd_get_ticks(FALSE), shared monotonic clock */
	uint32_t magic;
	uint32_t reserved;
};

struct rspamd_file_write_reply {
	uint64_t written;
	int32_t error;
	uint32_t done;
};

struct rspamd_file_writer;
struct rspamd_file_writer *rspamd_file_writer_new(struct ev_loop *loop);
void rspamd_file_writer_free(struct rspamd_file_writer *writer);
/* Consumes sock on every path. Accepted sockets must speak the above protocol. */
void rspamd_file_writer_accept(struct rspamd_file_writer *writer, int sock);
/* Best-effort small rejection, followed by close; EOF is also a client error. */
void rspamd_file_writer_reject(int sock, int error);
/* Nonblocking send, attaching fd only when it is nonnegative. */
ssize_t rspamd_file_write_send(int sock, const void *data, size_t len, int fd);

G_END_DECLS
#endif
