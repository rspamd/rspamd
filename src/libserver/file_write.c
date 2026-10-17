/* SPDX-License-Identifier: Apache-2.0 */
#include "file_write.h"
#include "libutil/util.h"
#include "unix-std.h"
#include <math.h>

enum file_write_state { FILE_HEADER, FILE_REPLY, FILE_DATA, FILE_DISK };

struct rspamd_file_writer {
	struct ev_loop *loop;
	GHashTable *jobs;
	GQueue ready;
	ev_timer disk;
};

struct file_write_job {
	struct rspamd_file_writer *writer;
	ev_io io;
	ev_timer timer;
	int sock, fd;
	enum file_write_state state;
	struct rspamd_file_write_header header;
	struct rspamd_file_write_reply reply;
	size_t pos, used, offset;
	uint64_t written;
	gboolean queued;
	unsigned char block[RSPAMD_FILE_WRITE_BLOCK];
};

ssize_t
rspamd_file_write_send(int sock, const void *data, size_t len, int fd)
{
	struct msghdr msg = {0};
	struct iovec iov = {.iov_base = (void *) data, .iov_len = len};
	union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
	int flags = 0;

#ifdef MSG_NOSIGNAL
	flags |= MSG_NOSIGNAL;
#endif
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (fd >= 0) {
		memset(&control, 0, sizeof(control));
		msg.msg_control = control.bytes;
		msg.msg_controllen = sizeof(control.bytes);
		struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
	}
	return sendmsg(sock, &msg, flags);
}

void
rspamd_file_writer_reject(int sock, int error)
{
	if (sock >= 0) {
		struct rspamd_file_write_reply reply = {.error = error, .done = 1};
		if (rspamd_socket_nonblocking(sock) != -1) {
			(void) rspamd_file_write_send(sock, &reply, sizeof(reply), -1);
		}
		close(sock);
	}
}

static void
file_write_drop(struct file_write_job *job)
{
	struct rspamd_file_writer *writer = job->writer;

	ev_io_stop(writer->loop, &job->io);
	ev_timer_stop(writer->loop, &job->timer);
	if (job->queued) {
		g_queue_remove(&writer->ready, job);
	}
	if (g_queue_is_empty(&writer->ready)) {
		ev_timer_stop(writer->loop, &writer->disk);
	}
	if (job->fd >= 0) close(job->fd);
	close(job->sock);
	g_hash_table_remove(writer->jobs, job);
	g_free(job);
}

static void
file_write_watch(struct file_write_job *job, int events)
{
	ev_io_stop(job->writer->loop, &job->io);
	ev_io_set(&job->io, job->sock, events);
	ev_io_start(job->writer->loop, &job->io);
}

static void
file_write_reply(struct file_write_job *job, int error, gboolean done)
{
	if (done && job->fd >= 0) {
		if (close(job->fd) == -1 && error == 0) error = errno;
		job->fd = -1;
	}
	job->reply.written = job->written;
	job->reply.error = error;
	job->reply.done = done;
	job->pos = 0;
	job->state = FILE_REPLY;
	file_write_watch(job, EV_READ | EV_WRITE);
}

static void
file_write_expired(EV_P_ ev_timer *w, int revents)
{
	struct file_write_job *job = w->data;
	if (job->state != FILE_HEADER) {
		double remaining = job->header.deadline - rspamd_get_ticks(FALSE);
		if (remaining > 0) {
			ev_now_update(EV_A);
			ev_timer_set(w, remaining, 0.0);
			ev_timer_start(EV_A_ w);
			return;
		}
	}
	/* The client owns the pathname and reports timeout independently. */
	file_write_drop(job);
}

static void
file_write_queue(struct file_write_job *job)
{
	struct rspamd_file_writer *writer = job->writer;
	job->queued = TRUE;
	g_queue_push_tail(&writer->ready, job);
	if (!ev_is_active(&writer->disk)) {
		ev_timer_set(&writer->disk, 0.0, 0.0);
		ev_timer_start(writer->loop, &writer->disk);
	}
}

static void
file_write_disk(EV_P_ ev_timer *w, int revents)
{
	struct rspamd_file_writer *writer = w->data;
	struct file_write_job *job = g_queue_pop_head(&writer->ready);
	unsigned char ch;
	ssize_t n;

	if (!job) return;
	job->queued = FALSE;
	/* Check cancellation even when the read watcher callback is still pending.
	 * No further payload is permitted until this block has been acknowledged. */
	n = recv(job->sock, &ch, 1, MSG_PEEK);
	if (n < 0 && errno == EINTR) {
		file_write_queue(job);
	}
	else if (n >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK) ||
		rspamd_get_ticks(FALSE) >= job->header.deadline) {
		file_write_drop(job);
	}
	else {
		/* Exactly one bounded disk syscall per turn. Regular-file I/O can still
		 * block in the kernel; no event-loop timer can interrupt that syscall. */
		n = write(job->fd, job->block + job->offset, job->used - job->offset);
		if (n < 0 && errno == EINTR) {
			file_write_queue(job);
		}
		else if (n <= 0) {
			file_write_reply(job, n == 0 ? EIO : errno, TRUE);
		}
		else {
			job->offset += n;
			job->written += n;
			if (job->offset < job->used) file_write_queue(job);
			else file_write_reply(job, 0, job->written == job->header.length);
		}
	}
	/* Round robin, including partial writes: neither large messages nor EINTR
	 * loops may monopolise the helper between cancellation checks. */
	if (!g_queue_is_empty(&writer->ready) && !ev_is_active(w)) {
		ev_timer_set(w, 0.0, 0.0);
		ev_timer_start(EV_A_ w);
	}
}

static gboolean
file_write_header(struct file_write_job *job)
{
	struct msghdr msg = {0};
	struct iovec iov = {
		.iov_base = (char *) &job->header + job->pos,
		.iov_len = sizeof(job->header) - job->pos};
	union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int) * 4)]; } control;
	gboolean invalid = FALSE;
	ssize_t n;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control.bytes;
	msg.msg_controllen = sizeof(control.bytes);
	n = recvmsg(job->sock, &msg, 0);
	if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return TRUE;
	if (n <= 0) return FALSE;
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg;
		 cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS &&
			cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
			size_t count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			for (size_t i = 0; i < count; i++) {
				int fd;
				memcpy(&fd, (char *) CMSG_DATA(cmsg) + i * sizeof(int), sizeof(fd));
				if (job->fd == -1) job->fd = fd;
				else { close(fd); invalid = TRUE; }
			}
		}
		else invalid = TRUE;
	}
	if (invalid || (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) return FALSE;
	job->pos += n;
	if (job->pos == sizeof(job->header)) {
		struct stat st;
		if (job->header.magic != RSPAMD_FILE_WRITE_MAGIC || job->header.reserved ||
			!isfinite(job->header.deadline) || job->fd < 0 ||
			fstat(job->fd, &st) == -1 || !S_ISREG(st.st_mode) ||
			fcntl(job->fd, F_SETFD, FD_CLOEXEC) == -1) return FALSE;
		ev_now_update(job->writer->loop);
		double remaining = job->header.deadline - rspamd_get_ticks(FALSE);
		if (remaining <= 0) return FALSE;
		ev_timer_stop(job->writer->loop, &job->timer);
		ev_timer_set(&job->timer, remaining, 0.0);
		ev_timer_start(job->writer->loop, &job->timer);
		file_write_reply(job, 0, job->header.length == 0);
	}
	return TRUE;
}

static void
file_write_io(EV_P_ ev_io *w, int revents)
{
	struct file_write_job *job = w->data;
	ssize_t n;

	if (job->state == FILE_HEADER) {
		if (!file_write_header(job)) file_write_drop(job);
		return;
	}
	if (rspamd_get_ticks(FALSE) >= job->header.deadline) {
		file_write_drop(job);
		return;
	}
	if (job->state == FILE_DATA) {
		size_t target = MIN((uint64_t) RSPAMD_FILE_WRITE_BLOCK,
			job->header.length - job->written);
		n = recv(job->sock, job->block + job->used, target - job->used, 0);
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
		if (n <= 0) { file_write_drop(job); return; }
		job->used += n;
		if (job->used == target) {
			job->state = FILE_DISK;
			job->offset = 0;
			file_write_queue(job);
		}
		return;
	}
	if (revents & EV_READ) {
		unsigned char ch;
		n = recv(job->sock, &ch, 1, MSG_PEEK);
		if (n >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
			file_write_drop(job);
			return;
		}
	}
	if (job->state == FILE_REPLY && (revents & EV_WRITE)) {
		n = rspamd_file_write_send(job->sock, (char *) &job->reply + job->pos,
			sizeof(job->reply) - job->pos, -1);
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
		if (n <= 0) { file_write_drop(job); return; }
		job->pos += n;
		if (job->pos == sizeof(job->reply)) {
			if (job->reply.done) { file_write_drop(job); return; }
			job->state = FILE_DATA;
			job->used = 0;
			file_write_watch(job, EV_READ);
		}
	}
}

struct rspamd_file_writer *
rspamd_file_writer_new(struct ev_loop *loop)
{
	struct rspamd_file_writer *writer = g_malloc0(sizeof(*writer));
	writer->loop = loop;
	writer->jobs = g_hash_table_new(g_direct_hash, g_direct_equal);
	g_queue_init(&writer->ready);
	ev_timer_init(&writer->disk, file_write_disk, 0.0, 0.0);
	writer->disk.data = writer;
	return writer;
}

void
rspamd_file_writer_accept(struct rspamd_file_writer *writer, int sock)
{
	struct file_write_job *job;
	if (sock < 0) return;
	if (g_hash_table_size(writer->jobs) >= RSPAMD_FILE_WRITE_MAX_JOBS) {
		rspamd_file_writer_reject(sock, EBUSY);
		return;
	}
	if (rspamd_socket_nonblocking(sock) == -1 || fcntl(sock, F_SETFD, FD_CLOEXEC) == -1) {
		close(sock);
		return;
	}
	job = g_malloc0(sizeof(*job));
	job->writer = writer;
	job->sock = sock;
	job->fd = -1;
	job->state = FILE_HEADER;
	ev_io_init(&job->io, file_write_io, sock, EV_READ);
	job->io.data = job;
	/* Bound a broken sender that never finishes the header. The operation's
	 * absolute deadline takes over once the complete header has arrived. */
	ev_timer_init(&job->timer, file_write_expired, 5.0, 0.0);
	job->timer.data = job;
	g_hash_table_add(writer->jobs, job);
	ev_io_start(writer->loop, &job->io);
	ev_now_update(writer->loop);
	ev_timer_start(writer->loop, &job->timer);
}

void
rspamd_file_writer_free(struct rspamd_file_writer *writer)
{
	GList *jobs = g_hash_table_get_keys(writer->jobs);
	for (GList *cur = jobs; cur; cur = cur->next) file_write_drop(cur->data);
	g_list_free(jobs);
	ev_timer_stop(writer->loop, &writer->disk);
	g_hash_table_destroy(writer->jobs);
	g_free(writer);
}
