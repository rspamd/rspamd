/*-
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
#include "rspamd.h"
#include "libserver/task.h"
#include "lua/lua_common.h"
#include "unix-std.h"
#include "libserver/file_write.h"
#include "libserver/rspamd_control.h"
#include <sys/wait.h>
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

extern struct rspamd_main *rspamd_main;
extern struct ev_loop *event_loop;

enum store_async_case {
	STORE_OK,
	STORE_DEFAULTS,
	STORE_DEFAULT_MODE,
	STORE_DEFAULT_TIMEOUT,
	STORE_ZERO_MODE,
	STORE_EMPTY,
	STORE_KEEP,
	STORE_TMPMASK,
	STORE_EXISTS,
	STORE_REUSE,
	STORE_FORCE_NEW,
	STORE_SHORT_WRITE,
	STORE_TIMEOUT,
	STORE_CANCEL,
	STORE_DESTROY,
	STORE_LATE_CANCEL,
	STORE_HELPER_LOST,
	STORE_BUSY,
	STORE_NO_WORKER,
	STORE_CHAIN,
	STORE_CALLBACK_ERROR,
	STORE_CALLBACK_DESTROY,
};

/* Exercise the real srv command sender and helper protocol, with a small
 * in-process broker replacing only the daemon's process supervision. The same
 * writer is reused across every case. Functional tests cover the real daemon. */
static struct rspamd_worker test_worker;
static struct rspamd_file_writer *test_writer;
static enum store_async_case broker_case;
static int held_socket = -1;

static void
store_async_broker(EV_P_ ev_io *w, int revents)
{
	struct rspamd_srv_command cmd;
	struct msghdr msg = {0};
	struct iovec iov = {.iov_base = &cmd, .iov_len = sizeof(cmd)};
	union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control;
	int fd;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control.bytes;
	msg.msg_controllen = sizeof(control.bytes);
	ssize_t n = recvmsg(w->fd, &msg, 0);
	if (n < 0 && (errno == EAGAIN || errno == EINTR)) return;
	g_assert_cmpint(n, ==, sizeof(cmd));
	g_assert_cmpint(cmd.type, ==, RSPAMD_SRV_FILE_WRITE);
	g_assert_cmpuint(msg.msg_controllen, >=, CMSG_LEN(sizeof(int)));
	memcpy(&fd, CMSG_DATA(CMSG_FIRSTHDR(&msg)), sizeof(fd));
	if (broker_case == STORE_TIMEOUT) held_socket = fd;
	else if (broker_case == STORE_HELPER_LOST) {
		close(fd);
		rspamd_file_writer_free(test_writer);
		test_writer = rspamd_file_writer_new(EV_A);
	}
	else if (broker_case == STORE_BUSY) rspamd_file_writer_reject(fd, EBUSY);
	else rspamd_file_writer_accept(test_writer, fd);
	struct rspamd_srv_reply rep = {.type = cmd.type, .id = cmd.id};
	g_assert_cmpint(write(w->fd, &rep, sizeof(rep)), ==, sizeof(rep));
}

struct store_async_test {
	struct rspamd_task *task;
	struct ev_loop *loop;
	const char *message;
	gsize len;
	char *filename, *second, *returned, *input;
	enum store_async_case kind;
	mode_t expected_mode;
	int calls;
	gboolean callback_ok, contents_ok, chain_ok, expired, cancelled;
	int observed_fd;
};

static void store_async_start(lua_State *L, struct store_async_test *test, gboolean second);

static gboolean
store_async_contents(const char *filename, const char *message, gsize len)
{
	char *contents = NULL;
	gsize actual = 0;
	gboolean ok = g_file_get_contents(filename, &contents, &actual, NULL) &&
		actual == len && (len == 0 || memcmp(contents, message, len) == 0);

	g_free(contents);
	return ok;
}

static int
store_async_callback(lua_State *L)
{
	struct store_async_test *test = lua_touserdata(L, lua_upvalueindex(1));
	gboolean failed = test->kind == STORE_EXISTS || test->kind == STORE_SHORT_WRITE ||
		test->kind == STORE_TIMEOUT || test->kind == STORE_HELPER_LOST ||
		test->kind == STORE_BUSY || test->kind == STORE_NO_WORKER;

	test->calls++;
	if (failed) {
		test->callback_ok = lua_type(L, 1) == LUA_TSTRING && lua_isnil(L, 2);
		if (test->kind == STORE_TIMEOUT) {
			test->callback_ok = test->callback_ok &&
				strcmp(lua_tostring(L, 1), strerror(ETIMEDOUT)) == 0;
		}
		if (test->kind != STORE_EXISTS) {
			test->callback_ok = test->callback_ok &&
				!g_file_test(test->filename, G_FILE_TEST_EXISTS);
		}
	}
	else {
		test->callback_ok = test->callback_ok && lua_isnil(L, 1) &&
			lua_type(L, 2) == LUA_TSTRING;
		if (lua_type(L, 2) == LUA_TSTRING) {
			const char *fname = lua_tostring(L, 2);
			struct stat st;

			if (test->kind != STORE_TMPMASK) {
				const char *expected = test->calls == 2 ? test->second :
					(test->kind == STORE_REUSE ? test->input : test->filename);

				test->callback_ok = test->callback_ok && strcmp(fname, expected) == 0;
			}
			g_free(test->returned);
			test->returned = g_strdup(fname);
			if (test->kind != STORE_REUSE) {
				test->contents_ok = test->contents_ok && stat(fname, &st) == 0 &&
					(st.st_mode & 0777) == test->expected_mode;
			}
			if (test->kind == STORE_ZERO_MODE) {
				/* Check 0000 first, then allow a non-root test runner to read it. */
				test->contents_ok = chmod(fname, 0600) == 0 && test->contents_ok;
			}
			test->contents_ok = test->contents_ok &&
				store_async_contents(fname, test->message, test->len);
		}
	}

	if (test->kind == STORE_CHAIN && test->calls == 1) {
		store_async_start(L, test, TRUE);
		test->chain_ok = rspamd_session_events_pending(test->task->s) == 2;
	}
	else if (test->kind == STORE_CALLBACK_DESTROY) {
		rspamd_task_free(test->task);
		test->task = NULL;
	}
	else if (test->kind == STORE_CALLBACK_ERROR) {
		return luaL_error(L, "intentional store_in_file_async test error");
	}
	return 0;
}

static void
store_async_start(lua_State *L, struct store_async_test *test, gboolean second)
{
	int top = lua_gettop(L);

	rspamd_lua_task_push(L, test->task);
	lua_getfield(L, -1, "store_in_file_async");
	lua_pushvalue(L, -2);
	lua_newtable(L);
	lua_pushstring(L, second ? test->second : test->filename);
	lua_setfield(L, -2, test->kind == STORE_TMPMASK ? "tmpmask" : "filename");
	if (test->kind != STORE_DEFAULTS && test->kind != STORE_DEFAULT_MODE) {
		lua_pushinteger(L, test->expected_mode);
		lua_setfield(L, -2, "mode");
	}
	/* Cancellation/error must remove files even when the caller asked to keep. */
	lua_pushboolean(L, test->kind == STORE_KEEP || test->kind == STORE_SHORT_WRITE ||
		test->kind == STORE_TIMEOUT || test->kind == STORE_CANCEL ||
		test->kind == STORE_DESTROY || test->kind == STORE_LATE_CANCEL);
	lua_setfield(L, -2, "keep");
	lua_pushboolean(L, test->kind == STORE_FORCE_NEW);
	lua_setfield(L, -2, "force_new");
	if (test->kind != STORE_DEFAULTS && test->kind != STORE_DEFAULT_TIMEOUT) {
		lua_pushnumber(L, test->kind == STORE_TIMEOUT ? 0.05 : 5.0);
		lua_setfield(L, -2, "timeout");
	}
	lua_pushlightuserdata(L, test);
	lua_pushcclosure(L, store_async_callback, 1);
	g_assert_cmpint(lua_pcall(L, 3, 1, 0), ==, 0);
	g_assert(lua_toboolean(L, -1));
	lua_settop(L, top);
}

static void
store_async_guard(EV_P_ ev_timer *w, int revents)
{
	struct store_async_test *test = w->data;

	test->expired = TRUE;
	ev_break(EV_A_ EVBREAK_ALL);
}

static void
store_async_cancel_after_block(EV_P_ ev_check *w, int revents)
{
	struct store_async_test *test = w->data;
	struct stat st;
	g_assert_cmpint(fstat(test->observed_fd, &st), ==, 0);
	if (st.st_size > 0) {
		g_assert_cmpuint(st.st_size, <=, RSPAMD_FILE_WRITE_BLOCK);
		rspamd_task_free(test->task);
		test->task = NULL;
		test->cancelled = TRUE;
		ev_check_stop(EV_A_ w);
	}
}

static void
store_async_make_task(struct store_async_test *test)
{
	test->task = rspamd_task_new(&test_worker, rspamd_main->cfg, NULL, NULL, test->loop, FALSE);
	test->task->msg.begin = rspamd_mempool_alloc(test->task->task_pool, MAX(test->len, 1));
	memcpy((void *) test->task->msg.begin, test->message, test->len);
	test->task->msg.len = test->len;
	test->task->s = rspamd_session_create(test->task->task_pool, NULL, NULL, NULL, NULL);
}

static void
store_async_run_case(struct ev_loop *loop, enum store_async_case kind)
{
	struct store_async_test test = {0}, other = {0};
	lua_State *L = rspamd_main->cfg->lua_state;
	char *dirname, *input;
	gsize len = RSPAMD_FILE_WRITE_BLOCK * 3 + 137;
	char *message = g_malloc(len);
	gboolean cleanup_ok, original_ok, session_ok;
	ev_timer guard;
	ev_check cancel;
#if defined(RLIMIT_FSIZE)
	struct rlimit old_limit, limit;
#endif

	/* Binary bytes spanning several blocks, including NULs and non-ASCII. */
	for (gsize i = 0; i < len; i++) message[i] = (unsigned char) (i * 17);
	dirname = g_build_filename(g_get_tmp_dir(), "rspamd-async-file-XXXXXX", NULL);
	g_assert(g_mkdtemp(dirname));
	test.filename = g_build_filename(dirname,
		kind == STORE_TMPMASK ? "message-XXXXXX" : "message", NULL);
	test.second = g_build_filename(dirname, "second", NULL);
	input = g_build_filename(dirname, "input", NULL);
	test.loop = loop;
	test.input = input;
	test.kind = kind;
	test.expected_mode = kind == STORE_DEFAULTS || kind == STORE_DEFAULT_MODE ? 0600 :
		(kind == STORE_ZERO_MODE ? 0 : 0640);
	test.message = message;
	test.len = kind == STORE_EMPTY ? 0 : len;
	test.callback_ok = test.contents_ok = TRUE;
	store_async_make_task(&test);
	broker_case = kind;
	if (kind == STORE_NO_WORKER) test.task->worker = NULL;

	if (kind == STORE_EXISTS) {
		g_assert(g_file_set_contents(test.filename, "existing", -1, NULL));
	}
	if (kind == STORE_REUSE || kind == STORE_FORCE_NEW) {
		g_assert(g_file_set_contents(input, message, len, NULL));
		test.task->flags |= RSPAMD_TASK_FLAG_FILE;
		test.task->msg.fpath = rspamd_mempool_strdup(test.task->task_pool, input);
	}
	store_async_start(L, &test, FALSE);
	g_assert_cmpint(test.calls, ==, 0);
	g_assert_cmpuint(rspamd_session_events_pending(test.task->s), ==, 1);

	if (kind == STORE_CANCEL) rspamd_session_cleanup(test.task->s, TRUE);
	else if (kind == STORE_DESTROY) {
		rspamd_task_free(test.task);
		test.task = NULL;
	}
	else if (kind == STORE_LATE_CANCEL) {
		/* Destroy one task between blocks while an independent write must finish. */
		test.observed_fd = open(test.filename, O_RDONLY);
		g_assert_cmpint(test.observed_fd, >=, 0);
		ev_check_init(&cancel, store_async_cancel_after_block);
		cancel.data = &test;
		ev_set_priority(&cancel, EV_MAXPRI);
		ev_check_start(loop, &cancel);
		other.loop = loop;
		other.kind = STORE_OK;
		other.filename = test.second;
		other.message = message;
		other.len = len;
		other.expected_mode = 0640;
		other.callback_ok = other.contents_ok = TRUE;
		store_async_make_task(&other);
		store_async_start(L, &other, FALSE);
	}
#if defined(RLIMIT_FSIZE)
	if (kind == STORE_SHORT_WRITE) {
		g_assert_cmpint(getrlimit(RLIMIT_FSIZE, &old_limit), ==, 0);
		limit = old_limit;
		limit.rlim_cur = 1;
		g_assert_cmpint(setrlimit(RLIMIT_FSIZE, &limit), ==, 0);
	}
#endif
	/* The broker is unreferenced; the operations alone must keep the loop alive. */
	ev_timer_init(&guard, store_async_guard, 10.0, 0.0);
	guard.data = &test;
	ev_timer_start(loop, &guard);
	ev_unref(loop);
	ev_run(loop, 0);
	ev_ref(loop);
	ev_timer_stop(loop, &guard);
#if defined(RLIMIT_FSIZE)
	if (kind == STORE_SHORT_WRITE) g_assert_cmpint(setrlimit(RLIMIT_FSIZE, &old_limit), ==, 0);
#endif
	if (held_socket != -1) { close(held_socket); held_socket = -1; }
	if (kind == STORE_LATE_CANCEL) {
		struct stat st;
		ev_check_stop(loop, &cancel);
		g_assert(test.cancelled);
		g_assert_cmpint(fstat(test.observed_fd, &st), ==, 0);
		g_assert_cmpuint(st.st_size, <=, RSPAMD_FILE_WRITE_BLOCK);
		close(test.observed_fd);
		g_assert_cmpint(other.calls, ==, 1);
		g_assert(other.callback_ok && other.contents_ok);
		rspamd_task_free(other.task);
		g_free(other.returned);
	}

	session_ok = test.task == NULL || rspamd_session_events_pending(test.task->s) == 0;
	if (test.task) {
		rspamd_session_cleanup(test.task->s, TRUE);
		rspamd_task_free(test.task);
	}
	original_ok = kind != STORE_EXISTS || store_async_contents(test.filename, "existing", 8);
	if (kind == STORE_REUSE || kind == STORE_FORCE_NEW) {
		original_ok = original_ok && store_async_contents(input, message, len);
	}
	cleanup_ok = kind == STORE_EXISTS ||
		g_file_test(test.filename, G_FILE_TEST_EXISTS) == (kind == STORE_KEEP);
	if (kind == STORE_TMPMASK) {
		cleanup_ok = test.returned && !g_file_test(test.returned, G_FILE_TEST_EXISTS);
	}
	cleanup_ok = cleanup_ok && !g_file_test(test.second, G_FILE_TEST_EXISTS);

	unlink(test.filename);
	unlink(test.second);
	unlink(input);
	if (test.returned) unlink(test.returned);
	g_assert_cmpint(rmdir(dirname), ==, 0);
	g_free(message);
	g_free(input);
	g_free(dirname);
	g_free(test.filename);
	g_free(test.second);
	g_free(test.returned);

	g_assert(!test.expired);
	g_assert(session_ok);
	g_assert(original_ok);
	g_assert(cleanup_ok);
	if (kind == STORE_CANCEL || kind == STORE_DESTROY || kind == STORE_LATE_CANCEL) {
		g_assert_cmpint(test.calls, ==, 0);
	}
	else {
		g_assert_cmpint(test.calls, ==, kind == STORE_CHAIN ? 2 : 1);
		g_assert(test.callback_ok);
		g_assert(test.contents_ok);
		if (kind == STORE_CHAIN) g_assert(test.chain_ok);
	}
}

static void
store_async_invalid_timeout(struct ev_loop *loop)
{
	lua_State *L = rspamd_main->cfg->lua_state;
	struct rspamd_task *task = rspamd_task_new(NULL, rspamd_main->cfg, NULL, NULL, loop, FALSE);
	int top = lua_gettop(L), rc;
	static const char script[] =
		"local task = ...\n"
		"local ok, err = pcall(task.store_in_file_async, task, {timeout = 0}, function() end)\n"
		"assert(not ok and type(err) == 'string' and "
		"err:find('timeout must be finite and positive', 1, true))\n";

	/* A rejected option must be reported before session/file setup. */
	g_assert_cmpint(luaL_loadstring(L, script), ==, 0);
	rspamd_lua_task_push(L, task);
	rc = lua_pcall(L, 1, 0, 0);
	lua_settop(L, top);
	rspamd_task_free(task);
	g_assert_cmpint(rc, ==, 0);
}

static void
store_async_headers(struct ev_loop *loop)
{
	/* Fragment the header at the SCM_RIGHTS boundary. Also reject a malformed
	 * header, a missing destination fd, and EOF midway through the header. */
	for (unsigned int variant = 0; variant < 4; variant++) {
		char *name = NULL;
		int fd = g_file_open_tmp("rspamd-async-header-XXXXXX", &name, NULL), pair[2];
		struct rspamd_file_write_header header = {
			.magic = variant == 1 ? 0 : RSPAMD_FILE_WRITE_MAGIC,
			.deadline = rspamd_get_ticks(FALSE) + 5.0};
		struct rspamd_file_write_reply reply;
		struct stat st;
		g_assert_cmpint(fd, >=, 0);
		g_assert_cmpint(rspamd_socketpair(pair, SOCK_STREAM), ==, TRUE);
		rspamd_file_writer_accept(test_writer, pair[1]);
		g_assert_cmpint(rspamd_file_write_send(pair[0], &header, 1,
			variant == 2 ? -1 : fd), ==, 1);
		ev_run(loop, EVRUN_NOWAIT);
		if (variant == 3) close(pair[0]);
		else {
			g_assert_cmpint(rspamd_file_write_send(pair[0], (char *) &header + 1,
				sizeof(header) - 1, -1), ==, sizeof(header) - 1);
		}
		ev_run(loop, 0);
		if (variant != 3) {
			ssize_t n = read(pair[0], &reply, sizeof(reply));
			g_assert_cmpint(n, ==, variant == 0 ? sizeof(reply) : 0);
			if (variant == 0) {
				g_assert_cmpuint(reply.done, ==, 1);
				g_assert_cmpuint(reply.written, ==, 0);
				g_assert_cmpint(reply.error, ==, 0);
			}
			close(pair[0]);
		}
		g_assert_cmpint(fstat(fd, &st), ==, 0); /* Sender's fd is still owned here. */
		g_assert_cmpuint(st.st_size, ==, 0);
		close(fd);
		unlink(name);
		g_free(name);
	}
}

static void
store_async_limits(struct ev_loop *loop)
{
	/* Saturate the helper independently of the per-caller admission limit. */
	int clients[RSPAMD_FILE_WRITE_MAX_JOBS], pair[2];
	struct rspamd_file_write_reply reply;
	for (unsigned int i = 0; i < RSPAMD_FILE_WRITE_MAX_JOBS; i++) {
		g_assert_cmpint(rspamd_socketpair(pair, SOCK_STREAM), ==, TRUE);
		clients[i] = pair[0];
		rspamd_file_writer_accept(test_writer, pair[1]);
	}
	g_assert_cmpint(rspamd_socketpair(pair, SOCK_STREAM), ==, TRUE);
	rspamd_file_writer_accept(test_writer, pair[1]);
	g_assert_cmpint(read(pair[0], &reply, sizeof(reply)), ==, sizeof(reply));
	g_assert_cmpint(reply.error, ==, EBUSY);
	g_assert_cmpuint(reply.done, ==, 1);
	close(pair[0]);
	for (unsigned int i = 0; i < RSPAMD_FILE_WRITE_MAX_JOBS; i++) close(clients[i]);
	ev_run(loop, 0); /* EOF must release all helper slots. */

	/* Queue 64 requests without running the broker, then reject the 65th.
	 * Cancel them before handoff to exercise queued-fd ownership and cleanup. */
	struct store_async_test jobs[RSPAMD_FILE_WRITE_WORKER_JOBS + 1] = {0};
	char *directory = g_build_filename(g_get_tmp_dir(), "rspamd-async-limit-XXXXXX", NULL);
	g_assert(g_mkdtemp(directory));
	for (unsigned int i = 0; i < G_N_ELEMENTS(jobs); i++) {
		struct store_async_test *test = &jobs[i];
		test->loop = loop;
		test->filename = g_strdup_printf("%s/%u", directory, i);
		test->kind = i == RSPAMD_FILE_WRITE_WORKER_JOBS ? STORE_BUSY : STORE_OK;
		test->message = "x";
		test->len = 1;
		test->expected_mode = 0600;
		test->callback_ok = test->contents_ok = TRUE;
		store_async_make_task(test);
		store_async_start(rspamd_main->cfg->lua_state, test, FALSE);
	}
	for (unsigned int i = 0; i < RSPAMD_FILE_WRITE_WORKER_JOBS; i++) {
		rspamd_session_cleanup(jobs[i].task->s, TRUE);
	}
	ev_run(loop, 0);
	for (unsigned int i = 0; i < G_N_ELEMENTS(jobs); i++) {
		g_assert_cmpint(jobs[i].calls, ==, i == RSPAMD_FILE_WRITE_WORKER_JOBS ? 1 : 0);
		g_assert(jobs[i].callback_ok);
		g_assert(!g_file_test(jobs[i].filename, G_FILE_TEST_EXISTS));
		rspamd_task_free(jobs[i].task);
		g_free(jobs[i].filename);
	}
	g_assert_cmpint(rmdir(directory), ==, 0);
	g_free(directory);
	store_async_run_case(loop, STORE_OK); /* Admission recovers after cancellation. */
}

static void
store_async_run_group(gboolean default_loop, unsigned int flags)
{
	pid_t group = fork();
	int status;

	g_assert_cmpint(group, >=, 0);
	if (group == 0) {
		struct ev_loop *loop;
		ev_io broker;

		/* Workers use a non-default loop; rspamadm/tests may use the default.
		 * Isolate their SIGCHLD ownership from the test runner's default loop. */
		ev_loop_destroy(event_loop);
		loop = default_loop ? ev_default_loop(flags) : ev_loop_new(flags);
		g_assert(loop);
		signal(SIGPIPE, SIG_IGN);
#ifdef SIGXFSZ
		signal(SIGXFSZ, SIG_IGN);
#endif
		g_assert_cmpint(rspamd_socketpair(test_worker.srv_pipe, SOCK_SEQPACKET), ==, TRUE);
		g_assert_cmpint(rspamd_socket_nonblocking(test_worker.srv_pipe[0]), !=, -1);
		g_assert_cmpint(rspamd_socket_nonblocking(test_worker.srv_pipe[1]), !=, -1);
		test_writer = rspamd_file_writer_new(loop);
		rspamd_srv_pipe_init(&test_worker, loop);
		ev_io_init(&broker, store_async_broker, test_worker.srv_pipe[0], EV_READ);
		ev_io_start(loop, &broker);
		ev_unref(loop);
		/* Bound failures in the test's own blocking synchronization as well. */
		alarm(60);
		store_async_invalid_timeout(loop);
		for (int kind = STORE_OK; kind <= STORE_CALLBACK_DESTROY; kind++) {
#if !defined(RLIMIT_FSIZE)
			if (kind == STORE_SHORT_WRITE) continue;
#endif
			store_async_run_case(loop, kind);
		}
		store_async_headers(loop);
		store_async_limits(loop);
		alarm(0);
		ev_ref(loop);
		ev_io_stop(loop, &broker);
		rspamd_srv_pipe_cleanup();
		rspamd_file_writer_free(test_writer);
		close(test_worker.srv_pipe[0]);
		close(test_worker.srv_pipe[1]);
		ev_loop_destroy(loop);
		_exit(EXIT_SUCCESS);
	}
	while (waitpid(group, &status, 0) == -1) {
		g_assert_cmpint(errno, ==, EINTR);
	}
	g_assert(WIFEXITED(status));
	g_assert_cmpint(WEXITSTATUS(status), ==, EXIT_SUCCESS);
}

void rspamd_lua_task_async_test_func(void)
{
	store_async_run_group(TRUE, 0);
	store_async_run_group(FALSE, 0);
	store_async_run_group(TRUE, EVFLAG_SIGNALFD);
	store_async_run_group(FALSE, EVFLAG_SIGNALFD);
}
