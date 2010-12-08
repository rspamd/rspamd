/*
 * Copyright (c) 2009, Rambler media
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Store greylisting data in memory
 */

#include "config.h"
#include "util.h"
#include "main.h"
#include "protocol.h"
#include "upstream.h"
#include "cfg_file.h"
#include "url.h"
#include "modules.h"
#include "message.h"
#include "greylist.h"

#ifdef WITH_JUDY
#include <Judy.h>
#endif

/* Number of insuccessfull bind retries */
#define MAX_RETRIES 40

struct greylist_ctx {
#ifdef WITH_JUDY
	Pvoid_t                  jtree;
#else
	GTree                   *tree;
#endif
	time_t                   greylist_time;
	time_t                   expire_time;
};

#ifndef HAVE_SA_SIGINFO
static void
sig_handler (gint signo)
#else
static void
sig_handler (gint signo, siginfo_t *info, void *unused)
#endif
{
	switch (signo) {
	case SIGINT:
		/* Ignore SIGINT as we should got SIGTERM after it anyway */
		return;
	case SIGTERM:
#ifdef WITH_PROFILER
		exit (0);
#else
		_exit (1);
#endif
		break;
	}
}

static void
sigterm_handler (gint fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	static struct timeval           tv = {
		.tv_sec = 0,
		.tv_usec = 0
	};

	close (worker->cf->listen_sock);
	(void)event_loopexit (&tv);
}

/*
 * Config reload is designed by sending sigusr to active workers and pending shutdown of them
 */
static void
sigusr_handler (gint fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	/* Do not accept new connections, preparing to end worker's process */
	struct timeval                  tv;

	tv.tv_sec = SOFT_SHUTDOWN_TIME;
	tv.tv_usec = 0;
	event_del (&worker->sig_ev);
	event_del (&worker->bind_ev);
	close (worker->cf->listen_sock);
	do_reopen_log = 1;
	msg_info ("worker's shutdown is pending in %d sec", SOFT_SHUTDOWN_TIME);
	event_loopexit (&tv);
	return;
}

struct greylist_session {
	struct rspamd_worker *worker;
	gint                            fd;
	socklen_t salen;
	struct sockaddr_storage sa;
	guint8 *pos;
	struct rspamd_grey_command cmd;
};

static gint
grey_cmp (gconstpointer a, gconstpointer b, gpointer unused)
{
	return memcmp (a, b, CHECKSUM_SIZE);
}

static gint
greylist_process_add_command (struct rspamd_grey_command *cmd, struct greylist_ctx *ctx)
{
	struct rspamd_grey_reply          reply;
	struct rspamd_grey_item          *item, **pitem = NULL;
	
	item = g_malloc (sizeof (struct rspamd_grey_item));
	item->age = time (NULL);
	memcpy (item->data, cmd->data, CHECKSUM_SIZE);
#ifdef WITH_JUDY

	JHSI (pitem, ctx->jtree, item->data, CHECKSUM_SIZE);
	if (pitem == PJERR) {
		reply.reply = GREY_ERR;
	}
	else if (*pitem != 0) {
		g_free (*pitem);
		*pitem = item;
	}
	else {
		*pitem = item;
	}
#else
	g_tree_insert (ctx->tree, item->data, item);
	reply.reply = GREY_OK;
#endif

	return reply.reply;
}

static gint
greylist_process_delete_command (struct rspamd_grey_command *cmd, struct greylist_ctx *ctx)
{
	struct rspamd_grey_reply          reply;
#ifdef WITH_JUDY
	gint                            rc;
	struct rspamd_grey_item         **pitem = NULL;

	JHSG (pitem, ctx->jtree, cmd->data, CHECKSUM_SIZE);
	if (pitem != NULL) {
		g_free (*pitem);
		JHSD (rc, ctx->jtree, cmd->data, CHECKSUM_SIZE);
		if (rc == 1) {
			reply.reply = GREY_OK;
		}
		else {
			reply.reply = GREY_NOT_FOUND;
		}
	}
	else {
		reply.reply = GREY_NOT_FOUND;
	}
#else
	if(g_tree_remove (ctx->tree, cmd->data)) {
		reply.reply = GREY_OK;
	}
	else {
		reply.reply = GREY_NOT_FOUND;
	}
#endif
	return reply.reply;
}

static gint
greylist_process_check_command (struct rspamd_grey_command *cmd, struct greylist_ctx *ctx)
{
	struct rspamd_grey_reply          reply;
	struct rspamd_grey_item          *item = NULL, **pitem = NULL;
	time_t                            now;
	
	now = time (NULL);
#ifdef WITH_JUDY
	JHSG (pitem, ctx->jtree, cmd->data, CHECKSUM_SIZE);
	if (pitem != NULL) {
		item = *pitem;
	}
#else
	item = g_tree_lookup (ctx->tree, cmd->data);
#endif
	if (item) {
		if (now - item->age > ctx->expire_time) {
			/* Remove expired item */
			reply.reply = GREY_EXPIRED;
			greylist_process_delete_command (cmd, ctx);
		}
		else if (now - item->age > ctx->greylist_time) {
			reply.reply = GREY_OK;
		}
		else {
			reply.reply = GREY_GREYLISTED;
		}
	}
	else {
		reply.reply = GREY_NOT_FOUND;
	}

	return reply.reply;
}

#define CMD_PROCESS(x)																								\
do {																												\
	reply.reply = greylist_process_##x##_command (&session->cmd, (struct greylist_ctx *)session->worker->ctx);		\
	if (sendto (session->fd, &reply, sizeof (reply), 0, (struct sockaddr *)&session->sa, session->salen) == -1) {	\
		msg_err ("error while writing reply: %s", strerror (errno));												\
	}																												\
} while(0)

static void
process_greylist_command (struct greylist_session *session)
{
	struct rspamd_grey_reply          reply;

	switch (session->cmd.cmd) {
	case GREY_CMD_CHECK:
		CMD_PROCESS (check);
		break;
	case GREY_CMD_ADD:
		CMD_PROCESS (add);
		break;
	case GREY_CMD_DEL:
		CMD_PROCESS (delete);
		break;
	}
}

#undef CMD_PROCESS

/*
 * Accept new connection and construct task
 */
static void
accept_greylist_socket (gint fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	struct greylist_session         session;
	ssize_t                         r;

	session.worker = worker;
	session.fd = fd;
	session.pos = (guint8 *) & session.cmd;
	session.salen = sizeof (session.sa);

	/* Got some data */
	if (what == EV_READ) {
		if ((r = recvfrom (fd, session.pos, sizeof (struct rspamd_grey_command), MSG_WAITALL, (struct sockaddr *)&session.sa, &session.salen)) == -1) {
			msg_err ("got error while reading from socket: %d, %s", errno, strerror (errno));
			return;
		}
		else if (r == sizeof (struct rspamd_grey_command)) {
			/* Assume that the whole command was read */
			process_greylist_command (&session);
		}
		else {
			msg_err ("got incomplete data while reading from socket: %d, %s", errno, strerror (errno));
			return;
		}
	}
}

static gboolean
config_greylist_worker (struct rspamd_worker *worker)
{
	struct greylist_ctx            *ctx;
	gchar                           *value;

	ctx = g_malloc0 (sizeof (struct greylist_ctx));
#ifdef WITH_JUDY
	ctx->jtree = NULL;
#else
	ctx->tree = g_tree_new_full (grey_cmp, NULL, NULL, g_free);
#endif
	
	ctx->greylist_time = DEFAULT_GREYLIST_TIME;
	ctx->expire_time = DEFAULT_EXPIRE_TIME;

	if ((value = g_hash_table_lookup (worker->cf->params, "greylist_time")) != NULL) {
		ctx->greylist_time = parse_time (value, TIME_SECONDS) / 1000;
	}
	if ((value = g_hash_table_lookup (worker->cf->params, "expire_time")) != NULL) {
		ctx->expire_time = parse_time (value, TIME_SECONDS) / 1000;
	}
	worker->ctx = ctx;

	return TRUE;
}

/*
 * Start worker process
 */
void
start_greylist_storage (struct rspamd_worker *worker)
{
	struct sigaction                signals;
	struct event                    sev;
	gint                            retries = 0;

	worker->srv->pid = getpid ();
	worker->srv->type = TYPE_GREYLIST;

	event_init ();

	init_signals (&signals, sig_handler);
	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);

	/* SIGUSR2 handler */
	signal_set (&worker->sig_ev, SIGUSR2, sigusr_handler, (void *)worker);
	signal_add (&worker->sig_ev, NULL);
	signal_set (&sev, SIGTERM, sigterm_handler, (void *)worker);
	signal_add (&sev, NULL);

	/* Accept event */
	while ((worker->cf->listen_sock = make_udp_socket (&worker->cf->bind_addr, worker->cf->bind_port, TRUE, TRUE)) == -1) {
		sleep (1);
		if (++retries > MAX_RETRIES) {
			msg_err ("cannot bind to socket, exiting");
			exit (EXIT_SUCCESS);
		}
	}
	event_set (&worker->bind_ev, worker->cf->listen_sock, EV_READ | EV_PERSIST, accept_greylist_socket, (void *)worker);
	event_add (&worker->bind_ev, NULL);

	gperf_profiler_init (worker->srv->cfg, "greylist");

	if (!config_greylist_worker (worker)) {
		msg_err ("cannot configure greylisting worker, exiting");
		exit (EXIT_SUCCESS);
	}

	event_loop (0);
	exit (EXIT_SUCCESS);
}
