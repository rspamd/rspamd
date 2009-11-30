/*
 * Copyright (c) 2009, Rambler media
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
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

#include "config.h"
#include "cfg_file.h"
#include "tokenizers/tokenizers.h"
#include "classifiers/classifiers.h"
#include "statfile.h"
#include "binlog.h"
#include "buffer.h"
#include "statfile_sync.h"

/* XXX: hardcoding this value is not very smart */
#define MAX_SYNC_TIME 60
#define IO_TIMEOUT 5


enum rspamd_sync_state {
	SYNC_STATE_GREETING,
	SYNC_STATE_READ_LINE,
	SYNC_STATE_READ_REV,
	SYNC_STATE_QUIT,
};

/* Context of sync process */
struct rspamd_sync_ctx {
	struct statfile *st;
	stat_file_t *real_statfile;
	statfile_pool_t *pool;
	rspamd_io_dispatcher_t *dispatcher;

	struct event tm_ev;

	struct timeval interval;
	struct timeval io_tv;
	int sock;
	enum rspamd_sync_state state;
	gboolean is_busy;

	uint64_t new_rev;
	uint64_t new_time;
	uint64_t new_len;
};

static void
log_next_sync (const char *symbol, time_t delay)
{
	char outstr[200];
    time_t t;
	struct tm *tmp;
	int r;

	t = time(NULL);
	t += delay;
    tmp = localtime(&t);

	if (tmp) {
		r = snprintf (outstr, sizeof (outstr), "statfile_sync: next sync of %s at ", symbol);
		if ((r = strftime(outstr + r, sizeof(outstr) - r, "%T", tmp)) != 0) {
			msg_info (outstr);
		}
	}
}

static                          gboolean
parse_revision_line (struct rspamd_sync_ctx *ctx, f_str_t *in)
{
	int i, state = 0;
	char *p, *c, t;
	uint64_t *val;

	/* First of all try to find END line */
	if (in->len >= sizeof ("END") - 1 && memcmp (in->begin, "END", sizeof ("END") - 1) == 0) {
		ctx->state = SYNC_STATE_QUIT;
		ctx->is_busy = FALSE;
		return TRUE;
	}

	/* Next check for error line */
	if (in->len >= sizeof ("FAIL") - 1 && memcmp (in->begin, "FAIL", sizeof ("FAIL") - 1) == 0) {
		ctx->state = SYNC_STATE_QUIT;
		ctx->is_busy = FALSE;
		return TRUE;
	}

	/* Now try to extract 3 numbers from string: revision, time and length */
	p = in->begin;
	val = &ctx->new_rev;
	for (i = 0; i < in->len; i ++, p ++) {
		if (g_ascii_isspace (*p) || i == in->len - 1) {
			if (state == 1) {
				t = *p;
				*p = '\0';
				errno = 0;
				*val = strtoull (c, NULL, 10);
				*p = t;
				if (errno != 0) {
					msg_info ("parse_revision_line: cannot parse number %s", strerror (errno));
					return FALSE;
				}
				state = 2;
			}
		}
		else {
			if (state == 0) {
				c = p;
				state = 1;
			}
			else if (state == 2) {
				if (val == &ctx->new_rev) {
					val = &ctx->new_time;
				}
				else if (val == &ctx->new_time) {
					val = &ctx->new_len;
				}
				c = p;
				state = 1;
			}
		}
	}
	
	/* Current value must be len value and its value must not be 0 */
	return ((val == &ctx->new_len) && *val != 0);
}

static                          gboolean
read_blocks (struct rspamd_sync_ctx *ctx, f_str_t *in)
{
	struct rspamd_binlog_element *elt;
	int                           i;
	
	statfile_pool_lock_file (ctx->pool, ctx->real_statfile);
	elt = (struct rspamd_binlog_element *)in->begin;
	for (i = 0; i < in->len / sizeof (struct rspamd_binlog_element); i ++, elt ++) {
		statfile_pool_set_block (ctx->pool, ctx->real_statfile, elt->h1, elt->h2, ctx->new_time, elt->value);
	}
	statfile_pool_unlock_file (ctx->pool, ctx->real_statfile);

	return TRUE;
}

static                          gboolean
sync_read (f_str_t * in, void *arg)
{
	struct rspamd_sync_ctx *ctx = arg;
	char                    buf[256];
	uint64_t                rev = 0;
	time_t                  ti = 0;

	switch (ctx->state) {
		case SYNC_STATE_GREETING:
			/* Skip greeting line and write sync command */
			/* Write initial data */
			statfile_get_revision (ctx->real_statfile, &rev, &ti);
			rev = snprintf (buf, sizeof (buf), "sync %s %ld %ld" CRLF, ctx->st->symbol, (long int)rev, (long int)ti);
			ctx->state = SYNC_STATE_READ_LINE;
			rspamd_dispatcher_write (ctx->dispatcher, buf, rev, FALSE, FALSE);	
			break;
		case SYNC_STATE_READ_LINE:
			/* Try to parse line from server */
			if (!parse_revision_line (ctx, in)) {
				msg_info ("sync_read: cannot parse line: %S", in);
				rspamd_remove_dispatcher (ctx->dispatcher);
				ctx->is_busy = FALSE;
				return FALSE;
			}
			else if (ctx->state != SYNC_STATE_QUIT) {
				ctx->state = SYNC_STATE_READ_REV;
				rspamd_set_dispatcher_policy (ctx->dispatcher, BUFFER_CHARACTER, ctx->new_len);
			}
			else {
				/* Quit this session */
				rspamd_remove_dispatcher (ctx->dispatcher);
				ctx->is_busy = FALSE;
				/* Immideately return from callback */ 
				return FALSE;
			}
			break;
		case SYNC_STATE_READ_REV:
			/* In now contains all blocks of specified revision, so we can read them directly */
			if (!read_blocks (ctx, in)) {
				msg_info ("sync_read: cannot read blocks");
				rspamd_remove_dispatcher (ctx->dispatcher);
				ctx->is_busy = FALSE;
				return FALSE;
			}
			statfile_set_revision (ctx->real_statfile, ctx->new_rev, ctx->new_time);
			/* Now try to read other revision or END line */
			rspamd_set_dispatcher_policy (ctx->dispatcher, BUFFER_LINE, 0);
			ctx->state = SYNC_STATE_READ_LINE;
			break;
		case SYNC_STATE_QUIT:
			rspamd_remove_dispatcher (ctx->dispatcher);
			ctx->is_busy = FALSE;
			return FALSE;
	}

	return TRUE;
}

static                         void 
sync_err (GError *err, void *arg)
{
	struct rspamd_sync_ctx *ctx = arg;

	msg_info ("sync_err: abnormally closing connection, error: %s", err->message);
	ctx->is_busy = FALSE;
	rspamd_remove_dispatcher (ctx->dispatcher);
}


static void
sync_timer_callback (int fd, short what, void *ud)
{
	struct rspamd_sync_ctx *ctx = ud;
	
	/* Plan new event */
	evtimer_del (&ctx->tm_ev);
	ctx->interval.tv_sec = g_random_int_range (MAX_SYNC_TIME, MAX_SYNC_TIME * 2);
	ctx->interval.tv_usec = 0;
	evtimer_add (&ctx->tm_ev, &ctx->interval);
	log_next_sync (ctx->st->symbol, ctx->interval.tv_sec);
	
	if (ctx->is_busy) {
		/* Sync is in progress */
		msg_info ("sync_timer_callback: syncronization process is in progress, do not start new one");
		return;
	}

	if ((ctx->sock = make_tcp_socket (&ctx->st->binlog->master_addr, ctx->st->binlog->master_port, FALSE, TRUE)) == -1) {
		msg_info ("sync_timer_callback: cannot connect to %s", inet_ntoa (ctx->st->binlog->master_addr));
		return;
	}
	/* Now create and activate dispatcher */
	ctx->io_tv.tv_sec = IO_TIMEOUT;
	ctx->io_tv.tv_usec = 0;
	ctx->dispatcher = rspamd_create_dispatcher (ctx->sock, BUFFER_LINE, sync_read, NULL, sync_err, &ctx->io_tv, ctx);
	
	ctx->state = SYNC_STATE_GREETING;
	ctx->is_busy = TRUE;

	msg_info ("sync_timer_callback: starting synchronization of %s", ctx->st->symbol);

}

static gboolean
add_statfile_watch (statfile_pool_t *pool, struct statfile *st)
{
	struct rspamd_sync_ctx *ctx;
	
	ctx = memory_pool_alloc (pool->pool, sizeof (struct rspamd_sync_ctx));
	ctx->st = st;
	/* Add some jittering for synchronization */
	ctx->interval.tv_sec = g_random_int_range (MAX_SYNC_TIME, MAX_SYNC_TIME * 2);
	ctx->interval.tv_usec = 0;
	/* Open statfile and attach it to pool */
	if ((ctx->real_statfile = statfile_pool_is_open (pool, st->path)) == NULL) {
		if ((ctx->real_statfile = statfile_pool_open (pool, st->path, st->size, FALSE)) == NULL) {
			msg_warn ("add_statfile_watch: cannot open %s", st->path);
			if (statfile_pool_create (pool, st->path, st->size) == -1) {
				msg_err ("add_statfile_watch: cannot create statfile %s", st->path);
				return FALSE;
			}
			ctx->real_statfile = statfile_pool_open (pool, st->path, st->size, FALSE);
		}
	}
	/* Now plan event for it's future executing */
	evtimer_set (&ctx->tm_ev, sync_timer_callback, ctx);
	evtimer_add (&ctx->tm_ev, &ctx->interval);
	log_next_sync (st->symbol, ctx->interval.tv_sec);

	return TRUE;
}

gboolean 
start_statfile_sync (statfile_pool_t *pool, struct config_file *cfg)
{
	GList *cur, *l;
	struct classifier_config *cl;
	struct statfile *st;

	/* 
	 * First of all walk through all classifiers and find those statfiles
	 * for which we should do sync (slave affinity)
	 */
	cur = cfg->classifiers;
	while (cur) {
		cl = cur->data;
		l = cl->statfiles;
		while (l) {
			st = l->data;
			if (st->binlog != NULL && st->binlog->affinity == AFFINITY_SLAVE) {
				if (!add_statfile_watch (pool, st)) {
					return FALSE;
				}
			}
			l = g_list_next (l);
		}
		cur = g_list_next (cur);
	}

	return TRUE;
}
