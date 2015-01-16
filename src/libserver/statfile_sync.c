/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "cfg_file.h"
#include "tokenizers.h"
#include "classifiers.h"
#include "statfile.h"
#include "binlog.h"
#include "buffer.h"
#include "statfile_sync.h"

enum rspamd_sync_state {
	SYNC_STATE_GREETING,
	SYNC_STATE_READ_LINE,
	SYNC_STATE_READ_REV,
	SYNC_STATE_QUIT,
};

/* Context of sync process */
struct rspamd_sync_ctx {
	struct rspamd_statfile_config *st;
	stat_file_t *real_statfile;
	statfile_pool_t *pool;
	rspamd_io_dispatcher_t *dispatcher;
	struct event_base *ev_base;

	struct event tm_ev;

	struct timeval interval;
	struct timeval io_tv;
	gint sock;
	guint32 timeout;
	guint32 sync_interval;
	enum rspamd_sync_state state;
	gboolean is_busy;

	guint64 new_rev;
	guint64 new_time;
	guint64 new_len;
};

static void
log_next_sync (const gchar *symbol, time_t delay)
{
	gchar outstr[200];
	time_t t;
	struct tm *tmp;
	gint r;

	t = time (NULL);
	t += delay;
	tmp = localtime (&t);

	if (tmp) {
		r = rspamd_snprintf (outstr,
				sizeof (outstr),
				"statfile_sync: next sync of %s at ",
				symbol);
		if ((r = strftime (outstr + r, sizeof(outstr) - r, "%T", tmp)) != 0) {
			msg_info (outstr);
		}
	}
}

static gboolean
parse_revision_line (struct rspamd_sync_ctx *ctx, rspamd_fstring_t *in)
{
	guint i, state = 0;
	gchar *p, *c, numbuf[sizeof("18446744073709551615")];
	guint64 *val;

	/* First of all try to find END line */
	if (in->len >= sizeof ("END") - 1 &&
		memcmp (in->begin, "END", sizeof ("END") - 1) == 0) {
		ctx->state = SYNC_STATE_QUIT;
		ctx->is_busy = FALSE;
		return TRUE;
	}

	/* Next check for error line */
	if (in->len >= sizeof ("FAIL") - 1 &&
		memcmp (in->begin, "FAIL", sizeof ("FAIL") - 1) == 0) {
		ctx->state = SYNC_STATE_QUIT;
		ctx->is_busy = FALSE;
		return TRUE;
	}

	/* Now try to extract 3 numbers from string: revision, time and length */
	p = in->begin;
	val = &ctx->new_rev;
	for (i = 0; i < in->len; i++, p++) {
		if (g_ascii_isspace (*p) || i == in->len - 1) {
			if (state == 1) {
				if (i == in->len - 1) {
					/* One more character */
					p++;
				}
				rspamd_strlcpy (numbuf, c, MIN (p - c + 1,
					(gint)sizeof (numbuf)));
				errno = 0;
				*val = strtoull (numbuf, NULL, 10);
				if (errno != 0) {
					msg_info ("cannot parse number %s", strerror (errno));
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
	return ((val == &ctx->new_len));
}

static gboolean
read_blocks (struct rspamd_sync_ctx *ctx, rspamd_fstring_t *in)
{
	struct rspamd_binlog_element *elt;
	guint i;

	statfile_pool_lock_file (ctx->pool, ctx->real_statfile);
	elt = (struct rspamd_binlog_element *)in->begin;
	for (i = 0; i < in->len / sizeof (struct rspamd_binlog_element); i++,
		elt++) {
		statfile_pool_set_block (ctx->pool,
			ctx->real_statfile,
			elt->h1,
			elt->h2,
			ctx->new_time,
			elt->value);
	}
	statfile_pool_unlock_file (ctx->pool, ctx->real_statfile);

	return TRUE;
}

static gboolean
sync_read (rspamd_fstring_t * in, void *arg)
{
	struct rspamd_sync_ctx *ctx = arg;
	gchar buf[256];
	guint64 rev = 0;
	time_t ti = 0;

	if (in->len == 0) {
		/* Skip empty lines */
		return TRUE;
	}
	switch (ctx->state) {
	case SYNC_STATE_GREETING:
		/* Skip greeting line and write sync command */
		/* Write initial data */
		statfile_get_revision (ctx->real_statfile, &rev, &ti);
		rev = rspamd_snprintf (buf,
				sizeof (buf),
				"sync %s %uL %T" CRLF,
				ctx->st->symbol,
				rev,
				ti);
		ctx->state = SYNC_STATE_READ_LINE;
		return rspamd_dispatcher_write (ctx->dispatcher, buf, rev, FALSE,
				   FALSE);
		break;
	case SYNC_STATE_READ_LINE:
		/* Try to parse line from server */
		if (!parse_revision_line (ctx, in)) {
			msg_info ("cannot parse line of length %z: '%*s'",
				in->len,
				(gint)in->len,
				in->begin);
			close (ctx->sock);
			rspamd_remove_dispatcher (ctx->dispatcher);
			ctx->is_busy = FALSE;
			return FALSE;
		}
		else if (ctx->state != SYNC_STATE_QUIT) {
			if (ctx->new_len > 0) {
				ctx->state = SYNC_STATE_READ_REV;
				rspamd_set_dispatcher_policy (ctx->dispatcher,
					BUFFER_CHARACTER,
					ctx->new_len);
			}
		}
		else {
			/* Quit this session */
			msg_info ("sync ended for: %s", ctx->st->symbol);
			close (ctx->sock);
			rspamd_remove_dispatcher (ctx->dispatcher);
			ctx->is_busy = FALSE;
			/* Immediately return from callback */
			return FALSE;
		}
		break;
	case SYNC_STATE_READ_REV:
		/* In now contains all blocks of specified revision, so we can read them directly */
		if (!read_blocks (ctx, in)) {
			msg_info ("cannot read blocks");
			close (ctx->sock);
			rspamd_remove_dispatcher (ctx->dispatcher);
			ctx->is_busy = FALSE;
			return FALSE;
		}
		statfile_set_revision (ctx->real_statfile, ctx->new_rev, ctx->new_time);
		msg_info ("set new revision: %uL, readed %z bytes",
			ctx->new_rev,
			in->len);
		/* Now try to read other revision or END line */
		ctx->state = SYNC_STATE_READ_LINE;
		rspamd_set_dispatcher_policy (ctx->dispatcher, BUFFER_LINE, 0);
		break;
	case SYNC_STATE_QUIT:
		close (ctx->sock);
		rspamd_remove_dispatcher (ctx->dispatcher);
		ctx->is_busy = FALSE;
		return FALSE;
	}

	return TRUE;
}

static void
sync_err (GError *err, void *arg)
{
	struct rspamd_sync_ctx *ctx = arg;

	msg_info ("abnormally closing connection, error: %s", err->message);
	ctx->is_busy = FALSE;
	close (ctx->sock);
	rspamd_remove_dispatcher (ctx->dispatcher);
}


static void
sync_timer_callback (gint fd, short what, void *ud)
{
	struct rspamd_sync_ctx *ctx = ud;
	guint32 jittered_interval;

	/* Plan new event */
	evtimer_del (&ctx->tm_ev);
	/* Add some jittering for synchronization */
	jittered_interval = g_random_int_range (ctx->sync_interval,
			ctx->sync_interval * 2);
	msec_to_tv (jittered_interval, &ctx->interval);
	evtimer_add (&ctx->tm_ev, &ctx->interval);
	log_next_sync (ctx->st->symbol, ctx->interval.tv_sec);

	if (ctx->is_busy) {
		/* Sync is in progress */
		msg_info ("syncronization process is in progress, do not start new one");
		return;
	}

	if ((ctx->sock =
		rspamd_socket (ctx->st->binlog->master_addr,
		ctx->st->binlog->master_port,
		SOCK_STREAM, TRUE, FALSE, TRUE)) == -1) {
		msg_info ("cannot connect to %s", ctx->st->binlog->master_addr);
		return;
	}
	/* Now create and activate dispatcher */
	msec_to_tv (ctx->timeout, &ctx->io_tv);
	ctx->dispatcher = rspamd_create_dispatcher (ctx->ev_base,
			ctx->sock,
			BUFFER_LINE,
			sync_read,
			NULL,
			sync_err,
			&ctx->io_tv,
			ctx);

	ctx->state = SYNC_STATE_GREETING;
	ctx->is_busy = TRUE;

	msg_info ("starting synchronization of %s", ctx->st->symbol);

}

static gboolean
add_statfile_watch (statfile_pool_t *pool,
	struct rspamd_statfile_config *st,
	struct rspamd_config *cfg,
	struct event_base *ev_base)
{
	struct rspamd_sync_ctx *ctx;
	guint32 jittered_interval;

	if (st->binlog->master_addr != NULL) {
		ctx =
			rspamd_mempool_alloc (pool->pool, sizeof (struct rspamd_sync_ctx));
		ctx->st = st;
		ctx->timeout = cfg->statfile_sync_timeout;
		ctx->sync_interval = cfg->statfile_sync_interval;
		ctx->ev_base = ev_base;
		/* Add some jittering for synchronization */
		jittered_interval = g_random_int_range (ctx->sync_interval,
				ctx->sync_interval * 2);
		msec_to_tv (jittered_interval, &ctx->interval);
		/* Open statfile and attach it to pool */
		if ((ctx->real_statfile =
			statfile_pool_is_open (pool, st->path)) == NULL) {
			if ((ctx->real_statfile =
				statfile_pool_open (pool, st->path, st->size, FALSE)) == NULL) {
				msg_warn ("cannot open %s", st->path);
				if (statfile_pool_create (pool, st->path, st->size) == -1) {
					msg_err ("cannot create statfile %s", st->path);
					return FALSE;
				}
				ctx->real_statfile = statfile_pool_open (pool,
						st->path,
						st->size,
						FALSE);
			}
		}
		/* Now plan event for it's future executing */
		evtimer_set (&ctx->tm_ev, sync_timer_callback, ctx);
		event_base_set (ctx->ev_base, &ctx->tm_ev);
		evtimer_add (&ctx->tm_ev, &ctx->interval);
		log_next_sync (st->symbol, ctx->interval.tv_sec);
	}
	else {
		msg_err ("cannot add statfile watch for statfile %s: no master defined",
			st->symbol);
		return FALSE;
	}

	return TRUE;
}

gboolean
start_statfile_sync (statfile_pool_t *pool,
	struct rspamd_config *cfg,
	struct event_base *ev_base)
{
	GList *cur, *l;
	struct rspamd_classifier_config *cl;
	struct rspamd_statfile_config *st;

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
				if (!add_statfile_watch (pool, st, cfg, ev_base)) {
					return FALSE;
				}
			}
			l = g_list_next (l);
		}
		cur = g_list_next (cur);
	}

	return TRUE;
}
