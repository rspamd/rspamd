/* Copyright (c) 2011, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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
#include "tests.h"
#include "main.h"
#include "aio_event.h"
#include "mem_pool.h"


extern struct event_base *base;

static void
aio_read_cb (gint fd, gint res, gsize len, gpointer data, gpointer ud)
{
	guchar *p = data;
	guint i;

	g_assert (res > 0);

	g_assert (len == BUFSIZ);
	for (i = 0; i < len; i ++) {
		g_assert (p[i] == 0xef);
	}

	event_base_loopbreak (base);
}

static void
aio_write_cb (gint fd, gint res, gsize len, gpointer data, gpointer ud)
{
	struct aio_context *aio_ctx = ud;
	gchar *testbuf;

	g_assert (res > 0);

	g_assert (posix_memalign ((void **)&testbuf, 512, BUFSIZ) == 0);

	g_assert (rspamd_aio_read (fd, testbuf, BUFSIZ, 0, aio_ctx, aio_read_cb, aio_ctx) != -1);
}

void
rspamd_async_test_func ()
{
	struct aio_context *aio_ctx;
	gchar *tmpfile;
	static gchar testbuf[BUFSIZ];
	gint fd, afd, ret;

	aio_ctx = rspamd_aio_init (base);

	g_assert (aio_ctx != NULL);

	fd = g_file_open_tmp ("raXXXXXX", &tmpfile, NULL);
	g_assert (fd != -1);

	afd = rspamd_aio_open (aio_ctx, tmpfile, O_RDWR);
	g_assert (fd != -1);

	/* Write some data */
	memset (testbuf, 0xef, sizeof (testbuf));
	ret = rspamd_aio_write (afd, testbuf, sizeof (testbuf), 0, aio_ctx, aio_write_cb, aio_ctx);
	g_assert (ret != -1);

	event_base_loop (base, 0);

	close (afd);
	close (fd);
	unlink (tmpfile);
}
