/*-
 * Copyright 2016 Vsevolod Stakhov
 *
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
#include "aio_event.h"
#include "unix-std.h"

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
