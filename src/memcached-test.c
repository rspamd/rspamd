/*
 * Copyright (c) 2012, Vsevolod Stakhov
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

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <event.h>

#include "upstream.h"
#include "memcached.h"

#define HOST "127.0.0.1"
#define PORT 11211

memcached_param_t               cur_param;

static void
test_memc_callback (memcached_ctx_t * ctx, memc_error_t error, void *data)
{
	gint                            s;
	gint                            r;
	gint                            *num = ((gint *)data);
	printf ("result of memc command '%s' is '%s'\n", ctx->cmd, memc_strerror (error));
	/* Connect */
	if (*num == 0) {
		printf ("Setting value to memcached: %s -> %s\n", cur_param.key, (gchar *)cur_param.buf);
		s = 1;
		r = memc_set (ctx, &cur_param, &s, 60);
		(*num)++;
	}
	else if (*num == 1) {
		printf ("Getting value from memcached: %s -> %s\n", cur_param.key, (gchar *)cur_param.buf);
		s = 1;
		r = memc_get (ctx, &cur_param, &s);
		(*num)++;
	}
	else {
		printf ("Got value from memcached: %s -> %s\n", cur_param.key, (gchar *)cur_param.buf);
		event_loopexit (NULL);
	}
}


gint
main (gint argc, gchar **argv)
{
	memcached_ctx_t                 mctx;
	gchar                           *addr, buf[512];
	gint                            num = 0;

	event_init ();
	strcpy (cur_param.key, "testkey");
	strcpy (buf, "test_value");
	cur_param.buf = buf;
	cur_param.bufsize = sizeof ("test_value") - 1;

	if (argc == 2) {
		addr = argv[1];
	}
	else {
		addr = HOST;
	}

	mctx.protocol = TCP_TEXT;
	mctx.timeout.tv_sec = 1;
	mctx.timeout.tv_usec = 0;
	mctx.port = htons (PORT);
	mctx.options = MEMC_OPT_DEBUG;
	mctx.callback = test_memc_callback;
	/* XXX: it is wrong to use local variable pointer here */
	mctx.callback_data = (void *)&num;
	inet_aton (addr, &mctx.addr);

	memc_init_ctx (&mctx);

	event_loop (0);
	return 0;
}
