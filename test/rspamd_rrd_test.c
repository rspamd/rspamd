/* Copyright (c) 2012, Vsevolod Stakhov
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
#include "rrd.h"
#include "main.h"

void
rspamd_rrd_test_func ()
{
	gchar  tmpfile[PATH_MAX];
	struct rrd_rra_def rra;
	struct rrd_ds_def ds;
	GArray ar;
	GError *err = NULL;
	struct rspamd_rrd_file *rrd;
	gint fd, i;
	gdouble t;

	rspamd_snprintf (tmpfile, sizeof (tmpfile), "/tmp/rspamd_rrd.rrd");

	/* Create sample rrd */
	g_assert ((rrd = rspamd_rrd_create (tmpfile, 1, 1, 5, &err)) != NULL);
	/* Add RRA */
	rrd_make_default_rra ("AVERAGE", 2, 100, &rra);
	ar.data = &rra;
	ar.len = sizeof (rra);
	g_assert (rspamd_rrd_add_rra (rrd, &ar, &err));
	/* Add DS */
	rrd_make_default_ds ("test", 1, &ds);
	ar.data = &ds;
	ar.len = sizeof (ds);
	g_assert (rspamd_rrd_add_ds (rrd, &ar, &err));
	/* Finalize */
	g_assert (rspamd_rrd_finalize (rrd, &err));
	/* Close */
	rspamd_rrd_close (rrd);

	/* Reopen */
	g_assert ((rrd = rspamd_rrd_open (tmpfile, &err)) != NULL);
#if 0
	/* Add some points */
	for (i = 0; i < 10; i ++) {
		t = i;
		ar.data = &t;
		ar.len = sizeof (gdouble);
		g_assert (rspamd_rrd_add_record (rrd, &ar, &err));
		sleep (1);
	}
#endif
	/* Finish */
	rspamd_rrd_close (rrd);
	/* unlink (tmpfile); */
}
