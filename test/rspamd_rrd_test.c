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
#include "tests.h"
#include "rrd.h"
#include "rspamd.h"
#include "ottery.h"

const int rows_cnt = 20;
const int pdp_per_cdp = 60;

void
rspamd_rrd_test_func ()
{
	gchar  tmpfile[PATH_MAX];
	struct rrd_rra_def rra[4];
	struct rrd_ds_def ds[2];
	GArray ar;
	GError *err = NULL;
	struct rspamd_rrd_file *rrd;
	gdouble ticks;
	gint i;
	gdouble t[2], cnt = 0.0;

	rspamd_snprintf (tmpfile, sizeof (tmpfile), "/tmp/rspamd_rrd.rrd");
	unlink (tmpfile);

	/* Create sample rrd */
	ticks = rspamd_get_calendar_ticks ();
	g_assert ((rrd = rspamd_rrd_create (tmpfile, 2, 4, 1, ticks, &err)) != NULL);
	/* Add RRA */
	rrd_make_default_rra ("AVERAGE", pdp_per_cdp, rows_cnt, &rra[0]);
	rrd_make_default_rra ("AVERAGE", pdp_per_cdp / 2, rows_cnt, &rra[1]);
	rrd_make_default_rra ("AVERAGE", pdp_per_cdp / 4, rows_cnt, &rra[2]);
	rrd_make_default_rra ("AVERAGE", pdp_per_cdp / 10, rows_cnt, &rra[3]);
	ar.data = rra;
	ar.len = sizeof (rra);
	g_assert (rspamd_rrd_add_rra (rrd, &ar, &err));
	/* Add DS */
	rrd_make_default_ds ("test", "COUNTER", 1, &ds[0]);
	rrd_make_default_ds ("test1", "COUNTER", 1, &ds[1]);
	ar.data = ds;
	ar.len = sizeof (ds);
	g_assert (rspamd_rrd_add_ds (rrd, &ar, &err));
	/* Finalize */
	g_assert (rspamd_rrd_finalize (rrd, &err));
	/* Close */
	rspamd_rrd_close (rrd);

	/* Reopen */
	g_assert ((rrd = rspamd_rrd_open (tmpfile, &err)) != NULL);
	/* Add some points */
	for (i = 0; i < pdp_per_cdp * rows_cnt / 2; i ++) {
		t[0] = i;
		t[1] = cnt ++;
		ar.data = t;
		ar.len = sizeof (t);
		ticks += 1.0;
		g_assert (rspamd_rrd_add_record (rrd, &ar, ticks, &err));

	}

	/* Add some more points */
	for (i = 0; i < pdp_per_cdp * rows_cnt / 4; i ++) {
		t[0] = i + rspamd_time_jitter (1.0, 0.0);
		t[1] = cnt ++;
		ar.data = t;
		ar.len = sizeof (t);
		ticks += 1.0;
		g_assert (rspamd_rrd_add_record (rrd, &ar, ticks, &err));

	}

	/* Add undefined interval */
	ticks += 200;

	/* Add some more points */
	for (i = 0; i < pdp_per_cdp * rows_cnt / 8; i ++) {
		t[0] = i;
		t[1] = cnt ++;
		ar.data = t;
		ar.len = sizeof (t);
		ticks += 1.0;
		g_assert (rspamd_rrd_add_record (rrd, &ar, ticks, &err));

	}

	/* Finish */
	rspamd_rrd_close (rrd);
	/* unlink (tmpfile); */
}
