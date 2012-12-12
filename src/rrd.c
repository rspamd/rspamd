/* Copyright (c) 2010-2012, Vsevolod Stakhov
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
#include "rrd.h"

/**
 * Open (and mmap) existing RRD file
 * @param filename path
 * @param err error pointer
 * @return rrd file structure
 */
struct rspamd_rrd_file*
rspamd_rrd_open (const gchar *filename, GError **err)
{
	return NULL;
}

/**
 * Create basic header for rrd file
 * @param filename file path
 * @param ds_count number of data sources
 * @param rra_count number of round robin archives
 * @param pdp_step step of primary data points
 * @param err error pointer
 * @return TRUE if file has been created
 */
gboolean
rspamd_rrd_create (const gchar *filename, gulong ds_count, gulong rra_count, gulong pdp_step, GError **err)
{
	return FALSE;
}

/**
 * Add data sources to rrd file
 * @param filename path to file
 * @param ds array of struct rrd_ds_def
 * @param err error pointer
 * @return TRUE if data sources were added
 */
gboolean
rspamd_rrd_add_ds (const gchar *filename, GArray *ds, GError **err)
{
	return FALSE;
}

/**
 * Add round robin archives to rrd file
 * @param filename path to file
 * @param ds array of struct rrd_rra_def
 * @param err error pointer
 * @return TRUE if archives were added
 */
gboolean
rspamd_rrd_add_rra (const gchar *filename, GArray *rra, GError **err)
{
	return FALSE;
}

/**
 * Finalize rrd file header and initialize all RRA in the file
 * @param filename file path
 * @param err error pointer
 * @return TRUE if rrd file is ready for use
 */
gboolean
rspamd_rrd_finalize (const gchar *filename, GError **err)
{
	return FALSE;
}

/**
 * Add record to rrd file
 * @param file rrd file object
 * @param rra_idx index of rra being added
 * @param points points (must be row suitable for this RRA, depending on ds count)
 * @param err error pointer
 * @return TRUE if a row has been added
 */
gboolean
rspamd_rrd_add_record (struct rspamd_rrd_file* file, guint rra_idx, GArray *points, GError **err)
{
	return FALSE;
}
