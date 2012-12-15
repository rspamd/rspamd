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

static GQuark
rrd_error_quark (void)
{
	return g_quark_from_static_string ("rrd-error");
}

/**
 * Convert rrd dst type from string to numeric value
 */
enum rrd_dst_type
rrd_dst_from_string (const gchar *str)
{
	if (g_ascii_strcasecmp (str, "counter") == 0) {
		return RRD_DST_COUNTER;
	}
	else if (g_ascii_strcasecmp (str, "absolute") == 0) {
		return RRD_DST_ABSOLUTE;
	}
	else if (g_ascii_strcasecmp (str, "gauge") == 0) {
		return RRD_DST_GAUGE;
	}
	else if (g_ascii_strcasecmp (str, "cdef") == 0) {
		return RRD_DST_CDEF;
	}
	else if (g_ascii_strcasecmp (str, "derive") == 0) {
		return RRD_DST_DERIVE;
	}
	return -1;
}

/**
 * Convert numeric presentation of dst to string
 */
const gchar*
rrd_dst_to_string (enum rrd_dst_type type)
{
	switch (type) {
	case RRD_DST_COUNTER:
		return "COUNTER";
	case RRD_DST_ABSOLUTE:
		return "ABSOLUTE";
	case RRD_DST_GAUGE:
		return "GAUGE";
	case RRD_DST_CDEF:
		return "CDEF";
	case RRD_DST_DERIVE:
		return "DERIVE";
	default:
		return "U";
	}

	return "U";
}

/**
 * Convert rrd consolidation function type from string to numeric value
 */
enum rrd_cf_type
rrd_cf_from_string (const gchar *str)
{
	if (g_ascii_strcasecmp (str, "average") == 0) {
		return RRD_CF_AVERAGE;
	}
	else if (g_ascii_strcasecmp (str, "minimum") == 0) {
		return RRD_CF_MINIMUM;
	}
	else if (g_ascii_strcasecmp (str, "maximum") == 0) {
		return RRD_CF_MAXIMUM;
	}
	else if (g_ascii_strcasecmp (str, "last") == 0) {
		return RRD_CF_LAST;
	}
	/* XXX: add other CF functions supported by rrd */
	return -1;
}

/**
 * Convert numeric presentation of cf to string
 */
const gchar*
rrd_cf_to_string (enum rrd_cf_type type)
{
	switch (type) {
	case RRD_CF_AVERAGE:
		return "AVERAGE";
	case RRD_CF_MINIMUM:
		return "MINIMUM";
	case RRD_CF_MAXIMUM:
		return "MAXIMUM";
	case RRD_CF_LAST:
		return "LAST";
	default:
		return "U";
	}

	/* XXX: add other CF functions supported by rrd */

	return "U";
}

/**
 * Check rrd file for correctness (size, cookies, etc)
 */
static gboolean
rspamd_rrd_check_file (const gchar *filename, gboolean need_data, GError **err)
{
	gint								 fd, i;
	struct stat							 st;
	struct rrd_file_head				 head;
	struct rrd_rra_def					 rra;
	gint								 head_size;

	fd = open (filename, O_RDWR);
	if (fd == -1) {
		g_set_error (err, rrd_error_quark (), errno, "rrd open error: %s", strerror (errno));
		return FALSE;
	}

	if (fstat (fd, &st) == -1) {
		g_set_error (err, rrd_error_quark (), errno, "rrd stat error: %s", strerror (errno));
		close (fd);
		return FALSE;
	}
	if (st.st_size < (goffset)sizeof (struct rrd_file_head)) {
		/* We have trimmed file */
		g_set_error (err, rrd_error_quark (), EINVAL, "rrd size is bad: %ud", (guint)st.st_size);
		close (fd);
		return FALSE;
	}

	/* Try to read header */
	if (read (fd, &head, sizeof (head)) != sizeof (head)) {
		g_set_error (err, rrd_error_quark (), errno, "rrd read head error: %s", strerror (errno));
		close (fd);
		return FALSE;
	}
	/* Check magic */
	if (memcmp (head.cookie, RRD_COOKIE, sizeof (head.cookie)) != 0 ||
			memcmp (head.version, RRD_VERSION, sizeof (head.version)) != 0 ||
			head.float_cookie != RRD_FLOAT_COOKIE) {
		g_set_error (err, rrd_error_quark (), EINVAL, "rrd head cookies error: %s", strerror (errno));
		close (fd);
		return FALSE;
	}
	/* Check for other params */
	if (head.ds_cnt <= 0 || head.rra_cnt <= 0) {
		g_set_error (err, rrd_error_quark (), EINVAL, "rrd head cookies error: %s", strerror (errno));
		close (fd);
		return FALSE;
	}
	/* Now we can calculate the overall size of rrd */
	head_size = sizeof (struct rrd_file_head) +
			sizeof (struct rrd_ds_def) * head.ds_cnt +
			sizeof (struct rrd_rra_def) * head.rra_cnt +
			sizeof (struct rrd_live_head) +
			sizeof (struct rrd_pdp_prep) * head.ds_cnt +
			sizeof (struct rrd_cdp_prep) * head.ds_cnt * head.rra_cnt +
			sizeof (struct rrd_rra_ptr) * head.rra_cnt;
	if (st.st_size < (goffset)head_size) {
		g_set_error (err, rrd_error_quark (), errno, "rrd file seems to have stripped header: %d", head_size);
		close (fd);
		return FALSE;
	}

	if (need_data) {
		/* Now check rra */
		if (lseek (fd, sizeof (struct rrd_ds_def) * head.ds_cnt, SEEK_CUR) == -1) {
			g_set_error (err, rrd_error_quark (), errno, "rrd head lseek error: %s", strerror (errno));
			close (fd);
			return FALSE;
		}
		for (i = 0; i < (gint)head.rra_cnt; i ++) {
			if (read (fd, &rra, sizeof (rra)) != sizeof (rra)) {
				g_set_error (err, rrd_error_quark (), errno, "rrd read rra error: %s", strerror (errno));
				close (fd);
				return FALSE;
			}
			head_size += rra.row_cnt * head.ds_cnt * sizeof (gdouble);
		}

		if (st.st_size != head_size) {
			g_set_error (err, rrd_error_quark (), EINVAL, "rrd file seems to have incorrect size: %d, must be %d", (gint)st.st_size, head_size);
			close (fd);
			return FALSE;
		}
	}

	close (fd);
	return TRUE;
}

/**
 * Adjust pointers in mmapped rrd file
 * @param file
 */
static void
rspamd_rrd_adjust_pointers (struct rspamd_rrd_file *file, gboolean completed)
{
	guint8										*ptr;

	ptr = file->map;
	file->stat_head = (struct rrd_file_head *)ptr;
	ptr += sizeof (struct rrd_file_head);
	file->ds_def = (struct rrd_ds_def *)ptr;
	ptr += sizeof (struct rrd_ds_def) * file->stat_head->ds_cnt;
	file->rra_def = (struct rrd_rra_def *)ptr;
	ptr += sizeof (struct rrd_rra_def) * file->stat_head->rra_cnt;
	file->live_head = (struct rrd_live_head *)ptr;
	ptr += sizeof (struct rrd_live_head);
	file->pdp_prep = (struct rrd_pdp_prep *)ptr;
	ptr += sizeof (struct rrd_pdp_prep) * file->stat_head->ds_cnt;
	file->cdp_prep = (struct rrd_cdp_prep *)ptr;
	ptr += sizeof (struct rrd_cdp_prep) * file->stat_head->rra_cnt * file->stat_head->ds_cnt;
	file->rra_ptr = (struct rrd_rra_ptr *)ptr;
	if (completed) {
		ptr += sizeof (struct rrd_rra_ptr) * file->stat_head->rra_cnt;
		file->rrd_value = (gdouble *)ptr;
	}
	else {
		file->rrd_value = NULL;
	}
}

/**
 * Open completed or incompleted rrd file
 * @param filename
 * @param completed
 * @param err
 * @return
 */
static struct rspamd_rrd_file*
rspamd_rrd_open_common (const gchar *filename, gboolean completed, GError **err)
{
	struct rspamd_rrd_file						*new;
	gint										 fd;
	struct stat									 st;

	if (!rspamd_rrd_check_file (filename, completed, err)) {
		return NULL;
	}

	new = g_slice_alloc0 (sizeof (struct rspamd_rrd_file));

	if (new == NULL) {
		g_set_error (err, rrd_error_quark (), ENOMEM, "not enough memory");
		return NULL;
	}

	/* Open file */
	fd = open (filename, O_RDWR);
	if (fd == -1) {
		g_set_error (err, rrd_error_quark (), errno, "rrd open error: %s", strerror (errno));
		return FALSE;
	}

	if (fstat (fd, &st) == -1) {
		g_set_error (err, rrd_error_quark (), errno, "rrd stat error: %s", strerror (errno));
		close (fd);
		return FALSE;
	}
	/* Mmap file */
	new->size = st.st_size;
	if ((new->map = mmap (NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		close (fd);
		g_set_error (err, rrd_error_quark (), ENOMEM, "mmap failed: %s", strerror (errno));
		g_slice_free1 (sizeof (struct rspamd_rrd_file), new);
		return NULL;
	}

	close (fd);

	/* Adjust pointers */
	rspamd_rrd_adjust_pointers (new, completed);

	/* Mark it as finalized */
	new->finalized = completed;

	new->filename = g_strdup (filename);

	return new;
}

/**
 * Open (and mmap) existing RRD file
 * @param filename path
 * @param err error pointer
 * @return rrd file structure
 */
struct rspamd_rrd_file*
rspamd_rrd_open (const gchar *filename, GError **err)
{
	return rspamd_rrd_open_common (filename, TRUE, err);
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
struct rspamd_rrd_file*
rspamd_rrd_create (const gchar *filename, gulong ds_count, gulong rra_count, gulong pdp_step, GError **err)
{
	struct rspamd_rrd_file						*new;
	struct rrd_file_head						 head;
	struct rrd_ds_def							 ds;
	struct rrd_rra_def							 rra;
	struct rrd_live_head						 lh;
	struct rrd_pdp_prep							 pdp;
	struct rrd_cdp_prep							 cdp;
	struct rrd_rra_ptr							 rra_ptr;
	gint										 fd;
	guint										 i, j;

	/* Open file */
	fd = open (filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd == -1) {
		g_set_error (err, rrd_error_quark (), errno, "rrd create error: %s", strerror (errno));
		return NULL;
	}

	/* Fill header */
	memset (&head, 0, sizeof (head));
	head.rra_cnt = rra_count;
	head.ds_cnt = ds_count;
	head.pdp_step = pdp_step;
	memcpy (head.cookie, RRD_COOKIE, sizeof (head.cookie));
	memcpy (head.version, RRD_VERSION, sizeof (head.version));
	head.float_cookie = RRD_FLOAT_COOKIE;

	if (write (fd, &head, sizeof (head)) != sizeof (head)) {
		close (fd);
		g_set_error (err, rrd_error_quark (), errno, "rrd write error: %s", strerror (errno));
		return NULL;
	}

	/* Fill DS section */
	memset (&ds.ds_nam, 0, sizeof (ds.ds_nam));
	memcpy (&ds.dst, "COUNTER", sizeof ("COUNTER"));
	memset (&ds.par, 0, sizeof (ds.par));
	for (i = 0; i < ds_count; i ++) {
		if (write (fd, &ds, sizeof (ds)) != sizeof (ds)) {
			close (fd);
			g_set_error (err, rrd_error_quark (), errno, "rrd write error: %s", strerror (errno));
			return NULL;
		}
	}

	/* Fill RRA section */
	memcpy (&rra.cf_nam, "AVERAGE", sizeof ("AVERAGE"));
	rra.pdp_cnt = 1;
	memset (&rra.par, 0, sizeof (rra.par));
	for (i = 0; i < rra_count; i ++) {
		if (write (fd, &rra, sizeof (rra)) != sizeof (rra)) {
			close (fd);
			g_set_error (err, rrd_error_quark (), errno, "rrd write error: %s", strerror (errno));
			return NULL;
		}
	}

	/* Fill live header */
	lh.last_up = time (NULL) - 10;
	lh.last_up_usec = 0;

	if (write (fd, &lh, sizeof (lh)) != sizeof (lh)) {
		close (fd);
		g_set_error (err, rrd_error_quark (), errno, "rrd write error: %s", strerror (errno));
		return NULL;
	}

	/* Fill pdp prep */
	memcpy (&pdp.last_ds, "U", sizeof ("U"));
	memset (&pdp.scratch, 0, sizeof (pdp.scratch));
	pdp.scratch[PDP_val].dv = 0.;
	pdp.scratch[PDP_unkn_sec_cnt].lv = lh.last_up % pdp_step;
	for (i = 0; i < ds_count; i ++) {
		if (write (fd, &pdp, sizeof (pdp)) != sizeof (pdp)) {
			close (fd);
			g_set_error (err, rrd_error_quark (), errno, "rrd write error: %s", strerror (errno));
			return NULL;
		}
	}

	/* Fill cdp prep */
	memset (&cdp.scratch, 0, sizeof (cdp.scratch));
	cdp.scratch[CDP_val].dv = NAN;
	for (i = 0; i < rra_count; i ++) {
		cdp.scratch[CDP_unkn_pdp_cnt].lv = ((lh.last_up - pdp.scratch[PDP_unkn_sec_cnt].lv) % (pdp_step * rra.pdp_cnt)) / pdp_step;
		for (j = 0; j < ds_count; j ++) {
			if (write (fd, &cdp, sizeof (cdp)) != sizeof (cdp)) {
				close (fd);
				g_set_error (err, rrd_error_quark (), errno, "rrd write error: %s", strerror (errno));
				return NULL;
			}
		}
	}

	/* Set row pointers */
	memset (&rra_ptr, 0, sizeof (rra_ptr));
	for (i = 0; i < rra_count; i ++) {
		if (write (fd, &rra_ptr, sizeof (rra_ptr)) != sizeof (rra_ptr)) {
			close (fd);
			g_set_error (err, rrd_error_quark (), errno, "rrd write error: %s", strerror (errno));
			return NULL;
		}
	}

	close (fd);
	new = rspamd_rrd_open_common (filename, FALSE, err);

	return new;
}

/**
 * Add data sources to rrd file
 * @param filename path to file
 * @param ds array of struct rrd_ds_def
 * @param err error pointer
 * @return TRUE if data sources were added
 */
gboolean
rspamd_rrd_add_ds (struct rspamd_rrd_file *file, GArray *ds, GError **err)
{

	if (file == NULL || file->stat_head->ds_cnt * sizeof (struct rrd_ds_def) != ds->len) {
		g_set_error (err, rrd_error_quark (), EINVAL, "rrd add ds failed: wrong arguments");
		return FALSE;
	}

	/* Straightforward memcpy */
	memcpy (file->ds_def, ds->data, ds->len);

	return TRUE;
}

/**
 * Add round robin archives to rrd file
 * @param filename path to file
 * @param ds array of struct rrd_rra_def
 * @param err error pointer
 * @return TRUE if archives were added
 */
gboolean
rspamd_rrd_add_rra (struct rspamd_rrd_file *file, GArray *rra, GError **err)
{
	if (file == NULL || file->stat_head->rra_cnt * sizeof (struct rrd_rra_def) != rra->len) {
		g_set_error (err, rrd_error_quark (), EINVAL, "rrd add rra failed: wrong arguments");
		return FALSE;
	}

	/* Straightforward memcpy */
	memcpy (file->rra_def, rra->data, rra->len);

	return TRUE;
}

/**
 * Finalize rrd file header and initialize all RRA in the file
 * @param filename file path
 * @param err error pointer
 * @return TRUE if rrd file is ready for use
 */
gboolean
rspamd_rrd_finalize (struct rspamd_rrd_file *file, GError **err)
{
	gint										 fd;
	guint										 i;
	gint										 count = 0;
	gdouble										 vbuf[1024];
	struct stat									 st;

	if (file == NULL || file->filename == NULL) {
		g_set_error (err, rrd_error_quark (), EINVAL, "rrd add rra failed: wrong arguments");
		return FALSE;
	}

	fd = open (file->filename, O_RDWR);
	if (fd == -1) {
		g_set_error (err, rrd_error_quark (), errno, "rrd open error: %s", strerror (errno));
		return FALSE;
	}

	if (lseek (fd, 0, SEEK_END) == -1) {
		g_set_error (err, rrd_error_quark (), errno, "rrd seek error: %s", strerror (errno));
		close (fd);
		return FALSE;
	}

	/* Adjust CDP */
	for (i = 0; i < file->stat_head->rra_cnt; i ++) {
		file->cdp_prep->scratch[CDP_unkn_pdp_cnt].lv =
				((file->live_head->last_up - file->pdp_prep->scratch[PDP_unkn_sec_cnt].lv) % (file->stat_head->pdp_step *
						file->rra_def[i].pdp_cnt)) / file->stat_head->pdp_step;
		/* Randomize row pointer */
		file->rra_ptr->cur_row = g_random_int () % file->rra_def[i].row_cnt;
		/* Calculate values count */
		count += file->rra_def[i].row_cnt * file->stat_head->ds_cnt;
	}

	munmap (file->map, file->size);
	/* Write values */
	for (i = 0; i < G_N_ELEMENTS (vbuf); i ++) {
		vbuf[i] = NAN;
	}

	while (count > 0) {
		/* Write values in buffered matter */
		if (write (fd, vbuf, MIN ((gint)G_N_ELEMENTS (vbuf), count) * sizeof (gdouble)) == -1) {
			g_set_error (err, rrd_error_quark (), errno, "rrd write error: %s", strerror (errno));
			close (fd);
			return FALSE;
		}
		count -= G_N_ELEMENTS (vbuf);
	}

	if (fstat (fd, &st) == -1) {
		g_set_error (err, rrd_error_quark (), errno, "rrd stat error: %s", strerror (errno));
		close (fd);
		return FALSE;
	}

	/* Mmap again */
	file->size = st.st_size;
	if ((file->map = mmap (NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		close (fd);
		g_set_error (err, rrd_error_quark (), ENOMEM, "mmap failed: %s", strerror (errno));
		g_slice_free1 (sizeof (struct rspamd_rrd_file), file);
		return FALSE;
	}
	close (fd);
	/* Adjust pointers */
	rspamd_rrd_adjust_pointers (file, TRUE);

	file->finalized = TRUE;

	return TRUE;
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
	gdouble									*row;
	guint									 i;

	if (file == NULL || file->stat_head->ds_cnt * sizeof (gdouble) != points->len || rra_idx >= file->stat_head->rra_cnt) {
		g_set_error (err, rrd_error_quark (), EINVAL, "rrd add points failed: wrong arguments");
		return FALSE;
	}

	row = file->rrd_value;
	/* Skip unaffected rra */
	for (i = 0; i < rra_idx; i ++) {
		row += file->rra_def[i].row_cnt * file->stat_head->ds_cnt;
	}

	row += file->rra_ptr[rra_idx].cur_row * file->stat_head->ds_cnt;

	/* Increase row index */
	file->rra_ptr[rra_idx].cur_row ++;
	if (file->rra_ptr[rra_idx].cur_row >= file->rra_def[rra_idx].row_cnt) {
		file->rra_ptr[rra_idx].cur_row = 0;
	}

	/* Write data */
	memcpy (row, points->data, points->len);

	return TRUE;
}

/**
 * Close rrd file
 * @param file
 * @return
 */
gint
rspamd_rrd_close (struct rspamd_rrd_file* file)
{
	if (file == NULL) {
		errno = EINVAL;
		return -1;
	}

	munmap (file->map, file->size);
	if (file->filename != NULL) {
		g_free (file->filename);
	}
	g_slice_free1 (sizeof (struct rspamd_rrd_file), file);

	return 0;
}
