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
#include "rrd.h"
#include "util.h"
#include "cfg_file.h"
#include "logger.h"
#include "unix-std.h"
#include "cryptobox.h"
#include <math.h>

#define RSPAMD_RRD_DS_COUNT METRIC_ACTION_MAX
#define RSPAMD_RRD_OLD_DS_COUNT 4
#define RSPAMD_RRD_RRA_COUNT 4

#define msg_err_rrd(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        "rrd", file->id, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_rrd(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        "rrd", file->id, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_rrd(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "rrd", file->id, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_rrd(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_rrd_log_id, "rrd", file->id, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(rrd)

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

	return RRD_DST_INVALID;
}

/**
 * Convert numeric presentation of dst to string
 */
const gchar *
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

	return RRD_CF_INVALID;
}

/**
 * Convert numeric presentation of cf to string
 */
const gchar *
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

void
rrd_make_default_rra (const gchar *cf_name,
	gulong pdp_cnt,
	gulong rows,
	struct rrd_rra_def *rra)
{
	g_assert (cf_name != NULL);
	g_assert (rrd_cf_from_string (cf_name) != RRD_CF_INVALID);

	rra->pdp_cnt = pdp_cnt;
	rra->row_cnt = rows;
	rspamd_strlcpy (rra->cf_nam, cf_name, sizeof (rra->cf_nam));
	memset (rra->par, 0, sizeof (rra->par));
	rra->par[RRA_cdp_xff_val].dv = 0.5;
}

void
rrd_make_default_ds (const gchar *name,
		const gchar *type,
		gulong pdp_step,
		struct rrd_ds_def *ds)
{
	g_assert (name != NULL);
	g_assert (type != NULL);
	g_assert (rrd_dst_from_string (type) != RRD_DST_INVALID);

	rspamd_strlcpy (ds->ds_nam, name,	   sizeof (ds->ds_nam));
	rspamd_strlcpy (ds->dst,	type, sizeof (ds->dst));
	memset (ds->par, 0, sizeof (ds->par));
	ds->par[RRD_DS_mrhb_cnt].lv = pdp_step * 2;
	ds->par[RRD_DS_min_val].dv = NAN;
	ds->par[RRD_DS_max_val].dv = NAN;
}

/**
 * Check rrd file for correctness (size, cookies, etc)
 */
static gboolean
rspamd_rrd_check_file (const gchar *filename, gboolean need_data, GError **err)
{
	gint fd, i;
	struct stat st;
	struct rrd_file_head head;
	struct rrd_rra_def rra;
	gint head_size;

	fd = open (filename, O_RDWR);
	if (fd == -1) {
		g_set_error (err,
			rrd_error_quark (), errno, "rrd open error: %s", strerror (errno));
		return FALSE;
	}

	if (fstat (fd, &st) == -1) {
		g_set_error (err,
			rrd_error_quark (), errno, "rrd stat error: %s", strerror (errno));
		close (fd);
		return FALSE;
	}
	if (st.st_size < (goffset)sizeof (struct rrd_file_head)) {
		/* We have trimmed file */
		g_set_error (err, rrd_error_quark (), EINVAL, "rrd size is bad: %ud",
			(guint)st.st_size);
		close (fd);
		return FALSE;
	}

	/* Try to read header */
	if (read (fd, &head, sizeof (head)) != sizeof (head)) {
		g_set_error (err,
			rrd_error_quark (), errno, "rrd read head error: %s",
			strerror (errno));
		close (fd);
		return FALSE;
	}
	/* Check magic */
	if (memcmp (head.version, RRD_VERSION, sizeof (head.version)) != 0) {
		g_set_error (err,
				rrd_error_quark (), EINVAL, "rrd head error: bad cookie");
		close (fd);
		return FALSE;
	}
	if (head.float_cookie != RRD_FLOAT_COOKIE) {
		g_set_error (err,
				rrd_error_quark (), EINVAL, "rrd head error: another architecture "
						"(file cookie %g != our cookie %g)",
				head.float_cookie, RRD_FLOAT_COOKIE);
		close (fd);
		return FALSE;
	}
	/* Check for other params */
	if (head.ds_cnt <= 0 || head.rra_cnt <= 0) {
		g_set_error (err,
			rrd_error_quark (), EINVAL, "rrd head cookies error: bad rra or ds count");
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
		g_set_error (err,
			rrd_error_quark (), errno, "rrd file seems to have stripped header: %d",
			head_size);
		close (fd);
		return FALSE;
	}

	if (need_data) {
		/* Now check rra */
		if (lseek (fd, sizeof (struct rrd_ds_def) * head.ds_cnt,
			SEEK_CUR) == -1) {
			g_set_error (err,
				rrd_error_quark (), errno, "rrd head lseek error: %s",
				strerror (errno));
			close (fd);
			return FALSE;
		}
		for (i = 0; i < (gint)head.rra_cnt; i++) {
			if (read (fd, &rra, sizeof (rra)) != sizeof (rra)) {
				g_set_error (err,
					rrd_error_quark (), errno, "rrd read rra error: %s",
					strerror (errno));
				close (fd);
				return FALSE;
			}
			head_size += rra.row_cnt * head.ds_cnt * sizeof (gdouble);
		}

		if (st.st_size != head_size) {
			g_set_error (err,
				rrd_error_quark (), EINVAL, "rrd file seems to have incorrect size: %d, must be %d",
				(gint)st.st_size, head_size);
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
	guint8 *ptr;

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
	ptr += sizeof (struct rrd_cdp_prep) * file->stat_head->rra_cnt *
		file->stat_head->ds_cnt;
	file->rra_ptr = (struct rrd_rra_ptr *)ptr;
	if (completed) {
		ptr += sizeof (struct rrd_rra_ptr) * file->stat_head->rra_cnt;
		file->rrd_value = (gdouble *)ptr;
	}
	else {
		file->rrd_value = NULL;
	}
}

static void
rspamd_rrd_calculate_checksum (struct rspamd_rrd_file *file)
{
	guchar sigbuf[rspamd_cryptobox_HASHBYTES];
	struct rrd_ds_def *ds;
	guint i;
	rspamd_cryptobox_hash_state_t st;

	if (file->finalized) {
		rspamd_cryptobox_hash_init (&st, NULL, 0);
		rspamd_cryptobox_hash_update (&st, file->filename, strlen (file->filename));

		for (i = 0; i < file->stat_head->ds_cnt; i ++) {
			ds = &file->ds_def[i];
			rspamd_cryptobox_hash_update (&st, ds->ds_nam, sizeof (ds->ds_nam));
		}

		rspamd_cryptobox_hash_final (&st, sigbuf);

		file->id = rspamd_encode_base32 (sigbuf, sizeof (sigbuf), RSPAMD_BASE32_DEFAULT);
	}
}

static int
rspamd_rrd_open_exclusive (const gchar *filename)
{
	struct timespec sleep_ts = {
			.tv_sec = 0,
			.tv_nsec = 1000000
	};
	gint fd;

	fd = open (filename, O_RDWR);

	if (fd == -1) {
		return -1;
	}

	for (;;) {
		if (rspamd_file_lock (fd, TRUE) == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				nanosleep (&sleep_ts, NULL);
				continue;
			}
			else {
				close (fd);
				return -1;
			}
		}
		else {
			break;
		}
	}

	return fd;
};

/**
 * Open completed or incompleted rrd file
 * @param filename
 * @param completed
 * @param err
 * @return
 */
static struct rspamd_rrd_file *
rspamd_rrd_open_common (const gchar *filename, gboolean completed, GError **err)
{
	struct rspamd_rrd_file *file;
	gint fd;
	struct stat st;

	if (!rspamd_rrd_check_file (filename, completed, err)) {
		return NULL;
	}

	file = g_malloc0 (sizeof (struct rspamd_rrd_file));

	/* Open file */
	fd = rspamd_rrd_open_exclusive (filename);
	if (fd == -1) {
		g_set_error (err,
			rrd_error_quark (), errno, "rrd open error: %s", strerror (errno));
		g_free (file);
		return FALSE;
	}

	if (fstat (fd, &st) == -1) {
		g_set_error (err,
			rrd_error_quark (), errno, "rrd stat error: %s", strerror (errno));
		rspamd_file_unlock (fd, FALSE);
		g_free (file);
		close (fd);
		return FALSE;
	}
	/* Mmap file */
	file->size = st.st_size;
	if ((file->map =
			mmap (NULL, st.st_size, PROT_READ | PROT_WRITE,
					MAP_SHARED, fd, 0)) == MAP_FAILED) {

		rspamd_file_unlock (fd, FALSE);
		close (fd);
		g_set_error (err,
			rrd_error_quark (), ENOMEM, "mmap failed: %s", strerror (errno));
		g_free (file);
		return NULL;
	}

	file->fd = fd;

	/* Adjust pointers */
	rspamd_rrd_adjust_pointers (file, completed);

	/* Mark it as finalized */
	file->finalized = completed;

	file->filename = g_strdup (filename);
	rspamd_rrd_calculate_checksum (file);

	return file;
}

/**
 * Open (and mmap) existing RRD file
 * @param filename path
 * @param err error pointer
 * @return rrd file structure
 */
struct rspamd_rrd_file *
rspamd_rrd_open (const gchar *filename, GError **err)
{
	struct rspamd_rrd_file *file;

	if ((file = rspamd_rrd_open_common (filename, TRUE, err))) {
		msg_info_rrd ("rrd file opened: %s", filename);
	}

	return file;
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
struct rspamd_rrd_file *
rspamd_rrd_create (const gchar *filename,
		gulong ds_count,
		gulong rra_count,
		gulong pdp_step,
		gdouble initial_ticks,
		GError **err)
{
	struct rspamd_rrd_file *new;
	struct rrd_file_head head;
	struct rrd_ds_def ds;
	struct rrd_rra_def rra;
	struct rrd_live_head lh;
	struct rrd_pdp_prep pdp;
	struct rrd_cdp_prep cdp;
	struct rrd_rra_ptr rra_ptr;
	gint fd;
	guint i, j;

	/* Open file */
	fd = open (filename, O_RDWR | O_CREAT | O_EXCL, 0644);
	if (fd == -1) {
		g_set_error (err,
			rrd_error_quark (), errno, "rrd create error: %s",
			strerror (errno));
		return NULL;
	}

	rspamd_file_lock (fd, FALSE);

	/* Fill header */
	memset (&head, 0, sizeof (head));
	head.rra_cnt = rra_count;
	head.ds_cnt = ds_count;
	head.pdp_step = pdp_step;
	memcpy (head.cookie,  RRD_COOKIE,  sizeof (head.cookie));
	memcpy (head.version, RRD_VERSION, sizeof (head.version));
	head.float_cookie = RRD_FLOAT_COOKIE;

	if (write (fd, &head, sizeof (head)) != sizeof (head)) {
		rspamd_file_unlock (fd, FALSE);
		close (fd);
		g_set_error (err,
			rrd_error_quark (), errno, "rrd write error: %s", strerror (errno));
		return NULL;
	}

	/* Fill DS section */
	memset (&ds, 0, sizeof (ds));
	memset (&ds.ds_nam, 0, sizeof (ds.ds_nam));
	memcpy (&ds.dst, "COUNTER", sizeof ("COUNTER"));
	memset (&ds.par, 0, sizeof (ds.par));
	for (i = 0; i < ds_count; i++) {
		if (write (fd, &ds, sizeof (ds)) != sizeof (ds)) {
			rspamd_file_unlock (fd, FALSE);
			close (fd);
			g_set_error (err,
				rrd_error_quark (), errno, "rrd write error: %s",
				strerror (errno));
			return NULL;
		}
	}

	/* Fill RRA section */
	memset (&rra, 0, sizeof (rra));
	memcpy (&rra.cf_nam, "AVERAGE", sizeof ("AVERAGE"));
	rra.pdp_cnt = 1;
	memset (&rra.par, 0, sizeof (rra.par));
	for (i = 0; i < rra_count; i++) {
		if (write (fd, &rra, sizeof (rra)) != sizeof (rra)) {
			rspamd_file_unlock (fd, FALSE);
			close (fd);
			g_set_error (err,
				rrd_error_quark (), errno, "rrd write error: %s",
				strerror (errno));
			return NULL;
		}
	}

	/* Fill live header */
	memset (&lh, 0, sizeof (lh));
	lh.last_up = (glong)initial_ticks;
	lh.last_up_usec = (glong)((initial_ticks - lh.last_up) * 1e6f);

	if (write (fd, &lh, sizeof (lh)) != sizeof (lh)) {
		rspamd_file_unlock (fd, FALSE);
		close (fd);
		g_set_error (err,
			rrd_error_quark (), errno, "rrd write error: %s", strerror (errno));
		return NULL;
	}

	/* Fill pdp prep */
	memset (&pdp, 0, sizeof (pdp));
	memcpy (&pdp.last_ds, "U", sizeof ("U"));
	memset (&pdp.scratch, 0, sizeof (pdp.scratch));
	pdp.scratch[PDP_val].dv = NAN;
	pdp.scratch[PDP_unkn_sec_cnt].lv = 0;

	for (i = 0; i < ds_count; i++) {
		if (write (fd, &pdp, sizeof (pdp)) != sizeof (pdp)) {
			rspamd_file_unlock (fd, FALSE);
			close (fd);
			g_set_error (err,
				rrd_error_quark (), errno, "rrd write error: %s",
				strerror (errno));
			return NULL;
		}
	}

	/* Fill cdp prep */
	memset (&cdp, 0, sizeof (cdp));
	memset (&cdp.scratch, 0, sizeof (cdp.scratch));
	cdp.scratch[CDP_val].dv = NAN;
	cdp.scratch[CDP_unkn_pdp_cnt].lv = 0;

	for (i = 0; i < rra_count; i++) {
		for (j = 0; j < ds_count; j++) {
			if (write (fd, &cdp, sizeof (cdp)) != sizeof (cdp)) {
				rspamd_file_unlock (fd, FALSE);
				close (fd);
				g_set_error (err,
					rrd_error_quark (), errno, "rrd write error: %s",
					strerror (errno));
				return NULL;
			}
		}
	}

	/* Set row pointers */
	memset (&rra_ptr, 0, sizeof (rra_ptr));
	for (i = 0; i < rra_count; i++) {
		if (write (fd, &rra_ptr, sizeof (rra_ptr)) != sizeof (rra_ptr)) {
			rspamd_file_unlock (fd, FALSE);
			close (fd);
			g_set_error (err,
				rrd_error_quark (), errno, "rrd write error: %s",
				strerror (errno));
			return NULL;
		}
	}

	rspamd_file_unlock (fd, FALSE);
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

	if (file == NULL || file->stat_head->ds_cnt * sizeof (struct rrd_ds_def) !=
		ds->len) {
		g_set_error (err,
			rrd_error_quark (), EINVAL, "rrd add ds failed: wrong arguments");
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
	if (file == NULL || file->stat_head->rra_cnt *
		sizeof (struct rrd_rra_def) != rra->len) {
		g_set_error (err,
			rrd_error_quark (), EINVAL, "rrd add rra failed: wrong arguments");
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
	gint fd;
	guint i;
	gint count = 0;
	gdouble vbuf[1024];
	struct stat st;

	if (file == NULL || file->filename == NULL || file->fd == -1) {
		g_set_error (err,
			rrd_error_quark (), EINVAL, "rrd add rra failed: wrong arguments");
		return FALSE;
	}

	fd = file->fd;

	if (lseek (fd, 0, SEEK_END) == -1) {
		g_set_error (err,
			rrd_error_quark (), errno, "rrd seek error: %s", strerror (errno));
		close (fd);
		return FALSE;
	}

	/* Adjust CDP */
	for (i = 0; i < file->stat_head->rra_cnt; i++) {
		file->cdp_prep->scratch[CDP_unkn_pdp_cnt].lv = 0;
		/* Randomize row pointer (disabled) */
		/* file->rra_ptr->cur_row = g_random_int () % file->rra_def[i].row_cnt; */
		file->rra_ptr->cur_row = file->rra_def[i].row_cnt - 1;
		/* Calculate values count */
		count += file->rra_def[i].row_cnt * file->stat_head->ds_cnt;
	}

	munmap (file->map, file->size);
	/* Write values */
	for (i = 0; i < G_N_ELEMENTS (vbuf); i++) {
		vbuf[i] = NAN;
	}

	while (count > 0) {
		/* Write values in buffered matter */
		if (write (fd, vbuf,
			MIN ((gint)G_N_ELEMENTS (vbuf), count) * sizeof (gdouble)) == -1) {
			g_set_error (err,
				rrd_error_quark (), errno, "rrd write error: %s",
				strerror (errno));
			close (fd);
			return FALSE;
		}
		count -= G_N_ELEMENTS (vbuf);
	}

	if (fstat (fd, &st) == -1) {
		g_set_error (err,
			rrd_error_quark (), errno, "rrd stat error: %s", strerror (errno));
		close (fd);
		return FALSE;
	}

	/* Mmap again */
	file->size = st.st_size;
	if ((file->map =
		mmap (NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
		0)) == MAP_FAILED) {
		close (fd);
		g_set_error (err,
			rrd_error_quark (), ENOMEM, "mmap failed: %s", strerror (errno));

		return FALSE;
	}

	/* Adjust pointers */
	rspamd_rrd_adjust_pointers (file, TRUE);

	file->finalized = TRUE;
	rspamd_rrd_calculate_checksum (file);
	msg_info_rrd ("rrd file created: %s", file->filename);

	return TRUE;
}

/**
 * Update pdp_prep data
 * @param file rrd file
 * @param vals new values
 * @param pdp_new new pdp array
 * @param interval time elapsed from the last update
 * @return
 */
static gboolean
rspamd_rrd_update_pdp_prep (struct rspamd_rrd_file *file,
	gdouble *vals,
	gdouble *pdp_new,
	gdouble interval)
{
	guint i;
	enum rrd_dst_type type;

	for (i = 0; i < file->stat_head->ds_cnt; i++) {
		type = rrd_dst_from_string (file->ds_def[i].dst);

		if (file->ds_def[i].par[RRD_DS_mrhb_cnt].lv < interval) {
			rspamd_strlcpy (file->pdp_prep[i].last_ds, "U",
					sizeof (file->pdp_prep[i].last_ds));
			pdp_new[i] = NAN;
			msg_debug_rrd ("adding unknown point interval %.3f is less than heartbeat %l",
					interval, file->ds_def[i].par[RRD_DS_mrhb_cnt].lv);
		}
		else {
			switch (type) {
			case RRD_DST_COUNTER:
			case RRD_DST_DERIVE:
				if (file->pdp_prep[i].last_ds[0] == 'U') {
					pdp_new[i] = NAN;
					msg_debug_rrd ("last point is NaN for point %ud", i);
				}
				else {
					pdp_new[i] = vals[i] - strtod (file->pdp_prep[i].last_ds,
							NULL);
					msg_debug_rrd ("new PDP %ud, %.3f", i, pdp_new[i]);
				}
				break;
			case RRD_DST_GAUGE:
				pdp_new[i] = vals[i] * interval;
				msg_debug_rrd ("new PDP %ud, %.3f", i, pdp_new[i]);
				break;
			case RRD_DST_ABSOLUTE:
				pdp_new[i] = vals[i];
				msg_debug_rrd ("new PDP %ud, %.3f", i, pdp_new[i]);
				break;
			default:
				return FALSE;
			}
		}

		/* Copy value to the last_ds */
		if (!isnan (vals[i])) {
			rspamd_snprintf (file->pdp_prep[i].last_ds,
				sizeof (file->pdp_prep[i].last_ds), "%.4f", vals[i]);
		}
		else {
			file->pdp_prep[i].last_ds[0] = 'U';
			file->pdp_prep[i].last_ds[1] = '\0';
		}
	}


	return TRUE;
}

/**
 * Update step for this pdp
 * @param file
 * @param pdp_new new pdp array
 * @param pdp_temp temp pdp array
 * @param interval time till last update
 * @param pre_int pre interval
 * @param post_int post intervall
 * @param pdp_diff time till last pdp update
 */
static void
rspamd_rrd_update_pdp_step (struct rspamd_rrd_file *file,
	gdouble *pdp_new,
	gdouble *pdp_temp,
	gdouble interval,
	gulong pdp_diff)
{
	guint i;
	rrd_value_t *scratch;
	gulong heartbeat;


	for (i = 0; i < file->stat_head->ds_cnt; i++) {
		scratch = file->pdp_prep[i].scratch;
		heartbeat = file->ds_def[i].par[RRD_DS_mrhb_cnt].lv;

		if (!isnan (pdp_new[i])) {
			if (isnan (scratch[PDP_val].dv)) {
				scratch[PDP_val].dv = 0;
			}
		}

		/* Check interval value for heartbeat for this DS */
		if ((interval > heartbeat) ||
			(file->stat_head->pdp_step / 2.0 < scratch[PDP_unkn_sec_cnt].lv)) {
			pdp_temp[i] = NAN;
		}
		else {
			pdp_temp[i] = scratch[PDP_val].dv /
				((double) (pdp_diff - scratch[PDP_unkn_sec_cnt].lv));
		}

		if (isnan (pdp_new[i])) {
			scratch[PDP_unkn_sec_cnt].lv = interval;
			scratch[PDP_val].dv = NAN;
		} else {
			scratch[PDP_unkn_sec_cnt].lv = 0;
			scratch[PDP_val].dv = pdp_new[i] / interval;
		}

		msg_debug_rrd ("new temp PDP %ud, %.3f -> %.3f, scratch: %3f",
				i, pdp_new[i], pdp_temp[i],
				scratch[PDP_val].dv);
	}
}

/**
 * Update CDP for this rra
 * @param file rrd file
 * @param pdp_steps how much pdp steps elapsed from the last update
 * @param pdp_offset offset from pdp
 * @param rra_steps how much steps must be updated for this rra
 * @param rra_index index of desired rra
 * @param pdp_temp temporary pdp points
 */
static void
rspamd_rrd_update_cdp (struct rspamd_rrd_file *file,
	gdouble pdp_steps,
	gdouble pdp_offset,
	gulong *rra_steps,
	gulong rra_index,
	gdouble *pdp_temp)
{
	guint i;
	struct rrd_rra_def *rra;
	rrd_value_t *scratch;
	enum rrd_cf_type cf;
	gdouble last_cdp = INFINITY, cur_cdp = INFINITY;
	gulong pdp_in_cdp;

	rra = &file->rra_def[rra_index];
	cf = rrd_cf_from_string (rra->cf_nam);

	/* Iterate over all DS for this RRA */
	for (i = 0; i < file->stat_head->ds_cnt; i++) {
		/* Get CDP for this RRA and DS */
		scratch =
			file->cdp_prep[rra_index * file->stat_head->ds_cnt + i].scratch;
		if (rra->pdp_cnt > 1) {
			/* Do we have any CDP to update for this rra ? */
			if (rra_steps[rra_index] > 0) {

				if (isnan (pdp_temp[i])) {
					/* New pdp is nan */
					/* Increment unknown points count */
					scratch[CDP_unkn_pdp_cnt].lv += pdp_offset;
					/* Reset secondary value */
					scratch[CDP_secondary_val].dv = NAN;
				}
				else {
					scratch[CDP_secondary_val].dv = pdp_temp[i];
				}

				/* Check XFF for this rra */
				if (scratch[CDP_unkn_pdp_cnt].lv > rra->pdp_cnt *
					rra->par[RRA_cdp_xff_val].lv) {
					/* XFF is reached */
					scratch[CDP_primary_val].dv = NAN;
				}
				else {
					/* Need to initialize CDP using specified consolidation */
					switch (cf) {
					case RRD_CF_AVERAGE:
						last_cdp =
							isnan (scratch[CDP_val].dv) ? 0.0 : scratch[CDP_val]
							.dv;
						cur_cdp = isnan (pdp_temp[i]) ? 0.0 : pdp_temp[i];
						scratch[CDP_primary_val].dv =
							(last_cdp + cur_cdp *
							pdp_offset) /
							(rra->pdp_cnt - scratch[CDP_unkn_pdp_cnt].lv);
						break;
					case RRD_CF_MAXIMUM:
						last_cdp =
							isnan (scratch[CDP_val].dv) ? -INFINITY : scratch[
							CDP_val].dv;
						cur_cdp = isnan (pdp_temp[i]) ? -INFINITY : pdp_temp[i];
						scratch[CDP_primary_val].dv = MAX (last_cdp, cur_cdp);
						break;
					case RRD_CF_MINIMUM:
						last_cdp =
							isnan (scratch[CDP_val].dv) ? INFINITY : scratch[
							CDP_val].dv;
						cur_cdp = isnan (pdp_temp[i]) ? INFINITY : pdp_temp[i];
						scratch[CDP_primary_val].dv = MIN (last_cdp, cur_cdp);
						break;
					case RRD_CF_LAST:
					default:
						scratch[CDP_primary_val].dv = pdp_temp[i];
						last_cdp = INFINITY;
						break;
					}
				}

				/* Init carry of this CDP */
				pdp_in_cdp = (pdp_steps - pdp_offset) / rra->pdp_cnt;
				if (pdp_in_cdp == 0 || isnan (pdp_temp[i])) {
					/* Set overflow */
					switch (cf) {
					case RRD_CF_AVERAGE:
						scratch[CDP_val].dv = 0;
						break;
					case RRD_CF_MAXIMUM:
						scratch[CDP_val].dv = -INFINITY;
						break;
					case RRD_CF_MINIMUM:
						scratch[CDP_val].dv = INFINITY;
						break;
					default:
						scratch[CDP_val].dv = NAN;
						break;
					}
				}
				else {
					/* Special carry for average */
					if (cf == RRD_CF_AVERAGE) {
						scratch[CDP_val].dv = pdp_temp[i] * pdp_in_cdp;
					}
					else {
						scratch[CDP_val].dv = pdp_temp[i];
					}
				}

				scratch[CDP_unkn_pdp_cnt].lv = 0;

				msg_debug_rrd ("update cdp for DS %d with value %.3f, "
						"stored value: %.3f, carry: %.3f",
						i, last_cdp,
						scratch[CDP_primary_val].dv, scratch[CDP_val].dv);
			}
			/* In this case we just need to update cdp_prep for this RRA */
			else {
				if (isnan (pdp_temp[i])) {
					/* Just increase undefined zone */
					scratch[CDP_unkn_pdp_cnt].lv += pdp_steps;
				}
				else {
					/* Calculate cdp value */
					last_cdp = scratch[CDP_val].dv;
					switch (cf) {
					case RRD_CF_AVERAGE:
						if (isnan (last_cdp)) {
							scratch[CDP_val].dv = pdp_temp[i] * pdp_steps;
						}
						else {
							scratch[CDP_val].dv = last_cdp + pdp_temp[i] *
								pdp_steps;
						}
						break;
					case RRD_CF_MAXIMUM:
						scratch[CDP_val].dv = MAX (last_cdp, pdp_temp[i]);
						break;
					case RRD_CF_MINIMUM:
						scratch[CDP_val].dv = MIN (last_cdp, pdp_temp[i]);
						break;
					case RRD_CF_LAST:
						scratch[CDP_val].dv = pdp_temp[i];
						break;
					default:
						scratch[CDP_val].dv = NAN;
						break;
					}
				}

				msg_debug_rrd ("aggregate cdp %d with pdp %.3f, "
						"stored value: %.3f",
						i, pdp_temp[i], scratch[CDP_val].dv);
			}
		}
		else {
			/* We have nothing to consolidate, but we may miss some pdp */
			if (pdp_steps > 2) {
				/* Just write PDP value */
				scratch[CDP_primary_val].dv = pdp_temp[i];
				scratch[CDP_secondary_val].dv = pdp_temp[i];
			}
		}
	}
}

/**
 * Update RRA in a file
 * @param file rrd file
 * @param rra_steps steps for each rra
 * @param now current time
 */
void
rspamd_rrd_write_rra (struct rspamd_rrd_file *file, gulong *rra_steps)
{
	guint i, j, ds_cnt;
	struct rrd_rra_def *rra;
	struct rrd_cdp_prep *cdp;
	gdouble *rra_row = file->rrd_value, *cur_row;


	ds_cnt = file->stat_head->ds_cnt;
	/* Iterate over all RRA */
	for (i = 0; i < file->stat_head->rra_cnt; i++) {
		rra = &file->rra_def[i];

		if (rra_steps[i] > 0) {

			/* Move row ptr */
			if (++file->rra_ptr[i].cur_row >= rra->row_cnt) {
				file->rra_ptr[i].cur_row = 0;
			}
			/* Calculate seek */
			cdp = &file->cdp_prep[ds_cnt * i];
			cur_row = rra_row + ds_cnt * file->rra_ptr[i].cur_row;
			/* Iterate over DS */
			for (j = 0; j < ds_cnt; j++) {
				cur_row[j] = cdp[j].scratch[CDP_primary_val].dv;
				msg_debug_rrd ("write cdp %d: %.3f", j, cur_row[j]);
			}
		}

		rra_row += rra->row_cnt * ds_cnt;
	}
}

/**
 * Add record to rrd file
 * @param file rrd file object
 * @param points points (must be row suitable for this RRA, depending on ds count)
 * @param err error pointer
 * @return TRUE if a row has been added
 */
gboolean
rspamd_rrd_add_record (struct rspamd_rrd_file *file,
		GArray *points,
		gdouble ticks,
		GError **err)
{
	gdouble interval, *pdp_new, *pdp_temp;
	guint i;
	glong seconds, microseconds;
	gulong pdp_steps, cur_pdp_count, prev_pdp_step, cur_pdp_step,
		prev_pdp_age, cur_pdp_age, *rra_steps, pdp_offset;

	if (file == NULL || file->stat_head->ds_cnt * sizeof (gdouble) !=
		points->len) {
		g_set_error (err,
			rrd_error_quark (), EINVAL,
			"rrd add points failed: wrong arguments");
		return FALSE;
	}

	/* Get interval */
	seconds = (glong)ticks;
	microseconds = (glong)((ticks - seconds) * 1000000.);
	interval = ticks - ((gdouble)file->live_head->last_up +
			file->live_head->last_up_usec / 1000000.);

	msg_debug_rrd ("update rrd record after %.3f seconds", interval);

	/* Update PDP preparation values */
	pdp_new = g_malloc0 (sizeof (gdouble) * file->stat_head->ds_cnt);
	pdp_temp = g_malloc0 (sizeof (gdouble) * file->stat_head->ds_cnt);
	/* How much steps need to be updated in each RRA */
	rra_steps = g_malloc0 (sizeof (gulong) * file->stat_head->rra_cnt);

	if (!rspamd_rrd_update_pdp_prep (file, (gdouble *)points->data, pdp_new,
		interval)) {
		g_set_error (err,
			rrd_error_quark (), EINVAL,
			"rrd update pdp failed: wrong arguments");
		g_free (pdp_new);
		g_free (pdp_temp);
		g_free (rra_steps);
		return FALSE;
	}

	/* Calculate elapsed steps */
	/* Age in seconds for previous pdp store */
	prev_pdp_age = file->live_head->last_up % file->stat_head->pdp_step;
	/* Time in seconds for last pdp update */
	prev_pdp_step = file->live_head->last_up - prev_pdp_age;
	/* Age in seconds from current time to required pdp time */
	cur_pdp_age = seconds % file->stat_head->pdp_step;
	/* Time of desired pdp step */
	cur_pdp_step = seconds - cur_pdp_age;
	cur_pdp_count = cur_pdp_step / file->stat_head->pdp_step;
	pdp_steps = (cur_pdp_step - prev_pdp_step) / file->stat_head->pdp_step;


	if (pdp_steps == 0) {
		/* Simple update of pdp prep */
		for (i = 0; i < file->stat_head->ds_cnt; i++) {
			if (isnan (pdp_new[i])) {
				/* Increment unknown period */
				file->pdp_prep[i].scratch[PDP_unkn_sec_cnt].lv += floor (
					interval);
			}
			else {
				if (isnan (file->pdp_prep[i].scratch[PDP_val].dv)) {
					/* Reset pdp to the current value */
					file->pdp_prep[i].scratch[PDP_val].dv = pdp_new[i];
				}
				else {
					/* Increment pdp value */
					file->pdp_prep[i].scratch[PDP_val].dv += pdp_new[i];
				}
			}
		}
	}
	else {
		/* Complex update of PDP, CDP and RRA */

		/* Update PDP for this step */
		rspamd_rrd_update_pdp_step (file,
			pdp_new,
			pdp_temp,
			interval,
			pdp_steps * file->stat_head->pdp_step);


		/* Update CDP points for each RRA*/
		for (i = 0; i < file->stat_head->rra_cnt; i++) {
			/* Calculate pdp offset for this RRA */
			pdp_offset = file->rra_def[i].pdp_cnt - cur_pdp_count %
				file->rra_def[i].pdp_cnt;
			/* How much steps we got for this RRA */
			if (pdp_offset <= pdp_steps) {
				rra_steps[i] =
					(pdp_steps - pdp_offset) / file->rra_def[i].pdp_cnt + 1;
			}
			else {
				/* This rra have not passed enough pdp steps */
				rra_steps[i] = 0;
			}

			msg_debug_rrd ("cdp: %ud, rra steps: %ul(%ul), pdp steps: %ul",
					i, rra_steps[i], pdp_offset, pdp_steps);

			/* Update this specific CDP */
			rspamd_rrd_update_cdp (file,
				pdp_steps,
				pdp_offset,
				rra_steps,
				i,
				pdp_temp);

		}

		/* Write RRA */
		rspamd_rrd_write_rra (file, rra_steps);
	}
	file->live_head->last_up = seconds;
	file->live_head->last_up_usec = microseconds;

	/* Sync and invalidate */
	msync (file->map, file->size, MS_ASYNC | MS_INVALIDATE);

	g_free (pdp_new);
	g_free (pdp_temp);
	g_free (rra_steps);

	return TRUE;
}

/**
 * Close rrd file
 * @param file
 * @return
 */
gint
rspamd_rrd_close (struct rspamd_rrd_file * file)
{
	if (file == NULL) {
		errno = EINVAL;
		return -1;
	}

	munmap (file->map, file->size);
	close (file->fd);
	g_free (file->filename);
	g_free (file->id);

	g_free (file);

	return 0;
}

static struct rspamd_rrd_file *
rspamd_rrd_create_file (const gchar *path, gboolean finalize, GError **err)
{
	struct rspamd_rrd_file *file;
	struct rrd_ds_def ds[RSPAMD_RRD_DS_COUNT];
	struct rrd_rra_def rra[RSPAMD_RRD_RRA_COUNT];
	gint i;
	GArray ar;

	/* Try to create new rrd file */

	file = rspamd_rrd_create (path, RSPAMD_RRD_DS_COUNT, RSPAMD_RRD_RRA_COUNT,
			1, rspamd_get_calendar_ticks (), err);

	if (file == NULL) {
		return NULL;
	}

	/* Create DS and RRA */

	for (i = METRIC_ACTION_REJECT; i < METRIC_ACTION_MAX; i ++) {
		rrd_make_default_ds (rspamd_action_to_str (i),
				rrd_dst_to_string (RRD_DST_COUNTER), 1, &ds[i]);
	}

	ar.data = (gchar *)ds;
	ar.len = sizeof (ds);

	if (!rspamd_rrd_add_ds (file, &ar, err)) {
		rspamd_rrd_close (file);
		return NULL;
	}

	/* Once per minute for 1 day */
	rrd_make_default_rra (rrd_cf_to_string (RRD_CF_AVERAGE),
			60, 24 * 60, &rra[0]);
	/* Once per 5 minutes for 1 week */
	rrd_make_default_rra (rrd_cf_to_string (RRD_CF_AVERAGE),
			5 * 60, 7 * 24 * 60 / 5, &rra[1]);
	/* Once per 10 mins for 1 month */
	rrd_make_default_rra (rrd_cf_to_string (RRD_CF_AVERAGE),
			60 * 10, 30 * 24 * 6, &rra[2]);
	/* Once per hour for 1 year */
	rrd_make_default_rra (rrd_cf_to_string (RRD_CF_AVERAGE),
			60 * 60, 365 * 24, &rra[3]);
	ar.data = (gchar *)rra;
	ar.len = sizeof (rra);

	if (!rspamd_rrd_add_rra (file, &ar, err)) {
		rspamd_rrd_close (file);
		return NULL;
	}

	if (finalize && !rspamd_rrd_finalize (file, err)) {
		rspamd_rrd_close (file);
		return NULL;
	}

	return file;
}

static void
rspamd_rrd_convert_ds (struct rspamd_rrd_file *old,
		 struct rspamd_rrd_file *cur, gint idx_old, gint idx_new)
{
	struct rrd_pdp_prep *pdp_prep_old, *pdp_prep_new;
	struct rrd_cdp_prep *cdp_prep_old, *cdp_prep_new;
	gdouble *val_old, *val_new;
	gulong rra_cnt, i, j, points_cnt, old_ds, new_ds;

	rra_cnt = old->stat_head->rra_cnt;
	pdp_prep_old = &old->pdp_prep[idx_old];
	pdp_prep_new = &cur->pdp_prep[idx_new];
	memcpy (pdp_prep_new, pdp_prep_old, sizeof (*pdp_prep_new));
	val_old = old->rrd_value;
	val_new = cur->rrd_value;
	old_ds = old->stat_head->ds_cnt;
	new_ds = cur->stat_head->ds_cnt;

	for (i = 0; i < rra_cnt; i++) {
		cdp_prep_old = &old->cdp_prep[i * old_ds] + idx_old;
		cdp_prep_new = &cur->cdp_prep[i * new_ds] + idx_new;
		memcpy (cdp_prep_new, cdp_prep_old, sizeof (*cdp_prep_new));
		points_cnt = old->rra_def[i].row_cnt;

		for (j = 0; j < points_cnt; j ++) {
			val_new[j * new_ds + idx_new] = val_old[j * old_ds + idx_old];
		}

		val_new += points_cnt * new_ds;
		val_old += points_cnt * old_ds;
	}
}

static struct rspamd_rrd_file *
rspamd_rrd_convert (const gchar *path, struct rspamd_rrd_file *old,
		GError **err)
{
	struct rspamd_rrd_file *rrd;
	gchar tpath[PATH_MAX];

	g_assert (old != NULL);

	rspamd_snprintf (tpath, sizeof (tpath), "%s.new", path);
	rrd = rspamd_rrd_create_file (tpath, TRUE, err);

	if (rrd) {
		/* Copy old data */
		memcpy (rrd->live_head, old->live_head, sizeof (*rrd->live_head));
		memcpy (rrd->rra_ptr, old->rra_ptr,
				sizeof (*old->rra_ptr) * rrd->stat_head->rra_cnt);

		/*
		 * Old DSes:
		 * 0 - spam -> reject
		 * 1 - probable spam -> add header
		 * 2 - greylist -> greylist
		 * 3 - ham -> ham
		 */
		rspamd_rrd_convert_ds (old, rrd, 0, METRIC_ACTION_REJECT);
		rspamd_rrd_convert_ds (old, rrd, 1, METRIC_ACTION_ADD_HEADER);
		rspamd_rrd_convert_ds (old, rrd, 2, METRIC_ACTION_GREYLIST);
		rspamd_rrd_convert_ds (old, rrd, 3, METRIC_ACTION_NOACTION);

		if (unlink (path) == -1) {
			g_set_error (err, rrd_error_quark (), errno, "cannot unlink old rrd file %s: %s",
					path, strerror (errno));
			unlink (tpath);
			rspamd_rrd_close (rrd);

			return NULL;
		}

		if (rename (tpath, path) == -1) {
			g_set_error (err, rrd_error_quark (), errno, "cannot rename old rrd file %s: %s",
					path, strerror (errno));
			unlink (tpath);
			rspamd_rrd_close (rrd);

			return NULL;
		}
	}

	return rrd;
}

struct rspamd_rrd_file *
rspamd_rrd_file_default (const gchar *path,
		GError **err)
{
	struct rspamd_rrd_file *file, *nf;

	g_assert (path != NULL);

	if (access (path, R_OK) != -1) {
		/* We can open rrd file */
		file = rspamd_rrd_open (path, err);

		if (file == NULL) {
			return NULL;
		}


		if (file->stat_head->rra_cnt != RSPAMD_RRD_RRA_COUNT) {
			msg_err_rrd ("rrd file is not suitable for rspamd: it has "
					"%ul ds and %ul rra", file->stat_head->ds_cnt,
					file->stat_head->rra_cnt);
			g_set_error (err, rrd_error_quark (), EINVAL, "bad rrd file");
			rspamd_rrd_close (file);

			return NULL;
		}
		else if (file->stat_head->ds_cnt == RSPAMD_RRD_OLD_DS_COUNT) {
			/* Old rrd, need to convert */
			msg_info_rrd ("rrd file %s is not suitable for rspamd, convert it",
					path);

			nf = rspamd_rrd_convert (path, file, err);
			rspamd_rrd_close (file);

			return nf;
		}
		else if (file->stat_head->ds_cnt == RSPAMD_RRD_DS_COUNT) {
			return file;
		}
		else {
			msg_err_rrd ("rrd file is not suitable for rspamd: it has "
					"%ul ds and %ul rra", file->stat_head->ds_cnt,
					file->stat_head->rra_cnt);
			g_set_error (err, rrd_error_quark (), EINVAL, "bad rrd file");
			rspamd_rrd_close (file);

			return NULL;
		}
	}

	file = rspamd_rrd_create_file (path, TRUE, err);

	return file;
}

struct rspamd_rrd_query_result *
rspamd_rrd_query (struct rspamd_rrd_file *file,
		gulong rra_num)
{
	struct rspamd_rrd_query_result *res;
	struct rrd_rra_def *rra;
	const gdouble *rra_offset = NULL;
	guint i;

	g_assert (file != NULL);


	if (rra_num > file->stat_head->rra_cnt) {
		msg_err_rrd ("requested unexisting rra: %l", rra_num);

		return NULL;
	}

	res = g_malloc0 (sizeof (*res));
	res->ds_count = file->stat_head->ds_cnt;
	res->last_update = (gdouble)file->live_head->last_up +
			((gdouble)file->live_head->last_up_usec / 1e6f);
	res->pdp_per_cdp = file->rra_def[rra_num].pdp_cnt;
	res->rra_rows = file->rra_def[rra_num].row_cnt;
	rra_offset = file->rrd_value;

	for (i = 0; i < file->stat_head->rra_cnt; i++) {
		rra = &file->rra_def[i];

		if (i == rra_num) {
			res->cur_row = file->rra_ptr[i].cur_row % rra->row_cnt;
			break;
		}

		rra_offset += rra->row_cnt * res->ds_count;
	}

	res->data = rra_offset;

	return res;
}
