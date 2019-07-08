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
#ifndef RRD_H_
#define RRD_H_

#include "config.h"

/**
 * This file contains basic structure and functions to operate with round-robin databases
 */

#define RRD_COOKIE    "RRD"
#define RRD_VERSION   "0003"
#define RRD_FLOAT_COOKIE  ((double)8.642135E130)

#ifdef  __cplusplus
extern "C" {
#endif

typedef union {
	unsigned long lv;
	double dv;
} rrd_value_t;

struct rrd_file_head {
	/* Data Base Identification Section ** */
	gchar cookie[4];         /* RRD */
	gchar version[5];        /* version of the format */
	gdouble float_cookie;    /* is it the correct double representation ?  */

	/* Data Base Structure Definition **** */
	gulong ds_cnt;   /* how many different ds provid input to the rrd */
	gulong rra_cnt;  /* how many rras will be maintained in the rrd */
	gulong pdp_step; /* pdp interval in seconds */

	rrd_value_t par[10];    /* global parameters ... unused
	                           at the moment */
};

enum rrd_dst_type {
	RRD_DST_INVALID = -1,
	RRD_DST_COUNTER = 0,  /* data source types available */
	RRD_DST_ABSOLUTE,
	RRD_DST_GAUGE,
	RRD_DST_DERIVE,
	RRD_DST_CDEF
};
enum rrd_ds_param {
	RRD_DS_mrhb_cnt = 0, /* minimum required heartbeat */
	RRD_DS_min_val,         /* the processed input of a ds must */
	RRD_DS_max_val,         /* be between max_val and min_val
	                         * both can be set to UNKNOWN if you
	                         * do not care. Data outside the limits
	                         * set to UNKNOWN */
	RRD_DS_cdef = RRD_DS_mrhb_cnt
};                      /* pointer to encoded rpn expression only applies to DST_CDEF */


/* The magic number here is one less than DS_NAM_SIZE */
#define RRD_DS_NAM_SIZE   20

#define RRD_DST_SIZE   20

struct rrd_ds_def {
	gchar ds_nam[RRD_DS_NAM_SIZE];  /* Name of the data source (null terminated) */
	gchar dst[RRD_DST_SIZE];    /* Type of data source (null terminated) */
	rrd_value_t par[10];  /* index of this array see ds_param_en */
};

/* RRA definition */

enum rrd_cf_type {
	RRD_CF_INVALID = -1,
	RRD_CF_AVERAGE = 0,    /* data consolidation functions */
	RRD_CF_MINIMUM,
	RRD_CF_MAXIMUM,
	RRD_CF_LAST,
};


#define MAX_RRA_PAR_EN 10

enum rrd_rra_param {
	RRA_cdp_xff_val = 0,  /* what part of the consolidated
	                       * datapoint must be known, to produce a
	                       * valid entry in the rra */
};


#define RRD_CF_NAM_SIZE   20

struct rrd_rra_def {
	gchar cf_nam[RRD_CF_NAM_SIZE];   /* consolidation function (null term) */
	gulong row_cnt;  /* number of entries in the store */
	gulong pdp_cnt;  /* how many primary data points are
	                  * required for a consolidated data point?*/
	rrd_value_t par[MAX_RRA_PAR_EN];  /* index see rra_param_en */

};

struct rrd_live_head {
	time_t last_up;  /* when was rrd last updated */
	glong last_up_usec; /* micro seconds part of the update timestamp. Always >= 0 */
};

#define RRD_LAST_DS_LEN 30

enum rrd_pdp_param {
	PDP_unkn_sec_cnt = 0, /* how many seconds of the current
	                       * pdp value is unknown data? */
	PDP_val
};                      /* current value of the pdp.
                           this depends on dst */

struct rrd_pdp_prep {
	gchar last_ds[RRD_LAST_DS_LEN]; /* the last reading from the data
	                                 * source.  this is stored in ASCII
	                                 * to cater for very large counters
	                                 * we might encounter in connection
	                                 * with SNMP. */
	rrd_value_t scratch[10];  /* contents according to pdp_par_en */
};

#define RRD_MAX_CDP_PAR_EN 10
#define RRD_MAX_CDP_FAILURES_IDX 8
/* max CDP scratch entries avail to record violations for a FAILURES RRA */
#define RRD_MAX_FAILURES_WINDOW_LEN 28

enum rrd_cdp_param {
	CDP_val = 0,
	/* the base_interval is always an
	 * average */
			CDP_unkn_pdp_cnt,
	/* how many unknown pdp were
	 * integrated. This and the cdp_xff
	 * will decide if this is going to
	 * be a UNKNOWN or a valid value */
			CDP_hw_intercept,
	/* Current intercept coefficient for the Holt-Winters
	 * prediction algorithm. */
			CDP_hw_last_intercept,
	/* Last iteration intercept coefficient for the Holt-Winters
	 * prediction algorihtm. */
			CDP_hw_slope,
	/* Current slope coefficient for the Holt-Winters
	 * prediction algorithm. */
			CDP_hw_last_slope,
	/* Last iteration slope coeffient. */
			CDP_null_count,
	/* Number of sequential Unknown (DNAN) values + 1 preceding
	 * the current prediction.
	 * */
			CDP_last_null_count,
	/* Last iteration count of Unknown (DNAN) values. */
			CDP_primary_val = 8,
	/* optimization for bulk updates: the value of the first CDP
	 * value to be written in the bulk update. */
			CDP_secondary_val = 9,
	/* optimization for bulk updates: the value of subsequent
	 * CDP values to be written in the bulk update. */
			CDP_hw_seasonal = CDP_hw_intercept,
	/* Current seasonal coefficient for the Holt-Winters
	 * prediction algorithm. This is stored in CDP prep to avoid
	 * redundant seek operations. */
			CDP_hw_last_seasonal = CDP_hw_last_intercept,
	/* Last iteration seasonal coefficient. */
			CDP_seasonal_deviation = CDP_hw_intercept,
	CDP_last_seasonal_deviation = CDP_hw_last_intercept,
	CDP_init_seasonal = CDP_null_count
};

struct rrd_cdp_prep {
	rrd_value_t scratch[RRD_MAX_CDP_PAR_EN];
	/* contents according to cdp_par_en *
	 * init state should be NAN */
};

struct rrd_rra_ptr {
	gulong cur_row;  /* current row in the rra */
};

/* Final rrd file structure */
struct rspamd_rrd_file {
	struct rrd_file_head *stat_head; /* the static header */
	struct rrd_ds_def *ds_def;   /* list of data source definitions */
	struct rrd_rra_def *rra_def; /* list of round robin archive def */
	struct rrd_live_head *live_head; /* rrd v >= 3 last_up with us */
	struct rrd_pdp_prep *pdp_prep;   /* pdp data prep area */
	struct rrd_cdp_prep *cdp_prep;   /* cdp prep area */
	struct rrd_rra_ptr *rra_ptr; /* list of rra pointers */
	gdouble *rrd_value; /* list of rrd values */

	gchar *filename;
	guint8 *map; /* mmapped area */
	gsize size; /* its size */
	gboolean finalized;
	gchar *id;
	gint fd;
};


/* Public API */

/**
 * Open (and mmap) existing RRD file
 * @param filename path
 * @param err error pointer
 * @return rrd file structure
 */
struct rspamd_rrd_file *rspamd_rrd_open (const gchar *filename, GError **err);

/**
 * Create basic header for rrd file
 * @param filename file path
 * @param ds_count number of data sources
 * @param rra_count number of round robin archives
 * @param pdp_step step of primary data points
 * @param err error pointer
 * @return TRUE if file has been created
 */
struct rspamd_rrd_file *rspamd_rrd_create (const gchar *filename,
										   gulong ds_count,
										   gulong rra_count,
										   gulong pdp_step,
										   gdouble initial_ticks,
										   GError **err);

/**
 * Add data sources to rrd file
 * @param filename path to file
 * @param ds array of struct rrd_ds_def
 * @param err error pointer
 * @return TRUE if data sources were added
 */
gboolean rspamd_rrd_add_ds (struct rspamd_rrd_file *file,
							GArray *ds,
							GError **err);

/**
 * Add round robin archives to rrd file
 * @param filename path to file
 * @param ds array of struct rrd_rra_def
 * @param err error pointer
 * @return TRUE if archives were added
 */
gboolean rspamd_rrd_add_rra (struct rspamd_rrd_file *file,
							 GArray *rra,
							 GError **err);

/**
 * Finalize rrd file header and initialize all RRA in the file
 * @param filename file path
 * @param err error pointer
 * @return TRUE if rrd file is ready for use
 */
gboolean rspamd_rrd_finalize (struct rspamd_rrd_file *file, GError **err);

/**
 * Add record to rrd file
 * @param file rrd file object
 * @param points points (must be row suitable for this RRA, depending on ds count)
 * @param err error pointer
 * @return TRUE if a row has been added
 */
gboolean rspamd_rrd_add_record (struct rspamd_rrd_file *file,
								GArray *points,
								gdouble ticks,
								GError **err);

/**
 * Close rrd file
 * @param file
 * @return
 */
gint rspamd_rrd_close (struct rspamd_rrd_file *file);

/*
 * Conversion functions
 */

/**
 * Convert rrd dst type from string to numeric value
 */
enum rrd_dst_type rrd_dst_from_string (const gchar *str);

/**
 * Convert numeric presentation of dst to string
 */
const gchar *rrd_dst_to_string (enum rrd_dst_type type);

/**
 * Convert rrd consolidation function type from string to numeric value
 */
enum rrd_cf_type rrd_cf_from_string (const gchar *str);

/**
 * Convert numeric presentation of cf to string
 */
const gchar *rrd_cf_to_string (enum rrd_cf_type type);

/* Default RRA and DS */

/**
 * Create default RRA
 */
void rrd_make_default_rra (const gchar *cf_name,
						   gulong pdp_cnt,
						   gulong rows,
						   struct rrd_rra_def *rra);

/**
 * Create default DS
 */
void rrd_make_default_ds (const gchar *name,
						  const gchar *type,
						  gulong pdp_step,
						  struct rrd_ds_def *ds);

/**
 * Open or create the default rspamd rrd file
 */
struct rspamd_rrd_file *rspamd_rrd_file_default (const gchar *path,
												 GError **err);

/**
 * Returned by querying rrd database
 */
struct rspamd_rrd_query_result {
	gulong rra_rows;
	gulong pdp_per_cdp;
	gulong ds_count;
	gdouble last_update;
	gulong cur_row;
	const gdouble *data;
};

/**
 * Return RRA data
 * @param file rrd file
 * @param rra_num number of rra to return data for
 * @return query result structure, that should be freed (using g_slice_free1) after usage
 */
struct rspamd_rrd_query_result *rspamd_rrd_query (struct rspamd_rrd_file *file,
												  gulong rra_num);

#ifdef  __cplusplus
}
#endif

#endif /* RRD_H_ */
