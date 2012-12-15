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


#ifndef RRD_H_
#define RRD_H_

#include "config.h"

/**
 * This file contains basic structure and functions to operate with round-robin databases
 */

#define RRD_COOKIE    "RRD"
#define RRD_VERSION   "0004"
#define RRD_FLOAT_COOKIE  ((double)8.642135E130)

typedef union {
	unsigned long lv;
	double dv;
} rrd_value_t;

struct rrd_file_head {
	/* Data Base Identification Section ** */
	gchar      cookie[4];    /* RRD */
	gchar      version[5];   /* version of the format */
	gdouble    float_cookie; /* is it the correct double representation ?  */

	/* Data Base Structure Definition **** */
	gulong ds_cnt;   /* how many different ds provid input to the rrd */
	gulong rra_cnt;  /* how many rras will be maintained in the rrd */
	gulong pdp_step; /* pdp interval in seconds */

	rrd_value_t   par[10];  /* global parameters ... unused
                           at the moment */
};

enum rrd_dst_type {
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
	RRD_CF_AVERAGE = 0,    /* data consolidation functions */
	RRD_CF_MINIMUM,
	RRD_CF_MAXIMUM,
	RRD_CF_LAST,
	RRD_CF_HWPREDICT,
	/* An array of predictions using the seasonal
	 * Holt-Winters algorithm. Requires an RRA of type
	 * CF_SEASONAL for this data source. */
	RRD_CF_SEASONAL,
	/* An array of seasonal effects. Requires an RRA of
	 * type CF_HWPREDICT for this data source. */
	RRD_CF_DEVPREDICT,
	/* An array of deviation predictions based upon
	 * smoothed seasonal deviations. Requires an RRA of
	 * type CF_DEVSEASONAL for this data source. */
	RRD_CF_DEVSEASONAL,
	/* An array of smoothed seasonal deviations. Requires
	 * an RRA of type CF_HWPREDICT for this data source.
	 * */
	RRD_CF_FAILURES,
	/* HWPREDICT that follows a moving baseline */
	RRD_CF_MHWPREDICT
	/* new entries must come last !!! */
};


#define MAX_RRA_PAR_EN 10

enum rrd_rra_param {
	RRA_cdp_xff_val = 0,  /* what part of the consolidated
 * datapoint must be known, to produce a
 * valid entry in the rra */
	/* CF_HWPREDICT: */
	RRA_hw_alpha = 1,
	/* exponential smoothing parameter for the intercept in
	 * the Holt-Winters prediction algorithm. */
	RRA_hw_beta = 2,
	/* exponential smoothing parameter for the slope in
	 * the Holt-Winters prediction algorithm. */

	RRA_dependent_rra_idx = 3,
	/* For CF_HWPREDICT: index of the RRA with the seasonal
	 * effects of the Holt-Winters algorithm (of type
	 * CF_SEASONAL).
	 * For CF_DEVPREDICT: index of the RRA with the seasonal
	 * deviation predictions (of type CF_DEVSEASONAL).
	 * For CF_SEASONAL: index of the RRA with the Holt-Winters
	 * intercept and slope coefficient (of type CF_HWPREDICT).
	 * For CF_DEVSEASONAL: index of the RRA with the
	 * Holt-Winters prediction (of type CF_HWPREDICT).
	 * For CF_FAILURES: index of the CF_DEVSEASONAL array.
	 * */

	/* CF_SEASONAL and CF_DEVSEASONAL: */
	RRA_seasonal_gamma = 1,
	/* exponential smoothing parameter for seasonal effects. */

	RRA_seasonal_smoothing_window = 2,
	/* fraction of the season to include in the running average
	 * smoother */

	/* RRA_dependent_rra_idx = 3, */

	RRA_seasonal_smooth_idx = 4,
	/* an integer between 0 and row_count - 1 which
	 * is index in the seasonal cycle for applying
	 * the period smoother. */

	/* CF_FAILURES: */
	RRA_delta_pos = 1,  /* confidence bound scaling parameters */
	RRA_delta_neg = 2,
	/* RRA_dependent_rra_idx = 3, */
	RRA_window_len = 4,
	RRA_failure_threshold = 5
	/* For CF_FAILURES, number of violations within the last
	 * window required to mark a failure. */
};


#define RRD_CF_NAM_SIZE   20

struct rrd_rra_def {
	gchar  cf_nam[RRD_CF_NAM_SIZE];  /* consolidation function (null term) */
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
	guint8* map; /* mmapped area */
	gsize size; /* its size */
	gboolean finalized;
};


/* Public API */

/**
 * Open (and mmap) existing RRD file
 * @param filename path
 * @param err error pointer
 * @return rrd file structure
 */
struct rspamd_rrd_file* rspamd_rrd_open (const gchar *filename, GError **err);

/**
 * Create basic header for rrd file
 * @param filename file path
 * @param ds_count number of data sources
 * @param rra_count number of round robin archives
 * @param pdp_step step of primary data points
 * @param err error pointer
 * @return TRUE if file has been created
 */
struct rspamd_rrd_file* rspamd_rrd_create (const gchar *filename, gulong ds_count, gulong rra_count, gulong pdp_step, GError **err);

/**
 * Add data sources to rrd file
 * @param filename path to file
 * @param ds array of struct rrd_ds_def
 * @param err error pointer
 * @return TRUE if data sources were added
 */
gboolean rspamd_rrd_add_ds (struct rspamd_rrd_file* file, GArray *ds, GError **err);

/**
 * Add round robin archives to rrd file
 * @param filename path to file
 * @param ds array of struct rrd_rra_def
 * @param err error pointer
 * @return TRUE if archives were added
 */
gboolean rspamd_rrd_add_rra (struct rspamd_rrd_file *file, GArray *rra, GError **err);

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
 * @param rra_idx index of rra being added
 * @param points points (must be row suitable for this RRA, depending on ds count)
 * @param err error pointer
 * @return TRUE if a row has been added
 */
gboolean rspamd_rrd_add_record (struct rspamd_rrd_file* file, guint rra_idx, GArray *points, GError **err);

/**
 * Close rrd file
 * @param file
 * @return
 */
gint rspamd_rrd_close (struct rspamd_rrd_file* file);

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
const gchar* rrd_dst_to_string (enum rrd_dst_type type);
/**
 * Convert rrd consolidation function type from string to numeric value
 */
enum rrd_cf_type rrd_cf_from_string (const gchar *str);
/**
 * Convert numeric presentation of cf to string
 */
const gchar* rrd_cf_to_string (enum rrd_cf_type type);

#endif /* RRD_H_ */
