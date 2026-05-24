#ifndef FPCONV_H
#define FPCONV_H

#define FPCONV_BUFLEN 32

/*
 * Sentinel precision for "emit all significant digits and trim trailing
 * zeros" mode.  Used internally by fpconv_dtoa when the caller wants
 * shortest accurate representation rather than a fixed number of
 * decimal places.
 *
 * rspamd_snprintf passes this for bare %f, %g, and %G (no explicit
 * precision).  Explicit %.Nf / %.Ng always pads to exactly N places.
 *
 * CAVEAT: any caller passing precision == FPCONV_PRECISION_ALL will
 * get trim-mode behaviour instead of fixed-width.  Since a double has
 * at most 17 significant digits, any N in [1..17] is safe; 18 and 19
 * are also fine (just unused in practice).  Do NOT pick 20 for
 * fixed-width padding.
 */
#define FPCONV_PRECISION_ALL  20
/* Fast and accurate double to string conversion based on Florian Loitsch's
 * Grisu-algorithm[1].
 *
 * Input:
 * fp -> the double to convert, dest -> destination buffer.
 * The generated string will never be longer than 24 characters.
 * Make sure to pass a pointer to at least 24 bytes of memory.
 * The emitted string will not be null terminated.
 *
 * Output:
 * The number of written characters.
 *
 * Exemplary usage:
 *
 * void print(double d)
 * {
 *      char buf[24 + 1] // plus null terminator
 *      int str_len = fpconv_dtoa(d, buf);
 *
 *      buf[str_len] = '\0';
 *      printf("%s", buf);
 * }
 *
 */

int fpconv_dtoa(double fp, char dest[FPCONV_BUFLEN], unsigned precision,
		bool scientific);

#endif

/* [1] http://florian.loitsch.com/publications/dtoa-pldi2010.pdf */
