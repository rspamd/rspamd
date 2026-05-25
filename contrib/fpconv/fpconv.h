#ifndef FPCONV_H
#define FPCONV_H

#define FPCONV_BUFLEN 32

/* Return codes from fpconv_grisu2 */
#define FPCONV_GRISU_ZERO (-1)
#define FPCONV_GRISU_INF  (-2)
#define FPCONV_GRISU_NAN  (-3)

/*
 * Raw grisu2 decomposition for external formatters.
 * digits[] receives the significant-digit characters (not null-terminated).
 * *K receives the decimal exponent.
 * *is_negative is set to 1 for negative values (including -0.0), 0 otherwise.
 * Returns the number of significant digits (>0), or a FPCONV_GRISU_* code (<0).
 */
int fpconv_grisu2(double d, char digits[18], int *K, int *is_negative);

#endif

/* [1] http://florian.loitsch.com/publications/dtoa-pldi2010.pdf */
