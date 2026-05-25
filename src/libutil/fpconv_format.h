#ifndef FPCONV_FORMAT_H
#define FPCONV_FORMAT_H

#include "contrib/fpconv/fpconv.h"

/*
 * Sentinel precision: emit all significant digits, then trim trailing zeros.
 * Any value in [1..17] is a valid fixed-width precision (double has at most
 * 17 significant digits).  20 sits safely above that range.
 * Do NOT use 20 as a fixed-width precision.
 */
#define FPCONV_PRECISION_ALL  20

/*
 * Format a double into dest[] with fixed-point or scientific notation.
 *
 * Input:
 * d    -> the double to convert, dest -> destination buffer.
 * Make sure to pass a pointer to at least FPCONV_BUFLEN bytes of memory.
 * The emitted string will not be null terminated.
 *
 * Output:
 * The number of written characters.
 *
 * precision:
 *   FPCONV_PRECISION_ALL (20)  - trim mode: shortest accurate representation
 *   0                           - round to integer (e.g. 1.6 -> "2")
 *   N (1..17)                   - fixed N decimal places with rounding
 *
 * scientific:
 *   false  - fixed-point (%f / %F)
 *   true   - shortest notation, may use scientific (%g / %G)
 *
 * Exemplary usage:
 *
 * void print(double d)
 * {
 *      char buf[FPCONV_BUFLEN + 1]; // plus null terminator
 *      int str_len = fpconv_format_dtoa(d, buf, FPCONV_PRECISION_ALL, false);
 *
 *      buf[str_len] = '\0';
 *      printf("%s", buf);
 * }
 */
int fpconv_format_dtoa(double d, char dest[FPCONV_BUFLEN],
		unsigned precision, bool scientific);

#endif
