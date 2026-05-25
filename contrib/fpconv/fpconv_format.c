#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <sys/param.h>

#include "fpconv_format.h"
#include "fpconv.h"

/*
 * Grisu2 produces at most 17 significant digits, so any explicit
 * precision in [1..17] is safe to use for fixed-width padding.
 * FPCONV_PRECISION_ALL (20) sits well above that range.
 */
static_assert(FPCONV_PRECISION_ALL > 17,
		"FPCONV_PRECISION_ALL must exceed max significant digits of a double");

#define absv(n) ((n) < 0 ? -(n) : (n))
#define minv(a, b) ((a) < (b) ? (a) : (b))

static inline int
round_up_digits (char *digits, int ndigits)
{
	int i = ndigits - 1;

	while (i >= 0) {
		if (digits[i] < '9') {
			digits[i]++;
			return ndigits;
		}
		digits[i] = '0';
		i--;
	}

	/*
	 * All digits carried (e.g. "99" -> "00"): shift right by one
	 * and prepend '1'.  The digits buffer from grisu2 has room
	 * for one extra character (at most 17 digits in an 18-byte
	 * array), so memmove is safe.
	 */
	memmove(digits + 1, digits, ndigits);
	digits[0] = '1';

	return ndigits + 1;
}

/*
 * Round the digits array at position `round_pos` (0-based).
 * If digits[round_pos] >= '5', carry into digits[0..round_pos-1].
 * Returns the new total number of digits (may increase by 1 on carry).
 * `total` is the current number of valid digits in the array.
 * If `carry_overflow` is non-NULL, sets it to 1 when a full carry
 * shifts the digits right (prepending '1'), 0 otherwise.
 */
static inline int
round_at_ex (char *digits, int total, int round_pos,
		int *carry_overflow)
{
	if (round_pos >= total || digits[round_pos] < '5') {
		if (carry_overflow) *carry_overflow = 0;
		return total;
	}

	/* Round up: carry into digits[0..round_pos-1] */
	if (round_pos == 0) {
		digits[0] = '1';
		if (carry_overflow) *carry_overflow = 0;
		return 1;
	}

	int new_total = round_pos;
	digits[round_pos] = '0';

	int i = round_pos - 1;
	while (i >= 0) {
		if (digits[i] < '9') {
			digits[i]++;
			if (carry_overflow) *carry_overflow = 0;
			return new_total;
		}
		digits[i] = '0';
		i--;
	}

	/* Full carry: shift right and prepend '1' */
	memmove(digits + 1, digits, new_total);
	digits[0] = '1';
	if (carry_overflow) *carry_overflow = 1;
	return new_total + 1;
}

static inline int
round_at (char *digits, int total, int round_pos)
{
	return round_at_ex(digits, total, round_pos, NULL);
}

/*
 * Trim trailing '0' characters from [start, start+len) and the preceding
 * '.' if all fractional digits are removed.  Returns new length.
 */
static inline int
trim_trailing_zeros (char *start, int len)
{
	if (len <= 0) {
		return len;
	}

	char *p = start + len - 1;

	while (p > start && *p == '0') {
		p--;
	}

	if (*p == '.') {
		p--;
	}

	return (p - start) + 1;
}

static inline int
emit_integer (char *digits, int ndigits,
		char *dest, int K, bool neg,
		unsigned precision)
{
	char *d = dest;

	memcpy (d, digits, ndigits);
	d += ndigits;
	memset (d, '0', K);
	d += K;

	if (precision == FPCONV_PRECISION_ALL) {
		return d - dest;
	}

	precision = MIN(precision, FPCONV_BUFLEN - (ndigits + K + 1));

	if (precision) {
		*d++ = '.';
		memset (d, '0', precision);
		d += precision;
	}

	return d - dest;
}

static inline int
emit_scientific_digits (char *digits, int ndigits,
		char *dest, int K, bool neg,
		unsigned precision, int exp)
{
	ndigits = minv(ndigits, 18 - neg);

	int idx = 0;
	dest[idx++] = digits[0];

	if (ndigits > 1) {
		dest[idx++] = '.';
		memcpy(dest + idx, digits + 1, ndigits - 1);
		idx += ndigits - 1;
	}

	dest[idx++] = 'e';

	char sign = K + ndigits - 1 < 0 ? '-' : '+';
	dest[idx++] = sign;

	int cent = 0;

	if (exp > 99) {
		cent = exp / 100;
		dest[idx++] = cent + '0';
		exp -= cent * 100;
	}
	if (exp > 9) {
		int dec = exp / 10;
		dest[idx++] = dec + '0';
		exp -= dec * 10;

	}
	else if (cent) {
		dest[idx++] = '0';
	}

	dest[idx++] = exp % 10 + '0';

	return idx;
}

static inline int
emit_fixed_digits (char *digits, int ndigits,
		char *dest, int K, bool neg,
		unsigned precision, int exp)
{
	int offset = ndigits - absv(K), to_print;
	bool trim = (precision == FPCONV_PRECISION_ALL);

	/* fp < 1.0 -> write leading zero */
	if (K < 0) {
		if (offset <= 0) {
			if (precision && !trim) {
				if (-offset > (int)precision) {
					/* Just print 0.[0]{precision} */
					dest[0] = '0';
					dest[1] = '.';
					memset(dest + 2, '0', precision);

					return precision + 2;
				}

				to_print = MAX(ndigits - offset, (int)precision);
			}
			else if (trim) {
				/*
				 * FPCONV_PRECISION_ALL: emit all significant digits,
				 * then trim trailing zeros.
				 */
				to_print = ndigits - offset;

				if (to_print <= FPCONV_BUFLEN - 3) {
					int orig_offset = -offset;
					dest[0] = '0';
					dest[1] = '.';
					memset(dest + 2, '0', orig_offset);
					memcpy(dest + orig_offset + 2, digits, ndigits);

					return trim_trailing_zeros(dest,
							ndigits + 2 + orig_offset);
				}
				else {
					return emit_scientific_digits(digits, ndigits,
							dest, K, neg, precision, exp);
				}
			}
			else {
				/*
				 * precision == 0: print as rounded integer.
				 */
				if (offset >= 0 && digits[0] >= '5') {
					dest[0] = '1';
				}
				else {
					dest[0] = '0';
				}

				return 1;
			}

			if (to_print <= FPCONV_BUFLEN - 3) {
				offset = -offset;

				if (precision) {
					unsigned orig_offset = offset;
					unsigned total_frac = precision;

					precision -= offset;

					if (precision == 0) {
						/*
						 * All fractional digits are leading zeros.
						 * Check if the first significant digit rounds up.
						 */
						if (digits[0] >= '5') {
							unsigned new_leading = orig_offset - 1;
							dest[0] = '0';
							dest[1] = '.';
							memset(dest + 2, '0', new_leading);
							dest[2 + new_leading] = '1';
							unsigned trailing = total_frac - new_leading - 1;

							if (trailing > 0) {
								memset(dest + 3 + new_leading, '0',
										trailing);
							}

							return total_frac + 2;
						}

						dest[0] = '0';
						dest[1] = '.';
						memset(dest + 2, '0', total_frac);

						return total_frac + 2;
					}

					if (precision <= (unsigned)ndigits) {
						int carry = 0;

						/* Round at the truncation point */
						if (precision < (unsigned)ndigits) {
							ndigits = round_at_ex(digits, ndigits,
									precision, &carry);
						}

						if (carry) {
							if (orig_offset == 0) {
								/*
								 * Carry crossed to integer part
								 * (e.g. 0.999 -> 1.00)
								 */
								dest[0] = '1';
								dest[1] = '.';
								memset(dest + 2, '0', total_frac);
							}
							else {
								/*
								 * Carry within fractional part
								 * (e.g. 0.0999 -> 0.10)
								 */
								unsigned new_leading = orig_offset - 1;
								dest[0] = '0';
								dest[1] = '.';
								memset(dest + 2, '0', new_leading);
								memcpy(dest + 2 + new_leading,
										digits, ndigits);
								unsigned emitted = new_leading + ndigits;

								if (emitted < total_frac) {
									memset(dest + 2 + emitted, '0',
											total_frac - emitted);
								}
							}

							return total_frac + 2;
						}

						dest[0] = '0';
						dest[1] = '.';
						memset(dest + 2, '0', orig_offset);
						memcpy(dest + 2 + orig_offset,
								digits, precision);

						return total_frac + 2;
					}
					else {
						/* Expand */
						dest[0] = '0';
						dest[1] = '.';
						memset(dest + 2, '0', offset);
						memcpy(dest + offset + 2, digits, ndigits);
						precision -= ndigits;
						memset(dest + offset + 2 + ndigits, '0', precision);

						return ndigits + 2 + offset + precision;
					}
				}
				else {
					dest[0] = '0';
					dest[1] = '.';
					memset(dest + 2, '0', offset);
					memcpy(dest + offset + 2, digits, ndigits);
				}

				return ndigits + 2 + offset;
			}
			else {
				return emit_scientific_digits (digits, ndigits, dest, K, neg, precision, exp);
			}
		}
		else {
			/*
			 * offset > 0: fp is 1.xxx .. 9.xxx
			 */
			if (offset > 0 && ndigits <= FPCONV_BUFLEN - 3) {
				char *d = dest;

				if (precision == 0) {
					if (offset < ndigits &&
					digits[offset] >= '5') {
						int new_ndigits = round_at(digits,
								ndigits, offset);

						memcpy(d, digits, new_ndigits);
						return new_ndigits;
					}

					memcpy(d, digits, offset);
					return offset;
				}

				ndigits -= offset;

				if (precision) {
					if (!trim && (unsigned)ndigits >= precision) {
						int round_pos = offset + precision;
						int orig_offset = offset;
						int carry = 0;

						ndigits = round_at_ex(digits,
								ndigits + offset, round_pos,
								&carry);

						if (carry) {
							int new_int = orig_offset + 1;
							memcpy(d, digits, new_int);
							d += new_int;
							*d++ = '.';
							int frac_avail = ndigits - new_int;
							if (frac_avail > 0) {
								memcpy(d, digits + new_int,
										frac_avail);
								d += frac_avail;
								precision -= frac_avail;
							}
							memset(d, '0', precision);
							d += precision;

							return d - dest;
						}

						memcpy(d, digits, orig_offset);
						d += orig_offset;
						*d++ = '.';
						memcpy(d, digits + orig_offset, precision);
						d += precision;

						return d - dest;
					}
					else if (trim) {
						memcpy(d, digits, offset);
						d += offset;
						*d++ = '.';
						memcpy(d, digits + offset, ndigits);
						d += ndigits;

						int total_len = d - dest;
						return trim_trailing_zeros(dest, total_len);
					}
					else {
						memcpy(d, digits, offset);
						d += offset;
						*d++ = '.';
						memcpy(d, digits + offset, ndigits);
						precision -= ndigits;
						d += ndigits;

						if ((d - dest) + precision <= FPCONV_BUFLEN) {
							memset (d, '0', precision);
							d += precision;
						}
						else {
							memset (d, '0', FPCONV_BUFLEN - (d - dest));
							d += FPCONV_BUFLEN - (d - dest);
						}
					}
				}
				else {
					memcpy(d, digits, offset);
					d += offset;
					*d++ = '.';
					memcpy(d, digits + offset, ndigits);
					d += ndigits;
				}

				return d - dest;
			}
		}
	}

	return emit_scientific_digits (digits, ndigits, dest, K, neg, precision, exp);
}

static int
emit_digits (char *digits, int ndigits, char *dest, int K, bool neg,
		unsigned precision, bool scientific)
{
	int exp = absv(K + ndigits - 1);

	/* write plain integer */
	if (K >= 0 && (exp < (ndigits + 7))) {
		return emit_integer (digits, ndigits, dest, K, neg, precision);
	}

	/* write decimal w/o scientific notation */
	if (!scientific || (K < 0 && (K > -7 || exp < 4))) {
		return emit_fixed_digits (digits, ndigits, dest, K, neg, precision, exp);
	}

	return emit_scientific_digits (digits, ndigits, dest, K, neg, precision, exp);
}

static int
format_special (int code, char *dest, unsigned precision, bool is_negative)
{
	char *d = dest;

	if (code == FPCONV_GRISU_ZERO) {
		if (is_negative) {
			*d++ = '-';
		}
		*d++ = '0';

		if (precision && precision != FPCONV_PRECISION_ALL) {
			*d++ = '.';
			memset(d, '0', precision);
			d += precision;
		}

		return d - dest;
	}

	if (code == FPCONV_GRISU_NAN) {
		dest[0] = 'n';
		dest[1] = 'a';
		dest[2] = 'n';
		return 3;
	}

	/* FPCONV_GRISU_INF */
	if (is_negative) {
		dest[0] = '-';
		dest[1] = 'i';
		dest[2] = 'n';
		dest[3] = 'f';
		return 4;
	}

	dest[0] = 'i';
	dest[1] = 'n';
	dest[2] = 'f';
	return 3;
}

int
fpconv_format_dtoa (double d, char dest[FPCONV_BUFLEN],
		unsigned precision, bool scientific)
{
	if (precision > FPCONV_BUFLEN - 5) {
		precision = FPCONV_BUFLEN - 5;
	}

	char digits[18];
	int K = 0, is_negative = 0;
	int ndigits = fpconv_grisu2(d, digits, &K, &is_negative);

	if (ndigits < 0) {
		return format_special(ndigits, dest, precision, is_negative);
	}

	int str_len = 0;
	if (is_negative) {
		dest[0] = '-';
		str_len = 1;
	}

	str_len += emit_digits(digits, ndigits, dest + str_len, K,
			is_negative, precision, scientific);

	return str_len;
}
