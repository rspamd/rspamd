#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <sys/param.h>

#include "fpconv.h"
#include "powers.h"

/*
 * Grisu2 produces at most 17 significant digits, so any explicit
 * precision in [1..17] is safe to use for fixed-width padding.
 * FPCONV_PRECISION_ALL (20) sits well above that range.
 */
static_assert(FPCONV_PRECISION_ALL > 17,
		"FPCONV_PRECISION_ALL must exceed max significant digits of a double");

#define fracmask  0x000FFFFFFFFFFFFFU
#define expmask   0x7FF0000000000000U
#define hiddenbit 0x0010000000000000U
#define signmask  0x8000000000000000U
#define expbias   (1023 + 52)

#define absv(n) ((n) < 0 ? -(n) : (n))
#define minv(a, b) ((a) < (b) ? (a) : (b))

static uint64_t tens[] = {
		10000000000000000000U, 1000000000000000000U, 100000000000000000U,
		10000000000000000U, 1000000000000000U, 100000000000000U,
		10000000000000U, 1000000000000U, 100000000000U,
		10000000000U, 1000000000U, 100000000U,
		10000000U, 1000000U, 100000U,
		10000U, 1000U, 100U,
		10U, 1U
};

static inline uint64_t get_dbits (double d) {
	union {
		double dbl;
		uint64_t i;
	} dbl_bits = {d};

	return dbl_bits.i;
}

static Fp build_fp (double d) {
	uint64_t bits = get_dbits (d);

	Fp fp;
	fp.frac = bits & fracmask;
	fp.exp = (bits & expmask) >> 52u;

	if (fp.exp) {
		fp.frac += hiddenbit;
		fp.exp -= expbias;

	}
	else {
		fp.exp = -expbias + 1;
	}

	return fp;
}

static void normalize (Fp *fp) {
	while ((fp->frac & hiddenbit) == 0) {
		fp->frac <<= 1u;
		fp->exp--;
	}

	const unsigned int shift = 64 - 52 - 1;
	fp->frac <<= shift;
	fp->exp -= shift;
}

static void get_normalized_boundaries (Fp *fp, Fp *lower, Fp *upper) {
	upper->frac = (fp->frac << 1u) + 1u;
	upper->exp = fp->exp - 1u;

	while ((upper->frac & (hiddenbit << 1u)) == 0) {
		upper->frac <<= 1u;
		upper->exp--;
	}

	const unsigned int u_shift = 64 - 52 - 2;

	upper->frac <<= u_shift;
	upper->exp = upper->exp - u_shift;


	unsigned int l_shift = fp->frac == hiddenbit ? 2u : 1u;

	lower->frac = (fp->frac << l_shift) - 1;
	lower->exp = fp->exp - l_shift;


	lower->frac <<= lower->exp - upper->exp;
	lower->exp = upper->exp;
}

static Fp multiply (Fp *a, Fp *b) {
	const uint64_t lomask = 0x00000000FFFFFFFFu;

	uint64_t ah_bl = (a->frac >> 32u) * (b->frac & lomask);
	uint64_t al_bh = (a->frac & lomask) * (b->frac >> 32u);
	uint64_t al_bl = (a->frac & lomask) * (b->frac & lomask);
	uint64_t ah_bh = (a->frac >> 32u) * (b->frac >> 32u);

	uint64_t tmp = (ah_bl & lomask) + (al_bh & lomask) + (al_bl >> 32u);
	/* round up */
	tmp += 1U << 31u;

	Fp fp = {
			ah_bh + (ah_bl >> 32u) + (al_bh >> 32u) + (tmp >> 32u),
			a->exp + b->exp + 64u
	};

	return fp;
}

static void round_digit (char *digits, int ndigits, uint64_t delta, uint64_t rem, uint64_t kappa, uint64_t frac) {
	while (rem < frac && delta - rem >= kappa &&
		   (rem + kappa < frac || frac - rem > rem + kappa - frac)) {

		digits[ndigits - 1]--;
		rem += kappa;
	}
}

static int generate_digits (Fp *fp, Fp *upper, Fp *lower, char *digits, int *K) {
	uint64_t wfrac = upper->frac - fp->frac;
	uint64_t delta = upper->frac - lower->frac;

	Fp one;
	one.frac = 1ULL << -upper->exp;
	one.exp = upper->exp;

	uint64_t part1 = upper->frac >> -one.exp;
	uint64_t part2 = upper->frac & (one.frac - 1);

	int idx = 0, kappa = 10;
	uint64_t *divp;
	/* 1000000000 */
	for (divp = tens + 10; kappa > 0; divp++) {

		uint64_t div = *divp;
		unsigned digit = part1 / div;

		if (digit || idx) {
			digits[idx++] = digit + '0';
		}

		part1 -= digit * div;
		kappa--;

		uint64_t tmp = (part1 << -one.exp) + part2;
		if (tmp <= delta) {
			*K += kappa;
			round_digit (digits, idx, delta, tmp, div << -one.exp, wfrac);

			return idx;
		}
	}

	/* 10 */
	uint64_t *unit = tens + 18;

	while (true) {
		part2 *= 10;
		delta *= 10;
		kappa--;

		unsigned digit = part2 >> -one.exp;
		if (digit || idx) {
			digits[idx++] = digit + '0';
		}

		part2 &= one.frac - 1;
		if (part2 < delta) {
			*K += kappa;
			round_digit (digits, idx, delta, part2, one.frac, wfrac * *unit);

			return idx;
		}

		unit--;
	}
}

static int grisu2 (double d, char *digits, int *K) {
	Fp w = build_fp (d);

	Fp lower, upper;
	get_normalized_boundaries (&w, &lower, &upper);

	normalize (&w);

	int k;
	Fp cp = find_cachedpow10 (upper.exp, &k);

	w = multiply (&w, &cp);
	upper = multiply (&upper, &cp);
	lower = multiply (&lower, &cp);

	lower.frac++;
	upper.frac--;

	*K = -k;

	return generate_digits (&w, &upper, &lower, digits, K);
}

static inline int emit_integer (char *digits, int ndigits,
								char *dest, int K, bool neg,
								unsigned precision)
{
	char *d = dest;

	memcpy (d, digits, ndigits);
	d += ndigits;
	memset (d, '0', K);
	d += K;

	if (precision == FPCONV_PRECISION_ALL) {
		/* Trim mode: no fractional part for integers */
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

static inline int emit_scientific_digits (char *digits, int ndigits,
									 char *dest, int K, bool neg,
									 unsigned precision, int exp)
{
	/* write decimal w/ scientific notation */
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

static inline int round_up_digits (char *digits, int ndigits)
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
static inline int round_at_ex (char *digits, int total, int round_pos,
		int *carry_overflow)
{
	if (round_pos >= total || digits[round_pos] < '5') {
		if (carry_overflow) *carry_overflow = 0;
		return total;
	}

	/* Round up: carry into digits[0..round_pos-1] */
	if (round_pos == 0) {
		/*
		 * The first significant digit >= '5': the value rounds up
		 * to 1 in the current magnitude (the caller places the
		 * decimal point via K, so "1" is always the correct result
		 * regardless of scale — e.g. 0.5→1, 0.05→1, 5→1).
		 */
		digits[0] = '1';
		if (carry_overflow) *carry_overflow = 0;
		return 1;
	}

	/* Set rounding position and everything after to '0' (caller
	 * won't use them, but zero them for safety during carry). */
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

static inline int round_at (char *digits, int total, int round_pos)
{
	return round_at_ex(digits, total, round_pos, NULL);
}

/*
 * Trim trailing '0' characters from [start, start+len) and the preceding
 * '.' if all fractional digits are removed.  Returns new length.
 */
static inline int trim_trailing_zeros (char *start, int len)
{
	if (len <= 0) {
		return len;
	}

	char *p = start + len - 1;

	while (p > start && *p == '0') {
		p--;
	}

	if (*p == '.') {
		/* Remove the decimal point too */
		p--;
	}

	return (p - start) + 1;
}

static inline int emit_fixed_digits (char *digits, int ndigits,
									 char *dest, int K, bool neg,
									 unsigned precision, int exp)
{
	int offset = ndigits - absv(K), to_print;
	bool trim = (precision == FPCONV_PRECISION_ALL);

	/* fp < 1.0 -> write leading zero */
	if (K < 0) {
		if (offset <= 0) {
			if (precision && !trim) {
				if (-offset >= (int)precision) {
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
				 * Numbers < 0.5 round to "0"; >= 0.5 round to "1".
				 *
				 * offset = ndigits + K (K < 0).  When offset >= 0,
				 * digits[0] is the tenths-place digit.  When
				 * offset < 0, the first significant digit is
				 * beyond the tenths place so the value is < 0.1.
				 */
				if (offset >= 0 && digits[0] >= '5') {
					/*
					 * Value is in [0.5, 1.0).  Round up to 1.
					 * If all integer digits carry (e.g. 0.999...),
					 * the result is still 1.
					 */
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

					precision -= offset;

					if (precision <= (unsigned)ndigits) {
						int carry = 0;

						/* Round at the truncation point */
						if (precision < (unsigned)ndigits) {
							ndigits = round_at_ex(digits, ndigits,
									orig_offset + precision, &carry);
						}

						if (carry) {
							/*
							 * Carry overflowed into integer
							 * part (e.g. 0.96 → 1.0).
							 * Result is "1.[0]{precision}".
							 */
							dest[0] = '1';
							dest[1] = '.';
							memset(dest + 2, '0', precision);

							return precision + 2;
						}

						dest[0] = '0';
						dest[1] = '.';
						memset(dest + 2, '0', orig_offset);
						memcpy(dest + orig_offset + 2,
								digits + orig_offset, precision);

						return precision + 2 + orig_offset;
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
					/*
					 * Round to integer: if the first fractional
					 * digit >= '5', carry into integer part.
					 */
					if (offset < ndigits &&
						digits[offset] >= '5') {
						/* Round up the integer digits */
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
						/* Round first, then emit */
						int round_pos = offset + precision;
						int orig_offset = offset;
						int carry = 0;

						ndigits = round_at_ex(digits,
								ndigits + offset, round_pos,
								&carry);

						if (carry) {
							/*
							 * Carry added a digit to the
							 * integer part (e.g. 9.96 → 10.0).
							 * Integer part is now orig_offset+1
							 * digits long.
							 */
							int new_int = orig_offset + 1;
							memcpy(d, digits, new_int);
							d += new_int;
							*d++ = '.';
							/* Fractional digits from the carry result */
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
						/* Emit all available fractional digits */
						memcpy(d, digits, offset);
						d += offset;
						*d++ = '.';
						memcpy(d, digits + offset, ndigits);
						d += ndigits;

						/* Trim trailing zeros */
						int total_len = d - dest;
						return trim_trailing_zeros(dest, total_len);
					}
					else {
						/* Expand */
						memcpy(d, digits, offset);
						d += offset;
						*d++ = '.';
						memcpy(d, digits + offset, ndigits);
						precision -= ndigits;
						d += ndigits;

						/* Check if we have enough bufspace */
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

static int emit_digits (char *digits, int ndigits, char *dest, int K, bool neg,
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

static int filter_special (double fp, char *dest, unsigned precision)
{
	int nchars = 3;
	char *d = dest;

	if (fp == 0.0) {
		if (get_dbits (fp) & signmask) {
			*d++ = '-';
		}
		*d++ = '0';

		if (precision && precision != FPCONV_PRECISION_ALL) {
			*d++ = '.';
			memset (d, '0', precision);
			d += precision;
		}

		return d - dest;
	}

	uint64_t bits = get_dbits (fp);

	bool nan = (bits & expmask) == expmask;

	if (!nan) {
		return 0;
	}

	if (bits & fracmask) {
		dest[0] = 'n';
		dest[1] = 'a';
		dest[2] = 'n';
	}
	else {
		if (get_dbits (fp) & signmask) {
			dest[0] = '-';
			dest[1] = 'i';
			dest[2] = 'n';
			dest[3] = 'f';
			nchars = 4;
		}
		else {
			dest[0] = 'i';
			dest[1] = 'n';
			dest[2] = 'f';
		}
	}

	return nchars;
}

int
fpconv_dtoa (double d, char dest[FPCONV_BUFLEN],
			 unsigned precision, bool scientific)
{
	char digits[18];

	int str_len = 0;
	bool neg = false;

	if (precision > FPCONV_BUFLEN - 5) {
		precision = FPCONV_BUFLEN - 5;
	}

	int spec = filter_special (d, dest, precision);

	if (spec) {
		return spec;
	}

	if (get_dbits (d) & signmask) {
		dest[0] = '-';
		str_len++;
		neg = true;
	}

	int K = 0;
	int ndigits = grisu2 (d, digits, &K);

	str_len += emit_digits (digits, ndigits, dest + str_len, K, neg, precision,
			scientific);

	return str_len;
}
