#include <stdbool.h>
#include <string.h>
#include <sys/param.h>

#include "fpconv.h"
#include "powers.h"

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

static inline int emit_fixed_digits (char *digits, int ndigits,
									 char *dest, int K, bool neg,
									 unsigned precision, int exp)
{
	int offset = ndigits - absv(K), to_print;
	/* fp < 1.0 -> write leading zero */
	if (K < 0) {
		if (offset <= 0) {
			if (precision) {
				if (-offset >= precision) {
					/* Just print 0.[0]{precision} */
					dest[0] = '0';
					dest[1] = '.';
					memset(dest + 2, '0', precision);

					return precision + 2;
				}

				to_print = MAX(ndigits - offset, precision);
			}
			else {
				to_print = ndigits - offset;
			}

			if (to_print <= FPCONV_BUFLEN - 3) {
				offset = -offset;
				dest[0] = '0';
				dest[1] = '.';
				memset(dest + 2, '0', offset);

				if (precision) {
					/* The case where offset > precision is covered previously */
					precision -= offset;

					if (precision <= ndigits) {
						/* Truncate or leave as is */
						memcpy(dest + offset + 2, digits, precision);

						return precision + 2 + offset;
					}
					else {
						/* Expand */
						memcpy(dest + offset + 2, digits, ndigits);
						precision -= ndigits;
						memset(dest + offset + 2 + ndigits, '0', precision);

						return ndigits + 2 + offset + precision;
					}
				}
				else {
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
			 * fp > 1.0, if offset > 0 then we have less digits than
			 * fp exponent, so we need to switch to scientific notation to
			 * display number at least more or less precisely
			 */
			if (offset > 0 && ndigits <= FPCONV_BUFLEN - 3) {
				char *d = dest;
				memcpy(d, digits, offset);
				d += offset;
				*d++ = '.';

				ndigits -= offset;

				if (precision) {
					if (ndigits >= precision) {
						/* Truncate or leave as is */
						memcpy(d, digits + offset, precision);
						d += precision;
					}
					else {
						/* Expand */
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
			*d++ = '0';
		}
		else {
			*d++ = '0';
		}

		if (precision) {
			*d ++ = '.';
			memset (d, '0', precision);
		}

		return d - dest + precision;
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
