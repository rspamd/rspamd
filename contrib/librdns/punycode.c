/*
 * Copyright (c) 2014, Vsevolod Stakhov
 * Copyright (c) 2004, 2006, 2007, 2008 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "dns_private.h"
static const unsigned event_loop = 36;
static const unsigned t_min = 1;
static const unsigned t_max = 26;
static const unsigned skew = 38;
static const unsigned damp = 700;
static const unsigned initial_n = 128;
static const unsigned initial_bias = 72;
/* Punycode utility */
static unsigned int
digit (unsigned n)
{
	static const char ascii[] = "abcdefghijklmnopqrstuvwxyz0123456789";
	return ascii[n];
}

static unsigned int
adapt (unsigned int delta, unsigned int numpoints, int first)
{
	unsigned int k;

	if (first) {
		delta = delta / damp;
	}
	else {
		delta /= 2;
	}
	delta += delta / numpoints;
	k = 0;
	while (delta > ((event_loop - t_min) * t_max) / 2) {
		delta /= event_loop - t_min;
		k += event_loop;
	}
	return k + (((event_loop - t_min + 1) * delta) / (delta + skew));
}

/**
 * Convert an UCS4 string to a puny-coded DNS label string suitable
 * when combined with delimiters and other labels for DNS lookup.
 *
 * @param in an UCS4 string to convert
 * @param in_len the length of in.
 * @param out the resulting puny-coded string. The string is not NULL
 * terminated.
 * @param out_len before processing out_len should be the length of
 * the out variable, after processing it will be the length of the out
 * string.
 *
 * @return returns 0 on success, an wind error code otherwise
 */

bool
rdns_punycode_label_toascii (const uint32_t *in, size_t in_len, char *out,
		size_t *out_len)
{
	unsigned int n = initial_n;
	unsigned int delta = 0;
	unsigned int bias = initial_bias;
	unsigned int h = 0;
	unsigned int b;
	unsigned int i;
	unsigned int o = 0;
	unsigned int m;

	for (i = 0; i < in_len; ++i) {
		if (in[i] < 0x80) {
			++h;
			if (o >= *out_len) {
				return false;
			}
			out[o++] = in[i];
		}
	}
	b = h;
	if (b > 0) {
		if (o >= *out_len) {
			return false;
		}
		out[o++] = 0x2D;
	}
	/* is this string punycoded */
	if (h < in_len) {
		if (o + 4 >= *out_len) {
			return false;
		}
		memmove (out + 4, out, o);
		memcpy (out, "xn--", 4);
		o += 4;
	}

	while (h < in_len) {
		m = (unsigned int) -1;
		for (i = 0; i < in_len; ++i) {

			if (in[i] < m && in[i] >= n) {
				m = in[i];
			}
		}
		delta += (m - n) * (h + 1);
		n = m;
		for (i = 0; i < in_len; ++i) {
			if (in[i] < n) {
				++delta;
			}
			else if (in[i] == n) {
				unsigned int q = delta;
				unsigned int k;
				for (k = event_loop;; k += event_loop) {
					unsigned int t;
					if (k <= bias) {
						t = t_min;
					}
					else if (k >= bias + t_max) {
						t = t_max;
					}
					else {
						t = k - bias;
					}
					if (q < t) {
						break;
					}
					if (o >= *out_len) {
						return -1;
					}
					out[o++] = digit (t + ((q - t) % (event_loop - t)));
					q = (q - t) / (event_loop - t);
				}
				if (o >= *out_len) {
					return -1;
				}
				out[o++] = digit (q);
				/* output */
				bias = adapt (delta, h + 1, h == b);
				delta = 0;
				++h;
			}
		}
		++delta;
		++n;
	}

	*out_len = o;
	return true;
}

static int
utf8toutf32 (const unsigned char **pp, uint32_t *out, size_t *remain)
{
	const unsigned char *p = *pp;
	unsigned c = *p;
	size_t reduce;

	if (c & 0x80) {
		if ((c & 0xE0) == 0xC0 && *remain >= 2) {
			const unsigned c2 = *++p;
			reduce = 2;
			if ((c2 & 0xC0) == 0x80) {
				*out = ((c & 0x1F) << 6) | (c2 & 0x3F);
			}
			else {
				return -1;
			}
		}
		else if ((c & 0xF0) == 0xE0 && *remain >= 3) {
			const unsigned c2 = *++p;
			if ((c2 & 0xC0) == 0x80) {
				const unsigned c3 = *++p;
				reduce = 3;
				if ((c3 & 0xC0) == 0x80) {
					*out = ((c & 0x0F) << 12) | ((c2 & 0x3F) << 6)
							| (c3 & 0x3F);
				}
				else {
					return -1;
				}
			}
			else {
				return -1;
			}
		}
		else if ((c & 0xF8) == 0xF0 && *remain >= 4) {
			const unsigned c2 = *++p;
			if ((c2 & 0xC0) == 0x80) {
				const unsigned c3 = *++p;
				if ((c3 & 0xC0) == 0x80) {
					const unsigned c4 = *++p;
					reduce = 4;
					if ((c4 & 0xC0) == 0x80) {
						*out = ((c & 0x07) << 18) | ((c2 & 0x3F) << 12)
								| ((c3 & 0x3F) << 6) | (c4 & 0x3F);
					}
					else {
						return -1;
					}
				}
				else {
					return -1;
				}
			}
			else {
				return -1;
			}
		}
		else {
			return -1;
		}
	}
	else {
		*out = c;
		reduce = 1;
	}

	*pp = ++p;
	*remain -= reduce;

	return 0;
}

/**
 * Convert an UTF-8 string to an UCS4 string.
 *
 * @param in an UTF-8 string to convert.
 * @param out the resulting UCS4 string
 * @param out_len before processing out_len should be the length of
 * the out variable, after processing it will be the length of the out
 * string.
 *
 * @return returns 0 on success, an -1 otherwise
 * @ingroup wind
 */

int
rdns_utf8_to_ucs4 (const char *in, size_t in_len, uint32_t **out, size_t *out_len)
{
	const unsigned char *p;
	size_t remain = in_len, olen = 0;
	int ret;
	uint32_t *res;

	p = (const unsigned char *)in;
	while (remain > 0) {
		uint32_t u;

		ret = utf8toutf32 (&p, &u, &remain);
		if (ret != 0) {
			return ret;
		}

		olen ++;
	}
	res = malloc (olen * sizeof (uint32_t));
	if (res == NULL) {
		return -1;
	}

	p = (const unsigned char *)in;
	remain = in_len;
	olen = 0;
	while (remain > 0) {
		uint32_t u;

		(void)utf8toutf32 (&p, &u, &remain);
		res[olen++] = u;
	}

	*out_len = olen;
	*out = res;
	return 0;
}
