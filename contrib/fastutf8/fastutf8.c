/*
 * MIT License
 *
 * Copyright (c) 2019 Yibo Cai
 * Copyright (c) 2019 Vsevolod Stakhov
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "fastutf8.h"
#include "platform_config.h"


/*
 * http://www.unicode.org/versions/Unicode6.0.0/ch03.pdf - page 94
 *
 * Table 3-7. Well-Formed UTF-8 Byte Sequences
 *
 * +--------------------+------------+-------------+------------+-------------+
 * | Code Points        | First Byte | Second Byte | Third Byte | Fourth Byte |
 * +--------------------+------------+-------------+------------+-------------+
 * | U+0000..U+007F     | 00..7F     |             |            |             |
 * +--------------------+------------+-------------+------------+-------------+
 * | U+0080..U+07FF     | C2..DF     | 80..BF      |            |             |
 * +--------------------+------------+-------------+------------+-------------+
 * | U+0800..U+0FFF     | E0         | A0..BF      | 80..BF     |             |
 * +--------------------+------------+-------------+------------+-------------+
 * | U+1000..U+CFFF     | E1..EC     | 80..BF      | 80..BF     |             |
 * +--------------------+------------+-------------+------------+-------------+
 * | U+D000..U+D7FF     | ED         | 80..9F      | 80..BF     |             |
 * +--------------------+------------+-------------+------------+-------------+
 * | U+E000..U+FFFF     | EE..EF     | 80..BF      | 80..BF     |             |
 * +--------------------+------------+-------------+------------+-------------+
 * | U+10000..U+3FFFF   | F0         | 90..BF      | 80..BF     | 80..BF      |
 * +--------------------+------------+-------------+------------+-------------+
 * | U+40000..U+FFFFF   | F1..F3     | 80..BF      | 80..BF     | 80..BF      |
 * +--------------------+------------+-------------+------------+-------------+
 * | U+100000..U+10FFFF | F4         | 80..8F      | 80..BF     | 80..BF      |
 * +--------------------+------------+-------------+------------+-------------+
 */

/* Return 0 - success,  >0 - index (1 based) of first error char */
off_t
rspamd_fast_utf8_validate_ref (const unsigned char *data, size_t len)
{
	off_t err_pos = 1;

	while (len) {
		int bytes;
		const unsigned char byte1 = data[0];

		/* 00..7F */
		if (byte1 <= 0x7F) {
			bytes = 1;
			/* C2..DF, 80..BF */
		}
		else if (len >= 2 && byte1 >= 0xC2 && byte1 <= 0xDF &&
				 (signed char) data[1] <= (signed char) 0xBF) {
			bytes = 2;
		}
		else if (len >= 3) {
			const unsigned char byte2 = data[1];

			/* Is byte2, byte3 between 0x80 ~ 0xBF */
			const int byte2_ok = (signed char) byte2 <= (signed char) 0xBF;
			const int byte3_ok = (signed char) data[2] <= (signed char) 0xBF;

			if (byte2_ok && byte3_ok &&
				/* E0, A0..BF, 80..BF */
				((byte1 == 0xE0 && byte2 >= 0xA0) ||
				 /* E1..EC, 80..BF, 80..BF */
				 (byte1 >= 0xE1 && byte1 <= 0xEC) ||
				 /* ED, 80..9F, 80..BF */
				 (byte1 == 0xED && byte2 <= 0x9F) ||
				 /* EE..EF, 80..BF, 80..BF */
				 (byte1 >= 0xEE && byte1 <= 0xEF))) {
				bytes = 3;
			}
			else if (len >= 4) {
				/* Is byte4 between 0x80 ~ 0xBF */
				const int byte4_ok = (signed char) data[3] <= (signed char) 0xBF;

				if (byte2_ok && byte3_ok && byte4_ok &&
					/* F0, 90..BF, 80..BF, 80..BF */
					((byte1 == 0xF0 && byte2 >= 0x90) ||
					 /* F1..F3, 80..BF, 80..BF, 80..BF */
					 (byte1 >= 0xF1 && byte1 <= 0xF3) ||
					 /* F4, 80..8F, 80..BF, 80..BF */
					 (byte1 == 0xF4 && byte2 <= 0x8F))) {
					bytes = 4;
				}
				else {
					return err_pos;
				}
			}
			else {
				return err_pos;
			}
		}
		else {
			return err_pos;
		}

		len -= bytes;
		err_pos += bytes;
		data += bytes;
	}

	return 0;
}

/* Prototypes */
#ifdef HAVE_SSSE3
extern off_t rspamd_fast_utf8_validate_sse41 (const unsigned char *data, size_t len);
#endif
#ifdef HAVE_AVX2
extern off_t rspamd_fast_utf8_validate_avx2 (const unsigned char *data, size_t len);
#endif

static off_t (*validate_func) (const unsigned char *data, size_t len) =
		rspamd_fast_utf8_validate_ref;


void
rspamd_fast_utf8_library_init (unsigned flags)
{
#ifdef HAVE_SSSE3
	if (flags & RSPAMD_FAST_UTF8_FLAG_SSE41) {
		validate_func = rspamd_fast_utf8_validate_sse41;
	}
#endif
#ifdef HAVE_AVX2
	if (flags & RSPAMD_FAST_UTF8_FLAG_AVX2) {
		validate_func = rspamd_fast_utf8_validate_avx2;
	}
#endif
}

off_t
rspamd_fast_utf8_validate (const unsigned char *data, size_t len)
{
	return len >= 64 ?
			validate_func (data, len) :
			rspamd_fast_utf8_validate_ref (data, len);
}