#include <stdlib.h>
#include <ctype.h>

#include "mime.h"
#include "fstring.h"

/* 
 * Quoted printable and base64 decoders for mime parser
 */

static f_str_t *
base64decode (f_str_t *src)
{
	int bits = 0, buf = 0, padding = 0, v;
	size_t pos;
	char c;
	f_str_t *res;

	res = fstralloc (src->len);
	if (res == NULL) {
		return NULL;
	}

	for (pos = 0; pos < src->len; pos ++) {
		c = *(src->begin + pos);
		if (c >= 'A' && c <= 'Z') {
			v = c - 'A';
		}
		else if (c >= 'a' && c <= 'z') {
			v = c - 'a' + 26;
		}
		else if (c >= '0' && c <= '9') {
			v = c - '0' + 52;
		}
		else if ('+' == c) {
			v = 62;
		}
		else if ('/' == c) {
			v = 63;
		}
		else if ('=' == c) {
			padding++;
			continue;
		} 
		else {
			continue;
		}
		if (padding) {
			padding = 0;
		}
		buf = buf << 6 | v;
		bits += 6;
		if (bits >= 8) {
			c = 255 & (buf >> (bits - 8));
			fstrpush (res, c);
		}
	}

	return res;
}

static f_str_t *
qpdecode (f_str_t *src, short header)
{
	f_str_t *res;
	size_t pos;
	char c;

	res = fstralloc (src->len);
	if (res == NULL) {
		return NULL;
	}

	for (pos = 0; pos < src->len; pos++) {
		c = *(src->begin + pos);
		if (header && '_' == c) {
			c = 0x20;
		}
		else if ('=' == c && pos + 3 <= src->len && isxdigit (fstridx (src, pos + 1)) && isxdigit (fstridx (src, pos + 2))) {
			if (isdigit (fstridx (src, pos + 2))) {
				if (isdigit (fstridx (src, pos + 1))) {
					c = (toupper (fstridx (src, pos + 2)) - '0') | (16 * (fstridx (src, pos + 1) - '0'));
				} 
				else {
					c = (toupper (fstridx (src, pos + 2)) - '0') | (16 * (toupper (fstridx (src, pos + 1)) - 'A' + 10));
				}
			}
			else if (isdigit (fstridx (src, pos + 1))) {
				c = (toupper (fstridx (src, pos + 2)) - 'A' + 10) | (16 * (fstridx (src, pos + 1) - '0'));
			} 
			else {
				c = (toupper (fstridx (src, pos + 2)) - 'A' + 10) | (16 * (toupper (fstridx (src, pos + 1)) - 'A' + 10));
			}
			pos += 2;
		} 
		else if ('=' == c && pos + 2 <= src->len && ('\r' == fstridx (src, pos + 1) || '\n' == fstridx (src, pos + 1))) {
			if ('\r' == fstridx (src, pos + 1)) {
				if (pos + 3 <= src->len && '\n' == fstridx (src, pos + 2)) {
					pos ++;
				}
				pos ++;
			}
			if ('\n' == fstridx (src, pos + 1)) {
				if (pos + 3 <= src->len && '\r' == fstridx (src, pos + 2)) {
					pos ++;
				}
				pos ++;
			}
			continue;
		}
		fstrpush (res, c);
	}

	return res;
}

