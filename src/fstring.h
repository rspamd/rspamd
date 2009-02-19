/*
 * Functions for handling with fixed size strings
 */

#ifndef FSTRING_H
#define FSTRING_H

#include "config.h"
#include "mem_pool.h"

#define update_buf_size(x) (x)->free = (x)->buf->size - ((x)->pos - (x)->buf->begin); (x)->buf->len = (x)->pos - (x)->buf->begin

typedef struct f_str_s {
	char *begin;
	size_t len;
	size_t size;
} f_str_t;

typedef struct f_str_buf_s {
	f_str_t *buf;
	char *pos;
	size_t free;
} f_str_buf_t;

typedef struct f_tok_s {
	f_str_t word;
	size_t pos;
} f_tok_t;

/*
 * Search first occurence of character in string
 */
ssize_t fstrchr (f_str_t *src, char c);

/*
 * Search last occurence of character in string
 */
ssize_t fstrrchr (f_str_t *src, char c);

/*
 * Search for pattern in orig
 */
ssize_t fstrstr (f_str_t *orig, f_str_t *pattern);

/*
 * Split string by tokens
 * word contains parsed word
 */
int fstrtok (f_str_t *text, const char *sep, f_tok_t *state);

/*
 * Copy one string into other
 */
size_t fstrcpy (f_str_t *dest, f_str_t *src);

/*
 * Concatenate two strings
 */
size_t fstrcat (f_str_t *dest, f_str_t *src);

/*
 * Push one character to fstr
 */
int fstrpush (f_str_t *dest, char c);

/*
 * Allocate memory for f_str_t
 */
f_str_t* fstralloc (memory_pool_t *pool, size_t len);

/*
 * Truncate string to its len
 */
f_str_t* fstrtruncate (memory_pool_t *pool, f_str_t *orig);

/*
 * Enlarge string to new size
 */
f_str_t* fstrgrow (memory_pool_t *pool, f_str_t *orig, size_t newlen);

/*
 * Return specified character
 */
#define fstridx(str, pos) *((str)->begin + (pos))

/*
 * Return fast hash value for fixed string
 */
uint32_t fstrhash (f_str_t *str);


/*
 * Make copy of string to 0-terminated string
 */
char* fstrcstr (f_str_t *str, memory_pool_t *pool);

#endif
