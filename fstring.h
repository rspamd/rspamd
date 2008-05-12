/*
 * Functions for handling with fixed size strings
 */

#ifndef FSTRING_H
#define FSTRING_H

#include <sys/types.h>

typedef struct f_str_s {
	char *begin;
	size_t len;
	size_t size;
} f_str_t;

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
f_str_t* fstralloc (size_t len);

/*
 * Truncate string to its len
 */
f_str_t* fstrtruncate (f_str_t *orig);

/*
 * Enlarge string to new size
 */
f_str_t* fstrgrow (f_str_t *orig, size_t newlen);

/*
 * Free memory for f_str_t
 */
#define fstrfree(x) free((x)->begin); free((x))

#endif
