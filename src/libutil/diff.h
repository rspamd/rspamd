/* Copyright (c) 2010, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#ifndef DIFF_H_
#define DIFF_H_

#include "config.h"
#include "fstring.h"

typedef enum
{
	DIFF_MATCH = 1,
	DIFF_DELETE,
	DIFF_INSERT
} diff_op;

struct diff_edit
{
	gshort op;
	gint off; /* off ginto s1 if MATCH or DELETE but s2 if INSERT */
	gint len;
};

/*
 * Calculate difference between two strings using diff algorithm
 * @param a the first line begin
 * @param aoff the first line offset
 * @param n the first line length
 * @param b the second line begin
 * @param boff the second line offset
 * @param b the second line length
 * @param dmax maximum differences number
 * @param ses here would be stored the shortest script to transform a to b
 * @param sn here would be stored a number of differences between a and b
 * @return distance between strings or -1 in case of error
 */
gint rspamd_diff (const void *a,
	gint aoff,
	gint n,
	const void *b,
	gint boff,
	gint m,
	gint dmax,
	GArray *ses,
	gint *sn);

/*
 * Calculate distance between two strings (in percentage) using diff algorithm.
 * @return 100 in case of identical strings and 0 in case of totally different strings.
 */
guint32 rspamd_diff_distance (rspamd_fstring_t *s1, rspamd_fstring_t *s2);

/*
 * Calculate distance between two strings (in percentage) using diff algorithm. Strings are normalized before:
 * all spaces are removed and all characters are lowercased.
 * @return 100 in case of identical strings and 0 in case of totally different strings.
 */
guint32 rspamd_diff_distance_normalized (rspamd_fstring_t *s1, rspamd_fstring_t *s2);

#endif /* DIFF_H_ */
