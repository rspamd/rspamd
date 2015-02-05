/* diff - compute a shortest edit script (SES) given two sequences
 * Copyright (c) 2004 Michael B. Allen <mba2000 ioplex.com>
 * Copyright (c) 2010-2014, Vsevolod Stakhov
 *
 * The MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/* This algorithm is basically Myers' solution to SES/LCS with
 * the Hirschberg linear space refinement as described in the
 * following publication:
 *
 *   E. Myers, ``An O(ND) Difference Algorithm and Its Variations,''
 *   Algorithmica 1, 2 (1986), 251-266.
 *   http://www.cs.arizona.edu/people/gene/PAPERS/diff.ps
 *
 * This is the same algorithm used by GNU diff(1).
 */


#include "config.h"
#include "diff.h"


#define FV(k) _v (ctx, (k), 0)
#define RV(k) _v (ctx, (k), 1)

#define MAX_DIFF 1024

struct _ctx
{
	GArray *buf;
	GArray *ses;
	gint si;
	gint dmax;
};

struct middle_snake
{
	gint x, y, u, v;
};

static
void
maybe_resize_array (GArray *arr, guint k)
{
	if (k > arr->len) {
		g_array_set_size (arr, k);
	}

}

static void
_setv (struct _ctx *ctx, gint k, gint r, gint val)
{
	gint j;
	gint *i;
	/* Pack -N to N ginto 0 to N * 2
	 */
	j = k <= 0 ? -k * 4 + r : k * 4 + (r - 2);

	maybe_resize_array (ctx->buf, j);
	i = (gint *) &g_array_index (ctx->buf, gint, j);
	*i = val;
}

static gint
_v (struct _ctx *ctx, gint k, gint r)
{
	gint j;

	j = k <= 0 ? -k * 4 + r : k * 4 + (r - 2);

	return *((gint *) &g_array_index (ctx->buf, gint, j));
}

static gint
_find_middle_snake (const void *a, gint aoff, gint n, const void *b,
	gint boff, gint m, struct _ctx *ctx, struct middle_snake *ms)
{
	gint delta, odd, mid, d;

	delta = n - m;
	odd = delta & 1;
	mid = (n + m) / 2;
	mid += odd;

	_setv (ctx, 1,		   0, 0);
	_setv (ctx, delta - 1, 1, n);

	for (d = 0; d <= mid; d++) {
		gint k, x, y;

		if ((2 * d - 1) >= ctx->dmax) {
			return ctx->dmax;
		}

		for (k = d; k >= -d; k -= 2) {
			if (k == -d || (k != d && FV (k - 1) < FV (k + 1))) {
				x = FV (k + 1);
			}
			else {
				x = FV (k - 1) + 1;
			}
			y = x - k;

			ms->x = x;
			ms->y = y;
			const guchar *a0 = (const guchar *) a + aoff;
			const guchar *b0 = (const guchar *) b + boff;
			while (x < n && y < m && a0[x] == b0[y]) {
				x++;
				y++;
			}
			_setv (ctx, k, 0, x);

			if (odd && k >= (delta - (d - 1)) && k <= (delta + (d - 1))) {
				if (x >= RV (k)) {
					ms->u = x;
					ms->v = y;
					return 2 * d - 1;
				}
			}
		}
		for (k = d; k >= -d; k -= 2) {
			gint kr = (n - m) + k;

			if (k == d || (k != -d && RV (kr - 1) < RV (kr + 1))) {
				x = RV (kr - 1);
			}
			else {
				x = RV (kr + 1) - 1;
			}
			y = x - kr;

			ms->u = x;
			ms->v = y;
			const guchar *a0 = (const guchar *) a + aoff;
			const guchar *b0 = (const guchar *) b + boff;
			while (x > 0 && y > 0 && a0[x - 1] == b0[y - 1]) {
				x--;
				y--;
			}
			_setv (ctx, kr, 1, x);

			if (!odd && kr >= -d && kr <= d) {
				if (x <= FV (kr)) {
					ms->x = x;
					ms->y = y;
					return 2 * d;
				}
			}
		}
	}

	errno = EFAULT;

	return -1;
}

static void
_edit (struct _ctx *ctx, gint op, gint off, gint len)
{
	struct diff_edit *e = NULL, newe;

	if (len == 0 || ctx->ses == NULL) {
		return;
	}
	/*
	 * Add an edit to the SES (or
	 * coalesce if the op is the same)
	 */
	if (ctx->ses->len != 0) {
		e = &g_array_index (ctx->ses, struct diff_edit, ctx->ses->len - 1);
	}
	if (e == NULL || e->op != op) {
		newe.op = op;
		newe.off = off;
		newe.len = len;
		g_array_append_val (ctx->ses, newe);
	}
	else {
		e->len += len;
	}
}

static gint
_ses (const void *a, gint aoff, gint n, const void *b, gint boff,
	gint m, struct _ctx *ctx)
{
	struct middle_snake ms = {
		.x = 0,
		.y = 0,
		.u = 0,
		.v = 0
	};
	gint d;

	if (n == 0) {
		_edit (ctx, DIFF_INSERT, boff, m);
		d = m;
	}
	else if (m == 0) {
		_edit (ctx, DIFF_DELETE, aoff, n);
		d = n;
	}
	else {
		/* Find the middle "snake" around which we
		 * recursively solve the sub-problems.
		 */
		d = _find_middle_snake (a, aoff, n, b, boff, m, ctx, &ms);
		if (d == -1) {
			return -1;
		}
		else if (d >= ctx->dmax) {
			return ctx->dmax;
		}
		else if (ctx->ses == NULL) {
			return d;
		}
		else if (d > 1) {
			if (_ses (a, aoff, ms.x, b, boff, ms.y, ctx) == -1) {
				return -1;
			}

			_edit (ctx, DIFF_MATCH, aoff + ms.x, ms.u - ms.x);

			aoff += ms.u;
			boff += ms.v;
			n -= ms.u;
			m -= ms.v;
			if (_ses (a, aoff, n, b, boff, m, ctx) == -1) {
				return -1;
			}
		}
		else {
			gint x = ms.x;
			gint u = ms.u;

			/* There are only 4 base cases when the
			 * edit distance is 1.
			 *
			 * n > m   m > n
			 *
			 *   -       |
			 *    \       \    x != u
			 *     \       \
			 *
			 *   \       \
			 *    \       \    x == u
			 *     -       |
			 */

			/*
			 * XXX: coverity found this code suspicious, needs checking
			 */
			if (m > n) {
				if (x == u) {
					_edit (ctx, DIFF_MATCH,	 aoff,			 n);
					_edit (ctx, DIFF_INSERT, boff + (m - 1), 1);
				}
				else {
					_edit (ctx, DIFF_INSERT, boff, 1);
					_edit (ctx, DIFF_MATCH,	 aoff, n);
				}
			}
			else {
				if (x == u) {
					_edit (ctx, DIFF_MATCH,	 aoff,			 m);
					_edit (ctx, DIFF_DELETE, aoff + (n - 1), 1);
				}
				else {
					_edit (ctx, DIFF_DELETE, aoff,	   1);
					_edit (ctx, DIFF_MATCH,	 aoff + 1, m);
				}
			}
		}
	}

	return d;
}

gint
rspamd_diff (const void *a, gint aoff, gint n, const void *b, gint boff, gint m,
	gint dmax, GArray *ses, gint *sn)
{
	struct _ctx ctx;
	gint d, x, y;
	GArray *tmp;

	tmp = g_array_sized_new (FALSE, TRUE, sizeof(gint), dmax);
	ctx.buf = tmp;
	ctx.ses = ses;
	ctx.si = 0;
	ctx.dmax = dmax;

	/* The _ses function assumes the SES will begin or end with a delete
	 * or insert. The following will insure this is true by eating any
	 * beginning matches. This is also a quick to process sequences
	 * that match entirely.
	 */
	x = y = 0;
	const guchar *a0 = (const guchar *) a + aoff;
	const guchar *b0 = (const guchar *) b + boff;
	while (x < n && y < m && a0[x] == b0[y]) {
		x++;
		y++;
	}
	_edit (&ctx, DIFF_MATCH, aoff, x);

	if ((d = _ses (a, aoff + x, n - x, b, boff + y, m - y, &ctx)) == -1) {
		g_array_free (tmp, TRUE);
		return -1;
	}

	g_array_free (tmp, TRUE);
	return d;
}

static guint32
compare_diff_distance_unnormalized (rspamd_fstring_t *s1, rspamd_fstring_t *s2)
{
	GArray *ses;
	struct diff_edit *e;
	guint i;
	guint32 distance = 0;

	ses = g_array_sized_new (FALSE, TRUE, sizeof (struct diff_edit), MAX_DIFF);

	if (rspamd_diff (s1->begin, 0, s1->len,
		s2->begin, 0, s2->len, MAX_DIFF, ses, NULL) == -1) {
		/* Diff failed, strings are different */
		g_array_free (ses, TRUE);
		return 0;
	}

	for (i = 0; i < ses->len; i++) {
		e = &g_array_index (ses, struct diff_edit, i);
		if (e->op != DIFF_MATCH) {
			distance += e->len;
		}
	}

	g_array_free (ses, TRUE);

	return distance;
}

guint32
rspamd_diff_distance (rspamd_fstring_t *s1, rspamd_fstring_t *s2)
{

	return 100 -
		   (2 *
		   compare_diff_distance_unnormalized (s1,
		   s2) * 100) / (s1->len + s2->len);
}


guint32
rspamd_diff_distance_normalized (rspamd_fstring_t *s1, rspamd_fstring_t *s2)
{
	gchar b1[BUFSIZ], b2[BUFSIZ], *t, *h, *p1, *p2;
	gsize r1, r2;
	rspamd_fstring_t t1, t2;
	guint32 cur_diff = 0;

	r1 = s1->len;
	r2 = s2->len;
	p1 = s1->begin;
	p2 = s2->begin;

	while (r1 > 0 && r2 > 0) {
		/* Copy strings to the buffer normalized */
		h = p1;
		t = b1;

		/* The first string */
		while (r1 > 0 && t - b1 < (gint)sizeof (b1)) {
			if (!g_ascii_isspace (*h)) {
				*t++ = g_ascii_tolower (*h);
			}
			h++;
			p1++;
			r1--;
		}

		t1.begin = b1;
		t1.len = t - b1;

		/* The second string */
		h = p2;
		t = b2;
		while (r2 > 0 && t - b2 < (gint)sizeof (b2)) {
			if (!g_ascii_isspace (*h)) {
				*t++ = g_ascii_tolower (*h);
			}
			h++;
			p2++;
			r2--;
		}

		t2.begin = b2;
		t2.len = t - b2;

		cur_diff += compare_diff_distance_unnormalized (&t1, &t2);
	}

	if (r1 > 0) {
		h = p1;
		while (r1 > 0) {
			if (!g_ascii_isspace (*h)) {
				cur_diff++;
			}
			r1--;
			h++;
		}
	}
	else if (r2 > 0) {
		h = p2;
		while (r2 > 0) {
			if (!g_ascii_isspace (*h)) {
				cur_diff++;
			}
			r2--;
			h++;
		}
	}

	return 100 - (2 * cur_diff * 100) / (s1->len + s2->len);
}
