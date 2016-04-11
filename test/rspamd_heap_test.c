/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "config.h"
#include "rspamd.h"
#include "heap.h"
#include "ottery.h"

static const guint niter = 100500;
static const guint nrem = 100;

static inline
struct rspamd_min_heap_elt *
new_elt (guint pri)
{
	struct rspamd_min_heap_elt *elt;

	elt = g_slice_alloc0 (sizeof (*elt));
	elt->pri = pri;

	return elt;
}

static gdouble
heap_nelts_test (guint nelts)
{
	struct rspamd_min_heap *heap;
	struct rspamd_min_heap_elt *elts;
	gdouble t1, t2;
	guint i;

	heap = rspamd_min_heap_create (nelts);
	/* Preallocate all elts */
	elts = g_slice_alloc (sizeof (*elts) * nelts);

	for (i = 0; i < nelts; i ++) {
		elts[i].pri = ottery_rand_uint32 () % G_MAXINT32 + 1;
		elts[i].idx = 0;
	}

	t1 = rspamd_get_virtual_ticks ();
	for (i = 0; i < nelts; i ++) {
		rspamd_min_heap_push (heap, &elts[i]);
	}

	for (i = 0; i < nelts; i ++) {
		(void)rspamd_min_heap_pop (heap);
	}
	t2 = rspamd_get_virtual_ticks ();

	g_slice_free1 (sizeof (*elts) * nelts, elts);
	rspamd_min_heap_destroy (heap);

	return (t2 - t1);
}

void
rspamd_heap_test_func (void)
{
	struct rspamd_min_heap *heap;
	struct rspamd_min_heap_elt *elt, *telt;
	guint i;
	guint prev;
	gdouble t[16];

	/* Push + update */
	heap = rspamd_min_heap_create (32);
	elt = new_elt (2);
	elt->data = GINT_TO_POINTER (1);
	rspamd_min_heap_push (heap, elt);
	elt = new_elt (3);
	elt->data = GINT_TO_POINTER (2);
	rspamd_min_heap_push (heap, elt);
	elt = new_elt (4);
	elt->data = GINT_TO_POINTER (3);
	rspamd_min_heap_push (heap, elt);

	rspamd_min_heap_update_elt (heap, elt, 0);
	elt = rspamd_min_heap_pop (heap);
	g_assert (elt->data == GINT_TO_POINTER (3));

	rspamd_min_heap_destroy (heap);

	/* Push + remove */
	heap = rspamd_min_heap_create (32);
	elt = new_elt (2);
	elt->data = GINT_TO_POINTER (1);
	rspamd_min_heap_push (heap, elt);
	rspamd_min_heap_remove_elt (heap, elt);
	elt = new_elt (3);
	elt->data = GINT_TO_POINTER (2);
	rspamd_min_heap_push (heap, elt);
	elt = rspamd_min_heap_pop (heap);
	g_assert (elt->data == GINT_TO_POINTER (2));
	elt = rspamd_min_heap_pop (heap);
	g_assert (elt == NULL);

	/* Push + push + remove + pop */
	elt = new_elt (2);
	elt->data = GINT_TO_POINTER (1);
	rspamd_min_heap_push (heap, elt);
	telt = elt;
	elt = new_elt (3);
	elt->data = GINT_TO_POINTER (2);
	rspamd_min_heap_push (heap, elt);
	rspamd_min_heap_remove_elt (heap, telt);
	elt = rspamd_min_heap_pop (heap);
	g_assert (elt->data == GINT_TO_POINTER (2));
	rspamd_min_heap_destroy (heap);

	/* Bulk test */
	heap = rspamd_min_heap_create (32);

	for (i = 100; i > 0; i --) {
		elt = new_elt (i - 1);
		rspamd_min_heap_push (heap, elt);
	}

	for (i = 0; i < 100; i ++) {
		elt = rspamd_min_heap_pop (heap);
		g_assert (elt->pri == i);
	}

	rspamd_min_heap_destroy (heap);

	/* Fuzz test */
	heap = rspamd_min_heap_create (128);

	/* Add */
	for (i = 0; i < niter; i ++) {
		elt = new_elt (ottery_rand_uint32 () % G_MAXINT32 + 1);
		rspamd_min_heap_push (heap, elt);
	}

	/* Remove */
	for (i = 0; i < nrem; i ++) {
		elt = rspamd_min_heap_index (heap, ottery_rand_uint32 () % niter);
		rspamd_min_heap_remove_elt (heap, elt);
	}

	/* Update */
	for (i = 0; i < niter / 10; i ++) {
		elt = rspamd_min_heap_index (heap, ottery_rand_uint32 () % (niter - nrem));
		rspamd_min_heap_update_elt (heap, elt,
				ottery_rand_uint32 () % G_MAXINT32 + 1);
	}

	prev = 0;

	/* Pop and check invariant */
	for (i = 0; i < niter - nrem; i ++) {
		elt = rspamd_min_heap_pop (heap);

		if (prev != 0) {
			g_assert (elt->pri >= prev);
		}

		prev = elt->pri;
	}

	rspamd_min_heap_destroy (heap);

	/* Complexity test (should be O(n * logn) */
	for (i = 1; i <= G_N_ELEMENTS (t); i ++) {
		t[i - 1] = heap_nelts_test (0x1 << (i + 4));
	}

	for (i = 1; i <= G_N_ELEMENTS (t); i ++) {
		rspamd_printf ("Elements: %d, time: %.4f\n", 0x1 << (i + 4), t[i - 1]);
	}
}
