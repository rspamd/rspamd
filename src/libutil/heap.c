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
#include "libutil/heap.h"

struct rspamd_min_heap {
	GPtrArray *ar;
};

#define __SWAP(a, b) do { \
	__typeof__(a) _a = (a); \
	__typeof__(b) _b = (b); \
	a = _b; \
	b = _a; \
} while (0)
#define heap_swap(h,e1,e2) do { \
	__SWAP((h)->ar->pdata[(e1)->idx - 1], (h)->ar->pdata[(e2)->idx - 1]); \
	__SWAP((e1)->idx, (e2)->idx); \
} while (0)

#define min_elt(e1, e2) ((e1)->pri <= (e2)->pri ? (e1) : (e2))

/*
 * Swims element added (or changed) to preserve heap's invariant
 */
static void
rspamd_min_heap_swim (struct rspamd_min_heap *heap,
		struct rspamd_min_heap_elt *elt)
{
	struct rspamd_min_heap_elt *parent;

	while (elt->idx > 1) {
		parent = g_ptr_array_index (heap->ar, elt->idx / 2 - 1);

		if (parent->pri > elt->pri) {
			heap_swap (heap, elt, parent);
		}
		else {
			break;
		}
	}
}

/*
 * Sinks the element popped (or changed) to preserve heap's invariant
 */
static void
rspamd_min_heap_sink (struct rspamd_min_heap *heap,
		struct rspamd_min_heap_elt *elt)
{
	struct rspamd_min_heap_elt *c1, *c2, *m;

	while (elt->idx * 2 < heap->ar->len) {
		c1 = g_ptr_array_index (heap->ar, elt->idx * 2 - 1);
		c2 = g_ptr_array_index (heap->ar, elt->idx * 2);
		m = min_elt (c1, c2);

		if (elt->pri > m->pri) {
			heap_swap (heap, elt, m);
		}
		else {
			break;
		}
	}

	if (elt->idx * 2 - 1 < heap->ar->len) {
		m = g_ptr_array_index (heap->ar, elt->idx * 2 - 1);
		if (elt->pri > m->pri) {
			heap_swap (heap, elt, m);
		}
	}
}

struct rspamd_min_heap *
rspamd_min_heap_create (gsize reserved_size)
{
	struct rspamd_min_heap *heap;

	heap = g_malloc (sizeof (*heap));
	heap->ar = g_ptr_array_sized_new (reserved_size);

	return heap;
}

void
rspamd_min_heap_push (struct rspamd_min_heap *heap,
		struct rspamd_min_heap_elt *elt)
{
	g_assert (heap != NULL);
	g_assert (elt != NULL);

	/* Add to the end */
	elt->idx = heap->ar->len + 1;
	g_ptr_array_add (heap->ar, elt);
	/* Now swim it up */
	rspamd_min_heap_swim (heap, elt);
}

struct rspamd_min_heap_elt*
rspamd_min_heap_pop (struct rspamd_min_heap *heap)
{
	struct rspamd_min_heap_elt *elt, *last;

	g_assert (heap != NULL);

	if (heap->ar->len == 0) {
		return NULL;
	}

	elt = g_ptr_array_index (heap->ar, 0);
	last = g_ptr_array_index (heap->ar, heap->ar->len - 1);

	if (elt != last) {
		/* Now replace elt with the last element and sink it if needed */
		heap_swap (heap, elt, last);
		g_ptr_array_remove_index_fast (heap->ar, heap->ar->len - 1);
		rspamd_min_heap_sink (heap, last);
	}
	else {
		g_ptr_array_remove_index_fast (heap->ar, heap->ar->len - 1);
	}


	return elt;
}

void
rspamd_min_heap_update_elt (struct rspamd_min_heap *heap,
		struct rspamd_min_heap_elt *elt, guint npri)
{
	guint oldpri;

	g_assert (heap != NULL);
	g_assert (elt->idx > 0 && elt->idx <= heap->ar->len);

	oldpri = elt->pri;
	elt->pri = npri;

	if (npri > oldpri) {
		/* We might need to sink */
		rspamd_min_heap_sink (heap, elt);
	}
	else if (npri < oldpri) {
		/* We might need to swim */
		rspamd_min_heap_swim (heap, elt);
	}
}

void
rspamd_min_heap_remove_elt (struct rspamd_min_heap *heap,
		struct rspamd_min_heap_elt *elt)
{
	struct rspamd_min_heap_elt *first;

	g_assert (heap != NULL);
	g_assert (elt->idx > 0 && elt->idx <= heap->ar->len);

	first = g_ptr_array_index (heap->ar, 0);

	if (elt != first) {
		elt->pri = first->pri - 1;
		rspamd_min_heap_swim (heap, elt);
	}

	/* Now the desired element is on the top of queue */
	(void)rspamd_min_heap_pop (heap);
}

void
rspamd_min_heap_destroy (struct rspamd_min_heap *heap)
{
	if (heap) {
		g_ptr_array_free (heap->ar, TRUE);
		g_free (heap);
	}
}

struct rspamd_min_heap_elt*
rspamd_min_heap_index (struct rspamd_min_heap *heap, guint idx)
{
	g_assert (heap != NULL);
	g_assert (idx < heap->ar->len);

	return g_ptr_array_index (heap->ar, idx);
}
