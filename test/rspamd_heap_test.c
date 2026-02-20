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

static const unsigned int niter = 100500;
static const unsigned int nrem = 100;

struct test_heap_elt {
	unsigned int pri;
	unsigned int idx;
	gpointer data;
};

RSPAMD_HEAP_DECLARE(test_heap, struct test_heap_elt);

static inline struct test_heap_elt
new_elt(unsigned int pri)
{
	struct test_heap_elt elt = {
		.pri = pri,
		.idx = 0,
		.data = NULL};

	return elt;
}

static double
heap_nelts_test(unsigned int nelts)
{
	test_heap_t heap;
	struct test_heap_elt *elts;
	double t1, t2;
	unsigned int i;

	rspamd_heap_init(test_heap, &heap);

	/* Preallocate all elts */
	elts = g_slice_alloc(sizeof(*elts) * nelts);

	for (i = 0; i < nelts; i++) {
		elts[i].pri = ottery_rand_uint32() % G_MAXINT32 + 1;
		elts[i].idx = 0;
	}

	t1 = rspamd_get_virtual_ticks();
	for (i = 0; i < nelts; i++) {
		rspamd_heap_push_safe(test_heap, &heap, &elts[i], cleanup);
	}

	for (i = 0; i < nelts; i++) {
		(void) rspamd_heap_pop(test_heap, &heap);
	}
	t2 = rspamd_get_virtual_ticks();

	g_slice_free1(sizeof(*elts) * nelts, elts);
	rspamd_heap_destroy(test_heap, &heap);

	return (t2 - t1);

cleanup:
	g_slice_free1(sizeof(*elts) * nelts, elts);
	rspamd_heap_destroy(test_heap, &heap);
	return 0;
}

void rspamd_heap_test_func(void)
{
	test_heap_t heap;
	struct test_heap_elt elt1, elt2, elt3;
	struct test_heap_elt *elt;
	unsigned int i;
	unsigned int prev;
	double t[16];

	/* Push + update */
	rspamd_heap_init(test_heap, &heap);

	elt1 = new_elt(2);
	elt1.data = GINT_TO_POINTER(1);
	rspamd_heap_push_safe(test_heap, &heap, &elt1, fail);

	elt2 = new_elt(3);
	elt2.data = GINT_TO_POINTER(2);
	rspamd_heap_push_safe(test_heap, &heap, &elt2, fail);

	elt3 = new_elt(4);
	elt3.data = GINT_TO_POINTER(3);
	rspamd_heap_push_safe(test_heap, &heap, &elt3, fail);

	/* Find elt3 in heap (it should be at some index with data==3) */
	struct test_heap_elt *elt_to_update = NULL;
	for (i = 0; i < rspamd_heap_size(test_heap, &heap); i++) {
		elt = rspamd_heap_index(test_heap, &heap, i);
		if (elt->data == GINT_TO_POINTER(3)) {
			elt_to_update = elt;
			break;
		}
	}
	g_assert(elt_to_update != NULL);
	rspamd_heap_update(test_heap, &heap, elt_to_update, 0);
	elt = rspamd_heap_pop(test_heap, &heap);
	g_assert(elt->data == GINT_TO_POINTER(3));

	rspamd_heap_destroy(test_heap, &heap);

	/* Push + remove */
	rspamd_heap_init(test_heap, &heap);

	elt1 = new_elt(2);
	elt1.data = GINT_TO_POINTER(1);
	rspamd_heap_push_safe(test_heap, &heap, &elt1, fail);

	/* Find and remove the element */
	for (i = 0; i < rspamd_heap_size(test_heap, &heap); i++) {
		elt = rspamd_heap_index(test_heap, &heap, i);
		if (elt->data == GINT_TO_POINTER(1)) {
			rspamd_heap_remove(test_heap, &heap, elt);
			break;
		}
	}
	elt = rspamd_heap_pop(test_heap, &heap);
	g_assert(elt == NULL);

	rspamd_heap_destroy(test_heap, &heap);

	/* Push + pop */
	rspamd_heap_init(test_heap, &heap);

	for (i = 0; i < niter; i++) {
		struct test_heap_elt tmp = new_elt(ottery_rand_uint32() % G_MAXINT32 + 1);
		tmp.data = GINT_TO_POINTER(i);
		rspamd_heap_push_safe(test_heap, &heap, &tmp, fail);
	}

	prev = 0;
	for (i = 0; i < niter; i++) {
		elt = rspamd_heap_pop(test_heap, &heap);
		g_assert(elt != NULL);

		if (prev != 0) {
			g_assert(prev <= elt->pri);
		}

		prev = elt->pri;
	}

	elt = rspamd_heap_pop(test_heap, &heap);
	g_assert(elt == NULL);

	rspamd_heap_destroy(test_heap, &heap);

	/* Push + pop + push */
	rspamd_heap_init(test_heap, &heap);

	for (i = 0; i < niter; i++) {
		struct test_heap_elt tmp = new_elt(ottery_rand_uint32() % G_MAXINT32 + 1);
		rspamd_heap_push_safe(test_heap, &heap, &tmp, fail);
	}

	for (i = 0; i < nrem; i++) {
		(void) rspamd_heap_pop(test_heap, &heap);
	}

	for (i = 0; i < nrem; i++) {
		struct test_heap_elt tmp = new_elt(ottery_rand_uint32() % G_MAXINT32 + 1);
		rspamd_heap_push_safe(test_heap, &heap, &tmp, fail);
	}

	prev = 0;
	for (i = 0; i < niter; i++) {
		elt = rspamd_heap_pop(test_heap, &heap);
		g_assert(elt != NULL);

		if (prev != 0) {
			g_assert(prev <= elt->pri);
		}

		prev = elt->pri;
	}

	elt = rspamd_heap_pop(test_heap, &heap);
	g_assert(elt == NULL);

	rspamd_heap_destroy(test_heap, &heap);

	for (i = 0; i < G_N_ELEMENTS(t); i++) {
		t[i] = heap_nelts_test(1 << (i + 4));
	}

	msg_info("heap push/pop performance (%d elts)", 1 << 4);

	for (i = 0; i < G_N_ELEMENTS(t); i++) {
		msg_info("%d elts: %.4f", 1 << (i + 4), t[i]);
	}

	return;

fail:
	g_assert_not_reached();
}
