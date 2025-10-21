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
#ifndef SRC_LIBUTIL_HEAP_H_
#define SRC_LIBUTIL_HEAP_H_

#include "config.h"
#include "contrib/libucl/kvec.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Fully intrusive binary min-heap implementation using kvec
 *
 * Elements are stored directly in the array (not pointers), providing
 * excellent cache locality and eliminating pointer indirection overhead.
 *
 * Requirements for element type:
 * - Must have 'unsigned int pri' field for priority
 * - Must have 'unsigned int idx' field for heap index (managed internally)
 *
 * If you need a heap of large objects, embed a pointer in your element type:
 *
 * struct my_heap_entry {
 *     unsigned int pri;
 *     unsigned int idx;
 *     struct large_object *data;  // pointer to actual data
 * };
 *
 * Example usage:
 *
 * struct my_element {
 *     unsigned int pri;  // priority (lower = higher priority)
 *     unsigned int idx;  // heap index (managed by heap)
 *     int data;          // your data stored directly
 * };
 *
 * RSPAMD_HEAP_DECLARE(my_heap, struct my_element);
 *
 * struct my_heap heap;
 * rspamd_heap_init(my_heap, &heap);
 *
 * struct my_element elt = {.pri = 10, .data = 42};
 * rspamd_heap_push_safe(my_heap, &heap, &elt, error);
 *
 * struct my_element *min = rspamd_heap_pop(my_heap, &heap);
 * rspamd_heap_destroy(my_heap, &heap);
 */

/**
 * Declare heap type
 * @param name heap type name
 * @param elt_type element type (must have 'pri' and 'idx' fields)
 */
#define RSPAMD_HEAP_DECLARE(name, elt_type) \
	typedef kvec_t(elt_type) name##_t

/**
 * Initialize heap
 */
#define rspamd_heap_init(name, heap) kv_init(*(heap))

/**
 * Destroy heap (does not free elements as they're stored inline)
 */
#define rspamd_heap_destroy(name, heap) kv_destroy(*(heap))

/**
 * Get heap size
 */
#define rspamd_heap_size(name, heap) kv_size(*(heap))

/**
 * Get pointer to element at index (0-based)
 */
#define rspamd_heap_index(name, heap, i) (&kv_A(*(heap), i))

/**
 * Swim element up to maintain heap invariant
 */
#define rspamd_heap_swim(name, heap, elt)                    \
	do {                                                     \
		unsigned int cur_idx = (elt)->idx;                   \
		while (cur_idx > 0) {                                \
			unsigned int parent_idx = (cur_idx - 1) / 2;     \
			typeof(elt) cur = &kv_A(*(heap), cur_idx);       \
			typeof(elt) parent = &kv_A(*(heap), parent_idx); \
			if (parent->pri > cur->pri) {                    \
				/* Swap elements directly */                 \
				typeof(*elt) tmp = *parent;                  \
				*parent = *cur;                              \
				*cur = tmp;                                  \
				/* Update indices */                         \
				parent->idx = parent_idx;                    \
				cur->idx = cur_idx;                          \
				/* Move up */                                \
				cur_idx = parent_idx;                        \
			}                                                \
			else {                                           \
				break;                                       \
			}                                                \
		}                                                    \
	} while (0)

/**
 * Sink element down to maintain heap invariant
 */
#define rspamd_heap_sink(name, heap, elt)                            \
	do {                                                             \
		unsigned int size = kv_size(*(heap));                        \
		unsigned int cur_idx = (elt)->idx;                           \
		while (cur_idx * 2 + 1 < size) {                             \
			unsigned int left_idx = cur_idx * 2 + 1;                 \
			unsigned int right_idx = cur_idx * 2 + 2;                \
			unsigned int min_idx = left_idx;                         \
			typeof(elt) cur = &kv_A(*(heap), cur_idx);               \
			typeof(elt) min_child = &kv_A(*(heap), left_idx);        \
			if (right_idx < size) {                                  \
				typeof(elt) right_child = &kv_A(*(heap), right_idx); \
				if (right_child->pri < min_child->pri) {             \
					min_idx = right_idx;                             \
					min_child = right_child;                         \
				}                                                    \
			}                                                        \
			if (cur->pri > min_child->pri) {                         \
				/* Swap elements directly */                         \
				typeof(*elt) tmp = *min_child;                       \
				*min_child = *cur;                                   \
				*cur = tmp;                                          \
				/* Update indices */                                 \
				cur->idx = cur_idx;                                  \
				min_child->idx = min_idx;                            \
				/* Move down */                                      \
				cur_idx = min_idx;                                   \
			}                                                        \
			else {                                                   \
				break;                                               \
			}                                                        \
		}                                                            \
	} while (0)

/**
 * Allocate slot in heap and return pointer to it (zero-initialized)
 * User fills the slot, then must call rspamd_heap_swim to restore heap property
 * Returns NULL on allocation failure
 */
#define rspamd_heap_push_slot(name, heap)                                           \
	({                                                                              \
		typeof(&kv_A(*(heap), 0)) slot = NULL;                                      \
		kv_push(typeof(kv_A(*(heap), 0)), *(heap), (typeof(kv_A(*(heap), 0))) {0}); \
		if (kv_size(*(heap)) > 0) {                                                 \
			slot = &kv_A(*(heap), kv_size(*(heap)) - 1);                            \
			slot->idx = kv_size(*(heap)) - 1;                                       \
		}                                                                           \
		slot;                                                                       \
	})

/**
 * Push element to heap (safe version with error handling)
 * Element is copied into the heap array.
 */
#define rspamd_heap_push_safe(name, heap, elt, error_label)                 \
	do {                                                                    \
		kv_push_safe(typeof(*(elt)), *(heap), *(elt), error_label);         \
		kv_A(*(heap), kv_size(*(heap)) - 1).idx = kv_size(*(heap)) - 1;     \
		rspamd_heap_swim(name, heap, &kv_A(*(heap), kv_size(*(heap)) - 1)); \
	} while (0)

/**
 * Pop minimum element from heap
 * Returns pointer to last element in the array (which now holds the popped value)
 * Valid until next heap modification.
 */
#define rspamd_heap_pop(name, heap)                                     \
	({                                                                  \
		typeof(&kv_A(*(heap), 0)) result = NULL;                        \
		if (kv_size(*(heap)) > 0) {                                     \
			if (kv_size(*(heap)) > 1) {                                 \
				/* Swap min to end, then sink the new root */           \
				typeof(kv_A(*(heap), 0)) tmp = kv_A(*(heap), 0);        \
				kv_A(*(heap), 0) = kv_A(*(heap), kv_size(*(heap)) - 1); \
				kv_A(*(heap), kv_size(*(heap)) - 1) = tmp;              \
				kv_size(*(heap))--;                                     \
				kv_A(*(heap), 0).idx = 0;                               \
				rspamd_heap_sink(name, heap, &kv_A(*(heap), 0));        \
				/* Return pointer to element that was moved to end */   \
				result = &kv_A(*(heap), kv_size(*(heap)));              \
			}                                                           \
			else {                                                      \
				/* Single element - return it and decrement */          \
				result = &kv_A(*(heap), 0);                             \
				kv_size(*(heap))--;                                     \
			}                                                           \
		}                                                               \
		result;                                                         \
	})

/**
 * Update element priority (element must be in heap)
 * Pass pointer to element obtained from rspamd_heap_index()
 */
#define rspamd_heap_update(name, heap, elt, new_pri) \
	do {                                             \
		unsigned int old_pri = (elt)->pri;           \
		(elt)->pri = (new_pri);                      \
		if ((new_pri) < old_pri) {                   \
			rspamd_heap_swim(name, heap, elt);       \
		}                                            \
		else if ((new_pri) > old_pri) {              \
			rspamd_heap_sink(name, heap, elt);       \
		}                                            \
	} while (0)

/**
 * Remove element from heap (element must be in heap)
 * Pass pointer to element obtained from rspamd_heap_index()
 */
#define rspamd_heap_remove(name, heap, elt)                                      \
	do {                                                                         \
		if ((elt)->idx < kv_size(*(heap))) {                                     \
			if ((elt)->idx < kv_size(*(heap)) - 1) {                             \
				kv_A(*(heap), (elt)->idx) = kv_A(*(heap), kv_size(*(heap)) - 1); \
				kv_size(*(heap))--;                                              \
				kv_A(*(heap), (elt)->idx).idx = (elt)->idx;                      \
				typeof(elt) moved = &kv_A(*(heap), (elt)->idx);                  \
				/* Need to restore heap property */                              \
				if (moved->pri < (elt)->pri) {                                   \
					rspamd_heap_swim(name, heap, moved);                         \
				}                                                                \
				else {                                                           \
					rspamd_heap_sink(name, heap, moved);                         \
				}                                                                \
			}                                                                    \
			else {                                                               \
				kv_size(*(heap))--;                                              \
			}                                                                    \
		}                                                                        \
	} while (0)

#ifdef __cplusplus
}
#endif

#endif /* SRC_LIBUTIL_HEAP_H_ */
