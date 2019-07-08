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

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Binary minimal heap interface based on glib
 */

struct rspamd_min_heap_elt {
	gpointer data;
	guint pri;
	guint idx;
};

struct rspamd_min_heap;

/**
 * Creates min heap with the specified reserved size and compare function
 * @param reserved_size reserved size in elements
 * @return opaque minimal heap
 */
struct rspamd_min_heap *rspamd_min_heap_create (gsize reserved_size);

/**
 * Pushes an element to the heap. `pri` should be initialized to use this function,
 * `idx` is used internally by heap interface
 * @param heap heap structure
 * @param elt element to push
 */
void rspamd_min_heap_push (struct rspamd_min_heap *heap,
						   struct rspamd_min_heap_elt *elt);

/**
 * Pops the minimum element from the heap and reorder the queue
 * @param heap heap structure
 * @return minimum element
 */
struct rspamd_min_heap_elt *rspamd_min_heap_pop (struct rspamd_min_heap *heap);

/**
 * Updates priority for the element. It must be in queue (so `idx` should be sane)
 * @param heap heap structure
 * @param elt element to update
 * @param npri new priority
 */
void rspamd_min_heap_update_elt (struct rspamd_min_heap *heap,
								 struct rspamd_min_heap_elt *elt, guint npri);


/**
 * Removes element from the heap
 * @param heap
 * @param elt
 */
void rspamd_min_heap_remove_elt (struct rspamd_min_heap *heap,
								 struct rspamd_min_heap_elt *elt);

/**
 * Destroys heap (elements are not destroyed themselves)
 * @param heap
 */
void rspamd_min_heap_destroy (struct rspamd_min_heap *heap);

/**
 * Returns element from the heap with the specified index
 * @param heap
 * @param idx
 * @return
 */
struct rspamd_min_heap_elt *rspamd_min_heap_index (struct rspamd_min_heap *heap,
												   guint idx);

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBUTIL_HEAP_H_ */
