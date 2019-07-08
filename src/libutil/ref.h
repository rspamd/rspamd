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
#ifndef REF_H_
#define REF_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


/**
 * @file ref.h
 * A set of macros to handle refcounts
 */

typedef void (*ref_dtor_cb_t)(void *data);

typedef struct ref_entry_s {
	unsigned int refcount;
	ref_dtor_cb_t dtor;
} ref_entry_t;

#define REF_INIT(obj, dtor_cb) do {								\
	if ((obj) != NULL) {											\
	(obj)->ref.refcount = 0;										\
	(obj)->ref.dtor = (ref_dtor_cb_t)(dtor_cb);						\
	}																\
} while (0)

#define REF_INIT_RETAIN(obj, dtor_cb) do {							\
	if ((obj) != NULL) {											\
	(obj)->ref.refcount = 1;										\
	(obj)->ref.dtor = (ref_dtor_cb_t)(dtor_cb);						\
	}																\
} while (0)

#ifdef HAVE_ATOMIC_BUILTINS
#define REF_RETAIN_ATOMIC(obj) do {										\
	if ((obj) != NULL) {											\
    __atomic_add_fetch (&(obj)->ref.refcount, 1, __ATOMIC_RELEASE);	\
	}																\
} while (0)

#define REF_RELEASE_ATOMIC(obj) do {										\
	if ((obj) != NULL) {											\
	unsigned int _rc_priv = __atomic_sub_fetch (&(obj)->ref.refcount, 1, __ATOMIC_ACQ_REL); \
	if (_rc_priv == 0 && (obj)->ref.dtor) {								\
		(obj)->ref.dtor (obj);										\
	}																\
	}																\
} while (0)

#else
#define REF_RETAIN_ATOMIC REF_RETAIN
#define REF_RELEASE_ATOMIC REF_RELEASE_ATOMIC
#endif

#define REF_RETAIN(obj) do {										\
	if ((obj) != NULL) {											\
	(obj)->ref.refcount ++;											\
	}																\
} while (0)

#define REF_RELEASE(obj) do {										\
	if ((obj) != NULL) {											\
	if (--(obj)->ref.refcount == 0 && (obj)->ref.dtor) {			\
		(obj)->ref.dtor (obj);										\
	}																\
	}																\
} while (0)

#endif /* REF_H_ */
