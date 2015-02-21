/* Copyright (c) 2014, Vsevolod Stakhov
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
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef REF_H_
#define REF_H_

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
	(obj)->ref.refcount = 0;										\
	(obj)->ref.dtor = (ref_dtor_cb_t)(dtor_cb);						\
} while (0)

#define REF_INIT_RETAIN(obj, dtor_cb) do {							\
	(obj)->ref.refcount = 1;										\
	(obj)->ref.dtor = (ref_dtor_cb_t)(dtor_cb);						\
} while (0)

#ifdef HAVE_ATOMIC_BUILTINS
#define REF_RETAIN(obj) do {										\
    __sync_add_and_fetch (&(obj)->ref.refcount, 1);					\
} while (0)

#define REF_RELEASE(obj) do {										\
	unsigned int rc = __sync_sub_and_fetch (&(obj)->ref.refcount, 1); \
	if (rc == 0 && (obj)->ref.dtor) {								\
		(obj)->ref.dtor (obj);										\
	}																\
} while (0)
#else
#define REF_RETAIN(obj) do {										\
	(obj)->ref.refcount ++;											\
} while (0)

#define REF_RELEASE(obj) do {										\
	if (--(obj)->ref.refcount == 0 && (obj)->ref.dtor) {			\
		(obj)->ref.dtor (obj);										\
	}																\
} while (0)
#endif

#endif /* REF_H_ */
