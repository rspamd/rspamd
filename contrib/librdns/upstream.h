/*
 * Copyright (c) 2014, Vsevolod Stakhov
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
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

#ifndef UPSTREAM_H_
#define UPSTREAM_H_

#include <time.h>
#include <stdio.h>

/**
 * @file upstream.h
 * The basic macros to define upstream objects
 */

#ifndef upstream_fatal
#define upstream_fatal(msg) do { perror (msg); exit (-1); } while (0)
#endif

#ifndef upstream_malloc
#define upstream_malloc(size) malloc (size)
#endif

#ifndef upstream_free
#define upstream_free(size, ptr) free (ptr)
#endif

struct upstream_entry_s;
struct upstream_common_data {
	void **upstreams;
	unsigned int allocated_nelts;
	unsigned int nelts;
	unsigned int alive;
};

typedef struct upstream_entry_s {
	unsigned short errors;						/**< errors for this upstream 	*/
	unsigned short dead;
	unsigned short priority;
	unsigned short weight;
	time_t time;								/**< time of marking 			*/
	void *parent;								/**< parent object				*/
	struct upstream_common_data *common;		/**< common data				*/
	void *next;									/**< link to the next			*/
} upstream_entry_t;

/*
 * Here we define some reasonable defaults:
 * if an upstream has more than `UPSTREAM_MAX_ERRORS` in the period of time
 * of `UPSTREAM_ERROR_TIME` then we shut it down for `UPSTREAM_REVIVE_TIME`.
 * In this particular case times are 10 seconds for 10 errors and revive in
 * 30 seconds.
 */
#ifndef UPSTREAM_REVIVE_TIME
#define UPSTREAM_REVIVE_TIME 30
#endif
#ifndef UPSTREAM_ERROR_TIME
#define UPSTREAM_ERROR_TIME 10
#endif
#ifndef UPSTREAM_MAX_ERRORS
#define UPSTREAM_MAX_ERRORS 10
#endif

#define UPSTREAM_FAIL(u, now) do {											\
    if ((u)->up.time != 0) {												\
      if ((now) - (u)->up.time >= UPSTREAM_ERROR_TIME) {					\
        if ((u)->up.errors >= UPSTREAM_MAX_ERRORS) {						\
          (u)->up.dead = 1;													\
          (u)->up.time = now;												\
          (u)->up.common->alive --;											\
        }																	\
        else {																\
          (u)->up.errors = 1;												\
          (u)->up.time = (now);												\
        }																	\
      }																		\
      else {																\
        (u)->up.errors ++;													\
      }																		\
    }																		\
    else {																	\
      (u)->up.errors ++;													\
      (u)->up.time = (now);													\
    }																		\
} while (0)

#define UPSTREAM_OK(u) do {													\
    (u)->up.errors = 0;														\
    (u)->up.time = 0;														\
} while (0)

#define UPSTREAM_ADD(head, u, priority) do {								\
    if (head == NULL) {														\
      struct upstream_common_data *cd;										\
      cd = upstream_malloc (sizeof (struct upstream_common_data));			\
      if (cd == NULL) {														\
        upstream_fatal ("malloc failed");									\
      }																		\
      cd->upstreams = upstream_malloc (sizeof (void *) * 8);				\
      if (cd == NULL) {														\
        upstream_fatal ("malloc failed");									\
      }																		\
      cd->allocated_nelts = 8;												\
      cd->nelts = 1;														\
      cd->alive = 1;														\
      cd->upstreams[0] = (u);												\
      (u)->up.common = cd;													\
    }																		\
    else {																	\
      struct upstream_common_data *cd = (head)->up.common;					\
      (u)->up.common = cd;													\
      if (cd->nelts == cd->allocated_nelts) {								\
        void **nup;															\
        nup = upstream_malloc (sizeof (void *) * cd->nelts * 2);			\
        if (nup == NULL) {													\
          upstream_fatal ("malloc failed");									\
        }																	\
        memcpy (nup, cd->upstreams, cd->nelts * sizeof (void *));			\
        upstream_free (cd->nelts * sizeof (void *), cd->upstreams);		\
        cd->upstreams = nup;												\
        cd->allocated_nelts *= 2;											\
      }																		\
      cd->upstreams[cd->nelts++] = (u);										\
      cd->alive ++;															\
    }																		\
    (u)->up.next = (head);													\
    (head) = (u);															\
    if (priority > 0) {														\
      (u)->up.priority = (u)->up.weight = (priority);						\
    }																		\
    else {																	\
      (u)->up.priority = (u)->up.weight = 65535;							\
    }																		\
    (u)->up.time = 0;														\
    (u)->up.errors = 0;														\
    (u)->up.dead = 0;														\
    (u)->up.parent = (u);													\
} while (0)

#define UPSTREAM_DEL(head, u) do {											\
    if (head != NULL) {														\
        struct upstream_common_data *cd = (head)->up.common;				\
        if ((u)->up.next != NULL) {											\
            (head) = (u)->up.next;											\
            cd->nelts --;													\
            cd->alive --;													\
        }																	\
        else {																\
            upstream_free (cd->allocated_nelts * sizeof (void *), 			\
                cd->upstreams);												\
            upstream_free (sizeof (struct upstream_common_data), cd);		\
            (head) = NULL;													\
        }																	\
    }																		\
} while (0)

#define UPSTREAM_FOREACH(head, u) for ((u) = (head); (u) != NULL; (u) = (u)->up.next)
#define UPSTREAM_FOREACH_SAFE(head, u, tmp) 								\
    for ((u) = (head);														\
    (u) != NULL && ((tmp = (u)->up.next) || true);							\
    (u) = (tmp))

#define UPSTREAM_REVIVE_ALL(head) do {										\
    __typeof(head) elt = (head);											\
    while (elt != NULL) {													\
      elt->up.dead = 0;														\
      elt->up.errors = 0;													\
      elt->up.time = 0;														\
      elt = elt->up.next;													\
    }																		\
    (head)->up.common->alive = (head)->up.common->nelts;					\
} while (0)

#define UPSTREAM_RESCAN(head, now) do {										\
    __typeof(head) elt = (head);											\
    if ((head)->up.common->alive == 0) {									\
      UPSTREAM_REVIVE_ALL((head));											\
    }																		\
    else {																	\
      while (elt != NULL) {													\
        if (elt->up.dead) {													\
          if ((now) - elt->up.time >= UPSTREAM_REVIVE_TIME) {				\
            elt->up.dead = 0;												\
            elt->up.errors = 0;												\
            elt->up.weight = elt->up.priority;								\
            (head)->up.common->alive ++;									\
          }																	\
        }																	\
        else {																\
          if ((now) - elt->up.time >= UPSTREAM_ERROR_TIME &&				\
              elt->up.errors >= UPSTREAM_MAX_ERRORS) {						\
            elt->up.dead = 1;												\
            elt->up.time = now;												\
            (head)->up.common->alive --;									\
          }																	\
        }																	\
        elt = elt->up.next;													\
      }																		\
    }																		\
} while (0)

#define UPSTREAM_SELECT_ROUND_ROBIN(head, selected) do {					\
    __typeof(head) elt = (head);											\
    (selected) = NULL;														\
    int alive = 0;															\
    unsigned max_weight = 0;												\
    if ((head)->up.common->alive == 0){ 									\
      UPSTREAM_REVIVE_ALL(head);											\
    }																		\
    while (elt != NULL) {													\
      if (!elt->up.dead) {													\
        if (elt->up.weight > max_weight) {									\
          max_weight = elt->up.weight;										\
          (selected) = elt;													\
        }																	\
        alive ++;															\
      }																		\
      elt = elt->up.next;													\
    }																		\
    if (max_weight == 0) {													\
      elt = (head);															\
      while (elt != NULL) {													\
        elt->up.weight = elt->up.priority;									\
        if (!elt->up.dead) {												\
          if (elt->up.priority > max_weight) {								\
            max_weight = elt->up.priority;									\
            (selected) = elt;												\
          }																	\
        }																	\
        elt = elt->up.next;													\
      }																		\
    }																		\
    (selected)->up.weight --;												\
} while (0)

#endif /* UPSTREAM_H_ */
