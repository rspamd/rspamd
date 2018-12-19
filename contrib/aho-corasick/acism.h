/*
** Copyright (C) 2009-2014 Mischa Sandberg <mischasan@gmail.com>
** Copyright (C) 2015 Vsevolod Stakhov <vsevolod@highsecure.ru>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU Lesser General Public License as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU Lesser General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU Lesser General Public License for more details.
**
** You should have received a copy of the GNU Lesser General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef ACISM_H
#define ACISM_H

#include "config.h"
// "acism" uses MEMREF {ptr,len} bytevec structs for "string" args,
// rather than NUL-terminated "C" strings.

typedef struct ac_trie_pat_s { char const *ptr; size_t len; } ac_trie_pat_t;

typedef struct acism ac_trie_t;
typedef struct acism ACISM;
typedef struct ac_trie_pat_s MEMREF;

ac_trie_t* acism_create(ac_trie_pat_t const *strv, int nstrs);
void   acism_destroy(ac_trie_t*);

// For each match, acism_scan calls its ACISM_ACTION fn,
//  giving it the strv[] index of the matched string,
//  and the text[] offset of the byte PAST the end of the string.
// If ACISM_ACTION returns 0, search continues; otherwise,
//  acism_more returns that nonzero value immediately.

typedef int (ACISM_ACTION)(int strnum, int textpos, void *context);

// If sequential blocks of (text) are passed to repeated acism_more calls,
//  then search continues where the previous acism_more left off --
//  string matches can cross block boundaries.
// *state should initially be (0).

int acism_lookup(ac_trie_t const *psp, const char *text, size_t len,
           ACISM_ACTION *cb, void *context, int *statep, bool caseless);

#endif//ACISM_H
