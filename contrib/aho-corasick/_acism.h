/*
** Copyright (C) 2009-2014 Mischa Sandberg <mischasan@gmail.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU Lesser General Public License Version 3 as
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
#ifndef _ACISM_H
#define _ACISM_H

#include <stdint.h>
#include <stdlib.h> // malloc
#include <string.h> // memcpy

typedef int (*qsort_cmp)(const void *, const void *);

// "Width" specifier for different plats
#if __LONG_MAX__ == 9223372036854775807LL
#   ifdef __APPLE__
#       define F64  "ll"
#   else
#       define F64  "l"
#   endif
#elif __LONG_MAX__ == 2147483647L || defined(_LONG_LONG) || defined(__sun) // AIX 6.1 ...
#   define F64      "ll"
#else
//XXX Assuming F64 is "ll" for VS
#   define F64      "ll"
#endif

#ifndef ACISM_SIZE
#   define ACISM_SIZE 4
#endif

#if ACISM_SIZE == 8
typedef uint64_t TRAN, STATE, STRNO;
#   define SYM_BITS 9U
#   define SYM_MASK 511
#   define FNO      F64
#else
typedef uint32_t TRAN, STATE, STRNO;
#   define SYM_BITS psp->sym_bits
#   define SYM_MASK psp->sym_mask
#   define FNO
#endif

typedef uint16_t  SYMBOL;
typedef unsigned _SYMBOL; // An efficient stacklocal SYMBOL

#define BACK ((SYMBOL)0)
#define ROOT ((STATE) 0)

// MATCH and SUFFIX are the top 2 bits of a TRAN:
enum {
    IS_MATCH  = (TRAN)1 << (8*sizeof(TRAN) - 1),
    IS_SUFFIX = (TRAN)1 << (8*sizeof(TRAN) - 2),
    T_FLAGS   = IS_MATCH | IS_SUFFIX
};

typedef struct { STATE state; STRNO strno; } STRASH;

struct acism {
    TRAN*   tranv;
    STRASH* hashv;
    unsigned flags;
#   define IS_MMAP 1

#if ACISM_SIZE < 8
    TRAN sym_mask;
    unsigned sym_bits;
#endif
    unsigned hash_mod; // search hashv starting at (state + sym) % hash_mod.
    unsigned hash_size; // #(hashv): hash_mod plus the overflows past [hash_mod-1]
    unsigned tran_size; // #(tranv)
    unsigned nsyms, nchars, nstrs, maxlen;
    SYMBOL symv[256];
};

#include "acism.h"

// p_size: size of tranv + hashv
static inline size_t p_size(ACISM const *psp)
{ return psp->hash_size * sizeof*psp->hashv
         + psp->tran_size * sizeof*psp->tranv; }

static inline unsigned  p_hash(ACISM const *psp, STATE s)
{ return s * 107 % psp->hash_mod; }

static inline void set_tranv(ACISM *psp, void *mem)
{ psp->hashv = (STRASH*)&(psp->tranv = (TRAN*)mem)[psp->tran_size]; }

// TRAN accessors. For ACISM_SIZE=8, SYM_{BITS,MASK} do not use psp.

static inline TRAN      p_tran(ACISM const *psp, STATE s, _SYMBOL sym)
{ return psp->tranv[s + sym] ^ sym; }

static inline _SYMBOL t_sym(ACISM const *psp, TRAN t)    { (void)psp; return t & SYM_MASK; }
static inline STATE   t_next(ACISM const *psp, TRAN t)   { (void)psp; return (t & ~T_FLAGS) >> SYM_BITS; }
static inline int     t_isleaf(ACISM const *psp, TRAN t) { return t_next(psp, t) >= psp->tran_size; }
static inline int     t_strno(ACISM const *psp, TRAN t)  { return t_next(psp, t) - psp->tran_size; }
static inline _SYMBOL t_valid(ACISM const *psp, TRAN t)  { return !t_sym(psp, t); }

#endif//_ACISM_H