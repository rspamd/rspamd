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
#include "_acism.h"

typedef enum { BASE=2, USED=1 } USES;

typedef struct tnode {
    struct tnode *child, *next, *back;
    // nrefs was used in "prune_backlinks".
    //  It will be used again in "curtail".
    unsigned    nrefs;
    STATE       state;
    STRNO       match;
    SYMBOL      sym;
    char        is_suffix;      // "bool"
} TNODE;

//--------------|---------------------------------------------
// bitwid: 1+floor(log2(u))
static inline int bitwid(unsigned u)
{
    int ret = !!u;
    if (u & 0xFFFF0000) u >>= 16, ret += 16;
    if (u & 0x0000FF00) u >>= 8, ret += 8;
    if (u & 0x000000F0) u >>= 4, ret += 4;
    if (u & 0x0000000C) u >>= 2, ret += 2;
    if (u & 0x00000002) ret++;
    return ret;
}

static void   fill_symv(ACISM*, MEMREF const*, int ns);
static int    create_tree(TNODE*, SYMBOL const*symv, MEMREF const*strv, int nstrs);
static void   add_backlinks(TNODE*, TNODE**, TNODE**);
static int    interleave(TNODE*, int nnodes, int nsyms, TNODE**, TNODE**);
static void   fill_tranv(ACISM*, TNODE const*);
static void   fill_hashv(ACISM*, TNODE const*, int nn);

static TNODE* find_child(TNODE*, SYMBOL);

// (ns) is either a STATE, or a (STRNO + tran_size)
static inline void
set_tran(ACISM *psp, STATE s, SYMBOL sym, int match, int suffix, TRAN ns)
{
    psp->tranv[s + sym] = sym    | (match ? IS_MATCH : 0)
                          | (suffix ? IS_SUFFIX : 0)
                          | (ns << SYM_BITS);
}

// Track statistics for construction
#ifdef ACISM_STATS
typedef struct { long long val; const char *name; } PSSTAT;
extern PSSTAT psstat[];
# define NOTE(n) (psstat[__LINE__] = (PSSTAT) {n, #n})
# define HIT(id) (psstat[__LINE__].val++, psstat[__LINE__].name = id)
#else
# define NOTE(n) (void)0
# define HIT(id) (void)0
#endif //ACISM_STATS

//--------------|---------------------------------------------
ACISM*
acism_create(MEMREF const* strv, int nstrs)
{
    TNODE **v1 = NULL, **v2 = NULL;
    ACISM *psp = g_malloc0(sizeof*psp);

    fill_symv(psp, strv, nstrs);
    TNODE *troot = g_malloc0((psp->nchars + 1) * sizeof(*troot));

    int nnodes = create_tree(troot, psp->symv, strv, nstrs);
    NOTE(nnodes);

    // v1, v2: breadth-first work vectors for add_backlink and interleave.
    int i = (nstrs + 1) * sizeof(TNODE);
    add_backlinks(troot, v1 = g_malloc0(i), v2 = g_malloc0(i));

    int     nhash = 0;
    TNODE*  tp = troot + nnodes;
    while (--tp > troot)
        nhash += tp->match && tp->child;

    // Calculate each node's offset in tranv[]:
    psp->tran_size = interleave(troot, nnodes, psp->nsyms, v1, v2);
    if (bitwid(psp->tran_size + nstrs - 1) + SYM_BITS > sizeof(TRAN)*8 - 2)
        goto FAIL;

    if (nhash) {
        // Hash table is for match info of non-leaf nodes (only).
        // Set hash_size for p_size(psp):
        psp->hash_mod = nhash * 5 / 4 + 1;
        // Initially oversize the table for overflows without wraparound.
        psp->hash_size = psp->hash_mod + nhash;
    }

    set_tranv(psp, g_malloc0(p_size(psp) + sizeof(TRAN)));
    if (!psp->tranv) goto FAIL;
    fill_tranv(psp, troot);
    // The root state (0) must not look like a valid backref.
    // Any symbol value other than (0) in tranv[0] ensures that.
    psp->tranv[0] = 1;

    if (nhash) {
        fill_hashv(psp, troot, nnodes);
        // Adjust hash_size to include trailing overflows
        //  but trim trailing empty slots.
        psp->hash_size = psp->hash_mod;
        while ( psp->hashv[psp->hash_size].state)     ++psp->hash_size;
        while (!psp->hashv[psp->hash_size - 1].state) --psp->hash_size;
        set_tranv(psp, g_realloc(psp->tranv, p_size(psp)));
    }

    // Diagnostics/statistics only:
    psp->nstrs = nstrs;
    for (i = psp->maxlen = 0; i < nstrs; ++i)
        if (psp->maxlen < strv[i].len) psp->maxlen = strv[i].len;

    goto DONE;
    FAIL: acism_destroy(psp), psp = NULL;
    DONE: free(troot), free(v1), free(v2);
    return psp;
}

typedef struct { int freq, rank; } FRANK;
static int frcmp(FRANK*a, FRANK*b) { return a->freq - b->freq; }

static void
fill_symv(ACISM *psp, MEMREF const *strv, int nstrs)
{
    int i, j;
    FRANK frv[256];

    for (i = 0; i < 256; ++i) frv[i] = (FRANK){0,i};
    for (i = 0; i < nstrs; ++i)
        for (psp->nchars += j = strv[i].len; --j >= 0;)
            frv[(uint8_t)strv[i].ptr[j]].freq++;

    qsort(frv, 256, sizeof*frv, (qsort_cmp)frcmp);

    for (i = 256; --i >= 0 && frv[i].freq;)
        psp->symv[frv[i].rank] = ++psp->nsyms;
    ++psp->nsyms;

#if ACISM_SIZE < 8
    psp->sym_bits = bitwid(psp->nsyms);
    psp->sym_mask = ~((~0u) << psp->sym_bits);
#endif
}

static int
create_tree(TNODE *Tree, SYMBOL const *symv, MEMREF const *strv, int nstrs)
{
    int i, j;
    TNODE *nextp = Tree + 1;

    for (i = 0; i < nstrs; ++i) {
        TNODE *tp = Tree;

        for (j = 0; tp->child && j < (int)strv[i].len; ++j) {
            SYMBOL sym = symv[(uint8_t)strv[i].ptr[j]];

            if (sym < tp->child->sym) {
                // Prep to insert new node before tp->child
                nextp->next = tp->child;
                break;
            }

            tp = tp->child;
            while (tp->next && sym >= tp->next->sym)
                tp = tp->next;

            // Insert new sibling after tp
            if (sym > tp->sym) {
                nextp->next = tp->next;
                tp = tp->next = nextp++;
                tp->sym = sym;
                tp->back = Tree;
            }
        }

        for (; j < (int) strv[i].len; ++j) {
            tp = tp->child = nextp++;
            tp->sym = symv[(uint8_t)strv[i].ptr[j]];
            tp->back = Tree;
        }

        tp->match = i + 1; // Encode strno as nonzero
    }

    return nextp - Tree;
}

static void
add_backlinks(TNODE *troot, TNODE **v1, TNODE **v2)
{
    TNODE *tp, **tmp;

    for (tp = troot->child, tmp = v1; tp; tp = tp->next)
        *tmp++ = tp;
    *tmp = NULL;

    while (*v1) {
        TNODE **spp = v1, **dpp = v2, *srcp, *dstp;

        while ((srcp = *spp++)) {
            for (dstp = srcp->child; dstp; dstp = dstp->next) {
                TNODE *bp = NULL;
                if (dstp->child)
                    *dpp++ = dstp;

                // Go through the parent (srcp) node's backlink chain,
                //  looking for a useful backlink for the child (dstp).
                // If the parent (srcp) has a backlink to (tp),
                //  and (tp) has a child matching the transition sym
                //  for (srcp -> dstp), then it is a useful backlink
                //  for the child (dstp).
                // Note that backlinks do not point at the suffix match;
                //  they point at the PARENT of that match.

                for (tp = srcp->back; tp; tp = tp->back)
                    if ((bp = find_child(tp, dstp->sym)))
                        break;
                if (!bp)
                    bp = troot;

                dstp->back = dstp->child ? bp : tp ? tp : troot;
                dstp->back->nrefs++;
                dstp->is_suffix = bp->match || bp->is_suffix;
            }
        }
        *dpp = 0;
        tmp = v1; v1 = v2; v2 = tmp;
    }
}

static int
interleave(TNODE *troot, int nnodes, int nsyms, TNODE **v1, TNODE **v2)
{
    unsigned usev_size = nnodes + nsyms;
    char *usev = g_malloc0(usev_size * sizeof(*usev));
    STATE last_trans = 0, startv[257][2];
    TNODE *cp, **tmp;

    memset(startv, 0, nsyms * sizeof*startv);

    // Iterate through one level of the Tree at a time.
    //  That srsly improves locality (L1-cache use).

    v1[0] = troot, v1[1] = NULL;
    for (; *v1; tmp = v1, v1 = v2, v2 = tmp) {
        TNODE **srcp = v1, **dstp = v2, *tp;
        while ((tp = *srcp++)) {
            if (!tp->child) continue;

            HIT("nonleaf");
            if (tp->back == troot) tp->back = NULL; // simplify tests.
            cp = tp->child;

            STATE pos, *startp = &startv[cp->sym][!!tp->back];
            while ((cp = cp->next)) {
                STATE *newp = &startv[cp->sym][!!tp->back];
                if (*startp < *newp) startp = newp;
            }

            // If (tp) has a backref, we need a slot at offset 0
            //  that is free as a base AND to be used (filled in).
            char need = tp->back ? BASE|USED : BASE;
            for (pos = *startp;; ++pos) {
                if (usev[pos] & need) {
                    HIT("inner loop");
                    continue;
                }

                for (cp = tp->child; cp; cp = cp->next) {
                    HIT("child loop");
                    if (usev[pos + cp->sym] & USED) break;
                }

                // No child needs an in-use slot? We're done.
                if (!cp) break;
            }
            tp->state = pos;

            // Mark node's base and children as used:
            usev[pos] |= need;
            STATE last = 0; // Make compiler happy
            int nkids = 0;
            for (cp = tp->child; cp; *dstp++ = cp, cp = cp->next, ++nkids)
                usev[last = pos + cp->sym] |= USED;

            // This is a HEURISTIC for advancing search for other nodes
            *startp += (pos - *startp) / nkids;

            if (last_trans < last) {
                last_trans = last;
                if (last + nsyms >= usev_size) {
                    usev = g_realloc(usev, usev_size << 1);
                    memset(usev + usev_size, 0, usev_size);
                    usev_size <<= 1;
                }
            }
        }

        *dstp = NULL;
    }

    free(usev);
    return last_trans + 1;
}

static void
fill_hashv(ACISM *psp, TNODE const treev[], int nnodes)
{
    STRASH *sv = g_malloc0(psp->hash_mod * sizeof*sv), *sp = sv;
    int i;

    // First pass: insert without resolving collisions.
    for (i = 0; i < nnodes; ++i) {
        STATE base = treev[i].state;
        TNODE const *tp;
        for (tp = treev[i].child; tp; tp = tp->next) {
            if (tp->match && tp->child) {
                STATE state = base + tp->sym;
                STRASH *hp = &psp->hashv[p_hash(psp, state)];
                *(hp->state ? sp++ : hp) = (STRASH){state, tp->match - 1};
            }
        }
    }

    while (--sp >= sv) {
        HIT("hash collisions");
        for (i = p_hash(psp, sp->state); psp->hashv[i].state; ++i)
            HIT("hash displacements");
        psp->hashv[i] = *sp;
    }

    free(sv);
}

static void
fill_tranv(ACISM *psp, TNODE const*tp)
{
    TNODE const *cp = tp->child;

    if (cp && tp->back)
        set_tran(psp, tp->state, 0, 0, 0, tp->back->state);

    for (; cp; cp = cp->next) {
        //NOTE: cp->match is (strno+1) so that !cp->match means "no match".
        set_tran(psp, tp->state, cp->sym, cp->match, cp->is_suffix,
                cp->child ? cp->state : cp->match - 1 + psp->tran_size);
        if (cp->child)
            fill_tranv(psp, cp);
    }
}

static TNODE *
find_child(TNODE *tp, SYMBOL sym)
{
    for (tp = tp->child; tp && tp->sym < sym; tp = tp->next);
    return tp && tp->sym == sym ? tp : NULL;
}

#ifdef ACISM_STATS
PSSTAT psstat[__LINE__] = {{__LINE__,0}};
#endif//ACISM_STATS
//EOF