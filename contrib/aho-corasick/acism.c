/*
** Copyright (C) 2009-2014 Mischa Sandberg <mischasan@gmail.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU Lesser General Public License Version as
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

#include <glib.h>

#include "_acism.h"
#include "unix-std.h"

#define BACK ((SYMBOL)0)
#define ROOT ((STATE) 0)
extern const guchar lc_map[256];

int
acism_lookup(ac_trie_t const *psp, const char *text, size_t len,
           ACISM_ACTION *cb, void *context, int *statep, bool caseless)
{
    char const *cp = text, *endp = cp + len;
    uint8_t s;
    STATE state = *statep;
    int ret = 0;

    while (cp < endp) {
        s = caseless ? lc_map[(guint8)*cp++] : *cp++;
        _SYMBOL sym = psp->symv[s];
        if (!sym) {
            // Input byte is not in any pattern string.
            state = ROOT;
            continue;
        }

        // Search for a valid transition from this (state, sym),
        //  following the backref chain.

        TRAN next;
        while (!t_valid(psp, next = p_tran(psp, state, sym)) && state != ROOT) {
            TRAN back = p_tran(psp, state, BACK);
            state = t_valid(psp, back) ? t_next(psp, back) : ROOT;
        }

        if (!t_valid(psp, next))
            continue;

        if (!(next & (IS_MATCH | IS_SUFFIX))) {
            // No complete match yet; keep going.
            state = t_next(psp, next);
            continue;
        }

        // At this point, one or more patterns have matched.
        // Find all matches by following the backref chain.
        // A valid node for (sym) with no SUFFIX flag marks the
        //  end of the suffix chain.
        // In the same backref traversal, find a new (state),
        //  if the original transition is to a leaf.

        STATE s = state;

        // Initially state is ROOT. The chain search saves the
        //  first state from which the next char has a transition.
        state = t_isleaf(psp, next) ? 0 : t_next(psp, next);

        while (1) {

            if (t_valid(psp, next)) {

                if (next & IS_MATCH) {
                    unsigned strno, ss = s + sym, i;
                    if (t_isleaf(psp, psp->tranv[ss])) {
                        strno = t_strno(psp, psp->tranv[ss]);
                    } else {
                        for (i = p_hash(psp, ss); psp->hashv[i].state != ss; ++i);
                        strno = psp->hashv[i].strno;
                    }

                    if ((ret = cb(strno, cp - text, context)))
                        goto EXIT;
                }

                if (!state && !t_isleaf(psp, next))
                    state = t_next(psp, next);
                if ( state && !(next & IS_SUFFIX))
                    break;
            }

            if (s == ROOT)
                break;

            TRAN b = p_tran(psp, s, BACK);
            s = t_valid(psp, b) ? t_next(psp, b) : ROOT;
            next = p_tran(psp, s, sym);
        }
    }
EXIT:
	*statep = state;
    return ret;
}

void
acism_destroy(ac_trie_t *psp)
{
	if (!psp) return;
	if (psp->flags & IS_MMAP)
		munmap((char*)psp->tranv - sizeof(ac_trie_t),
				sizeof(ac_trie_t) + p_size(psp));
	else g_free(psp->tranv);
	g_free(psp);
}
//EOF
