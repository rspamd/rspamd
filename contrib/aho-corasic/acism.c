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

#include "_acism.h"

#define BACK ((SYMBOL)0)
#define ROOT ((STATE) 0)

int
acism_more(ac_trie_t const *psp, MEMREF const text,
           ACISM_ACTION *cb, void *context, int *statep)
{
    ac_trie_t const ps = *psp;
    char const *cp = text.ptr, *endp = cp + text.len;
    STATE state = *statep;
    int ret = 0;

    while (cp < endp) {
        _SYMBOL sym = ps.symv[(uint8_t)*cp++];
        if (!sym) {
            // Input byte is not in any pattern string.
            state = ROOT;
            continue;
        }

        // Search for a valid transition from this (state, sym),
        //  following the backref chain.

        TRAN next;
        while (!t_valid(&ps, next = p_tran(&ps, state, sym)) && state != ROOT) {
            TRAN back = p_tran(&ps, state, BACK);
            state = t_valid(&ps, back) ? t_next(&ps, back) : ROOT;
        }

        if (!t_valid(&ps, next))
            continue;

        if (!(next & (IS_MATCH | IS_SUFFIX))) {
            // No complete match yet; keep going.
            state = t_next(&ps, next);
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
        state = t_isleaf(&ps, next) ? 0 : t_next(&ps, next);

        while (1) {

            if (t_valid(&ps, next)) {

                if (next & IS_MATCH) {
                    unsigned strno, ss = s + sym, i;
                    if (t_isleaf(&ps, ps.tranv[ss])) {
                        strno = t_strno(&ps, ps.tranv[ss]);
                    } else {
                        for (i = p_hash(&ps, ss); ps.hashv[i].state != ss; ++i);
                        strno = ps.hashv[i].strno;
                    }

                    if ((ret = cb(strno, cp - text.ptr, context)))
                        goto EXIT;
                }

                if (!state && !t_isleaf(&ps, next))
                    state = t_next(&ps, next);
                if ( state && !(next & IS_SUFFIX))
                    break;
            }

            if (s == ROOT)
                break;

            TRAN b = p_tran(&ps, s, BACK);
            s = t_valid(&ps, b) ? t_next(&ps, b) : ROOT;
            next = p_tran(&ps, s, sym);
        }
    }
EXIT:
    return *statep = state, ret;
}
//EOF
