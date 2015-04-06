aho-corasick
==

Aho-Corasick parallel string search, using interleaved arrays.

Mischa Sandberg mischasan@gmail.com

ACISM is an implementation of Aho-Corasick parallel string search,
using an Interleaved State-transition Matrix.
It combines the fastest possible Aho-Corasick implementation,
with the smallest possible data structure (!).

FEATURES
--------

* Fast. No hashing, no tree traversal; just a straight look-up equivalent to
    matrix[state, input-byte] per input character.

* Tiny. On average, the whole data structure (mostly the array) takes about 2-3 bytes per
    input pattern byte. The original set of pattern strings can be reverse-generated from the machine.

* Shareable. The state machine contains no pointers, so it can be compiled once,
    then memory-mapped by many processes.

* Searches byte vectors, not null-terminated strings.
    Suitable for searching machine code as much as searching text.

* DOS-proof. Well, that's an attribute of Aho-Corasick,
    so no real points for that.

* Stream-ready. The state can be saved between calls to search data.

DOCUMENTATION
-------------

The GoogleDocs description is at http://goo.gl/lE6zG
I originally called it "psearch", but found that name was overused by other authors.

LICENSE
-------

Though I've had strong suggestions to go with BSD license, I'm going with GPL2 until I figure out
how to keep in touch with people who download and use the code. Hence the "CONTACT ME IF..." line in the license.

GETTING STARTED
---------------

Download the source, type "gmake".
"gmake install" exports lib/libacism.a, include/acism.h and bin/acism_x.
"acism_x.c" is a good example of calling acism_create and acism_scan/acism_more.

(If you're interested in the GNUmakefile and rules.mk,
 check my blog posts on non-recursive make, at mischasan.wordpress.com.)
 
HISTORY
-------

The interleaved-array approach was tried and discarded in the late 70's, because the compile time was O(n^2). 
acism_create beats the problem with a "hint" array that tracks the restart points for searches.
That, plus discarding the original idea of how to get maximal density, resulted in the tiny-fast win-win.

ACKNOWLEDGEMENTS
----------------

I'd like to thank Mike Shannon, who wanted to see a machine built to make best use of L1/L2 cache.
The change to do that doubled performance on hardware with a much larger cache than the matrix.
Go figure.
