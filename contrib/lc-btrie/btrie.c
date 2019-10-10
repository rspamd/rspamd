/* Level-Compressed Tree Bitmap (LC-TBM) Trie implementation
 *
 * Contributed by Geoffrey T. Dairiki <dairiki@dairiki.org>
 *
 * This file is released under a "Three-clause BSD License".
 *
 * Copyright (c) 2013, Geoffrey T. Dairiki
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 *   * Neither the name of Geoffrey T. Dairiki nor the names of other
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GEOFFREY
 * T. DAIRIKI BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*****************************************************************
 *
 * This code implements a routing table conceptually based on a binary
 * trie structure.  Internally, the trie is represented by two types
 * of compound nodes: "multibit nodes", which contain the top few
 * levels of an entire binary subtree; and "level compression" (LC)
 * nodes which represent a (potentially long) chain of out-degree one
 * (single child) binary nodes (possibly ending at a terminal node).
 *
 * The multibit nodes are represented using a "Tree Bitmap" structure
 * (more on this below), which is very efficient --- both in terms of
 * memory usage and lookup speed --- at representing densely branching
 * parts of the trie.  The LC nodes can efficiently represent long
 * non-branching chains of binary trie nodes.  Using both node types
 * together results in efficient representation of both the sparse and
 * dense parts of a binary trie.
 *
 * Graphically, here's the rough idea:
 *
 *                    ........
 *                    .LC  o .
 *                    .   /  .    LC nodes can
 *                    .  o   . <= represent long chains
 *                    .   \  .    of (non-branching) binary
 *                    .    o .    trie nodes
 *                    .   /  .
 *                    .  o   .
 *              ......../.....
 *              .TBM   o   .
 *              .     / \  .    TBM nodes can represent
 *              .    o   * . <= several levels of densely
 *              .   / \    .    branching binary trie nodes
 *              .  o   o   .
 *         ......./.....\.......
 *         .TBM  o    .. o   LC.
 *         .    / \   ..  \    .
 *         .   o   o  ..   o   .
 *         .  /   / \ ..    \  .
 *         . *   o   *..     o .
 *         ...../.......    /  .
 *           . o  LC.  .   o   .
 *           .  \   .  .....\......
 *           .   *  .   .    o TBM.
 *           ........   .   / \   .
 *                      .  o   o  .
 *                      . / \   \ .
 *                      .*   *   *.
 *                      ...........
 *
 * Terminology
 * -----------
 *
 * node
 *   Usually, in the comments below, "node" will be used to refer to
 *   a compound node: either a multibit (TBM) node or an LC node.
 *
 * "internal node" or "prefix"
 *   The terms "prefix" or "internal node" are used to refer to
 *   a node in the binary trie which is internal to a multibit (TBM)
 *   node.
 *
 * ----------------------------------------------------------------
 *
 * Internal Representation of the Nodes
 * ====================================
 *
 * Multibit (TBM) Nodes
 * ~~~~~~~~~~~~~~~~~~~~
 *
 * The multibit nodes are represented using a "Tree Bitmap" (TBM)
 * structure as described by Eatherton, Dittia and Varghese[1]. See
 * the paper referenced below for basic details.
 *
 * A multibit node, represents several levels of a binary trie.
 * For example, here is a multibit node of stride 2 (which represent
 * two levels of a binary trie.
 *
 *           +------- | ------+
 *           | multi  o       |
 *           | bit   / \      |
 *           | node /   \     |
 *           |     o     *    |
 *           +--- / \ - / \ --+
 *               O
 *
 * Note that, for a multibit node of stride S, there are 2^S - 1 internal
 * nodes, each of which may have data (or not) associated with them, and
 * 2^S "external paths" leading to other (possibly compound nodes).
 * (In the diagram above, one of three internal node (the one denoted by "*")
 * has data, and one of four extending paths leads to an external node
 * (denoted by the 'O').)
 *
 * The TBM structure can represent these bitmaps in a very memory-efficient
 * manner.
 *
 * Each TBM node consists of two bitmaps --- the "internal bitmap" and the
 * "extending paths bitmap" --- and a pointer which points to an array
 * which contains both the extending path ("child") nodes and any
 * internal prefix data for the TBM node.
 *
 *        +--------+--------+
 *   TBM  | ext bm | int bm |
 *   Node +--------+--------+
 *        |     pointer     |----+
 *        +-----------------+    |
 *                               |
 *                               |
 *        +-----------------+    |
 *        | extending path  |    |
 *        |    node[N-1]    |    |
 *        +-----------------+    |
 *        /       ...       /    |
 *        /       ...       /    |
 *        +-----------------+    |
 *        | extending path  |    |
 *        |    node[0]      |    |
 *        +-----------------+<---+
 *        | int. data[M-1]  |
 *        +-----------------+
 *        /       ...       /
 *        +-----------------+
 *        | int. data[0]    |
 *        +-----------------+
 *
 * The extending paths bitmap (or "ext bitmap") has one bit for each
 * possible "extending path" from the bottom of the multibit node. To
 * check if a particular extending path is present, one checks to see if
 * the corresponding bit is set in the ext bitmap. The index into the
 * array of children for that path can be found by counting the number
 * of set bits to the left of that bit.
 *
 * Similarly, the internal bitmap has one bit for each binary node
 * which is internal to the multibit node. To determine whether there
 * is data stored for an internal prefix, one checks the corresponding
 * bit in the internal bitmap. As for extending paths, the index into
 * the array of internal data is found by counting the number of set
 * bits to the left of that bit.
 *
 * To save space in the node structure, the node data array is stored
 * contiguously with the node extending path array. The single
 * ("children") pointer in the TBM structure points to the beginning
 * of the array of extending path nodes and to (one past) the end of
 * the the internal data array.
 *
 * The multibit stride is chosen so that the entire TBM node structure fits
 * in the space of two pointers. On 32 bit machines this means the stride
 * is four (each of the two bitmaps is 16 bits); on 32 bit machines the
 * stride is five.
 *
 * Note that there are only 2^stride - 1 internal prefixes in a TBM
 * node. That means there is one unused bit in the internal bitmap.
 * We require that that bit must always be clear for a TBM node. (If
 * set, it indicates that the structure represents, instead, an LC
 * node. See below.)
 *
 * ----------------------------------------------------------------
 *
 * Level Compression (LC) Nodes
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * LC nodes are used to represent a chain of out-degree-one (single
 * child) prefixes in the binary trie. The are represented by a bit
 * string (the "relative prefix") along with its length and a pointer
 * to the extending path (the next node past the LC node.)
 *
 *
 *   Non-Terminal LC Node:
 *
 *     +------------------+-------+
 *     | relative prefix  |1|0|len|
 *     +------------------+-------+
 *     |       ptr.child          |--+
 *     +--------------------------+  |
 *                                   |
 *                                   |
 *     +--------------------------+  |
 *     | Next node -              |  |
 *     |    either LC or TBM      |  |
 *     |                          |  |
 *     +--------------------------+<-+
 *
 * The Relative Prefix
 * -------------------
 *
 * The maximum relative prefix per LC node is selected so that (again)
 * the entire node structure fits in the space of two pointers. On 32 bit
 * machines, the maximum relative prefix is 24 bits; on 62 bit machines
 * the limit is 56 bits.
 *
 * In the LC node structure, the relative prefix is stored as an array
 * of bytes. To avoid some bit-shifting during tree searches, these
 * bytes are byte-aligned with the global prefix. In other words, in
 * general there are (pos % 8) "pad" bits at the beginning of the
 * relative prefix --- where pos "starting bit" (or depth in the
 * binary tree) of the LC node --- which really belong to the parent
 * node(s) of the LC node. For efficiency (so that we don't have to
 * mask them out when matching) we require that these pad bits be
 * correct --- they must match the path which leads to the LC node.
 *
 * The relative prefix length stored in the LC node structure does not
 * count the pad bits.
 *
 * Terminal Node Compression
 * -------------------------
 *
 * For memory efficiency, we also support "terminal LC" nodes. When
 * the extension path from an LC node consists a single terminal node,
 * we store that terminal nodes data directly in the parent LC node.
 *
 * Instead of this:
 *
 *      +------------------+-------+
 *      | relative prefix  |1|0|len|
 *      +------------------+-------+
 *      |       ptr.child          |--+
 *      +--------------------------+  |
 *                                    |
 *      +--------------------------+  |
 *      | Terminal Node (TBM node, |  |
 *      | empty except for the     |  |
 *   +--| root internal node.)     |  |
 *   |  +--------------------------+<-+
 *   |
 *   +->+--------------------------+
 *      |  terminal node data      |
 *      +--------------------------+
 *
 * We can do this:
 *
 *      +------------------+-------+
 *      | relative prefix  |1|1|len|
 *      +------------------+-------+
 *      |   terminal node data     |
 *      +--------------------------+
 *
 * Terminal LC nodes are differentiated from non-terminal LC nodes
 * by the setting of the is_terminal flag.
 *
 * Node Structure Packing Details
 * ------------------------------
 *
 * The LC and TBM node structures are carefully packed so that the
 * "is_lc" flag (which indicates that a node is an LC node)
 * corresponds to the one unused bit in the internal bitmap of the TBM
 * node structure (which we require to be zero for TBM nodes).
 *
 * ----------------------------------------------------------------
 *
 * References
 * ==========
 *
 * [1] Will Eatherton, George Varghese, and Zubin Dittia. 2004. Tree
 *     bitmap: hardware/software IP lookups with incremental
 *     updates. SIGCOMM Comput. Commun. Rev. 34, 2 (April 2004),
 *     97-122. DOI=10.1145/997150.997160
 *     http://doi.acm.org/10.1145/997150.997160
 *     http://comnet.kaist.ac.kr/yhlee/CN_2008_Spring/readings/Eath-04-tree_bitmap.pdf
 *
 ****************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#if defined(TEST) && defined(NDEBUG)
# warning undefining NDEBUG for TEST build
# undef NDEBUG
#endif
#include <assert.h>

#include "btrie.h"
#include "libutil/mem_pool.h"

#ifdef __SIZEOF_POINTER__
#define SIZEOF_VOID_P __SIZEOF_POINTER__
#else
#if defined(__ILP32__) || defined(__ILP32) || defined(_ILP32)
#  define SIZEOF_VOID_P 4
#elif defined(__ILP64__) || defined(__ILP64) || defined(_ILP64)
#  define SIZEOF_VOID_P 8
#elif defined(__LLP64__) || defined(__LLP64) || defined(_LLP64) || defined(_WIN64)
#  define SIZEOF_VOID_P 8
#elif defined(__LP64__) || defined(__LP64) || defined(_LP64)
#  define SIZEOF_VOID_P 8
#elif defined(UINTPTR_MAX) && defined(UINT64_MAX) && (UINTPTR_MAX == UINT64_MAX)
#  define SIZEOF_VOID_P 8
#else
#  define SIZEOF_VOID_P 4
#endif
#endif

#if SIZEOF_VOID_P == 4
# define TBM_STRIDE      4
#elif SIZEOF_VOID_P == 8
# define TBM_STRIDE      5
#else
# error "Unsupported word size"
#endif

#ifndef NO_STDINT_H
# if TBM_STRIDE == 4
typedef uint16_t tbm_bitmap_t;
# else
typedef uint32_t tbm_bitmap_t;
# endif
#else /* NO_STDINT_H */
# if TBM_STRIDE == 4
#  if SIZEOF_SHORT == 2
typedef short unsigned tbm_bitmap_t;
#  else
#   error "can not determine type for 16 bit unsigned int"
#  endif
# else /* TBM_STRIDE == 5 */
#  if SIZEOF_INT == 4
typedef unsigned tbm_bitmap_t;
#  elif SIZEOF_LONG == 4
typedef long unsigned tbm_bitmap_t;
#  else
#   error "can not determine type for 32 bit unsigned int"
#  endif
# endif
#endif

#define TBM_FANOUT         (1U << TBM_STRIDE)
#define LC_BYTES_PER_NODE  (SIZEOF_VOID_P - 1)

typedef union node_u node_t;

/* The tbm_node and lc_node structs must be packed so that the the
 * high bit (LC_FLAGS_IS_LC) of lc_flags in the the lc_node struct
 * coincides with bit zero (the most significant bit) of tbm_node's
 * int_bm.  (This bit is how we differentiate between the two node
 * types.  It is always clear for a tbm_node and always set for an
 * lc_node.)
 */

struct tbm_node
{
#ifdef WORDS_BIGENDIAN
	tbm_bitmap_t int_bm; /* the internal bitmap */
	tbm_bitmap_t ext_bm; /* extending path ("external") bitmap */
#else
	tbm_bitmap_t ext_bm; /* extending path ("external") bitmap */
	tbm_bitmap_t int_bm; /* the internal bitmap */
#endif
	union
	{
		node_t *children; /* pointer to array of children */
		const void **data_end; /* one past end of internal prefix data array */
	} ptr;
};

struct lc_node
{
	/* lc_flags contains the LC prefix length and a couple of bit flags
	 * (apparently char-sized bit fields are a gcc extension)
	 */
# define LC_FLAGS_IS_LC       0x80
# define LC_FLAGS_IS_TERMINAL 0x40
# define LC_FLAGS_LEN_MASK    0x3f
#ifdef WORDS_BIGENDIAN
	btrie_oct_t lc_flags;
	btrie_oct_t prefix[LC_BYTES_PER_NODE];
#else
	btrie_oct_t prefix[LC_BYTES_PER_NODE];
	btrie_oct_t lc_flags;
#endif
	union
	{
		node_t *child; /* pointer to child (if !is_terminal) */
		const void *data; /* the prefix data (if is_terminal) */
	} ptr;
};

union node_u
{
	struct tbm_node tbm_node;
	struct lc_node lc_node;
};

struct free_hunk
{
	struct free_hunk *next;
};

#define MAX_CHILD_ARRAY_LEN (TBM_FANOUT + TBM_FANOUT / 2)

struct btrie
{
	node_t root;

	rspamd_mempool_t *mp;
	struct free_hunk *free_list[MAX_CHILD_ARRAY_LEN];
	jmp_buf exception;
	/* mem mgmt stats */
	size_t alloc_total; /* total bytes allocated from mempool */
	size_t alloc_data; /* bytes allocated for TBM node int. prefix data */
	size_t alloc_waste; /* bytes wasted by rounding of data array size */
#ifdef BTRIE_DEBUG_ALLOC
	size_t alloc_hist[MAX_CHILD_ARRAY_LEN * 2]; /* histogram of alloc sizes */
#endif

	/* trie stats */
	size_t n_entries; /* number of entries */
	size_t n_tbm_nodes; /* total number of TBM nodes in tree */
	size_t n_lc_nodes; /* total number of LC nodes in tree */
};

/****************************************************************
 *
 * Memory management
 *
 * We will need to frequently resize child/data arrays.  The current
 * mempool implementation does not support resizing/freeing, so here
 * we roll our own.
 */

static inline void _free_hunk(struct btrie *btrie, void *buf, unsigned n_nodes)
{
	struct free_hunk *hunk = buf;

	hunk->next = btrie->free_list[n_nodes - 1];
	btrie->free_list[n_nodes - 1] = hunk;
}

static inline void *
_get_hunk(struct btrie *btrie, unsigned n_nodes)
{
	struct free_hunk *hunk = btrie->free_list[n_nodes - 1];

	if (hunk != NULL)
		btrie->free_list[n_nodes - 1] = hunk->next;
	return hunk;
}

/* Get pointer to uninitialized child/data array.
 *
 * Allocates memory for an array of NDATA (void *)s followed by an
 * array of NCHILDREN (node_t)s.  The returned pointer points to to
 * beginning of the children array (i.e. it points to (one past) the
 * end of the data array.)
 */
static node_t *
alloc_nodes(struct btrie *btrie, unsigned nchildren, unsigned ndata)
{
	size_t n_nodes = nchildren + (ndata + 1) / 2;
	node_t *hunk;

	assert(n_nodes > 0 && n_nodes <= MAX_CHILD_ARRAY_LEN);

	hunk = _get_hunk (btrie, n_nodes);
	if (hunk == NULL) {
		/* Do not have free hunk of exactly the requested size, look for a
		 * larger hunk.  (The funny order in which we scan the buckets is
		 * heuristically selected in an attempt to minimize unnecessary
		 * creation of small fragments)
		 */
		size_t n, skip = n_nodes > 4 ? 4 : n_nodes;
		for (n = n_nodes + skip; n <= MAX_CHILD_ARRAY_LEN; n++) {
			if ((hunk = _get_hunk (btrie, n)) != NULL) {
				_free_hunk (btrie, hunk + n_nodes, n - n_nodes);
				goto DONE;
			}
		}
		for (n = n_nodes + 1; n < n_nodes + skip && n <= MAX_CHILD_ARRAY_LEN;
				n++) {
			if ((hunk = _get_hunk (btrie, n)) != NULL) {
				_free_hunk (btrie, hunk + n_nodes, n - n_nodes);
				goto DONE;
			}
		}

		/* failed to find free hunk, allocate a fresh one */
		hunk = rspamd_mempool_alloc0 (btrie->mp, n_nodes * sizeof(node_t));
		if (hunk == NULL)
			longjmp (btrie->exception, BTRIE_ALLOC_FAILED);
		btrie->alloc_total += n_nodes * sizeof(node_t);
	}

	DONE: btrie->alloc_data += ndata * sizeof(void *);
	btrie->alloc_waste += (ndata % 2) * sizeof(void *);
#ifdef BTRIE_DEBUG_ALLOC
	btrie->alloc_hist[2 * nchildren + ndata]++;
#endif

	/* adjust pointer to allow room for data array before child array */
	return hunk + (ndata + 1) / 2;
}

/* Free memory allocated by alloc_nodes */
static void free_nodes(struct btrie *btrie, node_t *buf, unsigned nchildren,
		unsigned ndata)
{
	size_t n_nodes = nchildren + (ndata + 1) / 2;

	assert(n_nodes > 0 && n_nodes <= MAX_CHILD_ARRAY_LEN);

	_free_hunk (btrie, buf - (ndata + 1) / 2, n_nodes);

	btrie->alloc_data -= ndata * sizeof(void *);
	btrie->alloc_waste -= (ndata % 2) * sizeof(void *);
#ifdef BTRIE_DEBUG_ALLOC
	btrie->alloc_hist[2 * nchildren + ndata]--;
#endif
}

/* Debugging/development only: */
#ifdef BTRIE_DEBUG_ALLOC
static void
dump_alloc_hist(const struct btrie *btrie)
{
	unsigned bin;
	size_t total_alloc = 0;
	size_t total_free = 0;
	size_t total_bytes = 0;
	size_t total_waste = 0;
	size_t total_free_bytes = 0;

	puts("hunk  alloc   free    alloc   wasted     free");
	puts("size  hunks  hunks    bytes    bytes    bytes");
	puts("==== ====== ====== ======== ======== ========");

	for (bin = 1; bin < 2 * MAX_CHILD_ARRAY_LEN; bin++) {
		size_t n_alloc = btrie->alloc_hist[bin];
		size_t bytes = n_alloc * bin * sizeof(void *);
		size_t waste_bytes = (bin % 2) * n_alloc * sizeof(void *);
		size_t n_free = 0, free_bytes;
		if (bin % 2 == 0) {
			const struct free_hunk *hunk;
			for (hunk = btrie->free_list[bin / 2 - 1]; hunk; hunk = hunk->next)
			n_free++;
		}
		free_bytes = n_free * bin * sizeof(void *);

		printf("%3zu: %6zu %6zu %8zu %8zu %8zu\n", bin * sizeof(void *),
				n_alloc, n_free, bytes, waste_bytes, free_bytes);

		total_alloc += n_alloc;
		total_free += n_free;
		total_bytes += bytes;
		total_waste += waste_bytes;
		total_free_bytes += free_bytes;
	}
	puts("---- ------ ------ -------- -------- --------");
	printf("SUM: %6zu %6zu %8zu %8zu %8zu\n",
			total_alloc, total_free, total_bytes, total_waste, total_free_bytes);
}
#endif

/****************************************************************
 *
 * Bit twiddling
 *
 */

static inline tbm_bitmap_t bit(unsigned b)
{
	return 1U << ((1 << TBM_STRIDE) - 1 - b);
}

/* count the number of set bits in bitmap
 *
 * algorithm from
 * http://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetParallel
 */
static inline unsigned count_bits(tbm_bitmap_t v)
{
	/* Count set bits in parallel. */
	/* v = (v & 0x5555...) + ((v >> 1) & 0x5555...); */
	v -= (v >> 1) & (tbm_bitmap_t) ~0UL / 3;
	/* v = (v & 0x3333...) + ((v >> 2) & 0x3333...); */
	v = (v & (tbm_bitmap_t) ~0UL / 5) + ((v >> 2) & (tbm_bitmap_t) ~0UL / 5);
	/* v = (v & 0x0f0f...) + ((v >> 4) & 0x0f0f...); */
	v = (v + (v >> 4)) & (tbm_bitmap_t) ~0UL / 17;
	/* v = v % 255; */
#if TBM_STRIDE == 4
	/* tbm_bitmap_t is uint16_t, avoid the multiply */
	return (v + (v >> 8)) & 0x0ff;
#else
	return (v * (tbm_bitmap_t) (~0UL / 255)) >> ((sizeof(tbm_bitmap_t) - 1) * 8);
#endif
}

static inline unsigned count_bits_before(tbm_bitmap_t bm, int b)
{
	return b ? count_bits (bm >> ((1 << TBM_STRIDE) - b)) : 0;
}

static inline unsigned count_bits_from(tbm_bitmap_t bm, int b)
{
	return count_bits (bm << b);
}

/* extracts a few bits from bitstring, returning them as an integer */
static inline btrie_oct_t RSPAMD_NO_SANITIZE extract_bits(const btrie_oct_t *prefix, unsigned pos,
		unsigned nbits)
{
	if (nbits == 0)
		return 0;
	else {
		unsigned v = (prefix[pos / 8] << 8) + prefix[pos / 8 + 1];
		return (v >> (16 - nbits - pos % 8)) & ((1U << nbits) - 1);
	}
}

static inline unsigned extract_bit(const btrie_oct_t *prefix, int pos)
{
	return (prefix[pos / 8] >> (7 - pos % 8)) & 0x01;
}

/* get mask for high n bits of a byte */
static inline btrie_oct_t high_bits(unsigned n)
{
	return (btrie_oct_t) -(1U << (8 - n));
}

/* determine whether two prefixes are equal */
static inline int prefixes_equal(const btrie_oct_t *pfx1,
		const btrie_oct_t *pfx2, unsigned len)
{
	return (memcmp (pfx1, pfx2, len / 8) == 0
			&& (len % 8 == 0 ||
			((pfx1[len / 8] ^ pfx2[len / 8]) & high_bits (len % 8)) == 0));
}

/* determine length of longest common subprefix */
static inline unsigned common_prefix(const btrie_oct_t *pfx1,
		const btrie_oct_t *pfx2, unsigned len)
{
	/* algorithm adapted from
	 * http://graphics.stanford.edu/~seander/bithacks.html#IntegerLogLookup
	 */
	static btrie_oct_t leading_zeros[] =
	{ 8, 7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3,
			3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
			2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, };
	unsigned nb;

	for (nb = 0; nb < len / 8; nb++) {
		unsigned diff = *pfx1++ ^ *pfx2++;
		if (diff != 0)
			return 8 * nb + leading_zeros[diff];
	}
	if (len % 8) {
		unsigned n = leading_zeros[*pfx1 ^ *pfx2];
		if (n < len % 8)
			return 8 * nb + n;
	}
	return len;
}

/****************************************************************
 */

static inline int is_empty_node(const node_t *node)
{
	return node->tbm_node.ext_bm == 0 && node->tbm_node.int_bm == 0;
}

static inline int is_lc_node(const node_t *node)
{
	return (node->lc_node.lc_flags & LC_FLAGS_IS_LC) != 0;
}

static inline int is_tbm_node(const node_t *node)
{
	return !is_lc_node (node);
}

/* is node a TBM node with internal data? */
static inline int has_data(const node_t *node)
{
	return is_tbm_node (node) && node->tbm_node.int_bm != 0;
}

static inline unsigned base_index(unsigned pfx, unsigned plen)
{
	assert(plen < TBM_STRIDE);
	assert(pfx < (1U << plen));
	return pfx | (1U << plen);
}

/* initialize node to an empty TBM node */
static inline void init_empty_node(struct btrie *btrie, node_t *node)
{
	memset(node, 0, sizeof(*node));
	btrie->n_tbm_nodes++;
}

/* get pointer to TBM internal prefix data */
static inline const void **
tbm_data_p(const struct tbm_node *node, unsigned pfx, unsigned plen)
{
	unsigned bi = base_index (pfx, plen);

	if ((node->int_bm & bit (bi)) == 0)
		return NULL; /* no data */
	else {
		return &node->ptr.data_end[-(int) count_bits_from (node->int_bm, bi)];
	}
}

/* add an element to the internal data array */
static void tbm_insert_data(struct btrie *btrie, struct tbm_node *node,
		unsigned pfx, unsigned plen, const void *data)
{
	/* XXX: don't realloc if already big enough? */
	unsigned bi = base_index (pfx, plen);
	unsigned nchildren = count_bits (node->ext_bm);
	int ndata = count_bits (node->int_bm);
	unsigned di = count_bits_before (node->int_bm, bi);
	node_t *old_children = node->ptr.children;
	const void **old_data_beg = node->ptr.data_end - ndata;
	const void **data_beg;

	assert((node->int_bm & bit (bi)) == 0);

	node->ptr.children = alloc_nodes (btrie, nchildren, ndata + 1);
	data_beg = node->ptr.data_end - (ndata + 1);
	data_beg[di] = data;
	node->int_bm |= bit (bi);

	if (nchildren != 0 || ndata != 0) {
		memcpy(data_beg, old_data_beg, di * sizeof(data_beg[0]));
		memcpy(&data_beg[di + 1], &old_data_beg[di],
				(ndata - di) * sizeof(data_beg[0])
						+ nchildren * sizeof(node_t));
		free_nodes (btrie, old_children, nchildren, ndata);
	}
}

/* determine whether TBM has internal prefix data for pfx/plen or ancestors */
static inline int has_internal_data(const struct tbm_node *node, unsigned pfx,
		unsigned plen)
{
# define BIT(n) (1U << ((1 << TBM_STRIDE) - 1 - (n)))
# define B0() BIT(1)            /* the bit for 0/0 */
# define B1(n) (BIT((n) + 2) | B0()) /* the bits for n/1 and its ancestors */
# define B2(n) (BIT((n) + 4) | B1(n >> 1)) /* the bits for n/2 and ancestors */
# define B3(n) (BIT((n) + 8) | B2(n >> 1)) /* the bits for n/3 and ancestors */
# define B4(n) (BIT((n) + 16) | B3(n >> 1)) /* the bits for n/4 and ancestors */

	static tbm_bitmap_t ancestors[] =
	{ 0, B0(), B1(0), B1(1), B2(0), B2(1), B2(2), B2(3), B3(0), B3(1), B3(2),
			B3(3), B3(4), B3(5), B3(6), B3(7),
# if TBM_STRIDE == 5
			B4(0), B4(1), B4(2), B4(3), B4(4), B4(5), B4(6), B4(7), B4(8), B4(
					9), B4(10), B4(11), B4(12), B4(13), B4(14), B4(15),
# elif TBM_STRIDE != 4
#   error "unsupported TBM_STRIDE"
# endif
			};
# undef B4
# undef B3
# undef B2
# undef B1
# undef B0
# undef BIT

	return (node->int_bm & ancestors[base_index (pfx, plen)]) != 0;
}

/* get pointer to TBM extending path */
static inline node_t *
tbm_ext_path(const struct tbm_node *node, unsigned pfx)
{
	if ((node->ext_bm & bit (pfx)) == 0)
		return NULL;
	else
		return &node->ptr.children[count_bits_before (node->ext_bm, pfx)];
}

/* resize TBM node child array to make space for new child node */
static node_t *
tbm_insert_ext_path(struct btrie *btrie, struct tbm_node *node, unsigned pfx)
{
	unsigned nchildren = count_bits (node->ext_bm);
	unsigned ci = count_bits_before (node->ext_bm, pfx);
	int ndata = count_bits (node->int_bm);
	node_t *old_children = node->ptr.children;
	const void **old_data_beg = node->ptr.data_end - ndata;

	assert((node->ext_bm & bit (pfx)) == 0);

	node->ptr.children = alloc_nodes (btrie, nchildren + 1, ndata);
	init_empty_node (btrie, &node->ptr.children[ci]);
	node->ext_bm |= bit (pfx);

	if (nchildren != 0 || ndata != 0) {
		const void **data_beg = node->ptr.data_end - ndata;
		memcpy(data_beg, old_data_beg,
				ndata * sizeof(data_beg[0]) + ci * sizeof(node_t));
		memcpy(&node->ptr.children[ci + 1], &old_children[ci],
				(nchildren - ci) * sizeof(old_children[0]));
		free_nodes (btrie, old_children, nchildren, ndata);
	}

	return &node->ptr.children[ci];
}

static inline int lc_is_terminal(const struct lc_node *node)
{
	return (node->lc_flags & LC_FLAGS_IS_TERMINAL) != 0;
}

static inline unsigned lc_len(const struct lc_node *node)
{
	return node->lc_flags & LC_FLAGS_LEN_MASK;
}

static inline void lc_init_flags(struct lc_node *node, int is_terminal,
		unsigned len)
{
	assert((len & ~LC_FLAGS_LEN_MASK) == 0);
	node->lc_flags = LC_FLAGS_IS_LC | len;
	if (is_terminal)
		node->lc_flags |= LC_FLAGS_IS_TERMINAL;
}

static inline void lc_add_to_len(struct lc_node *node, int increment)
{
	unsigned new_len = lc_len (node) + increment;
	assert((new_len & ~LC_FLAGS_LEN_MASK) == 0);
	node->lc_flags = (node->lc_flags & ~LC_FLAGS_LEN_MASK) | new_len;
}

static inline unsigned lc_shift(unsigned pos)
{
	return pos / 8;
}

static inline unsigned lc_base(unsigned pos)
{
	return 8 * lc_shift (pos);
}

static inline unsigned lc_bits(const struct lc_node *node, unsigned pos)
{
	return pos % 8 + lc_len (node);
}

static inline unsigned lc_bytes(const struct lc_node *node, unsigned pos)
{
	return (lc_bits (node, pos) + 7) / 8;
}

static inline unsigned lc_leading_bits(const struct lc_node *node, unsigned pos,
		unsigned nbits)
{
	return extract_bits (node->prefix, pos % 8, nbits);
}

/* Initialize a new terminal LC node
 *
 * If prefix is too long to fit in a single LC node, then a chain
 * of LC nodes will be created.
 */
static void init_terminal_node(struct btrie *btrie, node_t *dst, unsigned pos,
		const btrie_oct_t *prefix, unsigned len, const void *data)
{
	struct lc_node *node = &dst->lc_node;
	unsigned nbytes = (len + 7) / 8;

	while (nbytes - lc_shift (pos) > LC_BYTES_PER_NODE) {
		memcpy(node->prefix, prefix + lc_shift (pos), LC_BYTES_PER_NODE);
		lc_init_flags (node, 0, 8 * LC_BYTES_PER_NODE - pos % 8);
		node->ptr.child = alloc_nodes (btrie, 1, 0);
		pos += lc_len (node);
		node = &node->ptr.child->lc_node;
		btrie->n_lc_nodes++;
	}

	memcpy(node->prefix, prefix + lc_shift (pos), nbytes - lc_shift (pos));
	lc_init_flags (node, 1, len - pos);
	node->ptr.data = data;
	btrie->n_lc_nodes++;
}

/* merge chains of multiple LC nodes into a single LC node, if possible.
 *
 * also ensure that the leading nodes in the LC chain have maximum length.
 */
static void coalesce_lc_node(struct btrie *btrie, struct lc_node *node,
		unsigned pos)
{
	while (!lc_is_terminal (node) && lc_bits (node, pos) < 8 * LC_BYTES_PER_NODE
			&& is_lc_node (node->ptr.child)) {
		struct lc_node *child = &node->ptr.child->lc_node;
		unsigned spare_bits = 8 * LC_BYTES_PER_NODE - lc_bits (node, pos);
		unsigned end = pos + lc_len (node);
		unsigned shift = lc_shift (end) - lc_shift (pos);
		if (lc_len (child) <= spare_bits) {
			/* node plus child will fit in single node - merge */
			memcpy(node->prefix + shift, child->prefix, lc_bytes (child, end));
			lc_init_flags (node, lc_is_terminal (child),
					lc_len (node) + lc_len (child));
			node->ptr = child->ptr;
			free_nodes (btrie, (node_t *) child, 1, 0);
			btrie->n_lc_nodes--;
		}
		else {
			/* can't merge, but can take some of children bits */
			unsigned cshift = lc_shift (end + spare_bits) - lc_shift (end);

			memcpy(node->prefix + shift, child->prefix,
					LC_BYTES_PER_NODE - shift);
			lc_add_to_len (node, spare_bits);
			if (cshift)
				memmove(child->prefix, child->prefix + cshift,
						lc_bytes (child, end) - cshift);
			assert(lc_len (child) > spare_bits);
			lc_add_to_len (child, -spare_bits);

			pos += lc_len (node);
			node = child;
		}
	}
}

static void init_tbm_node(struct btrie *btrie, node_t *node, unsigned pos,
		const btrie_oct_t pbyte, const void **root_data_p, node_t *left,
		node_t *right);

/* given an LC node at orig_pos, create a new (shorter) node at pos */
static void shorten_lc_node(struct btrie *btrie, node_t *dst, unsigned pos,
		struct lc_node *src, unsigned orig_pos)
{
	assert(orig_pos < pos);
	assert(lc_len (src) >= pos - orig_pos);
	assert(dst != (node_t * )src);

	if (lc_len (src) == pos - orig_pos && !lc_is_terminal (src)) {
		/* just steal the child */
		node_t *child = src->ptr.child;
		*dst = *child;
		free_nodes (btrie, child, 1, 0);
		btrie->n_lc_nodes--;
	}
	else {
		struct lc_node *node = &dst->lc_node;
		unsigned shift = lc_shift (pos) - lc_shift (orig_pos);
		if (shift) {
			memmove(node->prefix, src->prefix + shift,
					lc_bytes (src, orig_pos) - shift);
			node->lc_flags = src->lc_flags;
			node->ptr = src->ptr;
		}
		else {
			*node = *src;
		}
		lc_add_to_len (node, -(pos - orig_pos));
		coalesce_lc_node (btrie, node, pos);
	}
}

/* convert LC node to non-terminal LC node of length len *in place*
 *
 * on entry, node must have length at least len
 */
static void split_lc_node(struct btrie *btrie, struct lc_node *node,
		unsigned pos, unsigned len)
{
	node_t *child = alloc_nodes (btrie, 1, 0);

	assert(lc_len (node) >= len);
	shorten_lc_node (btrie, child, pos + len, node, pos);

	lc_init_flags (node, 0, len);
	node->ptr.child = child;
	btrie->n_lc_nodes++;
}

/* convert non-terminal LC node of length one to a TBM node *in place* */
static void convert_lc_node_1(struct btrie *btrie, struct lc_node *node,
		unsigned pos)
{
	btrie_oct_t pbyte = node->prefix[0];
	node_t *child = node->ptr.child;
	node_t *left, *right;

	assert(lc_len (node) == 1);
	assert(!lc_is_terminal (node));

	if (extract_bit (node->prefix, pos % 8))
		left = NULL, right = child;
	else
		left = child, right = NULL;
	init_tbm_node (btrie, (node_t *) node, pos, pbyte, NULL, left, right);
	free_nodes (btrie, child, 1, 0);
	btrie->n_lc_nodes--;
}

/* convert an LC node to TBM node *in place* */
static void convert_lc_node(struct btrie *btrie, struct lc_node *node,
		unsigned pos)
{
	unsigned len = lc_len (node);

	if (len >= TBM_STRIDE) {
		unsigned pfx = lc_leading_bits (node, pos, TBM_STRIDE);
		struct tbm_node *result = (struct tbm_node *) node;

		/* split to LC of len TBM_STRIDE followed by child (extending path) */
		split_lc_node (btrie, node, pos, TBM_STRIDE);
		/* then convert leading LC node to TBM node */
		result->int_bm = 0;
		result->ext_bm = bit (pfx);
		btrie->n_lc_nodes--;
		btrie->n_tbm_nodes++;
	}
	else if (lc_is_terminal (node)) {
		/* convert short terminal LC to TBM (with internal data) */
		unsigned pfx = lc_leading_bits (node, pos, len);
		const void *data = node->ptr.data;
		node_t *result = (node_t *) node;

		init_empty_node (btrie, result);
		tbm_insert_data (btrie, &result->tbm_node, pfx, len, data);

		btrie->n_lc_nodes--;
	}
	else {
		assert(len > 0);
		for (; len > 1; len--) {
			split_lc_node (btrie, node, pos, len - 1);
			convert_lc_node_1 (btrie, &node->ptr.child->lc_node, pos + len - 1);
		}
		convert_lc_node_1 (btrie, node, pos);
	}
}

static void insert_lc_node(struct btrie *btrie, node_t *dst, unsigned pos,
		btrie_oct_t pbyte, unsigned last_bit, node_t *tail)
{
	struct lc_node *node = &dst->lc_node;
	btrie_oct_t mask = 1 << (7 - (pos % 8));
	btrie_oct_t bit = last_bit ? mask : 0;

	if (mask != 0x01 && is_lc_node (tail)) {
		/* optimization: LC tail has room for the extra bit (without shifting) */
		assert((tail->lc_node.prefix[0] & mask) == bit);
		*node = tail->lc_node;
		lc_add_to_len (node, 1);
		return;
	}

	/* add new leading LC node of len 1 */
	node->prefix[0] = pbyte | bit;
	lc_init_flags (node, 0, 1);
	node->ptr.child = alloc_nodes (btrie, 1, 0);
	node->ptr.child[0] = *tail;
	btrie->n_lc_nodes++;

	if (is_lc_node (tail))
		coalesce_lc_node (btrie, node, pos);
}

/* given:
 *  pbyte: the bits in the prefix between lc_base(pos) and pos
 *  pfx: the next TBM_STRIDE bits in the prefix starting at pos
 * returns:
 *  the bits in the prefix between lc_base(pos + plen) and pos + plen
 */
static inline btrie_oct_t next_pbyte(btrie_oct_t pbyte, unsigned pos,
		unsigned pfx)
{
	unsigned end = pos + TBM_STRIDE;

	if (end % 8 != 0) {
		btrie_oct_t nbyte = (btrie_oct_t) pfx << (8 - end % 8);
		if (end % 8 > TBM_STRIDE)
			nbyte |= pbyte & high_bits (pos % 8);
		return nbyte;
	}
	return 0;
}

/* construct a new TBM node, given the data and children of the
 * root prefix of the new node.
 */
static void init_tbm_node(struct btrie *btrie, node_t *dst, unsigned pos,
		const btrie_oct_t pbyte, const void **root_data_p, node_t *left,
		node_t *right)
{
	struct tbm_node *node = &dst->tbm_node;
	unsigned nchildren = 0;
	unsigned ndata = 0;
	node_t children[TBM_FANOUT];
	const void *data[TBM_FANOUT - 1];
	tbm_bitmap_t ext_bm = 0;
	tbm_bitmap_t int_bm = 0;
	unsigned i, d, pfx_base;

	if (left && is_lc_node (left) && lc_len (&left->lc_node) < TBM_STRIDE)
		convert_lc_node (btrie, &left->lc_node, pos + 1);
	if (right && is_lc_node (right) && lc_len (&right->lc_node) < TBM_STRIDE)
		convert_lc_node (btrie, &right->lc_node, pos + 1);

	/* set internal data for root prefix */
	if (root_data_p) {
		data[ndata++] = *root_data_p;
		int_bm |= bit (base_index (0, 0));
	}
	/* copy internal data from children */
	for (d = 0; d < TBM_STRIDE - 1; d++) {
		if (left && has_data (left)) {
			for (i = 0; i < 1U << d; i++) {
				const void **data_p = tbm_data_p (&left->tbm_node, i, d);
				if (data_p) {
					data[ndata++] = *data_p;
					int_bm |= bit (base_index (i, d + 1));
				}
			}
		}
		if (right && has_data (right)) {
			for (i = 0; i < 1U << d; i++) {
				const void **data_p = tbm_data_p (&right->tbm_node, i, d);
				if (data_p) {
					data[ndata++] = *data_p;
					int_bm |= bit (base_index (i + (1 << d), d + 1));
				}
			}
		}
	}

	/* copy extending paths */
	for (pfx_base = 0; pfx_base < TBM_FANOUT; pfx_base += TBM_FANOUT / 2) {
		node_t *child = pfx_base ? right : left;
		if (child == NULL) {
			continue;
		}
		else if (is_lc_node (child)) {
			unsigned pfx = pfx_base + lc_leading_bits (&child->lc_node, pos + 1,
			TBM_STRIDE - 1);
			/* child is LC node, just shorten it by TBM_STRIDE - 1 */
			shorten_lc_node (btrie, &children[nchildren++], pos + TBM_STRIDE,
					&child->lc_node, pos + 1);
			ext_bm |= bit (pfx);
		}
		else if (!is_empty_node (child)) {
			/* convert deepest internal prefixes of child to extending paths
			 * of the new node
			 */
			for (i = 0; i < TBM_FANOUT / 2; i++) {
				const void **data_p = tbm_data_p (&child->tbm_node, i,
						TBM_STRIDE - 1);
				node_t *left_ext = tbm_ext_path (&child->tbm_node, 2 * i);
				node_t *right_ext = tbm_ext_path (&child->tbm_node, 2 * i + 1);
				if (data_p || left_ext || right_ext) {
					node_t *ext_path = &children[nchildren++];
					unsigned pfx = pfx_base + i;
					btrie_oct_t npbyte = next_pbyte (pbyte, pos, pfx);

					ext_bm |= bit (pfx);
					if (left_ext == NULL && right_ext == NULL) {
						/* only have data - set ext_path to zero-length terminal LC node */
						lc_init_flags (&ext_path->lc_node, 1, 0);
						ext_path->lc_node.prefix[0] = npbyte;
						ext_path->lc_node.ptr.data = *data_p;
						btrie->n_lc_nodes++;
					}
					else if (data_p || (left_ext && right_ext)) {
						/* have at least two of data, left_ext, right_ext
						 * ext_path must be a full TBM node */
						init_tbm_node (btrie, ext_path, pos + TBM_STRIDE,
								npbyte, data_p, left_ext, right_ext);
					}
					else if (left_ext) {
						/* have only left_ext, insert length-one LC node */
						insert_lc_node (btrie, ext_path, pos + TBM_STRIDE,
								npbyte, 0, left_ext);
					}
					else {
						/* have only right_ext, insert length-one LC node */
						insert_lc_node (btrie, ext_path, pos + TBM_STRIDE,
								npbyte, 1, right_ext);
					}
				}
			}
			btrie->n_tbm_nodes--;
			free_nodes (btrie, child->tbm_node.ptr.children,
					count_bits (child->tbm_node.ext_bm),
					count_bits (child->tbm_node.int_bm));
		}
	}

	assert(count_bits (int_bm) == ndata);
	assert(count_bits (ext_bm) == nchildren);

	node->ptr.children = alloc_nodes (btrie, nchildren, ndata);
	memcpy(node->ptr.data_end - (int )ndata, data, ndata * sizeof(data[0]));
	memcpy(node->ptr.children, children, nchildren * sizeof(children[0]));
	node->ext_bm = ext_bm;
	node->int_bm = int_bm;
	btrie->n_tbm_nodes++;
}

static enum btrie_result add_to_trie(struct btrie *btrie, node_t *node,
		unsigned pos, const btrie_oct_t *prefix, unsigned len, const void *data)
{
	for (;;) {
		if (is_lc_node (node)) {
			struct lc_node *lc_node = &node->lc_node;
			unsigned end = pos + lc_len (lc_node);
			unsigned cbits = common_prefix (prefix + lc_shift (pos),
					lc_node->prefix, (len < end ? len : end) - lc_base (pos));
			unsigned clen = lc_base (pos) + cbits; /* position of first mismatch */

			if (clen == end && !lc_is_terminal (lc_node)) {
				/* matched entire prefix of LC node, proceed to child */
				assert(lc_len (lc_node) > 0);
				node = lc_node->ptr.child;
				pos = end;
			}
			else if (clen == end && len == end && lc_is_terminal (lc_node)) {
				/* exact match for terminal node - already have data for prefix */
				return BTRIE_DUPLICATE_PREFIX;
			}
			else {
				assert(clen < end || (lc_is_terminal (lc_node) && len > end));
				/* Need to insert new TBM node at clen */
				if (clen > pos) {
					split_lc_node (btrie, lc_node, pos, clen - pos);
					node = lc_node->ptr.child;
					assert(is_lc_node (node));
					pos = clen;
				}
				convert_lc_node (btrie, &node->lc_node, pos);
			}
		}
		else if (is_empty_node (node)) {
			/* at empty TBM node - just replace with terminal LC node */
			init_terminal_node (btrie, node, pos, prefix, len, data);
			btrie->n_entries++;
			btrie->n_tbm_nodes--;
			return BTRIE_OKAY;
		}
		else {
			struct tbm_node *tbm_node = &node->tbm_node;
			unsigned end = pos + TBM_STRIDE;

			if (len < end) {
				unsigned plen = len - pos;
				unsigned pfx = extract_bits (prefix, pos, plen);

				if (tbm_data_p (tbm_node, pfx, plen) != NULL)
					return BTRIE_DUPLICATE_PREFIX; /* prefix already has data */
				else {
					tbm_insert_data (btrie, tbm_node, pfx, plen, data);
					btrie->n_entries++;
					return BTRIE_OKAY;
				}
			}
			else {
				unsigned pfx = extract_bits (prefix, pos, TBM_STRIDE);

				/* follow extending path */
				node = tbm_ext_path (tbm_node, pfx);
				if (node == NULL)
					node = tbm_insert_ext_path (btrie, tbm_node, pfx);
				pos = end;
			}
		}
	}
}

static const void *
search_trie(const node_t *node, unsigned pos, const btrie_oct_t *prefix,
		unsigned len)
{
	/* remember last TBM node seen with internal data */
	const struct tbm_node *int_node = 0;
	unsigned int_pfx = 0, int_plen = 0;

	while (node) {
		if (is_lc_node (node)) {
			const struct lc_node *lc_node = &node->lc_node;
			unsigned end = pos + lc_len (lc_node);
			if (len < end)
				break;
			if (!prefixes_equal (prefix + lc_shift (pos), lc_node->prefix,
					end - lc_base (pos)))
				break;

			if (lc_is_terminal (lc_node))
				return lc_node->ptr.data; /* found terminal node */

			pos = end;
			node = lc_node->ptr.child;
		}
		else {
			const struct tbm_node *tbm_node = &node->tbm_node;
			unsigned end = pos + TBM_STRIDE;
			if (len < end) {
				unsigned plen = len - pos;
				unsigned pfx = extract_bits (prefix, pos, plen);
				if (has_internal_data (tbm_node, pfx, plen)) {
					int_node = tbm_node;
					int_pfx = pfx;
					int_plen = plen;
				}
				break;
			}
			else {
				unsigned pfx = extract_bits (prefix, pos, TBM_STRIDE);
				if (has_internal_data (tbm_node, pfx >> 1, TBM_STRIDE - 1)) {
					int_node = tbm_node;
					int_pfx = pfx >> 1;
					int_plen = TBM_STRIDE - 1;
				}
				pos = end;
				node = tbm_ext_path (tbm_node, pfx);
			}
		}
	}

	if (int_node) {
		const void **data_p = tbm_data_p (int_node, int_pfx, int_plen);
		while (data_p == NULL) {
			assert(int_plen > 0);
			int_pfx >>= 1;
			int_plen--;
			data_p = tbm_data_p (int_node, int_pfx, int_plen);
		}
		return *data_p;
	}

	return NULL;
}

struct btrie *
btrie_init(rspamd_mempool_t *mp)
{
	struct btrie *btrie;

	if (!(btrie = rspamd_mempool_alloc0 (mp, sizeof(*btrie)))) {
		return NULL;
	}

	btrie->mp = mp;
	btrie->alloc_total = sizeof(*btrie);

	/* count the empty root node */
	btrie->n_tbm_nodes = 1;

	return btrie;
}

enum btrie_result btrie_add_prefix(struct btrie *btrie,
		const btrie_oct_t *prefix, unsigned len, const void *data)
{
	enum btrie_result rv;
	if ((rv = setjmp (btrie->exception)) != 0)
		return rv; /* out of memory */

	return add_to_trie (btrie, &btrie->root, 0, prefix, len, data);
}

const void *
btrie_lookup(const struct btrie *btrie, const btrie_oct_t *prefix, unsigned len)
{
	return search_trie (&btrie->root, 0, prefix, len);
}

/****************************************************************
 *
 * btrie_stats() - statistics reporting
 */

#ifdef BTRIE_EXTENDED_STATS

/* Define BTRIE_EXTENDED_STATS to get extra statistics (including
 * trie depth).  This statistics require a traversal of the entire trie
 * to compute, and so are disabled by default.
 */

struct stats {
	size_t max_depth;
	size_t total_depth;
#ifndef NDEBUG
	size_t n_lc_nodes;
	size_t n_tbm_nodes;
	size_t n_entries;
	size_t alloc_data;
	size_t alloc_waste;
#endif
};

static void
node_stats(const node_t *node, size_t depth, struct stats *stats)
{
	if (depth > stats->max_depth)
	stats->max_depth = depth;
	stats->total_depth += depth;

	if (is_lc_node(node)) {
#ifndef NDEBUG
		stats->n_lc_nodes++;
#endif
		if (!lc_is_terminal(&node->lc_node))
		node_stats(node->lc_node.ptr.child, depth + 1, stats);
#ifndef NDEBUG
		else
		stats->n_entries++;
#endif
	}
	else {
		unsigned i;
		unsigned nchildren = count_bits(node->tbm_node.ext_bm);
#ifndef NDEBUG
		unsigned ndata = count_bits(node->tbm_node.int_bm);

		stats->n_tbm_nodes++;
		stats->n_entries += ndata;
		stats->alloc_data += ndata * sizeof(void *);
		stats->alloc_waste += (ndata % 2) * sizeof(void *);
#endif
		for (i = 0; i < nchildren; i++)
		node_stats(&node->tbm_node.ptr.children[i], depth + 1, stats);
	}
}
#endif /* BTRIE_EXTENDED_STATS */

#ifndef NDEBUG
static size_t count_free(const struct btrie *btrie)
{
	size_t total = 0;
	unsigned sz;
	for (sz = 1; sz <= MAX_CHILD_ARRAY_LEN; sz++) {
		const struct free_hunk *free = btrie->free_list[sz - 1];
		size_t n;
		for (n = 0; free; n++)
			free = free->next;
		total += sz * n;
	}
	return total * sizeof(node_t);
}
#endif /* not NDEBUG */

const char *
btrie_stats(const struct btrie *btrie, guint duplicates)
{
	static char buf[128];
	size_t n_nodes = btrie->n_lc_nodes + btrie->n_tbm_nodes;
	size_t alloc_free = (btrie->alloc_total + sizeof(node_t) /* do not double-count the root node */
	- n_nodes * sizeof(node_t) - btrie->alloc_data - btrie->alloc_waste
			- sizeof(*btrie));
#ifdef BTRIE_EXTENDED_STATS
	struct stats stats;
	double average_depth;

	memset(&stats, 0, sizeof(stats));
	node_stats(&btrie->root, 0, &stats);
	average_depth = (double)stats.total_depth / n_nodes;

#ifndef NDEBUG
	/* check the node counts */
	assert(stats.n_lc_nodes == btrie->n_lc_nodes);
	assert(stats.n_tbm_nodes == btrie->n_tbm_nodes);
	assert(stats.n_entries == btrie->n_entries);
	assert(stats.alloc_data == btrie->alloc_data);
	assert(stats.alloc_waste == btrie->alloc_waste);
#endif /* not NDEBUG */
#endif /* BTRIE_EXTENDED_STATS */

#ifndef NDEBUG
	/* check that we haven't lost any memory */
	assert(alloc_free == count_free (btrie));
#endif

#ifdef BTRIE_DEBUG_ALLOC
	dump_alloc_hist(btrie);
#endif


#ifdef BTRIE_EXTENDED_STATS
	snprintf(buf, sizeof(buf),
			"ents=%lu tbm=%lu lc=%lu mem=%.0fk free=%lu waste=%lu"
			" depth=%.1f/%lu"
			,(long unsigned)btrie->n_entries, (long unsigned)btrie->n_tbm_nodes,
			(long unsigned)btrie->n_lc_nodes, (double)btrie->alloc_total / 1024,
			(long unsigned)alloc_free, (long unsigned)btrie->alloc_waste
			, average_depth, (long unsigned)stats.max_depth);
#else
	snprintf(buf, sizeof(buf),
			"ents=%lu dup=%u tbm=%lu lc=%lu mem=%.0fk free=%lu waste=%lu",
			(long unsigned)btrie->n_entries,
			duplicates,
			(long unsigned)btrie->n_tbm_nodes,
			(long unsigned)btrie->n_lc_nodes, (double)btrie->alloc_total / 1024,
			(long unsigned)alloc_free, (long unsigned)btrie->alloc_waste
			);
#endif
	buf[sizeof(buf) - 1] = '\0';
	return buf;
}

/****************************************************************/

#ifndef NO_MASTER_DUMP

struct walk_context
{
	btrie_walk_cb_t *callback;
	void *user_data;

	btrie_oct_t prefix[(BTRIE_MAX_PREFIX + 7) / 8];
};

static void
walk_node(const node_t *node, unsigned pos, struct walk_context *ctx);

static void walk_tbm_node(const struct tbm_node *node, unsigned pos,
		unsigned pfx, unsigned plen, struct walk_context *ctx)
{
	btrie_oct_t *prefix = ctx->prefix;
	int pbyte = pos / 8;
	btrie_oct_t pbit = 0x80 >> (pos % 8);
	const void **data_p = tbm_data_p (node, pfx, plen);

	if (pos >= BTRIE_MAX_PREFIX) {
		/* This can/should not happen, but don't overwrite buffers if it does. */
		return;
	}

	if (data_p)
		ctx->callback (prefix, pos, *data_p, 0, ctx->user_data);

	/* walk children */
	if (plen < TBM_STRIDE - 1) {
		/* children are internal prefixes in same node */
		walk_tbm_node (node, pos + 1, pfx << 1, plen + 1, ctx);
		prefix[pbyte] |= pbit;
		walk_tbm_node (node, pos + 1, (pfx << 1) + 1, plen + 1, ctx);
		prefix[pbyte] &= ~pbit;
	}
	else {
		/* children are extending paths */
		const node_t *ext_path;
		if ((ext_path = tbm_ext_path (node, pfx << 1)) != NULL)
			walk_node (ext_path, pos + 1, ctx);
		if ((ext_path = tbm_ext_path (node, (pfx << 1) + 1)) != NULL) {
			prefix[pbyte] |= pbit;
			walk_node (ext_path, pos + 1, ctx);
			prefix[pbyte] &= ~pbit;
		}
	}

	if (data_p)
		ctx->callback (prefix, pos, *data_p, 1, ctx->user_data);
}

static void walk_lc_node(const struct lc_node *node, unsigned pos,
		struct walk_context *ctx)
{
	btrie_oct_t *prefix = ctx->prefix;
	unsigned end = pos + lc_len (node);
	btrie_oct_t save_prefix = prefix[lc_shift (pos)];

	if (end > BTRIE_MAX_PREFIX) {
		/* This can/should not happen, but don't overwrite buffers if it does. */
		return;
	}

	/* construct full prefix to node */
	memcpy(&prefix[lc_shift (pos)], node->prefix, lc_bytes (node, pos));
	if (end % 8)
		prefix[end / 8] &= high_bits (end % 8);

	if (lc_is_terminal (node)) {
		ctx->callback (prefix, end, node->ptr.data, 0, ctx->user_data);
		ctx->callback (prefix, end, node->ptr.data, 1, ctx->user_data);
	}
	else
		walk_node (node->ptr.child, end, ctx);

	prefix[lc_shift (pos)] = save_prefix; /* restore parents prefix */
	if (lc_bytes (node, pos) > 1)
		memset(&prefix[lc_shift (pos) + 1], 0, lc_bytes (node, pos) - 1);
}

static void walk_node(const node_t *node, unsigned pos,
		struct walk_context *ctx)
{
	if (is_lc_node (node))
		walk_lc_node (&node->lc_node, pos, ctx);
	else
		walk_tbm_node (&node->tbm_node, pos, 0, 0, ctx);
}

/* walk trie in lexicographical order
 *
 * calls callback twice (once preorder, once postorder) at each prefix
 */
void btrie_walk(const struct btrie *btrie, btrie_walk_cb_t *callback,
		void *user_data)
{
	struct walk_context ctx;

	memset(&ctx, 0, sizeof(ctx));
	ctx.callback = callback;
	ctx.user_data = user_data;

	walk_node (&btrie->root, 0, &ctx);
}

#endif /* not NO_MASTER_DUMP */


#ifdef TEST
/*****************************************************************
 *
 * Unit tests
 *
 */
#include <stdio.h>

#ifndef UNUSED
# define UNUSED __attribute__((unused))
#endif

/* bogus replacements mp_alloc for running self-tests */
void *
mp_alloc(UNUSED struct mempool *mp, unsigned sz, UNUSED int align)
{
	return malloc(sz);
}

#if 0
# define PASS(name) puts("OK " name)
#else
# define PASS(name) fputs(".", stdout); fflush(stdout)
#endif

const char * pgm_name = "???";

static void
test_struct_node_packing()
{
	node_t node;

	assert(sizeof(struct tbm_node) == 2 * sizeof(void *));
	assert(sizeof(struct lc_node) == 2 * sizeof(void *));
	assert(sizeof(node_t) == 2 * sizeof(void *));

	/* The lc_node bit must be an alias for bit zero of int_bm, since
	 * that is the only unused bit in the TBM node structure.
	 */
	memset(&node, 0, sizeof(node));
	assert(node.tbm_node.int_bm == 0);
	lc_init_flags(&node.lc_node, 0, 0);
	assert(node.tbm_node.int_bm == bit(0));

	PASS("test_struct_node_packing");
}

static void
test_bit()
{
	tbm_bitmap_t ones = ~(tbm_bitmap_t)0;
	tbm_bitmap_t high_bit = ones ^ (ones >> 1);

	assert(bit(0) == high_bit);
	assert(bit(1) == high_bit >> 1);
	assert(bit(8 * sizeof(tbm_bitmap_t) - 1) == 1);
	PASS("test_bit");
}

static void
test_count_bits()
{
	unsigned max_bits = sizeof(tbm_bitmap_t) * 8;
	tbm_bitmap_t ones = ~(tbm_bitmap_t)0;

	assert(count_bits(0) == 0);
	assert(count_bits(1) == 1);
	assert(count_bits(2) == 1);
	assert(count_bits(3) == 2);
	assert(count_bits(ones) == max_bits);
	assert(count_bits(~1) == max_bits - 1);

	/* count_bits(0x5555....) */
	assert(count_bits(ones / 3) == max_bits / 2);
	/* count_bits(0x3333...) */
	assert(count_bits(ones / 5) == max_bits / 2);
	/* count_bits(0x0f0f...) */
	assert(count_bits(ones / 17) == max_bits / 2);
	/* count_bits(0x1010...) */
	assert(count_bits(ones / 255) == max_bits / 8);

	PASS("test_count_bits");
}

static void
test_count_bits_before()
{
	unsigned max_bits = sizeof(tbm_bitmap_t) * 8;
	tbm_bitmap_t ones = ~(tbm_bitmap_t)0;
	unsigned i;

	for (i = 0; i < max_bits; i++) {
		assert(count_bits_before(0, i) == 0);
		assert(count_bits_before(ones, i) == i);
	}

	PASS("test_count_bits_before");
}

static void
test_count_bits_from()
{
	unsigned max_bits = sizeof(tbm_bitmap_t) * 8;
	tbm_bitmap_t ones = ~(tbm_bitmap_t)0;
	unsigned i;

	for (i = 0; i < max_bits; i++) {
		assert(count_bits_from(0, i) == 0);
		assert(count_bits_from(ones, i) == max_bits - i);
	}

	PASS("test_count_bits_from");
}

static void
test_extract_bits()
{
	static btrie_oct_t prefix[] = {0xff, 0x55, 0xaa, 0x00};
	unsigned i;

	for (i = 0; i < 32; i++)
	assert(extract_bits(prefix, i, 0) == 0);

	for (i = 0; i < 8; i++)
	assert(extract_bits(prefix, i, 1) == 1);
	for (i = 8; i < 16; i++)
	assert(extract_bits(prefix, i, 1) == i % 2);
	for (i = 16; i < 24; i++)
	assert(extract_bits(prefix, i, 1) == (i + 1) % 2);
	for (i = 24; i < 32; i++)
	assert(extract_bits(prefix, i, 1) == 0);

	assert(extract_bits(prefix, 2, 6) == 0x3f);
	assert(extract_bits(prefix, 3, 6) == 0x3e);
	assert(extract_bits(prefix, 4, 6) == 0x3d);
	assert(extract_bits(prefix, 5, 6) == 0x3a);
	assert(extract_bits(prefix, 6, 6) == 0x35);
	assert(extract_bits(prefix, 7, 6) == 0x2a);
	assert(extract_bits(prefix, 8, 6) == 0x15);

	PASS("test_extract_bits");
}

static void
test_high_bits()
{
	assert(high_bits(0) == 0x00);
	assert(high_bits(1) == 0x80);
	assert(high_bits(2) == 0xc0);
	assert(high_bits(3) == 0xe0);
	assert(high_bits(4) == 0xf0);
	assert(high_bits(5) == 0xf8);
	assert(high_bits(6) == 0xfc);
	assert(high_bits(7) == 0xfe);
	assert(high_bits(8) == 0xff);
	PASS("test_high_bits");
}

static void
test_prefixes_equal()
{
	btrie_oct_t prefix1[LC_BYTES_PER_NODE];
	btrie_oct_t prefix2[LC_BYTES_PER_NODE];
	unsigned i;
	memset(prefix1, 0xaa, LC_BYTES_PER_NODE);
	memset(prefix2, 0xaa, LC_BYTES_PER_NODE);

	for (i = 0; i < 8 * LC_BYTES_PER_NODE; i++) {
		assert(prefixes_equal(prefix1, prefix2, i));
		prefix1[i / 8] ^= 1 << (7 - i % 8);
		assert(!prefixes_equal(prefix1, prefix2, 8 * LC_BYTES_PER_NODE));
		assert(prefixes_equal(prefix1, prefix2, i));
		if (i + 1 < 8 * LC_BYTES_PER_NODE)
		assert(!prefixes_equal(prefix1, prefix2, i + 1));
		prefix1[i / 8] ^= 1 << (7 - i % 8);
	}
	PASS("test_prefixes_equal");
}

static void
test_common_prefix()
{
	btrie_oct_t prefix1[LC_BYTES_PER_NODE];
	btrie_oct_t prefix2[LC_BYTES_PER_NODE];
	unsigned i;
	memset(prefix1, 0x55, LC_BYTES_PER_NODE);
	memset(prefix2, 0x55, LC_BYTES_PER_NODE);

	for (i = 0; i < 8 * LC_BYTES_PER_NODE; i++) {
		assert(common_prefix(prefix1, prefix2, i) == i);
		prefix1[i / 8] ^= 1 << (7 - i % 8);
		assert(common_prefix(prefix1, prefix2, 8 * LC_BYTES_PER_NODE) == i);
		if (i + 1 < 8 * LC_BYTES_PER_NODE)
		assert(common_prefix(prefix1, prefix2, i+1) == i);
		prefix1[i / 8] ^= 1 << (7 - i % 8);
	}
	PASS("test_common_prefix");
}

static void
test_base_index()
{
	assert(base_index(0,0) == 1);
	assert(base_index(0,1) == 2);
	assert(base_index(1,1) == 3);
	assert(base_index(0,2) == 4);
	assert(base_index(1,2) == 5);
	assert(base_index(2,2) == 6);
	assert(base_index(3,2) == 7);
	PASS("test_base_index");
}

static void
test_has_internal_data()
{
	struct tbm_node node;
	unsigned plen, pfx, bi;
	for (plen = 0; plen < TBM_STRIDE; plen++) {
		for (pfx = 0; pfx < 1U << plen; pfx++) {
			tbm_bitmap_t ancestor_mask = 0;
			for (bi = base_index(pfx, plen); bi; bi >>= 1) {
				node.int_bm = bit(bi);
				ancestor_mask |= bit(bi);
				assert(has_internal_data(&node, pfx, plen));
			}
			node.int_bm = ~ancestor_mask;
			assert(!has_internal_data(&node, pfx, plen));
		}
	}
	PASS("test_has_internal_data");
}

/****************************************************************/
static const btrie_oct_t numbered_bytes[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
};

static void
check_non_terminal_lc_node(struct lc_node *node, unsigned len)
{
	assert(is_lc_node((node_t *)node));
	assert(!lc_is_terminal(node));
	assert(lc_len(node) == len);
}

static void
check_terminal_lc_node(struct lc_node *node, unsigned len, const void *data)
{
	assert(is_lc_node((node_t *)node));
	assert(lc_is_terminal(node));
	assert(lc_len(node) == len);
	assert(node->ptr.data == data);
}

static void
test_init_terminal_node()
{
	struct btrie *btrie = btrie_init(NULL);
	const void *data = (void *)0xdeadbeef;
	node_t node;
	struct lc_node *head = &node.lc_node;

	init_terminal_node(btrie, &node, 0,
			numbered_bytes, 8 * LC_BYTES_PER_NODE, data);
	check_terminal_lc_node(head, 8 * LC_BYTES_PER_NODE, data);
	assert(memcmp(head->prefix, numbered_bytes, LC_BYTES_PER_NODE) == 0);

	init_terminal_node(btrie, &node, 7,
			numbered_bytes, 8 * LC_BYTES_PER_NODE, data);
	check_terminal_lc_node(head, 8 * LC_BYTES_PER_NODE - 7, data);
	assert(memcmp(head->prefix, numbered_bytes, LC_BYTES_PER_NODE) == 0);

	init_terminal_node(btrie, &node, 0,
			numbered_bytes, 2 * 8 * LC_BYTES_PER_NODE, data);
	check_non_terminal_lc_node(head, 8 * LC_BYTES_PER_NODE);
	assert(memcmp(head->prefix, numbered_bytes, LC_BYTES_PER_NODE) == 0);
	{
		struct lc_node *child = &head->ptr.child->lc_node;
		check_terminal_lc_node(child, 8 * LC_BYTES_PER_NODE, data);
		assert(memcmp(child->prefix, &numbered_bytes[LC_BYTES_PER_NODE],
						LC_BYTES_PER_NODE) == 0);
	}

	init_terminal_node(btrie, &node, 15,
			numbered_bytes, 8 * LC_BYTES_PER_NODE + 15, data);
	check_non_terminal_lc_node(head, 8 * LC_BYTES_PER_NODE - 7);
	assert(memcmp(head->prefix, &numbered_bytes[1], LC_BYTES_PER_NODE) == 0);
	{
		struct lc_node *child = &head->ptr.child->lc_node;
		check_terminal_lc_node(child, 7, data);
		assert(child->prefix[0] == numbered_bytes[LC_BYTES_PER_NODE + 1]);
	}

	PASS("test_init_terminal_node");
}

static void
test_coalesce_lc_node()
{
	struct btrie *btrie = btrie_init(NULL);
	const void *data = (void *)0xdeadbeef;
	node_t node;
	struct lc_node *head = &node.lc_node;

	/* test merging */
	init_terminal_node(btrie, &node, 0,
			numbered_bytes, 8 * (LC_BYTES_PER_NODE + 1), data);
	check_non_terminal_lc_node(head, LC_BYTES_PER_NODE * 8);
	lc_add_to_len(head, -8);
	coalesce_lc_node(btrie, head, 8);
	check_terminal_lc_node(head, LC_BYTES_PER_NODE * 8, data);
	assert(head->prefix[LC_BYTES_PER_NODE - 1]
			== numbered_bytes[LC_BYTES_PER_NODE]);

	/* test bit stealing */
	init_terminal_node(btrie, &node, 0,
			numbered_bytes, 8 * (2 * LC_BYTES_PER_NODE), data);
	check_non_terminal_lc_node(head, LC_BYTES_PER_NODE * 8);
	lc_add_to_len(head, -15);
	coalesce_lc_node(btrie, head, 15);
	check_non_terminal_lc_node(head, LC_BYTES_PER_NODE * 8 - 7);
	assert(memcmp(head->prefix, numbered_bytes, LC_BYTES_PER_NODE - 1) == 0);
	assert(head->prefix[LC_BYTES_PER_NODE - 1]
			== numbered_bytes[LC_BYTES_PER_NODE]);
	{
		struct lc_node *child = &head->ptr.child->lc_node;
		check_terminal_lc_node(child, 8 * (LC_BYTES_PER_NODE - 1), data);
		assert(memcmp(child->prefix, &numbered_bytes[LC_BYTES_PER_NODE + 1],
						LC_BYTES_PER_NODE - 1) == 0);
	}

	PASS("test_coalesce_lc_node");
}

static void
test_shorten_lc_node()
{
	struct btrie *btrie = btrie_init(NULL);
	const void *data = (void *)0xdeadbeef;
	node_t node, shorter;

	/* test shorten without shift */
	init_terminal_node(btrie, &node, 0,
			numbered_bytes, 8 * LC_BYTES_PER_NODE, data);
	memset(shorter.lc_node.prefix, 0xff, LC_BYTES_PER_NODE);
	shorten_lc_node(btrie, &shorter, 7, &node.lc_node, 0);
	check_terminal_lc_node(&shorter.lc_node, LC_BYTES_PER_NODE * 8 - 7, data);
	assert(memcmp(shorter.lc_node.prefix, numbered_bytes, LC_BYTES_PER_NODE)
			== 0);

	/* test shorten with shift */
	init_terminal_node(btrie, &node, 7,
			numbered_bytes, 8 * LC_BYTES_PER_NODE, data);
	memset(shorter.lc_node.prefix, 0xff, LC_BYTES_PER_NODE);
	shorten_lc_node(btrie, &shorter, 9, &node.lc_node, 7);
	check_terminal_lc_node(&shorter.lc_node, LC_BYTES_PER_NODE * 8 - 9, data);
	assert(memcmp(shorter.lc_node.prefix, &numbered_bytes[1],
					LC_BYTES_PER_NODE - 1) == 0);

	{
		/* test child stealing */
		struct lc_node head;
		node_t tail, shorter;

		lc_init_flags(&head, 0, 7);
		head.ptr.child = &tail;
		init_empty_node(btrie, &tail);

		shorten_lc_node(btrie, &shorter, 7, &head, 0);
		assert(is_empty_node(&shorter));
	}

	PASS("test_shorten_lc_node");
}

static void
test_split_lc_node()
{
	struct btrie *btrie = btrie_init(NULL);
	const void *data = (void *)0xdeadbeef;
	struct lc_node node;

	init_terminal_node(btrie, (node_t *)&node, 1, numbered_bytes, 25, data);
	split_lc_node(btrie, &node, 1, 8);
	check_non_terminal_lc_node(&node, 8);
	check_terminal_lc_node(&node.ptr.child->lc_node, 16, data);

	/* test conversion of terminal to non-terminal */
	init_terminal_node(btrie, (node_t *)&node, 7, numbered_bytes, 10, data);
	split_lc_node(btrie, &node, 7, 3);
	check_non_terminal_lc_node(&node, 3);
	check_terminal_lc_node(&node.ptr.child->lc_node, 0, data);

	PASS("test_split_lc_node");
}

static void
test_convert_lc_node_1()
{
	struct btrie *btrie = btrie_init(NULL);
	const void *data = (void *)0xdeadbeef;
	struct lc_node head;

	/* test tail is left */
	lc_init_flags(&head, 0, 1);
	head.prefix[0] = 0;
	head.ptr.child = alloc_nodes(btrie, 1, 0);
	init_terminal_node(btrie, head.ptr.child, 1, numbered_bytes, 1, data);
	convert_lc_node_1(btrie, &head, 0);
	{
		node_t *result = (node_t *)&head;
		assert(is_tbm_node(result));
		assert(result->tbm_node.ext_bm == 0);
		assert(result->tbm_node.int_bm == bit(base_index(0, 1)));
		assert(*tbm_data_p(&result->tbm_node, 0, 1) == data);
	}

	/* test tail is right */
	lc_init_flags(&head, 0, 1);
	head.prefix[0] = 1;
	head.ptr.child = alloc_nodes(btrie, 1, 0);
	init_terminal_node(btrie, head.ptr.child, 8, numbered_bytes, 10, data);
	convert_lc_node_1(btrie, &head, 7);
	{
		node_t *result = (node_t *)&head;
		assert(is_tbm_node(result));
		assert(result->tbm_node.ext_bm == 0);
		assert(result->tbm_node.int_bm == bit(base_index(4, 3)));
		assert(*tbm_data_p(&result->tbm_node, 4, 3) == data);
	}

	PASS("test_convert_lc_node_1");
}

static void
test_convert_lc_node()
{
	struct btrie *btrie = btrie_init(NULL);
	const void *data = (void *)0xdeadbeef;
	node_t node;

	/* if (len >= TBM_STRIDE) */
	init_terminal_node(btrie, &node, 7, numbered_bytes, TBM_STRIDE + 7, data);
	convert_lc_node(btrie, &node.lc_node, 7);
	assert(is_tbm_node(&node));
	assert(node.tbm_node.ext_bm == bit(0));
	assert(node.tbm_node.int_bm == 0);
	check_terminal_lc_node(&tbm_ext_path(&node.tbm_node, 0)->lc_node, 0, data);

	/* if (lc_is_terminal(node)) */
	init_terminal_node(btrie, &node, 0, numbered_bytes, 0, data);
	convert_lc_node(btrie, &node.lc_node, 0);
	assert(is_tbm_node(&node));
	assert(node.tbm_node.ext_bm == 0);
	assert(node.tbm_node.int_bm == bit(base_index(0, 0)));
	assert(*tbm_data_p(&node.tbm_node, 0, 0) == data);

	/* else */
	lc_init_flags(&node.lc_node, 0, TBM_STRIDE - 1);
	node.lc_node.prefix[0] = 0;
	node.lc_node.ptr.child = alloc_nodes(btrie, 1, 0);
	init_empty_node(btrie, node.lc_node.ptr.child);
	tbm_insert_data(btrie, &node.lc_node.ptr.child->tbm_node, 0, 0, data);

	convert_lc_node(btrie, &node.lc_node, 0);
	assert(is_tbm_node(&node));
	assert(node.tbm_node.ext_bm == 0);
	assert(node.tbm_node.int_bm == bit(base_index(0, TBM_STRIDE - 1)));
	assert(*tbm_data_p(&node.tbm_node, 0, TBM_STRIDE - 1) == data);

	PASS("test_convert_lc_node");
}

static void
test_insert_lc_node()
{
	struct btrie *btrie = btrie_init(NULL);
	const void *data = (void *)0xdeadbeef;
	node_t node, tail;

	/* test optimized case, last_bit == 0 */
	init_terminal_node(btrie, &tail, 9, numbered_bytes, 17, data);
	insert_lc_node(btrie, &node, 8, 0, 0, &tail);
	check_terminal_lc_node(&node.lc_node, 9, data);
	assert(memcmp(node.lc_node.prefix, &numbered_bytes[1], 2) == 0);

	/* test optimized case, last_bit == 1 */
	init_terminal_node(btrie, &tail, 7, &numbered_bytes[0x12], 15, data);
	insert_lc_node(btrie, &node, 6, 0x10, 1, &tail);
	check_terminal_lc_node(&node.lc_node, 9, data);
	assert(node.lc_node.prefix[0] == 0x12);
	assert(node.lc_node.prefix[1] == 0x13);

	/* test with shift */
	init_terminal_node(btrie, &tail, 0, numbered_bytes, 8, data);
	insert_lc_node(btrie, &node, 7, 0x40, 1, &tail);
	check_terminal_lc_node(&node.lc_node, 9, data);
	assert(node.lc_node.prefix[0] == 0x41);
	assert(node.lc_node.prefix[1] == numbered_bytes[0]);

	/* test with TBM node */
	init_empty_node(btrie, &tail);
	insert_lc_node(btrie, &node, 6, 0x40, 0, &tail);
	check_non_terminal_lc_node(&node.lc_node, 1);
	assert(is_tbm_node(node.lc_node.ptr.child));

	PASS("test_insert_lc_node");
}

static void
test_next_pbyte()
{
	assert(next_pbyte(0xff, 0, 1) == 0x80 >> (TBM_STRIDE - 1));
	assert(next_pbyte(0xff, 1, 1) == (0x80 | (0x80 >> TBM_STRIDE)));
	assert(next_pbyte(0xff, 2, 1) == (0xc0 | (0x80 >> (TBM_STRIDE + 1))));
	assert(next_pbyte(0xff, 8 - TBM_STRIDE, 1) == 0);
	assert(next_pbyte(0xff, 9 - TBM_STRIDE, 1) == 0x80);

	PASS("test_next_pbyte");
}

static void
test_init_tbm_node()
{
	struct btrie *btrie = btrie_init(NULL);
	const void *data = (void *)0xdeadbeef;
	unsigned lr;
	node_t node;

	/* test root data */
	init_tbm_node(btrie, &node, 0, 0, &data, NULL, NULL);
	assert(is_tbm_node(&node));
	assert(node.tbm_node.ext_bm == 0);
	assert(node.tbm_node.int_bm == bit(base_index(0, 0)));
	assert(*tbm_data_p(&node.tbm_node, 0, 0) == data);

	for (lr = 0; lr < 2; lr++) {
		node_t child;
		node_t *left = lr ? NULL : &child;
		node_t *right = lr ? &child : NULL;
		unsigned base = lr ? (1U << (TBM_STRIDE - 1)) : 0;
		unsigned pfx;

		/* test with long LC node child */
		init_terminal_node(btrie, &child, 1, numbered_bytes, TBM_STRIDE + 1, data);
		init_tbm_node(btrie, &node, 0, 0, NULL, left, right);
		assert(is_tbm_node(&node));
		assert(node.tbm_node.ext_bm == bit(base));
		assert(node.tbm_node.int_bm == 0);
		check_terminal_lc_node(&tbm_ext_path(&node.tbm_node, base)->lc_node,
				1, data);

		/* test with short LC node children */
		init_terminal_node(btrie, &child, 1, numbered_bytes, TBM_STRIDE - 1, data);
		init_tbm_node(btrie, &node, 0, 0, NULL, left, right);
		assert(is_tbm_node(&node));
		assert(node.tbm_node.ext_bm == 0);
		assert(node.tbm_node.int_bm == bit(base_index(base >> 1, TBM_STRIDE-1)));
		assert(*tbm_data_p(&node.tbm_node, base >> 1, TBM_STRIDE-1) == data);

		/* construct TBM node with all eight combinations of having data,
		 * left_ext and/or right_ext in its extending paths */
		init_empty_node(btrie, &child);
		for (pfx = 0; pfx < 8; pfx++) {
			if (pfx & 1)
			tbm_insert_data(btrie, &child.tbm_node, pfx, TBM_STRIDE - 1, data);
			if (pfx & 2) {
				btrie_oct_t prefix0 = 0;
				init_terminal_node(btrie,
						tbm_insert_ext_path(btrie, &child.tbm_node, 2*pfx),
						TBM_STRIDE + 1,
						&prefix0, TBM_STRIDE + 2, data);
			}
			if (pfx & 4) {
				btrie_oct_t prefix0 = 0x80 >> TBM_STRIDE;
				init_terminal_node(btrie,
						tbm_insert_ext_path(btrie, &child.tbm_node, 2*pfx+1),
						TBM_STRIDE + 1,
						&prefix0, TBM_STRIDE + 3, data);
			}
		}
		init_tbm_node(btrie, &node, 0, 0, NULL, left, right);
		for (pfx = 0; pfx < 8; pfx++) {
			unsigned base = lr ? (1U << (TBM_STRIDE - 1)) : 0;
			node_t *ext_path = tbm_ext_path(&node.tbm_node, base + pfx);
			if (pfx == 0)
			assert(ext_path == NULL);
			else if (pfx == 1)
			check_terminal_lc_node(&ext_path->lc_node, 0, data);
			else if (pfx == 2) {
				check_terminal_lc_node(&ext_path->lc_node, 2, data);
				assert(ext_path->lc_node.prefix[0] == 0);
			}
			else if (pfx == 4) {
				check_terminal_lc_node(&ext_path->lc_node, 3, data);
				assert(ext_path->lc_node.prefix[0] == (0x80 >> TBM_STRIDE));
			}
			else {
				tbm_bitmap_t int_bm = 0;
				assert(is_tbm_node(ext_path));
				if (pfx & 1) {
					int_bm |= bit(base_index(0, 0));
					assert(*tbm_data_p(&ext_path->tbm_node, 0, 0) == data);
				}
				if (pfx & 2) {
					int_bm |= bit(base_index(0, 2));
					assert(*tbm_data_p(&ext_path->tbm_node, 0, 2) == data);
				}
				if (pfx & 4) {
					int_bm |= bit(base_index(4, 3));
					assert(*tbm_data_p(&ext_path->tbm_node, 4, 3) == data);
				}
				assert(ext_path->tbm_node.int_bm == int_bm);
			}
		}
	}

	PASS("test_init_tbm_node");
}

static void
test_add_to_trie()
{
	struct btrie *btrie = btrie_init(NULL);
	const void *data = (void *)0xdeadbeef;
	enum btrie_result result;
	unsigned pfx, plen;
	node_t root;

	/* test initial insertion */
	init_empty_node(btrie, &root);
	result = add_to_trie(btrie, &root, 0,
			numbered_bytes, 8 * 2 * LC_BYTES_PER_NODE, data);
	assert(result == BTRIE_OKAY);
	check_non_terminal_lc_node(&root.lc_node, 8 * LC_BYTES_PER_NODE);
	check_terminal_lc_node(&root.lc_node.ptr.child->lc_node,
			8 * LC_BYTES_PER_NODE, data);

	/* test can follow LC node to tail, and then detect duplicate prefix */
	result = add_to_trie(btrie, &root, 0,
			numbered_bytes, 8 * 2 * LC_BYTES_PER_NODE, data);
	assert(result == BTRIE_DUPLICATE_PREFIX);

	/* test can insert new TBM node within existing LC node */
	result = add_to_trie(btrie, &root, 0,
			&numbered_bytes[1], 16, data);
	assert(result == BTRIE_OKAY);
	check_non_terminal_lc_node(&root.lc_node, 7);
	assert(is_tbm_node(root.lc_node.ptr.child));

	/* test can convert terminal LC node to TBM node */
	init_terminal_node(btrie, &root, 0, numbered_bytes, 12, data);
	result = add_to_trie(btrie, &root, 0, numbered_bytes, 24, data);
	assert(result == BTRIE_OKAY);
	check_non_terminal_lc_node(&root.lc_node, 12);
	assert(is_tbm_node(root.lc_node.ptr.child));

	/* test can insert internal prefix data in TBM node */
	for (plen = 0; plen < TBM_STRIDE; plen++) {
		for (pfx = 0; pfx < (1U << plen); pfx++) {
			btrie_oct_t prefix0 = plen ? pfx << (8 - plen) : 0;
			init_empty_node(btrie, &root);
			init_terminal_node(btrie, tbm_insert_ext_path(btrie, &root.tbm_node, 0),
					TBM_STRIDE,
					numbered_bytes, 8, data);
			result = add_to_trie(btrie, &root, 0, &prefix0, plen, data);
			assert(result == BTRIE_OKAY);
			assert(is_tbm_node(&root));
			assert(root.tbm_node.ext_bm == bit(0));
			assert(root.tbm_node.int_bm == bit(base_index(pfx, plen)));
			assert(*tbm_data_p(&root.tbm_node, pfx, plen) == data);

			result = add_to_trie(btrie, &root, 0, &prefix0, plen, data);
			assert(result == BTRIE_DUPLICATE_PREFIX);
		}
	}

	/* test can add extending paths to TBM node */
	for (pfx = 0; pfx < (1U << TBM_STRIDE); pfx++) {
		btrie_oct_t prefix0 = pfx << (8 - TBM_STRIDE);
		init_empty_node(btrie, &root);
		tbm_insert_data(btrie, &root.tbm_node, 0, 0, data);
		result = add_to_trie(btrie, &root, 0, &prefix0, 8, data);
		assert(result == BTRIE_OKAY);
		assert(is_tbm_node(&root));
		assert(root.tbm_node.ext_bm == bit(pfx));
		assert(root.tbm_node.int_bm == bit(base_index(0, 0)));
		check_terminal_lc_node(&tbm_ext_path(&root.tbm_node, pfx)->lc_node,
				8 - TBM_STRIDE, data);

		result = add_to_trie(btrie, &root, 0, &prefix0, 8, data);
		assert(result == BTRIE_DUPLICATE_PREFIX);
	}

	/* test can follow extending path */
	init_empty_node(btrie, &root);
	init_terminal_node(btrie,
			tbm_insert_ext_path(btrie, &root.tbm_node, 0), TBM_STRIDE,
			numbered_bytes, 8, data);
	result = add_to_trie(btrie, &root, 0, numbered_bytes, 7, data);
	assert(result == BTRIE_OKAY);
	assert(root.tbm_node.ext_bm == bit(0));
	assert(root.tbm_node.int_bm == 0);
	check_non_terminal_lc_node(&root.tbm_node.ptr.children[0].lc_node,
			7 - TBM_STRIDE);

	PASS("test_add_to_trie");
}

static void
test_search_trie()
{
	struct btrie *btrie = btrie_init(NULL);
	const void *data01 = (void *)0xdead0001;
	const void *data11 = (void *)0xdead0101;
	const void *data = (void *)0xdeadbeef;
	unsigned plen, pfx;
	node_t root;

	/* test can follow chain of LC nodes to an exact match */
	init_empty_node(btrie, &root);
	add_to_trie(btrie, &root, 0,
			numbered_bytes, 8 * 2 * LC_BYTES_PER_NODE, data);

	assert(search_trie(&root, 0, numbered_bytes, 8 * 2 * LC_BYTES_PER_NODE)
			== data);
	assert(search_trie(&root, 0, numbered_bytes, 8 * 2 * LC_BYTES_PER_NODE + 1)
			== data);
	assert(search_trie(&root, 0, numbered_bytes, 8 * 2 * LC_BYTES_PER_NODE - 1)
			== NULL);
	assert(search_trie(&root, 0, &numbered_bytes[1], 8 * 2 * LC_BYTES_PER_NODE)
			== NULL);

	/* test can follow extending path to an exact match */
	for (pfx = 0; pfx < (1U << TBM_STRIDE); pfx++) {
		btrie_oct_t prefix0 = pfx << (8 - TBM_STRIDE);
		init_empty_node(btrie, &root);
		tbm_insert_data(btrie, &root.tbm_node, 0, 1, data01);
		tbm_insert_data(btrie, &root.tbm_node, 1, 1, data11);
		add_to_trie(btrie, &root, 0, &prefix0, 8, data);
		assert(search_trie(&root, 0, &prefix0, 8) == data);
		/* test that last matching TBM internal prefix gets picked up */
		if (prefix0 & 0x80)
		assert(search_trie(&root, 0, &prefix0, 7) == data11);
		else
		assert(search_trie(&root, 0, &prefix0, 7) == data01);
		prefix0 ^= 1 << (8 - TBM_STRIDE);
		if (prefix0 & 0x80)
		assert(search_trie(&root, 0, &prefix0, 8) == data11);
		else
		assert(search_trie(&root, 0, &prefix0, 8) == data01);
	}

	/* test finding of TBM internal prefixes */
	init_empty_node(btrie, &root);
	tbm_insert_data(btrie, &root.tbm_node, 0, 1, data01);
	tbm_insert_data(btrie, &root.tbm_node, 1, 1, data11);

	assert(search_trie(&root, 0, numbered_bytes, 0) == NULL);
	for (plen = 1; plen < TBM_STRIDE; plen++) {
		for (pfx = 0; pfx < (1U << TBM_STRIDE); pfx++) {
			btrie_oct_t prefix0 = pfx << (8 - plen);
			if (prefix0 & 0x80)
			assert(search_trie(&root, 0, &prefix0, plen) == data11);
			else
			assert(search_trie(&root, 0, &prefix0, plen) == data01);
		}
	}

	PASS("test_search_trie");
}

static int
unit_tests()
{
	test_struct_node_packing();
	test_bit();
	test_count_bits();
	test_count_bits_before();
	test_count_bits_from();
	test_extract_bits();
	test_high_bits();
	test_prefixes_equal();
	test_common_prefix();
	test_base_index();
	test_has_internal_data();

	test_init_terminal_node();
	test_coalesce_lc_node();
	test_shorten_lc_node();
	test_split_lc_node();
	test_convert_lc_node_1();
	test_convert_lc_node();
	test_insert_lc_node();
	test_next_pbyte();
	test_init_tbm_node();
	test_add_to_trie();
	test_search_trie();

	puts("\nOK");
	return 0;
}

/*****************************************************************
 *
 * btrie_dump: print out the trie structure (for testing)
 *
 */
#define INDENT_FILL "....:....|....:....|....:....|....:....|"

static void dump_node(const node_t *node, unsigned pos, btrie_oct_t *prefix,
		int indent);

static void
dump_prefix(btrie_oct_t *prefix, unsigned len, int indent, const char *tail)
{
	unsigned i;

	printf("%*.*s0x", indent, indent, INDENT_FILL);
	for (i = 0; i < len / 8; i++)
	printf("%02x", prefix[i]);
	if (len % 8)
	printf("%02x", prefix[len / 8] & high_bits(len % 8));
	printf("/%u%s", len, tail);
}

/* the opposite of extract_bits, sets a short string of bits from integer */
static void
insert_bits(btrie_oct_t *prefix, unsigned pos, btrie_oct_t pfx, unsigned nbits)
{
	if (nbits != 0) {
		unsigned v = (prefix[pos / 8] << 8) + prefix[pos / 8 + 1];
		unsigned mask = (1U << nbits) - 1;
		unsigned shift = 16 - (pos % 8) - nbits;
		v = (v & ~(mask << shift)) | (pfx << shift);
		prefix[pos / 8] = v >> 8;
		prefix[pos / 8 + 1] = (btrie_oct_t)v;
	}
}

static void
dump_tbm_node(const struct tbm_node *node, unsigned pos,
		btrie_oct_t *prefix, int indent)
{
	unsigned pfx = 0, plen = 0;

	dump_prefix(prefix, pos, indent, " [tbm]\n");

	for (;;) {
		if (plen < TBM_STRIDE) {
			const void **data_p = tbm_data_p(node, pfx, plen);
			if (data_p) {
				insert_bits(prefix, pos, pfx, plen);
				dump_prefix(prefix, pos + plen, indent, "");
				printf(" [%u/%u] (%s)\n", pfx, plen, (const char *)*data_p);
			}
			plen++;
			pfx <<= 1;
		}
		else {
			const node_t *ext_path = tbm_ext_path(node, pfx);
			if (ext_path) {
				insert_bits(prefix, pos, pfx, TBM_STRIDE);
				dump_node(ext_path, pos + TBM_STRIDE, prefix, indent + 1);
			}
			while (pfx & 1) {
				if (--plen == 0)
				return;
				pfx >>= 1;
			}
			pfx++;
		}
	}
}

static void
dump_lc_node(const struct lc_node *node, unsigned pos,
		btrie_oct_t *prefix, int indent)
{
	unsigned end = pos + lc_len(node);
	btrie_oct_t save_prefix = prefix[lc_shift(pos)];

	memcpy(&prefix[lc_shift(pos)], node->prefix, lc_bytes(node, pos));

	if (lc_is_terminal(node)) {
		dump_prefix(prefix, end, indent, "");
		printf(" (%s)\n", (const char *)node->ptr.data);
	}
	else {
		dump_prefix(prefix, end, indent, "\n");
		dump_node(node->ptr.child, end, prefix, indent + 1);
	}

	prefix[lc_shift(pos)] = save_prefix;
	if (lc_bytes(node, pos) > 1)
	memset(&prefix[lc_shift(pos) + 1], 0, lc_bytes(node, pos) - 1);
}

static void
dump_node(const node_t *node, unsigned pos, btrie_oct_t *prefix, int indent)
{
	if (is_lc_node(node))
	dump_lc_node(&node->lc_node, pos, prefix, indent);
	else
	dump_tbm_node(&node->tbm_node, pos, prefix, indent);
}

static void
btrie_dump(struct btrie *btrie)
{
	btrie_oct_t prefix[(BTRIE_MAX_PREFIX + 7) / 8];

	memset(prefix, 0, sizeof(prefix));
	dump_node(&btrie->root, 0, prefix, 0);
	puts(btrie_stats(btrie));
}

/****************************************************************
 *
 * test program - just enough to construct a trie and preform a lookup
 *
 */

#include <arpa/inet.h>

static int
parse_prefix(const char *arg, btrie_oct_t prefix[16], unsigned *len)
{
	char addrbuf[128];
	return sscanf(arg, "%127[0-9a-fA-F:]/%u", addrbuf, len) == 2
	&& inet_pton(AF_INET6, addrbuf, prefix) == 1;
}

static int
test_btrie(int argc, char *argv[])
{
	struct btrie *btrie = btrie_init(NULL);
	int i;
	btrie_oct_t prefix[16];
	unsigned len;

	for (i = 1; i < argc-1; i++) {
		if (!parse_prefix(argv[i], prefix, &len)) {
			fprintf(stderr, "Can not parse arg '%s'\n", argv[i]);
			return 1;
		}
		btrie_add_prefix(btrie, prefix, len, argv[i]);
	}

	btrie_dump(btrie);

	if (argc > 1) {
		const void *data;

		if (!parse_prefix(argv[argc-1], prefix, &len)) {
			fprintf(stderr, "Can not parse arg '%s'\n", argv[argc-1]);
			return 1;
		}
		data = btrie_lookup(btrie, prefix, 128);
		printf("lookup(%s) => %s\n", argv[argc-1], (const char *)data);
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	if ((pgm_name = strrchr(argv[0], '/')) != NULL)
	pgm_name++;
	else
	pgm_name = argv[0];

	if (argc > 1)
	return test_btrie(argc, argv);
	else
	return unit_tests();
}

#endif /* TEST */
