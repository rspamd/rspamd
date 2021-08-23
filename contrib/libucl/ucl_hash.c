/* Copyright (c) 2013, Vsevolod Stakhov
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

#include "ucl_internal.h"
#include "ucl_hash.h"
#include "khash.h"
#include "utlist.h"

#include "cryptobox.h"
#include "libutil/str_util.h"
#include "ucl.h"

#include <time.h>
#include <limits.h>

struct ucl_hash_elt {
	const ucl_object_t *obj;
	struct ucl_hash_elt *prev, *next;
};

struct ucl_hash_struct {
	void *hash;
	struct ucl_hash_elt *head;
	bool caseless;
};

static uint64_t
ucl_hash_seed (void)
{
	static uint64_t seed;
	if (seed == 0) {
#ifdef UCL_RANDOM_FUNCTION
		seed = UCL_RANDOM_FUNCTION;
#else
		/* Not very random but can be useful for our purposes */
		seed = time (NULL);
#endif
	}

	return seed;
}

extern const guchar lc_map[256];

static inline uint32_t
ucl_hash_func (const ucl_object_t *o)
{
	return (uint32_t)rspamd_cryptobox_fast_hash (o->key, o->keylen, 0xb9a1ef83c4561c95ULL);
}

static inline int
ucl_hash_equal (const ucl_object_t *k1, const ucl_object_t *k2)
{
	if (k1->keylen == k2->keylen) {
		return memcmp (k1->key, k2->key, k1->keylen) == 0;
	}

	return 0;
}

KHASH_INIT (ucl_hash_node, const ucl_object_t *, struct ucl_hash_elt *, 1,
		ucl_hash_func, ucl_hash_equal)

static inline uint32_t
ucl_hash_caseless_func (const ucl_object_t *o)
{
	unsigned len = o->keylen;
	unsigned leftover = o->keylen % 4;
	unsigned fp, i;
	const uint8_t* s = (const uint8_t*)o->key;
	union {
		struct {
			unsigned char c1, c2, c3, c4;
		} c;
		uint32_t pp;
	} u;
	uint64_t h = 0xe5ae6ab1ef9f3b54ULL;
	rspamd_cryptobox_fast_hash_state_t hst;

	fp = len - leftover;
	rspamd_cryptobox_fast_hash_init (&hst, h);

	for (i = 0; i != fp; i += 4) {
		u.c.c1 = s[i], u.c.c2 = s[i + 1], u.c.c3 = s[i + 2], u.c.c4 = s[i + 3];
		u.c.c1 = lc_map[u.c.c1];
		u.c.c2 = lc_map[u.c.c2];
		u.c.c3 = lc_map[u.c.c3];
		u.c.c4 = lc_map[u.c.c4];
		rspamd_cryptobox_fast_hash_update (&hst, &u, sizeof (u));
	}

	u.pp = 0;
	switch (leftover) {
	case 3:
		u.c.c3 = lc_map[(unsigned char)s[i++]];
	case 2:
		/* fallthrough */
		u.c.c2 = lc_map[(unsigned char)s[i++]];
	case 1:
		/* fallthrough */
		u.c.c1 = lc_map[(unsigned char)s[i]];
		rspamd_cryptobox_fast_hash_update (&hst, &u, sizeof (u));
		break;
	}

	return (uint32_t)rspamd_cryptobox_fast_hash_final (&hst);
}


static inline bool
ucl_hash_caseless_equal (const ucl_object_t *k1, const ucl_object_t *k2)
{
	if (k1->keylen == k2->keylen) {
		return rspamd_lc_cmp (k1->key, k2->key, k1->keylen) == 0;
	}

	return false;
}

KHASH_INIT (ucl_hash_caseless_node, const ucl_object_t *, struct ucl_hash_elt *, 1,
		ucl_hash_caseless_func, ucl_hash_caseless_equal)

ucl_hash_t*
ucl_hash_create (bool ignore_case)
{
	ucl_hash_t *new;

	new = UCL_ALLOC (sizeof (ucl_hash_t));
	if (new != NULL) {
		void *h;
		new->head = NULL;
		new->caseless = ignore_case;
		if (ignore_case) {
			h = (void *)kh_init (ucl_hash_caseless_node);
		}
		else {
			h = (void *)kh_init (ucl_hash_node);
		}
		if (h == NULL) {
			UCL_FREE (sizeof (ucl_hash_t), new);
			return NULL;
		}
		new->hash = h;
	}
	return new;
}

void ucl_hash_destroy (ucl_hash_t* hashlin, ucl_hash_free_func func)
{

	if (hashlin == NULL) {
		return;
	}

	if (func != NULL) {
		/* Iterate over the hash first */
		khash_t(ucl_hash_node) *h = (khash_t(ucl_hash_node) *)
				hashlin->hash;
		khiter_t k;
		const ucl_object_t *cur, *tmp;

		for (k = kh_begin (h); k != kh_end (h); ++k) {
			if (kh_exist (h, k)) {
				cur = (kh_value (h, k))->obj;
				while (cur != NULL) {
					tmp = cur->next;
					func (__DECONST (ucl_object_t *, cur));
					cur = tmp;
				}
			}
		}
	}

	if (hashlin->caseless) {
		khash_t(ucl_hash_caseless_node) *h = (khash_t(ucl_hash_caseless_node) *)
				hashlin->hash;
		kh_destroy (ucl_hash_caseless_node, h);
	}
	else {
		khash_t(ucl_hash_node) *h = (khash_t(ucl_hash_node) *)
				hashlin->hash;
		kh_destroy (ucl_hash_node, h);
	}

	struct ucl_hash_elt *cur, *tmp;

	DL_FOREACH_SAFE(hashlin->head, cur, tmp) {
		UCL_FREE(sizeof(*cur), cur);
	}

	UCL_FREE (sizeof (*hashlin), hashlin);
}

bool
ucl_hash_insert (ucl_hash_t* hashlin, const ucl_object_t *obj,
				 const char *key, unsigned keylen)
{
	khiter_t k;
	int ret;
	struct ucl_hash_elt **pelt, *elt;

	if (hashlin == NULL) {
		return false;
	}

	if (hashlin->caseless) {
		khash_t(ucl_hash_caseless_node) *h = (khash_t(ucl_hash_caseless_node) *)
				hashlin->hash;
		k = kh_put (ucl_hash_caseless_node, h, obj, &ret);
		if (ret > 0) {
			elt = UCL_ALLOC(sizeof(*elt));
			pelt = &kh_value (h, k);
			*pelt = elt;
			DL_APPEND(hashlin->head, elt);
			elt->obj = obj;
		}
		else if (ret < 0) {
			goto e0;
		}
	}
	else {
		khash_t(ucl_hash_node) *h = (khash_t(ucl_hash_node) *)
				hashlin->hash;
		k = kh_put (ucl_hash_node, h, obj, &ret);
		if (ret > 0) {
			elt = UCL_ALLOC(sizeof(*elt));
			pelt = &kh_value (h, k);
			*pelt = elt;
			DL_APPEND(hashlin->head, elt);
			elt->obj = obj;
		} else if (ret < 0) {
			goto e0;
		}
	}
	return true;
	e0:
	return false;
}

void ucl_hash_replace (ucl_hash_t* hashlin, const ucl_object_t *old,
					   const ucl_object_t *new)
{
	khiter_t k;
	int ret;
	struct ucl_hash_elt *elt, *nelt;

	if (hashlin == NULL) {
		return;
	}

	if (hashlin->caseless) {
		khash_t(ucl_hash_caseless_node) *h = (khash_t(ucl_hash_caseless_node) *)
				hashlin->hash;
		k = kh_put (ucl_hash_caseless_node, h, old, &ret);
		if (ret == 0) {
			elt = kh_value(h, k);
			kh_del (ucl_hash_caseless_node, h, k);
			k = kh_put (ucl_hash_caseless_node, h, new, &ret);
			nelt = UCL_ALLOC(sizeof(*nelt));
			nelt->obj = new;
			kh_value(h, k) = nelt;
			DL_REPLACE_ELEM(hashlin->head, elt, nelt);
			UCL_FREE(sizeof(*elt), elt);
		}
	}
	else {
		khash_t(ucl_hash_node) *h = (khash_t(ucl_hash_node) *)
				hashlin->hash;
		k = kh_put (ucl_hash_node, h, old, &ret);
		if (ret == 0) {
			elt = kh_value (h, k);
			kh_del (ucl_hash_node, h, k);
			k = kh_put (ucl_hash_node, h, new, &ret);
			nelt = UCL_ALLOC(sizeof(*nelt));
			nelt->obj = new;
			kh_value(h, k) = nelt;
			DL_REPLACE_ELEM(hashlin->head, elt, nelt);
			UCL_FREE(sizeof(*elt), elt);
		}
	}
}

struct ucl_hash_real_iter {
	const struct ucl_hash_elt *cur;
};

#define UHI_SETERR(ep, ern) {if (ep != NULL) *ep = (ern);}

const void*
ucl_hash_iterate2 (ucl_hash_t *hashlin, ucl_hash_iter_t *iter, int *ep)
{
	struct ucl_hash_real_iter *it = (struct ucl_hash_real_iter *)(*iter);
	const ucl_object_t *ret = NULL;

	if (hashlin == NULL) {
		UHI_SETERR(ep, EINVAL);
		return NULL;
	}

	if (it == NULL) {
		it = UCL_ALLOC (sizeof (*it));

		if (it == NULL) {
			UHI_SETERR(ep, ENOMEM);
			return NULL;
		}

		it->cur = hashlin->head;
	}

	UHI_SETERR(ep, 0);
	if (it->cur) {
		ret = it->cur->obj;
		it->cur = it->cur->next;
	}
	else {
		UCL_FREE (sizeof (*it), it);
		*iter = NULL;
		return NULL;
	}

	*iter = it;

	return ret;
}

bool
ucl_hash_iter_has_next (ucl_hash_t *hashlin, ucl_hash_iter_t iter)
{
	struct ucl_hash_real_iter *it = (struct ucl_hash_real_iter *)(iter);

	return it->cur != NULL;
}


const ucl_object_t*
ucl_hash_search (ucl_hash_t* hashlin, const char *key, unsigned keylen)
{
	khiter_t k;
	const ucl_object_t *ret = NULL;
	ucl_object_t search;
	struct ucl_hash_elt *elt;

	search.key = key;
	search.keylen = keylen;

	if (hashlin == NULL) {
		return NULL;
	}

	if (hashlin->caseless) {
		khash_t(ucl_hash_caseless_node) *h = (khash_t(ucl_hash_caseless_node) *)
				hashlin->hash;

		k = kh_get (ucl_hash_caseless_node, h, &search);
		if (k != kh_end (h)) {
			elt = kh_value (h, k);
			ret = elt->obj;
		}
	}
	else {
		khash_t(ucl_hash_node) *h = (khash_t(ucl_hash_node) *)
				hashlin->hash;
		k = kh_get (ucl_hash_node, h, &search);
		if (k != kh_end (h)) {
			elt = kh_value (h, k);
			ret = elt->obj;
		}
	}

	return ret;
}

void
ucl_hash_delete (ucl_hash_t* hashlin, const ucl_object_t *obj)
{
	khiter_t k;
	struct ucl_hash_elt *elt;

	if (hashlin == NULL) {
		return;
	}

	if (hashlin->caseless) {
		khash_t(ucl_hash_caseless_node) *h = (khash_t(ucl_hash_caseless_node) *)
				hashlin->hash;

		k = kh_get (ucl_hash_caseless_node, h, obj);
		if (k != kh_end (h)) {
			elt = kh_value (h, k);
			DL_DELETE(hashlin->head, elt);
			kh_del (ucl_hash_caseless_node, h, k);
			UCL_FREE(sizeof(*elt), elt);
		}
	}
	else {
		khash_t(ucl_hash_node) *h = (khash_t(ucl_hash_node) *)
				hashlin->hash;
		k = kh_get (ucl_hash_node, h, obj);
		if (k != kh_end (h)) {
			elt = kh_value (h, k);
			DL_DELETE(hashlin->head, elt);
			kh_del (ucl_hash_node, h, k);
			UCL_FREE(sizeof(*elt), elt);
		}
	}
}

bool
ucl_hash_reserve (ucl_hash_t *hashlin, size_t sz)
{
	if (hashlin == NULL) {
		return false;
	}

	if (sz > kh_size((khash_t(ucl_hash_node) *)hashlin->hash)) {
		if (hashlin->caseless) {
			khash_t(ucl_hash_caseless_node) *h = (khash_t(
					ucl_hash_caseless_node) *)
					hashlin->hash;
			kh_resize (ucl_hash_caseless_node, h, sz * 2);
		} else {
			khash_t(ucl_hash_node) *h = (khash_t(ucl_hash_node) *)
					hashlin->hash;
			kh_resize (ucl_hash_node, h, sz * 2);
		}
	}

	return true;
}

static int
ucl_hash_cmp_icase (const void *a, const void *b)
{
	const struct ucl_hash_elt *oa = (const struct ucl_hash_elt *)a,
		*ob = (const struct ucl_hash_elt *)b;

	if (oa->obj->keylen == ob->obj->keylen) {
		return rspamd_lc_cmp (oa->obj->key, ob->obj->key, oa->obj->keylen);
	}

	return ((int)(oa->obj->keylen)) - ob->obj->keylen;
}

static int
ucl_hash_cmp_case_sens (const void *a, const void *b)
{
	const struct ucl_hash_elt *oa = (const struct ucl_hash_elt *)a,
			*ob = (const struct ucl_hash_elt *)b;

	if (oa->obj->keylen == ob->obj->keylen) {
		return memcmp (oa->obj->key, ob->obj->key, oa->obj->keylen);
	}

	return ((int)(oa->obj->keylen)) - ob->obj->keylen;
}

void
ucl_hash_sort (ucl_hash_t *hashlin, enum ucl_object_keys_sort_flags fl)
{

	if (fl & UCL_SORT_KEYS_ICASE) {
		DL_SORT(hashlin->head, ucl_hash_cmp_icase);
	}
	else {
		DL_SORT(hashlin->head, ucl_hash_cmp_case_sens);
	}

	if (fl & UCL_SORT_KEYS_RECURSIVE) {
		struct ucl_hash_elt *elt;

		DL_FOREACH(hashlin->head, elt) {
			if (ucl_object_type (elt->obj) == UCL_OBJECT) {
				ucl_hash_sort (elt->obj->value.ov, fl);
			}
		}
	}
}