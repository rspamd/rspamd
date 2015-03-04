/*
 * Copyright (c) 2015, Vsevolod Stakhov
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

#include "config.h"
#include "regexp.h"
#include "blake2.h"
#include "ref.h"
#include <pcre.h>

struct rspamd_regexp_s {
	gdouble exec_time;			   /**< average execution time								*/
	pcre *re;
	pcre_extra *extra;
	pcre *raw_re;
	pcre_extra *raw_extra;
	guchar id[BLAKE2B_OUTBYTES / 2];
	ref_entry_t ref;
};

struct rspamd_regexp_cache {
	GHashTable *tbl;
};

static struct rspamd_regexp_cache *global_re_cache = NULL;

rspamd_regexp_t*
rspamd_regexp_new (const gchar *pattern, const gchar *flags,
		GError **err)
{
	return NULL;
}

gboolean
rspamd_regexp_search (rspamd_regexp_t *re, const gchar *text, gsize len)
{
	return FALSE;
}

gboolean
rspamd_regexp_match (rspamd_regexp_t *re, const gchar *text, gsize len)
{
	return FALSE;
}

void
rspamd_regexp_unref (rspamd_regexp_t *re)
{
	REF_RELEASE (re);
}

struct rspamd_regexp_cache*
rspamd_regexp_cache_new (void)
{
	return NULL;
}


rspamd_regexp_t*
rspamd_regexp_cache_query (struct rspamd_regexp_cache* cache,
		const gchar *pattern,
		const gchar *flags)
{
	return NULL;
}


rspamd_regexp_t*
rspamd_regexp_cache_create (struct rspamd_regexp_cache *cache,
		const gchar *pattern,
		const gchar *flags, GError **err)
{
	return NULL;
}

void
rspamd_regexp_cache_destroy (struct rspamd_regexp_cache *cache)
{

}
