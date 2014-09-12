/* Copyright (c) 2011, Vsevolod Stakhov
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

#include "config.h"
#include "tests.h"
#include "main.h"
#include "dkim.h"

static const gchar test_dkim_sig[] = "v=1; a=rsa-sha256; c=relaxed/relaxed; "
		"d=highsecure.ru; s=dkim; t=1410516996; "
		"bh=guFoWYHWVzFRqVyAQebnvPcdm7bUQo7pRHt/uIHD7gs=; "
		"h=Message-ID:Date:From:MIME-Version:To:Subject:Content-Type:Content-Transfer-Encoding; "
		"b=PCiECkOaPFb99DW+gApgfmdlTUo6XN6YXjnj52Cxoz2FoA857B0ZHFgeQe4JAKHuhW"
		"oq3BLHap0GcMTTpSOgfQOKa8Df35Ns11JoOFjdBQ8GpM99kOrJP+vZcT8b7AMfthYm0Kwy"
		"D9TjlkpScuoY5LjsWVnijh9dSNVLFqLatzg=;";

extern struct event_base *base;

static void
test_key_handler (rspamd_dkim_key_t *key, gsize keylen, rspamd_dkim_context_t *ctx, gpointer ud, GError *err)
{
	struct rspamd_async_session *s = ud;
	g_assert (key != NULL);

	destroy_session (s);
}

static gboolean
session_fin (gpointer unused)
{
	struct timeval tv;

	tv.tv_sec = 0;
	tv.tv_usec = 0;
	event_loopexit (&tv);

	return TRUE;
}

void
rspamd_dkim_test_func ()
{
	rspamd_dkim_context_t *ctx;
	rspamd_dkim_key_t *key;
	rspamd_mempool_t *pool;
	struct rspamd_dns_resolver *resolver;
	struct rspamd_config *cfg;
	GError *err = NULL;
	struct rspamd_async_session *s;

	cfg = (struct rspamd_config *)g_malloc (sizeof (struct rspamd_config));
	bzero (cfg, sizeof (struct rspamd_config));
	cfg->cfg_pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());
	cfg->dns_retransmits = 2;
	cfg->dns_timeout = 0.5;

	pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());

	resolver = dns_resolver_init (NULL, base, cfg);

	g_assert (resolver != NULL);

	ctx = rspamd_create_dkim_context (test_dkim_sig, pool, 0, &err);

	g_assert (ctx != NULL);

	/* Key part */
	s = new_async_session (pool, session_fin, NULL, NULL, NULL);

	g_assert (rspamd_get_dkim_key (ctx, resolver, s, test_key_handler, s));

	event_base_loop (base, 0);
}
