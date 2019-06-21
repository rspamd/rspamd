/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "tests.h"
#include "rspamd.h"
#include "dkim.h"

static const gchar test_dkim_sig[] = "v=1; a=rsa-sha256; c=relaxed/relaxed; "
		"d=highsecure.ru; s=dkim; t=1410516996; "
		"bh=guFoWYHWVzFRqVyAQebnvPcdm7bUQo7pRHt/uIHD7gs=; "
		"h=Message-ID:Date:From:MIME-Version:To:Subject:Content-Type:Content-Transfer-Encoding; "
		"b=PCiECkOaPFb99DW+gApgfmdlTUo6XN6YXjnj52Cxoz2FoA857B0ZHFgeQe4JAKHuhW"
		"oq3BLHap0GcMTTpSOgfQOKa8Df35Ns11JoOFjdBQ8GpM99kOrJP+vZcT8b7AMfthYm0Kwy"
		"D9TjlkpScuoY5LjsWVnijh9dSNVLFqLatzg=;";

extern struct ev_loop *event_loop;
#if 0
static void
test_key_handler (rspamd_dkim_key_t *key, gsize keylen, rspamd_dkim_context_t *ctx, gpointer ud, GError *err)
{
	struct rspamd_async_session *s = ud;
	g_assert (key != NULL);

	rspamd_session_destroy (s);
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
#endif
void
rspamd_dkim_test_func ()
{
#if 0
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
	s = rspamd_session_create (pool, session_fin, NULL, NULL, NULL);

	g_assert (rspamd_get_dkim_key (ctx, resolver, s, test_key_handler, s));

	event_base_loop (base, 0);
#endif
}
