/*
 * Copyright (c) 2016, Vsevolod Stakhov
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
#include "learn_cache.h"
#include "rspamd.h"
#include "stat_api.h"
#include "stat_internal.h"
#include "cryptobox.h"
#include "ucl.h"
#include "hiredis/hiredis.h"
#include "hiredis/adapters/libevent.h"

gpointer
rspamd_stat_cache_redis_init (struct rspamd_stat_ctx *ctx,
		struct rspamd_config *cfg,
		struct rspamd_statfile *st,
		const ucl_object_t *cf)
{
	return NULL;
}

gpointer
rspamd_stat_cache_redis_runtime (struct rspamd_task *task,
		gpointer ctx)
{
	return NULL;
}

gint
rspamd_stat_cache_redis_check (struct rspamd_task *task,
		gboolean is_spam,
		gpointer runtime,
		gpointer c)
{
	return RSPAMD_LEARN_OK;
}

gint
rspamd_stat_cache_redis_learn (struct rspamd_task *task,
		gboolean is_spam,
		gpointer runtime,
		gpointer c)
{
	return RSPAMD_LEARN_OK;
}

void
rspamd_stat_cache_redis_close (gpointer c)
{

}
