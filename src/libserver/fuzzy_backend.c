/* Copyright (c) 2014, Vsevolod Stakhov
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
#include "main.h"
#include "fuzzy_backend.h"
#include "fuzzy_storage.h"


struct rspamd_fuzzy_backend;

struct
rspamd_fuzzy_backend* rspamd_fuzzy_backend_open (const gchar *path,
		GError **err)
{

}

struct rspamd_fuzzy_reply
rspamd_fuzzy_backend_check (struct rspamd_fuzzy_backend *backend,
		const struct rspamd_fuzzy_cmd *cmd)
{

}

gboolean
rspamd_fuzzy_backend_add (struct rspamd_fuzzy_backend *backend,
		const struct rspamd_fuzzy_cmd *cmd)
{

}


gboolean
rspamd_fuzzy_backend_del (struct rspamd_fuzzy_backend *backend,
		const struct rspamd_fuzzy_cmd *cmd)
{

}

gboolean
rspamd_fuzzy_backend_sync (struct rspamd_fuzzy_backend *backend)
{

}


void
rspamd_fuzzy_backend_close (struct rspamd_fuzzy_backend *backend)
{

}
