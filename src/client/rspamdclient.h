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

#ifndef RSPAMDCLIENT_H_
#define RSPAMDCLIENT_H_

#include "config.h"
#include "ucl.h"

/**
 * Callback is called on client request completed
 * @param name name of server
 * @param port port for server
 * @param result result object
 * @param ud opaque user data
 * @param err error pointer (should be freed if not NULL)
 */
typedef void (*rspamd_client_callback) (
		const gchar *name,
		guint16 port,
		ucl_object_t *result,
		gpointer ud,
		GError *err);

/**
 * Start rspamd worker or controller command
 * @param ev_base event base
 * @param name server name (hostname or unix socket)
 * @param command command name
 * @param attrs additional attributes
 * @param port port number (in host order)
 * @param timeout timeout in seconds
 * @param in input file or NULL if no input required
 * @param ud opaque user data
 * @return
 */
gboolean rspamd_client_command (
		struct event_base *ev_base,
		const gchar *name,
		guint16 port,
		const gchar *command,
		GHashTable *attrs,
		gdouble timeout,
		FILE *in,
		gpointer ud);

#endif /* RSPAMDCLIENT_H_ */
