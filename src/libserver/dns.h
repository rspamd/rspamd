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

#ifndef RSPAMD_DNS_H
#define RSPAMD_DNS_H

#include "config.h"
#include "mem_pool.h"
#include "events.h"
#include "logger.h"
#include "rdns.h"
#include "upstream.h"

struct rspamd_config;

struct rspamd_dns_resolver {
	struct rdns_resolver *r;
	struct event_base *ev_base;
	struct upstream_list *ups;
	struct rspamd_config *cfg;
	gdouble request_timeout;
	guint max_retransmits;
};

/* Rspamd DNS API */

/**
 * Init DNS resolver, params are obtained from a config file or system file /etc/resolv.conf
 */
struct rspamd_dns_resolver * rspamd_dns_resolver_init (rspamd_logger_t *logger,
													   struct event_base *ev_base, struct rspamd_config *cfg);

struct rspamd_dns_request_ud;
/**
 * Make a DNS request
 * @param resolver resolver object
 * @param session async session to register event
 * @param pool memory pool for storage
 * @param cb callback to call on resolve completing
 * @param ud user data for callback
 * @param type request type
 * @param ... string or ip address based on a request type
 * @return TRUE if request was sent.
 */
struct rspamd_dns_request_ud * rspamd_dns_resolver_request (struct rspamd_dns_resolver *resolver,
															struct rspamd_async_session *session,
															rspamd_mempool_t *pool,
															dns_callback_type cb,
															gpointer ud,
															enum rdns_request_type type,
															const char *name);

gboolean rspamd_dns_resolver_request_task (struct rspamd_task *task,
										   dns_callback_type cb,
										   gpointer ud,
										   enum rdns_request_type type,
										   const char *name);

gboolean rspamd_dns_resolver_request_task_forced (struct rspamd_task *task,
												  dns_callback_type cb,
												  gpointer ud,
												  enum rdns_request_type type,
												  const char *name);

#endif
