/*-
 * Copyright 2022 Vsevolod Stakhov
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


#ifndef RSPAMD_SYMCACHE_PERIODIC_HXX
#define RSPAMD_SYMCACHE_PERIODIC_HXX

#pragma once

#include "config.h"
#include "contrib/libev/ev.h"
#include "symcache_internal.hxx"
#include "worker_util.h"

namespace rspamd::symcache {
struct cache_refresh_cbdata {
private:
	symcache *cache;
	struct ev_loop *event_loop;
	struct rspamd_worker *w;
	double reload_time;
	double last_resort;
	ev_timer resort_ev;

public:
	explicit cache_refresh_cbdata(symcache *_cache,
								  struct ev_loop *_ev_base,
								  struct rspamd_worker *_w)
		: cache(_cache), event_loop(_ev_base), w(_w)
	{
		auto log_tag = [&]() { return cache->log_tag(); };
		last_resort = rspamd_get_ticks(TRUE);
		reload_time = cache->get_reload_time();
		auto tm = rspamd_time_jitter(reload_time, 0);
		msg_debug_cache("next reload in %.2f seconds", tm);
		ev_timer_init(&resort_ev, cache_refresh_cbdata::resort_cb,
					  tm, tm);
		resort_ev.data = (void *) this;
		ev_timer_start(event_loop, &resort_ev);
		rspamd_mempool_add_destructor(cache->get_pool(),
									  cache_refresh_cbdata::refresh_dtor, (void *) this);
	}

	static void refresh_dtor(void *d)
	{
		auto *cbdata = (struct cache_refresh_cbdata *) d;
		delete cbdata;
	}

	static void resort_cb(EV_P_ ev_timer *w, int _revents)
	{
		auto *cbdata = (struct cache_refresh_cbdata *) w->data;

		auto log_tag = [&]() { return cbdata->cache->log_tag(); };

		if (rspamd_worker_is_primary_controller(cbdata->w)) {
			/* Plan new event */
			auto tm = rspamd_time_jitter(cbdata->reload_time, 0);
			msg_debug_cache("resort symbols cache, next reload in %.2f seconds", tm);
			cbdata->resort_ev.repeat = tm;
			ev_timer_again(EV_A_ w);
			auto cur_time = rspamd_get_ticks(FALSE);
			cbdata->cache->periodic_resort(cbdata->event_loop, cur_time, cbdata->last_resort);
			cbdata->last_resort = cur_time;
		}
	}

private:
	~cache_refresh_cbdata()
	{
		ev_timer_stop(event_loop, &resort_ev);
	}
};
}// namespace rspamd::symcache

#endif//RSPAMD_SYMCACHE_PERIODIC_HXX
