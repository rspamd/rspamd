--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

--[[[
-- @module dynamic_conf
-- Deprecated: the dynamic configuration of symbol scores, action thresholds and enabled symbols is
-- served by the `lua_dynconf` framework now (see the `dynconf` section). This module does nothing but
-- tell that. Its section, `dynamic_conf { redis_key, servers, ... }`, only tells the framework where the
-- data of the previous Redis based implementation is, to import it once, and only when the dynconf
-- backend is Redis: nothing switches the backend automatically, so the module reports an error at every
-- start while a section with Redis servers is configured and the backend is not Redis (or dynconf is
-- disabled altogether).
--]]

local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"
local lua_redis = require "lua_redis"
local N = "dynamic_conf"

if confighelp then
  return
end

local section = rspamd_config:get_all_opt(N)

if not section then
  lua_util.disable_module(N, "config")
  return
end

local backend = require("lua_dynconf").backend()

if backend == 'redis' then
  rspamd_logger.warnx(rspamd_config, 'the %s module is deprecated and replaced by the dynconf framework: ' ..
      'its redis data is imported into dynconf once, and the section can be removed afterwards', N)
elseif type(section) == 'table' and lua_redis.parse_redis_server(N, section) then
  if backend then
    rspamd_logger.errx(rspamd_config, 'the %s module is deprecated and replaced by the dynconf framework, ' ..
        'and its redis data is NOT applied: the dynconf backend is "%s". Set `dynconf { backend = "redis"; }` ' ..
        'to apply it (it is imported into dynconf once, at the first start with the redis backend)',
        N, backend)
  else
    -- `enabled = false` (or a dynconf section that cannot be loaded, see the log) switches everything
    -- off whatever the backend is, so setting the backend alone would not help
    rspamd_logger.errx(rspamd_config, 'the %s module is deprecated and replaced by the dynconf framework, ' ..
        'and its redis data is NOT applied: dynconf is disabled (`enabled = false`, or its configuration is ' ..
        'invalid). Enable dynconf and set `dynconf { backend = "redis"; }` to apply it (it is imported into ' ..
        'dynconf once, at the first start with the redis backend)', N)
  end
else
  rspamd_logger.warnx(rspamd_config, 'the %s module is deprecated and replaced by the dynconf framework: ' ..
      'it has no redis servers, there is nothing to import, the section can be removed', N)
end
