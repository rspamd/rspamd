--[[
Copyright (c) 2016, Andrew Lewis <nerf@judo.za.org>
Copyright (c) 2016, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- A plugin that provides common header manipulations

local logger = require "rspamd_logger"
local N = 'rmilter_headers'

local settings = {
  routines = {
    ['x-spamd-bar'] = {
      header = 'X-Spamd-Bar',
      positive = '+',
      negative = '-',
      neutral = '/',
      remove = 1,
    },
    ['x-spam-level'] = {
      header = 'X-Spam-Level',
      char = '*',
      remove = 1,
    },
    ['x-spam-status'] = {
      header = 'X-Spam-Status',
      remove = 1,
    },
  },
}

local active_routines = {}
local routines = {}

routines['x-spamd-bar'] = function(task, common_meta)
  local common, add, remove = {}, {}, {}
  if not common_meta['metric_score'] then
    common['metric_score'] = task:get_metric_score('default')
    common_meta['metric_score'] = common['metric_score']
  end
  local score = common_meta['metric_score'][1]
  local spambar
  if score <= -1 then
    spambar = string.rep(settings.routines['x-spamd-bar'].negative, score*-1)
  elseif score >= 1 then
    spambar = string.rep(settings.routines['x-spamd-bar'].positive, score)
  else
    spambar = settings.routines['x-spamd-bar'].neutral
  end
  if settings.routines['x-spamd-bar'].remove then
    remove[settings.routines['x-spamd-bar'].header] = settings.routines['x-spamd-bar'].remove
  end
  if spambar ~= '' then
    add[settings.routines['x-spamd-bar'].header] = spambar
  end
  return nil, add, remove, common
end

routines['x-spam-level'] = function(task, common_meta)
  local common, add, remove = {}, {}, {}
  if not common_meta['metric_score'] then
    common['metric_score'] = task:get_metric_score('default')
    common_meta['metric_score'] = common['metric_score']
  end
  local score = common_meta['metric_score'][1]
  if score < 1 then
    return nil, {}, {}, common
  end
  if settings.routines['x-spam-level'].remove then
    remove[settings.routines['x-spam-level'].header] = settings.routines['x-spam-level'].remove
  end
  add[settings.routines['x-spam-level'].header] = string.rep(settings.routines['x-spam-level'].char, score)
  return nil, add, remove, common
end

routines['x-spam-status'] = function(task, common_meta)
  local common, add, remove = {}, {}, {}
  if not common_meta['metric_score'] then
    common['metric_score'] = task:get_metric_score('default')
    common_meta['metric_score'] = common['metric_score']
  end
  if not common_meta['metric_action'] then
    common['metric_action'] = task:get_metric_action('default')
    common_meta['metric_action'] = common['metric_action']
  end
  local score = common_meta['metric_score'][1]
  local action = common_meta['metric_action']
  local is_spam
  local spamstatus
  if action ~= 'no action' and action ~= 'greylist' then
    is_spam = 'Yes'
  else
    is_spam = 'No'
  end
  spamstatus = is_spam .. ', score=' .. string.format('%.2f', score)
  if settings.routines['x-spam-status'].remove then
    remove[settings.routines['x-spam-status'].header] = settings.routines['x-spam-status'].remove
  end
  add[settings.routines['x-spam-status'].header] = spamstatus
  return nil, add, remove, common
end

local function rmilter_headers(task)
  local common_meta, to_add, to_remove = {}, {}, {}
  for n, f in pairs(active_routines) do
    local ok, err, add, remove, common = pcall(routines[f], task, common_meta)
    if not ok then
      logger.errx(task, 'call to %s failed: %s', n, err)
    else
      for k, v in pairs(add) do
        to_add[k] = v
      end
      for k, v in pairs(remove) do
        to_remove[k] = v
      end
      for k, v in pairs(common) do
        common_meta[k] = v
      end
    end
  end
  if not next(to_add) then to_add = nil end
  if not next(to_remove) then to_remove = nil end
  if to_add or to_remove then
    task:set_rmilter_reply({
      add_headers = to_add,
      remove_headers = to_remove
    })
  end
end

local opts = rspamd_config:get_all_opt(N)
if not opts then return end
if type(opts['use']) == 'string' then
  opts['use'] = {opts['use']}
end
if type(opts['use']) ~= 'table' then
  logger.errx(rspamd_config, 'unexpected type for "use" option: %s', type(opts['use']))
  return
end
if type(opts['custom']) == 'table' then
  for k, v in pairs(opts['custom']) do
    local f, err = load(v)
    if err then
      logger.errx(rspamd_config, 'could not load "%s": %s', k, err)
    else
      routines[k] = f
    end
  end
end
for _, s in ipairs(opts['use']) do
  if not routines[s] then
    logger.errx(rspamd_config, 'routine "%s" does not exist', s)
  else
    table.insert(active_routines, s)
  end
end
if (#active_routines < 1) then
  logger.errx(rspamd_config, 'no active routines')
  return
end
rspamd_config:register_symbol({
  name = 'RMILTER_HEADERS',
  type = 'postfilter',
  callback = rmilter_headers,
  priority = 10
})
