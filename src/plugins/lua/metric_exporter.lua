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
]] --

local logger = require "rspamd_logger"
local mempool = require "rspamd_mempool"
local util = require "rspamd_util"
local tcp = require "rspamd_tcp"

local pool = mempool.create()
local settings = {
  poll = 30,
  interval = 120,
  timeout = 15,
}

local VAR_NAME = 'metric_exporter_last_push'

local valid_metrics = {
  'actions.add header',
  'actions.greylist',
  'actions.no action',
  'actions.reject',
  'actions.rewrite subject',
  'actions.soft reject',
  'bytes_allocated',
  'chunks_allocated',
  'chunks_freed',
  'chunks_oversized',
  'connections',
  'control_connections',
  'ham_count',
  'learned',
  'pools_allocated',
  'pools_freed',
  'scanned',
  'shared_chunks_allocated',
  'spam_count',
}

local function graphite_config(opts)
  local defaults = {
    host = 'localhost',
    port = 2003,
    metric_prefix = 'rspamd'
  }
  for k, v in pairs(defaults) do
    if settings[k] == nil then
      settings[k] = v
    end
  end
  if type(settings['metrics']) ~= 'table' or #settings['metrics'] == 0 then
    logger.err('No metrics specified for collection')
    return false
  end
  for _, v in ipairs(settings['metrics']) do
    isvalid = false
    for _, vm in ipairs(valid_metrics) do
      if vm == v then
        isvalid = true
        break
      end
    end
    if not isvalid then
      logger.errx('Invalid metric: %s', v)
      return false
    end
    local split = rspamd_str_split(v, '.')
    if #split > 2 then
      logger.errx('Too many dots in metric name: %s', v)
      return false
    end
  end
  return true
end

local function graphite_push(kwargs)
  local stamp = math.floor(kwargs['time'])
  local metrics_str = ''
  for _, v in ipairs(settings['metrics']) do
    local mname = string.format('%s.%s', settings['metric_prefix'], v:gsub(' ', '_'))
    local split = rspamd_str_split(v, '.')
    if #split == 1 then
      mvalue = kwargs['stats'][v]
    elseif #split == 2 then
      mvalue = kwargs['stats'][split[1]][split[2]]
    end
    metrics_str = metrics_str .. string.format('%s %s %s\n', mname, mvalue, stamp)
  end
  metrics_str = metrics_str .. '\n'
  tcp.request({
    ev_base = kwargs['ev_base'],
    pool = pool,
    host = settings['host'],
    port = settings['port'],
    timeout = settings['timeout'],
    read = false,
    data = {
      metrics_str,
    },
    callback = (function (err, data)
      if err then
        logger.errx('Push failed: %1', err)
        return
      end
      pool:set_variable(VAR_NAME, stamp)
    end)
  })
end

local backends = {
  graphite = {
    configure = graphite_config,
    push = graphite_push,
  },
} 

local function configure_metric_exporter()
  local opts = rspamd_config:get_all_opt('metric_exporter')
  if not backends[opts['backend']] then
    logger.err('Backend is invalid or unspecified')
    return false
  end
  if not opts['statefile'] then
    logger.err('No statefile specified')
    return false
  end
  for k, v in pairs(opts) do
    settings[k] = v
  end
  return backends[opts['backend']]['configure'](opts)
end

if not configure_metric_exporter() then return end

rspamd_config:add_on_load(function (cfg, ev_base, worker)
  if not (worker:get_name() == 'normal' and worker:get_index() == 0) then return end
  rspamd_config:register_finish_script(function (task)
    local stamp = pool:get_variable(VAR_NAME, 'double')
    if not stamp then
      logger.warn('No last metric exporter push to persist to disk')
      return
    end
    local f, err = io.open(settings['statefile'], 'w')
    if err then
      logger.errx('Unable to write statefile to disk: %s', err)
      return
    end
    if f then
      f:write(pool:get_variable(VAR_NAME, 'double'))
      f:close()
    end
  end)
  local f, err = io.open(settings['statefile'], 'r')
  if err then
    logger.errx('Failed to open statefile: %s', err)
  end
  if f then
    io.input(f)
    local stamp = tonumber(io.read())
    pool:set_variable(VAR_NAME, stamp)
  end
  rspamd_config:add_periodic(ev_base, settings['poll'], function (cfg, ev_base)
    logger.debug('Checking if metrics need to be pushed')
    local last_push = pool:get_variable(VAR_NAME, 'double')
    local time = util.get_time()
    if (not last_push) or ((time-last_push) >= settings['interval']) then
      logger.infox('Pushing metrics to %s backend', settings['backend'])
      backends[settings['backend']]['push']({
        ev_base = ev_base,
        stats = worker:get_stat(),
        time = time,
      })
    end
    return true
  end)
end)
