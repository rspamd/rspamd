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

if confighelp then
  return
end

-- A plugin that provides common header manipulations

local logger = require "rspamd_logger"
local util = require "rspamd_util"
local N = 'milter_headers'
local lua_util = require "lua_util"
local lua_maps = require "lua_maps"
local lua_mime = require "lua_mime"
local ts = require("tableshape").types
local E = {}

local HOSTNAME = util.get_hostname()

local settings = {
  remove_upstream_spam_flag = true;
  skip_local = true,
  skip_authenticated = true,
  skip_all = false,
  local_headers = {},
  authenticated_headers = {},
  default_headers_order = nil, -- Insert at the end (set 1 to insert just after the first received)
  routines = {
    ['remove-headers'] = {
      headers = {},
    },
    ['add-headers'] = {
      headers = {},
      remove = 0,
    },
    ['remove-header'] = {
      remove = 0,
    },
    ['x-spamd-result'] = {
      header = 'X-Spamd-Result',
      remove = 0,
      stop_chars = ' ',
      sort_by = 'score',
    },
    ['x-rspamd-server'] = {
      header = 'X-Rspamd-Server',
      remove = 0,
      hostname = nil, -- Get the local computer host name
    },
    ['x-rspamd-queue-id'] = {
      header = 'X-Rspamd-Queue-Id',
      remove = 0,
    },
    ['x-rspamd-pre-result'] = {
      header = 'X-Rspamd-Pre-Result',
      remove = 0,
    },
    ['remove-spam-flag'] = {
      header = 'X-Spam',
    },
    ['spam-header'] = {
      header = 'Deliver-To',
      value = 'Junk',
      remove = 0,
    },
    ['x-virus'] = {
      header = 'X-Virus',
      remove = 0,
      status_clean = nil,
      status_infected = nil,
      status_fail = nil,
      symbols_fail = {},
      symbols = {}, -- needs config
    },
    ['x-os-fingerprint'] = {
      header = 'X-OS-Fingerprint',
      remove = 0,
    },
    ['x-spamd-bar'] = {
      header = 'X-Spamd-Bar',
      positive = '+',
      negative = '-',
      neutral = '/',
      remove = 0,
    },
    ['x-spam-level'] = {
      header = 'X-Spam-Level',
      char = '*',
      remove = 0,
    },
    ['x-spam-status'] = {
      header = 'X-Spam-Status',
      remove = 0,
    },
    ['authentication-results'] = {
      header = 'Authentication-Results',
      remove = 0,
      add_smtp_user = true,
      stop_chars = ';',
    },
    ['stat-signature'] = {
      header = 'X-Stat-Signature',
      remove = 0,
    },
    ['fuzzy-hashes'] = {
      header = 'X-Rspamd-Fuzzy',
    },
  },
}

local active_routines = {}
local custom_routines = {}

local function milter_headers(task)

  -- Used to override wanted stuff by means of settings
  local settings_override = false

  local function skip_wanted(hdr)
    if settings_override then return true end
    -- Normal checks
    local function match_extended_headers_rcpt()
      local rcpts = task:get_recipients('smtp')
      if not rcpts then return false end
      local found
      for _, r in ipairs(rcpts) do
        found = false
        -- Try full addr match
        if r.addr and r.domain and r.user then
          if settings.extended_headers_rcpt:get_key(r.addr) then
            lua_util.debugm(N, task, 'found full addr in recipients for extended headers: %s',
                r.addr)
            found = true
          end
          -- Try user as plain match
          if not found and settings.extended_headers_rcpt:get_key(r.user) then
            lua_util.debugm(N, task, 'found user in recipients for extended headers: %s (%s)',
                r.user, r.addr)
            found = true
          end
          -- Try @domain to match domain
          if not found and settings.extended_headers_rcpt:get_key('@' .. r.domain) then
            lua_util.debugm(N, task, 'found domain in recipients for extended headers: @%s (%s)',
                r.domain, r.addr)
            found = true
          end
        end
        if found then break end
      end
      return found
    end

    if settings.extended_headers_rcpt and match_extended_headers_rcpt() then
      return false
    end

    if settings.skip_local and not settings.local_headers[hdr] then
      local ip = task:get_ip()
      if (ip and ip:is_local()) then return true end
    end

    if settings.skip_authenticated and not settings.authenticated_headers[hdr] then
      if task:get_user() ~= nil then return true end
    end

    if settings.skip_all then
      return true
    end

    return false

  end

  -- XXX: fix this crap one day
  -- routines - are closures that encloses all environment including task
  -- common - a common environment shared between routines
  -- add - add headers table (filled by routines)
  -- remove - remove headers table (filled by routines)
  local routines, common, add, remove = {}, {}, {}, {}

  local function add_header(name, value, stop_chars, order)
    local hname = settings.routines[name].header
    if order then
      if not add[hname] then
        add[hname] = {
          order = order,
          value = lua_util.fold_header(task, hname, value, stop_chars)
        }
      else
        if not add[hname][1] then
          -- Convert to a table
          add[hname] = {
            [1] = add[hname]
          }
        end

        table.insert(add[hname], {
          order = order,
          value = lua_util.fold_header(task, hname, value, stop_chars)
        })
      end
    else
      if not add[hname] then
        add[hname] = lua_util.fold_header(task, hname, value, stop_chars)
      else
        if not add[hname][1] then
          -- Convert to a table
          add[hname] = {
            [1] = add[hname]
          }
        end

        if settings.default_headers_order then
          table.insert(add[hname], {
            order = settings.default_headers_order,
            value = lua_util.fold_header(task, hname, value, stop_chars)
          })
        else
          table.insert(add[hname],
              lua_util.fold_header(task, hname, value, stop_chars))
        end

      end
    end
  end

  routines['x-spamd-result'] = function()
    local local_mod = settings.routines['x-spamd-result']
    if skip_wanted('x-spamd-result') then return end
    if not common.symbols then
      common.symbols = task:get_symbols_all()
    end
    if not common['metric_score'] then
      common['metric_score'] = task:get_metric_score('default')
    end
    if not common['metric_action'] then
      common['metric_action'] = task:get_metric_action('default')
    end
    if local_mod.remove then
      remove[local_mod.header] = local_mod.remove
    end

    local buf = {}
    local verdict = string.format('default: %s [%.2f / %.2f]',
        --TODO: (common.metric_action == 'no action') and 'False' or 'True',
        (common.metric_action == 'reject') and 'True' or 'False',
        common.metric_score[1], common.metric_score[2])
    table.insert(buf, verdict)

    -- Deal with symbols
    table.sort(common.symbols, function(s1, s2)
      local res
      if local_mod.sort_by == 'name' then
        res = s1.name < s2.name
      else
        -- inverse order to show important symbols first
        res = math.abs(s1.score) > math.abs(s2.score)
      end

      return res
    end)

    for _, s in ipairs(common.symbols) do
      local sym_str = string.format('%s(%.2f)[%s]',
          s.name, s.score,  table.concat(s.options or {}, ','))
      table.insert(buf, sym_str)
    end
    add_header('x-spamd-result', table.concat(buf, '; '), ';')

    local has_pr,action,message,module = task:has_pre_result()

    if has_pr then
      local pr_header = {}
      if action then
        table.insert(pr_header, string.format('action=%s', action))
      end
      if module then
        table.insert(pr_header, string.format('module=%s', module))
      end
      if message then
        table.insert(pr_header, message)
      end
      add_header('x-rspamd-pre-result', table.concat(pr_header, '; '), ';')
    end
  end

  routines['x-rspamd-queue-id'] = function()
    if skip_wanted('x-rspamd-queue-id') then return end
    if common.queue_id ~= false then
      common.queue_id = task:get_queue_id()
      if not common.queue_id then
        common.queue_id = false
      end
    end
    if settings.routines['x-rspamd-queue-id'].remove then
      remove[settings.routines['x-rspamd-queue-id'].header] = settings.routines['x-rspamd-queue-id'].remove
    end
    if common.queue_id then
      add[settings.routines['x-rspamd-queue-id'].header] = common.queue_id
    end
  end

  routines['remove-header'] = function()
    if skip_wanted('remove-header') then return end
    if settings.routines['remove-header'].header and settings.routines['remove-header'].remove then
      remove[settings.routines['remove-header'].header] = settings.routines['remove-header'].remove
    end
  end

  routines['remove-headers'] = function()
    if skip_wanted('remove-headers') then return end
    for h, r in pairs(settings.routines['remove-headers'].headers) do
      remove[h] = r
    end
  end

  routines['add-headers'] = function()
    if skip_wanted('add-headers') then return end
    for h, r in pairs(settings.routines['add-headers'].headers) do
      add[h] = r
      remove[h] = settings.routines['add-headers'].remove
    end
  end

  routines['x-rspamd-server'] = function()
    local local_mod = settings.routines['x-rspamd-server']
    if skip_wanted('x-rspamd-server') then return end
    if local_mod.remove then
      remove[local_mod.header] = local_mod.remove
    end
    local hostname = local_mod.hostname
    add[local_mod.header] = hostname and hostname or HOSTNAME
  end

  routines['x-spamd-bar'] = function()
    local local_mod = settings.routines['x-spamd-bar']
    if skip_wanted('x-rspamd-bar') then return end
    if not common['metric_score'] then
      common['metric_score'] = task:get_metric_score('default')
    end
    local score = common['metric_score'][1]
    local spambar
    if score <= -1 then
      spambar = string.rep(local_mod.negative, math.floor(score * -1))
    elseif score >= 1 then
      spambar = string.rep(local_mod.positive, math.floor(score))
    else
      spambar = local_mod.neutral
    end
    if local_mod.remove then
      remove[local_mod.header] = local_mod.remove
    end
    if spambar ~= '' then
      add[local_mod.header] = spambar
    end
  end

  routines['x-spam-level'] = function()
    local local_mod = settings.routines['x-spam-level']
    if skip_wanted('x-spam-level') then return end
    if not common['metric_score'] then
      common['metric_score'] = task:get_metric_score('default')
    end
    local score = common['metric_score'][1]
    if score < 1 then
      return nil, {}, {}
    end
    if local_mod.remove then
      remove[local_mod.header] = local_mod.remove
    end
    add[local_mod.header] = string.rep(local_mod.char, math.floor(score))
  end

  local function spam_header (class, name, value, remove_v)
    if skip_wanted(class) then return end
    if not common['metric_action'] then
      common['metric_action'] = task:get_metric_action('default')
    end
    if remove_v then
      remove[name] = remove_v
    end
    local action = common['metric_action']
    if action ~= 'no action' and action ~= 'greylist' then
      add[name] = value
    end
  end

  routines['spam-header'] = function()
    spam_header('spam-header',
        settings.routines['spam-header'].header,
        settings.routines['spam-header'].value,
        settings.routines['spam-header'].remove)
  end

  routines['remove-spam-flag'] = function()
    remove[settings.routines['remove-spam-flag'].header] = 0
  end

  routines['x-virus'] = function()
    local local_mod = settings.routines['x-virus']
    if skip_wanted('x-virus') then return end
    if not common.symbols_hash then
      if not common.symbols then
        common.symbols = task:get_symbols_all()
      end
      local h = {}
      for _, s in ipairs(common.symbols) do
        h[s.name] = s
      end
      common.symbols_hash = h
    end
    if local_mod.remove then
      remove[local_mod.header] = local_mod.remove
    end
    local virii = {}
    for _, sym in ipairs(local_mod.symbols) do
      local s = common.symbols_hash[sym]
      if s then
        if (s.options or E)[1] then
          table.insert(virii, table.concat(s.options, ','))
        elseif s then
          table.insert(virii, 'unknown')
        end
      end
    end
    if #virii > 0 then
      local virusstatus = table.concat(virii, ',')
      if local_mod.status_infected then
        virusstatus = local_mod.status_infected .. ', ' .. virusstatus
      end
      add_header('x-virus', virusstatus)
    else
      local failed = false
      local fail_reason = 'unknown'
      for _, sym in ipairs(local_mod.symbols_fail) do
        local s = common.symbols_hash[sym]
        if s then
          failed = true
          if (s.options or E)[1] then
            fail_reason = table.concat(s.options, ',')
          end
        end
      end
      if not failed then
        if local_mod.status_clean then
          add_header('x-virus', local_mod.status_clean)
        end
      else
        if local_mod.status_clean then
          add_header('x-virus', string.format('%s(%s)',
              local_mod.status_fail, fail_reason))
        end
      end
    end
  end

  routines['x-os-fingerprint'] = function()
    if skip_wanted('x-os-fingerprint') then return end
    local local_mod = settings.routines['x-os-fingerprint']

    local os_string, link_type, uptime_min, distance =
      task:get_mempool():get_variable('os_fingerprint',
        'string, string, double, double');

    if not os_string then return end

    local value = string.format('%s, (up: %i min), (distance %i, link: %s)',
      os_string, uptime_min, distance, link_type)

    if local_mod.remove then
      remove[local_mod.header] = local_mod.remove
    end

    add_header('x-os-fingerprint', value)
  end

  routines['x-spam-status'] = function()
    if skip_wanted('x-spam-status') then return end
    if not common['metric_score'] then
      common['metric_score'] = task:get_metric_score('default')
    end
    if not common['metric_action'] then
      common['metric_action'] = task:get_metric_action('default')
    end
    local score = common['metric_score'][1]
    local action = common['metric_action']
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
    add_header('x-spam-status', spamstatus)
  end

  routines['authentication-results'] = function()
    if skip_wanted('authentication-results') then return end
    local ar = require "lua_auth_results"

    if settings.routines['authentication-results'].remove then
      remove[settings.routines['authentication-results'].header] =
          settings.routines['authentication-results'].remove
    end

    local res = ar.gen_auth_results(task,
        lua_util.override_defaults(ar.default_settings,
            settings.routines['authentication-results']))

    if res then
      add_header('authentication-results', res, ';', 1)
    end
  end

  routines['stat-signature'] = function()
    if skip_wanted('stat-signature') then return end
    if settings.routines['stat-signature'].remove then
      remove[settings.routines['stat-signature'].header] =
        settings.routines['stat-signature'].remove
    end
    local res = task:get_mempool():get_variable("stat_signature")
    if res then
      add[settings.routines['stat-signature'].header] = res
    end
  end

  routines['fuzzy-hashes'] = function()
    local res = task:get_mempool():get_variable("fuzzy_hashes", "fstrings")

    if res and #res > 0 then
      for _,h in ipairs(res) do
        add_header('fuzzy-hashes', h)
      end
    end
  end

  local routines_enabled = active_routines
  local user_settings = task:cache_get('settings')
  if user_settings and user_settings.plugins then
    user_settings = user_settings.plugins.milter_headers or E
  end

  if user_settings and type(user_settings.routines) == 'table' then
    lua_util.debugm(N, task, 'override routines to %s from user settings',
        user_settings.routines)
    routines_enabled = user_settings.routines
    settings_override = true
  end

  for _, n in ipairs(routines_enabled) do
    local ok, err
    if custom_routines[n] then
      local to_add, to_remove, common_in
      ok, err, to_add, to_remove, common_in = pcall(custom_routines[n], task, common)
      if ok then
        for k, v in pairs(to_add) do
          add[k] = v
        end
        for k, v in pairs(to_remove) do
          remove[k] = v
        end
        for k, v in pairs(common_in) do
          if type(v) == 'table' then
            if not common[k] then
              common[k] = {}
            end
            for kk, vv in pairs(v) do
              common[k][kk] = vv
            end
          else
            common[k] = v
          end
        end
      end
    else
      ok, err = pcall(routines[n])
    end
    if not ok then
      logger.errx(task, 'call to %s failed: %s', n, err)
    end
  end

  if not next(add) then add = nil end
  if not next(remove) then remove = nil end
  if add or remove then

    lua_mime.modify_headers(task, {
      add = add,
      remove = remove
    })
  end
end

local config_schema = ts.shape({
  use = ts.array_of(ts.string) + ts.string / function(s) return {s} end,
  remove_upstream_spam_flag = ts.boolean:is_optional(),
  extended_spam_headers = ts.boolean:is_optional(),
  skip_local = ts.boolean:is_optional(),
  skip_authenticated = ts.boolean:is_optional(),
  local_headers = ts.array_of(ts.string):is_optional(),
  authenticated_headers = ts.array_of(ts.string):is_optional(),
  extended_headers_rcpt = lua_maps.map_schema:is_optional(),
  custom = ts.map_of(ts.string, ts.string):is_optional(),
}, {
  extra_fields = ts.map_of(ts.string, ts.any)
})

local opts = rspamd_config:get_all_opt(N) or
             rspamd_config:get_all_opt('rmilter_headers')

if not opts then return end

-- Process config
do
  local res,err = config_schema:transform(opts)
  if not res then
    logger.errx(rspamd_config, 'invalid config for %s: %s', N, err)
    return
  else
    opts = res
  end
end

local have_routine = {}
local function activate_routine(s)
  if settings.routines[s] or custom_routines[s] then
    if not have_routine[s] then
      have_routine[s] = true
      table.insert(active_routines, s)
      if (opts.routines and opts.routines[s]) then
        settings.routines[s] = lua_util.override_defaults(settings.routines[s],
            opts.routines[s])
      end
    end
  else
    logger.errx(rspamd_config, 'routine "%s" does not exist', s)
  end
end

if opts.remove_upstream_spam_flag ~= nil then
  settings.remove_upstream_spam_flag = opts.remove_upstream_spam_flag
end

if opts.extended_spam_headers then
  activate_routine('x-spamd-result')
  activate_routine('x-rspamd-server')
  activate_routine('x-rspamd-queue-id')
end

if opts.local_headers then
  for _, h in ipairs(opts.local_headers) do
    settings.local_headers[h] = true
  end
end
if opts.authenticated_headers then
  for _, h in ipairs(opts.authenticated_headers) do
    settings.authenticated_headers[h] = true
  end
end
if opts.custom then
  for k, v in pairs(opts['custom']) do
    local f, err = load(v)
    if not f then
      logger.errx(rspamd_config, 'could not load "%s": %s', k, err)
    else
      custom_routines[k] = f()
    end
  end
end

if type(opts['skip_local']) == 'boolean' then
  settings.skip_local = opts['skip_local']
end

if type(opts['skip_authenticated']) == 'boolean' then
  settings.skip_authenticated = opts['skip_authenticated']
end

if type(opts['skip_all']) == 'boolean' then
  settings.skip_all = opts['skip_all']
end

for _, s in ipairs(opts['use']) do
  if not have_routine[s] then
    activate_routine(s)
  end
end

if settings.remove_upstream_spam_flag then
  activate_routine('remove-spam-flag')
end

if (#active_routines < 1) then
  logger.errx(rspamd_config, 'no active routines')
  return
end

logger.infox(rspamd_config, 'active routines [%s]',
    table.concat(active_routines, ','))

if opts.extended_headers_rcpt then
  settings.extended_headers_rcpt = lua_maps.rspamd_map_add_from_ucl(opts.extended_headers_rcpt,
      'set', 'Extended headers recipients')
end

rspamd_config:register_symbol({
  name = 'MILTER_HEADERS',
  type = 'idempotent',
  callback = milter_headers,
  priority = 10,
  flags = 'empty',
})
