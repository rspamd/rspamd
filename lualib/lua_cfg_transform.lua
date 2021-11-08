--[[
Copyright (c) 2017, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local logger = require "rspamd_logger"
local lua_util = require "lua_util"
local rspamd_util = require "rspamd_util"
local fun = require "fun"

local function is_implicit(t)
  local mt = getmetatable(t)

  return mt and mt.class and mt.class == 'ucl.type.impl_array'
end

local function metric_pairs(t)
  -- collect the keys
  local keys = {}
  local implicit_array = is_implicit(t)

  local function gen_keys(tbl)
    if implicit_array then
      for _,v in ipairs(tbl) do
        if v.name then
          table.insert(keys, {v.name, v})
          v.name = nil
        else
          -- Very tricky to distinguish:
          -- group {name = "foo" ... } + group "blah" { ... }
          for gr_name,gr in pairs(v) do
            if type(gr_name) ~= 'number' then
              -- We can also have implicit arrays here
              local gr_implicit = is_implicit(gr)

              if gr_implicit then
                for _,gr_elt in ipairs(gr) do
                  table.insert(keys, {gr_name, gr_elt})
                end
              else
                table.insert(keys, {gr_name, gr})
              end
            end
          end
        end
      end
    else
      if tbl.name then
        table.insert(keys, {tbl.name, tbl})
        tbl.name = nil
      else
        for k,v in pairs(tbl) do
          if type(k) ~= 'number' then
            -- We can also have implicit arrays here
            local sym_implicit = is_implicit(v)

            if sym_implicit then
              for _,elt in ipairs(v) do
                table.insert(keys, {k, elt})
              end
            else
              table.insert(keys, {k, v})
            end
          end
        end
      end
    end
  end

  gen_keys(t)

  -- return the iterator function
  local i = 0
  return function()
    i = i + 1
    if keys[i] then
      return keys[i][1], keys[i][2]
    end
  end
end

local function group_transform(cfg, k, v)
  if v.name then k = v.name end

  local new_group = {
    symbols = {}
  }

  if v.enabled then new_group.enabled = v.enabled end
  if v.disabled then new_group.disabled = v.disabled end
  if v.max_score then new_group.max_score = v.max_score end

  if v.symbol then
    for sk,sv in metric_pairs(v.symbol) do
      if sv.name then
        sk = sv.name
        sv.name = nil -- Remove field
      end

      new_group.symbols[sk] = sv
    end
  end

  if not cfg.group then cfg.group = {} end

  if cfg.group[k] then
    cfg.group[k] = lua_util.override_defaults(cfg.group[k], new_group)
  else
    cfg.group[k] = new_group
  end

  logger.infox("overriding group %s from the legacy metric settings", k)
end

local function symbol_transform(cfg, k, v)
  -- first try to find any group where there is a definition of this symbol
  for gr_n, gr in pairs(cfg.group) do
    if gr.symbols and gr.symbols[k] then
      -- We override group symbol with ungrouped symbol
      logger.infox("overriding group symbol %s in the group %s", k, gr_n)
      gr.symbols[k] = lua_util.override_defaults(gr.symbols[k], v)
      return
    end
  end
  -- Now check what Rspamd knows about this symbol
  local sym = rspamd_config:get_metric_symbol(k)

  if not sym or not sym.group then
    -- Otherwise we just use group 'ungrouped'
    if not cfg.group.ungrouped then
      cfg.group.ungrouped = {
        symbols = {}
      }
    end

    cfg.group.ungrouped.symbols[k] = v
    logger.debugx("adding symbol %s to the group 'ungrouped'", k)
  end
end

local function test_groups(groups)
  for gr_name, gr in pairs(groups) do
    if not gr.symbols then
      local cnt = 0
      for _,_ in pairs(gr) do cnt = cnt + 1 end

      if cnt == 0 then
        logger.debugx('group %s is empty', gr_name)
      else
        logger.infox('group %s has no symbols', gr_name)
      end
    end
  end
end

local function convert_metric(cfg, metric)
  if metric.actions then
    cfg.actions = lua_util.override_defaults(cfg.actions, metric.actions)
    logger.infox("overriding actions from the legacy metric settings")
  end
  if metric.unknown_weight then
    cfg.actions.unknown_weight = metric.unknown_weight
  end

  if metric.subject then
    logger.infox("overriding subject from the legacy metric settings")
    cfg.actions.subject = metric.subject
  end

  if metric.group then
    for k, v in metric_pairs(metric.group) do
      group_transform(cfg, k, v)
    end
  else
    if not cfg.group then
      cfg.group = {
        ungrouped = {
          symbols = {}
        }
      }
    end
  end

  if metric.symbol then
    for k, v in metric_pairs(metric.symbol) do
      symbol_transform(cfg, k, v)
    end
  end

  return cfg
end

-- Converts a table of groups indexed by number (implicit array) to a
-- merged group definition
local function merge_groups(groups)
  local ret = {}
  for k,gr in pairs(groups) do
    if type(k) == 'number' then
      for key,sec in pairs(gr) do
        ret[key] = sec
      end
    else
      ret[k] = gr
    end
  end

  return ret
end

-- Checks configuration files for statistics
local function check_statistics_sanity()
  local local_conf = rspamd_paths['LOCAL_CONFDIR']
  local local_stat = string.format('%s/local.d/%s', local_conf,
      'statistic.conf')
  local local_bayes = string.format('%s/local.d/%s', local_conf,
      'classifier-bayes.conf')

  if rspamd_util.file_exists(local_stat) and
      rspamd_util.file_exists(local_bayes) then
    logger.warnx(rspamd_config, 'conflicting files %s and %s are found: '..
        'Rspamd classifier configuration might be broken!', local_stat, local_bayes)
  end
end

-- Converts surbl module config to rbl module
local function surbl_section_convert(cfg, section)
  local rbl_section = cfg.rbl.rbls
  local wl = section.whitelist
  for name,value in pairs(section.rules or {}) do
    if rbl_section[name] then
      logger.warnx(rspamd_config, 'conflicting names in surbl and rbl rules: %s, prefer surbl rule!',
          name)
    end
    local converted = {
      urls = true,
      ignore_defaults = true,
    }

    if wl then
      converted.whitelist = wl
    end

    for k,v in pairs(value) do
      local skip = false
      -- Rename
      if k == 'suffix' then k = 'rbl' end
      if k == 'ips' then k = 'returncodes' end
      if k == 'bits' then k = 'returnbits' end
      if k == 'noip' then k = 'no_ip' end
      -- Crappy legacy
      if k == 'options' then
        if v == 'noip' or v == 'no_ip' then
          converted.no_ip = true
          skip = true
        end
      end
      if k:match('check_') then
        local n = k:match('check_(.*)')
        k = n
      end

      if k == 'dkim' and v then
        converted.dkim_domainonly = false
        converted.dkim_match_from = true
      end

      if k == 'emails' and v then
        -- To match surbl behaviour
        converted.emails_domainonly = true
      end

      if not skip then
        converted[k] = lua_util.deepcopy(v)
      end
    end
    rbl_section[name] = lua_util.override_defaults(rbl_section[name], converted)
  end
end

-- Converts surbl module config to rbl module
local function emails_section_convert(cfg, section)
  local rbl_section = cfg.rbl.rbls
  local wl = section.whitelist
  for name,value in pairs(section.rules or {}) do
    if rbl_section[name] then
      logger.warnx(rspamd_config, 'conflicting names in emails and rbl rules: %s, prefer emails rule!',
          name)
    end
    local converted = {
      emails = true,
      ignore_defaults = true,
    }

    if wl then
      converted.whitelist = wl
    end

    for k,v in pairs(value) do
      local skip = false
      -- Rename
      if k == 'dnsbl' then k = 'rbl' end
      if k == 'check_replyto' then k = 'replyto' end
      if k == 'hashlen' then k = 'hash_len' end
      if k == 'encoding' then k = 'hash_format' end
      if k == 'domain_only' then k = 'emails_domainonly' end
      if k == 'delimiter' then k = 'emails_delimiter' end
      if k == 'skip_body' then
        skip = true
        if v then
          -- Hack
          converted.emails = false
          converted.replyto = true
        else
          converted.emails = true
        end
      end
      if k == 'expect_ip' then
        -- Another stupid hack
        if not converted.return_codes then
          converted.returncodes = {}
        end
        local symbol = value.symbol or name
        converted.returncodes[symbol] = { v }
        skip = true
      end

      if not skip then
        converted[k] = lua_util.deepcopy(v)
      end
    end
    rbl_section[name] = lua_util.override_defaults(rbl_section[name], converted)
  end
end

return function(cfg)
  local ret = false

  if cfg['metric'] then
    for _, v in metric_pairs(cfg.metric) do
      cfg = convert_metric(cfg, v)
    end
    ret = true
  end

  if cfg.symbols then
    for k, v in metric_pairs(cfg.symbols) do
      symbol_transform(cfg, k, v)
    end
  end

  check_statistics_sanity()

  if not cfg.actions then
    logger.errx('no actions defined')
  else
    -- Perform sanity check for actions
    local actions_defs = {'no action', 'no_action', -- In case if that's added
                          'greylist', 'add header', 'add_header',
                          'rewrite subject', 'rewrite_subject', 'quarantine',
                          'reject', 'discard'}

    if not cfg.actions['no action'] and not cfg.actions['no_action'] and
            not cfg.actions['accept'] then
      for _,d in ipairs(actions_defs) do
        if cfg.actions[d] then

          local action_score = nil
          if type(cfg.actions[d]) == 'number' then
            action_score = cfg.actions[d]
          elseif type(cfg.actions[d]) == 'table' and cfg.actions[d]['score'] then
            action_score = cfg.actions[d]['score']
          end

          if type(cfg.actions[d]) ~= 'table' and not action_score then
            cfg.actions[d] = nil
          elseif type(action_score) == 'number' and action_score < 0 then
            cfg.actions['no_action'] = cfg.actions[d] - 0.001
            logger.infox(rspamd_config, 'set no_action score to: %s, as action %s has negative score',
                    cfg.actions['no_action'], d)
            break
          end
        end
      end
    end

    local actions_set = lua_util.list_to_hash(actions_defs)

    -- Now check actions section for garbadge
    actions_set['unknown_weight'] = true
    actions_set['grow_factor'] = true
    actions_set['subject'] = true

    for k,_ in pairs(cfg.actions) do
      if not actions_set[k] then
        logger.warnx(rspamd_config, 'unknown element in actions section: %s', k)
      end
    end

    -- Performs thresholds sanity
    -- We exclude greylist here as it can be set to whatever threshold in practice
    local actions_order = {
      'no_action',
      'add_header',
      'rewrite_subject',
      'quarantine',
      'reject',
      'discard'
    }
    for i=1,(#actions_order - 1) do
      local act = actions_order[i]

      if cfg.actions[act] and type(cfg.actions[act]) == 'number' then
        local score = cfg.actions[act]

        for j=i+1,#actions_order do
          local next_act = actions_order[j]
          if cfg.actions[next_act] and type(cfg.actions[next_act]) == 'number' then
            local next_score = cfg.actions[next_act]
            if next_score <= score then
              logger.errx(rspamd_config, 'invalid actions thresholds order: action %s (%s) must have lower '..
                  'score than action %s (%s)', act, score, next_act, next_score)
              ret = false
            end
          end
        end
      end
    end
  end

  if not cfg.group then
    logger.errx('no symbol groups defined')
  else
    if cfg.group[1] then
      -- We need to merge groups
      cfg.group = merge_groups(cfg.group)
      ret = true
    end
    test_groups(cfg.group)
  end

  -- Deal with dkim settings
  if not cfg.dkim then
    cfg.dkim = {}
  else
    if cfg.dkim.sign_condition then
      -- We have an obsoleted sign condition, so we need to either add dkim_signing and move it
      -- there or just move sign condition there...
      if not cfg.dkim_signing then
        logger.warnx('obsoleted DKIM signing method used, converting it to "dkim_signing" module')
        cfg.dkim_signing = {
          sign_condition = cfg.dkim.sign_condition
        }
      else
        if not cfg.dkim_signing.sign_condition then
          logger.warnx('obsoleted DKIM signing method used, move it to "dkim_signing" module')
          cfg.dkim_signing.sign_condition = cfg.dkim.sign_condition
        else
          logger.warnx('obsoleted DKIM signing method used, ignore it as "dkim_signing" also defines condition!')
        end
      end
    end
  end

  -- Again: legacy stuff :(
  if not cfg.dkim.sign_headers then
    local sec = cfg.dkim_signing
    if sec and sec[1] then sec = cfg.dkim_signing[1] end

    if sec and sec.sign_headers then
      cfg.dkim.sign_headers = sec.sign_headers
    end
  end

  -- DKIM signing/ARC legacy
  for _, mod in ipairs({'dkim_signing', 'arc'}) do
    if cfg[mod] then
      if cfg[mod].auth_only ~= nil then
        if cfg[mod].sign_authenticated ~= nil then
          logger.warnx(rspamd_config,
              'both auth_only (%s) and sign_authenticated (%s) for %s are specified, prefer auth_only',
              cfg[mod].auth_only, cfg[mod].sign_authenticated, mod)
        end
        cfg[mod].sign_authenticated = cfg[mod].auth_only
      end
    end
  end

  if cfg.dkim and cfg.dkim.sign_headers and type(cfg.dkim.sign_headers) == 'table' then
    -- Flatten
    cfg.dkim.sign_headers = table.concat(cfg.dkim.sign_headers, ':')
  end

  -- Try to find some obvious issues with configuration
  for k,v in pairs(cfg) do
    if type(v) == 'table' and v[k] and type (v[k]) == 'table' then
      logger.errx('nested section: %s { %s { ... } }, it is likely a configuration error',
              k, k)
    end
  end

  -- If neural network is enabled we MUST have `check_all_filters` flag
  if cfg.neural then
    if not cfg.options then
      cfg.options = {}
    end

    if not cfg.options.check_all_filters then
      logger.infox(rspamd_config, 'enable `options.check_all_filters` for neural network')
      cfg.options.check_all_filters = true
    end
  end

  -- Deal with IP_SCORE
  if cfg.ip_score and (cfg.ip_score.servers or cfg.redis.servers) then
    logger.warnx(rspamd_config, 'ip_score module is deprecated in honor of reputation module!')

    if not cfg.reputation then
      cfg.reputation = {
        rules = {}
      }
    end

    if not cfg.reputation.rules then cfg.reputation.rules = {} end

    if not fun.any(function(_, v) return v.selector and v.selector.ip end,
        cfg.reputation.rules) then
      logger.infox(rspamd_config, 'attach ip reputation element to use it')

      cfg.reputation.rules.ip_score = {
        selector = {
          ip = {},
        },
        backend = {
          redis = {},
        }
      }

      if cfg.ip_score.servers then
        cfg.reputation.rules.ip_score.backend.redis.servers = cfg.ip_score.servers
      end

      if cfg.symbols and cfg.symbols['IP_SCORE'] then
        local t = cfg.symbols['IP_SCORE']

        if not cfg.symbols['SENDER_REP_SPAM'] then
          cfg.symbols['SENDER_REP_SPAM'] = t
          cfg.symbols['SENDER_REP_HAM'] = t
          cfg.symbols['SENDER_REP_HAM'].weight = -(t.weight or 0)
        end
      end
    else
      logger.infox(rspamd_config, 'ip reputation already exists, do not do any IP_SCORE transforms')
    end
  end

  if cfg.surbl then
    if not cfg.rbl then
      cfg.rbl = {
        rbls = {}
      }
    end
    if not cfg.rbl.rbls then
      cfg.rbl.rbls = {}
    end
    surbl_section_convert(cfg, cfg.surbl)
    logger.infox(rspamd_config, 'converted surbl rules to rbl rules')
    cfg.surbl = {}
  end

  if cfg.emails then
    if not cfg.rbl then
      cfg.rbl = {
        rbls = {}
      }
    end
    if not cfg.rbl.rbls then
      cfg.rbl.rbls = {}
    end
    emails_section_convert(cfg, cfg.emails)
    logger.infox(rspamd_config, 'converted emails rules to rbl rules')
    cfg.emails = {}
  end

  return ret, cfg
end
