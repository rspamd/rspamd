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

local logger = require "rspamd_logger"
local lua_util = require "lua_util"
local rspamd_util = require "rspamd_util"

-- Converts surbl module config to rbl module
local function surbl_section_convert(cfg, section)
  local rbl_section = cfg.rbl.rbls
  local wl = section.whitelist
  if section.rules then
    for name, value in section.rules:pairs() do
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

      for k, v in value:pairs() do
        local skip = false
        -- Rename
        if k == 'suffix' then
          k = 'rbl'
        end
        if k == 'ips' then
          k = 'returncodes'
        end
        if k == 'bits' then
          k = 'returnbits'
        end
        if k == 'noip' then
          k = 'no_ip'
        end
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
end


-- Converts surbl module config to rbl module
local function emails_section_convert(cfg, section)
  local rbl_section = cfg.rbl.rbls
  local wl = section.whitelist
  if section.rules then
    for name, value in section.rules:pairs() do
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

      for k, v in value:pairs() do
        local skip = false
        -- Rename
        if k == 'dnsbl' then
          k = 'rbl'
        end
        if k == 'check_replyto' then
          k = 'replyto'
        end
        if k == 'hashlen' then
          k = 'hash_len'
        end
        if k == 'encoding' then
          k = 'hash_format'
        end
        if k == 'domain_only' then
          k = 'emails_domainonly'
        end
        if k == 'delimiter' then
          k = 'emails_delimiter'
        end
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
end

local function group_transform(cfg, k, v)
  if v:at('name') then
    k = v:at('name'):unwrap()
  end

  local new_group = {
    symbols = {}
  }

  if v:at('enabled') then
    new_group.enabled = v:at('enabled'):unwrap()
  end
  if v:at('disabled') then
    new_group.disabled = v:at('disabled'):unwrap()
  end
  if v.max_score then
    new_group.max_score = v:at('max_score'):unwrap()
  end

  if v:at('symbol') then
    for sk, sv in v:at('symbol'):pairs() do
      if sv:at('name') then
        sk = sv:at('name'):unwrap()
        sv.name = nil -- Remove field
      end

      new_group.symbols[sk] = sv
    end
  end

  if not cfg:at('group') then
    cfg.group = {}
  end

  if cfg:at('group'):at(k) then
    cfg:at('group')[k] = lua_util.override_defaults(cfg:at('group')[k]:unwrap(), new_group)
  else
    cfg:at('group')[k] = new_group
  end

  logger.infox("overriding group %s from the legacy metric settings", k)
end

local function symbol_transform(cfg, k, v)
  local groups = cfg:at('group')
  -- first try to find any group where there is a definition of this symbol
  for gr_n, gr in groups:pairs() do
    local symbols = gr:at('symbols')
    if symbols and symbols:at(k) then
      -- We override group symbol with ungrouped symbol
      logger.infox("overriding group symbol %s in the group %s", k, gr_n)
      symbols[k] = lua_util.override_defaults(symbols:at(k):unwrap(), v:unwrap())
      return
    end
  end
  -- Now check what Rspamd knows about this symbol
  local sym = rspamd_config:get_symbol(k)

  if not sym or not sym.group then
    -- Otherwise we just use group 'ungrouped'
    if not groups:at('ungrouped') then
      groups.ungrouped = {
        symbols = {
          [k] = v
        }
      }
    else
      groups:at('ungrouped'):at('symbols')[k] = v
    end

    logger.debugx("adding symbol %s to the group 'ungrouped'", k)
  end
end

local function convert_metric(cfg, metric)
  if metric:type() ~= 'object' then
    logger.errx('invalid metric definition: %s', metric)
    return
  end

  if metric:at('actions') then
    local existing_actions = cfg:at('actions') and cfg:at('actions'):unwrap() or {}
    cfg.actions = lua_util.override_defaults(existing_actions, metric:at('actions'):unwrap())
    logger.infox("overriding actions from the legacy metric settings")
  end
  if metric:at('unknown_weight') then
    logger.infox("overriding unknown weight from the legacy metric settings")
    cfg:at('actions').unknown_weight = metric:at('unknown_weight'):unwrap()
  end

  if metric:at('subject') then
    logger.infox("overriding subject from the legacy metric settings")
    cfg:at('actions').subject = metric:at('subject'):unwrap()
  end

  if metric:at('group') then
    for k, v in metric:at('group'):pairs() do
      group_transform(cfg, k, v)
    end
  end

  if metric:at('symbol') then
    for k, v in metric:at('symbol'):pairs() do
      symbol_transform(cfg, k, v)
    end
  end
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
    logger.warnx(rspamd_config, 'conflicting files %s and %s are found: ' ..
        'Rspamd classifier configuration might be broken!', local_stat, local_bayes)
  end
end

return function(cfg)
  local ret = false

  if cfg:at('metric') then
    local metric = cfg:at('metric')

    -- There are two things that we can have (old `metric_pairs` logic)
    -- 1. A metric is a single metric definition like: metric { name = "default", ... }
    -- 2. A metric is a list of metrics like: metric { "default": ... }
    if metric:at('actions') or metric:at('name') then
      convert_metric(cfg, metric)
    else
      for _, v in cfg:at('metric'):pairs() do
        if v:type() == 'object' then
          logger.infox('converting metric element %s', v)
          convert_metric(cfg, v)
        end
      end
    end
    ret = true
  end

  if cfg:at('symbols') then
    for k, v in cfg:at('symbols'):pairs() do
      symbol_transform(cfg, k, v)
    end
  end

  check_statistics_sanity()

  if not cfg:at('actions') then
    logger.errx('no actions defined')
  else
    -- Perform sanity check for actions
    local actions_defs = { 'no action', 'no_action', -- In case if that's added
                           'greylist', 'add header', 'add_header',
                           'rewrite subject', 'rewrite_subject', 'quarantine',
                           'reject', 'discard' }

    local actions = cfg:at('actions')
    if not actions:at('no action') and not actions:at('no_action') and
        not actions:at('accept') then
      for _, d in ipairs(actions_defs) do
        if actions:at(d) then

          local action_score
          local act = actions:at(d)
          if act:type() ~= 'object' then
            action_score = act:unwrap()
          elseif act:type() == 'object' and act:at('score') then
            action_score = act:at('score'):unwrap()
          end

          if act:type() ~= 'object' and not action_score then
            actions[d] = nil
          elseif type(action_score) == 'number' and action_score < 0 then
            actions['no_action'] = actions:at(d):unwrap() - 0.001
            logger.infox(rspamd_config, 'set no_action score to: %s, as action %s has negative score',
                actions:at('no_action'):unwrap(), d)
            break
          end
        end
      end
    end

    local actions_set = lua_util.list_to_hash(actions_defs)

    -- Now check actions section for garbage
    actions_set['unknown_weight'] = true
    actions_set['grow_factor'] = true
    actions_set['subject'] = true

    for k, _ in cfg:at('actions'):pairs() do
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
    for i = 1, (#actions_order - 1) do
      local act = actions_order[i]

      local act_value = actions:at(act)

      if act_value then
        local val_type = act_value:type()
        local score = 0
        if val_type == 'string' then
          if act_value:unwrap() ~= 'null' then
            score = tonumber(act_value:unwrap())
          end
        elseif val_type == 'number' then
          score = act_value:unwrap()
        end

        for j = i + 1, #actions_order do
          local next_act = actions_order[j]
          if actions:at(next_act) and actions:at(next_act):type() == 'number' then
            local next_score = actions:at(next_act):unwrap()
            if next_score <= score then
              logger.errx(rspamd_config, 'invalid actions thresholds order: action %s (%s) must have lower ' ..
                  'score than action %s (%s)', act, score, next_act, next_score)
              ret = false
            end
          end
        end
      end
    end
  end

  -- DKIM signing/ARC legacy
  for _, mod in ipairs({ 'dkim_signing', 'arc' }) do
    if cfg:at(mod) then
      if cfg:at(mod):at('auth_only') then
        if cfg:at(mod):at('sign_authenticated') then
          logger.warnx(rspamd_config,
              'both auth_only (%s) and sign_authenticated (%s) for %s are specified, prefer auth_only',
              cfg:at(mod):at('auth_only'):unwrap(), cfg:at(mod):at('sign_authenticated'):unwrap(), mod)
        end
        cfg:at(mod).sign_authenticated = cfg:at(mod):at('auth_only')
      end
    end
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

  -- Try to find some obvious issues with configuration
  for k, v in cfg:pairs() do
    if v:type() == 'object' and v:at(k) and v:at(k):type() == 'object' then
      logger.errx('nested section: %s { %s { ... } }, it is likely a configuration error',
          k, k)
    end
  end

  -- If neural network is enabled we MUST have `check_all_filters` flag
  if cfg:at('neural') then

    if cfg:at('options') then
      if not cfg:at('options'):at('check_all_filters') then
        logger.infox(rspamd_config, 'enable `options.check_all_filters` for neural network')
        cfg:at('options')['check_all_filters'] = true
      end
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
    cfg.surbl = nil
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
    cfg.emails = nil
  end

  -- Common misprint options.upstreams -> options.upstream
  if type(cfg.options) == 'table' and type(cfg.options.upstreams) == 'table' and not cfg.options.upstream then
    cfg.options.upstream = cfg.options.upstreams
  end

  return ret, cfg
end
