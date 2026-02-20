--[[
Copyright (c) 2025, Vsevolod Stakhov <vsevolod@rspamd.com>

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

-- luacheck: globals rspamd_config confighelp

--[[[
-- @module aliases
-- Email aliases resolution and message classification plugin
--
-- This plugin:
-- - Resolves email aliases (Unix, virtual, service-specific)
-- - Classifies message direction (inbound/outbound/internal)
-- - Applies plus-addressing and Gmail-specific rules
-- - Inserts classification symbols
--]]

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local lua_util = require "lua_util"
local lua_aliases = require "lua_aliases"
local fun = require "fun"

local N = "aliases"

--[[ Forwarding detection functions (moved from rules/forwarding.lua) ]] --

--- Check for Google forwarding (VERP-based)
local function check_fwd_google(task)
  if not (task:has_from(1) and task:has_recipients(1)) then
    return false
  end
  local envfrom = task:get_from { 'smtp', 'orig' }
  local envrcpts = task:get_recipients(1)
  if #envrcpts > 1 then
    return false
  end
  local rcpt = envrcpts[1].addr:lower()
  local verp = rcpt:gsub('@', '=')
  local ef_user = envfrom[1].user:lower()
  if ef_user:find('+caf_=' .. verp, 1, true) then
    local _, _, user = ef_user:find('^(.+)+caf_=')
    if user then
      user = user .. '@' .. envfrom[1].domain
      return true, 'google', user
    end
  end
  return false
end

--- Check for Yandex forwarding
local function check_fwd_yandex(task)
  if not (task:has_from(1) and task:has_recipients(1)) then
    return false
  end
  local hostname = task:get_hostname()
  if hostname and hostname:lower():find('%.yandex%.[a-z]+$') then
    if task:has_header('X-Yandex-Forward') then
      return true, 'yandex'
    end
  end
  return false
end

--- Check for Mail.ru forwarding
local function check_fwd_mailru(task)
  if not (task:has_from(1) and task:has_recipients(1)) then
    return false
  end
  local hostname = task:get_hostname()
  if hostname and hostname:lower():find('%.mail%.ru$') then
    if task:has_header('X-MailRu-Forward') then
      return true, 'mailru'
    end
  end
  return false
end

--- Check for SRS (Sender Rewriting Scheme) forwarding
local function check_fwd_srs(task)
  if not (task:has_from(1) and task:has_recipients(1)) then
    return false
  end
  local envfrom = task:get_from(1)
  local envrcpts = task:get_recipients(1)
  if #envrcpts > 1 then
    return false
  end
  local srs = '=' .. envrcpts[1].domain:lower() ..
      '=' .. envrcpts[1].user:lower()
  if envfrom[1].user:lower():find('^srs[01]=') and
      envfrom[1].user:lower():find(srs, 1, false) then
    return true, 'srs'
  end
  return false
end

--- Check for Sieve forwarding
local function check_fwd_sieve(task)
  if not (task:has_from(1) and task:has_recipients(1)) then
    return false
  end
  local envfrom = task:get_from(1)
  local envrcpts = task:get_recipients(1)
  if #envrcpts > 1 then
    return false
  end
  if envfrom[1].user:lower():find('^srs[01]=') then
    if task:has_header('X-Sieve-Redirected-From') then
      return true, 'sieve'
    end
  end
  return false
end

--- Check for cPanel forwarding
local function check_fwd_cpanel(task)
  if not (task:has_from(1) and task:has_recipients(1)) then
    return false
  end
  local envfrom = task:get_from(1)
  local envrcpts = task:get_recipients(1)
  if #envrcpts > 1 then
    return false
  end
  if envfrom[1].user:lower():find('^srs[01]=') then
    local rewrite_hdr = task:get_header('From-Rewrite')
    if rewrite_hdr and rewrite_hdr:find('forwarded message') then
      return true, 'cpanel'
    end
  end
  return false
end

--- Check for generic forwarding (Received headers analysis)
local function check_fwd_generic(task)
  local function normalize_addr(addr)
    addr = string.match(addr, '^<?([^>]*)>?$') or addr
    local cap, _, domain = string.match(addr, '^([^%+][^%+]*)(%+[^@]*)@(.*)$')
    if cap then
      addr = string.format('%s@%s', cap, domain)
    end
    return addr
  end

  if not task:has_recipients(1) or not task:has_recipients(2) then
    return false
  end
  local envrcpts = task:get_recipients(1)
  if #envrcpts > 1 then
    return false
  end
  local has_list_unsub = task:has_header('List-Unsubscribe')
  local to = task:get_recipients(2)
  local matches = 0
  local rcvds = task:get_received_headers()

  if rcvds then
    for _, rcvd in ipairs(rcvds) do
      local addr = rcvd['for']
      if addr then
        addr = normalize_addr(addr)
        matches = matches + 1
        if not rspamd_util.strequal_caseless(addr, envrcpts[1].addr) then
          if matches < 2 and has_list_unsub and to and rspamd_util.strequal_caseless(to[1].addr, addr) then
            return false
          else
            return true, 'generic', addr
          end
        end
        return false
      end
    end
  end
  return false
end

--- Detect all forwarding types
-- @param task rspamd task
-- @return detected (boolean), forwarding_type (string), additional_info (string or nil)
local function detect_forwarding(task)
  -- Check specific forwarding types first (faster)
  local detected, fwd_type, info

  detected, fwd_type, info = check_fwd_google(task)
  if detected then return detected, fwd_type, info end

  detected, fwd_type, info = check_fwd_yandex(task)
  if detected then return detected, fwd_type, info end

  detected, fwd_type, info = check_fwd_mailru(task)
  if detected then return detected, fwd_type, info end

  detected, fwd_type, info = check_fwd_srs(task)
  if detected then return detected, fwd_type, info end

  detected, fwd_type, info = check_fwd_sieve(task)
  if detected then return detected, fwd_type, info end

  detected, fwd_type, info = check_fwd_cpanel(task)
  if detected then return detected, fwd_type, info end

  -- Generic check last (most expensive)
  detected, fwd_type, info = check_fwd_generic(task)
  if detected then return detected, fwd_type, info end

  return false
end

if confighelp then
  rspamd_config:add_example(nil, N,
    "Email aliases resolution and message classification",
    [[
aliases {
	enabled = true;

#Unix aliases
	system_aliases = "/etc/aliases";

#Virtual aliases
	virtual_aliases = "/etc/postfix/virtual";

#Local domains
	local_domains = ["example.com", "mail.example.com"];

#Options
	max_recursion_depth = 10;
	expand_multiple = true;
	enable_gmail_rules = true;
	enable_plus_aliases = true;
}
]])
  return
end

-- Configuration
local settings = {
  enabled = true,

  --Backend configurations
  system_aliases = nil,
  virtual_aliases = nil,
  local_domains = nil,
  rspamd_aliases = nil,

  --Resolution options
  max_recursion_depth = 10,
  expand_multiple = true,
  track_chain = false,

  --Application scope
  apply_to_mime = true,
  apply_to_smtp = true,

  --Service - specific rules
  enable_gmail_rules = true,
  enable_plus_aliases = true,

  --Symbol names
  symbol_local_inbound = 'LOCAL_INBOUND',
  symbol_local_outbound = 'LOCAL_OUTBOUND',
  symbol_internal_mail = 'INTERNAL_MAIL',
  symbol_alias_resolved = 'ALIAS_RESOLVED',
  symbol_tagged_from = 'TAGGED_FROM',
  symbol_tagged_rcpt = 'TAGGED_RCPT',

  --Symbol scores
  score_local_inbound = 0.0,
  score_local_outbound = 0.0,
  score_internal_mail = 0.0,
  score_alias_resolved = 0.0,
  score_tagged_from = 0.0,
  score_tagged_rcpt = 0.0,
}

--- Helper to update address fields after resolution
-- @param addr address table
-- @param new_user new user part
-- @param new_domain new domain part
local function set_addr(addr, new_user, new_domain)
  if new_user then
    addr.user = new_user
  end
  if new_domain then
    addr.domain = new_domain
  end

  -- Only update if we have both user and domain as non-empty strings
  if addr.user and addr.user ~= '' and addr.domain and addr.domain ~= '' then
    addr.addr = string.format('%s@%s', addr.user, addr.domain)

    if addr.name and #addr.name > 0 then
      addr.raw = string.format('"%s" <%s>', addr.name, addr.addr)
    else
      addr.raw = string.format('<%s>', addr.addr)
    end
  else
    -- Invalid address - don't modify
    lua_util.debugm(N, rspamd_config,
        'set_addr: invalid address user=%s domain=%s, not modifying',
        addr.user or 'nil', addr.domain or 'nil')
  end
end

--- Process aliases callback (prefilter)
local function aliases_callback(task)
  local resolve_opts = {
    max_depth = settings.max_recursion_depth,
    track_chain = settings.track_chain,
    expand_multiple = false, -- Don't expand in simple resolution
  }

  local alias_resolved = false
  local tagged_from = {}
  local tagged_rcpt = {}

  -- Detect forwarding BEFORE any modifications
  local forwarding_detected, fwd_type, fwd_info = detect_forwarding(task)

  -- Classify message BEFORE modifying addresses (important!)
  local classification = lua_aliases.classify_message(task, {
    max_depth = settings.max_recursion_depth,
    track_chain = false,
    expand_multiple = settings.expand_multiple,
    forwarding_detected = forwarding_detected,
    forwarding_type = fwd_type,
    forwarding_info = fwd_info,
  })

  --- Check and resolve From address
  -- @param addr_type 'smtp' or 'mime'
  local function check_from(addr_type)
    if not task:has_from(addr_type) then
      return
    end

    local addr = task:get_from(addr_type)[1]
    local original_addr = addr.addr

    -- Apply service-specific rules (Gmail, plus-aliases)
    if settings.enable_gmail_rules or settings.enable_plus_aliases then
      local nu, tags, nd = lua_aliases.apply_service_rules(addr)

      if nu or nd then
        set_addr(addr, nu, nd)

        if tags and #tags > 0 then
          fun.each(function(t)
            if t and #t > 0 then
              table.insert(tagged_from, t)
            end
          end, tags)
        end

        alias_resolved = true
      end
    end

    -- Resolve through alias system
    local canonical = lua_aliases.resolve_address(addr, resolve_opts)
    if canonical and canonical:lower() ~= original_addr:lower() then
      -- Update address
      local user, domain = canonical:match('^([^@]+)@(.+)$')
      if user and domain then
        set_addr(addr, user, domain)
        alias_resolved = true
      end
    end

    -- Update in task
    if alias_resolved then
      task:set_from(addr_type, addr, 'alias')
    end
  end

  --- Check and resolve recipients
  -- @param addr_type 'smtp' or 'mime'
  local function check_rcpt(addr_type)
    if not task:has_recipients(addr_type) then
      return
    end

    local modified = false
    local addrs = task:get_recipients(addr_type)

    for _, addr in ipairs(addrs) do
      local original_addr = addr.addr

      -- Apply service-specific rules
      if settings.enable_gmail_rules or settings.enable_plus_aliases then
        local nu, tags, nd = lua_aliases.apply_service_rules(addr)
        if nu or nd then
          set_addr(addr, nu, nd)

          if tags and #tags > 0 then
            fun.each(function(t)
              if t and #t > 0 then
                table.insert(tagged_rcpt, t)
              end
            end, tags)
          end

          modified = true
          alias_resolved = true
        end
      end

      -- Resolve through alias system
      local canonical = lua_aliases.resolve_address(addr, resolve_opts)
      if canonical and canonical:lower() ~= original_addr:lower() then
        -- Update address
        local user, domain = canonical:match('^([^@]+)@(.+)$')
        if user and domain then
          set_addr(addr, user, domain)
          modified = true
          alias_resolved = true
        end
      end
    end

    -- Update in task
    if modified then
      task:set_recipients(addr_type, addrs, 'alias')
    end
  end

  -- Process SMTP addresses
  if settings.apply_to_smtp then
    check_from('smtp')
    check_rcpt('smtp')
  end

  -- Process MIME addresses
  if settings.apply_to_mime then
    check_from('mime')
    check_rcpt('mime')
  end

  -- Insert tagging symbols
  if #tagged_from > 0 then
    task:insert_result(settings.symbol_tagged_from, 1.0, tagged_from)
  end

  if #tagged_rcpt > 0 then
    task:insert_result(settings.symbol_tagged_rcpt, 1.0, tagged_rcpt)
  end

  -- Insert forwarding symbols (for backward compatibility with rules/forwarding.lua)
  if forwarding_detected then
    if fwd_type == 'google' then
      task:insert_result('FWD_GOOGLE', 1.0, fwd_info or '')
    elseif fwd_type == 'yandex' then
      task:insert_result('FWD_YANDEX', 1.0)
    elseif fwd_type == 'mailru' then
      task:insert_result('FWD_MAILRU', 1.0)
    elseif fwd_type == 'srs' then
      task:insert_result('FWD_SRS', 1.0)
    elseif fwd_type == 'sieve' then
      task:insert_result('FWD_SIEVE', 1.0)
    elseif fwd_type == 'cpanel' then
      task:insert_result('FWD_CPANEL', 1.0)
    elseif fwd_type == 'generic' then
      task:insert_result('FORWARDED', 1.0, fwd_info or '')
    end

    lua_util.debugm(N, task, 'detected forwarding: %s', fwd_type)
  end

  -- Insert classification symbols (classification was done at the beginning)
  if classification.direction == 'inbound' then
    task:insert_result(settings.symbol_local_inbound, 1.0)
  elseif classification.direction == 'outbound' then
    task:insert_result(settings.symbol_local_outbound, 1.0)
  elseif classification.direction == 'internal' then
    task:insert_result(settings.symbol_internal_mail, 1.0)
  end

  -- Insert alias resolution symbol
  if alias_resolved then
    task:insert_result(settings.symbol_alias_resolved, 1.0)
  end

  -- Store classification in task cache for other plugins
  task:cache_set('aliases_classification', classification)

  lua_util.debugm(N, task, 'classification: %s, from_local: %s, to_local: %s',
    classification.direction,
    classification.from_local,
    classification.to_local)
end

-- Module initialization
local opts = rspamd_config:get_all_opt(N)
if opts then
  settings = lua_util.override_defaults(settings, opts)

  if settings.enabled then
    -- Initialize lua_aliases library
    local init_opts = {
      system_aliases = settings.system_aliases,
      virtual_aliases = settings.virtual_aliases,
      local_domains = settings.local_domains,
      rspamd_aliases = settings.rspamd_aliases,
    }

    local success = lua_aliases.init(rspamd_config, init_opts)
    if not success then
      rspamd_logger.errx(rspamd_config, 'failed to initialize lua_aliases')
      return
    end

    -- Register prefilter callback
    local id = rspamd_config:register_symbol({
      name = 'ALIASES_CHECK',
      type = 'prefilter',
      callback = aliases_callback,
      priority = lua_util.symbols_priorities.top + 1,
      flags = 'nice,explicit_disable',
      group = 'aliases',
    })

    -- Register classification symbols
    rspamd_config:register_symbol({
      name = settings.symbol_local_inbound,
      type = 'virtual',
      parent = id,
      score = settings.score_local_inbound,
      description = 'Mail from external to local domain',
      group = 'aliases',
    })

    rspamd_config:register_symbol({
      name = settings.symbol_local_outbound,
      type = 'virtual',
      parent = id,
      score = settings.score_local_outbound,
      description = 'Mail from local to external domain',
      group = 'aliases',
    })

    rspamd_config:register_symbol({
      name = settings.symbol_internal_mail,
      type = 'virtual',
      parent = id,
      score = settings.score_internal_mail,
      description = 'Mail from local to local domain',
      group = 'aliases',
    })

    rspamd_config:register_symbol({
      name = settings.symbol_alias_resolved,
      type = 'virtual',
      parent = id,
      score = settings.score_alias_resolved,
      description = 'Address was resolved through aliases',
      group = 'aliases',
    })

    rspamd_config:register_symbol({
      name = settings.symbol_tagged_from,
      type = 'virtual',
      parent = id,
      score = settings.score_tagged_from,
      description = 'From address has plus-tags',
      group = 'aliases',
    })

    rspamd_config:register_symbol({
      name = settings.symbol_tagged_rcpt,
      type = 'virtual',
      parent = id,
      score = settings.score_tagged_rcpt,
      description = 'Recipient has plus-tags',
      group = 'aliases',
    })

    -- Register forwarding detection symbols (moved from rules/forwarding.lua)
    rspamd_config:register_symbol({
      name = 'FWD_GOOGLE',
      type = 'virtual',
      parent = id,
      score = 0.0,
      description = 'Message was forwarded by Google',
      group = 'forwarding',
    })

    rspamd_config:register_symbol({
      name = 'FWD_YANDEX',
      type = 'virtual',
      parent = id,
      score = 0.0,
      description = 'Message was forwarded by Yandex',
      group = 'forwarding',
    })

    rspamd_config:register_symbol({
      name = 'FWD_MAILRU',
      type = 'virtual',
      parent = id,
      score = 0.0,
      description = 'Message was forwarded by Mail.ru',
      group = 'forwarding',
    })

    rspamd_config:register_symbol({
      name = 'FWD_SRS',
      type = 'virtual',
      parent = id,
      score = 0.0,
      description = 'Message was forwarded using Sender Rewriting Scheme (SRS)',
      group = 'forwarding',
    })

    rspamd_config:register_symbol({
      name = 'FWD_SIEVE',
      type = 'virtual',
      parent = id,
      score = 0.0,
      description = 'Message was forwarded using Sieve',
      group = 'forwarding',
    })

    rspamd_config:register_symbol({
      name = 'FWD_CPANEL',
      type = 'virtual',
      parent = id,
      score = 0.0,
      description = 'Message was forwarded using cPanel',
      group = 'forwarding',
    })

    rspamd_config:register_symbol({
      name = 'FORWARDED',
      type = 'virtual',
      parent = id,
      score = 0.0,
      description = 'Message was forwarded',
      group = 'forwarding',
    })

    rspamd_logger.infox(rspamd_config, 'aliases plugin enabled with forwarding detection')
  else
    rspamd_logger.infox(rspamd_config, 'aliases plugin disabled')
  end
end
