--[[
Copyright (c) 2011-2017, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- Emails is module for different checks for emails inside messages

if confighelp then
  return
end

-- Rules format:
-- symbol = sym, map = file:///path/to/file, domain_only = yes
-- symbol = sym2, dnsbl = bl.somehost.com, domain_only = no
local rules = {}
local logger = require "rspamd_logger"
local hash = require "rspamd_cryptobox_hash"
local rspamd_lua_utils = require "lua_util"
local util = require "rspamd_util"
local N = "emails"

-- Check rule for a single email
local function check_email_rule(task, rule, addr)
  if rule['dnsbl'] then
    local email
    local to_resolve

    if rule['domain_only'] then
      email = addr.domain
    else
      email = string.format('%s%s%s', addr.user, rule.delimiter, addr.domain)
    end

    local function emails_dns_cb(_, _, results, err)
      if err and (err ~= 'requested record is not found'
          and err ~= 'no records with this name') then
        logger.errx(task, 'Error querying DNS: %1', err)
      elseif results then
        if rule['hash'] then
          task:insert_result(rule['symbol'], 1.0, {email, to_resolve})
        else
          task:insert_result(rule['symbol'], 1.0, email)
        end

      end
    end

    logger.debugm(N, task, "check %s on %s", email, rule['dnsbl'])

    if rule['hash'] then
      local hkey = hash.create_specific(rule['hash'], email)

      if rule['encoding'] == 'base32' then
        to_resolve = hkey:base32()
      else
        to_resolve = hkey:hex()
      end

      if rule['hashlen'] and type(rule['hashlen']) == 'number' then
        if #to_resolve > rule['hashlen'] then
          to_resolve = string.sub(to_resolve, 1, rule['hashlen'])
        end
      end
    else
      to_resolve = email
    end

    local dns_arg = string.format('%s.%s', to_resolve, rule['dnsbl'])

    logger.debugm(N, task, "query %s", dns_arg)

    task:get_resolver():resolve_a({
      task=task,
      name = dns_arg,
      callback = emails_dns_cb})
  elseif rule['map'] then
    if rule['domain_only'] then
      local key = addr.domain
      if rule['map']:get_key(key) then
        task:insert_result(rule['symbol'], 1)
        logger.infox(task, '<%1> email: \'%2\' is found in list: %3',
          task:get_message_id(), key, rule['symbol'])
      end
    else
      local key = string.format('%s%s%s', addr.user, rule.delimiter, addr.domain)
      if rule['map']:get_key(key) then
        task:insert_result(rule['symbol'], 1)
        logger.infox(task, '<%1> email: \'%2\' is found in list: %3',
          task:get_message_id(), key, rule['symbol'])
      end
    end
  end
end

-- Check email
local function gen_check_emails(rule)
  return function(task)
    local emails = task:get_emails()
    local checked = {}
    if emails and not rule.skip_body then
      for _,addr in ipairs(emails) do
        local to_check = string.format('%s%s%s', addr:get_user(),
          rule.delimiter, addr:get_host())
        local naddr = {
          user = (addr:get_user() or ''):lower(),
          domain = (addr:get_host() or ''):lower(),
          addr = to_check:lower()
        }

        rspamd_lua_utils.remove_email_aliases(naddr)

        if not checked[naddr.addr] then
          check_email_rule(task, rule, naddr)
          checked[naddr.addr] = true
        end
      end
    end

    if rule.check_replyto then
      local function get_raw_header(name)
        return ((task:get_header_full(name) or {})[1] or {})['value']
      end

      local replyto = get_raw_header('Reply-To')
      if not replyto then return false end
      local rt = util.parse_mail_address(replyto)

      if rt and rt[1] then
        rspamd_lua_utils.remove_email_aliases(rt[1])
        if not checked[rt[1].addr] then
          check_email_rule(task, rule, rt[1])
          checked[rt[1].addr] = true
        end
      end
    end
  end
end

local opts = rspamd_config:get_module_opt('emails', 'rules')
if opts and type(opts) == 'table' then
  for k,v in pairs(opts) do
    local rule = v
    if not rule['symbol'] then
      rule['symbol'] = k
    end

    if not rule['delimiter'] then
      rule['delimiter'] = "@"
    end

    if rule['map'] then
      rule['name'] = rule['map']
      rule['map'] = rspamd_config:add_map({
        url = rule['name'],
        description = string.format('Emails rule %s', rule['symbol']),
        type = 'regexp'
      })
    end
    if not rule['symbol'] or (not rule['map'] and not rule['dnsbl']) then
      logger.errx(rspamd_config, 'incomplete rule: %s', rule)
    else
      table.insert(rules, rule)
      logger.infox(rspamd_config, 'add emails rule %s',
        rule['dnsbl'] or rule['name'] or '???')
    end
  end
end

if #rules > 0 then
  for _,rule in ipairs(rules) do
    local cb = gen_check_emails(rule)
    rspamd_config:register_symbol({
      name = rule['symbol'],
      callback = cb,
    })
  end
end
