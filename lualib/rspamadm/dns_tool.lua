--[[
Copyright (c) 2019, Vsevolod Stakhov <vsevolod@highsecure.ru>

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


local argparse = require "argparse"
local rspamd_logger = require "rspamd_logger"
local ansicolors = require "ansicolors"
local bit = require "bit"

local parser = argparse()
    :name "rspamadm dnstool"
    :description "DNS tools provided by Rspamd"
    :help_description_margin(30)
    :command_target("command")
    :require_command(true)

parser:option "-c --config"
      :description "Path to config file"
      :argname("<cfg>")
      :default(rspamd_paths["CONFDIR"] .. "/" .. "rspamd.conf")

local spf = parser:command "spf"
                      :description "Extracts spf records"
spf:mutex(
    spf:option "-d --domain"
       :description "Domain to use"
       :argname("<domain>"),
    spf:option "-f --from"
       :description "SMTP from to use"
       :argname("<from>")
)

spf:option "-i --ip"
   :description "Source IP address to use"
   :argname("<ip>")
spf:flag "-a --all"
   :description "Print all records"

local function printf(fmt, ...)
  if fmt then
    io.write(string.format(fmt, ...))
  end
  io.write('\n')
end

local function highlight(str)
  return ansicolors.white .. str .. ansicolors.reset
end

local function green(str)
  return ansicolors.green .. str .. ansicolors.reset
end

local function red(str)
  return ansicolors.red .. str .. ansicolors.reset
end

local function load_config(opts)
  local _r,err = rspamd_config:load_ucl(opts['config'])

  if not _r then
    rspamd_logger.errx('cannot parse %s: %s', opts['config'], err)
    os.exit(1)
  end

  _r,err = rspamd_config:parse_rcl({'logging', 'worker'})
  if not _r then
    rspamd_logger.errx('cannot process %s: %s', opts['config'], err)
    os.exit(1)
  end
end

local function spf_handler(opts)
  local rspamd_spf = require "rspamd_spf"
  local rspamd_task = require "rspamd_task"
  local rspamd_ip = require "rspamd_ip"

  local task = rspamd_task:create(rspamd_config, rspamadm_ev_base)
  task:set_session(rspamadm_session)
  task:set_resolver(rspamadm_dns_resolver)

  if opts.ip then
    opts.ip = rspamd_ip.fromstring(opts.ip)
    task:set_from_ip(opts.ip)
  else
    opts.all = true
  end

  if opts.from then
    local rspamd_parsers = require "rspamd_parsers"
    local addr_parsed = rspamd_parsers.parse_mail_address(opts.from)
    if addr_parsed then
      task:set_from('smtp', addr_parsed[1])
    else
      io.stderr:write('Invalid from addr\n')
      os.exit(1)
    end
  elseif opts.domain then
    task:set_from('smtp', {user = 'user', domain = opts.domain})
  else
    io.stderr:write('Neither domain nor from specified\n')
    os.exit(1)
  end

  local function flag_to_str(fl)
    if bit.band(fl, rspamd_spf.flags.temp_fail) ~= 0 then
      return "temporary failure"
    elseif bit.band(fl, rspamd_spf.flags.perm_fail) ~= 0 then
      return "permanent failure"
    elseif bit.band(fl, rspamd_spf.flags.na) ~= 0 then
      return "no spf record"
    end

    return "unknown flag: " .. tostring(fl)
  end

  local function display_spf_results(elt, colored)
    local dec = function(e) return e end
    local policy_decode = function(e)
      if e == rspamd_spf.policy.fail then
        return 'reject'
      elseif e == rspamd_spf.policy.pass then
        return 'pass'
      elseif e == rspamd_spf.policy.soft_fail then
        return 'soft fail'
      elseif e == rspamd_spf.policy.neutral then
        return 'neutral'
      end

      return 'unknown'
    end

    if colored then
      dec = function(e) return highlight(e) end

      if elt.result == rspamd_spf.policy.pass  then
        dec = function(e) return green(e) end
      elseif elt.result  == rspamd_spf.policy.fail then
        dec = function(e) return red(e) end
      end

    end
    printf('%s: %s', highlight('Policy'), dec(policy_decode(elt.result)))
    printf('%s: %s', highlight('Network'), dec(elt.addr))

    if elt.str then
      printf('%s: %s', highlight('Original'), elt.str)
    end
  end

  local function cb(record, flags, err)
    if record then
      local result, flag_or_policy, error_or_addr
      if opts.ip then
        result, flag_or_policy, error_or_addr = record:check_ip(opts.ip)
      elseif opts.all then
        result = true
      end
      if opts.ip and not opts.all then
        if result then
          display_spf_results(error_or_addr, true)
        else
          printf('Not matched: %s', error_or_addr)
        end

        os.exit(0)
      end

      if result then
        printf('SPF record for %s; digest: %s',
            highlight(opts.domain or opts.from), highlight(record:get_digest()))
        for _,elt in ipairs(record:get_elts()) do
          if result and error_or_addr and elt.str and elt.str == error_or_addr.str then
            printf("%s", highlight('*** Matched ***'))
            display_spf_results(elt, true)
            printf('------')
          else
            display_spf_results(elt, false)
            printf('------')
          end
        end
      else
        printf('Error getting SPF record: %s (%s flag)', err,
            flag_to_str(flag_or_policy or flags))
      end
    else
      printf('Cannot get SPF record: %s', err)
    end
  end
  rspamd_spf.resolve(task, cb)
end

local function handler(args)
  local opts = parser:parse(args)
  load_config(opts)

  local command = opts.command

  if command == 'spf' then
    spf_handler(opts)
  else
    parser:error('command %s is not implemented', command)
  end
end

return {
  name = 'dnstool',
  aliases = {'dns', 'dns_tool'},
  handler = handler,
  description = parser._description
}