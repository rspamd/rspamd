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
local lua_util = require "lua_util"
local ansicolors = require "ansicolors"

local parser = argparse()
    :name "rspamadm dns_tool"
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
parser:mutex(
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
  local lua_spf = require("lua_ffi").spf
  local rspamd_task = require "rspamd_task"

  local task = rspamd_task:create(rspamd_config, rspamadm_ev_base)
  task:set_session(rspamadm_session)
  task:set_resolver(rspamadm_dns_resolver)

  if opts.ip then
    task:set_from_ip(opts.ip)
  end

  if opts.from then
    task:set_from('smtp', {addr = opts.from})
  elseif opts.domain then
    task:set_from('smtp', {user = 'user', domain = opts.domain})
  else
    io.stderr:write('Neither domain nor from specified\n')
    os.exit(1)
  end

  local function display_spf_results(elt, colored)
    local dec = function(e) return e end

    if colored then
      dec = function(e) return highlight(e) end

      if elt.res == 'pass' then
        dec = function(e) return green(e) end
      elseif elt.res == 'fail' then
        dec = function(e) return red(e) end
      end

    end
    printf('%s: %s', highlight('Result'), dec(elt.res))
    printf('%s: %s', highlight('Network'), dec(elt.ipnet))

    if elt.spf_str then
      printf('%s: %s', highlight('Original'), elt.spf_str)
    end
  end

  local function cb(success, res, matched)
    if success then
      if opts.ip and not opts.all then
        if matched then
          display_spf_results(matched, true)
        else
          printf('Not matched')
        end

        os.exit(0)
      end

      printf('SPF record for %s; digest: %s',
          highlight(opts.domain or opts.from), highlight(res.digest))
      for _,elt in ipairs(res.addrs) do
        if lua_util.table_cmp(elt, matched) then
          printf("%s", highlight('*** Matched ***'))
          display_spf_results(elt, true)
          printf('------')
        else
          display_spf_results(elt, false)
          printf('------')
        end
      end
    else
      printf('Cannot get SPF record: %s', res)
    end
  end
  lua_spf.spf_resolve(task, cb)
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