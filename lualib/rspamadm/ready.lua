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

local argparse = require "argparse"
local rspamd_http = require "rspamd_http"
local rspamd_logger = require "rspamd_logger"
local rspamd_upstream_list = require "rspamd_upstream_list"
local lua_util = require "lua_util"

local E = {}

-- Define command line options
local parser = argparse()
    :name 'rspamadm ready'
    :description 'Check if Rspamd controller is ready'
    :help_description_margin(30)
    :command_target('command')

parser:option '-c --config'
      :description 'Path to config file'
      :argname('config_file')
      :default(rspamd_paths['CONFDIR'] .. '/rspamd.conf')
parser:option '-u --url'
      :description 'URL of the Rspamd controller'
      :argname('url')
      :default('http://localhost:11334')
parser:option '-t --timeout'
      :description 'Total timeout in seconds'
      :argname('timeout')
      :default('60')
parser:option '-i --interval'
      :description 'Polling interval in seconds'
      :argname('interval')
      :default('1')
parser:flag '--no-ssl-verify'
      :description 'Disable SSL verification'
      :argname('no_ssl_verify')
parser:flag '-q --quiet'
      :description 'Only output errors'
      :argname('quiet')
parser:flag '-v --verbose'
      :description 'Output more information'
      :argname('verbose')

local http_params = {
  config = rspamd_config,
  ev_base = rspamadm_ev_base,
  session = rspamadm_session,
  resolver = rspamadm_dns_resolver,
}

local function load_config(config_file)
  local _r, err = rspamd_config:load_ucl(config_file)

  if not _r then
    rspamd_logger.errx('cannot load %s: %s', config_file, err)
    os.exit(1)
  end

  _r, err = rspamd_config:parse_rcl({ 'logging', 'worker' })
  if not _r then
    rspamd_logger.errx('cannot process %s: %s', config_file, err)
    os.exit(1)
  end

  if not rspamd_config:init_modules() then
    rspamd_logger.errx('cannot init modules when parsing %s', config_file)
    os.exit(1)
  end

  rspamd_config:init_subsystem('symcache')
end

local function poll_ready(args)
  local total_timeout = tonumber(args.timeout)
  local interval = tonumber(args.interval)
  local url = args.url
  
  -- Fix: Properly remove trailing slash without relying on lua_util
  if not url:match("/ready$") then
    url = url:gsub("/$", "") .. "/ready"
  end
  
  local start_time = os.time()
  local attempts = 0
  local exit_code = 1
  
  local function retry()
    if os.time() - start_time >= total_timeout then
      if not args.quiet then
        io.stderr:write("Timeout reached. Rspamd is not ready.\n")
      end
      os.exit(exit_code)
    end
    
    attempts = attempts + 1
    if not args.quiet then
      io.stdout:write(string.format("Attempt %d: Checking if Rspamd is ready...\n", attempts))
    end
    
    local err, response = rspamd_http.request({
      url = url,
      config = rspamd_config,
      ev_base = rspamadm_ev_base,
      session = rspamadm_session,
      resolver = rspamadm_dns_resolver,
      log_obj = rspamd_config,
      no_ssl_verify = args.no_ssl_verify,
    })
    
    if err then
      if args.verbose then
        io.stderr:write(string.format("Error checking Rspamd status: %s\n", err))
      end
    elseif response and response.code == 200 then
      if not args.quiet then
        io.stdout:write("Rspamd is ready and operational!\n")
      end
      exit_code = 0
      os.exit(exit_code)
    else
      local status_code = response and response.code or "unknown"
      if args.verbose then
        io.stderr:write(string.format("Rspamd not ready (status code: %s)\n", status_code))
      end
    end
    
    -- Fix: Using ev_base:add_timer for non-blocking retries
    rspamadm_ev_base:add_timer(interval * 1000, retry)
  end
  
  retry()  -- Start the first attempt
end

local function handler(args)
  local cmd_opts = parser:parse(args)
  
  load_config(cmd_opts.config_file)
  
  poll_ready(cmd_opts)
end

return {
  handler = handler,
  description = parser._description,
  name = 'ready'
}