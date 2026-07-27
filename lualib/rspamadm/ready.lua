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

-- Define command line options
local parser = argparse()
    :name 'rspamadm ready'
    :description 'Check if Rspamd controller is ready'
    :help_description_margin(30)
    :command_target('command')

parser:option '-c --config'
      :description 'Path to config file'
      :argname('config')
      :default(rspamd_paths['CONFDIR'] .. '/rspamd.conf')
parser:option '-u --url'
      :description 'URL of the Rspamd controller'
      :argname('url')
      :default('http://localhost:11334')
parser:option '-t --timeout'
      :description 'Total timeout in seconds'
      :argname('timeout')
      :convert(tonumber)
      :default(60)
parser:option '-i --interval'
      :description 'Polling interval in seconds'
      :argname('interval')
      :convert(tonumber)
      :default(1)
parser:flag '--no-ssl-verify'
      :description 'Disable SSL verification'
parser:flag '-q --quiet'
      :description 'Only output errors'
parser:flag '-v --verbose'
      :description 'Output more information'

local function load_config(config_file)
  if not rspamd_config then
    rspamd_logger.errx('rspamd_config is not available')
    os.exit(1)
  end
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
  -- Check if required global variables exist
  if not rspamadm_ev_base or not rspamadm_session or not rspamadm_dns_resolver then
    rspamd_logger.errx('Required global variables are not available')
    os.exit(1)
  end
  local total_timeout = tonumber(args.timeout)
  local interval = tonumber(args.interval)
  local url = args.url
  -- Properly construct the /ready URL
  if not url:match("/ready$") then
    -- Remove trailing slash if present, then add /ready
    url = url:gsub("/$", "") .. "/ready"
  end
  
  local start_time = os.time()
  local attempts = 0
  local timer_set = false

  local function retry()
    attempts = attempts + 1
    timer_set = false
    if not args.quiet then
      io.stdout:write(string.format("Attempt %d: Checking if Rspamd is ready...\n", attempts))
    end
    rspamd_http.request({
      url = url,
      config = rspamd_config,
      ev_base = rspamadm_ev_base,
      session = rspamadm_session,
      resolver = rspamadm_dns_resolver,
      log_obj = rspamd_config,
      no_ssl_verify = args.no_ssl_verify,
      callback = function(err, response)
        -- Check if total timeout has been reached
        if os.time() - start_time >= total_timeout then
          if not args.quiet then
            io.stderr:write("Timeout reached. Rspamd is not ready.\n")
          end
          os.exit(1)
        end
        if err then
          if args.verbose then
            io.stderr:write(string.format("Error checking Rspamd status: %s\n", err))
          end
          -- Schedule next retry after interval
          rspamadm_ev_base:add_timer(interval * 1000, retry)
          timer_set = true
        else
          if response.code == 200 then
            if not args.quiet then
              io.stdout:write("Rspamd is ready and operational!\n")
            end
            os.exit(0)
          else
            if args.verbose then
              io.stderr:write(string.format("Rspamd not ready (status code: %s)\n", response.code))
              if response.body then
                io.stderr:write(string.format("Response body: %s\n", response.body))
              end
            end
            -- Schedule next retry after interval
            rspamadm_ev_base:add_timer(interval * 1000, retry)
            timer_set = true
          end
        end
      end
    })
  end

  -- Start the first attempt
  retry()
  -- Set a failsafe timer in case the HTTP request fails to even start
  if not timer_set then
    rspamadm_ev_base:add_timer(interval * 1000, retry)
  end
  -- Enter the event loop
  rspamadm_ev_base:loop()
end

local function handler(args)
  local cmd_opts = parser:parse(args)
  -- Check for rspamd_paths
  if not rspamd_paths then
    rspamd_logger.errx('rspamd_paths is not available')
    os.exit(1)
  end
  load_config(cmd_opts.config)
  poll_ready({
    timeout = cmd_opts.timeout,
    interval = cmd_opts.interval,
    url = cmd_opts.url,
    no_ssl_verify = cmd_opts.no_ssl_verify,
    quiet = cmd_opts.quiet,
    verbose = cmd_opts.verbose
  })
end
return {
  handler = handler,
  description = parser._description,
  name = 'ready'
}
