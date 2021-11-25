--[[
Copyright (c) 2021, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- Define command line options
local parser = argparse()
    :name 'rspamadm publicsuffix'
    :description 'Do manipulations with the publicsuffix list'
    :help_description_margin(30)
    :command_target('command')
    :require_command(true)

parser:option '-c --config'
      :description 'Path to config file'
      :argname('config_file')
      :default(rspamd_paths['CONFDIR'] .. '/rspamd.conf')

parser:command 'compile'
    :description 'Compile publicsuffix list if needed'

local function load_config(config_file)
  local _r,err = rspamd_config:load_ucl(config_file)

  if not _r then
    rspamd_logger.errx('cannot load %s: %s', config_file, err)
    os.exit(1)
  end

  _r,err = rspamd_config:parse_rcl({'logging', 'worker'})
  if not _r then
    rspamd_logger.errx('cannot process %s: %s', config_file, err)
    os.exit(1)
  end
end

local function compile_handler(_)
  local rspamd_url = require "rspamd_url"
  local tld_file = rspamd_config:get_tld_path()

  if not tld_file then
    rspamd_logger.errx('missing `url_tld` option, cannot continue')
    os.exit(1)
  end

  rspamd_logger.messagex('loading public suffix file from %s', tld_file)
  rspamd_url.init(tld_file)
  rspamd_logger.messagex('public suffix file has been loaded')
end

local function handler(args)
  local cmd_opts = parser:parse(args)

  load_config(cmd_opts.config_file)


  if cmd_opts.command == 'compile' then
    compile_handler(cmd_opts)
  else
    rspamd_logger.errx('unknown command: %s', cmd_opts.command)
    os.exit(1)
  end
end

return {
  handler = handler,
  description = parser._description,
  name = 'publicsuffix'
}