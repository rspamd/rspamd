--[[
Copyright (c) 2018, Vsevolod Stakhov <vsevolod@highsecure.ru>

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
local rspamd_keypair = require "rspamd_cryptobox_keypair"
local ucl = require "ucl"

-- Define command line options
local parser = argparse()
    :name "rspamadm keypair"
    :description "Manages keypairs for Rspamd"
    :help_description_margin(30)
    :command_target("command")
    :require_command(false)

local generate = parser:command "generate gen g"
                       :description "Creates a new keypair"
generate:flag "-s --sign"
        :description "Generates a sign keypair instead of the encryption one"
generate:flag "-n --nist"
        :description "Uses nist encryption algorithm"
generate:mutex(
    generate:flag "-j --json"
            :description "Output JSON instead of UCL",
    generate:flag "-u --ucl"
            :description "Output UCL"
            :default(true)
)

-- Default command is generate, so duplicate options
parser:flag "-s --sign"
        :description "Generates a sign keypair instead of the encryption one"
parser:flag "-n --nist"
        :description "Uses nist encryption algorithm"
parser:mutex(
    parser:flag "-j --json"
            :description "Output JSON instead of UCL",
    parser:flag "-u --ucl"
            :description "Output UCL"
            :default(true)
)

local function handler(args)
  local opts = parser:parse(args)

  local command = opts.command or "generate"

  if command == 'generate' then
    local mode = 'encryption'
    if opts.sign then
      mode = 'sign'
    end
    local alg = 'curve25519'
    if opts.nist then
      alg = 'nist'
    end
    -- TODO: probably, do it in a more safe way
    local kp = rspamd_keypair.create(mode, alg):totable()

    local format = 'ucl'

    if opts.json then
      format = 'json'
    end
    io.write(ucl.to_format(kp, format))
  else
    parser:error('command %s is not yet implemented', command)
  end
end

return {
  name = 'keypair',
  aliases = {'kp', 'key'},
  handler = handler,
  description = parser._description
}