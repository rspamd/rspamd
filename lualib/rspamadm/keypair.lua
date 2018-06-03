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
local rspamd_crypto = require "rspamd_cryptobox"
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
generate:option "-o --output"
        :description "Write keypair to file"
        :argname "<file>"
generate:mutex(
    generate:flag "-j --json"
            :description "Output JSON instead of UCL",
    generate:flag "-u --ucl"
            :description "Output UCL"
            :default(true)
)

local sign = parser:command "sign sig s"
                   :description "Signs a file using keypair"
sign:option "-k --keypair"
    :description "Keypair to use"
    :argname "<file>"
sign:option "-s --suffix"
    :description "Suffix for signature"
    :argname "<suffix>"
    :default("sig")
sign:argument "file"
    :description "File to sign"
    :argname "<file>"
    :args "*"

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
parser:option "-o --output"
      :description "Write keypair to file"
      :argname "<file>"

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

    if opts.output then
      local out = io.open(opts.output, 'w')
      if not out then
        parser:error('cannot open output to write: ' .. opts.output)
      end
      out:write(ucl.to_format(kp, format))
      out:close()
    else
      io.write(ucl.to_format(kp, format))
    end

  elseif command == 'sign' then
    if opts.file then
      if type(opts.file) == 'string' then
        opts.file = {opts.file}
      end
    else
      parser:error('no files to sign')
    end
    if not opts.keypair then
      parser:error("no keypair specified")
    end

    local ucl_parser = ucl.parser()
    local res,err = ucl_parser:parse_file(opts.keypair)

    if not res then
      parser:error(string.format('cannot load %s: %s', opts.keypair, err))
    end

    local kp = rspamd_keypair.load(ucl_parser:get_object())

    if not kp then
      parser:error("cannot load keypair: " .. opts.keypair)
    end

    for _,fname in ipairs(opts.file) do
      local sig = rspamd_crypto.sign_file(kp, fname)

      if not sig then
        parser:error(string.format("cannot sign %s\n", fname))
      end

      local out = string.format('%s.%s', fname, opts.suffix or 'sig')
      local of = io.open(out, 'w')
      if not of then
        parser:error('cannot open output to write: ' .. out)
      end
      of:write(sig:bin())
      of:close()
      io.write(string.format('signed %s -> %s (%s)\n', fname, out, sig:hex()))
    end
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