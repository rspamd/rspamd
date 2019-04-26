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


local rspamd_logger = require "rspamd_logger"
local ansicolors = require "ansicolors"
local ucl = require "ucl"
local argparse = require "argparse"
local fun = require "fun"
local rspamd_http = require "rspamd_http"
local cr = require "rspamd_cryptobox"

local parser = argparse()
    :name "rspamadm vault"
    :description "Perform Hashicorp Vault management"
    :help_description_margin(32)
    :command_target("command")
    :require_command(true)

parser:flag "-s --silent"
      :description "Do not output extra information"
parser:option "-a --addr"
      :description "Vault address (if not defined in VAULT_ADDR env)"
parser:option "-t --token"
      :description "Vault token (not recommended, better define VAULT_TOKEN env)"
parser:option "-p --path"
      :description "Path to work with in the vault"
      :default "dkim"
parser:option "-o --output"
      :description "Output format ('ucl', 'json', 'json-compact', 'yaml')"
      :argname("<type>")
      :convert {
        ucl = "ucl",
        json = "json",
        ['json-compact'] = "json-compact",
        yaml = "yaml",
      }
    :default "ucl"

parser:command "list ls l"
    :description "List elements in the vault"

local show = parser:command "show get"
      :description "Extract element from the vault"
show:option "-d --domain"
      :description "Domain to create key for"
      :count "1"

local newkey = parser:command "newkey new create"
                     :description "Add new key to the vault"
newkey:option "-d --domain"
      :description "Domain to create key for"
      :count "1"
newkey:option "-s --selector"
      :description "Selector to use"
      :count "1"
newkey:option "-A --algorithm"
      :argname("<type>")
      :convert {
        rsa = "rsa",
        ed25519 = "ed25519",
      }
      :default "rsa"
newkey:option "-b --bits"
      :argname("<nbits>")
      :convert(tonumber)
      :default "1024"
newkey:flag "-r --rewrite"


local function printf(fmt, ...)
  if fmt then
    io.write(rspamd_logger.slog(fmt, ...))
  end
  io.write('\n')
end

local function maybe_printf(opts, fmt, ...)
  if not opts.silent then
    printf(fmt, ...)
  end
end

local function highlight(str, color)
  return ansicolors[color or 'white'] .. str .. ansicolors.reset
end

local function vault_url(opts, path)
  if path then
    return string.format('%s/v1/%s/%s', opts.addr, opts.path, path)
  end

  return string.format('%s/v1/%s', opts.addr, opts.path)
end

local function maybe_print_vault_data(opts, data, func)
  local p = ucl.parser()
  local res,parser_err = p:parse_string(data)

  if not res then
    printf('vault reply for cannot be parsed: %s', parser_err)
  else
    local obj = p:get_object()

    if func then
      printf(ucl.to_format(func(obj), opts.output))
    else
      printf(ucl.to_format(obj, opts.output))
    end
  end
end

local function show_handler(opts)
  local uri = vault_url(opts, opts.domain)
  local err,data = rspamd_http.request{
    config = rspamd_config,
    ev_base = rspamadm_ev_base,
    session = rspamadm_session,
    resolver = rspamadm_resolver,
    url = uri,
    headers = {
      ['X-Vault-Token'] = opts.token
    }
  }

  if err then
    printf('cannot get request to the vault (%s), HTTP error code %s', uri, data.code)
    maybe_print_vault_data(opts, err)
    os.exit(1)
  else
    maybe_print_vault_data(opts, data.content, function(obj)
      return obj.data.selectors
    end)
  end
end

local function list_handler(opts)
  local uri = vault_url(opts)
  local err,data = rspamd_http.request{
    config = rspamd_config,
    ev_base = rspamadm_ev_base,
    session = rspamadm_session,
    resolver = rspamadm_resolver,
    url = uri .. '?list=true',
    headers = {
      ['X-Vault-Token'] = opts.token
    }
  }

  if err then
    printf('cannot get request to the vault (%s), HTTP error code %s', uri, data.code)
    maybe_print_vault_data(opts, err)
    os.exit(1)
  else
    maybe_print_vault_data(opts, data.content, function(obj)
      return obj.data.keys
    end)
  end
end

-- Returns pair privkey+pubkey
local function genkey(opts)
  return cr.gen_dkim_keypair(opts.algorithm, opts.bits)
end

local function newkey_handler(opts)
  local uri = vault_url(opts, opts.domain)
  local err,data = rspamd_http.request{
    config = rspamd_config,
    ev_base = rspamadm_ev_base,
    session = rspamadm_session,
    resolver = rspamadm_resolver,
    url = uri,
    method = 'get',
    headers = {
      ['X-Vault-Token'] = opts.token
    }
  }

  if err or not data.content.data then
    local sk,pk = genkey(opts)

    local res = {
      selectors = {
        [1] = {
          selector = opts.selector,
          domain = opts.domain,
          key = sk
        }
      }
    }

    ret,data = rspamd_http.request{
      config = rspamd_config,
      ev_base = rspamadm_ev_base,
      session = rspamadm_session,
      resolver = rspamadm_resolver,
      url = uri,
      method = 'put',
      headers = {
        ['X-Vault-Token'] = opts.token
      },
      body = {
        ucl.to_format(res, 'json-compact')
      },
    }

    if not ret then
      printf('cannot get request to the vault (%s), HTTP error code %s', uri, data.code)
      maybe_print_vault_data(opts, data.content)
      os.exit(1)
    end
  else
    -- Existing data
  end
end

local function handler(args)
  local opts = parser:parse(args)

  if not opts.addr then
    opts.addr = os.getenv('VAULT_ADDR')
  end

  if not opts.token then
    opts.token = os.getenv('VAULT_TOKEN')
  else
    maybe_printf(opts, 'defining token via command line is insecure, define it via environment variable %s',
        highlight('VAULT_TOKEN', 'red'))
  end

  if not opts.token or not opts.addr then
    printf('no token or/and vault addr has been specified, exiting')
    os.exit(1)
  end

  local command = opts.command

  if command == 'list' then
    list_handler(opts)
  elseif command == 'show' then
    show_handler(opts)
  elseif command == 'newkey' then
    newkey_handler(opts)
  else
    parser:error(string.format('command %s is not implemented', command))
  end
end

return {
  handler = handler,
  description = parser._description,
  name = 'vault'
}