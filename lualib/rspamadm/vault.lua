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
show:argument "domain"
      :description "Domain to create key for"
      :args "+"

local delete = parser:command "delete del rm remove"
      :description "Delete element from the vault"
delete:argument "domain"
    :description "Domain to create delete key(s) for"
    :args "+"


local newkey = parser:command "newkey new create"
                     :description "Add new key to the vault"
newkey:argument "domain"
      :description "Domain to create key for"
      :args "+"
newkey:option "-s --selector"
      :description "Selector to use"
      :count "?"
newkey:option "-A --algorithm"
      :argname("<type>")
      :convert {
        rsa = "rsa",
        ed25519 = "ed25519",
        eddsa = "ed25519",
      }
      :default "rsa"
newkey:option "-b --bits"
      :argname("<nbits>")
      :convert(tonumber)
      :default "1024"
newkey:option "-x --expire"
      :argname("<days>")
      :convert(tonumber)
newkey:flag "-r --rewrite"

local roll = parser:command "roll rollover"
                   :description "Perform keys rollover"
roll:argument "domain"
    :description "Domain to roll key(s) for"
    :args "+"
roll:option "-T --ttl"
    :description "Validity period for old keys (days)"
    :convert(tonumber)
    :default "1"
roll:flag "-r --remove-expired"
    :description "Remove expired keys"
roll:option "-x --expire"
    :argname("<days>")
    :convert(tonumber)

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

local function is_http_error(err, data)
  return err or (math.floor(data.code / 100) ~= 2)
end

local function parse_vault_reply(data)
  local p = ucl.parser()
  local res,parser_err = p:parse_string(data)

  if not res then
    return nil,parser_err
  else
    return p:get_object(),nil
  end
end

local function maybe_print_vault_data(opts, data, func)
  if data then
    local res,parser_err = parse_vault_reply(data)

    if not res then
      printf('vault reply for cannot be parsed: %s', parser_err)
    else
      if func then
        printf(ucl.to_format(func(res), opts.output))
      else
        printf(ucl.to_format(res, opts.output))
      end
    end
  else
    printf('no data received')
  end
end

local function print_dkim_txt_record(b64, selector, alg)
  local labels = {}
  local prefix = string.format("v=DKIM1; k=%s; p=", alg)
  b64 = prefix .. b64
  if #b64 < 255 then
    labels = {'"' .. b64 .. '"'}
  else
    for sl=1,#b64,256 do
      table.insert(labels, '"' .. b64:sub(sl, sl + 255) .. '"')
    end
  end

  printf("%s._domainkey IN TXT ( %s )", selector,
      table.concat(labels, "\n\t"))
end

local function show_handler(opts, domain)
  local uri = vault_url(opts, domain)
  local err,data = rspamd_http.request{
    config = rspamd_config,
    ev_base = rspamadm_ev_base,
    session = rspamadm_session,
    resolver = rspamadm_dns_resolver,
    url = uri,
    headers = {
      ['X-Vault-Token'] = opts.token
    }
  }

  if is_http_error(err, data) then
    printf('cannot get request to the vault (%s), HTTP error code %s', uri, data.code)
    maybe_print_vault_data(opts, err)
    os.exit(1)
  else
    maybe_print_vault_data(opts, data.content, function(obj)
      return obj.data.selectors
    end)
  end
end

local function delete_handler(opts, domain)
  local uri = vault_url(opts, domain)
  local err,data = rspamd_http.request{
    config = rspamd_config,
    ev_base = rspamadm_ev_base,
    session = rspamadm_session,
    resolver = rspamadm_dns_resolver,
    url = uri,
    method = 'delete',
    headers = {
      ['X-Vault-Token'] = opts.token
    }
  }

  if is_http_error(err, data) then
    printf('cannot get request to the vault (%s), HTTP error code %s', uri, data.code)
    maybe_print_vault_data(opts, err)
    os.exit(1)
  else
    printf('deleted key(s) for %s', domain)
  end
end

local function list_handler(opts)
  local uri = vault_url(opts)
  local err,data = rspamd_http.request{
    config = rspamd_config,
    ev_base = rspamadm_ev_base,
    session = rspamadm_session,
    resolver = rspamadm_dns_resolver,
    url = uri .. '?list=true',
    headers = {
      ['X-Vault-Token'] = opts.token
    }
  }

  if is_http_error(err, data) then
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

local function create_and_push_key(opts, domain, existing)
  local uri = vault_url(opts, domain)
  local sk,pk = genkey(opts)

  local res = {
    selectors = {
      [1] = {
        selector = opts.selector,
        domain = domain,
        key = tostring(sk),
        pubkey = tostring(pk),
        alg = opts.algorithm,
        bits = opts.bits or 0,
        valid_start = os.time(),
      }
    }
  }

  for _,sel in ipairs(existing) do
    res.selectors[#res.selectors + 1] = sel
  end

  if opts.expire then
    res.selectors[1].valid_end = os.time() + opts.expire * 3600 * 24
  end

  local err,data = rspamd_http.request{
    config = rspamd_config,
    ev_base = rspamadm_ev_base,
    session = rspamadm_session,
    resolver = rspamadm_dns_resolver,
    url = uri,
    method = 'put',
    headers = {
      ['Content-Type'] = 'application/json',
      ['X-Vault-Token'] = opts.token
    },
    body = {
      ucl.to_format(res, 'json-compact')
    },
  }

  if is_http_error(err, data) then
    printf('cannot get request to the vault (%s), HTTP error code %s', uri, data.code)
    maybe_print_vault_data(opts, data.content)
    os.exit(1)
  else
    maybe_printf(opts,'stored key for: %s, selector: %s', domain, opts.selector)
    maybe_printf(opts, 'please place the corresponding public key as following:')

    if opts.silent then
      printf('%s', pk)
    else
      print_dkim_txt_record(tostring(pk), opts.selector, opts.algorithm)
    end
  end
end

local function newkey_handler(opts, domain)
  local uri = vault_url(opts, domain)

  if not opts.selector then
    opts.selector = string.format('%s-%s', opts.algorithm,
        os.date("!%Y%m%d"))
  end

  local err,data = rspamd_http.request{
    config = rspamd_config,
    ev_base = rspamadm_ev_base,
    session = rspamadm_session,
    resolver = rspamadm_dns_resolver,
    url = uri,
    method = 'get',
    headers = {
      ['X-Vault-Token'] = opts.token
    }
  }

  if is_http_error(err, data) or not data.content then
    create_and_push_key(opts, domain,{})
  else
    -- Key exists
    local rep = parse_vault_reply(data.content)

    if not rep or not rep.data then
      printf('cannot parse reply for %s: %s', uri, data.content)
      os.exit(1)
    end

    local elts = rep.data.selectors

    if not elts then
      create_and_push_key(opts, domain,{})
      os.exit(0)
    end

    for _,sel in ipairs(elts) do
      if sel.alg == opts.algorithm then
        printf('key with the specific algorithm %s is already presented at %s selector for %s domain',
            opts.algorithm, sel.selector, domain)
        os.exit(1)
      else
        create_and_push_key(opts, domain, elts)
      end
    end
  end
end

local function roll_handler(opts, domain)
  local uri = vault_url(opts, domain)
  local res = {
    selectors = {}
  }

  local err,data = rspamd_http.request{
    config = rspamd_config,
    ev_base = rspamadm_ev_base,
    session = rspamadm_session,
    resolver = rspamadm_dns_resolver,
    url = uri,
    method = 'get',
    headers = {
      ['X-Vault-Token'] = opts.token
    }
  }

  if is_http_error(err, data) or not data.content then
    printf("No keys to roll for domain %s", domain)
    os.exit(1)
  else
    local rep = parse_vault_reply(data.content)

    if not rep or not rep.data then
      printf('cannot parse reply for %s: %s', uri, data.content)
      os.exit(1)
    end

    local elts = rep.data.selectors

    if not elts then
      printf("No keys to roll for domain %s", domain)
      os.exit(1)
    end

    local nkeys = {} -- indexed by algorithm

    local function insert_key(sel, add_expire)
      if not nkeys[sel.alg] then
        nkeys[sel.alg] = {}
      end

      if add_expire then
        sel.valid_end = os.time() + opts.ttl * 3600 * 24
      end

      table.insert(nkeys[sel.alg], sel)
    end

    for _,sel in ipairs(elts) do
      if sel.valid_end and sel.valid_end < os.time() then
        if not opts.remove_expired then
          insert_key(sel, false)
        else
          maybe_printf(opts, 'removed expired key for %s (selector %s, expire "%s"',
              domain, sel.selector, os.date('%c', sel.valid_end))
        end
      else
        insert_key(sel, true)
      end
    end

    -- Now we need to ensure that all but one selectors have either expired or just a single key
    for alg,keys in pairs(nkeys) do
      table.sort(keys, function(k1, k2)
        if k1.valid_end and k2.valid_end then
          return k1.valid_end > k2.valid_end
        elseif k1.valid_end then
          return true
        elseif k2.valid_end then
          return false
        end
        return false
      end)
      -- Exclude the key with the highest expiration date and examine the rest
      if not (#keys == 1 or fun.all(function(k)
            return k.valid_end and k.valid_end < os.time()
          end, fun.tail(keys))) then
        printf('bad keys list for %s and %s algorithm', domain, alg)
        fun.each(function(k)
          if not k.valid_end then
            printf('selector %s, algorithm %s has a key with no expire',
                k.selector, k.alg)
          elseif k.valid_end >= os.time() then
            printf('selector %s, algorithm %s has a key that not yet expired: %s',
                k.selector, k.alg, os.date('%c', k.valid_end))
          end
        end, fun.tail(keys))
        os.exit(1)
      end
      -- Do not create new keys, if we only want to remove expired keys
      if not opts.remove_expired then
        -- OK to process
        -- Insert keys for each algorithm in pairs <old_key(s)>, <new_key>
        local sk,pk = genkey({algorithm = alg, bits = keys[1].bits})
        local selector = string.format('%s-%s', alg,
            os.date("!%Y%m%d"))

        if selector == keys[1].selector then
          selector = selector .. '-1'
        end
        local nelt = {
          selector = selector,
          domain = domain,
          key = tostring(sk),
          pubkey = tostring(pk),
          alg = alg,
          bits = keys[1].bits,
          valid_start = os.time(),
        }

        if opts.expire then
          nelt.valid_end = os.time() + opts.expire * 3600 * 24
        end

        table.insert(res.selectors, nelt)
      end
      for _,k in ipairs(keys) do
        table.insert(res.selectors, k)
      end
    end
  end

  -- We can now store res in the vault
  err,data = rspamd_http.request{
    config = rspamd_config,
    ev_base = rspamadm_ev_base,
    session = rspamadm_session,
    resolver = rspamadm_dns_resolver,
    url = uri,
    method = 'put',
    headers = {
      ['Content-Type'] = 'application/json',
      ['X-Vault-Token'] = opts.token
    },
    body = {
      ucl.to_format(res, 'json-compact')
    },
  }

  if is_http_error(err, data) then
    printf('cannot put request to the vault (%s), HTTP error code %s', uri, data.code)
    maybe_print_vault_data(opts, data.content)
    os.exit(1)
  else
    for _,key in ipairs(res.selectors) do
      if not key.valid_end or key.valid_end > os.time() + opts.ttl * 3600 * 24  then
        maybe_printf(opts,'rolled key for: %s, new selector: %s', domain, key.selector)
        maybe_printf(opts, 'please place the corresponding public key as following:')

        if opts.silent then
          printf('%s', key.pubkey)
        else
          print_dkim_txt_record(key.pubkey, key.selector, key.alg)
        end

      end
    end

    maybe_printf(opts, 'your old keys will be valid until %s',
        os.date('%c', os.time() + opts.ttl * 3600 * 24))
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
    fun.each(function(d) show_handler(opts, d) end, opts.domain)
  elseif command == 'newkey' then
    fun.each(function(d) newkey_handler(opts, d) end, opts.domain)
  elseif command == 'roll' then
    fun.each(function(d) roll_handler(opts, d) end, opts.domain)
  elseif command == 'delete' then
    fun.each(function(d) delete_handler(opts, d) end, opts.domain)
  else
    parser:error(string.format('command %s is not implemented', command))
  end
end

return {
  handler = handler,
  description = parser._description,
  name = 'vault'
}
