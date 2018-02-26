--[[
Copyright (c) 2017, Vsevolod Stakhov <vsevolod@highsecure.ru>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]] --

if confighelp then
  return
end

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local rspamd_http = require "rspamd_http"
local rspamd_keypairlib = require "rspamd_cryptobox_keypair"
local rspamd_cryptolib = require "rspamd_cryptobox"
local fun = require "fun"

local settings = {
  sync_time = 60.0,
  saved_cookie = '',
  timeout = 10.0,
}

local function send_data_mirror(m, cfg, ev_base, body)
  local function store_callback(err, _, _, _)
    if err then
      rspamd_logger.errx(cfg, 'cannot save data on %(%s): %s', m.server, m.name, err)
    else
      rspamd_logger.infox(cfg, 'saved data on %s(%s)', m.server, m.name)
    end
  end
  rspamd_http.request{
    url = string.format('http://%s//update_v1/%s', m.server, m.name),
    resolver = cfg:get_resolver(),
    config = cfg,
    ev_base = ev_base,
    timeout = settings.timeout,
    callback = store_callback,
    body = body,
    peer_key = m.pubkey,
    keypair = m.keypair,
  }
end

local function collect_fuzzy_hashes(cfg, ev_base)
  local function data_callback(err, _, body, _)
    if not body or err then
      rspamd_logger.errx(cfg, 'cannot load data: %s', err)
    else
      -- Here, we actually copy body once for each mirror
      fun.each(function(_, v) send_data_mirror(v, cfg, ev_base, body) end,
        settings.mirrors)
    end
  end

  local function cookie_callback(err, _, body, _)
    if not body or err then
      rspamd_logger.errx(cfg, 'cannot load cookie: %s', err)
    else
      if settings.saved_cookie ~= tostring(body) then
        settings.saved_cookie = tostring(body)
        rspamd_logger.infox(cfg, 'received collection cookie %s',
          tostring(rspamd_util.encode_base32(settings.saved_cookie:sub(1, 6))))
        local sig = rspamd_cryptolib.sign_memory(settings.sign_keypair,
          settings.saved_cookie)
        if not sig then
          rspamd_logger.info(cfg, 'cannot sign cookie')
        else
          rspamd_http.request{
            url = string.format('http://%s/data', settings.collect_server),
            resolver = cfg:get_resolver(),
            config = cfg,
            ev_base = ev_base,
            timeout = settings.timeout,
            callback = data_callback,
            peer_key = settings.collect_pubkey,
            headers = {
              Signature = sig:hex()
            },
            opaque_body = true,
          }
        end
      else
        rspamd_logger.info(cfg, 'cookie has not changed, do not update')
      end
    end
  end
  rspamd_logger.infox(cfg, 'start fuzzy collection, next sync in %s seconds',
    settings.sync_time)
  rspamd_http.request{
    url = string.format('http://%s/cookie', settings.collect_server),
    resolver = cfg:get_resolver(),
    config = cfg,
    ev_base = ev_base,
    timeout = settings.timeout,
    callback = cookie_callback,
    peer_key = settings.collect_pubkey,
  }

  return settings.sync_time
end

local function test_mirror_config(k, m)
  if not m.server then
    rspamd_logger.errx(rspamd_config, 'server is missing for the mirror')
    return false
  end

  if not m.pubkey then
    rspamd_logger.errx(rspamd_config, 'pubkey is missing for the mirror')
    return false
  end

  if type(k) ~= 'string' and not m.name then
    rspamd_logger.errx(rspamd_config, 'name is missing for the mirror')
    return false
  end

  if not m.keypair then
    rspamd_logger.errx(rspamd_config, 'keypair is missing for the mirror')
    return false
  end

  if not m.name then
    m.name = k
  end

  return true
end

local opts = rspamd_config:get_all_opt('fuzzy_collect')

if opts and type(opts) == 'table' then
  for k,v in pairs(opts) do
    settings[k] = v
  end
  local sane_config = true

  if not settings['sign_keypair'] then
    rspamd_logger.errx(rspamd_config, 'sign_keypair is missing')
    sane_config = false
  end

  settings['sign_keypair'] = rspamd_keypairlib.create(settings['sign_keypair'])
  if not settings['sign_keypair'] then
    rspamd_logger.errx(rspamd_config, 'sign_keypair is invalid')
    sane_config = false
  end

  if not settings['collect_server'] then
    rspamd_logger.errx(rspamd_config, 'collect_server is missing')
    sane_config = false
  end

  if not settings['collect_pubkey'] then
    rspamd_logger.errx(rspamd_config, 'collect_pubkey is missing')
    sane_config = false
  end

  if not settings['mirrors'] then
    rspamd_logger.errx(rspamd_config, 'collect_pubkey is missing')
    sane_config = false
  end

  if not fun.all(test_mirror_config, settings['mirrors']) then
    sane_config = false
  end

  if sane_config then
    rspamd_config:add_on_load(function(_, ev_base, worker)
      if worker:is_primary_controller() then
        rspamd_config:add_periodic(ev_base, 0.0,
          function(_cfg, _ev_base)
            return collect_fuzzy_hashes(_cfg, _ev_base)
          end)
      end
    end)
  else
    rspamd_logger.errx(rspamd_config, 'module is not configured properly')
  end
end
