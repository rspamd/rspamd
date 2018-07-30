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
]]--

if confighelp then
  return
end

-- Some popular UA
local default_ua = {
  'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
  'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
  'Wget/1.9.1',
  'Mozilla/5.0 (Android; Linux armv7l; rv:9.0) Gecko/20111216 Firefox/9.0 Fennec/9.0',
  'Mozilla/5.0 (Windows NT 5.2; RW; rv:7.0a1) Gecko/20091211 SeaMonkey/9.23a1pre',
  'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko',
  'W3C-checklink/4.5 [4.160] libwww-perl/5.823',
  'Lynx/2.8.8dev.3 libwww-FM/2.14 SSL-MM/1.4.1',
}

local redis_params
local N = 'url_redirector'
local settings = {
  expire = 86400, -- 1 day by default
  timeout = 10, -- 10 seconds by default
  nested_limit = 5, -- How many redirects to follow
  --proxy = "http://example.com:3128", -- Send request through proxy
  key_prefix = 'rdr:', -- default hash name
  check_ssl = false, -- check ssl certificates
  max_size = 10 * 1024, -- maximum body to process
  user_agent = default_ua,
  redirectors_only = true, -- follow merely redirectors
  top_urls_key = 'rdr:top_urls', -- key for top urls
  top_urls_count = 200, -- how many top urls to save
}

local rspamd_logger = require "rspamd_logger"
local rspamd_http = require "rspamd_http"
local hash = require "rspamd_cryptobox_hash"
local lua_util = require "lua_util"

local function cache_url(task, orig_url, url, key, param)
  local function redis_trim_cb(err, data)
    if err then
      rspamd_logger.errx(task, 'got error while getting top urls count: %s', err)
    else
      rspamd_logger.infox(task, 'trimmed url set to %s elements',
        settings.top_urls_count)
    end
    rspamd_plugins.surbl.continue_process(url, param)
  end

  -- Cleanup logic
  local function redis_card_cb(err, data)
    if err then
      rspamd_logger.errx(task, 'got error while getting top urls count: %s', err)
    else
      if data then
        if tonumber(data) > settings.top_urls_count * 2 then
          local ret = rspamd_redis_make_request(task,
            redis_params, -- connect params
            key, -- hash key
            true, -- is write
            redis_trim_cb, --callback
            'ZREMRANGEBYRANK', -- command
            {settings.top_urls_key, '0',
              tostring(settings.top_urls_count + 1)} -- arguments
          )
          if not ret then
            rspamd_logger.errx(task, 'cannot trim top urls set')
            rspamd_plugins.surbl.continue_process(url, param)
          else
            rspamd_logger.infox(task, 'need to trim urls set from %s to %s elements',
              data,
              settings.top_urls_count)
            return
          end
        end
      end
    end

    rspamd_plugins.surbl.continue_process(url, param)
  end

  local function redis_set_cb(err, _)
    if err then
      rspamd_logger.errx(task, 'got error while setting redirect keys: %s', err)
    else
      local ret = rspamd_redis_make_request(task,
        redis_params, -- connect params
        key, -- hash key
        false, -- is write
        redis_card_cb, --callback
        'ZCARD', -- command
        {settings.top_urls_key} -- arguments
      )
      if not ret then
        rspamd_logger.errx(task, 'cannot make redis request to cache results')
        rspamd_plugins.surbl.continue_process(url, param)
      end
    end
  end

  local ret,conn,_ = rspamd_redis_make_request(task,
    redis_params, -- connect params
    key, -- hash key
    true, -- is write
    redis_set_cb, --callback
    'SETEX', -- command
    {key, tostring(settings.expire), url} -- arguments
  )

  if not ret then
    rspamd_logger.errx(task, 'cannot make redis request to cache results')
  else
    conn:add_cmd('ZINCRBY', {settings.top_urls_key, '1', url})
  end
end

local function resolve_cached(task, orig_url, url, key, param, ntries)
  local function resolve_url()
    if ntries > settings.nested_limit then
      -- We cannot resolve more, stop
      rspamd_logger.infox(task, 'cannot get more requests to resolve %s, stop on %s after %s attempts',
        orig_url, url, ntries)
      cache_url(task, orig_url, url, key, param)

      return
    end

    local function http_callback(err, code, body, headers)
      if err then
        rspamd_logger.infox(task, 'found redirect error from %s to %s, err message: %s',
          orig_url, url, err)
        cache_url(task, orig_url, url, key, param)
      else
        if code == 200 then
          if orig_url == url then
            rspamd_logger.infox(task, 'direct url %s, err code 200',
              url)
          else
            rspamd_logger.infox(task, 'found redirect from %s to %s, err code 200',
              orig_url, url)
          end

          cache_url(task, orig_url, url, key, param)

        elseif code == 301 or code == 302 then
          local loc = headers['location']
          rspamd_logger.infox(task, 'found redirect from %s to %s, err code %s',
            orig_url, loc, code)
          if loc then
            if settings.redirectors_only then
              if rspamd_plugins.surbl.is_redirector(task, loc) then
                resolve_cached(task, orig_url, loc, key, param, ntries + 1)
              else
                rspamd_logger.debugm(N, task,
                  "stop resolving redirects as %s is not a redirector", loc)
                cache_url(task, orig_url, loc, key, param)
              end
            else
              resolve_cached(task, orig_url, loc, key, param, ntries + 1)
            end
          else
            rspamd_logger.infox(task, "no location, headers: %s", headers)
            cache_url(task, orig_url, url, key, param)
          end
        else
          rspamd_logger.infox(task, 'found redirect error from %s to %s, err code: %s',
            orig_url, url, code)
          cache_url(task, orig_url, url, key, param)
        end
      end
    end

    local ua
    if type(settings.user_agent) == 'string' then
      ua = settings.user_agent
    else
      ua = settings.user_agent[math.random(#settings.user_agent)]
    end

    rspamd_http.request{
      headers = {
        ['User-Agent'] = ua,
      },
      url = url,
      task = task,
      method = 'head',
      max_size = settings.max_size,
      timeout = settings.timeout,
      opaque_body = true,
      no_ssl_verify = not settings.check_ssl,
      callback = http_callback
    }
  end
  local function redis_get_cb(err, data)
    if not err then
      if type(data) == 'string' then
        if data ~= 'processing' then
          -- Got cached result
          rspamd_logger.infox(task, 'found cached redirect from %s to %s',
            url, data)
          rspamd_plugins.surbl.continue_process(data, param)
          return
        end
      end
    end
    local function redis_reserve_cb(nerr, ndata)
      if nerr then
        rspamd_logger.errx(task, 'got error while setting redirect keys: %s', nerr)
      elseif ndata == 'OK' then
        orig_url = url
        resolve_url()
      end
    end

    if orig_url == url then
      local ret = rspamd_redis_make_request(task,
        redis_params, -- connect params
        key, -- hash key
        true, -- is write
        redis_reserve_cb, --callback
        'SET', -- command
        {key, 'processing', 'EX', tostring(settings.timeout * 2), 'NX'} -- arguments
      )
      if not ret then
        rspamd_logger.errx(task, 'Couldn\'t schedule SET')
      end
    else
      resolve_url()
    end

  end
  local ret = rspamd_redis_make_request(task,
    redis_params, -- connect params
    key, -- hash key
    false, -- is write
    redis_get_cb, --callback
    'GET', -- command
    {key} -- arguments
  )
  if not ret then
    rspamd_logger.errx(task, 'cannot make redis request to check results')
  end
end

local function url_redirector_handler(task, url, param)
  local url_str = url:get_raw()
  -- 32 base32 characters are roughly 20 bytes of data or 160 bits
  local key = settings.key_prefix .. hash.create(url_str):base32():sub(1, 32)
  resolve_cached(task, url_str, url_str, key, param, 1)
end

local opts =  rspamd_config:get_all_opt('url_redirector')
if opts then
  for k,v in pairs(opts) do
    settings[k] = v
  end
  redis_params = rspamd_parse_redis_server('url_redirector')
  if not redis_params then
    rspamd_logger.infox(rspamd_config, 'no servers are specified, disabling module')
    lua_util.disable_module(N, "redis")
  else
    if rspamd_plugins.surbl then
      rspamd_plugins.surbl.register_redirect(rspamd_config, url_redirector_handler)
    else
      rspamd_logger.infox(rspamd_config, 'surbl module is not enabled, disabling module')
      lua_util.disable_module(N, "fail")
    end
  end
end
