--[[
Copyright (c) 2020, Lionel PRAT <lionel.prat9@gmail.com>
Modified plugin url_redirector.lua by Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- !!WARNING!!: 
-- - This task needs a long time to finish, it is therefore important to adapt the global option "task_timeout"
-- - Redis save more informations in memory, especially if you use check all_urls

-- Features (plugin check_url):
-- - You can check all site or just redirect site map list (if all_url == true)
-- - Use synchrone request
-- - Check if internal site or ip before request 'HEAD'
-- - Symbol if url is direct ip (ex: http://X.X.X.X) but diffference with symbol 'HTTP_TO_IP' is not internal IP
-- - Extract information mimetype, filename
-- - MAP "suspect_mimetype_in_url_map" for create symbol if content-type is present in map
-- - MAP "suspect_filename_in_url" for create symbol if filename is present in map
-- - Symbol if max deep in url redirect is execeeded
-- - Symbol if port no standard
-- - MAP path create symbol if path is suspect in map suspect_path_in_url_map (regexp)
-- - MAP subhost create symbol suspect Host (sub host with many .. => paypal.com.realdom.xx)
-- - MAP ip blacklist create symbol resolv ip from url is in blacklist

if confighelp then
  return
end

local rspamd_logger = require "rspamd_logger"
local rspamd_http = require "rspamd_http"
local hash = require "rspamd_cryptobox_hash"
local rspamd_url = require "rspamd_url"
local rspamd_dns = require "rspamd_dns"
local rspamd_ip = require 'rspamd_ip'
local rspamd_redis = require 'rspamd_redis'
local lua_util = require "lua_util"
local lua_redis = require "lua_redis"
local ucl = require "ucl"
local N = "url_check"

-- Some popular UA
local default_ua = {
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36)',
  'Mozilla/5.0 (Windows NT 5.1; rv:36.0) Gecko/20100101 Firefox/36.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36 Edge/15.15063',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36',
  'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0',
  'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18362',
}

local redis_params

local settings = {
  expire = 86400, -- 1 day by default
  timeout = 10, -- 10 seconds by default
  nested_limit = 5, -- How many redirects to follow
  --proxy = "http://example.com:3128", -- Send request through proxy
  key_prefix= 'rdr:', -- default hash name
  check_ssl = false, -- check ssl certificates
  max_urls = 5, -- how many urls to check
  max_size = 10 * 1024, -- maximum body to process
  mx_check = false, -- check mx on domaine url
  a_check = false, -- check if resolv A host is same than A domain
  user_agent = default_ua,
  mimetype_url_only_allow = true, -- check suspect_mimetype_in_url_map in mode only allowed
  internal_url = false, -- no check url/ip internal
  redirector_symbol = nil, -- insert symbol if redirected url has been found
  download_symbol = nil, -- insert symbol if download file has been found
  mimetype_symbol = nil, -- insert symbol if suspect mimetype (in or not in map suspect_mimetype_in_url_map)
  filename_symbol = nil, -- insert symbol if suspect filename (in map suspect_filename_in_url_map)
  path_symbol = nil, -- insert symbol if suspect url path(in map suspect_path_in_url_map)
  subhost_suspect_symbol = nil, -- suspect subhost
  free_download_symbol = nil, --  download on free site like: google, drive live.com or pastbin/raw
  freehost_symbol = nil, -- insert symbol if suspect use freehost (in map free_hosted_dom_map)
  too_much_redir_symbol = nil, -- to much redirect, cannot be followed
  subhost_max_part_symbol = nil, -- if sub host has lot of part (ex: sub0.sub1.sub2.dom.com) -> sub_host_number_part_max
  port_symbol = nil, -- insert symbol if port url is not standard has been found
  ip_symbol = nil, -- insert symbol if ip direct in url has been found
  mx_symbol = nil, -- insert symbol if domain url have no mx record
  a_symbol = nil, -- insert symbol if domain resolv A is same than host domain A
  redirectors_only = true, -- follow merely redirectors
  all_urls = false, -- check all url, not just redirector_hosts_map
  top_urls_key = 'rdr:top_urls', -- key for top urls -> i don't understand usage of this
  top_urls_count = 200, -- how many top urls to save -> i don't understand usage of this
  redirector_hosts_map = nil, -- check only those redirectors
  suspect_mimetype_in_url_map = nil, -- check mimetype url suspected by user
  mimetype_map_regexp = false, -- if map type regexp: suspect_mimetype_in_url_map 
  suspect_path_in_url_map = nil, -- check mimetype url suspected by user
  suspect_filename_in_url_map = nil, -- check mimetype url suspected by user
  sub_host_number_part_max = 2, -- if sub host has more than 2 part (sub1.sub2.dom.com)
  free_hosted_dom_map = nil, -- map free hosted (tld & host)
  sub_host_suspect_map = nil, -- map subhost suspect regexp (ex: paypal, facebook, bank, ...)
  host_use_get_map = nil, -- map host to use get method (ex: onedrive.live.com)
  url_ip_blacklist_map = nil -- map IP from resolv url
}

local function add_dyn_info_url(task, url, value)
  rspamd_logger.debugm(N, task, 'Enter: add_dyn_info_url -> URL [%s] value: %s ', url, value)
  -- add info symbol
  -- table = {redir=URL, mimetype=MT, expire=EXP, filename=FN, }
  local redir_url = nil
  if value then
    if value['ip'] ~= nil then
      for k,ipx in ipairs(value['ip']) do
        task:insert_result(settings.ip_blacklist_symbol, 1.0, ipx)
      end
    end
    if value['nomx'] ~= nil then
      task:insert_result(settings.mx_symbol, 1.0, tostring(url:get_tld()))
    end
    if value['samea'] ~= nil then
      task:insert_result(settings.a_symbol, 1.0, tostring(url:get_host()))
    end
    if value['redir'] ~= nil then
      -- add information
      redir_url = rspamd_url.create(task:get_mempool(), value['redir'])
      url:set_redirected(redir_url)
      task:inject_url(redir_url)
      if settings.redirector_symbol then
        task:insert_result(settings.redirector_symbol, 1.0,
          string.format('%s->%s', url:get_host(), redir_url:get_host()))
      end
    else
      local host = url:get_host()
      -- check mimetype
      if value['mimetype'] ~= nil then
        -- check if suspect mimetype
        if settings.mimetype_url_only_allow then
          if settings.suspect_mimetype_in_url_map and not settings.suspect_mimetype_in_url_map:get_key(value['mimetype']) then
            -- mode not in whitelist
            task:insert_result(settings.mimetype_symbol, 1.0,
              string.format('%s->%s', host, value['mimetype'] ))
          end
        else
          if settings.suspect_mimetype_in_url_map and settings.suspect_mimetype_in_url_map:get_key(value['mimetype']) then
            -- mode blacklist
            task:insert_result(settings.mimetype_symbol, 1.0,
              string.format('%s->%s', host, value['mimetype'] ))
          end
        end
      end
      -- check filename
      if value['filename'] ~= nil then
        -- check if suspect filename extension or name
        task:insert_result(settings.download_symbol, 1.0,
              string.format('%s->%s', host, value['filename'] ))
        if settings.suspect_filename_in_url_map and settings.suspect_filename_in_url_map:get_key(value['filename']) then
          -- regexp check
          task:insert_result(settings.filename_symbol, 1.0,
            string.format('%s->%s', host, value['filename'] ))
        end
      elseif value['code'] ~= nil and value['code'] == 200 then
        -- check if filename is in URL
        local path = url:get_path()
        local filename = nil
        for i in string.gmatch(path, "[^%/]+") do
          filename = i
        end
        if filename ~= nil and settings.suspect_filename_in_url_map and settings.suspect_filename_in_url_map:get_key(filename) then
          task:insert_result(settings.filename_symbol, 1.0,
            string.format('%s->%s', host, value['filename'] ))
        end
      end
    end
  end
  return redir_url
end

local function redis_read(task, key, command, args)
  local addr = redis_params['read_servers']:get_upstream_by_hash(key)
  if redis_params['expand_keys'] then
    local m = get_key_expansion_metadata(task)
    local indexes = get_key_indexes(command, args)
    for _, i in ipairs(indexes) do
      args[i] = lutil.template(args[i], m)
    end
  end
  local ip_addr = addr:get_addr()
  local options = {
    task = task,
    host = ip_addr,
    timeout = redis_params['timeout'],
    cmd = command,
    args = args
  }
  if redis_params['password'] then
    options['password'] = redis_params['password']
  end
  if redis_params['db'] then
    options['dbname'] = redis_params['db']
  end
  local is_ok, results = rspamd_redis.make_request_sync(options)
  return is_ok, results
end

local function redis_write(task, key, command, args)
  local addr = redis_params['write_servers']:get_upstream_by_hash(key)
  if redis_params['expand_keys'] then
    local m = get_key_expansion_metadata(task)
    local indexes = get_key_indexes(command, args)
    for _, i in ipairs(indexes) do
      args[i] = lutil.template(args[i], m)
    end
  end
  local ip_addr = addr:get_addr()
  local options = {
    task = task,
    host = ip_addr,
    timeout = redis_params['timeout'],
    cmd = command,
    args = args
  }
  if redis_params['password'] then
    options['password'] = redis_params['password']
  end
  if redis_params['db'] then
    options['dbname'] = redis_params['db']
  end
  local is_ok, results = rspamd_redis.make_request_sync(options)
  return is_ok, results
end

local function url_check_process_url(task, urlx, ntries)
  local url_str = urlx:get_raw()
  -- 32 base32 characters are roughly 20 bytes of data or 160 bits
  local key = settings.key_prefix .. hash.create(url_str):base32():sub(1, 32)
  rspamd_logger.debugm(N, task, 'Enter: url_check_process_url -> URL [%s] count: %s -- key: %s', urlx, ntries, key)
  -- resolve_cached(task, url, url, key, 1) -- old
  -- extract host and port and path ...
  local port = urlx:get_port()
  local host = urlx:get_host()
  local tld = urlx:get_tld()
  local path = '/' .. urlx:get_path()
  local subhost = host:sub(1,-string.len(tld)-1)
  -- check port no standard
  if port and not (port == 0) and not ((string.find(string.lower(url_str), 'https://') and port == 443) or (string.find(string.lower(url_str), 'http://') and port == 80) or (string.find(string.lower(url_str), 'ftp://') and port == 21)) then
    task:insert_result(settings.port_symbol, 1.0,string.format('%s->%s', tostring(host), tostring(port)))
  end
  -- check Path suspect
  if  settings.suspect_path_in_url_map and settings.suspect_path_in_url_map:get_key(tostring(path)) then
    task:insert_result(settings.path_symbol, 1.0,string.format('%s->%s', tostring(host), tostring(path)))
  end
  -- check if free site download
  -- TODO: find idea for use user config
  if (string.find(string.lower(url_str), 'drive.google.com/uc') and string.find(string.lower(url_str), 'export=download')) 
                or string.find(string.lower(url_str), 'onedrive.live.com/download')
                or (string.find(string.lower(url_str), 'googleusercontent.com') and string.find(string.lower(url_str), 'e=download')) 
                or string.find(string.lower(url_str), 'pastebin.com/raw/')
  then
    task:insert_result(settings.free_download_symbol, 1.0, tostring(host))
  end
  -- check sub hosting
  local count = 0
  for nouse in string.gmatch(subhost, "[^%.]+")  do
    count = count + 1
  end
  if count > settings.sub_host_number_part_max then
     task:insert_result(settings.subhost_max_part_symbol, 1.0,tostring(host))
  end
  if  settings.sub_host_suspect_map and settings.sub_host_suspect_map:get_key(subhost) then
    task:insert_result(settings.subhost_suspect_symbol, 1.0,tostring(host))
  end
  -- check free hosting
  if  settings.free_hosted_dom_map and (settings.free_hosted_dom_map:get_key(host) or settings.free_hosted_dom_map:get_key(tld)) then
    task:insert_result(settings.freehost_symbol, 1.0, tostring(host))
  end
  -- check if ip local
  local host = urlx:get_host()
  local chunks = {host:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")}
  local host_is_ip = true
  local try_connect = true
  local ip_host = nil
  local bl_ip = {}
  if (#chunks == 4) then
    for _,v in pairs(chunks) do
      if (tonumber(v) < 0 or tonumber(v) > 255) then
        host_is_ip = false
      end
    end
  else
    host_is_ip = false
  end
  local ip4 = nil
  if host_is_ip then ip4 = rspamd_ip.from_string(host) end
  if host_is_ip and ip4:is_valid() then
    if ip4:is_local() then
      try_connect = false
    else
      if settings.redirector_symbol then
        task:insert_result(settings.ip_symbol, 1.0,tostring(host))
      end
    end
  end
  -- check url in cache
  if try_connect then
    -- check in redis cache url
    local is_ok, results = redis_read(task, key, 'GET', {key})
    rspamd_logger.debugm(N, task, 'Redis return %s -> %s', is_ok, results)
    if is_ok and results ~= nil and type(results) == 'string' and results ~= "" then
      try_connect = false
      -- add info
      -- extract information format ucl
      local parser = ucl.parser()
      local resp,err = parser:parse_string(results)
      if err then
        rspamd_logger.errx(task, 'URL [%s] error [%s] to parse ucl string format: %s ', urlx, err, results)
      else
        local value = parser:get_object()
        rspamd_logger.debugm(N, task, 'URL [%s] cache: %s ', urlx, value)
        rurl=add_dyn_info_url(task, urlx, value)
        if rurl ~= nil then
          if not (ntries > settings.nested_limit) then
            if settings.all_urls or not settings.redirectors_only or (settings.redirector_hosts_map and settings.redirector_hosts_map:get_key(rurl:get_host())) then
              -- url redir to check
              rspamd_logger.debugm(N, task, 'Follow Redir URL (from cache): %s', rurl)
              url_check_process_url(task, rurl, ntries+1)
            end
          else
            -- too much redirect for url, cannot be fully followed
            task:insert_result(settings.too_much_redir_symbol, 1.0,
                string.format('%s', rurl:get_host()))
          end
        end
      end
    elseif not host_is_ip then
      -- no cache - verify resolv and not internal
      local is_ok, results = rspamd_dns.request({
                task = task,
                type = 'a',
                name = tostring(host)
      })
      if is_ok then
        rspamd_logger.debugm(N, task, 'Resolved return %s', results)
        for _,r in ipairs(results) do
          local ip4 = rspamd_ip.from_string(tostring(r))
          if ip4:is_valid() then
            if ip4:is_local() then
              try_connect = false
              -- add in cache
              local cache = {}
              local str_table = ucl.to_format(cache, 'ucl')
              local is_ok, results = redis_write(task, key, 'SETEX',  {key, tostring(settings.expire), str_table})
            else
              ip_host = tostring(ip4)
              if settings.url_ip_blacklist_map and settings.url_ip_blacklist_map:get_key(ip_host) then
                -- task:insert_result(settings.ip_blacklist_symbol, 1.0, ip_host)
                -- cache
                table.insert(bl_ip, ip_host)
              end
            end
          end
        end
      else
        -- error resolve
        rspamd_logger.errx(task, 'Error to Resolved %s', host)
        try_connect = false
        -- cache info
        -- Would it be interesting to keep the information from the error? but it will take up unnecessary space
        local cache = {}
        local str_table = ucl.to_format(cache, 'ucl')
        local is_ok, results = redis_write(task, key, 'SETEX',  {key, tostring(settings.expire), str_table})
      end
    end
  end
  -- connect to url if not local and not in cache
  if try_connect then
    rspamd_logger.debugm(N, task, 'Create HEAD request to %s', urlx)
    -- special host change methode to get
    local meth = 'head'
    -- check free hosting
    if  settings.host_use_get_map and settings.host_use_get_map:get_key(host) then
      meth = 'get'
    end
    local err, response = rspamd_http.request({
                  url =  url_str ,
                  task = task,
                  max_size = settings.max_size,
                  timeout = settings.timeout,
                  method = meth,
                  opaque_body = true,
                  no_ssl_verify = not settings.check_ssl
    })
    -- ret http
    rspamd_logger.debugm(N, task,  'Return request to %s ou %s : %s - %s', url_str, err, response)
    if err then
      rspamd_logger.errx(task, 'Error request on %s because error request: %s', host, err)
      -- Would it be interesting to keep the information from the error? but it will take up unnecessary space
      local cache = {}
      local str_table = ucl.to_format(cache, 'ucl')
      local is_ok, results = redis_write(task, key, 'SETEX',  {key, tostring(settings.expire), str_table})
    else
      -- parse info
      local cache = {}
      if next(bl_ip) ~= nil then
        cache['ip'] = bl_ip
      end
      local redir_url = nil
      local code = response['code']
      local headers = response['headers']
      if code == 200 then
        -- code 200 - extract mime & filename if existe
        cache['code'] = 200        
        local head_ct = headers['content-type']
        local head_cd = headers['content-disposition']
        -- local head_lm = headers['last-modified']
        -- local head_date = headers['date']
        if head_ct then
          -- TODO: fix "content-type: text/html; charset=UTF-8" to extract just ct
          cache['mimetype'] = head_ct
        end
        if head_cd then
          local attrs = {}
          string.gsub(head_cd, ';%s*([^%s=]+)="(.-)"', function(attr, val)
	        attrs[attr] = val 
	      end)
	      if attrs.filename then
            cache['filename'] = attrs.filename 
          end
        end
      elseif code == 301 or code == 302 then
        -- code 30X - extract redirect location
        local loc = headers['location']
        if loc then
          if not (string.find(string.lower(loc), 'http://') or string.find(string.lower(loc), 'https://')  or string.find(string.lower(loc), 'ftp://')) then
            -- loc local
            if port and not (port == 0) then
              loc = urlx:get_protocol() .. '://'.. urlx:get_host() .. ':' ..  port .. loc
            else
              loc = urlx:get_protocol() .. '://' .. urlx:get_host() .. loc
            end
          end
          cache['redir']=loc
          redir_url = rspamd_url.create(task:get_mempool(), loc)
        end
      end
      -- check MX domain
      if settings.mx_check then
        local is_ok_mx, results_mx = rspamd_dns.request({
                  task = task,
                  type = 'mx',
                  name = tostring(tld)
        })
        if is_ok_mx then
          -- TODO len()
          local count = true
          for _,r in ipairs(results_mx) do
            count = false
          end
          if count then
             cache['nomx']=true
          end
        else
          cache['nomx']=true
        end
      end
      -- Check A host == A domain
      if settings.a_check and tostring(tld) ~= tostring(host) then
        local is_ok_a, results_a = rspamd_dns.request({
                  task = task,
                  type = 'a',
                  name = tostring(tld)
        })
        if is_ok_a then
          for _,r in ipairs(results_a) do
            if tostring(r) == ip_host then
              cache['samea'] = true
            end
          end
        end
      end
      -- add symboles
      add_dyn_info_url(task, urlx, cache)
      -- cache parsing
      rspamd_logger.debugm(N, task, 'Cache information request for %s -> %s', urlx, cache)
      local str_table = ucl.to_format(cache, 'ucl')
      local is_ok, results = redis_write(task, key, 'SETEX',  {key, tostring(settings.expire), str_table})
      if redir_url ~= nil then 
        if not (ntries > settings.nested_limit) then
          if settings.all_urls or not settings.redirectors_only or (settings.redirector_hosts_map and settings.redirector_hosts_map:get_key(rurl:get_host())) then
            -- url redir to check
            rspamd_logger.debugm(N, task, 'Follow Redir URL: %s', redir_url)
            url_check_process_url(task, redir_url, ntries+1)
          end
        else
          task:insert_result(settings.too_much_redir_symbol, 1.0,
            string.format('%s', redir_url:get_host()))
        end
      end
    end
  end
end

local function url_check_handler(task)
  local sp_urls = lua_util.extract_specific_urls({
      task = task,
      limit = settings.max_urls,
      filter = function(url)
        local host = url:get_host()
        if settings.all_urls or (settings.redirector_hosts_map and settings.redirector_hosts_map:get_key(host)) then
          lua_util.debugm(N, task, 'check url %s', tostring(url))
          return true
        end
      end,
      no_cache = true,
    })

  if sp_urls then
    for _,u in ipairs(sp_urls) do
      url_check_process_url(task, u, 1)
    end
  end
end

local opts = rspamd_config:get_all_opt('url_check')
if opts then
  settings = lua_util.override_defaults(settings, opts)
  redis_params = lua_redis.parse_redis_server('url_check', settings)

  if not redis_params then
    rspamd_logger.infox(rspamd_config, 'no servers are specified, disabling module')
    lua_util.disable_module(N, "redis")
  else
    if not settings.all_urls and not settings.redirector_hosts_map then
      rspamd_logger.infox(rspamd_config, 'no redirector_hosts_map option is specified, disabling module')
      lua_util.disable_module(N, "config")
    else
      local lua_maps = require "lua_maps"
      if settings.redirector_hosts_map then
        settings.redirector_hosts_map = lua_maps.map_add_from_ucl(settings.redirector_hosts_map,
          'set', 'Redirectors definitions')
      end
      if settings.suspect_mimetype_in_url_map then
        local maptype = 'set'
        if settings.mimetype_map_regexp then
          maptype = 'regexp'
        end
        settings.suspect_mimetype_in_url_map = lua_maps.map_add_from_ucl(settings.suspect_mimetype_in_url_map,
          maptype, 'Mimetype Suspect definitions')
      end
      if settings.suspect_filename_in_url_map then
        settings.suspect_filename_in_url_map = lua_maps.map_add_from_ucl(settings.suspect_filename_in_url_map,
          'regexp', 'Filename regexp Suspect definitions')
      end
      if settings.suspect_path_in_url_map then
        settings.suspect_path_in_url_map = lua_maps.map_add_from_ucl(settings.suspect_path_in_url_map,
          'regexp', 'Path regexp Suspect definitions')
      end
      if settings.free_hosted_dom_map then
        settings.free_hosted_dom_map = lua_maps.map_add_from_ucl(settings.free_hosted_dom_map,
          'set', 'Freehosting host or tld definitions')
      end
      if settings.sub_host_suspect_map then
        settings.sub_host_suspect_map = lua_maps.map_add_from_ucl(settings.sub_host_suspect_map,
          'regexp', 'Subhost regexp Suspect definitions')
      end
      if settings.host_use_get_map then
        settings.host_use_get_map = lua_maps.map_add_from_ucl(settings.host_use_get_map,
          'set', 'Host redirect need get method')
      end
      if settings.url_ip_blacklist_map  then
        settings.url_ip_blacklist_map  = lua_maps.map_add_from_ucl(settings.url_ip_blacklist_map,
          'set', 'IP fropm url resolv Suspect definitions')
      end

      lua_redis.register_prefix(settings.key_prefix .. '[a-z0-9]{32}', N,
        'URL informations hashes', {
          type = 'string',
        })
      local id = rspamd_config:register_symbol{
        name = 'URL_CHECKING',
        type = 'callback,prefilter',
        flags = 'coro', 
        callback = url_check_handler,
      }

      if settings.redirector_symbol then
        rspamd_config:register_symbol{
          name = settings.redirector_symbol,
          type = 'virtual',
          parent = id,
          score = 0,
	  group = N
        }
      end
      if settings.download_symbol then
        rspamd_config:register_symbol{
          name = settings.download_symbol,
          type = 'virtual',
          parent = id,
          score = 0,
	  group = N
        }
      end
      if settings.mx_symbol then
        rspamd_config:register_symbol{
          name = settings.mx_symbol,
          type = 'virtual',
          parent = id,
          score = 0,
	  group = N
        }
      end
      if settings.ip_symbol then
        rspamd_config:register_symbol{
          name = settings.ip_symbol,
          type = 'virtual',
          parent = id,
          score = 0,
	  group = N
        }
      end
      if settings.port_symbol then
        rspamd_config:register_symbol{
          name = settings.port_symbol,
          type = 'virtual',
          parent = id,
          score = 0,
	  group = N
        }
      end
      if settings.mimetype_symbol then
        rspamd_config:register_symbol{
          name = settings.mimetype_symbol,
          type = 'virtual',
          parent = id,
          score = 0,
	  group = N
        }
      end
      if settings.freehost_symbol then
        rspamd_config:register_symbol{
          name = settings.freehost_symbol,
          type = 'virtual',
          parent = id,
          score = 0,
	  group = N
        }
      end
      if settings.free_download_symbol then
        rspamd_config:register_symbol{
          name = settings.free_download_symbol,
          type = 'virtual',
          parent = id,
          score = 0,
	  group = N
        }
      end
      if settings.subhost_suspect_symbol then
        rspamd_config:register_symbol{
          name = settings.subhost_suspect_symbol,
          type = 'virtual',
          parent = id,
          score = 0,
	  group = N
        }
      end
      if settings.path_symbol then
        rspamd_config:register_symbol{
          name = settings.path_symbol,
          type = 'virtual',
          parent = id,
          score = 0,
	  group = N
        }
      end
      if settings.filename_symbol then
        rspamd_config:register_symbol{
          name = settings.filename_symbol,
          type = 'virtual',
          parent = id,
          score = 0,
	  group = N
        }
      end
      if settings.too_much_redir_symbol then
        rspamd_config:register_symbol{
          name = settings.too_much_redir_symbol,
          type = 'virtual',
          parent = id,
          score = 0,
	  group = N
        }
      end
      if settings.subhost_max_part_symbol then
        rspamd_config:register_symbol{
          name = settings.subhost_max_part_symbol,
          type = 'virtual',
          parent = id,
          score = 0,
	  group = N
        }
      end
      if settings.a_symbol then
        rspamd_config:register_symbol{
          name = settings.a_symbol,
          type = 'virtual',
          parent = id,
          score = 0,
	  group = N
        }
      end
      if settings.ip_blacklist_symbol then
        rspamd_config:register_symbol{
          name = settings.ip_blacklist_symbol,
          type = 'virtual',
          parent = id,
          score = 0,
	  group = N
        }
      end
    end
  end
end
