--[[
Copyright (c) 2016, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local rspamd_regexp = require "rspamd_regexp"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local lua_util = require "lua_util"
local fun = require "fun"
local redis_params

local N = "antivirus"

if confighelp then
  rspamd_config:add_example(nil, 'antivirus',
    "Check messages for viruses",
    [[
antivirus {
  # multiple scanners could be checked, for each we create a configuration block with an arbitrary name
  clamav {
    # If set force this action if any virus is found (default unset: no action is forced)
    # action = "reject";
    # If set, then rejection message is set to this value (mention single quotes)
    # message = '${SCANNER}: virus found: "${VIRUS}"';
    # Scan mime_parts seperately - otherwise the complete mail will be transfered to AV Scanner
    #scan_mime_parts = true;
    # Scanning Text is suitable for some av scanner databases (e.g. Sanesecurity)
    #scan_text_mime = false;
    #scan_image_mime = false;
    # If `max_size` is set, messages > n bytes in size are not scanned
    max_size = 20000000;
    # symbol to add (add it to metric if you want non-zero weight)
    symbol = "CLAM_VIRUS";
    # type of scanner: "clamav", "fprot", "sophos" or "savapi"
    type = "clamav";
    # For "savapi" you must also specify the following variable
    product_id = 12345;
    # You can enable logging for clean messages
    log_clean = true;
    # servers to query (if port is unspecified, scanner-specific default is used)
    # can be specified multiple times to pool servers
    # can be set to a path to a unix socket
    # Enable this in local.d/antivirus.conf
    servers = "127.0.0.1:3310";
    # if `patterns` is specified virus name will be matched against provided regexes and the related
    # symbol will be yielded if a match is found. If no match is found, default symbol is yielded.
    patterns {
      # symbol_name = "pattern";
      JUST_EICAR = "^Eicar-Test-Signature$";
    }
    # `whitelist` points to a map of IP addresses. Mail from these addresses is not scanned.
    whitelist = "/etc/rspamd/antivirus.wl";
  }
}
]])
  return
end

local default_message = '${SCANNER}: virus found: "${VIRUS}"'

local function match_patterns(default_sym, found, patterns)
  if type(patterns) ~= 'table' then return default_sym end
  if not patterns[1] then
    for sym, pat in pairs(patterns) do
      if pat:match(found) then
        return sym
      end
    end
    return default_sym
  else
    for _, p in ipairs(patterns) do
      for sym, pat in pairs(p) do
        if pat:match(found) then
          return sym
        end
      end
    end
    return default_sym
  end
end

local function yield_result(task, rule, vname)
  local all_whitelisted = true
  if type(vname) == 'string' then
    local symname = match_patterns(rule['symbol'], vname, rule['patterns'])
    if rule['whitelist'] and rule['whitelist']:get_key(vname) then
      rspamd_logger.infox(task, '%s: "%s" is in whitelist', rule['type'], vname)
      return
    end
    task:insert_result(symname, 1.0, vname)
    rspamd_logger.infox(task, '%s: virus found: "%s"', rule['type'], vname)
  elseif type(vname) == 'table' then
    for _, vn in ipairs(vname) do
      local symname = match_patterns(rule['symbol'], vn, rule['patterns'])
      if rule['whitelist'] and rule['whitelist']:get_key(vn) then
        rspamd_logger.infox(task, '%s: "%s" is in whitelist', rule['type'], vn)
      else
        all_whitelisted = false
        task:insert_result(symname, 1.0, vn)
        rspamd_logger.infox(task, '%s: virus found: "%s"', rule['type'], vn)
      end
    end
  end
  if rule['action'] then
    if type(vname) == 'table' then
      if all_whitelisted then return end
      vname = table.concat(vname, '; ')
    end
    task:set_pre_result(rule['action'],
        lua_util.template(rule.message or 'Rejected', {
          SCANNER = rule['type'],
          VIRUS = vname,
        }), N)
  end
end

local function clamav_config(opts)
  local clamav_conf = {
    scan_mime_parts = true;
    scan_text_mime = false;
    scan_image_mime = false;
    default_port = 3310,
    log_clean = false,
    timeout = 15.0, -- FIXME: this will break task_timeout!
    retransmits = 2,
    cache_expire = 3600, -- expire redis in one hour
    message = default_message,
  }

  for k,v in pairs(opts) do
    clamav_conf[k] = v
  end

  if not clamav_conf.prefix then
    clamav_conf.prefix = 'rs_cl'
  end

  if not clamav_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  clamav_conf['upstreams'] = upstream_list.create(rspamd_config,
    clamav_conf['servers'],
    clamav_conf.default_port)

  if clamav_conf['upstreams'] then
    return clamav_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
    clamav_conf['servers'])
  return nil
end

local function fprot_config(opts)
  local fprot_conf = {
    scan_mime_parts = true;
    scan_text_mime = false;
    scan_image_mime = false;
    default_port = 10200,
    timeout = 15.0, -- FIXME: this will break task_timeout!
    log_clean = false,
    retransmits = 2,
    cache_expire = 3600, -- expire redis in one hour
    message = default_message,
  }

  for k,v in pairs(opts) do
    fprot_conf[k] = v
  end

  if not fprot_conf.prefix then
    fprot_conf.prefix = 'rs_fp'
  end

  if not fprot_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  fprot_conf['upstreams'] = upstream_list.create(rspamd_config,
    fprot_conf['servers'],
    fprot_conf.default_port)

  if fprot_conf['upstreams'] then
    return fprot_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
    fprot_conf['servers'])
  return nil
end

local function sophos_config(opts)
  local sophos_conf = {
    scan_mime_parts = true;
    scan_text_mime = false;
    scan_image_mime = false;
    default_port = 4010,
    timeout = 15.0,
    log_clean = false,
    retransmits = 2,
    cache_expire = 3600, -- expire redis in one hour
    message = default_message,
    savdi_report_encrypted = false,
    savdi_report_oversize = false,
  }

  for k,v in pairs(opts) do
    sophos_conf[k] = v
  end

  if not sophos_conf.prefix then
    sophos_conf.prefix = 'rs_sp'
  end

  if not sophos_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  sophos_conf['upstreams'] = upstream_list.create(rspamd_config,
    sophos_conf['servers'],
    sophos_conf.default_port)

  if sophos_conf['upstreams'] then
    return sophos_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
    sophos_conf['servers'])
  return nil
end

local function savapi_config(opts)
  local savapi_conf = {
    scan_mime_parts = true;
    scan_text_mime = false;
    scan_image_mime = false;
    default_port = 4444, -- note: You must set ListenAddress in savapi.conf
    product_id = 0,
    log_clean = false,
    timeout = 15.0, -- FIXME: this will break task_timeout!
    retransmits = 1, -- FIXME: useless, for local files
    cache_expire = 3600, -- expire redis in one hour
    message = default_message,
    tmpdir = '/tmp',
  }

  for k,v in pairs(opts) do
    savapi_conf[k] = v
  end

  if not savapi_conf.prefix then
    savapi_conf.prefix = 'rs_ap'
  end

  if not savapi_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  savapi_conf['upstreams'] = upstream_list.create(rspamd_config,
    savapi_conf['servers'],
    savapi_conf.default_port)

  if savapi_conf['upstreams'] then
    return savapi_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
    savapi_conf['servers'])
  return nil
end

local function kaspersky_config(opts)
  local kaspersky_conf = {
    scan_mime_parts = true;
    scan_text_mime = false;
    scan_image_mime = false;
    product_id = 0,
    log_clean = false,
    timeout = 5.0,
    retransmits = 1, -- use local files, retransmits are useless
    cache_expire = 3600, -- expire redis in one hour
    message = default_message,
    tmpdir = '/tmp',
    prefix = 'rs_ak',
  }

  kaspersky_conf = lua_util.override_defaults(kaspersky_conf, opts)

  if not kaspersky_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  kaspersky_conf['upstreams'] = upstream_list.create(rspamd_config,
      kaspersky_conf['servers'], 0)

  if kaspersky_conf['upstreams'] then
    return kaspersky_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      kaspersky_conf['servers'])
  return nil
end

local function message_not_too_large(task, content, rule)
  local max_size = tonumber(rule['max_size'])
  if not max_size then return true end
  if #content > max_size then
    rspamd_logger.infox("skip %s AV check as it is too large: %s (%s is allowed)",
      rule.type, #content, max_size)
    return false
  end
  return true
end

local function need_av_check(task, content, rule)
  return message_not_too_large(task, content, rule)
end

local function check_av_cache(task, digest, rule, fn)
  local key = digest

  local function redis_av_cb(err, data)
    if data and type(data) == 'string' then
      -- Cached
      if data ~= 'OK' then
        lua_util.debugm(N, task, 'got cached result for %s: %s', key, data)
        data = rspamd_str_split(data, '\v')
        yield_result(task, rule, data)
      else
        lua_util.debugm(N, task, 'got cached result for %s: %s', key, data)
      end
    else
      if err then
        rspamd_logger.errx(task, 'Got error checking cache: %1', err)
      end
      fn()
    end
  end

  if redis_params then

    key = rule['prefix'] .. key

    if rspamd_redis_make_request(task,
      redis_params, -- connect params
      key, -- hash key
      false, -- is write
      redis_av_cb, --callback
      'GET', -- command
      {key} -- arguments)
    ) then
      return true
    end
  end

  return false
end

local function save_av_cache(task, digest, rule, to_save)
  local key = digest

  local function redis_set_cb(err)
    -- Do nothing
    if err then
      rspamd_logger.errx(task, 'failed to save virus cache for %s -> "%s": %s',
        to_save, key, err)
    else
      lua_util.debugm(N, task, 'saved cached result for %s: %s', key, to_save)
    end
  end

  if type(to_save) == 'table' then
    to_save = table.concat(to_save, '\v')
  end

  if redis_params then
    key = rule['prefix'] .. key

    rspamd_redis_make_request(task,
      redis_params, -- connect params
      key, -- hash key
      true, -- is write
      redis_set_cb, --callback
      'SETEX', -- command
      { key, rule['cache_expire'], to_save }
    )
  end

  return false
end

local function fprot_check(task, content, digest, rule)
  local function fprot_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local scan_id = task:get_queue_id()
    if not scan_id then scan_id = task:get_uid() end
    local header = string.format('SCAN STREAM %s SIZE %d\n', scan_id,
        #content)
    local footer = '\n'

    local function fprot_callback(err, data)
      if err then
        -- set current upstream to fail because an error occurred
        upstream:fail()

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          addr = upstream:get_addr()

          lua_util.debugm(N, task, '%s [%s]: retry IP: %s', rule['symbol'], rule['type'], addr)

          tcp.request({
            task = task,
            host = addr:to_string(),
            port = addr:get_port(),
            timeout = rule['timeout'],
            callback = fprot_callback,
            data = { header, content, footer },
            stop_pattern = '\n'
          })
        else
          rspamd_logger.errx(task, '%s [%s]: failed to scan, maximum retransmits exceed', rule['symbol'], rule['type'])
          task:insert_result(rule['symbol_fail'], 0.0, 'failed to scan and retransmits exceed')
        end
      else
        upstream:ok()
        data = tostring(data)
        local cached
        local clean = string.match(data, '^0 <clean>')
        if clean then
          cached = 'OK'
          if rule['log_clean'] then
            rspamd_logger.infox(task, '%s [%s]: message or mime_part is clean', rule['symbol'], rule['type'])
          end
        else
          -- returncodes: 1: infected, 2: suspicious, 3: both, 4-255: some error occured
          -- see http://www.f-prot.com/support/helpfiles/unix/appendix_c.html for more detail
          local vname = string.match(data, '^[1-3] <[%w%s]-: (.-)>')
          if not vname then
            rspamd_logger.errx(task, 'Unhandled response: %s', data)
          else
            yield_result(task, rule, vname)
            cached = vname
          end
        end
        if cached then
          save_av_cache(task, digest, rule, cached)
        end
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule['timeout'],
      callback = fprot_callback,
      data = { header, content, footer },
      stop_pattern = '\n'
    })
  end

  if need_av_check(task, content, rule) then
    if check_av_cache(task, digest, rule, fprot_check_uncached) then
      return
    else
      fprot_check_uncached()
    end
  end
end

local function clamav_check(task, content, digest, rule)
  local function clamav_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local header = rspamd_util.pack("c9 c1 >I4", "zINSTREAM", "\0",
      #content)
    local footer = rspamd_util.pack(">I4", 0)

    local function clamav_callback(err, data)
      if err then

        -- set current upstream to fail because an error occurred
        upstream:fail()

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          addr = upstream:get_addr()

          lua_util.debugm(N, task, '%s [%s]: retry IP: %s', rule['symbol'], rule['type'], addr)

          tcp.request({
            task = task,
            host = addr:to_string(),
            port = addr:get_port(),
            timeout = rule['timeout'],
            callback = clamav_callback,
            data = { header, content, footer },
            stop_pattern = '\0'
          })
        else
          rspamd_logger.errx(task, '%s [%s]: failed to scan, maximum retransmits exceed', rule['symbol'], rule['type'])
          task:insert_result(rule['symbol_fail'], 0.0, 'failed to scan and retransmits exceed')
        end

      else
        upstream:ok()
        data = tostring(data)
        local cached
        lua_util.debugm(N, task, '%s [%s]: got reply: %s', rule['symbol'], rule['type'], data)
        if data == 'stream: OK' then
          cached = 'OK'
          if rule['log_clean'] then
            rspamd_logger.infox(task, '%s [%s]: message or mime_part is clean', rule['symbol'], rule['type'])
          else
            lua_util.debugm(N, task, '%s [%s]: message or mime_part is clean', rule['symbol'], rule['type'])
          end
        else
          local vname = string.match(data, 'stream: (.+) FOUND')
          if vname then
            yield_result(task, rule, vname)
            cached = vname
          else
            rspamd_logger.errx(task, 'unhandled response: %s', data)
            task:insert_result(rule['symbol_fail'], 0.0, 'unhandled response')
          end
        end
        if cached then
          save_av_cache(task, digest, rule, cached)
        end
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule['timeout'],
      callback = clamav_callback,
      data = { header, content, footer },
      stop_pattern = '\0'
    })
  end

  if need_av_check(task, content, rule) then
    if check_av_cache(task, digest, rule, clamav_check_uncached) then
      return
    else
      clamav_check_uncached()
    end
  end
end

local function sophos_check(task, content, digest, rule)
  local function sophos_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local protocol = 'SSSP/1.0\n'
    local streamsize = string.format('SCANDATA %d\n', #content)
    local bye = 'BYE\n'

    local function sophos_callback(err, data, conn)

      if err then
          -- set current upstream to fail because an error occurred
          upstream:fail()

          -- retry with another upstream until retransmits exceeds
          if retransmits > 0 then

            retransmits = retransmits - 1

            -- Select a different upstream!
            upstream = rule.upstreams:get_upstream_round_robin()
            addr = upstream:get_addr()

            lua_util.debugm(N, task, '%s [%s]: retry IP: %s', rule['symbol'], rule['type'], addr)

            tcp.request({
              task = task,
              host = addr:to_string(),
              port = addr:get_port(),
              timeout = rule['timeout'],
              callback = sophos_callback,
              data = { protocol, streamsize, content, bye }
            })
          else
            rspamd_logger.errx(task, '%s [%s]: failed to scan, maximum retransmits exceed', rule['symbol'], rule['type'])
            task:insert_result(rule['symbol_fail'], 0.0, 'failed to scan and retransmits exceed')
          end
      else
        upstream:ok()
        data = tostring(data)
        lua_util.debugm(N, task, '%s [%s]: got reply: %s', rule['symbol'], rule['type'], data)
        local vname = string.match(data, 'VIRUS (%S+) ')
        if vname then
          yield_result(task, rule, vname)
          save_av_cache(task, digest, rule, vname)
        else
          if string.find(data, 'DONE OK') then
            if rule['log_clean'] then
              rspamd_logger.infox(task, '%s [%s]: message or mime_part is clean', rule['symbol'], rule['type'])
            else
              lua_util.debugm(N, task, '%s [%s]: message or mime_part is clean', rule['symbol'], rule['type'])
            end
            save_av_cache(task, digest, rule, 'OK')
            -- not finished - continue
          elseif string.find(data, 'ACC') or string.find(data, 'OK SSSP') then
            conn:add_read(sophos_callback)
            -- set pseudo virus if configured, else do nothing since it's no fatal
          elseif string.find(data, 'FAIL 0212') then
            rspamd_logger.infox(task, 'Message is ENCRYPTED (0212 SOPHOS_SAVI_ERROR_FILE_ENCRYPTED): %s', data)
            if rule['savdi_report_encrypted'] then
              yield_result(task, rule, "SAVDI_FILE_ENCRYPTED")
              save_av_cache(task, digest, rule, "SAVDI_FILE_ENCRYPTED")
            end
            -- set pseudo virus if configured, else set fail since part was not scanned
          elseif string.find(data, 'REJ 4') then
            if rule['savdi_report_oversize'] then
              rspamd_logger.infox(task, 'SAVDI: Message is OVERSIZED (SSSP reject code 4): %s', data)
              yield_result(task, rule, "SAVDI_FILE_OVERSIZED")
              save_av_cache(task, digest, rule, "SAVDI_FILE_OVERSIZED")
            else
              rspamd_logger.errx(task, 'SAVDI: Message is OVERSIZED (SSSP reject code 4): %s', data)
              task:insert_result(rule['symbol_fail'], 0.0, 'Message is OVERSIZED (SSSP reject code 4):' .. data)
            end
            -- excplicitly set REJ1 message when SAVDIreports a protocol error
          elseif string.find(data, 'REJ 1') then
            rspamd_logger.errx(task, 'SAVDI (Protocol error (REJ 1)): %s', data)
            task:insert_result(rule['symbol_fail'], 0.0, 'SAVDI (Protocol error (REJ 1)):' .. data)
          else
            rspamd_logger.errx(task, 'unhandled response: %s', data)
            task:insert_result(rule['symbol_fail'], 0.0, 'unhandled response')
          end

        end
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule['timeout'],
      callback = sophos_callback,
      data = { protocol, streamsize, content, bye }
    })
  end

  if need_av_check(task, content, rule) then
    if check_av_cache(task, digest, rule, sophos_check_uncached) then
      return
    else
      sophos_check_uncached()
    end
  end
end

local function savapi_check(task, content, digest, rule)
  local function savapi_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local fname = string.format('%s/%s.tmp',
        rule.tmpdir, rspamd_util.random_hex(32))
    local message_fd = rspamd_util.create_file(fname)

    if not message_fd then
      rspamd_logger.errx('cannot store file for savapi scan: %s', fname)
      return
    end

    if type(content) == 'string' then
      -- Create rspamd_text
      local rspamd_text = require "rspamd_text"
      content = rspamd_text.fromstring(content)
    end
    content:save_in_file(message_fd)

    -- Ensure cleanup
    task:get_mempool():add_destructor(function()
      os.remove(fname)
      rspamd_util.close_file(message_fd)
    end)

    local vnames = {}

    -- Forward declaration for recursive calls
    local savapi_scan1_cb

    local function savapi_fin_cb(err, conn)
      local vnames_reordered = {}
      -- Swap table
      for virus,_ in pairs(vnames) do
        table.insert(vnames_reordered, virus)
      end
      lua_util.debugm(N, task, "%s: number of virus names found %s", rule['type'], #vnames_reordered)
      if #vnames_reordered > 0 then
        local vname = {}
        for _,virus in ipairs(vnames_reordered) do
          table.insert(vname, virus)
        end

        yield_result(task, rule, vname)
        save_av_cache(task, digest, rule, vname)
      end
      if conn then
        conn:close()
      end
    end

    local function savapi_scan2_cb(err, data, conn)
      local result = tostring(data)
      lua_util.debugm(N, task, "%s: got reply: %s",
          rule['type'], result)

      -- Terminal response - clean
      if string.find(result, '200') or string.find(result, '210') then
        if rule['log_clean'] then
          rspamd_logger.infox(task, '%s: message or mime_part is clean', rule['type'])
        end
        save_av_cache(task, digest, rule, 'OK')
        conn:add_write(savapi_fin_cb, 'QUIT\n')

      -- Terminal response - infected
      elseif string.find(result, '319') then
        conn:add_write(savapi_fin_cb, 'QUIT\n')

      -- Non-terminal response
      elseif string.find(result, '310') then
        local virus
        virus = result:match "310.*<<<%s(.*)%s+;.*;.*"
        if not virus then
          virus = result:match "310%s(.*)%s+;.*;.*"
          if not virus then
            rspamd_logger.errx(task, "%s: virus result unparseable: %s",
                rule['type'], result)
            return
          end
        end
        -- Store unique virus names
        vnames[virus] = 1
        -- More content is expected
        conn:add_write(savapi_scan1_cb, '\n')
      end
    end

    savapi_scan1_cb = function(err, conn)
      conn:add_read(savapi_scan2_cb, '\n')
    end

    -- 100 PRODUCT:xyz
    local function savapi_greet2_cb(err, data, conn)
      local result = tostring(data)
      if string.find(result, '100 PRODUCT') then
        lua_util.debugm(N, task, "%s: scanning file: %s",
            rule['type'], fname)
        conn:add_write(savapi_scan1_cb, {string.format('SCAN %s\n',
            fname)})
      else
        rspamd_logger.errx(task, '%s: invalid product id %s', rule['type'],
            rule['product_id'])
        conn:add_write(savapi_fin_cb, 'QUIT\n')
      end
    end

    local function savapi_greet1_cb(err, conn)
      conn:add_read(savapi_greet2_cb, '\n')
    end

    local function savapi_callback_init(err, data, conn)
      if err then

        -- set current upstream to fail because an error occurred
        upstream:fail()

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          addr = upstream:get_addr()

          lua_util.debugm(N, task, '%s [%s]: retry IP: %s', rule['symbol'], rule['type'], addr)

          tcp.request({
            task = task,
            host = addr:to_string(),
            port = addr:get_port(),
            timeout = rule['timeout'],
            callback = savapi_callback_init,
            stop_pattern = {'\n'},
          })
        else
          rspamd_logger.errx(task, '%s [%s]: failed to scan, maximum retransmits exceed', rule['symbol'], rule['type'])
          task:insert_result(rule['symbol_fail'], 0.0, 'failed to scan and retransmits exceed')
        end
      else
        upstream:ok()
        local result = tostring(data)

        -- 100 SAVAPI:4.0 greeting
        if string.find(result, '100') then
          conn:add_write(savapi_greet1_cb, {string.format('SET PRODUCT %s\n', rule['product_id'])})
        end
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule['timeout'],
      callback = savapi_callback_init,
      stop_pattern = {'\n'},
    })
  end

  if need_av_check(task, content, rule) then
    if check_av_cache(task, digest, rule, savapi_check_uncached) then
      return
    else
      savapi_check_uncached()
    end
  end
end

local function kaspersky_check(task, content, digest, rule)
  local function kaspersky_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local fname = string.format('%s/%s.tmp',
        rule.tmpdir, rspamd_util.random_hex(32))
    local message_fd = rspamd_util.create_file(fname)
    local clamav_compat_cmd = string.format("nSCAN %s\n", fname)

    if not message_fd then
      rspamd_logger.errx('cannot store file for kaspersky scan: %s', fname)
      return
    end

    if type(content) == 'string' then
      -- Create rspamd_text
      local rspamd_text = require "rspamd_text"
      content = rspamd_text.fromstring(content)
    end
    content:save_in_file(message_fd)

    -- Ensure file cleanup
    task:get_mempool():add_destructor(function()
      os.remove(fname)
      rspamd_util.close_file(message_fd)
    end)


    local function kaspersky_callback(err, data)
      if err then
        -- set current upstream to fail because an error occurred
        upstream:fail()

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          addr = upstream:get_addr()

          lua_util.debugm(N, task,
              '%s [%s]: retry IP: %s', rule['symbol'], rule['type'], addr)

          tcp.request({
            task = task,
            host = addr:to_string(),
            port = addr:get_port(),
            timeout = rule['timeout'],
            callback = kaspersky_callback,
            data = { clamav_compat_cmd },
            stop_pattern = '\n'
          })
        else
          rspamd_logger.errx(task,
              '%s [%s]: failed to scan, maximum retransmits exceed',
              rule['symbol'], rule['type'])
          task:insert_result(rule['symbol_fail'], 0.0,
              'failed to scan and retransmits exceed')
        end

      else
        upstream:ok()
        data = tostring(data)
        local cached
        lua_util.debugm(N, task, '%s [%s]: got reply: %s',
            rule['symbol'], rule['type'], data)
        if data == 'stream: OK' then
          cached = 'OK'
          if rule['log_clean'] then
            rspamd_logger.infox(task, '%s [%s]: message or mime_part is clean',
                rule['symbol'], rule['type'])
          else
            lua_util.debugm(N, task, '%s [%s]: message or mime_part is clean',
                rule['symbol'], rule['type'])
          end
        else
          local vname = string.match(data, ': (.+) FOUND')
          if vname then
            yield_result(task, rule, vname)
            cached = vname
          else
            rspamd_logger.errx(task, 'unhandled response: %s', data)
            task:insert_result(rule['symbol_fail'], 0.0, 'unhandled response')
          end
        end
        if cached then
          save_av_cache(task, digest, rule, cached)
        end
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule['timeout'],
      callback = kaspersky_callback,
      data = { clamav_compat_cmd },
      stop_pattern = '\n'
    })
  end

  if need_av_check(task, content, rule) then
    if check_av_cache(task, digest, rule, kaspersky_check_uncached) then
      return
    else
      kaspersky_check_uncached()
    end
  end
end

local av_types = {
  clamav = {
    configure = clamav_config,
    check = clamav_check
  },
  fprot = {
    configure = fprot_config,
    check = fprot_check
  },
  sophos = {
    configure = sophos_config,
    check = sophos_check
  },
  savapi = {
    configure = savapi_config,
    check = savapi_check
  },
  kaspersky = {
    configure = kaspersky_config,
    check = kaspersky_check
  }
}

local function add_antivirus_rule(sym, opts)
  if not opts['type'] then
    rspamd_logger.errx(rspamd_config, 'unknown type for AV rule %s', sym)
    return nil
  end

  if not opts['symbol'] then opts['symbol'] = sym:upper() end
  local cfg = av_types[opts['type']]

  if not opts['symbol_fail'] then
    opts['symbol_fail'] = string.upper(opts['type']) .. '_FAIL'
  end

  -- WORKAROUND for deprecated attachments_only
  if opts['attachments_only'] ~= nil then
    opts['scan_mime_parts'] = opts['attachments_only']
    rspamd_logger.warnx(rspamd_config, '%s [%s]: Using attachments_only is deprecated. '..
     'Please use scan_mime_parts = %s instead', opts['symbol'], opts['type'], opts['attachments_only'])
  end
  -- WORKAROUND for deprecated attachments_only

  if not cfg then
    rspamd_logger.errx(rspamd_config, 'unknown antivirus type: %s',
      opts['type'])
  end

  local rule = cfg.configure(opts)
  rule.type = opts.type
  rule.symbol_fail = opts.symbol_fail


  if not rule then
    rspamd_logger.errx(rspamd_config, 'cannot configure %s for %s',
      opts['type'], opts['symbol'])
    return nil
  end

  if type(opts['patterns']) == 'table' then
    rule['patterns'] = {}
    if opts['patterns'][1] then
      for i, p in ipairs(opts['patterns']) do
        if type(p) == 'table' then
          local new_set = {}
          for k, v in pairs(p) do
            new_set[k] = rspamd_regexp.create_cached(v)
          end
          rule['patterns'][i] = new_set
        else
          rule['patterns'][i] = {}
        end
      end
    else
      for k, v in pairs(opts['patterns']) do
        rule['patterns'][k] = rspamd_regexp.create_cached(v)
      end
    end
  end

  if opts['whitelist'] then
    rule['whitelist'] = rspamd_config:add_hash_map(opts['whitelist'])
  end

  return function(task)
    if rule.scan_mime_parts then
      local parts = task:get_parts() or {}

      local filter_func = function(p)
        return (rule.scan_image_mime and p:is_image())
            or (rule.scan_text_mime and p:is_text())
            or (p:is_attachment())
      end

      fun.each(function(p)
        local content = p:get_content()

        if content and #content > 0 then
          cfg.check(task, content, p:get_digest(), rule)
        end
      end, fun.filter(filter_func, parts))

    else
      cfg.check(task, task:get_content(), task:get_digest(), rule)
    end
  end
end

-- Registration
local opts = rspamd_config:get_all_opt('antivirus')
if opts and type(opts) == 'table' then
  redis_params = rspamd_parse_redis_server('antivirus')
  local has_valid = false
  for k, m in pairs(opts) do
    if type(m) == 'table' and m.servers then
      if not m.type then m.type = k end
      local cb = add_antivirus_rule(k, m)

      if not cb then
        rspamd_logger.errx(rspamd_config, 'cannot add rule: "' .. k .. '"')
      else
        local id = rspamd_config:register_symbol({
          type = 'normal',
          name = m['symbol'],
          callback = cb,
          score = 0.0,
          group = 'antivirus'
        })
        rspamd_config:register_symbol({
          type = 'virtual',
          name = m['symbol_fail'],
          parent = id,
          score = 0.0,
          group = 'antivirus'
        })
        has_valid = true
        if type(m['patterns']) == 'table' then
          if m['patterns'][1] then
            for _, p in ipairs(m['patterns']) do
              if type(p) == 'table' then
                for sym in pairs(p) do
                  rspamd_logger.debugm(N, rspamd_config, 'registering: %1', {
                    type = 'virtual',
                    name = sym,
                    parent = m['symbol'],
                    parent_id = id,
                  })
                  rspamd_config:register_symbol({
                    type = 'virtual',
                    name = sym,
                    parent = id
                  })
                end
              end
            end
          else
            for sym in pairs(m['patterns']) do
              rspamd_config:register_symbol({
                type = 'virtual',
                name = sym,
                parent = id
              })
            end
          end
        end
        if m['score'] then
          -- Register metric symbol
          local description = 'antivirus symbol'
          local group = 'antivirus'
          if m['description'] then
            description = m['description']
          end
          if m['group'] then
            group = m['group']
          end
          rspamd_config:set_metric_symbol({
            name = m['symbol'],
            score = m['score'],
            description = description,
            group = group or 'antivirus'
          })
        end
      end
    end
  end

  if not has_valid then
    lua_util.disable_module(N, 'config')
  end
end
