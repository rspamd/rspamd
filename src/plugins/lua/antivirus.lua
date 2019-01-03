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
local rspamd_regexp = require "rspamd_regexp"
local lua_util = require "lua_util"
local fun = require "fun"
local lua_antivirus = require("lua_scanners").filter('antivirus')
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


local function add_antivirus_rule(sym, opts)
  if not opts['type'] then
    rspamd_logger.errx(rspamd_config, 'unknown type for AV rule %s', sym)
    return nil
  end

  if not opts['symbol'] then opts['symbol'] = sym:upper() end
  local cfg = lua_antivirus[opts['type']]

  if not cfg then
    rspamd_logger.errx(rspamd_config, 'unknown antivirus type: %s',
        opts['type'])
    return nil
  end

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

  local rule = cfg.configure(opts)
  rule.type = opts.type
  rule.symbol_fail = opts.symbol_fail
  rule.redis_params = redis_params

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
local opts = rspamd_config:get_all_opt(N)
if opts and type(opts) == 'table' then
  redis_params = rspamd_parse_redis_server(N)
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
          group = N
        })
        rspamd_config:register_symbol({
          type = 'virtual',
          name = m['symbol_fail'],
          parent = id,
          score = 0.0,
          group = N
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
                    group = N
                  })
                  rspamd_config:register_symbol({
                    type = 'virtual',
                    name = sym,
                    parent = id,
                    group = N
                  })
                end
              end
            end
          else
            for sym in pairs(m['patterns']) do
              rspamd_config:register_symbol({
                type = 'virtual',
                name = sym,
                parent = id,
                group = N
              })
            end
          end
        end
        if m['score'] then
          -- Register metric symbol
          local description = 'antivirus symbol'
          local group = N
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
