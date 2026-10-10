--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

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
local lua_util = require "lua_util"
local lua_redis = require "lua_redis"
local lua_antivirus = require("lua_scanners").filter('antivirus')
local common = require "lua_scanners/common"
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
      # Scan mime_parts separately - otherwise the complete mail will be transferred to AV Scanner
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
        JUST_EICAR = "^Eicar-Test-Signature$";
      }
      # `whitelist` points to a map of threat names/signatures to ignore. When a
      # detected threat name is in this map, the `_IGNORE` symbol is set instead.
      whitelist = "/etc/rspamd/antivirus.wl";
      # Replace content that exactly matches the following string to the EICAR pattern
      # Useful for E2E testing when another party removes/blocks EICAR attachments
      #eicar_fake_pattern = 'testpatterneicar';
    }
  }
  ]])
  return
end

local function add_antivirus_rule(sym, opts)
  if not opts.type then
    rspamd_logger.errx(rspamd_config, 'unknown type for AV rule %s', sym)
    return nil
  end

  opts.symbol, opts.symbol_fail, opts.symbol_encrypted, opts.symbol_macro, opts.symbol_ignore =
    common.derive_symbols(sym, opts)

  local cfg = lua_antivirus[opts.type]

  if not cfg then
    rspamd_logger.errx(rspamd_config, 'unknown antivirus type: %s',
      opts.type)
    return nil
  end

  -- WORKAROUND for deprecated attachments_only
  if opts.attachments_only ~= nil then
    opts.scan_mime_parts = opts.attachments_only
    rspamd_logger.warnx(rspamd_config, '%s [%s]: Using attachments_only is deprecated. ' ..
      'Please use scan_mime_parts = %s instead', opts.symbol, opts.type, opts.attachments_only)
  end
  -- WORKAROUND for deprecated attachments_only

  local rule = cfg.configure(opts)
  if not rule then
    return common.configure_failed_stub(opts.type, sym, opts,
      opts.symbol, opts.symbol_fail, opts.symbol_encrypted, opts.symbol_macro, opts.symbol_ignore)
  end

  rule.type = opts.type
  rule.symbol_fail = opts.symbol_fail
  rule.symbol_encrypted = opts.symbol_encrypted
  rule.symbol_macro = opts.symbol_macro
  rule.symbol_ignore = opts.symbol_ignore
  rule.redis_params = redis_params
  rule.eicar_fake_pattern = opts.eicar_fake_pattern

  rule.patterns = common.create_regex_table(opts.patterns or {})
  rule.patterns_fail = common.create_regex_table(opts.patterns_fail or {})

  lua_redis.register_prefix(rule.prefix .. '_*', N,
    string.format('Antivirus cache for rule "%s"',
      rule.type), {
      type = 'string',
    })

  rule.mime_parts_filter_regex = common.create_regex_table(opts.mime_parts_filter_regex or {})
  rule.mime_parts_filter_regex_exclude = common.create_regex_table(opts.mime_parts_filter_regex_exclude or {})

  rule.mime_parts_filter_ext = common.create_regex_table(opts.mime_parts_filter_ext or {})
  rule.mime_parts_filter_ext_exclude = common.create_regex_table(opts.mime_parts_filter_ext_exclude or {})

  -- if any mime_part filter defined, do not scan all attachments
  if next(rule.mime_parts_filter_regex) ~= nil
      or next(rule.mime_parts_filter_regex_exclude) ~= nil
      or next(rule.mime_parts_filter_ext) ~= nil
      or next(rule.mime_parts_filter_ext_exclude) ~= nil then
    rule.scan_all_mime_parts = false
  else
    rule.scan_all_mime_parts = true
  end

  common.configure_whitelist(rule, opts, 'antivirus whitelist for ' .. rule.log_prefix)

  return common.make_scan_callback(cfg, rule), common.make_report_callback(cfg, rule), rule
end

-- Registration
local opts = rspamd_config:get_all_opt(N)
if opts and type(opts) == 'table' then
  redis_params = lua_redis.parse_redis_server(N)
  local has_valid = false
  for k, m in pairs(opts) do
    if type(m) == 'table' and (m.servers or m.socket) then
      if not m.type then
        m.type = k
      end
      if not m.name then
        m.name = k
      end
      local cb, report_cb, rule = add_antivirus_rule(k, m)

      if not cb then
        rspamd_logger.errx(rspamd_config, 'cannot add rule: "' .. k .. '"')
        lua_util.config_utils.push_config_error(N, 'cannot add AV rule: "' .. k .. '"')
      else
        m = rule
        rspamd_logger.infox(rspamd_config, 'added antivirus engine %s -> %s', k, m.symbol)

        local t = common.scanner_symbol_registration(m.symbol, cb, m, N)
        local id = rspamd_config:register_symbol(t)

        if report_cb and m.symbol_report then
          rspamd_logger.infox(rspamd_config, 'added antivirus report symbol %s -> %s', k, m.symbol_report)
          rspamd_config:register_symbol(common.report_symbol_registration(m.symbol_report, report_cb, m, N))
        end

        common.register_scanner_symbols(id, m.symbol, m, N)

        has_valid = true
      end
    end
  end

  if not has_valid then
    lua_util.disable_module(N, 'config')
  end
end
