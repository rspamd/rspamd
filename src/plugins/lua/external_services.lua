--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>
Copyright (c) 2019, Carsten Rosenberg <c.rosenberg@heinlein-support.de>

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
local lua_scanners = require("lua_scanners").filter('scanner')
local common = require "lua_scanners/common"
local redis_params

local N = "external_services"

if confighelp then
  rspamd_config:add_example(nil, 'external_services',
      "Check messages using external services (e.g. OEM AS engines, Pyzor etc)",
      [[
  external_services {
    # multiple scanners could be checked, for each we create a configuration block with an arbitrary name

    oletools {
      # If set force this action if any virus is found (default unset: no action is forced)
      # action = "reject";
      # If set, then rejection message is set to this value (mention single quotes)
      # If `max_size` is set, messages > n bytes in size are not scanned
      # max_size = 20000000;
      # log_clean = true;
      # servers = "127.0.0.1:10050";
      # cache_expire = 86400;
      # scan_mime_parts = true;
      # extended = false;
      # if `patterns` is specified virus name will be matched against provided regexes and the related
      # symbol will be yielded if a match is found. If no match is found, default symbol is yielded.
      patterns {
        JUST_EICAR = "^Eicar-Test-Signature$";
      }
      # mime-part regex matching in content-type or filename
      mime_parts_filter_regex {
        GEN1 = "application\/octet-stream";
        DOC2 = "application\/msword";
        DOC3 = "application\/vnd\.ms-word.*";
        XLS = "application\/vnd\.ms-excel.*";
        PPT = "application\/vnd\.ms-powerpoint.*";
        GEN2 = "application\/vnd\.openxmlformats-officedocument.*";
      }
      # Mime-Part filename extension matching (no regex)
      mime_parts_filter_ext {
        doc = "doc";
        dot = "dot";
        docx = "docx";
        dotx = "dotx";
        docm = "docm";
        dotm = "dotm";
        xls = "xls";
        xlt = "xlt";
        xla = "xla";
        xlsx = "xlsx";
        xltx = "xltx";
        xlsm = "xlsm";
        xltm = "xltm";
        xlam = "xlam";
        xlsb = "xlsb";
        ppt = "ppt";
        pot = "pot";
        pps = "pps";
        ppa = "ppa";
        pptx = "pptx";
        potx = "potx";
        ppsx = "ppsx";
        ppam = "ppam";
        pptm = "pptm";
        potm = "potm";
        ppsm = "ppsm";
      }
      # `whitelist` points to a map of IP addresses. Mail from these addresses is not scanned.
      whitelist = "/etc/rspamd/antivirus.wl";
    }
  }
  ]])
  return
end

local function add_scanner_rule(sym, opts)
  if not opts.type then
    rspamd_logger.errx(rspamd_config, 'unknown type for external scanner rule %s', sym)
    return nil
  end

  local cfg = lua_scanners[opts.type]

  if not cfg then
    rspamd_logger.errx(rspamd_config, 'unknown external scanner type: %s',
        opts.type)
    return nil
  end

  -- Resolve symbol names up-front so a failed configure() can still register
  -- the fail symbol and surface the misconfiguration on every scan.
  local symbol, symbol_fail, symbol_encrypted, symbol_macro, symbol_ignore = common.derive_symbols(sym, opts)

  local rule = cfg.configure(opts)

  if not rule then
    return common.configure_failed_stub(opts.type, sym, opts,
      symbol, symbol_fail, symbol_encrypted, symbol_macro, symbol_ignore)
  end

  rule.type = opts.type
  -- Prefer the symbols the scanner resolved in configure() -- its own documented
  -- defaults (e.g. VADE_CHECK / VADE_FAIL) or the user's `symbol =` applied via
  -- override_defaults. Fall back to the key-derived names (also used for the
  -- configure()-failed stub above) only when the scanner left them unset, so a
  -- scanner's default symbol is honoured and stays a stable dependency target.
  rule.symbol = rule.symbol or symbol
  rule.symbol_fail = rule.symbol_fail or (rule.symbol .. '_FAIL')
  rule.symbol_encrypted = rule.symbol_encrypted or (rule.symbol .. '_ENCRYPTED')
  rule.symbol_macro = rule.symbol_macro or (rule.symbol .. '_MACRO')
  rule.symbol_ignore = rule.symbol_ignore or (rule.symbol .. '_IGNORE')

  rule.redis_params = redis_params
  rule.eicar_fake_pattern = opts.eicar_fake_pattern

  lua_redis.register_prefix(rule.prefix .. '_*', N,
      string.format('External services cache for rule "%s"',
          rule.type), {
        type = 'string',
      })

  -- if any mime_part filter defined, do not scan all attachments
  if opts.mime_parts_filter_regex ~= nil
      or opts.mime_parts_filter_ext ~= nil then
    rule.scan_all_mime_parts = false
  else
    rule.scan_all_mime_parts = true
  end

  rule.patterns = common.create_regex_table(opts.patterns or {})
  rule.patterns_fail = common.create_regex_table(opts.patterns_fail or {})

  rule.mime_parts_filter_regex = common.create_regex_table(opts.mime_parts_filter_regex or {})

  rule.mime_parts_filter_ext = common.create_regex_table(opts.mime_parts_filter_ext or {})

  common.configure_whitelist(rule, opts, 'external services whitelist for ' .. rule.log_prefix)

  rspamd_logger.infox(rspamd_config, 'registered external services rule: symbol %s; type %s',
      rule.symbol, rule.type)

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
      local cb, report_cb, nrule = add_scanner_rule(k, m)

      if not cb then
        rspamd_logger.errx(rspamd_config, 'cannot add rule: "' .. k .. '"')
        lua_util.config_utils.push_config_error(N, 'cannot add external services rule: "' .. k .. '"')
      else
        m = nrule

        -- Every external service is scheduled under a stable <RULE>_CHECK
        -- callback symbol, so it is a predictable dependency target regardless
        -- of how the scan result symbols are named. Scanners whose main symbol
        -- is already a *_CHECK (e.g. VADE_CHECK, CLOUDMARK_CHECK) use it as is;
        -- otherwise the anchor is derived from the rule key (unique per rule, so
        -- no collisions between instances) and the result symbol (e.g.
        -- DCC_REJECT) becomes a virtual child, so its score and results stay
        -- unchanged.
        local check_symbol = m.symbol
        if not check_symbol:match('_CHECK$') then
          check_symbol = k:upper() .. '_CHECK'
        end

        local t = common.scanner_symbol_registration(check_symbol, cb, m, N)
        local id = rspamd_config:register_symbol(t)

        if report_cb and m.symbol_report then
          rspamd_logger.infox(rspamd_config, 'added external services report symbol %s -> %s', k, m.symbol_report)
          rspamd_config:register_symbol(common.report_symbol_registration(m.symbol_report, report_cb, m, N))
        end

        common.register_scanner_symbols(id, check_symbol, m, N)

        has_valid = true

        -- Add preloads if a module requires that
        if type(m.preloads) == 'table' then
          for _, preload in ipairs(m.preloads) do
            rspamd_config:add_on_load(function(cfg, ev_base, worker)
              preload(m, cfg, ev_base, worker)
            end)
          end
        end
      end
    end
  end

  if not has_valid then
    lua_util.disable_module(N, 'config')
  end
end
