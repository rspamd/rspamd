--[[
Copyright (c) 2019, Vsevolod Stakhov <vsevolod@highsecure.ru>
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
local fun = require "fun"
local lua_scanners = require("lua_scanners").filter('scanner')
local common = require "lua_scanners/common"
local redis_params

local N = "external_services"

if confighelp then
  rspamd_config:add_example(nil, 'external_services',
    "Check messages using external services (e.g. OEM AS engines, DCC, Pyzor etc)",
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
      # symbol_name = "pattern";
      JUST_EICAR = "^Eicar-Test-Signature$";
    }
    # mime-part regex matching in content-type or filename
    mime_parts_filter_regex {
      #GEN1 = "application\/octet-stream";
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
  dcc {
    # If set force this action if any virus is found (default unset: no action is forced)
    # action = "reject";
    # If set, then rejection message is set to this value (mention single quotes)
    # If `max_size` is set, messages > n bytes in size are not scanned
    max_size = 20000000;
    #servers = "127.0.0.1:10045;
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

  local rule = cfg.configure(opts)

  if not rule then
    rspamd_logger.errx(rspamd_config, 'cannot configure %s for %s',
      opts.type, rule.symbol or sym:upper())
    return nil
  end

  rule.type = opts.type
  -- Fill missing symbols
  if not rule.symbol then
    rule.symbol = sym:upper()
  end
  if not rule.symbol_fail then
    rule.symbol_fail = rule.symbol .. '_FAIL'
  end
  if not rule.symbol_encrypted then
    rule.symbol_encrypted = rule.symbol .. '_ENCRYPTED'
  end
  if not rule.symbol_macro then
    rule.symbol_macro = rule.symbol .. '_MACRO'
  end

  rule.redis_params = redis_params

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

  if opts.whitelist then
    rule.whitelist = rspamd_config:add_hash_map(opts.whitelist)
  end

  local function scan_cb(task)
    if rule.scan_mime_parts then

      fun.each(function(p)
        local content = p:get_content()
        if content and #content > 0 then
          cfg.check(task, content, p:get_digest(), rule)
        end
      end, common.check_parts_match(task, rule))

    else
      cfg.check(task, task:get_content(), task:get_digest(), rule)
    end
  end

  rspamd_logger.infox(rspamd_config, 'registered external services rule: symbol %s; type %s',
      rule.symbol, rule.type)

  return scan_cb, rule
end

-- Registration
local opts = rspamd_config:get_all_opt(N)
if opts and type(opts) == 'table' then
  redis_params = lua_redis.parse_redis_server(N)
  local has_valid = false
  for k, m in pairs(opts) do
    if type(m) == 'table' and m.servers then
      if not m.type then m.type = k end
      if not m.name then m.name = k end
      local cb, nrule = add_scanner_rule(k, m)

      if not cb then
        rspamd_logger.errx(rspamd_config, 'cannot add rule: "' .. k .. '"')
      else
        m = nrule

        local t = {
          name = m.symbol,
          callback = cb,
          score = 0.0,
          group = N
        }

        if m.symbol_type == 'postfilter' then
          t.type = 'postfilter'
          t.priority = 3
        else
          t.type = 'normal'
        end

        local id = rspamd_config:register_symbol(t)

        if m.symbol_fail then
          rspamd_config:register_symbol({
            type = 'virtual',
            name = m['symbol_fail'],
            parent = id,
            score = 0.0,
            group = N
          })
        end

        if m.symbol_encrypted then
          rspamd_config:register_symbol({
            type = 'virtual',
            name = m['symbol_encrypted'],
            parent = id,
            score = 0.0,
            group = N
          })
        end
        if m.symbol_macro then
          rspamd_config:register_symbol({
            type = 'virtual',
            name = m['symbol_macro'],
            parent = id,
            score = 0.0,
            group = N
          })
        end
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
                    parent = id,
                    score = 0.0,
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
                score = 0.0,
                group = N
              })
            end
          end
        end
        if type(m['patterns_fail']) == 'table' then
          if m['patterns_fail'][1] then
            for _, p in ipairs(m['patterns_fail']) do
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
                    parent = id,
                    score = 0.0,
                    group = N
                  })
                end
              end
            end
          else
            for sym in pairs(m['patterns_fail']) do
              rspamd_config:register_symbol({
                type = 'virtual',
                name = sym,
                parent = id,
                score = 0.0,
                group = N
              })
            end
          end
        end
        if m.symbols then
          local function reg_symbols(tbl)
            for _,sym in pairs(tbl) do
              if type(sym) == 'string' then
                rspamd_config:register_symbol({
                  type = 'virtual',
                  name = sym,
                  parent = id,
                  group = N
                })
              elseif type(sym) == 'table' then
                if sym.symbol then
                  rspamd_config:register_symbol({
                    type = 'virtual',
                    name = sym.symbol,
                    parent = id,
                    group = N
                  })

                  if sym.score then
                    rspamd_config:set_metric_symbol({
                      name = sym.symbol,
                      score = sym.score,
                      description = sym.description,
                      group = sym.group or N,
                    })
                  end
                else
                  reg_symbols(sym)
                end
              end
            end
          end

          reg_symbols(m.symbols)
        end

        if m['score'] then
          -- Register metric symbol
          local description = 'external services symbol'
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
            group = group
          })
        end

        -- Add preloads if a module requires that
        if type(m.preloads) == 'table' then
          for _,preload in ipairs(m.preloads) do
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
