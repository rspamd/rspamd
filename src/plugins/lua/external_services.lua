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
local rspamd_regexp = require "rspamd_regexp"
local lua_util = require "lua_util"
local fun = require "fun"
local lua_scanners = require("lua_scanners").filter('scanner')
local redis_params

local N = "external_services"

if confighelp then
  rspamd_config:add_example(nil, 'external_services',
    "Check messages using external services (e.g. OEM AS engines, DCC, Pyzor etc)",
    [[
external_services {
  # multiple scanners could be checked, for each we create a configuration block with an arbitrary name
  dcc {
    # If set force this action if any virus is found (default unset: no action is forced)
    # action = "reject";
    # If set, then rejection message is set to this value (mention single quotes)
    # If `max_size` is set, messages > n bytes in size are not scanned
    max_size = 20000000;
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


local function add_scanner_rule(sym, opts)
  if not opts['type'] then
    rspamd_logger.errx(rspamd_config, 'unknown type for external scanner rule %s', sym)
    return nil
  end

  if not opts['symbol'] then opts['symbol'] = sym:upper() end
  local cfg = lua_scanners[opts['type']]

  if not cfg then
    rspamd_logger.errx(rspamd_config, 'unknown antivirus type: %s',
        opts['type'])
    return nil
  end

  if not opts['symbol_fail'] then
    opts['symbol_fail'] = string.upper(opts['type']) .. '_FAIL'
  end

  local rule = cfg.configure(opts)
  rule.type = opts.type
  rule.symbol_fail = opts.symbol_fail
  rule.redis_params = redis_params

  if not rule then
    rspamd_logger.errx(rspamd_config, 'cannot configure %s for %s',
      opts['type'], opts['symbol'])
    return nil
  end

  local function create_regex_table(task, patterns)
    local regex_table = {}
    if patterns[1] then
      for i, p in ipairs(patterns) do
        if type(p) == 'table' then
          local new_set = {}
          for k, v in pairs(p) do
            new_set[k] = rspamd_regexp.create_cached(v)
          end
          regex_table[i] = new_set
        else
          regex_table[i] = {}
        end
      end
    else
      for k, v in pairs(patterns) do
        regex_table[k] = rspamd_regexp.create_cached(v)
      end
    end
    return regex_table
  end

  if opts['mime_parts_filter_regex'] ~= nil
    or opts['mime_parts_filter_ext'] ~= nil then
      rule.scan_all_mime_parts = false
  end

  rule['patterns'] = create_regex_table(task, opts['patterns'] or {})

  rule['mime_parts_filter_regex'] = create_regex_table(task, opts['mime_parts_filter_regex'] or {})

  rule['mime_parts_filter_ext'] = create_regex_table(task, opts['mime_parts_filter_ext'] or {})

  if opts['whitelist'] then
    rule['whitelist'] = rspamd_config:add_hash_map(opts['whitelist'])
  end

  local function match_filter(task, found, patterns)
    if type(patterns) ~= 'table' then
      lua_util.debugm(N, task, '%s: pattern not table %s', rule.log_prefix, type(patterns))
      return false
    end
    if not patterns[1] then
      --lua_util.debugm(N, task, '%s: in not pattern[1]', rule['symbol'], rule['type'])
      for _, pat in pairs(patterns) do
        if pat:match(found) then
          return true
        end
      end
      return false
    else
      for _, p in ipairs(patterns) do
        for _, pat in ipairs(p) do
          if pat:match(found) then
            return true
          end
        end
      end
      return false
    end
  end

  -- borrowed from mime_types.lua
  -- ext is the last extension, LOWERCASED
  -- ext2 is the one before last extension LOWERCASED
  local function gen_extension(fname)
    local filename_parts = rspamd_str_split(fname, '.')

    local ext = {}
    for n = 1, 2 do
        ext[n] = #filename_parts > n and string.lower(filename_parts[#filename_parts + 1 - n]) or nil
    end
  --lua_util.debugm(N, task, '%s: extension found: %s', rule.log_prefix, ext[1])
    return ext[1],ext[2],filename_parts
  end

  return function(task)
    if rule.scan_mime_parts then
      local parts = task:get_parts() or {}

      local filter_func = function(p)
        local content_type,content_subtype = p:get_type()
        local fname = p:get_filename()
        local ext,ext2,part_table
        local extension_check = false
        local content_type_check = false
        if fname ~= nil then
          ext,ext2,part_table = gen_extension(fname)
          lua_util.debugm(N, task, '%s: extension found: %s - 2.ext: %s - parts: %s',
            rule.log_prefix, ext, ext2, part_table)
          if match_filter(task, ext, rule['mime_parts_filter_ext'])
            or match_filter(task, ext2, rule['mime_parts_filter_ext']) then
            lua_util.debugm(N, task, '%s: extension matched: %s', rule.log_prefix, ext)
            extension_check = true
          end
          if match_filter(task, fname, rule['mime_parts_filter_regex']) then
            --lua_util.debugm(N, task, '%s: regex fname: %s', rule.log_prefix, fname)
            content_type_check = true
          end
        end
        if content_type ~=nil and content_subtype ~= nil then
          if match_filter(task, content_type..'/'..content_subtype, rule['mime_parts_filter_regex']) then
            lua_util.debugm(N, task, '%s: regex ct: %s', rule.log_prefix, content_type..'/'..content_subtype)
            content_type_check = true
          end
        end

        return (rule.scan_image_mime and p:is_image())
            or (rule.scan_text_mime and p:is_text())
            or (p:get_filename() and rule.scan_all_mime_parts ~= false)
            or extension_check
            or content_type_check
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
      if not m.name then m.name = k end
      local cb = add_scanner_rule(k, m)

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
      end
    end
  end

  if not has_valid then
    lua_util.disable_module(N, 'config')
  end
end
