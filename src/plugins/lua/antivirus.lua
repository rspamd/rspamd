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
local lua_util = require "lua_util"
local rspamd_util = require "rspamd_util"
local lua_redis = require "lua_redis"
local fun = require "fun"
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
      # symbol_name = "pattern";
      JUST_EICAR = "^Eicar-Test-Signature$";
    }
    # `whitelist` points to a map of IP addresses. Mail from these addresses is not scanned.
    whitelist = "/etc/rspamd/antivirus.wl";
    # Replace content that exactly matches the following string to the EICAR pattern
    # Useful for E2E testing when another party removes/blocks EICAR attachments
    #eicar_fake_pattern = 'testpatterneicar';
  }
}
]])
  return
end

-- Encode as base32 in the source to avoid crappy stuff
local eicar_pattern = rspamd_util.decode_base32(
    [[akp6woykfbonrepmwbzyfpbmibpone3mj3pgwbffzj9e1nfjdkorisckwkohrnfe1nt41y3jwk1cirjki4w4nkieuni4ndfjcktnn1yjmb1wn]]
)

local function add_antivirus_rule(sym, opts)
  if not opts.type then
    rspamd_logger.errx(rspamd_config, 'unknown type for AV rule %s', sym)
    return nil
  end

  if not opts.symbol then opts.symbol = sym:upper() end
  local cfg = lua_antivirus[opts.type]

  if not cfg then
    rspamd_logger.errx(rspamd_config, 'unknown antivirus type: %s',
        opts.type)
    return nil
  end

  if not opts.symbol_fail then
    opts.symbol_fail = opts.symbol .. '_FAIL'
  end
  if not opts.symbol_encrypted then
    opts.symbol_encrypted = opts.symbol .. '_ENCRYPTED'
  end
  if not opts.symbol_macro then
    opts.symbol_macro = opts.symbol .. '_MACRO'
  end

  -- WORKAROUND for deprecated attachments_only
  if opts.attachments_only ~= nil then
    opts.scan_mime_parts = opts.attachments_only
    rspamd_logger.warnx(rspamd_config, '%s [%s]: Using attachments_only is deprecated. '..
        'Please use scan_mime_parts = %s instead', opts.symbol, opts.type, opts.attachments_only)
  end
  -- WORKAROUND for deprecated attachments_only

  local rule = cfg.configure(opts)
  if not rule then return nil end

  rule.type = opts.type
  rule.symbol_fail = opts.symbol_fail
  rule.symbol_encrypted = opts.symbol_encrypted
  rule.redis_params = redis_params

  if not rule then
    rspamd_logger.errx(rspamd_config, 'cannot configure %s for %s',
        opts.type, opts.symbol)
    return nil
  end

  rule.patterns = common.create_regex_table(opts.patterns or {})
  rule.patterns_fail = common.create_regex_table(opts.patterns_fail or {})

  lua_redis.register_prefix(rule.prefix .. '_*', N,
      string.format('Antivirus cache for rule "%s"',
          rule.type), {
        type = 'string',
      })

  if opts.whitelist then
    rule.whitelist = rspamd_config:add_hash_map(opts.whitelist)
  end

  return function(task)
    if rule.scan_mime_parts then

      fun.each(function(p)
        local content = p:get_content()
        local clen = #content
        if content and clen > 0 then
          if opts.eicar_fake_pattern then
            if type(opts.eicar_fake_pattern) == 'string' then
              -- Convert it to Rspamd text
              local rspamd_text = require "rspamd_text"
              opts.eicar_fake_pattern = rspamd_text.fromstring(opts.eicar_fake_pattern)
            end

            if clen == #opts.eicar_fake_pattern and content == opts.eicar_fake_pattern then
              rspamd_logger.infox(task, 'found eicar fake replacement part in the part (filename="%s")',
                p:get_filename())
              content = eicar_pattern
            end
          end
          cfg.check(task, content, p:get_digest(), rule, p)
        end
      end, common.check_parts_match(task, rule))

    else
      cfg.check(task, task:get_content(), task:get_digest(), rule)
    end
  end
end

-- Registration
local opts = rspamd_config:get_all_opt(N)
if opts and type(opts) == 'table' then
  redis_params = lua_redis.parse_redis_server(N)
  local has_valid = false
  for k, m in pairs(opts) do
    if type(m) == 'table' then
      if not m.type then m.type = k end
      if not m.name then m.name = k end
      local cb = add_antivirus_rule(k, m)

      if not cb then
        rspamd_logger.errx(rspamd_config, 'cannot add rule: "' .. k .. '"')
      else
        rspamd_logger.infox(rspamd_config, 'added antivirus engine %s -> %s', k, m.symbol)
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

        rspamd_config:register_symbol({
          type = 'virtual',
          name = m['symbol_fail'],
          parent = id,
          score = 0.0,
          group = N
        })
        rspamd_config:register_symbol({
          type = 'virtual',
          name = m['symbol_encrypted'],
          parent = id,
          score = 0.0,
          group = N
        })
        rspamd_config:register_symbol({
          type = 'virtual',
          name = m['symbol_macro'],
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
                    group = N
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
