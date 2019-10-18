--[[
Copyright (c) 2018, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

--[[[
-- @module savapi
-- This module contains avira savapi antivirus access functions
--]]

local lua_util = require "lua_util"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local rspamd_util = require "rspamd_util"
local rspamd_logger = require "rspamd_logger"
local common = require "lua_scanners/common"

local N = "savapi"

local default_message = '${SCANNER}: virus found: "${VIRUS}"'

local function savapi_config(opts)
  local savapi_conf = {
    name = N,
    scan_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false,
    default_port = 4444, -- note: You must set ListenAddress in savapi.conf
    product_id = 0,
    log_clean = false,
    timeout = 15.0, -- FIXME: this will break task_timeout!
    retransmits = 1, -- FIXME: useless, for local files
    cache_expire = 3600, -- expire redis in one hour
    message = default_message,
    detection_category = "virus",
    tmpdir = '/tmp',
  }

  savapi_conf = lua_util.override_defaults(savapi_conf, opts)

  if not savapi_conf.prefix then
    savapi_conf.prefix = 'rs_' .. savapi_conf.name .. '_'
  end

  if not savapi_conf.log_prefix then
    if savapi_conf.name:lower() == savapi_conf.type:lower() then
      savapi_conf.log_prefix = savapi_conf.name
    else
      savapi_conf.log_prefix = savapi_conf.name .. ' (' .. savapi_conf.type .. ')'
    end
  end

  if not savapi_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  savapi_conf['upstreams'] = upstream_list.create(rspamd_config,
      savapi_conf['servers'],
      savapi_conf.default_port)

  if savapi_conf['upstreams'] then
    lua_util.add_debug_alias('antivirus', savapi_conf.name)
    return savapi_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      savapi_conf['servers'])
  return nil
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
      lua_util.debugm(rule.name, task, "%s: number of virus names found %s", rule['type'], #vnames_reordered)
      if #vnames_reordered > 0 then
        local vname = {}
        for _,virus in ipairs(vnames_reordered) do
          table.insert(vname, virus)
        end

        common.yield_result(task, rule, vname)
        common.save_cache(task, digest, rule, vname)
      end
      if conn then
        conn:close()
      end
    end

    local function savapi_scan2_cb(err, data, conn)
      local result = tostring(data)
      lua_util.debugm(rule.name, task, "%s: got reply: %s",
          rule.type, result)

      -- Terminal response - clean
      if string.find(result, '200') or string.find(result, '210') then
        if rule['log_clean'] then
          rspamd_logger.infox(task, '%s: message or mime_part is clean', rule['type'])
        end
        common.save_cache(task, digest, rule, 'OK')
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
            common.yield_result(task, rule, 'virus result unparseable: ' .. result, 0.0, 'fail')
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
        lua_util.debugm(rule.name, task, "%s: scanning file: %s",
            rule['type'], fname)
        conn:add_write(savapi_scan1_cb, {string.format('SCAN %s\n',
            fname)})
      else
        rspamd_logger.errx(task, '%s: invalid product id %s', rule['type'],
            rule['product_id'])
        common.yield_result(task, rule, 'invalid product id: ' .. result, 0.0, 'fail')
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

          lua_util.debugm(rule.name, task, '%s: error: %s; retry IP: %s; retries left: %s',
              rule.log_prefix, err, addr, retransmits)

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
          common.yield_result(task, rule, 'failed to scan and retransmits exceed', 0.0, 'fail')
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

  if common.condition_check_and_continue(task, content, rule, digest, savapi_check_uncached) then
    return
  else
    savapi_check_uncached()
  end

end

return {
  type = 'antivirus',
  description = 'savapi avira antivirus',
  configure = savapi_config,
  check = savapi_check,
  name = N
}
