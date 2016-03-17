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
]]--

-- This plugin implements mime types checks for mail messages
local rspamd_logger = require "rspamd_logger"
local rspamd_regexp = require "rspamd_regexp"

local settings = {
  file = '',
  symbol_unknown = 'MIME_UNKNOWN',
  symbol_bad = 'MIME_BAD',
  symbol_good = 'MIME_GOOD',
  symbol_attachment = 'MIME_BAD_ATTACHMENT',
  regexp = false,
  extension_map = { -- extension -> mime_type
    html = 'text/html',
    txt = 'text/plain',
    pdf = 'application/pdf'
  },
}

local map = nil

local function check_mime_type(task)
  local parts = task:get_parts()

  if parts then
    for _,p in ipairs(parts) do
      local type,subtype = p:get_type()

      if not type then
        task:insert_result(settings['symbol_unknown'], 1.0, 'missing content type')
      else
        -- Check for attachment
        local filename = p:get_filename()
        local ct = string.format('%s/%s', type, subtype)

        if filename then
          local ext = string.match(filename, '%.([^.]+)$')

          if ext then
            if settings['extension_map'] then
              if ct ~= settings['extension_map'] then
                task:insert_result(settings['symbol_attachment'], 1.0, ext)
              end
            end
          end
        end

        if map then
          local v = map:get_key(ct)
          if v then
            local n = tonumber(v)

            if n > 0 then
              task:insert_result(settings['symbol_bad'], n, ct)
            elseif n < 0 then
              task:insert_result(settings['symbol_good'], -n, ct)
            end
          else
            task:insert_result(settings['symbol_unknown'], 1.0, ct)
          end
        end
      end
    end
  end
end

local opts =  rspamd_config:get_all_opt('mime_types')
if opts then
  for k,v in pairs(opts) do
    settings[k] = v
  end

  if settings['file'] and #settings['file'] > 0 then
    map = rspamd_config:add_kv_map (settings['file'], 
      'mime types map')
    if map then
      local id = rspamd_config:register_callback_symbol(1.0, check_mime_type)
      rspamd_config:register_virtual_symbol(settings['symbol_unknown'], 1.0, id)
      rspamd_config:register_virtual_symbol(settings['symbol_bad'], 1.0, id)
      rspamd_config:register_virtual_symbol(settings['symbol_good'], 1.0, id)
    else
      rspamd_logger.warnx(rspamd_config, 'Cannot add mime_types: map doesn\'t exists: %1',
        settings['file'])
    end
    local id = rspamd_config:register_callback_symbol(1.0, check_mime_type)
    rspamd_config:register_virtual_symbol(settings['symbol_unknown'], 1.0, id)
    rspamd_config:register_virtual_symbol(settings['symbol_bad'], 1.0, id)
    rspamd_config:register_virtual_symbol(settings['symbol_good'], 1.0, id)
    rspamd_config:register_virtual_symbol(settings['symbol_attachment'], 1.0, id)
  end
end
