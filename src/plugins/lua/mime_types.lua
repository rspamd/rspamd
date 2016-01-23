--[[
Copyright (c) 2016, Vsevolod Stakhov <vsevolod@highsecure.ru>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
]]--

-- This plugin implements mime types checks for mail messages
local rspamd_logger = require "rspamd_logger"

local settings = {
  file = '',
  symbol_unknown = 'MIME_UNKNOWN',
  symbol_bad = 'MIME_BAD',
  symbol_good = 'MIME_GOOD',
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
        local ct = string.format('%s/%s', type, subtype)
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
  end
end