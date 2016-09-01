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
  symbol_encrypted_archive = 'MIME_ENCRYPTED_ARCHIVE',
  symbol_archive_in_archive = 'MIME_ARCHIVE_IN_ARCHIVE',
  symbol_double_extension = 'MIME_DOUBLE_BAD_EXTENSION',
  symbol_bad_extension = 'MIME_BAD_EXTENSION',
  regexp = false,
  extension_map = { -- extension -> mime_type
    html = 'text/html',
    htm = 'text/html',
    txt = 'text/plain',
    pdf = 'application/pdf'
  },

  bad_extensions = {
    scr = 4,
    lnk = 4,
    exe = 1,
    jar = 2,
    com = 2,
    bat = 2,
    -- Have you ever seen that in legit email?
    ace = 4,
    arj = 4,
    cab = 3,
  },

  -- Something that should not be in archive
  bad_archive_extensions = {
    pptx = 0.1,
    docx = 0.1,
    xlsx = 0.1,
    pdf = 0.1,
    jar = 3,
    js = 0.5,
    vbs = 4,
  },

  archive_extensions = {
    zip = 1,
    arj = 1,
    rar = 1,
    ace = 1,
    ['7z'] = 1,
    cab = 1,
  }
}

local map = nil

local function check_mime_type(task)
  local function check_filename(fname, ct, is_archive)
    local parts = rspamd_str_split(fname, '.')

    local ext
    if #parts > 1 then
      ext = parts[#parts]
    end

    local function check_extension(badness_mult)
      if badness_mult then
        if #parts > 2
          -- We need to ensure that it is an extension, so we check for its length
          and #parts[#parts - 1] <= 4
          -- Check if next-to-last extension is not a number
          and not string.match(parts[#parts - 1], '^%d+$') then
          -- Double extension + bad extension == VERY bad
          task:insert_result(settings['symbol_double_extension'], badness_mult, {
            '.' .. parts[#parts - 1] .. '.' .. ext
          })
        else
          -- Just bad extension
          task:insert_result(settings['symbol_bad_extension'], badness_mult, ext)
        end
      end

    end

    if ext then
      check_extension(settings['bad_extensions'][ext:lower()])

      -- Also check for archive bad extension
      if is_archive then
        check_extension(settings['bad_archive_extensions'][ext:lower()])

        if settings['archive_extensions'][ext:lower()] then
          -- Archive in archive
          task:insert_result(settings['symbol_archive_in_archive'], 1.0, ext)
        end
      end

      local mt = settings['extension_map'][ext:lower()]
      if mt and ct then
        local found = nil
        if (type(mt) == "table") then
          for _,v in pairs(mt) do
            if ct == v then
              found = true
              break
            end
          end
        else
          if ct == mt then
            found = true
          end
        end

        if not found  then
          task:insert_result(settings['symbol_attachment'], 1.0, ext)
        end
      end
    end
  end

  local parts = task:get_parts()

  if parts then
    for _,p in ipairs(parts) do
      local mtype,subtype = p:get_type()

      if not mtype then
        task:insert_result(settings['symbol_unknown'], 1.0, 'missing content type')
      else
        -- Check for attachment
        local filename = p:get_filename()
        local ct = string.format('%s/%s', mtype, subtype):lower()

        if filename then
          filename = filename:gsub('[^%s%g]', '?')
          check_filename(filename, ct, false)
        end

        if p:is_archive() then
          local arch = p:get_archive()

          if arch:is_encrypted() then
            task:insert_result(settings['symbol_encrypted_archive'], 1.0, filename)
          end

          local fl = arch:get_files_full()

          for _,f in ipairs(fl) do
            -- Strip bad characters
            if f['name'] then
              f['name'] = f['name']:gsub('[^%s%g]', '?')
            end

            if f['encrypted'] then
              task:insert_result(settings['symbol_encrypted_archive'], 1.0, f['name'])
            end

            if f['name'] then
              check_filename(f['name'], nil, true)
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
  if opts['enabled'] == false then
    rspamd_logger.info('Module is disabled')
    return
  end
  for k,v in pairs(opts) do
    settings[k] = v
  end

  if settings['file'] and #settings['file'] > 0 then

    if settings['regexp'] then
      map = rspamd_config:add_map ({
        url = settings['file'],
        type = 'regexp',
        description = 'mime types map (regexps)'
      })
    else
      map = rspamd_config:add_map ({
        url = settings['file'],
        type = 'map',
        description = 'mime types map (plain)'
      })
    end
    local id = rspamd_config:register_symbol({
      callback = check_mime_type,
      type = 'callback'
    })

    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_unknown'],
      parent = id
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_bad'],
      parent = id
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_good'],
      flags = 'nice',
      parent = id
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_attachment'],
      parent = id
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_encrypted_archive'],
      parent = id
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_archive_in_archive'],
      parent = id
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_double_extension'],
      parent = id
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_bad_extension'],
      parent = id
    })
  end
end
