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

if confighelp then
  return
end

-- This plugin implements mime types checks for mail messages
local logger = require "rspamd_logger"
local lua_util = require "lua_util"
local rspamd_util = require "rspamd_util"
local lua_maps = require "lua_maps"
local lua_mime_types = require "lua_mime_types"
local lua_magic_types = require "lua_magic/types"
local fun = require "fun"

local N = "mime_types"
local settings = {
  file = '',
  symbol_unknown = 'MIME_UNKNOWN',
  symbol_bad = 'MIME_BAD',
  symbol_good = 'MIME_GOOD',
  symbol_attachment = 'MIME_BAD_ATTACHMENT',
  symbol_encrypted_archive = 'MIME_ENCRYPTED_ARCHIVE',
  symbol_exe_in_gen_split_rar = 'MIME_EXE_IN_GEN_SPLIT_RAR',
  symbol_archive_in_archive = 'MIME_ARCHIVE_IN_ARCHIVE',
  symbol_double_extension = 'MIME_DOUBLE_BAD_EXTENSION',
  symbol_bad_extension = 'MIME_BAD_EXTENSION',
  symbol_bad_unicode = 'MIME_BAD_UNICODE',
  regexp = false,
  extension_map = { -- extension -> mime_type
    html = 'text/html',
    htm = 'text/html',
    txt = 'text/plain',
    pdf = 'application/pdf'
  },

  bad_extensions = {
    bat = 2,
    com = 2,
    exe = 1,
    iso = 4,
    jar = 2,
    lnk = 4,
    scr = 4,
    -- Have you ever seen that in legit email?
    ace = 4,
    arj = 2,
    cab = 3,
    -- Additional bad extensions from Gmail
    ade = 2,
    adp = 2,
    chm = 2,
    cmd = 2,
    cpl = 2,
    ins = 2,
    isp = 2,
    js = 2,
    jse = 2,
    lib = 2,
    mde = 2,
    msc = 2,
    msi = 2,
    msp = 2,
    mst = 2,
    nsh = 2,
    pif = 2,
    sct = 2,
    shb = 2,
    sys = 2,
    vb = 2,
    vbe = 2,
    vbs = 2,
    vxd = 2,
    wsc = 2,
    wsh = 2,
    -- Additional bad extensions from Outlook
    app = 2,
    asp = 2,
    bas = 2,
    cnt = 2,
    csh = 2,
    diagcab = 2,
    fxp = 2,
    gadget = 2,
    grp = 2,
    hlp = 2,
    hpj = 2,
    inf = 2,
    its = 2,
    jnlp = 2,
    ksh = 2,
    mad = 2,
    maf = 2,
    mag = 2,
    mam = 2,
    maq = 2,
    mar = 2,
    mas = 2,
    mat = 2,
    mau = 2,
    mav = 2,
    maw = 2,
    mcf = 2,
    mda = 2,
    mdb = 2,
    mdt = 2,
    mdw = 2,
    mdz = 2,
    msh = 2,
    msh1 = 2,
    msh2 = 2,
    mshxml = 2,
    msh1xml = 2,
    msh2xml = 2,
    msu = 2,
    ops = 2,
    osd = 2,
    pcd = 2,
    pl = 2,
    plg = 2,
    prf = 2,
    prg = 2,
    printerexport = 2,
    ps1 = 2,
    ps1xml = 2,
    ps2 = 2,
    ps2xml = 2,
    psc1 = 2,
    psc2 = 2,
    psd1 = 2,
    psdm1 = 2,
    pst = 2,
    reg = 2,
    scf = 2,
    shs = 2,
    theme = 2,
    url = 2,
    vbp = 2,
    vsmacros = 2,
    vsw = 2,
    webpnp = 2,
    website = 2,
    ws = 2,
    xbap = 2,
    xll = 2,
    xnk = 2,
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
    wsf = 4,
    hta = 4,
  },

  archive_extensions = {
    zip = 1,
    arj = 1,
    rar = 1,
    ace = 1,
    ['7z'] = 1,
    cab = 1,
    bz2 = 1,
    egg = 1,
    alz = 1,
    xz = 1,
    lz = 1,
  },

  -- Not really archives
  archive_exceptions = {
    odt = true,
    ods = true,
    odp = true,
    docx = true,
    xlsx = true,
    pptx = true,
    vsdx = true,
    -- jar = true,
  },

  -- Multiplier for full extension_map mismatch
  other_extensions_mult = 0.4,
}

local map = nil

local function check_mime_type(task)
  local function gen_extension(fname)
    local parts = lua_util.str_split(fname or '', '.')

    local ext = {}
    for n = 1, 2 do
        ext[n] = #parts > n and string.lower(parts[#parts + 1 - n]) or nil
    end

    return ext[1],ext[2],parts
  end

  local function check_filename(fname, ct, is_archive, part, detected_ext, nfiles)

    local has_bad_unicode, char, ch_pos = rspamd_util.has_obscured_unicode(fname)
    if has_bad_unicode then
      task:insert_result(settings.symbol_bad_unicode, 1.0,
          string.format("0x%xd after %s", char,
              fname:sub(1, ch_pos)))
    end

    -- Decode hex encoded characters
    fname = string.gsub(fname, '%%(%x%x)',
        function (hex) return string.char(tonumber(hex,16)) end )

    -- Replace potentially bad characters with '?'
    fname = fname:gsub('[^%s%g]', '?')

    -- Check file is in filename whitelist
    if settings.filename_whitelist and
        settings.filename_whitelist:get_key(fname) then
      logger.debugm("mime_types", task, "skip checking of %s - file is in filename whitelist",
          fname)
      return
    end

    local ext,ext2,parts = gen_extension(fname)
    -- ext is the last extension, LOWERCASED
    -- ext2 is the one before last extension LOWERCASED

    local detected

    if not is_archive and detected_ext then
      detected = lua_magic_types[detected_ext]
    end

    if detected_ext and ((not ext) or ext ~= detected_ext) then
      -- Try to find extension by real content type
      check_filename('detected.' .. detected_ext, detected.ct,
          false, part, nil, 1)
    end

    if not ext then return end

    local function check_extension(badness_mult, badness_mult2)
      if not badness_mult and not badness_mult2 then return end
      if #parts > 2 then
        -- We need to ensure that next-to-last extension is an extension,
        -- so we check for its length and if it is not a number or date
        if #ext2 > 0 and #ext2 <= 4 and not string.match(ext2, '^%d+[%]%)]?$') then

          -- Use the greatest badness multiplier
          if not badness_mult or
              (badness_mult2 and badness_mult < badness_mult2) then
            badness_mult = badness_mult2
          end

          -- Double extension + bad extension == VERY bad
          task:insert_result(settings['symbol_double_extension'], badness_mult,
              string.format(".%s.%s", ext2, ext))
          task:insert_result('MIME_TRACE', 0.0,
              string.format("%s:%s", part:get_id(), '-'))
          return
        end
      end
      if badness_mult then
        -- Just bad extension
        task:insert_result(settings['symbol_bad_extension'], badness_mult, ext)
        task:insert_result('MIME_TRACE', 0.0,
            string.format("%s:%s", part:get_id(), '-'))
      end
    end

    -- Process settings
    local extra_table = {}
    local extra_archive_table = {}
    local user_settings = task:cache_get('settings')
    if user_settings and user_settings.plugins then
      user_settings = user_settings.plugins.mime_types
    end

    if user_settings then
      logger.infox(task, 'using special tables from user settings')
      if user_settings.bad_extensions then
        if user_settings.bad_extensions[1] then
          -- Convert to a key-value map
          extra_table = fun.tomap(
              fun.map(function(e) return e,1.0 end,
                  user_settings.bad_extensions))
        else
          extra_table = user_settings.bad_extensions
        end
      end
      if user_settings.bad_archive_extensions then
        if user_settings.bad_archive_extensions[1] then
          -- Convert to a key-value map
          extra_archive_table = fun.tomap(fun.map(
              function(e) return e,1.0 end,
              user_settings.bad_archive_extensions))
        else
          extra_archive_table = user_settings.bad_archive_extensions
        end
      end
    end

    local function check_tables(e)
      if is_archive then
        return extra_archive_table[e] or (nfiles < 2 and settings.bad_archive_extensions[e]) or
            extra_table[e] or settings.bad_extensions[e]
      end

      return extra_table[e] or settings.bad_extensions[e]
    end

    -- Also check for archive bad extension
    if is_archive then
      if ext2 then
        local score1 = check_tables(ext)
        local score2 = check_tables(ext2)
        check_extension(score1, score2)
      else
        local score1 = check_tables(ext)
        check_extension(score1, nil)
      end

      if settings['archive_extensions'][ext] then
        -- Archive in archive
        task:insert_result(settings['symbol_archive_in_archive'], 1.0, ext)
        task:insert_result('MIME_TRACE', 0.0,
            string.format("%s:%s", part:get_id(), '-'))
      end
    else
      if ext2 then
        local score1 = check_tables(ext)
        local score2 = check_tables(ext2)
        check_extension(score1, score2)
        -- Check for archive cloaking like .zip.gz
        if settings['archive_extensions'][ext2]
            -- Exclude multipart archive extensions, e.g. .zip.001
            and not string.match(ext, '^%d+$')
        then
          task:insert_result(settings['symbol_archive_in_archive'],
              1.0, string.format(".%s.%s", ext2, ext))
          task:insert_result('MIME_TRACE', 0.0,
              string.format("%s:%s", part:get_id(), '-'))
        end
      else
        local score1 = check_tables(ext)
        check_extension(score1, nil)
      end
    end

    local mt = settings['extension_map'][ext]
    if mt and ct and ct ~= 'application/octet-stream' then
      local found
      local mult
      for _,v in ipairs(mt) do
        mult = v.mult
        if ct == v.ct then
          found = true
          break
        end
      end

      if not found then
        task:insert_result(settings['symbol_attachment'], mult, string.format('%s:%s',
            ext, ct))
      end
    end
  end

  local parts = task:get_parts()

  if parts then
    for _,p in ipairs(parts) do
      local mtype,subtype = p:get_type()

      if not mtype then
        lua_util.debugm(N, task, "no content type for part: %s", p:get_id())
        task:insert_result(settings['symbol_unknown'], 1.0, 'missing content type')
        task:insert_result('MIME_TRACE', 0.0,
            string.format("%s:%s", p:get_id(), '~'))
      else
        -- Check for attachment
        local filename = p:get_filename()
        local ct = string.format('%s/%s', mtype, subtype):lower()
        local detected_ext = p:get_detected_ext()

        if filename then
          check_filename(filename, ct, false, p, detected_ext, 1)
        end

        if p:is_archive() then
          local check = true
          if detected_ext then
            local detected_type = lua_magic_types[detected_ext]

            if detected_type.type ~= 'archive' then
              logger.debugm("mime_types", task, "skip checking of %s as archive, %s is not archive but %s",
                  filename, detected_type.type)
              check = false
            end
          end
          if check and filename then
            local ext = gen_extension(filename)

            if ext and settings.archive_exceptions[ext] then
              check = false
              logger.debugm("mime_types", task, "skip checking of %s as archive, %s is whitelisted",
                  filename, ext)
            end
          end
          local arch = p:get_archive()

          if arch:is_encrypted() then
            task:insert_result(settings.symbol_encrypted_archive, 1.0, filename)
            task:insert_result('MIME_TRACE', 0.0,
                string.format("%s:%s", p:get_id(), '-'))
          elseif arch:is_unreadable() then
            task:insert_result(settings.symbol_encrypted_archive, 0.5, {
              'compressed header',
              filename,
            })
            task:insert_result('MIME_TRACE', 0.0,
                string.format("%s:%s", p:get_id(), '-'))
          end

          if check then
            local is_gen_split_rar = false
            if filename then
              local ext = gen_extension(filename)
              is_gen_split_rar = ext and (string.match(ext, '^%d%d%d$')) and (arch:get_type() == 'rar')
            end

            local fl = arch:get_files_full(1000)

            local nfiles = #fl

            for _,f in ipairs(fl) do
              if f['encrypted'] then
                task:insert_result(settings['symbol_encrypted_archive'],
                    1.0, f['name'])
                task:insert_result('MIME_TRACE', 0.0,
                    string.format("%s:%s", p:get_id(), '-'))
              end

              if f['name'] then
                if is_gen_split_rar and (gen_extension(f['name']) or '') == 'exe' then
                  task:insert_result(settings['symbol_exe_in_gen_split_rar'], 1.0, f['name'])
                else
                  check_filename(f['name'], nil,
                      true, p, nil, nfiles)
                end
              end
            end

            if nfiles == 1 and fl[1].name then
              -- We check that extension of the file inside archive is
              -- the same as double extension of the file
              local _,ext2 = gen_extension(filename)

              if ext2 and #ext2 > 0 then
                local enc_ext = gen_extension(fl[1].name)

                if enc_ext
                    and settings['bad_extensions'][enc_ext]
                    and not tonumber(ext2)
                    and enc_ext ~= ext2 then
                  task:insert_result(settings['symbol_double_extension'], 2.0,
                      string.format("%s!=%s", ext2, enc_ext))
                end
              end
            end
          end
        end

        if map then
          local v = map:get_key(ct)
          local detected_different = false

          local detected_type
          if detected_ext then
            detected_type = lua_magic_types[detected_ext]
          end

          if detected_type and detected_type.ct ~= ct then
            local v_detected = map:get_key(detected_type.ct)
            if not v or v_detected and v_detected > v then v = v_detected end
            detected_different = true
          end
          if v then
            local n = tonumber(v)

            if n then
              if n > 0 then
                if detected_different then
                  -- Penalize case
                  n = n * 1.5
                  task:insert_result(settings['symbol_bad'], n,
                      string.format('%s:%s', ct, detected_type.ct))
                else
                  task:insert_result(settings['symbol_bad'], n, ct)
                end
                task:insert_result('MIME_TRACE', 0.0,
                    string.format("%s:%s", p:get_id(), '-'))
              elseif n < 0 then
                task:insert_result(settings['symbol_good'], -n, ct)
                task:insert_result('MIME_TRACE', 0.0,
                    string.format("%s:%s", p:get_id(), '+'))
              else
                -- Neutral content type
                task:insert_result('MIME_TRACE', 0.0,
                    string.format("%s:%s", p:get_id(), '~'))
              end
            else
              logger.warnx(task, 'unknown value: "%s" for content type %s in the map',
                  v, ct)
            end
          else
            task:insert_result(settings['symbol_unknown'], 1.0, ct)
            task:insert_result('MIME_TRACE', 0.0,
                string.format("%s:%s", p:get_id(), '~'))
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

  settings.filename_whitelist = lua_maps.rspamd_map_add('mime_types', 'filename_whitelist', 'regexp',
    'filename whitelist')

  local function change_extension_map_entry(ext, ct, mult)
    if type(ct) == 'table' then
      local tbl = {}
      for _,elt in ipairs(ct) do
        table.insert(tbl, {
          ct = elt,
          mult = mult,
        })
      end
      settings.extension_map[ext] = tbl
    else
      settings.extension_map[ext] = { [1] = {
        ct = ct,
        mult = mult
      } }
    end
  end

  -- Transform extension_map
  for ext,ct in pairs(settings.extension_map) do
    change_extension_map_entry(ext, ct, 1.0)
  end

  -- Add all extensions
  for _,pair in ipairs(lua_mime_types.full_extensions_map) do
    local ext, ct = pair[1], pair[2]
    if not settings.extension_map[ext] then
        change_extension_map_entry(ext, ct, settings.other_extensions_mult)
    end
  end

  local map_type = 'map'
  if settings['regexp'] then map_type = 'regexp' end
  map = lua_maps.rspamd_map_add('mime_types', 'file', map_type,
    'mime types map')
  if map then
    local id = rspamd_config:register_symbol({
      name = 'MIME_TYPES_CALLBACK',
      callback = check_mime_type,
      type = 'callback',
      flags = 'nostat',
      group = 'mime_types',
    })

    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_unknown'],
      parent = id,
      group = 'mime_types',
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_bad'],
      parent = id,
      group = 'mime_types',
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_good'],
      flags = 'nice',
      parent = id,
      group = 'mime_types',
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_attachment'],
      parent = id,
      group = 'mime_types',
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_encrypted_archive'],
      parent = id,
      group = 'mime_types',
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_exe_in_gen_split_rar'],
      parent = id,
      group = 'mime_types',
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_archive_in_archive'],
      parent = id,
      group = 'mime_types',
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_double_extension'],
      parent = id,
      group = 'mime_types',
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_bad_extension'],
      parent = id,
      group = 'mime_types',
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = settings['symbol_bad_unicode'],
      parent = id,
      group = 'mime_types',
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = 'MIME_TRACE',
      parent = id,
      group = 'mime_types',
      flags = 'nostat',
      score = 0,
    })
  else
    lua_util.disable_module(N, "config")
  end
end
