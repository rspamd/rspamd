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
  symbol_obfuscated_archive = 'MIME_OBFUSCATED_ARCHIVE',
  symbol_exe_in_gen_split_rar = 'MIME_EXE_IN_GEN_SPLIT_RAR',
  symbol_archive_in_archive = 'MIME_ARCHIVE_IN_ARCHIVE',
  symbol_double_extension = 'MIME_DOUBLE_BAD_EXTENSION',
  symbol_bad_extension = 'MIME_BAD_EXTENSION',
  symbol_bad_unicode = 'MIME_BAD_UNICODE',
  regexp = false,
  extension_map = { -- extension -> mime_type
    html = 'text/html',
    htm = 'text/html',
    pdf = 'application/pdf',
    shtm = 'text/html',
    shtml = 'text/html',
    txt = 'text/plain'
  },

  bad_extensions = {
    cue = 2,
    exe = 1,
    iso = 4,
    jar = 2,
    -- In contrast to HTML MIME parts, dedicated HTML attachments are considered harmful
    htm = 1,
    html = 1,
    shtm = 1,
    shtml = 1,
    -- Have you ever seen that in legit email?
    ace = 4,
    arj = 2,
    aspx = 1,
    asx = 2,
    cab = 3,
    dll = 4,
    dqy = 2,
    iqy = 2,
    mht = 2,
    mhtml = 2,
    oqy = 2,
    rqy = 2,
    sfx = 2,
    slk = 2,
    vst = 2,
    vss = 2,
    wim = 2,
    -- Additional bad extensions from Gmail
    ade = 4,
    adp = 4,
    cmd = 4,
    cpl = 4,
    ins = 4,
    isp = 4,
    js = 4,
    jse = 4,
    lib = 4,
    mde = 4,
    msc = 4,
    msi = 4,
    msp = 4,
    mst = 4,
    nsh = 4,
    pif = 4,
    sct = 4,
    shb = 4,
    sys = 4,
    vb = 4,
    vbe = 4,
    vbs = 4,
    vxd = 4,
    wsc = 4,
    wsh = 4,
    -- Additional bad extensions from Outlook
    app = 4,
    asp = 4,
    bas = 4,
    bat = 4,
    chm = 4,
    cnt = 4,
    com = 4,
    csh = 4,
    diagcab = 4,
    fxp = 4,
    gadget = 4,
    grp = 4,
    hlp = 4,
    hpj = 4,
    hta = 4,
    htc = 4,
    inf = 4,
    its = 4,
    jnlp = 4,
    lnk = 4,
    ksh = 4,
    mad = 4,
    maf = 4,
    mag = 4,
    mam = 4,
    maq = 4,
    mar = 4,
    mas = 4,
    mat = 4,
    mau = 4,
    mav = 4,
    maw = 4,
    mcf = 4,
    mda = 4,
    mdb = 4,
    mdt = 4,
    mdw = 4,
    mdz = 4,
    msh = 4,
    msh1 = 4,
    msh2 = 4,
    mshxml = 4,
    msh1xml = 4,
    msh2xml = 4,
    msu = 4,
    ops = 4,
    osd = 4,
    pcd = 4,
    pl = 4,
    plg = 4,
    prf = 4,
    prg = 4,
    printerexport = 4,
    ps1 = 4,
    ps1xml = 4,
    ps2 = 4,
    ps2xml = 4,
    psc1 = 4,
    psc2 = 4,
    psd1 = 4,
    psdm1 = 4,
    pst = 4,
    pyc = 4,
    pyo = 4,
    pyw = 4,
    pyz = 4,
    pyzw = 4,
    reg = 4,
    scf = 4,
    scr = 4,
    shs = 4,
    theme = 4,
    url = 4,
    vbp = 4,
    vhd = 4,
    vhdx = 4,
    vsmacros = 4,
    vsw = 4,
    webpnp = 4,
    website = 4,
    ws = 4,
    wsf = 4,
    xbap = 4,
    xll = 4,
    xnk = 4,
  },

  -- Something that should not be in archive
  bad_archive_extensions = {
    docx = 0.1,
    hta = 4,
    jar = 3,
    js = 0.5,
    pdf = 0.1,
    pptx = 0.1,
    vbs = 4,
    wsf = 4,
    xlsx = 0.1,
  },

  archive_extensions = {
    ['7z'] = 1,
    ace = 1,
    alz = 1,
    arj = 1,
    bz2 = 1,
    cab = 1,
    egg = 1,
    lz = 1,
    rar = 1,
    xz = 1,
    zip = 1,
  },

  -- Not really archives
  archive_exceptions = {
    docx = true,
    odp = true,
    ods = true,
    odt = true,
    pptx = true,
    vsdx = true,
    xlsx = true,
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

    return ext[1], ext[2], parts
  end

  local function check_filename(fname, ct, is_archive, part, detected_ext, nfiles)

    lua_util.debugm(N, task, "check filename: %s, ct=%s, is_archive=%s, detected_ext=%s, nfiles=%s",
        fname, ct, is_archive, detected_ext, nfiles)
    local has_bad_unicode, char, ch_pos = rspamd_util.has_obscured_unicode(fname)
    if has_bad_unicode then
      task:insert_result(settings.symbol_bad_unicode, 1.0,
          string.format("0x%xd after %s", char,
              fname:sub(1, ch_pos)))
    end

    -- Decode hex encoded characters
    fname = string.gsub(fname, '%%(%x%x)',
        function(hex)
          return string.char(tonumber(hex, 16))
        end)

    -- Replace potentially bad characters with '?'
    fname = fname:gsub('[^%s%g]', '?')

    -- Check file is in filename whitelist
    if settings.filename_whitelist and
        settings.filename_whitelist:get_key(fname) then
      logger.debugm("mime_types", task, "skip checking of %s - file is in filename whitelist",
          fname)
      return
    end

    local ext, ext2, parts = gen_extension(fname)
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

    if not ext then
      return
    end

    local function check_extension(badness_mult, badness_mult2)
      if not badness_mult and not badness_mult2 then
        return
      end
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
              fun.map(function(e)
                return e, 1.0
              end,
                  user_settings.bad_extensions))
        else
          extra_table = user_settings.bad_extensions
        end
      end
      if user_settings.bad_archive_extensions then
        if user_settings.bad_archive_extensions[1] then
          -- Convert to a key-value map
          extra_archive_table = fun.tomap(fun.map(
              function(e)
                return e, 1.0
              end,
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
      for _, v in ipairs(mt) do
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
    for _, p in ipairs(parts) do
      local mtype, subtype = p:get_type()

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

          -- TODO: migrate to flags once C part is ready
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
          elseif arch:is_obfuscated() then
            task:insert_result(settings.symbol_obfuscated_archive, 1.0, {
              'obfuscated archive',
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

            for _, f in ipairs(fl) do
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
              local _, ext2 = gen_extension(filename)

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
            if not v or v_detected and v_detected > v then
              v = v_detected
            end
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

local opts = rspamd_config:get_all_opt('mime_types')
if opts then
  for k, v in pairs(opts) do
    settings[k] = v
  end

  settings.filename_whitelist = lua_maps.rspamd_map_add('mime_types', 'filename_whitelist', 'regexp',
      'filename whitelist')

  local function change_extension_map_entry(ext, ct, mult)
    if type(ct) == 'table' then
      local tbl = {}
      for _, elt in ipairs(ct) do
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
  for ext, ct in pairs(settings.extension_map) do
    change_extension_map_entry(ext, ct, 1.0)
  end

  -- Add all extensions
  for _, pair in ipairs(lua_mime_types.full_extensions_map) do
    local ext, ct = pair[1], pair[2]
    if not settings.extension_map[ext] then
      change_extension_map_entry(ext, ct, settings.other_extensions_mult)
    end
  end

  local map_type = 'map'
  if settings['regexp'] then
    map_type = 'regexp'
  end
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
      name = settings['symbol_obfuscated_archive'],
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
