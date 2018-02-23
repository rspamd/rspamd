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
local N = "mime_types"
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
    cer = 2,
    cnt = 2,
    crt = 2,
    csh = 2,
    der = 2,
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
    tmp = 2,
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
}

local map = nil

local function check_mime_type(task)
  local function gen_extension(fname)
    local parts = rspamd_str_split(fname, '.')

    local ext = {}
    for n = 1, 2 do
        ext[n] = #parts > n and string.lower(parts[#parts + 1 - n]) or nil
    end

    return ext[1],ext[2],parts
  end

  local function check_filename(fname, ct, is_archive)
    local ext,ext2,parts = gen_extension(fname)
    -- ext is the last extension, LOWERCASED
    -- ext2 is the one before last extension LOWERCASED

    local function check_extension(badness_mult, badness_mult2)
      if not badness_mult and not badness_mult2 then return end
      if #parts > 2 then
        -- We need to ensure that next-to-last extension is an extension,
        -- so we check for its length and if it is not a number or date
        if #ext2 <= 4 and not string.match(ext2, '^%d+$') then

          -- Use the greatest badness multiplier
          if not badness_mult or
              (badness_mult2 and badness_mult < badness_mult2) then
            badness_mult = badness_mult2
          end

          -- Double extension + bad extension == VERY bad
          task:insert_result(settings['symbol_double_extension'], badness_mult,
            string.format(".%s.%s", ext2, ext))
          return
        end
      end
      if badness_mult then
        -- Just bad extension
        task:insert_result(settings['symbol_bad_extension'], badness_mult, ext)
      end
    end

    if ext then
      -- Also check for archive bad extension
      if is_archive then
        if ext2 then
          local score1 = settings['bad_archive_extensions'][ext] or
              settings['bad_extensions'][ext]
          local score2 = settings['bad_archive_extensions'][ext2] or
              settings['bad_extensions'][ext2]
          check_extension(score1, score2)
        else
          local score1 = settings['bad_archive_extensions'][ext] or
              settings['bad_extensions'][ext]
          check_extension(score1, nil)
        end

        if settings['archive_extensions'][ext] then
          -- Archive in archive
          task:insert_result(settings['symbol_archive_in_archive'], 1.0, ext)
        end
      else
        if ext2 then
          check_extension(settings['bad_extensions'][ext],
            settings['bad_extensions'][ext2])
        else
          check_extension(settings['bad_extensions'][ext], nil)
        end
      end

      local mt = settings['extension_map'][ext]
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

          local check = true

          if filename then
            local ext = gen_extension(filename)

            if ext and settings.archive_exceptions[ext] then
              check = false
              logger.debugm("mime_types", task, "skip checking of %s as archive, %s is whitelisted",
                filename, ext)
            end
          end
          local arch = p:get_archive()

          if arch:is_encrypted() then
            task:insert_result(settings['symbol_encrypted_archive'], 1.0, filename)
          end

          if check then
            local fl = arch:get_files_full()

            for _,f in ipairs(fl) do
              -- Strip bad characters
              if f['name'] then
                f['name'] = f['name']:gsub('[\128-\255%s%G]', '?')
              end

              if f['encrypted'] then
                task:insert_result(settings['symbol_encrypted_archive'], 1.0, f['name'])
              end

              if f['name'] then
                check_filename(f['name'], nil, true)
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

  local type = 'map'
  if settings['regexp'] then type = 'regexp' end
  map = rspamd_map_add('mime_types', 'file', type,
    'mime types map')
  if map then
    local id = rspamd_config:register_symbol({
      callback = check_mime_type,
      type = 'callback,nostat'
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
  else
    lua_util.disable_module(N, "config")
  end
end
