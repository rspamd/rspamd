local rspamd_regexp = require "rspamd_regexp"
local lua_maps = require "lua_maps"

local clickbait_map = lua_maps.map_add_from_ucl(
    {
      string.format('%s/maps.d/%s', rspamd_paths.CONFDIR, 'exe_clickbait.inc'),
      string.format('%s/local.d/maps.d/%s', rspamd_paths.LOCAL_CONFDIR, 'exe_clickbait.inc')
    },
    'regexp',
    'Inappropriate descriptions for executables'
)

local exe_re = rspamd_regexp.create_cached([[/\.exe$|\.com$/i]])
local img_re = rspamd_regexp.create_cached([[/\.img$/i]])
local rar_re = rspamd_regexp.create_cached([[/\.rar$|\.r[0-9]{2}$/i]])

local id = rspamd_config:register_symbol {
  callback = function(task)
    local num_checked = 0
    local have_subject_clickbait = false

    if clickbait_map:get_key(task:get_subject()) then
      have_subject_clickbait = true
    end

    for _, p in ipairs(task:get_parts()) do
      local clickbait, exe, misidentified_rar = false, false, false

      if p:is_archive() then
        num_checked = num_checked + 1
        local arc = p:get_archive()
        local fn = p:get_filename()

        if clickbait_map:get_key(fn) ~= false then
          clickbait = true
        end

        if arc:get_type() == 'rar' then
          if fn then
            if not rar_re:match(fn) then
              task:insert_result('MISIDENTIFIED_RAR', 1.0)
              misidentified_rar = true
            end
          end
        end

        local files = arc:get_files_full()
        local max_check = math.min(#files, 10)

        for i = 1, max_check do
          local info = files[i]
          local name = info.name

          if img_re:match(name) then
            local ratio = info.uncompressed_size / info.compressed_size
            if ratio >= 500 then
              task:insert_result('UDF_COMPRESSION_500PLUS', 1.0)
            end
          elseif exe_re:match(name) then
            exe = true
            task:insert_result('EXE_IN_ARCHIVE', 1.0)
            if misidentified_rar then
              task:insert_result('EXE_IN_MISIDENTIFIED_RAR', 1.0)
            end
            if clickbait then
              task:insert_result('EXE_ARCHIVE_CLICKBAIT_FILENAME', 1.0)
            elseif have_subject_clickbait then
              task:insert_result('EXE_ARCHIVE_CLICKBAIT_SUBJECT', 1.0)
            end
          end
        end

        if exe then
          if #files == 1 then
            task:insert_result('SINGLE_FILE_ARCHIVE_WITH_EXE', 1.0)
          end
        end

        if num_checked >= 10 then
          return
        end
      end
    end
  end,
  name = 'CHECK_ARCHIVES',
  type = 'callback',
}

rspamd_config:register_symbol {
  description = 'exe file in archive with clickbait filename',
  group = 'malware',
  name = 'EXE_ARCHIVE_CLICKBAIT_FILENAME',
  one_shot = true,
  parent = id,
  score = 9.0,
  type = 'virtual',
}

rspamd_config:register_symbol {
  description = 'exe file in archive with clickbait subject',
  group = 'malware',
  name = 'EXE_ARCHIVE_CLICKBAIT_SUBJECT',
  one_shot = true,
  parent = id,
  score = 9.0,
  type = 'virtual',
}

rspamd_config:register_symbol {
  description = 'exe file in archive',
  group = 'malware',
  name = 'EXE_IN_ARCHIVE',
  one_shot = true,
  parent = id,
  score = 1.5,
  type = 'virtual',
}

rspamd_config:register_symbol {
  description = 'rar with wrong extension containing exe file',
  group = 'malware',
  name = 'EXE_IN_MISIDENTIFIED_RAR',
  one_shot = true,
  parent = id,
  score = 5.0,
  type = 'virtual',
}

rspamd_config:register_symbol {
  description = 'rar with wrong extension',
  group = 'malware',
  name = 'MISIDENTIFIED_RAR',
  one_shot = true,
  parent = id,
  score = 4.0,
  type = 'virtual',
}

rspamd_config:register_symbol {
  description = 'single file container bearing executable',
  group = 'malware',
  name = 'SINGLE_FILE_ARCHIVE_WITH_EXE',
  one_shot = true,
  parent = id,
  score = 5.0,
  type = 'virtual',
}

rspamd_config:register_symbol {
  description = 'very well compressed img file in archive',
  name = 'UDF_COMPRESSION_500PLUS',
  one_shot = true,
  parent = id,
  score = 9.0,
  type = 'virtual',
}
