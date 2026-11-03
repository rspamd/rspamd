-- Check symbol lifetime across two asynchronous writes scheduled from callbacks.
-- Omit mode and timeout in both calls to exercise their defaults in a worker.
local tmpmask = assert(os.getenv('RSPAMD_TMPDIR')) .. '/async-file-XXXXXX'

local id = rspamd_config:register_symbol {
  name = 'ASYNC_FILE_WRITE',
  type = 'normal',
  callback = function(task)
    local content = tostring(task:get_content())
    local function fail(err)
      task:insert_result('ASYNC_FILE_ERROR', 1.0, tostring(err))
    end
    local function check_file(err, filename)
      if err then
        fail(err)
        return false
      end
      local f, open_err = io.open(filename, 'rb')
      if not f then
        fail(open_err)
        return false
      end
      local data = f:read('*a')
      f:close()
      if data ~= content then
        fail('incomplete file')
        return false
      end
      return true
    end
    local ok, err = task:store_in_file_async({
      force_new = true,
      tmpmask = tmpmask,
    }, function(write_err, filename)
      if not check_file(write_err, filename) then
        return
      end
      task:insert_result('ASYNC_FILE_FIRST', 1.0)
      local next_ok, next_err = task:store_in_file_async({
        force_new = true,
        tmpmask = tmpmask,
      }, function(second_err, second_filename)
        if check_file(second_err, second_filename) then
          task:insert_result('ASYNC_FILE_SECOND', 1.0)
        end
      end)
      if not next_ok then
        fail(next_err)
      end
    end)
    if not ok then
      fail(err)
    end
  end,
}

for _, name in ipairs {'ASYNC_FILE_FIRST', 'ASYNC_FILE_SECOND', 'ASYNC_FILE_ERROR'} do
  rspamd_config:register_symbol {
    name = name,
    type = 'virtual',
    parent = id,
  }
end

rspamd_config:register_symbol {
  name = 'ASYNC_FILE_AFTER',
  type = 'normal',
  callback = function(task)
    if task:has_symbol('ASYNC_FILE_FIRST') and task:has_symbol('ASYNC_FILE_SECOND') then
      task:insert_result('ASYNC_FILE_AFTER', 1.0)
    end
  end,
}
rspamd_config:register_dependency('ASYNC_FILE_AFTER', 'ASYNC_FILE_WRITE')
