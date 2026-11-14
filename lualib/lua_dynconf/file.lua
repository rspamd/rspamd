--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>

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

--[[[
-- @module lua_dynconf.file
-- File backend for lua_dynconf: the overrides live in one small JSON file, by default
-- `$DBDIR/rspamd_dynconf.json`:
--
--   {"v": <global version>, "modules": {"<module>": {"v": <module version>, "o": { ...override table... }}}}
--
-- The file is read by every worker from its periodic (or from the on-access trigger): a check is one
-- `stat`, and the file is read and parsed only when its modification time or size has changed. A missing
-- file means "no overrides". The backend is synchronous (`sync = true`): it never waits for anything but
-- the local file system, so it can also be used offline (`rspamadm configdump --dynamic`).
--
-- Only the controller writes. A write re-reads the file under an advisory lock (`<path>.lock`), changes
-- one module and replaces the file atomically (temporary file in the same directory, then `rename`), so
-- that concurrent controllers never lose each other's changes and readers never see a partial file.
-- There is no `fsync` binding in Lua: the data is flushed to the operating system, but a power loss right
-- after a write can lose it.
--]]

local lua_util = require "lua_util"
local logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local json = require "lua_dynconf.json"
local ucl = require "ucl"

local exports = {}

-- The file is read by whole: a limit keeps a wrong `path` from being slurped into memory
local DEFAULT_MAX_SIZE = 8 * 1024 * 1024
-- 0644 (Lua has no octal literals)
local FILE_MODE = 420
local ENOENT = 2
-- mtime has a granularity of one second: a file that was read less than this long after its last
-- modification can still be changed within the same second without changing the signature
local MTIME_GRANULARITY = 2

local path
local max_size = DEFAULT_MAX_SIZE

-- State of the last check: signature of the file (`none` when it does not exist), the time it was read,
-- the global version and the module entries that have been delivered to the registry
local last_sig
local last_read
local last_version = 0
local applied = {}

local function get_time()
  return rspamd_util.get_time()
end

local function reset_state()
  last_sig = nil
  last_read = nil
  last_version = 0
  applied = {}
end

--[[[
-- @function lua_dynconf.file.configure(section)
-- Parses the `dynconf` section: `path` (default `$DBDIR/rspamd_dynconf.json`) and `max_size`
-- @return {boolean} true or `false, error`
--]]
function exports.configure(section)
  section = section or {}
  reset_state()

  if section.path ~= nil then
    if type(section.path) ~= 'string' or section.path == '' then
      return false, 'path must be a non-empty string'
    end
    path = section.path
  else
    local dbdir = rspamd_paths and rspamd_paths.DBDIR
    if type(dbdir) ~= 'string' or dbdir == '' then
      return false, 'cannot find the database directory, set `path` explicitly'
    end
    path = dbdir .. '/rspamd_dynconf.json'
  end

  max_size = DEFAULT_MAX_SIZE
  if section.max_size ~= nil then
    local sz = tonumber(section.max_size)
    if not sz or sz <= 0 then
      return false, 'max_size must be a positive number'
    end
    max_size = sz
  end

  return true
end

--[[[
-- @function lua_dynconf.file.path()
-- Returns the path of the override file
--]]
function exports.path()
  return path
end

--[[[
-- @function lua_dynconf.file.start(cfg, ev_base, worker)
-- Called in every worker after fork: the next check reads the file unconditionally
--]]
function exports.start(_, _, _)
  reset_state()
end

--[[[
-- @function lua_dynconf.file.version()
-- Returns the last seen global version
--]]
function exports.version()
  return last_version
end

-- The backend never blocks on anything but the local file system
exports.sync = true

-- Reads and parses the file. Returns the decoded document, or `nil, error`; a missing file is an empty
-- document. The second value is true for a file that exists but has no content at all
local function read_document()
  local f, err, errno = io.open(path, 'rb')
  if not f then
    if errno == ENOENT then
      return { v = 0, modules = {} }
    end
    return nil, string.format('cannot open %s: %s', path, err)
  end

  local data = f:read(max_size + 1)
  f:close()
  if data == nil then
    data = ''
  end
  if #data > max_size then
    return nil, string.format('%s is larger than %d bytes', path, max_size)
  end

  local doc = { v = 0, modules = {} }
  local empty = not data:find('%S')
  if not empty then
    local parser = ucl.parser()
    local ok, perr = parser:parse_text(data)
    if not ok then
      return nil, string.format('cannot parse %s: %s', path, perr)
    end
    local obj = parser:get_object()
    -- The UCL parser is lenient: make sure that this is our document and not a text that happens to parse
    if type(obj) ~= 'table' or (type(obj.modules) ~= 'table' and next(obj) ~= nil) then
      return nil, string.format('%s: unexpected content, a JSON object with `modules` is expected', path)
    end
    doc.v = tonumber(obj.v) or 0
    doc.modules = obj.modules or {}
  end

  return doc, empty
end

-- Compares the document with what has been delivered. Returns `updates` (or nil) and the new applied map
local function process_document(doc)
  local updates = {}
  local new_applied = {}
  local any = false

  for module, entry in pairs(doc.modules) do
    if type(entry) ~= 'table' or type(entry.o) ~= 'table' then
      -- A broken entry must not look like a removed override
      logger.warnx(rspamd_config, 'dynconf: invalid override for module %s in %s', module, path)
      new_applied[module] = applied[module]
    else
      new_applied[module] = entry
      local prev = applied[module]
      if not prev or not lua_util.table_cmp(prev, entry) then
        updates[module] = { version = tonumber(entry.v) or 0, values = entry.o }
        any = true
      end
    end
  end

  -- Overrides that have vanished from the file must be removed
  for module in pairs(applied) do
    if doc.modules[module] == nil then
      updates[module] = false
      any = true
    end
  end

  return any and updates or nil, new_applied
end

--[[[
-- @function lua_dynconf.file.check(ev_base, cb)
-- Compares the signature of the file with the last seen one and reads it if it has changed.
-- `cb(err, updates, commit)` is called before `check` returns.
--]]
function exports.check(_, cb)
  if not path then
    cb('file backend is not configured')
    return
  end

  -- A failure that cannot be fixed by a retry is reported once and then not until something changes
  -- (the signature has the error in it), not by every probe of every worker
  local function fail(sig, msg)
    if sig == last_sig then
      cb(nil, nil)
      return
    end
    last_sig, last_read = sig, get_time()
    cb(msg)
  end

  local sig
  local mtime
  local serr, st = rspamd_util.stat(path)
  if serr then
    -- The only error that means "no overrides" is a missing file
    local f, ferr, errno = io.open(path, 'rb')
    if f then
      -- It has just appeared: the next check reads it
      f:close()
      cb(nil, nil)
      return
    end
    if errno ~= ENOENT then
      fail(string.format('err:%s', tostring(errno or ferr or serr)),
          string.format('cannot access %s: %s', path, ferr or serr))
      return
    end
    sig = 'none'
  else
    if st.type ~= 'regular' then
      fail(string.format('type:%s:%d', tostring(st.type), st.mtime or 0),
          string.format('%s is not a regular file', path))
      return
    end
    mtime = st.mtime
    sig = string.format('%d:%d', st.mtime, st.size)
    if st.size > max_size then
      last_sig, last_read = sig, get_time()
      cb(string.format('%s is larger than %d bytes', path, max_size))
      return
    end
  end

  -- An unchanged signature is trusted only if the file was read long enough after its modification
  if sig == last_sig and (not mtime or (last_read and last_read - mtime >= MTIME_GRANULARITY)) then
    cb(nil, nil)
    return
  end

  local now = get_time()
  local doc, rerr_or_empty = read_document()
  if not doc then
    -- Do not read (and complain about) a broken file again until it changes
    last_sig, last_read = sig, now
    cb(rerr_or_empty)
    return
  end
  if rerr_or_empty and next(applied) ~= nil then
    -- Nothing but a damaged or truncated file looks like this: set() never writes it. The overrides go
    -- away (an empty file is a valid "no overrides"), so at least say so
    logger.warnx(rspamd_config, 'dynconf: %s is empty, all the overrides are removed', path)
  end

  local updates, new_applied = process_document(doc)
  cb(nil, updates, function()
    last_sig, last_read = sig, now
    last_version = doc.v
    applied = new_applied
  end)
end

-- Takes the advisory lock that serialises writers; returns the descriptor or `nil, error`
local function lock_writers()
  local lock_path = path .. '.lock'
  local fd, err = rspamd_util.create_file(lock_path, FILE_MODE)
  if not fd then
    return nil, string.format('cannot create %s: %s', lock_path, err)
  end
  local lfd, lerr = rspamd_util.lock_file(lock_path, fd)
  if not lfd then
    rspamd_util.close_file(fd)
    return nil, string.format('cannot lock %s: %s', lock_path, lerr)
  end
  return lfd
end

-- Writes `content` to `path` through a temporary file in the same directory
local function replace_file(content)
  local tmp = path .. '.tmp'
  -- Create it with the mode of the legacy dump first, `io.open` keeps the mode of an existing file
  local fd, cerr = rspamd_util.create_file(tmp, FILE_MODE)
  if not fd then
    return false, string.format('cannot create %s: %s', tmp, cerr)
  end
  rspamd_util.close_file(fd)

  local f, oerr = io.open(tmp, 'wb')
  if not f then
    os.remove(tmp)
    return false, string.format('cannot open %s: %s', tmp, oerr)
  end
  local wok, werr = f:write(content)
  local cok, clerr = f:close()
  if not wok or not cok then
    os.remove(tmp)
    return false, string.format('cannot write %s: %s', tmp, werr or clerr)
  end

  local rok, rerr = os.rename(tmp, path)
  if not rok then
    os.remove(tmp)
    return false, string.format('cannot rename %s to %s: %s', tmp, path, rerr)
  end
  return true
end

-- Stores `values` (nil removes the entry) as the override of a module into the document that has just been
-- read under the lock, and replaces the file. Returns the new global version, or `nil, error`
local function store(doc, module, values)
  local version = doc.v + 1
  local new_modules = {}
  for name, entry in pairs(doc.modules) do
    new_modules[name] = entry
  end
  if values ~= nil then
    new_modules[module] = { v = version, o = values }
  else
    new_modules[module] = nil
  end

  local content, eerr = json.encode({ v = version, modules = new_modules })
  if not content then
    return nil, string.format('cannot encode the override: %s', eerr)
  end
  local ok, werr = replace_file(content)
  if not ok then
    return nil, werr
  end

  -- Remember what was written, so that this worker does not apply it again
  if values ~= nil then
    applied[module] = { v = version, o = lua_util.deepcopy(values) }
  else
    applied[module] = nil
  end
  return version
end

--[[[
-- @function lua_dynconf.file.set(ctx, module, values, cb)
-- Stores (or removes, when `values` is nil) the override of a module. The file is re-read under a lock
-- and replaced atomically, so the other modules keep whatever has been written by others in the meantime.
-- `cb(err, version)` is called before `set` returns; `ctx` is not used.
--]]
function exports.set(_, module, values, cb)
  if not path then
    cb('file backend is not configured')
    return
  end

  local lfd, lerr = lock_writers()
  if not lfd then
    cb(lerr)
    return
  end

  local doc, rerr = read_document()
  local version, serr
  if not doc then
    -- Overwriting a file that cannot be understood would lose its overrides silently
    serr = rerr
  else
    version, serr = store(doc, module, values)
  end
  rspamd_util.unlock_file(lfd)
  cb(serr, version)
end

--[[[
-- @function lua_dynconf.file.update(ctx, module, patch, prepare, cb)
-- Changes some top-level keys of the override of a module: `patch` maps a key to its new value, or to
-- `false` to remove the key. The override is merged with what the file holds right now (under the lock),
-- not with what this worker has applied, so that nothing that has not been applied (or has been written
-- by somebody else) is lost. `prepare(merged)` is called with the result (nil when no key is left) before
-- anything is written and returns `ok, error`: a refusal stops the update.
-- `cb(err, version, rejected)` is called before `update` returns; `rejected` is true if `prepare` refused.
--]]
function exports.update(_, module, patch, prepare, cb)
  if not path then
    cb('file backend is not configured')
    return
  end

  local lfd, lerr = lock_writers()
  if not lfd then
    cb(lerr)
    return
  end

  local doc, rerr = read_document()
  if not doc then
    rspamd_util.unlock_file(lfd)
    cb(rerr)
    return
  end

  local entry = doc.modules[module]
  local values = {}
  if type(entry) == 'table' and type(entry.o) == 'table' then
    values = lua_util.deepcopy(entry.o)
  end
  for k, v in pairs(patch) do
    if v == false then
      values[k] = nil
    else
      values[k] = v
    end
  end
  if next(values) == nil then
    values = nil
  end

  -- The lock must be released whatever `prepare` does
  local called, pok, perr = pcall(prepare, values)
  if not called or not pok then
    rspamd_util.unlock_file(lfd)
    cb(called and tostring(perr or 'rejected') or tostring(pok), nil, true)
    return
  end

  local version, serr = store(doc, module, values)
  rspamd_util.unlock_file(lfd)
  cb(serr, version)
end

--[[[
-- @function lua_dynconf.file.holds(module)
-- Returns true if the last document delivered to the registry holds an override for the module (whether or
-- not the registry has accepted it)
--]]
function exports.holds(module)
  return applied[module] ~= nil
end

return exports
