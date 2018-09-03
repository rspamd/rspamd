local rspamd_tcp = require "rspamd_tcp"
local lua_util = require "lua_util"

local exports = {}
local N = 'tcp_sync'

local tcp_sync = {_conn = nil, _data = '', _eof = false, _addr = ''}
local metatable = {
  __tostring = function (self)
    return "class {tcp_sync connect to: " .. self._addr .. "}"
  end
}

function tcp_sync.new(connection)
  local self = {}

  for name, method in pairs(tcp_sync) do
    if name ~= 'new' then
      self[name] = method
    end
  end

  self._conn = connection

  setmetatable(self, metatable)

  return self
end

--[[[
-- @method tcp_sync.read_once()
--
-- Acts exactly like low-level tcp_sync.read_once()
-- the only exception is that if there is some pending data,
-- it's returned immediately and no underlying call is performed
--
-- @return
--          true, {data} if everything is fine
--          false, {error message} otherwise
--
--]]
function tcp_sync:read_once()
  local is_ok, data
  if self._data:len() > 0 then
    data = self._data
    self._data = nil
    return true, data
  end

  is_ok, data = self._conn:read_once()

  return is_ok, data
end

--[[[
-- @method tcp_sync.read_until(pattern)
--
-- Reads data from the connection until pattern is found
-- returns all bytes before the pattern
--
-- @param {pattern} Read data until pattern is found
-- @return
--          true, {data} if everything is fine
--          false, {error message} otherwise
-- @example
--
--]]
function tcp_sync:read_until(pattern)
  repeat 
    local pos_start, pos_end = self._data:find(pattern, 1, true)
    if pos_start then
      local data = self._data:sub(1, pos_start - 1)
      self._data = self._data:sub(pos_end + 1)
      return true, data
    end

    local is_ok, more_data = self._conn:read_once()
    if not is_ok then
      return is_ok, more_data
    end

    self._data = self._data .. more_data
  until false
end

--[[[
-- @method tcp_sync.read_bytes(n)
--
-- Reads {n} bytes from the stream
--
-- @param {n} Number of bytes to read
-- @return
--          true, {data} if everything is fine
--          false, {error message} otherwise
--
--]]
function tcp_sync:read_bytes(n)
  repeat
    if self._data:len() >= n then
      local data = self._data:sub(1, n)
      self._data = self._data:sub(n + 1)
      return true, data
    end

    local is_ok, more_data = self._conn:read_once()
    if not is_ok then
      return is_ok, more_data
    end

    self._data = self._data .. more_data
  until false
end

--[[[
-- @method tcp_sync.read_until_eof(n)
--
-- Reads stream until EOF is reached
--
-- @return
--          true, {data} if everything is fine
--          false, {error message} otherwise
--
--]]
function tcp_sync:read_until_eof()
  while not self:eof() do
    local is_ok, more_data = self._conn:read_once()
    if not is_ok then
      if self:eof() then
        -- this error is EOF (connection terminated)
        -- exactly what we were waiting for
        break
      end
      return is_ok, more_data
    end
    self._data = self._data .. more_data
  end

  local data = self._data
  self._data = ''
  return true, data
end

--[[[
-- @method tcp_sync.write(n)
--
-- Writes data into the stream.
--
-- @return
--          true if everything is fine
--          false, {error message} otherwise
--
--]]
function tcp_sync:write(data)
  return self._conn:write(data)
end

--[[[
-- @method tcp_sync.close()
--
-- Closes the connection. If the connection was created with task,
-- this method is called automatically as soon as the task is done
-- Calling this method helps to prevent connections leak.
-- The object is finally destroyed by garbage collector.
--
-- @return
--
--]]
function tcp_sync:close()
  return self._conn:close()
end

--[[[
-- @method tcp_sync.eof()
--
-- @return
--          true if last "read" operation ended with EOF
--          false otherwise
--
--]]
function tcp_sync:eof()
  if not self._eof and self._conn:eof() then
    self._eof = true
  end
  return self._eof
end

--[[[
-- @function tcp_sync.shutdown(n)
--
-- half-close socket
--
-- @return
--
--]]
function tcp_sync:shutdown()
  return self._conn:shutdown()
end

exports.connect = function (args)
  local is_ok, connection = rspamd_tcp.connect_sync(args)
  if not is_ok then
    return is_ok, connection
  end

  local instance = tcp_sync.new(connection)
  instance._addr = string.format("%s:%s", tostring(args.host), tostring(args.port))

  lua_util.debugm(N, args.task, 'Connected to %s', instance._addr)

  return true, instance
end

return exports