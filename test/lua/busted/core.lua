local getfenv = require 'busted.compatibility'.getfenv
local setfenv = require 'busted.compatibility'.setfenv
local unpack = require 'busted.compatibility'.unpack
local path = require 'pl.path'
local pretty = require 'pl.pretty'
local throw = error

local failureMt = {
  __index = {},
  __tostring = function(e) return tostring(e.message) end,
  __type = 'failure'
}

local failureMtNoString = {
  __index = {},
  __type = 'failure'
}

local pendingMt = {
  __index = {},
  __tostring = function(p) return p.message end,
  __type = 'pending'
}

local function metatype(obj)
  local otype = type(obj)
  return otype == 'table' and (getmetatable(obj) or {}).__type or otype
end

local function hasToString(obj)
  return type(obj) == 'string' or (getmetatable(obj) or {}).__tostring
end

return function()
  local mediator = require 'mediator'()

  local busted = {}
  busted.version = '2.0.rc6-0'

  local root = require 'busted.context'()
  busted.context = root.ref()

  local environment = require 'busted.environment'(busted.context)
  busted.environment = {
    set = environment.set,

    wrap = function(callable)
      if (type(callable) == 'function' or getmetatable(callable).__call) then
        -- prioritize __call if it exists, like in files
        environment.wrap((getmetatable(callable) or {}).__call or callable)
      end
    end
  }

  busted.executors = {}
  local executors = {}

  busted.status = require 'busted.status'

  function busted.getTrace(element, level, msg)
    level = level or  3

    local thisdir = path.dirname(debug.getinfo(1, 'Sl').source)
    local info = debug.getinfo(level, 'Sl')
    while info.what == 'C' or info.short_src:match('luassert[/\\].*%.lua$') or
          (info.source:sub(1,1) == '@' and thisdir == path.dirname(info.source)) do
      level = level + 1
      info = debug.getinfo(level, 'Sl')
    end

    info.traceback = debug.traceback('', level)
    info.message = msg

    local file = busted.getFile(element)
    return file.getTrace(file.name, info)
  end

  function busted.rewriteMessage(element, message, trace)
    local file = busted.getFile(element)
    local msg = hasToString(message) and tostring(message)
    msg = msg or (message ~= nil and pretty.write(message) or 'Nil error')
    msg = (file.rewriteMessage and file.rewriteMessage(file.name, msg) or msg)

    local hasFileLine = msg:match('^[^\n]-:%d+: .*')
    if not hasFileLine then
      local trace = trace or busted.getTrace(element, 3, message)
      local fileline = trace.short_src .. ':' .. trace.currentline .. ': '
      msg = fileline .. msg
    end

    return msg
  end

  function busted.publish(...)
    return mediator:publish(...)
  end

  function busted.subscribe(...)
    return mediator:subscribe(...)
  end

  function busted.getFile(element)
    local parent = busted.context.parent(element)

    while parent do
      if parent.file then
        local file = parent.file[1]
        return {
          name = file.name,
          getTrace = file.run.getTrace,
          rewriteMessage = file.run.rewriteMessage
        }
      end

      if parent.descriptor == 'file' then
        return {
          name = parent.name,
          getTrace = parent.run.getTrace,
          rewriteMessage = parent.run.rewriteMessage
        }
      end

      parent = busted.context.parent(parent)
    end

    return parent
  end

  function busted.fail(msg, level)
    local rawlevel = (type(level) ~= 'number' or level <= 0) and level
    local level = level or 1
    local _, emsg = pcall(throw, msg, rawlevel or level+2)
    local e = { message = emsg }
    setmetatable(e, hasToString(msg) and failureMt or failureMtNoString)
    throw(e, rawlevel or level+1)
  end

  function busted.pending(msg)
    local p = { message = msg }
    setmetatable(p, pendingMt)
    throw(p)
  end

  function busted.replaceErrorWithFail(callable)
    local env = {}
    local f = (getmetatable(callable) or {}).__call or callable
    setmetatable(env, { __index = getfenv(f) })
    env.error = busted.fail
    setfenv(f, env)
  end

  function busted.safe(descriptor, run, element)
    busted.context.push(element)
    local trace, message
    local status = 'success'

    local ret = { xpcall(run, function(msg)
      local errType = metatype(msg)
      status = ((errType == 'pending' or errType == 'failure') and errType or 'error')
      trace = busted.getTrace(element, 3, msg)
      message = busted.rewriteMessage(element, msg, trace)
    end) }

    if not ret[1] then
      busted.publish({ status, descriptor }, element, busted.context.parent(element), message, trace)
    end
    ret[1] = busted.status(status)

    busted.context.pop()
    return unpack(ret)
  end

  function busted.register(descriptor, executor)
    executors[descriptor] = executor

    local publisher = function(name, fn)
      if not fn and type(name) == 'function' then
        fn = name
        name = nil
      end

      local trace

      local ctx = busted.context.get()
      if busted.context.parent(ctx) then
        trace = busted.getTrace(ctx, 3, name)
      end

      local publish = function(f)
        busted.publish({ 'register', descriptor }, name, f, trace)
      end

      if fn then publish(fn) else return publish end
    end

    busted.executors[descriptor] = publisher
    if descriptor ~= 'file' then
      environment.set(descriptor, publisher)
    end

    busted.subscribe({ 'register', descriptor }, function(name, fn, trace)
      local ctx = busted.context.get()
      local plugin = {
        descriptor = descriptor,
        name = name,
        run = fn,
        trace = trace
      }

      busted.context.attach(plugin)

      if not ctx[descriptor] then
        ctx[descriptor] = { plugin }
      else
        ctx[descriptor][#ctx[descriptor]+1] = plugin
      end
    end)
  end

  function busted.alias(alias, descriptor)
    local publisher = busted.executors[descriptor]
    busted.executors[alias] = publisher
    environment.set(alias, publisher)
  end

  function busted.execute(current)
    if not current then current = busted.context.get() end
    for _, v in pairs(busted.context.children(current)) do
      local executor = executors[v.descriptor]
      if executor and not busted.skipAll then
        busted.safe(v.descriptor, function() executor(v) end, v)
      end
    end
  end

  return busted
end
