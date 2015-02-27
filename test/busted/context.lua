local tablex = require 'pl.tablex'

local function save()
  local g = {}
  for k,_ in next, _G, nil do
    g[k] = rawget(_G, k)
  end
  return {
    gmt = getmetatable(_G),
    g = g,
    loaded = tablex.copy(package.loaded)
  }
end

local function restore(state)
  setmetatable(_G, state.gmt)
  for k,_ in next, _G, nil do
    rawset(_G, k, state.g[k])
  end
  for k,_ in pairs(package.loaded) do
    package.loaded[k] = state.loaded[k]
  end
end

return function()
  local context = {}

  local data = {}
  local parents = {}
  local children = {}
  local stack = {}

  function context.ref()
    local ref = {}
    local ctx = data

    function ref.get(key)
      if not key then return ctx end
      return ctx[key]
    end

    function ref.set(key, value)
      ctx[key] = value
    end

    function ref.clear()
      data = {}
      parents = {}
      children = {}
      stack = {}
      ctx = data
    end

    function ref.attach(child)
      if not children[ctx] then children[ctx] = {} end
      parents[child] = ctx
      table.insert(children[ctx], child)
    end

    function ref.children(parent)
      return children[parent] or {}
    end

    function ref.parent(child)
      return parents[child]
    end

    function ref.push(current)
      if not parents[current] then error('Detached child. Cannot push.') end
      if ctx ~= current and current.descriptor == 'file' then
        current.state = save()
      end
      table.insert(stack, ctx)
      ctx = current
    end

    function ref.pop()
      local current = ctx
      ctx = table.remove(stack)
      if ctx ~= current and current.state then
        restore(current.state)
        current.state = nil
      end
      if not ctx then error('Context stack empty. Cannot pop.') end
    end

    return ref
  end

  return context
end
