local OptionalType, TaggedType, types, is_type
local BaseType, TransformNode, SequenceNode, FirstOfNode, DescribeNode, NotType, Literal
local FailedTransform = { }
local unpack = unpack or table.unpack
local clone_state
clone_state = function(state_obj)
  if type(state_obj) ~= "table" then
    return { }
  end
  local out
  do
    local _tbl_0 = { }
    for k, v in pairs(state_obj) do
      _tbl_0[k] = v
    end
    out = _tbl_0
  end
  do
    local mt = getmetatable(state_obj)
    if mt then
      setmetatable(out, mt)
    end
  end
  return out
end
local describe_type
describe_type = function(val)
  if type(val) == "string" then
    if not val:match('"') then
      return "\"" .. tostring(val) .. "\""
    elseif not val:match("'") then
      return "'" .. tostring(val) .. "'"
    else
      return "`" .. tostring(val) .. "`"
    end
  elseif BaseType:is_base_type(val) then
    return val:_describe()
  else
    return tostring(val)
  end
end
local coerce_literal
coerce_literal = function(value)
  local _exp_0 = type(value)
  if "string" == _exp_0 or "number" == _exp_0 or "boolean" == _exp_0 then
    return Literal(value)
  elseif "table" == _exp_0 then
    if BaseType:is_base_type(value) then
      return value
    end
  end
  return nil, "failed to coerce literal into type, use types.literal() to test for literal value"
end
local join_names
join_names = function(items, sep, last_sep)
  if sep == nil then
    sep = ", "
  end
  local count = #items
  local chunks = { }
  for idx, name in ipairs(items) do
    if idx > 1 then
      local current_sep
      if idx == count then
        current_sep = last_sep or sep
      else
        current_sep = sep
      end
      table.insert(chunks, current_sep)
    end
    table.insert(chunks, name)
  end
  return table.concat(chunks)
end
do
  local _class_0
  local _base_0 = {
    __div = function(self, fn)
      return TransformNode(self, fn)
    end,
    __mod = function(self, fn)
      do
        local _with_0 = TransformNode(self, fn)
        _with_0.with_state = true
        return _with_0
      end
    end,
    __mul = function(_left, _right)
      local left, err = coerce_literal(_left)
      if not (left) then
        error("left hand side of multiplication: " .. tostring(_left) .. ": " .. tostring(err))
      end
      local right
      right, err = coerce_literal(_right)
      if not (right) then
        error("right hand side of multiplication: " .. tostring(_right) .. ": " .. tostring(err))
      end
      return SequenceNode(left, right)
    end,
    __add = function(_left, _right)
      local left, err = coerce_literal(_left)
      if not (left) then
        error("left hand side of addition: " .. tostring(_left) .. ": " .. tostring(err))
      end
      local right
      right, err = coerce_literal(_right)
      if not (right) then
        error("right hand side of addition: " .. tostring(_right) .. ": " .. tostring(err))
      end
      if left.__class == FirstOfNode then
        local options = {
          unpack(left.options)
        }
        table.insert(options, right)
        return FirstOfNode(unpack(options))
      elseif right.__class == FirstOfNode then
        return FirstOfNode(left, unpack(right.options))
      else
        return FirstOfNode(left, right)
      end
    end,
    __unm = function(self, right)
      return NotType(right)
    end,
    __tostring = function(self)
      return self:_describe()
    end,
    _describe = function(self)
      return error("Node missing _describe: " .. tostring(self.__class.__name))
    end,
    check_value = function(self, ...)
      local value, state_or_err = self:_transform(...)
      if value == FailedTransform then
        return nil, state_or_err
      end
      if type(state_or_err) == "table" then
        return state_or_err
      else
        return true
      end
    end,
    transform = function(self, ...)
      local value, state_or_err = self:_transform(...)
      if value == FailedTransform then
        return nil, state_or_err
      end
      if type(state_or_err) == "table" then
        return value, state_or_err
      else
        return value
      end
    end,
    repair = function(self, ...)
      return self:transform(...)
    end,
    on_repair = function(self, fn)
      return (self + types.any / fn * self):describe(function()
        return self:_describe()
      end)
    end,
    is_optional = function(self)
      return OptionalType(self)
    end,
    describe = function(self, ...)
      return DescribeNode(self, ...)
    end,
    tag = function(self, name)
      return TaggedType(self, {
        tag = name
      })
    end,
    clone_opts = function(self)
      return error("clone_opts is not longer supported")
    end,
    __call = function(self, ...)
      return self:check_value(...)
    end
  }
  _base_0.__index = _base_0
  _class_0 = setmetatable({
    __init = function(self, opts) end,
    __base = _base_0,
    __name = "BaseType"
  }, {
    __index = _base_0,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  local self = _class_0
  self.is_base_type = function(self, val)
    do
      local mt = type(val) == "table" and getmetatable(val)
      if mt then
        if mt.__class then
          return mt.__class.is_base_type == BaseType.is_base_type
        end
      end
    end
    return false
  end
  self.__inherited = function(self, cls)
    cls.__base.__call = cls.__call
    cls.__base.__div = self.__div
    cls.__base.__mod = self.__mod
    cls.__base.__mul = self.__mul
    cls.__base.__add = self.__add
    cls.__base.__unm = self.__unm
    cls.__base.__tostring = self.__tostring
  end
  BaseType = _class_0
end
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    _describe = function(self)
      return self.node:_describe()
    end,
    _transform = function(self, value, state)
      local state_or_err
      value, state_or_err = self.node:_transform(value, state)
      if value == FailedTransform then
        return FailedTransform, state_or_err
      else
        local out
        local _exp_0 = type(self.t_fn)
        if "function" == _exp_0 then
          if self.with_state then
            out = self.t_fn(value, state_or_err)
          else
            out = self.t_fn(value)
          end
        else
          out = self.t_fn
        end
        return out, state_or_err
      end
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, node, t_fn)
      self.node, self.t_fn = node, t_fn
      return assert(self.node, "missing node for transform")
    end,
    __base = _base_0,
    __name = "TransformNode",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  TransformNode = _class_0
end
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    _describe = function(self)
      local item_names
      do
        local _accum_0 = { }
        local _len_0 = 1
        local _list_0 = self.sequence
        for _index_0 = 1, #_list_0 do
          local i = _list_0[_index_0]
          _accum_0[_len_0] = describe_type(i)
          _len_0 = _len_0 + 1
        end
        item_names = _accum_0
      end
      return join_names(item_names, " then ")
    end,
    _transform = function(self, value, state)
      local _list_0 = self.sequence
      for _index_0 = 1, #_list_0 do
        local node = _list_0[_index_0]
        value, state = node:_transform(value, state)
        if value == FailedTransform then
          break
        end
      end
      return value, state
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, ...)
      self.sequence = {
        ...
      }
    end,
    __base = _base_0,
    __name = "SequenceNode",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  SequenceNode = _class_0
end
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    _describe = function(self)
      local item_names
      do
        local _accum_0 = { }
        local _len_0 = 1
        local _list_0 = self.options
        for _index_0 = 1, #_list_0 do
          local i = _list_0[_index_0]
          _accum_0[_len_0] = describe_type(i)
          _len_0 = _len_0 + 1
        end
        item_names = _accum_0
      end
      return join_names(item_names, ", ", ", or ")
    end,
    _transform = function(self, value, state)
      if not (self.options[1]) then
        return FailedTransform, "no options for node"
      end
      local _list_0 = self.options
      for _index_0 = 1, #_list_0 do
        local node = _list_0[_index_0]
        local new_val, new_state = node:_transform(value, state)
        if not (new_val == FailedTransform) then
          return new_val, new_state
        end
      end
      return FailedTransform, "expected " .. tostring(self:_describe())
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, ...)
      self.options = {
        ...
      }
    end,
    __base = _base_0,
    __name = "FirstOfNode",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  FirstOfNode = _class_0
end
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    _transform = function(self, input, ...)
      local value, state = self.node:_transform(input, ...)
      if value == FailedTransform then
        local err
        if self.err_handler then
          err = self.err_handler(input, state)
        else
          err = "expected " .. tostring(self:_describe())
        end
        return FailedTransform, err
      end
      return value, state
    end,
    describe = function(self, ...)
      return DescribeNode(self.node, ...)
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, node, describe)
      self.node = node
      local err_message
      if type(describe) == "table" then
        describe, err_message = describe.type, describe.error
      end
      if type(describe) == "string" then
        self._describe = function()
          return describe
        end
      else
        self._describe = describe
      end
      if err_message then
        if type(err_message) == "string" then
          self.err_handler = function()
            return err_message
          end
        else
          self.err_handler = err_message
        end
      end
    end,
    __base = _base_0,
    __name = "DescribeNode",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  DescribeNode = _class_0
end
local AnnotateNode
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    format_error = function(self, value, err)
      return tostring(tostring(value)) .. ": " .. tostring(err)
    end,
    _transform = function(self, value, state)
      local new_value, state_or_err = self.base_type:_transform(value, state)
      if new_value == FailedTransform then
        return FailedTransform, self:format_error(value, state_or_err)
      else
        return new_value, state_or_err
      end
    end,
    _describe = function(self)
      if self.base_type._describe then
        return self.base_type:_describe()
      end
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, base_type, opts)
      self.base_type = assert(coerce_literal(base_type))
      if opts then
        if opts.format_error then
          self.format_error = assert(types.func:transform(opts.format_error))
        end
      end
    end,
    __base = _base_0,
    __name = "AnnotateNode",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  AnnotateNode = _class_0
end
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    update_state = function(self, state, value, ...)
      local out = clone_state(state)
      if self.tag_type == "function" then
        if select("#", ...) > 0 then
          self.tag_name(out, ..., value)
        else
          self.tag_name(out, value)
        end
      else
        if self.tag_array then
          local existing = out[self.tag_name]
          if type(existing) == "table" then
            local copy
            do
              local _tbl_0 = { }
              for k, v in pairs(existing) do
                _tbl_0[k] = v
              end
              copy = _tbl_0
            end
            table.insert(copy, value)
            out[self.tag_name] = copy
          else
            out[self.tag_name] = {
              value
            }
          end
        else
          out[self.tag_name] = value
        end
      end
      return out
    end,
    _transform = function(self, value, state)
      value, state = self.base_type:_transform(value, state)
      if value == FailedTransform then
        return FailedTransform, state
      end
      state = self:update_state(state, value)
      return value, state
    end,
    _describe = function(self)
      local base_description = self.base_type:_describe()
      return tostring(base_description) .. " tagged " .. tostring(describe_type(self.tag_name))
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, base_type, opts)
      if opts == nil then
        opts = { }
      end
      self.base_type = base_type
      self.tag_name = assert(opts.tag, "tagged type missing tag")
      self.tag_type = type(self.tag_name)
      if self.tag_type == "string" then
        if self.tag_name:match("%[%]$") then
          self.tag_name = self.tag_name:sub(1, -3)
          self.tag_array = true
        end
      end
    end,
    __base = _base_0,
    __name = "TaggedType",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  TaggedType = _class_0
end
local TagScopeType
do
  local _class_0
  local _parent_0 = TaggedType
  local _base_0 = {
    create_scope_state = function(self, state)
      return nil
    end,
    _transform = function(self, value, state)
      local scope
      value, scope = self.base_type:_transform(value, self:create_scope_state(state))
      if value == FailedTransform then
        return FailedTransform, scope
      end
      if self.tag_name then
        state = self:update_state(state, scope, value)
      end
      return value, state
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, base_type, opts)
      if opts then
        return _class_0.__parent.__init(self, base_type, opts)
      else
        self.base_type = base_type
      end
    end,
    __base = _base_0,
    __name = "TagScopeType",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  TagScopeType = _class_0
end
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    _transform = function(self, value, state)
      if value == nil then
        return value, state
      end
      return self.base_type:_transform(value, state)
    end,
    is_optional = function(self)
      return self
    end,
    _describe = function(self)
      if self.base_type._describe then
        local base_description = self.base_type:_describe()
        return "optional " .. tostring(base_description)
      end
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, base_type)
      self.base_type = base_type
      return assert(BaseType:is_base_type(self.base_type), "expected a type checker")
    end,
    __base = _base_0,
    __name = "OptionalType",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  OptionalType = _class_0
end
local AnyType
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    _transform = function(self, v, state)
      return v, state
    end,
    _describe = function(self)
      return "anything"
    end,
    is_optional = function(self)
      return self
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, ...)
      return _class_0.__parent.__init(self, ...)
    end,
    __base = _base_0,
    __name = "AnyType",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  AnyType = _class_0
end
local Type
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    _transform = function(self, value, state)
      local got = type(value)
      if self.t ~= got then
        return FailedTransform, "expected type " .. tostring(describe_type(self.t)) .. ", got " .. tostring(describe_type(got))
      end
      if self.length_type then
        local len = #value
        local res
        res, state = self.length_type:_transform(len, state)
        if res == FailedTransform then
          return FailedTransform, tostring(self.t) .. " length " .. tostring(state) .. ", got " .. tostring(len)
        end
      end
      return value, state
    end,
    length = function(self, left, right)
      local l
      if BaseType:is_base_type(left) then
        l = left
      else
        l = types.range(left, right)
      end
      return Type(self.t, {
        length = l
      })
    end,
    _describe = function(self)
      local t = "type " .. tostring(describe_type(self.t))
      if self.length_type then
        t = t .. " length_type " .. tostring(self.length_type:_describe())
      end
      return t
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, t, opts)
      self.t = t
      if opts then
        if opts.length then
          self.length_type = assert(coerce_literal(opts.length))
        end
      end
    end,
    __base = _base_0,
    __name = "Type",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  Type = _class_0
end
local ArrayType
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    _describe = function(self)
      return "an array"
    end,
    _transform = function(self, value, state)
      if not (type(value) == "table") then
        return FailedTransform, "expecting table"
      end
      local k = 1
      for i, v in pairs(value) do
        if not (type(i) == "number") then
          return FailedTransform, "non number field: " .. tostring(i)
        end
        if not (i == k) then
          return FailedTransform, "non array index, got " .. tostring(describe_type(i)) .. " but expected " .. tostring(describe_type(k))
        end
        k = k + 1
      end
      return value, state
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, ...)
      return _class_0.__parent.__init(self, ...)
    end,
    __base = _base_0,
    __name = "ArrayType",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  ArrayType = _class_0
end
local OneOf
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    _describe = function(self)
      local item_names
      do
        local _accum_0 = { }
        local _len_0 = 1
        local _list_0 = self.options
        for _index_0 = 1, #_list_0 do
          local i = _list_0[_index_0]
          if type(i) == "table" and i._describe then
            _accum_0[_len_0] = i:_describe()
          else
            _accum_0[_len_0] = describe_type(i)
          end
          _len_0 = _len_0 + 1
        end
        item_names = _accum_0
      end
      return tostring(join_names(item_names, ", ", ", or "))
    end,
    _transform = function(self, value, state)
      if self.options_hash then
        if self.options_hash[value] then
          return value, state
        end
      else
        local _list_0 = self.options
        for _index_0 = 1, #_list_0 do
          local _continue_0 = false
          repeat
            local item = _list_0[_index_0]
            if item == value then
              return value, state
            end
            if BaseType:is_base_type(item) then
              local new_value, new_state = item:_transform(value, state)
              if new_value == FailedTransform then
                _continue_0 = true
                break
              end
              return new_value, new_state
            end
            _continue_0 = true
          until true
          if not _continue_0 then
            break
          end
        end
      end
      return FailedTransform, "expected " .. tostring(self:_describe())
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, options)
      self.options = options
      assert(type(self.options) == "table", "expected table for options in one_of")
      local fast_opts = types.array_of(types.number + types.string)
      if fast_opts(self.options) then
        do
          local _tbl_0 = { }
          local _list_0 = self.options
          for _index_0 = 1, #_list_0 do
            local v = _list_0[_index_0]
            _tbl_0[v] = true
          end
          self.options_hash = _tbl_0
        end
      end
    end,
    __base = _base_0,
    __name = "OneOf",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  OneOf = _class_0
end
local AllOf
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    _describe = function(self)
      local item_names
      do
        local _accum_0 = { }
        local _len_0 = 1
        local _list_0 = self.types
        for _index_0 = 1, #_list_0 do
          local i = _list_0[_index_0]
          _accum_0[_len_0] = describe_type(i)
          _len_0 = _len_0 + 1
        end
        item_names = _accum_0
      end
      return join_names(item_names, " and ")
    end,
    _transform = function(self, value, state)
      local _list_0 = self.types
      for _index_0 = 1, #_list_0 do
        local t = _list_0[_index_0]
        value, state = t:_transform(value, state)
        if value == FailedTransform then
          return FailedTransform, state
        end
      end
      return value, state
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, types)
      self.types = types
      assert(type(self.types) == "table", "expected table for first argument")
      local _list_0 = self.types
      for _index_0 = 1, #_list_0 do
        local checker = _list_0[_index_0]
        assert(BaseType:is_base_type(checker), "all_of expects all type checkers")
      end
    end,
    __base = _base_0,
    __name = "AllOf",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  AllOf = _class_0
end
local ArrayOf
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    _describe = function(self)
      return "array of " .. tostring(describe_type(self.expected))
    end,
    _transform = function(self, value, state)
      local pass, err = types.table(value)
      if not (pass) then
        return FailedTransform, err
      end
      if self.length_type then
        local len = #value
        local res
        res, state = self.length_type:_transform(len, state)
        if res == FailedTransform then
          return FailedTransform, "array length " .. tostring(state) .. ", got " .. tostring(len)
        end
      end
      local is_literal = not BaseType:is_base_type(self.expected)
      local copy, k
      for idx, item in ipairs(value) do
        local skip_item = false
        local transformed_item
        if is_literal then
          if self.expected ~= item then
            return FailedTransform, "array item " .. tostring(idx) .. ": expected " .. tostring(describe_type(self.expected))
          else
            transformed_item = item
          end
        else
          local item_val
          item_val, state = self.expected:_transform(item, state)
          if item_val == FailedTransform then
            return FailedTransform, "array item " .. tostring(idx) .. ": " .. tostring(state)
          end
          if item_val == nil and not self.keep_nils then
            skip_item = true
          else
            transformed_item = item_val
          end
        end
        if transformed_item ~= item or skip_item then
          if not (copy) then
            do
              local _accum_0 = { }
              local _len_0 = 1
              local _max_0 = idx - 1
              for _index_0 = 1, _max_0 < 0 and #value + _max_0 or _max_0 do
                local i = value[_index_0]
                _accum_0[_len_0] = i
                _len_0 = _len_0 + 1
              end
              copy = _accum_0
            end
            k = idx
          end
        end
        if copy and not skip_item then
          copy[k] = transformed_item
          k = k + 1
        end
      end
      return copy or value, state
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, expected, opts)
      self.expected = expected
      if opts then
        self.keep_nils = opts.keep_nils and true
        if opts.length then
          self.length_type = assert(coerce_literal(opts.length))
        end
      end
    end,
    __base = _base_0,
    __name = "ArrayOf",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  local self = _class_0
  self.type_err_message = "expecting table"
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  ArrayOf = _class_0
end
local ArrayContains
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    short_circuit = true,
    keep_nils = false,
    _describe = function(self)
      return "array containing " .. tostring(describe_type(self.contains))
    end,
    _transform = function(self, value, state)
      local pass, err = types.table(value)
      if not (pass) then
        return FailedTransform, err
      end
      local is_literal = not BaseType:is_base_type(self.contains)
      local contains = false
      local copy, k
      for idx, item in ipairs(value) do
        local skip_item = false
        local transformed_item
        if is_literal then
          if self.contains == item then
            contains = true
          end
          transformed_item = item
        else
          local item_val, new_state = self.contains:_transform(item, state)
          if item_val == FailedTransform then
            transformed_item = item
          else
            state = new_state
            contains = true
            if item_val == nil and not self.keep_nils then
              skip_item = true
            else
              transformed_item = item_val
            end
          end
        end
        if transformed_item ~= item or skip_item then
          if not (copy) then
            do
              local _accum_0 = { }
              local _len_0 = 1
              local _max_0 = idx - 1
              for _index_0 = 1, _max_0 < 0 and #value + _max_0 or _max_0 do
                local i = value[_index_0]
                _accum_0[_len_0] = i
                _len_0 = _len_0 + 1
              end
              copy = _accum_0
            end
            k = idx
          end
        end
        if copy and not skip_item then
          copy[k] = transformed_item
          k = k + 1
        end
        if contains and self.short_circuit then
          if copy then
            for kdx = idx + 1, #value do
              copy[k] = value[kdx]
              k = k + 1
            end
          end
          break
        end
      end
      if not (contains) then
        return FailedTransform, "expected " .. tostring(self:_describe())
      end
      return copy or value, state
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, contains, opts)
      self.contains = contains
      assert(self.contains, "missing contains")
      if opts then
        self.short_circuit = opts.short_circuit and true
        self.keep_nils = opts.keep_nils and true
      end
    end,
    __base = _base_0,
    __name = "ArrayContains",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  local self = _class_0
  self.type_err_message = "expecting table"
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  ArrayContains = _class_0
end
local MapOf
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    _describe = function(self)
      return "map of " .. tostring(self.expected_key:_describe()) .. " -> " .. tostring(self.expected_value:_describe())
    end,
    _transform = function(self, value, state)
      local pass, err = types.table(value)
      if not (pass) then
        return FailedTransform, err
      end
      local key_literal = not BaseType:is_base_type(self.expected_key)
      local value_literal = not BaseType:is_base_type(self.expected_value)
      local transformed = false
      local out = { }
      for k, v in pairs(value) do
        local _continue_0 = false
        repeat
          local new_k = k
          local new_v = v
          if key_literal then
            if k ~= self.expected_key then
              return FailedTransform, "map key expected " .. tostring(describe_type(self.expected_key))
            end
          else
            new_k, state = self.expected_key:_transform(k, state)
            if new_k == FailedTransform then
              return FailedTransform, "map key " .. tostring(state)
            end
          end
          if value_literal then
            if v ~= self.expected_value then
              return FailedTransform, "map value expected " .. tostring(describe_type(self.expected_value))
            end
          else
            new_v, state = self.expected_value:_transform(v, state)
            if new_v == FailedTransform then
              return FailedTransform, "map value " .. tostring(state)
            end
          end
          if new_k ~= k or new_v ~= v then
            transformed = true
          end
          if new_k == nil then
            _continue_0 = true
            break
          end
          out[new_k] = new_v
          _continue_0 = true
        until true
        if not _continue_0 then
          break
        end
      end
      return transformed and out or value, state
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, expected_key, expected_value)
      self.expected_key = coerce_literal(expected_key)
      self.expected_value = coerce_literal(expected_value)
    end,
    __base = _base_0,
    __name = "MapOf",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  MapOf = _class_0
end
local Shape
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    open = false,
    check_all = false,
    is_open = function(self)
      return Shape(self.shape, {
        open = true,
        check_all = self.check_all or nil
      })
    end,
    _describe = function(self)
      local parts
      do
        local _accum_0 = { }
        local _len_0 = 1
        for k, v in pairs(self.shape) do
          _accum_0[_len_0] = tostring(describe_type(k)) .. " = " .. tostring(describe_type(v))
          _len_0 = _len_0 + 1
        end
        parts = _accum_0
      end
      return "{ " .. tostring(table.concat(parts, ", ")) .. " }"
    end,
    _transform = function(self, value, state)
      local pass, err = types.table(value)
      if not (pass) then
        return FailedTransform, err
      end
      local check_all = self.check_all
      local remaining_keys
      do
        local _tbl_0 = { }
        for key in pairs(value) do
          _tbl_0[key] = true
        end
        remaining_keys = _tbl_0
      end
      local errors
      local dirty = false
      local out = { }
      for shape_key, shape_val in pairs(self.shape) do
        local item_value = value[shape_key]
        if remaining_keys then
          remaining_keys[shape_key] = nil
        end
        local new_val
        if BaseType:is_base_type(shape_val) then
          new_val, state = shape_val:_transform(item_value, state)
        else
          if shape_val == item_value then
            new_val, state = item_value, state
          else
            new_val, state = FailedTransform, "expected " .. tostring(describe_type(shape_val))
          end
        end
        if new_val == FailedTransform then
          err = "field " .. tostring(describe_type(shape_key)) .. ": " .. tostring(state)
          if check_all then
            if errors then
              table.insert(errors, err)
            else
              errors = {
                err
              }
            end
          else
            return FailedTransform, err
          end
        else
          if new_val ~= item_value then
            dirty = true
          end
          out[shape_key] = new_val
        end
      end
      if remaining_keys and next(remaining_keys) then
        if self.open then
          for k in pairs(remaining_keys) do
            out[k] = value[k]
          end
        elseif self.extra_fields_type then
          for k in pairs(remaining_keys) do
            local item_value = value[k]
            local tuple
            tuple, state = self.extra_fields_type:_transform({
              [k] = item_value
            }, state)
            if tuple == FailedTransform then
              err = "field " .. tostring(describe_type(k)) .. ": " .. tostring(state)
              if check_all then
                if errors then
                  table.insert(errors, err)
                else
                  errors = {
                    err
                  }
                end
              else
                return FailedTransform, err
              end
            else
              do
                local nk = tuple and next(tuple)
                if nk then
                  if nk ~= k then
                    dirty = true
                  elseif tuple[nk] ~= item_value then
                    dirty = true
                  end
                  out[nk] = tuple[nk]
                else
                  dirty = true
                end
              end
            end
          end
        else
          local names
          do
            local _accum_0 = { }
            local _len_0 = 1
            for key in pairs(remaining_keys) do
              _accum_0[_len_0] = describe_type(key)
              _len_0 = _len_0 + 1
            end
            names = _accum_0
          end
          err = "extra fields: " .. tostring(table.concat(names, ", "))
          if check_all then
            if errors then
              table.insert(errors, err)
            else
              errors = {
                err
              }
            end
          else
            return FailedTransform, err
          end
        end
      end
      if errors and next(errors) then
        return FailedTransform, table.concat(errors, "; ")
      end
      return dirty and out or value, state
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, shape, opts)
      self.shape = shape
      assert(type(self.shape) == "table", "expected table for shape")
      if opts then
        if opts.extra_fields then
          assert(BaseType:is_base_type(opts.extra_fields), "extra_fields_type must be type checker")
          self.extra_fields_type = opts.extra_fields
        end
        self.open = opts.open and true
        self.check_all = opts.check_all and true
        if self.open then
          assert(not self.extra_fields_type, "open can not be combined with extra_fields")
        end
        if self.extra_fields_type then
          return assert(not self.open, "extra_fields can not be combined with open")
        end
      end
    end,
    __base = _base_0,
    __name = "Shape",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  local self = _class_0
  self.type_err_message = "expecting table"
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  Shape = _class_0
end
local Partial
do
  local _class_0
  local _parent_0 = Shape
  local _base_0 = {
    open = true,
    is_open = function(self)
      return error("is_open has no effect on Partial")
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, ...)
      return _class_0.__parent.__init(self, ...)
    end,
    __base = _base_0,
    __name = "Partial",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  Partial = _class_0
end
local Pattern
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    _describe = function(self)
      return "pattern " .. tostring(describe_type(self.pattern))
    end,
    _transform = function(self, value, state)
      local test_value
      if self.coerce then
        if BaseType:is_base_type(self.coerce) then
          local c_res, err = self.coerce:_transform(value)
          if c_res == FailedTransform then
            return FailedTransform, err
          end
          test_value = c_res
        else
          test_value = tostring(value)
        end
      else
        test_value = value
      end
      local t_res, err = types.string(test_value)
      if not (t_res) then
        return FailedTransform, err
      end
      if test_value:match(self.pattern) then
        return value, state
      else
        return FailedTransform, "doesn't match " .. tostring(self:_describe())
      end
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, pattern, opts)
      self.pattern = pattern
      assert(type(self.pattern) == "string", "Pattern must be a string")
      if opts then
        self.coerce = opts.coerce
        return assert(opts.initial_type == nil, "initial_type has been removed from types.pattern (got: " .. tostring(opts.initial_type) .. ")")
      end
    end,
    __base = _base_0,
    __name = "Pattern",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  Pattern = _class_0
end
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    _describe = function(self)
      return describe_type(self.value)
    end,
    _transform = function(self, value, state)
      if self.value ~= value then
        return FailedTransform, "expected " .. tostring(self:_describe())
      end
      return value, state
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, value)
      self.value = value
    end,
    __base = _base_0,
    __name = "Literal",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  Literal = _class_0
end
local Custom
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    _describe = function(self)
      return "custom checker " .. tostring(self.fn)
    end,
    _transform = function(self, value, state)
      local pass, err = self.fn(value, state)
      if not (pass) then
        return FailedTransform, err or "failed custom check"
      end
      return value, state
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, fn)
      self.fn = fn
      return assert(type(self.fn) == "function", "custom checker must be a function")
    end,
    __base = _base_0,
    __name = "Custom",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  Custom = _class_0
end
local Equivalent
do
  local _class_0
  local values_equivalent
  local _parent_0 = BaseType
  local _base_0 = {
    _describe = function(self)
      return "equivalent to " .. tostring(describe_type(self.val))
    end,
    _transform = function(self, value, state)
      if values_equivalent(self.val, value) then
        return value, state
      else
        return FailedTransform, "not equivalent to " .. tostring(self.val)
      end
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, val)
      self.val = val
    end,
    __base = _base_0,
    __name = "Equivalent",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  local self = _class_0
  values_equivalent = function(a, b)
    if a == b then
      return true
    end
    if type(a) == "table" and type(b) == "table" then
      local seen_keys = { }
      for k, v in pairs(a) do
        seen_keys[k] = true
        if not (values_equivalent(v, b[k])) then
          return false
        end
      end
      for k, v in pairs(b) do
        local _continue_0 = false
        repeat
          if seen_keys[k] then
            _continue_0 = true
            break
          end
          if not (values_equivalent(v, a[k])) then
            return false
          end
          _continue_0 = true
        until true
        if not _continue_0 then
          break
        end
      end
      return true
    else
      return false
    end
  end
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  Equivalent = _class_0
end
local Range
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    _transform = function(self, value, state)
      local res
      res, state = self.value_type:_transform(value, state)
      if res == FailedTransform then
        return FailedTransform, "range " .. tostring(state)
      end
      if value < self.left then
        return FailedTransform, "not in " .. tostring(self:_describe())
      end
      if value > self.right then
        return FailedTransform, "not in " .. tostring(self:_describe())
      end
      return value, state
    end,
    _describe = function(self)
      return "range from " .. tostring(self.left) .. " to " .. tostring(self.right)
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, left, right)
      self.left, self.right = left, right
      assert(self.left <= self.right, "left range value should be less than right range value")
      self.value_type = assert(types[type(self.left)], "couldn't figure out type of range boundary")
    end,
    __base = _base_0,
    __name = "Range",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  Range = _class_0
end
local Proxy
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    _transform = function(self, ...)
      return assert(self.fn(), "proxy missing transformer"):_transform(...)
    end,
    _describe = function(self, ...)
      return assert(self.fn(), "proxy missing transformer"):_describe(...)
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, fn)
      self.fn = fn
    end,
    __base = _base_0,
    __name = "Proxy",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  Proxy = _class_0
end
local AssertType
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    assert = assert,
    _transform = function(self, value, state)
      local state_or_err
      value, state_or_err = self.base_type:_transform(value, state)
      self.assert(value ~= FailedTransform, state_or_err)
      return value, state_or_err
    end,
    _describe = function(self)
      if self.base_type._describe then
        local base_description = self.base_type:_describe()
        return "assert " .. tostring(base_description)
      end
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, base_type)
      self.base_type = base_type
      return assert(BaseType:is_base_type(self.base_type), "expected a type checker")
    end,
    __base = _base_0,
    __name = "AssertType",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  AssertType = _class_0
end
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    _transform = function(self, value, state)
      local out, _ = self.base_type:_transform(value, state)
      if out == FailedTransform then
        return value, state
      else
        return FailedTransform, "expected " .. tostring(self:_describe())
      end
    end,
    _describe = function(self)
      if self.base_type._describe then
        local base_description = self.base_type:_describe()
        return "not " .. tostring(base_description)
      end
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, base_type)
      self.base_type = base_type
      return assert(BaseType:is_base_type(self.base_type), "expected a type checker")
    end,
    __base = _base_0,
    __name = "NotType",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  NotType = _class_0
end
local CloneType
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    _transform = function(self, value, state)
      local _exp_0 = type(value)
      if "nil" == _exp_0 or "string" == _exp_0 or "number" == _exp_0 or "boolean" == _exp_0 then
        return value, state
      elseif "table" == _exp_0 then
        local clone_value
        do
          local _tbl_0 = { }
          for k, v in pairs(value) do
            _tbl_0[k] = v
          end
          clone_value = _tbl_0
        end
        do
          local mt = getmetatable(value)
          if mt then
            setmetatable(clone_value, mt)
          end
        end
        return clone_value, state
      else
        return FailedTransform, tostring(describe_type(value)) .. " is not cloneable"
      end
    end,
    _describe = function(self)
      return "cloneable value"
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, ...)
      return _class_0.__parent.__init(self, ...)
    end,
    __base = _base_0,
    __name = "CloneType",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  CloneType = _class_0
end
local MetatableIsType
do
  local _class_0
  local _parent_0 = BaseType
  local _base_0 = {
    allow_metatable_update = false,
    _transform = function(self, value, state)
      local state_or_err
      value, state_or_err = types.table:_transform(value, state)
      if value == FailedTransform then
        return FailedTransform, state_or_err
      end
      local mt = getmetatable(value)
      local new_mt
      new_mt, state_or_err = self.metatable_type:_transform(mt, state_or_err)
      if new_mt == FailedTransform then
        return FailedTransform, "metatable expected: " .. tostring(state_or_err)
      end
      if new_mt ~= mt then
        if self.allow_metatable_update then
          setmetatable(value, new_mt)
        else
          return FailedTransform, "metatable was modified by a type but { allow_metatable_update = true } is not enabled"
        end
      end
      return value, state_or_err
    end,
    _describe = function(self)
      return "has metatable " .. tostring(describe_type(self.metatable_type))
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  _class_0 = setmetatable({
    __init = function(self, metatable_type, opts)
      if BaseType:is_base_type(metatable_type) then
        self.metatable_type = metatable_type
      else
        self.metatable_type = Literal(metatable_type)
      end
      if opts then
        self.allow_metatable_update = opts.allow_metatable_update and true
      end
    end,
    __base = _base_0,
    __name = "MetatableIsType",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        local parent = rawget(cls, "__parent")
        if parent then
          return parent[name]
        end
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  MetatableIsType = _class_0
end
local type_nil = Type("nil")
local type_function = Type("function")
local type_number = Type("number")
types = setmetatable({
  any = AnyType(),
  string = Type("string"),
  number = type_number,
  ["function"] = type_function,
  func = type_function,
  boolean = Type("boolean"),
  userdata = Type("userdata"),
  ["nil"] = type_nil,
  null = type_nil,
  table = Type("table"),
  array = ArrayType(),
  clone = CloneType(),
  integer = Pattern("^%d+$", {
    coerce = type_number / tostring
  }),
  one_of = OneOf,
  all_of = AllOf,
  shape = Shape,
  partial = Partial,
  pattern = Pattern,
  array_of = ArrayOf,
  array_contains = ArrayContains,
  map_of = MapOf,
  literal = Literal,
  range = Range,
  equivalent = Equivalent,
  custom = Custom,
  scope = TagScopeType,
  proxy = Proxy,
  assert = AssertType,
  annotate = AnnotateNode,
  metatable_is = MetatableIsType
}, {
  __index = function(self, fn_name)
    return error("Type checker does not exist: `" .. tostring(fn_name) .. "`")
  end
})
local check_shape
check_shape = function(value, shape)
  assert(shape.check_value, "missing check_value method from shape")
  return shape:check_value(value)
end
is_type = function(val)
  return BaseType:is_base_type(val)
end
return {
  check_shape = check_shape,
  types = types,
  is_type = is_type,
  BaseType = BaseType,
  FailedTransform = FailedTransform,
  VERSION = "2.6.0"
}
