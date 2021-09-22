--[[
Copyright (c) 2018, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- This module contains 'selectors' implementation: code to extract data
-- from Rspamd tasks and compose those together
--
-- Read more at https://rspamd.com/doc/configuration/selectors.html

--[[[
-- @module lua_selectors
-- This module contains 'selectors' implementation: code to extract data
-- from Rspamd tasks and compose those together.
-- Typical selector looks like this: header(User).lower.substring(1, 2):ip
--]]

local exports = {
  maps = require "lua_selectors/maps"
}

local logger = require 'rspamd_logger'
local fun = require 'fun'
local lua_util = require "lua_util"
local M = "selectors"
local rspamd_text = require "rspamd_text"
local unpack_function = table.unpack or unpack
local E = {}

local extractors = require "lua_selectors/extractors"
local transform_function = require "lua_selectors/transforms"

local text_cookie = rspamd_text.cookie

local function pure_type(ltype)
  return ltype:match('^(.*)_list$')
end

local function implicit_tostring(t, ud_or_table)
  if t == 'table' then
    -- Table (very special)
    if ud_or_table.value then
      return ud_or_table.value,'string'
    elseif ud_or_table.addr then
      return ud_or_table.addr,'string'
    end

    return logger.slog("%s", ud_or_table),'string'
  elseif (t == 'string' or t == 'text') and type(ud_or_table) == 'userdata' then
    if ud_or_table.cookie and ud_or_table.cookie == text_cookie then
      -- Preserve opaque
      return ud_or_table,'string'
    else
      return tostring(ud_or_table),'string'
    end
  elseif t ~= 'nil' then
    return tostring(ud_or_table),'string'
  end

  return nil
end

local function process_selector(task, sel)
  local function allowed_type(t)
    if t == 'string' or t == 'string_list' then
      return true
    end

    return false
  end

  local function list_type(t)
    return pure_type(t)
  end

  local input,etype = sel.selector.get_value(task, sel.selector.args)

  if not input then
    lua_util.debugm(M, task, 'no value extracted for %s', sel.selector.name)
    return nil
  end

  lua_util.debugm(M, task, 'extracted %s, type %s',
      sel.selector.name, etype)

  local pipe = sel.processor_pipe or E
  local first_elt = pipe[1]

  if first_elt and first_elt.method then
    -- Explicit conversion
    local meth = first_elt

    if meth.types[etype] then
      lua_util.debugm(M, task, 'apply method `%s` to %s',
          meth.name, etype)
      input,etype = meth.process(input, etype, meth.args)
    else
      local pt = pure_type(etype)

      if meth.types[pt] then
        lua_util.debugm(M, task, 'map method `%s` to list of %s',
            meth.name, pt)
        -- Map method to a list of inputs, excluding empty elements
        input = fun.filter(function(map_elt) return map_elt end,
            fun.map(function(list_elt)
              local ret, _ = meth.process(list_elt, pt)
              return ret
            end, input))
        etype = 'string_list'
      end
    end
    -- Remove method from the pipeline
    pipe = fun.drop_n(1, pipe)
  elseif etype:match('^userdata') or etype:match('^table') then
    -- Implicit conversion

    local pt = pure_type(etype)

    if not pt then
      lua_util.debugm(M, task, 'apply implicit conversion %s->string', etype)
      input = implicit_tostring(etype, input)
      etype = 'string'
    else
      lua_util.debugm(M, task, 'apply implicit map %s->string', pt)
      input = fun.filter(function(map_elt) return map_elt end,
          fun.map(function(list_elt)
            local ret = implicit_tostring(pt, list_elt)
            return ret
          end, input))
      etype = 'string_list'
    end
  end

  -- Now we fold elements using left fold
  local function fold_function(acc, x)
    if acc == nil or acc[1] == nil then
      lua_util.debugm(M, task, 'do not apply %s, accumulator is nil', x.name)
      return nil
    end

    local value = acc[1]
    local t = acc[2]

    if not x.types[t] then
      local pt = pure_type(t)

      if pt and x.types['list'] then
        -- Generic list processor
        lua_util.debugm(M, task, 'apply list function `%s` to %s', x.name, t)
        return {x.process(value, t, x.args)}
      elseif pt and x.map_type and x.types[pt] then
        local map_type = x.map_type .. '_list'
        lua_util.debugm(M, task, 'map `%s` to list of %s resulting %s',
            x.name, pt, map_type)
        -- Apply map, filtering empty values
        return {
          fun.filter(function(map_elt) return map_elt end,
              fun.map(function(list_elt)
                if not list_elt then return nil end
                local ret, _ = x.process(list_elt, pt, x.args)
                return ret
              end, value)),
          map_type -- Returned type
        }
      end
      logger.errx(task, 'cannot apply transform %s for type %s', x.name, t)
      return nil
    end

    lua_util.debugm(M, task, 'apply %s to %s', x.name, t)
    return {x.process(value, t, x.args)}
  end

  local res = fun.foldl(fold_function,
      {input, etype},
      pipe)

  if not res or not res[1] then return nil end -- Pipeline failed

  if not allowed_type(res[2]) then

    -- Search for implicit conversion
    local pt = pure_type(res[2])

    if pt then
      lua_util.debugm(M, task, 'apply implicit map %s->string_list', pt)
      res[1] = fun.map(function(e) return implicit_tostring(pt, e) end, res[1])
      res[2] = 'string_list'
    else
      res[1] = implicit_tostring(res[2], res[1])
      res[2] = 'string'
    end
  end

  if list_type(res[2]) then
    -- Convert to table as it might have a functional form
    res[1] = fun.totable(res[1])
  end

  lua_util.debugm(M, task, 'final selector type: %s, value: %s', res[2], res[1])

  return res[1]
end

local function make_grammar()
  local l = require "lpeg"
  local spc = l.S(" \t\n")^0
  local cont = l.R("\128\191") -- continuation byte
  local utf8_high = l.R("\194\223") * cont
      + l.R("\224\239") * cont * cont
      + l.R("\240\244") * cont * cont * cont
  local atom = l.C((l.R("az") + l.R("AZ") + l.R("09") + l.S("_-") + utf8_high)^1)
  local singlequoted_string = l.P "'" * l.C(((1 - l.S "'\r\n\f\\") + (l.P'\\' * 1))^0) * "'"
  local doublequoted_string = l.P '"' * l.C(((1 - l.S'"\r\n\f\\') + (l.P'\\' * 1))^0) * '"'
  local argument = atom + singlequoted_string + doublequoted_string
  local dot = l.P(".")
  local semicolon = l.P(":")
  local obrace = "(" * spc
  local tbl_obrace = "{" * spc
  local eqsign = spc * "=" * spc
  local tbl_ebrace = spc * "}"
  local ebrace = spc * ")"
  local comma = spc * "," * spc
  local sel_separator = spc * l.S";*" * spc

  return l.P{
    "LIST";
    LIST = l.Ct(l.V("EXPR")) * (sel_separator * l.Ct(l.V("EXPR")))^0,
    EXPR = l.V("FUNCTION") * (semicolon * l.V("METHOD"))^-1 * (dot * l.V("PROCESSOR"))^0,
    PROCESSOR = l.Ct(atom * spc * (obrace * l.V("ARG_LIST") * ebrace)^0),
    FUNCTION = l.Ct(atom * spc * (obrace * l.V("ARG_LIST") * ebrace)^0),
    METHOD = l.Ct(atom / function(e) return '__' .. e end * spc * (obrace * l.V("ARG_LIST") * ebrace)^0),
    ARG_LIST = l.Ct((l.V("ARG") * comma^0)^0),
    ARG = l.Cf(tbl_obrace * l.V("NAMED_ARG") * tbl_ebrace, rawset) + argument + l.V("LIST_ARGS"),
    NAMED_ARG = (l.Ct("") * l.Cg(argument * eqsign * (argument + l.V("LIST_ARGS")) * comma^0)^0),
    LIST_ARGS = l.Ct(tbl_obrace * l.V("LIST_ARG") * tbl_ebrace),
    LIST_ARG = l.Cg(argument * comma^0)^0,
  }
end

local parser = make_grammar()

--[[[
-- @function lua_selectors.parse_selector(cfg, str)
--]]
exports.parse_selector = function(cfg, str)
  local parsed = {parser:match(str)}
  local output = {}

  if not parsed or not parsed[1] then return nil end

  local function check_args(name, schema, args)
    if schema then
      if getmetatable(schema) then
        -- Schema covers all arguments
        local res,err = schema:transform(args)
        if not res then
          logger.errx(rspamd_config, 'invalid arguments for %s: %s', name, err)
          return false
        else
          for i,elt in ipairs(res) do
            args[i] = elt
          end
        end
      else
        for i,selt in ipairs(schema) do
          local res,err = selt:transform(args[i])

          if err then
            logger.errx(rspamd_config, 'invalid arguments for %s: %s', name, err)
            return false
          else
            args[i] = res
          end
        end
      end
    end

    return true
  end

  -- Output AST format is the following:
  -- table of individual selectors
  -- each selector: list of functions
  -- each function: function name + optional list of arguments
  for _,sel in ipairs(parsed) do
    local res = {
      selector = {},
      processor_pipe = {},
    }

    local selector_tbl = sel[1]
    if not selector_tbl then
      logger.errx(cfg, 'no selector represented')
      return nil
    end
    if not extractors[selector_tbl[1]] then
      logger.errx(cfg, 'selector %s is unknown', selector_tbl[1])
      return nil
    end

    res.selector = lua_util.shallowcopy(extractors[selector_tbl[1]])
    res.selector.name = selector_tbl[1]
    res.selector.args = selector_tbl[2] or E

    if not check_args(res.selector.name,
        res.selector.args_schema,
        res.selector.args) then
      return nil
    end

    lua_util.debugm(M, cfg, 'processed selector %s, args: %s',
        res.selector.name, res.selector.args)

    local pipeline_error = false
    -- Now process processors pipe
    fun.each(function(proc_tbl)
      local proc_name = proc_tbl[1]

      if proc_name:match('^__') then
        -- Special case - method
        local method_name = proc_name:match('^__(.*)$')
        -- Check array indexing...
        if tonumber(method_name) then
          method_name = tonumber(method_name)
        end
        local processor = {
          name = tostring(method_name),
          method = true,
          args = proc_tbl[2] or E,
          types = {
            userdata = true,
            table = true,
            string = true,
          },
          map_type = 'string',
          process = function(inp, t, args)
            local ret
            if t == 'table' then
              -- Plain table field
              ret = inp[method_name]
            else
              -- We call method unpacking arguments and dropping all but the first result returned
              ret = (inp[method_name](inp, unpack_function(args or E)))
            end

            local ret_type = type(ret)

            if ret_type == 'nil' then return nil end
            -- Now apply types heuristic
            if ret_type == 'string' then
              return ret,'string'
            elseif ret_type == 'table' then
              -- TODO: we need to ensure that 1) table is numeric 2) table has merely strings
              return ret,'string_list'
            else
              return implicit_tostring(ret_type, ret)
            end
          end,
        }
        lua_util.debugm(M, cfg, 'attached method %s to selector %s, args: %s',
            proc_name, res.selector.name, processor.args)
        table.insert(res.processor_pipe, processor)
      else

        if not transform_function[proc_name] then
          logger.errx(cfg, 'processor %s is unknown', proc_name)
          pipeline_error = proc_name
          return nil
        end
        local processor = lua_util.shallowcopy(transform_function[proc_name])
        processor.name = proc_name
        processor.args = proc_tbl[2] or E

        if not check_args(processor.name, processor.args_schema, processor.args) then
          pipeline_error = 'args schema for ' .. proc_name
          return nil
        end

        lua_util.debugm(M, cfg, 'attached processor %s to selector %s, args: %s',
            proc_name, res.selector.name, processor.args)
        table.insert(res.processor_pipe, processor)
      end
    end, fun.tail(sel))

    if pipeline_error then
      logger.errx(cfg, 'unknown or invalid processor used: "%s", exiting', pipeline_error)
      return nil
    end

    table.insert(output, res)
  end

  return output
end

--[[[
-- @function lua_selectors.register_extractor(cfg, name, selector)
--]]
exports.register_extractor = function(cfg, name, selector)
  if selector.get_value then
    if extractors[name] then
      logger.warnx(cfg, 'redefining selector %s', name)
    end
    extractors[name] = selector

    return true
  end

  logger.errx(cfg, 'bad selector %s', name)
  return false
end

--[[[
-- @function lua_selectors.register_transform(cfg, name, transform)
--]]
exports.register_transform = function(cfg, name, transform)
  if transform.process and transform.types then
    if transform_function[name] then
      logger.warnx(cfg, 'redefining transform function %s', name)
    end
    transform_function[name] = transform

    return true
  end

  logger.errx(cfg, 'bad transform function %s', name)
  return false
end

--[[[
-- @function lua_selectors.process_selectors(task, selectors_pipe)
--]]
exports.process_selectors = function(task, selectors_pipe)
  local ret = {}

  for _,sel in ipairs(selectors_pipe) do
    local r = process_selector(task, sel)

    -- If any element is nil, then the whole selector is nil
    if not r then return nil end
    table.insert(ret, r)
  end

  return ret
end

--[[[
-- @function lua_selectors.combine_selectors(task, selectors, delimiter)
--]]
exports.combine_selectors = function(_, selectors, delimiter)
  if not delimiter then delimiter = '' end

  if not selectors then return nil end

  local have_tables, have_userdata

  for _,s in ipairs(selectors) do
    if type(s) == 'table' then
      have_tables = true
    elseif type(s) == 'userdata' then
      have_userdata = true
    end
  end

  if not have_tables then
    if not have_userdata then
      return table.concat(selectors, delimiter)
    else
      return rspamd_text.fromtable(selectors, delimiter)
    end
  else
    -- We need to do a spill on each table selector and make a cortezian product
    -- e.g. s:tbl:s -> s:telt1:s + s:telt2:s ...
    local tbl = {}
    local res = {}

    for i,s in ipairs(selectors) do
      if type(s) == 'string' then
        rawset(tbl, i, fun.duplicate(s))
      elseif type(s) == 'userdata' then
        rawset(tbl, i, fun.duplicate(tostring(s)))
      else
        -- Raw table
        rawset(tbl, i, fun.map(tostring, s))
      end
    end

    fun.each(function(...)
      table.insert(res, table.concat({...}, delimiter))
    end, fun.zip(lua_util.unpack(tbl)))

    return res
  end
end

--[[[
-- @function lua_selectors.flatten_selectors(selectors)
-- Convert selectors to a flat table of elements
--]]
exports.flatten_selectors = function(selectors)
  local res = {}

  local function fill(tbl)
    for _,s in ipairs(tbl) do
      if type(s) == 'string' then
        rawset(res, #res + 1, s)
      elseif type(s) == 'userdata' then
        rawset(res, #res + 1, tostring(s))
      else
        fill(s)
      end
    end
  end

  fill(selectors)

  return res
end

--[[[
-- @function lua_selectors.create_closure(cfg, selector_str, delimiter='', flatten=false)
--]]
exports.create_selector_closure = function(cfg, selector_str, delimiter, flatten)
  local selector = exports.parse_selector(cfg, selector_str)

  if not selector then
    return nil
  end

  return function(task)
    local res = exports.process_selectors(task, selector)

    if res then
      if flatten then
        return exports.flatten_selectors(res)
      else
        return exports.combine_selectors(nil, res, delimiter)
      end
    end

    return nil
  end
end

local function display_selectors(tbl)
  return fun.tomap(fun.map(function(k,v)
    return k, fun.tomap(fun.filter(function(kk, vv)
      return type(vv) ~= 'function'
    end, v))
  end, tbl))
end

exports.list_extractors = function()
  return display_selectors(extractors)
end

exports.list_transforms = function()
  return display_selectors(transform_function)
end

return exports
