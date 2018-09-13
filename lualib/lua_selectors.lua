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

--[[[
-- @module lua_selectors
-- This module contains 'selectors' implementation: code to extract data
-- from Rspamd tasks and compose those together.
-- Typical selector looks like this: header(User).lower.substring(1, 2):ip
--]]

local exports = {}
local logger = require 'rspamd_logger'
local fun = require 'fun'
local lua_util = require "lua_util"
local M = "lua_selectors"
local E = {}

local extractors = {
  -- Get source IP address
  ['ip'] = {
    ['type'] = 'ip',
    ['get_value'] = function(task)
      local ip = task:get_ip()
      if ip and ip:is_valid() then return tostring(ip) end
      return nil
    end,
    ['description'] = 'Get source IP address',
  },
  -- Get SMTP from
  ['smtp_from'] = {
    ['type'] = 'email',
    ['get_value'] = function(task)
      local from = task:get_from(0)
      if ((from or E)[1] or E).addr then
        return from[1]
      end
      return nil
    end,
    ['description'] = 'Get SMTP from',
  },
  -- Get MIME from
  ['mime_from'] = {
    ['type'] = 'email',
    ['get_value'] = function(task)
      local from = task:get_from(0)
      if ((from or E)[1] or E).addr then
        return from[1]
      end
      return nil
    end,
    ['description'] = 'Get MIME from',
  },
  -- Get country (ASN module must be executed first)
  ['country'] = {
    ['type'] = 'string',
    ['get_value'] = function(task)
      local asn = task:get_mempool():get_variable('asn')
      if not asn then
        return nil
      else
        return asn
      end
    end,
    ['description'] = 'Get country (ASN module must be executed first)',
  },
  -- Get ASN number
  ['asn'] = {
    ['type'] = 'string',
    ['get_value'] = function(task)
      local asn = task:get_mempool():get_variable('asn')
      if not asn then
        return nil
      else
        return asn
      end
    end,
    ['description'] = 'Get ASN number',
  },
  -- Get authenticated username
  ['user'] = {
    ['type'] = 'string',
    ['get_value'] = function(task)
      local auser = task:get_user()
      if not auser then
        return nil
      else
        return auser
      end
    end,
    ['description'] = 'Get authenticated username',
  },
  -- Get principal recipient
  ['to'] = {
    ['type'] = 'email',
    ['get_value'] = function(task)
      return task:get_principal_recipient()
    end,
    ['description'] = 'Get principal recipient',
  },
  -- Get content digest
  ['digest'] = {
    ['type'] = 'string',
    ['get_value'] = function(task)
      return task:get_digest()
    end,
    ['description'] = 'Get content digest',
  },
  -- Get list of all attachments digests
  ['attachments'] = {
    ['type'] = 'string_list',
    ['get_value'] = function(task)
      local parts = task:get_parts() or E
      local digests = {}

      for _,p in ipairs(parts) do
        if p:get_filename() then
          table.insert(digests, p:get_digest())
        end
      end

      if #digests > 0 then
        return digests
      end

      return nil
    end,
    ['description'] = 'Get list of all attachments digests',
  },
  -- Get all attachments files
  ['files'] = {
    ['type'] = 'string_list',
    ['get_value'] = function(task)
      local parts = task:get_parts() or E
      local files = {}

      for _,p in ipairs(parts) do
        local fname = p:get_filename()
        if fname then
          table.insert(files, fname)
        end
      end

      if #files > 0 then
        return files
      end

      return nil
    end,
    ['description'] = 'Get all attachments files',
  },
  -- Get helo value
  ['helo'] = {
    ['type'] = 'string',
    ['get_value'] = function(task)
      return task:get_helo()
    end,
    ['description'] = 'Get helo value',
  },
  -- Get header with the name that is expected as an argument. Returns list of
  -- headers with this name
  ['header'] = {
    ['type'] = 'kv_list',
    ['get_value'] = function(task, args)
      return task:get_header_full(args[1])
    end,
    ['description'] = 'Get header with the name that is expected as an argument. Returns list of headers with this name',
  },
  -- Get list of received headers (returns list of tables)
  ['received'] = {
    ['type'] = 'kv_list',
    ['get_value'] = function(task)
      return task:get_received_headers()
    end,
    ['description'] = 'Get list of received headers (returns list of tables)',
  },
  -- Get all urls
  ['urls'] = {
    ['type'] = 'url_list',
    ['get_value'] = function(task)
      return task:get_urls()
    end,
    ['description'] = 'Get all urls',
  },
  -- Get all emails
  ['emails'] = {
    ['type'] = 'url_list',
    ['get_value'] = function(task)
      return task:get_emails()
    end,
    ['description'] = 'Get all emails',
  },
  -- Get specific pool var. The first argument must be variable name,
  -- the second argument is optional and defines the type (string by default)
  ['pool_var'] = {
    ['type'] = 'string',
    ['get_value'] = function(task, args)
      return task:get_mempool():get_variable(args[1], args[2])
    end,
    ['description'] = [[Get specific pool var. The first argument must be variable name,
      the second argument is optional and defines the type (string by default)]],
  },
  -- Get specific HTTP request header. The first argument must be header name.
  ['request_header'] = {
    ['type'] = 'string',
    ['get_value'] = function(task, args)
      local hdr = task:get_request_header(args[1])
      if hdr then
        return tostring(hdr)
      end

      return nil
    end,
    ['description'] = 'Get specific HTTP request header. The first argument must be header name.',
  },
  -- Get task date, optionally formatted
  ['time'] = {
    ['type'] = 'string',
    ['get_value'] = function(task, args)
      local what = args[1] or 'message'
      local dt = task:get_date{format = what, gmt = true}

      if dt then
        if args[2] then
          -- Should be in format !xxx, as dt is in GMT
          return os.date(args[2], dt)
        end

        return tostring(dt)
      end

      return nil
    end,
    ['description'] = 'Get task date, optionally formatted (see os.date)',
  }
}

local function pure_type(ltype)
  return ltype:match('^(.*)_list$')
end

local transform_function = {
  -- Get hostname from url or a list of urls
  ['get_host'] = {
    ['types'] = {
      ['url'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, t)
      return inp:get_host(),'string'
    end,
    ['description'] = 'Get hostname from url or a list of urls',
  },
  -- Get tld from url or a list of urls
  ['get_tld'] = {
    ['types'] = {
      ['url'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, t)
      return inp:get_tld()
    end,
    ['description'] = 'Get tld from url or a list of urls',
  },
  -- Get address
  ['get_addr'] = {
    ['types'] = {
      ['email'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _)
      return inp:get_addr()
    end,
    ['description'] = 'Get email address as a string',
  },
  -- Returns the lowercased string
  ['lower'] = {
    ['types'] = {
      ['string'] = true,
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _)
      return inp:lower(),'string'
    end,
    ['description'] = 'Returns the lowercased string',
  },
  -- Returns the first element
  ['first'] = {
    ['types'] = {
      ['list'] = true,
    },
    ['process'] = function(inp, t)
      return inp[1],pure_type(t)
    end,
    ['description'] = 'Returns the first element',
  },
  -- Returns the last element
  ['last'] = {
    ['types'] = {
      ['list'] = true,
    },
    ['process'] = function(inp, t)
      return inp[#inp],pure_type(t)
    end,
    ['description'] = 'Returns the last element',
  },
  -- Returns the nth element
  ['nth'] = {
    ['types'] = {
      ['list'] = true,
    },
    ['process'] = function(inp, t, args)
      return inp[tonumber(args[1] or 1)],pure_type(t)
    end,
    ['description'] = 'Returns the nth element',
  },
  -- Joins strings into a single string using separator in the argument
  ['join'] = {
    ['types'] = {
      ['string_list'] = true
    },
    ['process'] = function(inp, _, args)
      return table.concat(inp, args[1] or ''), 'string'
    end,
    ['description'] = 'Joins strings into a single string using separator in the argument',
  },
  -- Create a digest from string or a list of strings
  ['digest'] = {
    ['types'] = {
      ['string'] = true
    },
    ['map_type'] = 'hash',
    ['process'] = function(inp, _, args)
      local hash = require 'rspamd_cryptobox_hash'
      local ht = args[1] or 'blake2'
      return hash:create_specific(ht):update(inp), 'hash'
    end,
    ['description'] = 'Create a digest from string or a list of strings',
  },
  -- Encode hash to string (using hex encoding by default)
  ['encode'] = {
    ['types'] = {
      ['hash'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _, args)
      local how = args[1] or 'hex'
      if how == 'hex' then
        return inp:hex()
      elseif how == 'base32' then
        return inp:base32()
      elseif how == 'base64' then
        return inp:base64()
      end
    end,
    ['description'] = 'Encode hash to string (using hex encoding by default)',
  },
  -- Extracts substring
  ['substring'] = {
    ['types'] = {
      ['string'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _, args)
      local start_pos = args[1] or 1
      local end_pos = args[2] or -1

      return inp:sub(start_pos, end_pos), 'string'
    end,
    ['description'] = 'Extracts substring',
  },
  -- Drops input value and return values from function's arguments or an empty string
  ['id'] = {
    ['types'] = {
      ['string'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(_, _, args)
      if args[1] and args[2] then
        return fun.map(tostring, args)
      elseif args[1] then
        return args[1]
      end

      return ''
    end,
    ['description'] = 'Drops input value and return values from function\'s arguments or an empty string',
  },
  -- Extracts table value from key-value list
  ['elt'] = {
    ['types'] = {
      ['kv'] = true,
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, t, args)
      return inp[args[1]],'string'
    end,
    ['description'] = 'Extracts table value from key-value list',
  },
  -- Call specific userdata method
  ['method'] = {
    ['types'] = {
      ['email'] = true,
      ['url'] = true,
      ['ip'] = true,
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _, args)
      return inp[args[1]](inp)
    end,
    ['description'] = 'Call specific userdata method',
  },
  -- Boolean function in, returns either nil or its input if input is in args list
  ['in'] = {
    ['types'] = {
      ['string'] = true,
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, t, args)
      for _,a in ipairs(args) do if a == inp then return inp,t end end
      return nil
    end,
    ['description'] = 'Boolean function in, returns either nil or its input if input is in args list',
  },
  ['not_in'] = {
    ['types'] = {
      ['string'] = true,
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, t, args)
      for _,a in ipairs(args) do if a == inp then return nil end end
      return inp,t
    end,
    ['description'] = 'Boolean function in, returns either nil or its input if input is not in args list',
  },
}

local function process_selector(task, sel)
  local input = sel.selector.get_value(task, sel.selector.args)
  if not input then return nil end

  -- Now we fold elements using left fold
  local function fold_function(acc, x)
    if acc == nil or acc[1] == nil then return nil end
    local value = acc[1]
    local t = acc[2]

    if not x.types[t] then
      -- Additional case for map
      local pt = pure_type(t, '^(.*)_list$')
      if x.types['list'] then
        -- Generic list
        return {x.process(value, t, x.args)}
      elseif pt and x.map_type and x.types[pt] then
        return {fun.map(function(list_elt)
          local ret, _ = x.process(list_elt, pt, x.args)
          return ret
        end, value), x.map_type}
      end
      logger.errx(task, 'cannot apply transform %s for type %s', x.name, t)
      return nil
    end

    return {x.process(value, t, x.args)}
  end

  local res = fun.foldl(fold_function,
      {input, sel.selector.type},
      sel.processor_pipe)

  if not res or not res[1] then return nil end -- Pipeline failed

  if not (res[2] == 'string' or res[2] == 'string_list') then
    logger.errx(task, 'transform pipeline has returned bad type: %s, string expected: res = %s, sel: %s',
        res[2], res, sel)
    return nil
  end

  if res[2] == 'string_list' then
    -- Convert to table as it might have a functional form
    return fun.totable(res[1])
  end

  return res[1]
end

local function make_grammar()
  local l = require "lpeg"
  local spc = l.S(" \t\n")^0
  local atom = l.C((l.R("az") + l.R("AZ") + l.R("09") + l.S("_-"))^1)
  local singlequoted_string = l.P "'" * l.C(((1 - l.S "'\r\n\f\\") + (l.P'\\' * 1))^0) * "'"
  local doublequoted_string = l.P '"' * l.C(((1 - l.S'"\r\n\f\\') + (l.P'\\' * 1))^0) * '"'
  local argument = atom + singlequoted_string + doublequoted_string
  local dot = l.P(".")
  local obrace = "(" * spc
  local ebrace = spc * ")"
  local comma = spc * "," * spc
  local sel_separator = l.S":;"

  return l.P{
    "LIST";
    LIST = l.Ct(l.V("EXPR")) * (sel_separator * l.Ct(l.V("EXPR")))^0,
    EXPR = l.V("FUNCTION") * (dot * l.V("PROCESSOR"))^0,
    PROCESSOR = l.Ct(atom * spc * (obrace * l.V("ARG_LIST") * ebrace)^0),
    FUNCTION = l.Ct(atom * spc * (obrace * l.V("ARG_LIST") * ebrace)^0),
    ARG_LIST = l.Ct((argument * comma^0)^0)
  }
end

local parser = make_grammar()

--[[[
-- @function lua_selectors.parse_selectors(cfg, str)
--]]
exports.parse_selector = function(cfg, str)
  local parsed = {parser:match(str)}
  local output = {}

  if not parsed then return nil end

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
    res.selector.args = selector_tbl[2] or {}

    lua_util.debugm(M, cfg, 'processed selector %s, args: %s',
        res.selector.name, res.selector.arg)

    -- Now process processors pipe
    fun.each(function(proc_tbl)
      local proc_name = proc_tbl[1]

      if not transform_function[proc_name] then
        logger.errx(cfg, 'processor %s is unknown', proc_name)
        return nil
      end
      local processor = lua_util.shallowcopy(transform_function[proc_name])
      processor.name = proc_name
      processor.args = proc_tbl[2]
      lua_util.debugm(M, cfg, 'attached processor %s to selector %s, args: %s',
          proc_name, res.selector.name, processor.args)
      table.insert(res.processor_pipe, processor)
    end, fun.tail(sel))

    table.insert(output, res)
  end

  return output
end

--[[[
-- @function lua_selectors.register_selector(cfg, name, selector)
--]]
exports.register_selector = function(cfg, name, selector)
  if selector.get_value and selector.type then
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

  local all_strings = fun.all(function(s) return type(s) == 'string' end, selectors)

  if all_strings then
    return table.concat(selectors, delimiter)
  else
    -- We need to do a spill on each table selector
    -- e.g. s:tbl:s -> s:telt1:s + s:telt2:s ...
    local prefix = {}
    local tbl = {}
    local suffix = {}
    local res = {}

    local in_prefix = true
    for _,s in ipairs(selectors) do
      if in_prefix then
        if type(s) == 'string' then
          table.insert(prefix, s)
        else
          in_prefix = false
          table.insert(tbl, s)
        end
      else
        if type(s) == 'string' then
          table.insert(suffix, s)
        else
          table.insert(tbl, s)
        end
      end
    end

    prefix = table.concat(prefix, delimiter)
    suffix = table.concat(suffix, delimiter)

    for _,t in ipairs(tbl) do
      fun.each(function(...)
        table.insert(res, table.concat({...}, delimiter))
      end, fun.zip(fun.duplicate(prefix), t, fun.duplicate(suffix)))
    end

    return res
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