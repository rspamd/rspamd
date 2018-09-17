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
local M = "selectors"
local E = {}

local extractors = {
  ['id'] = {
    ['get_value'] = function(_, args)
      if args[1] then
        return args[1], 'string'
      end

      return '','string'
    end,
    ['description'] = [[Return value from function's argument or an empty string,
For example, `id('Something')` returns a string 'Something']],
  },
  -- Get source IP address
  ['ip'] = {
    ['get_value'] = function(task)
      local ip = task:get_ip()
      if ip and ip:is_valid() then return ip,'ip' end
      return nil
    end,
    ['description'] = [[Get source IP address]],
  },
  -- Get MIME from
  ['from'] = {
    ['get_value'] = function(task, args)
      local from = task:get_from(args[1] or 0)
      if ((from or E)[1] or E).addr then
        return from[1],'email'
      end
      return nil
    end,
    ['description'] = [[Get MIME or SMTP from (e.g. `from('smtp')` or `from('mime')`,
uses any type by default)]],
  },
  ['rcpts'] = {
    ['get_value'] = function(task, args)
      local rcpts = task:get_recipients(args[1] or 0)
      if ((rcpts or E)[1] or E).addr then
        return rcpts,'email_list'
      end
      return nil
    end,
    ['description'] = [[Get MIME or SMTP rcpts (e.g. `rcpts('smtp')` or `rcpts('mime')`,
uses any type by default)]],
  },
  -- Get country (ASN module must be executed first)
  ['country'] = {
    ['get_value'] = function(task)
      local country = task:get_mempool():get_variable('country')
      if not country then
        return nil
      else
        return country,'string'
      end
    end,
    ['description'] = [[Get country (ASN module must be executed first)]],
  },
  -- Get ASN number
  ['asn'] = {
    ['type'] = 'string',
    ['get_value'] = function(task)
      local asn = task:get_mempool():get_variable('asn')
      if not asn then
        return nil
      else
        return asn,'string'
      end
    end,
    ['description'] = [[Get AS number (ASN module must be executed first)]],
  },
  -- Get authenticated username
  ['user'] = {
    ['get_value'] = function(task)
      local auser = task:get_user()
      if not auser then
        return nil
      else
        return auser,'string'
      end
    end,
    ['description'] = 'Get authenticated user name',
  },
  -- Get principal recipient
  ['to'] = {
    ['get_value'] = function(task)
      return task:get_principal_recipient(),'string'
    end,
    ['description'] = 'Get principal recipient',
  },
  -- Get content digest
  ['digest'] = {
    ['get_value'] = function(task)
      return task:get_digest(),'string'
    end,
    ['description'] = 'Get content digest',
  },
  -- Get list of all attachments digests
  ['attachments'] = {
    ['get_value'] = function(task)
      local parts = task:get_parts() or E
      local digests = {}

      for _,p in ipairs(parts) do
        if p:get_filename() then
          table.insert(digests, p:get_digest())
        end
      end

      if #digests > 0 then
        return digests,'string_list'
      end

      return nil
    end,
    ['description'] = 'Get list of all attachments digests',
  },
  -- Get all attachments files
  ['files'] = {
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
        return files,'string_list'
      end

      return nil
    end,
    ['description'] = 'Get all attachments files',
  },
  -- Get helo value
  ['helo'] = {
    ['get_value'] = function(task)
      return task:get_helo(),'string'
    end,
    ['description'] = 'Get helo value',
  },
  -- Get header with the name that is expected as an argument. Returns list of
  -- headers with this name
  ['header'] = {
    ['get_value'] = function(task, args)
      local strong = false
      if args[2] then
        if args[2]:match('strong') then
          strong = true
        end

        if args[2]:match('full') then
          return task:get_header_full(args[1], strong),'kv_list'
        end

        return task:get_header(args[1], strong),'string'
      else
        return task:get_header(args[1]),'string'
      end
    end,
    ['description'] = [[Get header with the name that is expected as an argument.
The optional second argument accepts list of flags:
  - `full`: returns all headers with this name with all data (like task:get_header_full())
  - `strong`: use case sensitive match when matching header's name]],
  },
  -- Get list of received headers (returns list of tables)
  ['received'] = {
    ['get_value'] = function(task, args)
      local rh = task:get_received_headers()
      if args[1] and rh then
        return fun.map(function(r) return r[args[1]] end, rh), 'string_list'
      end

      return rh,'kv_list'
    end,
    ['description'] = [[Get list of received headers.
If no arguments specified, returns list of tables. Otherwise, selects a specific element,
e.g. `by_hostname`]],
  },
  -- Get all urls
  ['urls'] = {
    ['get_value'] = function(task, args)
      local urls = task:get_urls()
      if args[1] and urls then
        return fun.map(function(r) return r[args[1]](r) end, urls), 'string_list'
      end
      return urls,'url_list'
    end,
    ['description'] = [[Get list of all urls.
If no arguments specified, returns list of url objects. Otherwise, calls a specific method,
e.g. `get_tld`]],
  },
  -- Get all emails
  ['emails'] = {
    ['get_value'] = function(task, args)
      local urls = task:get_emails()
      if args[1] and urls then
        return fun.map(function(r) return r[args[1]](r) end, urls), 'string_list'
      end
      return urls,'url_list'
    end,
    ['description'] = [[Get list of all emails.
If no arguments specified, returns list of url objects. Otherwise, calls a specific method,
e.g. `get_user`]],
  },
  -- Get specific pool var. The first argument must be variable name,
  -- the second argument is optional and defines the type (string by default)
  ['pool_var'] = {
    ['get_value'] = function(task, args)
      return task:get_mempool():get_variable(args[1], args[2]),(args[2] or 'string')
    end,
    ['description'] = [[Get specific pool var. The first argument must be variable name,
the second argument is optional and defines the type (string by default)]],
  },
  -- Get specific HTTP request header. The first argument must be header name.
  ['request_header'] = {
    ['get_value'] = function(task, args)
      local hdr = task:get_request_header(args[1])
      if hdr then
        return tostring(hdr),'string'
      end

      return nil
    end,
    ['description'] = [[Get specific HTTP request header.
The first argument must be header name.]],
  },
  -- Get task date, optionally formatted
  ['time'] = {
    ['get_value'] = function(task, args)
      local what = args[1] or 'message'
      local dt = task:get_date{format = what, gmt = true}

      if dt then
        if args[2] then
          -- Should be in format !xxx, as dt is in GMT
          return os.date(args[2], dt),'string'
        end

        return tostring(dt),'string'
      end

      return nil
    end,
    ['description'] = [[Get task timestamp. The first argument is type:
  - `connect`: connection timestamp (default)
  - `message`: timestamp as defined by `Date` header

  The second argument is optional time format, see [os.date](http://pgl.yoyo.org/luai/i/os.date) description]]
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
  ['addr'] = {
    ['types'] = {
      ['email'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _)
      return inp.addr
    end,
    ['description'] = 'Get email address as a string',
  },
  -- Get address
  ['name'] = {
    ['types'] = {
      ['email'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _)
      return inp.name
    end,
    ['description'] = 'Get email name as a string',
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
  ['take_n'] = {
    ['types'] = {
      ['list'] = true,
    },
    ['process'] = function(inp, t, args)
      return fun.take_n(tonumber(args[1]) or 1, inp),t
    end,
    ['description'] = 'Returns the n first elements',
  },
  ['drop_n'] = {
    ['types'] = {
      ['list'] = true,
    },
    ['process'] = function(inp, t, args)
      return fun.drop_n(tonumber(args[1]) or 1, inp),t
    end,
    ['description'] = 'Returns list without the first n elements',
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
  -- Regexp matching
  ['regexp'] = {
    ['types'] = {
      ['string'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _, args)
      local rspamd_regexp = require "rspamd_regexp"

      local re = rspamd_regexp.create_cached(args[1])

      if not re then
        logger.errx('invalid regexp: %s', args[1])
        return nil
      end

      local res = re:search(inp, false, true)

      if res then
        if #res == 1 then
          return res[1],'string'
        end

        return res,'string_list'
      end

      return nil
    end,
    ['description'] = 'Regexp matching',
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
    ['description'] = [[Boolean function in.
Returns either nil or its input if input is in args list]],
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
    ['description'] = [[Boolean function not in.
Returns either nil or its input if input is not in args list]],
  },
}

local implicit_types_map = {
  ip = {'string', tostring},
  email = {'string', function(e)
    if e.name then
      return string.format("%s <%s>", e.name, e.addr)
    end
    return string.format("<%s>", e.addr)
  end},
  url = {'string', tostring}
}

local function process_selector(task, sel)
  local function allowed_type(t)
    if t == 'string' or t == 'text' or t == 'string_list' or t == 'text_list' then
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

  lua_util.debugm(M, task, 'extracted %s, type %s', sel.selector.name, etype)

  -- Now we fold elements using left fold
  local function fold_function(acc, x)
    if acc == nil or acc[1] == nil then
      lua_util.debugm(M, task, 'do not apply %s, accumulator is nil', x.name)
      return nil
    end
    local value = acc[1]
    local t = acc[2]

    if not x.types[t] then
      -- Additional case for map
      local pt = pure_type(t)
      if x.types['list'] then
        -- Generic list
        lua_util.debugm(M, task, 'apply list function %s to %s', x.name, t)
        return {x.process(value, t, x.args)}
      elseif pt and x.map_type and x.types[pt] then
        lua_util.debugm(M, task, 'map %s to list of %s resulting %s',
            x.name, pt, x.map_type)

        return {fun.map(function(list_elt)
          local ret, _ = x.process(list_elt, pt, x.args)
          return ret
        end, value), x.map_type}
      end
      logger.errx(task, 'cannot apply transform %s for type %s', x.name, t)
      return nil
    end

    lua_util.debugm(M, task, 'apply %s to %s', x.name, t)
    return {x.process(value, t, x.args)}
  end

  local res = fun.foldl(fold_function,
      {input, etype},
      sel.processor_pipe)

  if not res or not res[1] then return nil end -- Pipeline failed

  if not allowed_type(res[2]) then

    -- Search for implicit conversion
    local pt = pure_type(res[2])

    if pt then
      local it = implicit_types_map[pt]
      if it then
        lua_util.debugm(M, task, 'apply implicit map %s->%s',
            pt, it[1])
        res[1] = fun.map(it[2], res[1])
        res[2] = string.format('%s_list', it[1])
      end
    else
      local it = implicit_types_map[res[2]]

      if it then
        lua_util.debugm(M, task, 'apply implicit conversion %s->%s',
            res[2], it[1])
        res[1] = it[2](res[1])
        res[2] = it[1]
      end
    end

    if not not allowed_type(res[2]) then
      logger.errx(task, 'transform pipeline has returned bad type: %s, string expected: res = %s, sel: %s',
          res[2], res, sel)
      return nil
    end
  end

  lua_util.debugm(M, task, 'final selector type: %s', res[2])

  if list_type(res[2]) then
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
  local sel_separator = spc * l.S":;*" * spc

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
        elseif type(s) == 'userdata' then
          table.insert(prefix, tostring(s))
        else
          in_prefix = false
          table.insert(tbl, s)
        end
      else
        if type(s) == 'string' then
          table.insert(suffix, s)
        elseif type(s) == 'userdata' then
          table.insert(suffix, tostring(s))
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

--[[[
-- @function lua_selectors.create_closure(cfg, selector_str, delimiter='')
--]]
exports.create_selector_closure = function(cfg, selector_str, delimiter)
  local selector = exports.parse_selector(cfg, selector_str)

  if not selector then
    return nil
  end

  return function(task)
    local res = exports.process_selectors(task, selector)

    if res then
      return exports.combine_selectors(nil, res, delimiter)
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