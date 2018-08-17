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

local selectors = {
  ['ip'] = {
    ['type'] = 'ip',
    ['get_value'] = function(task)
      local ip = task:get_ip()
      if ip and ip:is_valid() then return tostring(ip) end
      return nil
    end,
  },
  ['smtp_from'] = {
    ['type'] = 'email',
    ['get_value'] = function(task)
      local from = task:get_from(0)
      if ((from or E)[1] or E).addr then
        return from[1]
      end
      return nil
    end,
  },
  ['mime_from'] = {
    ['type'] = 'email',
    ['get_value'] = function(task)
      local from = task:get_from(0)
      if ((from or E)[1] or E).addr then
        return from[1]
      end
      return nil
    end,
  },
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
  },
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
  },
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
  },
  ['to'] = {
    ['type'] = 'email',
    ['get_value'] = function(task)
      return task:get_principal_recipient()
    end,
  },
  ['digest'] = {
    ['type'] = 'string',
    ['get_value'] = function(task)
      return task:get_digest()
    end,
  },
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
  },
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
  },
  ['helo'] = {
    ['type'] = 'string',
    ['get_value'] = function(task)
      return task:get_helo()
    end,
  },
  ['header'] = {
    ['type'] = 'header_list',
    ['get_value'] = function(task, args)
      return task:get_header_full(args[1])
    end,
  },
  ['received'] = {
    ['type'] = 'received_list',
    ['get_value'] = function(task)
      return task:get_received_headers()
    end,
  },
  ['urls'] = {
    ['type'] = 'url_list',
    ['get_value'] = function(task)
      return task:get_urls()
    end,
  },
  ['emails'] = {
    ['type'] = 'url_list',
    ['get_value'] = function(task)
      return task:get_emails()
    end,
  }
}

local transform_function = {
  -- Get hostname from url or a list of urls
  ['get_host'] = {
    ['types'] = {
      ['url'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, t)
      return inp:get_host(),'string'
    end
  },
  -- Get tld from url or a list of urls
  ['get_tld'] = {
    ['types'] = {
      ['url'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, t)
      return inp:get_tld()
    end
  },
  -- Get address
  ['get_addr'] = {
    ['types'] = {
      ['email'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _)
      return inp:get_addr()
    end
  },
  -- Returns the lowercased string
  ['lower'] = {
    ['types'] = {
      ['string'] = true,
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, t)
      return inp:lower(),'string'
    end
  },
  -- Returns the first element
  ['first'] = {
    ['types'] = {
      ['url_list'] = true,
      ['header_list'] = true,
      ['received_list'] = true,
      ['string_list'] = true
    },
    ['process'] = function(inp, t)
      local pure_type = t:match('^(.*)_list$')
      return inp[1],pure_type
    end
  },
  -- Returns the last element
  ['last'] = {
    ['types'] = {
      ['url_list'] = true,
      ['header_list'] = true,
      ['received_list'] = true,
      ['string_list'] = true
    },
    ['process'] = function(inp, t)
      local pure_type = t:match('^(.*)_list$')
      return inp[#inp],pure_type
    end
  },
  -- Returns the nth element
  ['nth'] = {
    ['types'] = {
      ['url_list'] = true,
      ['header_list'] = true,
      ['received_list'] = true,
      ['string_list'] = true
    },
    ['process'] = function(inp, t, args)
      local pure_type = t:match('^(.*)_list$')
      return inp[tonumber(args[1])],pure_type
    end
  },
  -- Joins strings into a single string using separator in the argument
  ['join'] = {
    ['types'] = {
      ['string_list'] = true
    },
    ['process'] = function(inp, _, args)
      return table.concat(inp, args[1] or ''), 'string'
    end
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
    end
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
    end
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
    end
  },
  -- Get header value
  ['hdr_value'] = {
    ['types'] = {
      ['header'] = true,
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _)
      return inp.value
    end
  },
  -- Extracts table value from table
  ['elt'] = {
    ['types'] = {
      ['header'] = true,
      ['received'] = true,
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, t, args)
      return inp[args[1]],'string'
    end
  },
  -- Get address
  ['method'] = {
    ['types'] = {
      ['email'] = true,
      ['url'] = true,
      ['ip'] = true,
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _, args)
      return inp[args[1]](inp)
    end
  },
}

local function process_selector(task, sel)
  local input = sel.selector.get_value(task, sel.selector.args)
  if not input then return nil end

  -- Now we fold elements using left fold
  local function fold_function(acc, x)
    if acc == nil then return nil end
    local value = acc[1]
    local t = acc[2]

    if not x.types[t] then
      -- Additional case for map
      local pure_type = t:match('^(.*)_list$')
      if pure_type and x.map_type and x.types[pure_type] then
        return fun.map(function(list_elt)
          local ret, _ = x.process(list_elt, pure_type, x.args)
          return ret
        end, value), x.map_type
      end
      logger.errx(task, 'cannot apply transform %s for type %s', x.name, t)
      return nil
    end

    return x.process(value, t, x.args)
  end

  local res = fun.foldl(fold_function,
      {input, sel.selector.type},
      sel.processor_pipe)

  if not res then return nil end -- Error in pipeline

  if not (res[2] == 'string' or res[2] == 'string_list') then
    logger.errx(task, 'transform pipeline has returned bad type: %s, string expected',
        res[2])
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
  local dot = l.P(".")
  local obrace = "(" * spc
  local ebrace = spc * ")"
  local comma = spc * "," * spc
  local colon = ":"

  return l.P{
    "LIST";
    LIST = l.Ct(l.V("EXPR")) * (colon * l.Ct(l.V("EXPR")))^0,
    EXPR = l.V("FUNCTION") * (dot * l.V("PROCESSOR"))^0,
    PROCESSOR = l.Ct(atom * spc * (obrace * l.V("ARG_LIST") * ebrace)^0),
    FUNCTION = l.Ct(atom * spc * (obrace * l.V("ARG_LIST") * ebrace)^0),
    ARG_LIST = l.Ct((atom * comma^0)^0)
  }
end

local parser = make_grammar()

--[[[
-- @function lua_selectors.parse_selectors(cfg, str)
--]]
exports.parse_selector = function(cfg, str)
  local parsed = parser:match(str)
  local output = {}

  if not parsed then return nil end
  local function shallowcopy(orig)
    local orig_type = type(orig)
    local copy
    if orig_type == 'table' then
      copy = {}
      for orig_key, orig_value in pairs(orig) do
        copy[orig_key] = orig_value
      end
    else
      copy = orig
    end
    return copy
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
    if not selectors[selector_tbl[1]] then
      logger.errx(cfg, 'selector %s is unknown', selector_tbl[1])
      return nil
    end

    res.selector = shallowcopy(selectors[selector_tbl[1]])
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
      local processor = shallowcopy(transform_function[proc_name])
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
    if selectors[name] then
      logger.warnx(cfg, 'redefining selector %s', name)
    end
    selectors[name] = selector

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
  local ret = fun.totable(fun.map(function(sel)
    return process_selector(task, sel)
  end, selectors_pipe))

  if fun.any(function(e) return e == nil end, ret) then
    -- If any element is nil, then the whole selector is nil
    return nil
  end

  return ret
end

return exports