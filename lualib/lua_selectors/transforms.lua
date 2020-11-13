--[[
Copyright (c) 2019, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local fun = require 'fun'
local lua_util = require "lua_util"
local rspamd_util = require "rspamd_util"
local ts = require("tableshape").types
local logger = require 'rspamd_logger'
local common = require "lua_selectors/common"
local M = "selectors"

local maps = require "lua_selectors/maps"

local function pure_type(ltype)
  return ltype:match('^(.*)_list$')
end

local transform_function = {
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
      return fun.head(inp),pure_type(t)
    end,
    ['description'] = 'Returns the first element',
  },
  -- Returns the last element
  ['last'] = {
    ['types'] = {
      ['list'] = true,
    },
    ['process'] = function(inp, t)
      return fun.nth(fun.length(inp), inp),pure_type(t)
    end,
    ['description'] = 'Returns the last element',
  },
  -- Returns the nth element
  ['nth'] = {
    ['types'] = {
      ['list'] = true,
    },
    ['process'] = function(inp, t, args)
      return fun.nth(args[1] or 1, inp),pure_type(t)
    end,
    ['description'] = 'Returns the nth element',
    ['args_schema'] = {ts.number + ts.string / tonumber}
  },
  ['take_n'] = {
    ['types'] = {
      ['list'] = true,
    },
    ['process'] = function(inp, t, args)
      return fun.take_n(args[1] or 1, inp),t
    end,
    ['description'] = 'Returns the n first elements',
    ['args_schema'] = {ts.number + ts.string / tonumber}
  },
  ['drop_n'] = {
    ['types'] = {
      ['list'] = true,
    },
    ['process'] = function(inp, t, args)
      return fun.drop_n(args[1] or 1, inp),t
    end,
    ['description'] = 'Returns list without the first n elements',
    ['args_schema'] = {ts.number + ts.string / tonumber}
  },
  -- Joins strings into a single string using separator in the argument
  ['join'] = {
    ['types'] = {
      ['string_list'] = true
    },
    ['process'] = function(inp, _, args)
      return table.concat(fun.totable(inp), args[1] or ''), 'string'
    end,
    ['description'] = 'Joins strings into a single string using separator in the argument',
    ['args_schema'] = {ts.string:is_optional()}
  },
  -- Sort strings
  ['sort'] = {
    ['types'] = {
      ['list'] = true
    },
    ['process'] = function(inp, t, _)
      table.sort(inp)
      return inp, t
    end,
    ['description'] = 'Sort strings lexicographically',
  },
  -- Return unique elements based on hashing (can work without sorting)
  ['uniq'] = {
    ['types'] = {
      ['list'] = true
    },
    ['process'] = function(inp, t, _)
      local tmp = {}
      fun.each(function(val)
        tmp[val] = true
      end, inp)

      return fun.map(function(k, _) return k end, tmp), t
    end,
    ['description'] = 'Returns a list of unique elements (using a hash table)',
  },
  -- Create a digest from string or a list of strings
  ['digest'] = {
    ['types'] = {
      ['string'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _, args)
      return common.create_digest(inp, args),'string'
    end,
    ['description'] = [[Create a digest from a string.
The first argument is encoding (`hex`, `base32` (and forms `bleach32`, `rbase32`), `base64`),
the second argument is optional hash type (`blake2`, `sha256`, `sha1`, `sha512`, `md5`)]],
    ['args_schema'] = common.digest_schema()
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
    ['description'] = 'Extracts substring; the first argument is start, the second is the last (like in Lua)',
    ['args_schema'] = {(ts.number + ts.string / tonumber):is_optional(),
                       (ts.number + ts.string / tonumber):is_optional()}
  },
  -- Prepends a string or a strings list
  ['prepend'] = {
    ['types'] = {
      ['string'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _, args)
      local prepend = table.concat(args, '')

      return prepend .. inp, 'string'
    end,
    ['description'] = 'Prepends a string or a strings list',
  },
  -- Appends a string or a strings list
  ['append'] = {
    ['types'] = {
      ['string'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _, args)
      local append = table.concat(args, '')

      return inp .. append, 'string'
    end,
    ['description'] = 'Appends a string or a strings list',
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
        -- Map all results in a single list
        local flattened_table = {}
        local function flatten_table(tbl)
          for _, v in ipairs(tbl) do
            if type(v) == 'table' then
              flatten_table(v)
            else
              table.insert(flattened_table, v)
            end
          end
        end
        flatten_table(res)
        return flattened_table,'string_list'
      end

      return nil
    end,
    ['description'] = 'Regexp matching, returns all matches flattened in a single list',
    ['args_schema'] = {ts.string}
  },
  -- Returns a value if it exists in some map (or acts like a `filter` function)
  ['filter_map'] = {
    ['types'] = {
      ['string'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, t, args)
      local map = maps[args[1]]

      if not map then
        logger.errx('invalid map name: %s', args[1])
        return nil
      end

      local res = map:get_key(inp)

      if res then
        return inp,t
      end

      return nil
    end,
    ['description'] = 'Returns a value if it exists in some map (or acts like a `filter` function)',
    ['args_schema'] = {ts.string}
  },
  -- Returns a value if it exists in some map (or acts like a `filter` function)
  ['except_map'] = {
    ['types'] = {
      ['string'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, t, args)
      local map = maps[args[1]]

      if not map then
        logger.errx('invalid map name: %s', args[1])
        return nil
      end

      local res = map:get_key(inp)

      if not res then
        return inp,t
      end

      return nil
    end,
    ['description'] = 'Returns a value if it does not exists in some map (or acts like a `except` function)',
    ['args_schema'] = {ts.string}
  },
  -- Returns a value from some map corresponding to some key (or acts like a `map` function)
  ['apply_map'] = {
    ['types'] = {
      ['string'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, t, args)
      local map = maps[args[1]]

      if not map then
        logger.errx('invalid map name: %s', args[1])
        return nil
      end

      local res = map:get_key(inp)

      if res then
        return res,t
      end

      return nil
    end,
    ['description'] = 'Returns a value from some map corresponding to some key (or acts like a `map` function)',
    ['args_schema'] = {ts.string}
  },
  -- Drops input value and return values from function's arguments or an empty string
  ['id'] = {
    ['types'] = {
      ['string'] = true,
      ['list'] = true,
    },
    ['map_type'] = 'string',
    ['process'] = function(_, _, args)
      if args[1] and args[2] then
        return fun.map(tostring, args),'string_list'
      elseif args[1] then
        return args[1],'string'
      end

      return '','string'
    end,
    ['description'] = 'Drops input value and return values from function\'s arguments or an empty string',
    ['args_schema'] = (ts.string + ts.array_of(ts.string)):is_optional()
  },
  ['equal'] = {
    ['types'] = {
      ['string'] = true,
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _, args)
      if inp == args[1] then
        return inp,'string'
      end

      return nil
    end,
    ['description'] = [[Boolean function equal.
Returns either nil or its argument if input is equal to argument]],
    ['args_schema'] = {ts.string}
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
    ['args_schema'] = ts.array_of(ts.string)
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
    ['args_schema'] = ts.array_of(ts.string)
  },
  ['inverse'] = {
    ['types'] = {
      ['string'] = true,
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _, args)
      if inp then
        return nil
      else
        return (args[1] or 'true'),'string'
      end
    end,
    ['description'] = [[Inverses input.
Empty string comes the first argument or 'true', non-empty string comes nil]],
    ['args_schema'] = {ts.string:is_optional()}
  },
  ['ipmask'] = {
    ['types'] = {
      ['string'] = true,
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _, args)
      local rspamd_ip = require "rspamd_ip"
      -- Non optimal: convert string to an IP address
      local ip = rspamd_ip.from_string(inp)

      if not ip or not ip:is_valid() then
        lua_util.debugm(M, "cannot convert %s to IP", inp)
        return nil
      end

      if ip:get_version() == 4 then
        local mask = tonumber(args[1])

        return ip:apply_mask(mask):to_string(),'string'
      else
        -- IPv6 takes the second argument or the first one...
        local mask_str = args[2] or args[1]
        local mask = tonumber(mask_str)

        return ip:apply_mask(mask):to_string(),'string'
      end
    end,
    ['description'] = 'Applies mask to IP address.' ..
      ' The first argument is the mask for IPv4 addresses, the second is the mask for IPv6 addresses.',
    ['args_schema'] = {(ts.number + ts.string / tonumber),
                       (ts.number + ts.string / tonumber):is_optional()}
  },
  -- Returns the string(s) with all non ascii chars replaced
  ['to_ascii'] = {
    ['types'] = {
      ['string'] = true,
      ['list'] = true,
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _, args)
      if type(inp) == 'table' then
        return fun.map(
          function(s)
            return string.gsub(tostring(s), '[\128-\255]', args[1] or '?')
          end, inp), 'string_list'
      else
        return string.gsub(tostring(inp), '[\128-\255]', '?'), 'string'
      end
    end,
    ['description'] = 'Returns the string with all non-ascii bytes replaced with the character ' ..
      'given as second argument or `?`',
    ['args_schema'] = {ts.string:is_optional()}
  },
  -- Extracts tld from a hostname
  ['get_tld'] = {
    ['types'] = {
      ['string'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _, _)
      return rspamd_util.get_tld(inp),'string'
    end,
    ['description'] = 'Extracts tld from a hostname represented as a string',
    ['args_schema'] = {}
  },
  -- Converts list of strings to numbers and returns a packed string
  ['pack_numbers'] = {
    ['types'] = {
      ['string_list'] = true
    },
    ['map_type'] = 'string',
    ['process'] = function(inp, _, args)
      local fmt = args[1] or 'f'
      local res = {}
      for _, s in ipairs(inp) do
        table.insert(res, tonumber(s))
      end
      return rspamd_util.pack(string.rep(fmt, #res), lua_util.unpack(res)), 'string'
    end,
    ['description'] = 'Converts a list of strings to numbers & returns a packed string',
    ['args_schema'] = {ts.string:is_optional()}
  },
  -- Filter nils from a list
  ['filter_string_nils'] = {
    ['types'] = {
      ['string_list'] = true
    },
    ['process'] = function(inp, _, _)
      return fun.filter(function(val) return type(val) == 'string' and val ~= 'nil' end, inp), 'string_list'
    end,
    ['description'] = 'Removes all nils from a list of strings (when converted implicitly)',
    ['args_schema'] = {}
  },
}

transform_function.match = transform_function.regexp

return transform_function
