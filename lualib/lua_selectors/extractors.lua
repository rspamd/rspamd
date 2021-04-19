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
local meta_functions = require "lua_meta"
local lua_util = require "lua_util"
local rspamd_url = require "rspamd_url"
local common = require "lua_selectors/common"
local ts = require("tableshape").types
local E = {}

local url_flags_ts = ts.array_of(ts.one_of(lua_util.keys(rspamd_url.flags))):is_optional()

local function gen_exclude_flags_filter(exclude_flags)
  return function(u)
    local got_flags = u:get_flags()
    for _, flag in ipairs(exclude_flags) do
      if got_flags[flag] then return false end
    end
    return true
  end
end

local extractors = {
  -- Plain id function
  ['id'] = {
    ['get_value'] = function(_, args)
      if args[1] then
        return args[1], 'string'
      end

      return '','string'
    end,
    ['description'] = [[Return value from function's argument or an empty string,
For example, `id('Something')` returns a string 'Something']],
    ['args_schema'] = {ts.string:is_optional()}
  },
  -- Similar but for making lists
  ['list'] = {
    ['get_value'] = function(_, args)
      if args[1] then
        return fun.map(tostring, args), 'string_list'
      end

      return {},'string_list'
    end,
    ['description'] = [[Return a list from function's arguments or an empty list,
For example, `list('foo', 'bar')` returns a list {'foo', 'bar'}]],
  },
  -- Get source IP address
  ['ip'] = {
    ['get_value'] = function(task)
      local ip = task:get_ip()
      if ip and ip:is_valid() then return ip,'userdata' end
      return nil
    end,
    ['description'] = [[Get source IP address]],
  },
  -- Get MIME from
  ['from'] = {
    ['get_value'] = function(task, args)
      local from
      if type(args) == 'table' then
        from = task:get_from(args)
      else
        from = task:get_from(0)
      end
      if ((from or E)[1] or E).addr then
        return from[1],'table'
      end
      return nil
    end,
    ['description'] = [[Get MIME or SMTP from (e.g. `from('smtp')` or `from('mime')`,
uses any type by default)]],
  },
  ['rcpts'] = {
    ['get_value'] = function(task, args)
      local rcpts
      if type(args) == 'table' then
        rcpts = task:get_recipients(args)
      else
        rcpts = task:get_recipients(0)
      end
      if ((rcpts or E)[1] or E).addr then
        return rcpts,'table_list'
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
    ['get_value'] = function(task, args)
      local parts = task:get_parts() or E
      local digests = {}
      for i,p in ipairs(parts) do
        if p:is_attachment() then
          table.insert(digests, common.get_cached_or_raw_digest(task, i, p, args))
        end
      end

      if #digests > 0 then
        return digests,'string_list'
      end

      return nil
    end,
    ['description'] = [[Get list of all attachments digests.
The first optional argument is encoding (`hex`, `base32` (and forms `bleach32`, `rbase32`), `base64`),
the second optional argument is optional hash type (`blake2`, `sha256`, `sha1`, `sha512`, `md5`)]],
    ['args_schema'] = common.digest_schema()

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
  -- Get languages for text parts
  ['languages'] = {
    ['get_value'] = function(task)
      local text_parts = task:get_text_parts() or E
      local languages = {}

      for _,p in ipairs(text_parts) do
        local lang = p:get_language()
        if lang then
          table.insert(languages, lang)
        end
      end

      if #languages > 0 then
        return languages,'string_list'
      end

      return nil
    end,
    ['description'] = 'Get languages for text parts',
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
          return task:get_header_full(args[1], strong),'table_list'
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
    ['args_schema'] = {ts.string,
                       (ts.pattern("strong") + ts.pattern("full")):is_optional()}
  },
  -- Get list of received headers (returns list of tables)
  ['received'] = {
    ['get_value'] = function(task, args)
      local rh = task:get_received_headers()
      if not rh[1] then
        return nil
      end
      if args[1] then
        return fun.map(function(r) return r[args[1]] end, rh), 'string_list'
      end

      return rh,'table_list'
    end,
    ['description'] = [[Get list of received headers.
If no arguments specified, returns list of tables. Otherwise, selects a specific element,
e.g. `by_hostname`]],
  },
  -- Get all urls
  ['urls'] = {
    ['get_value'] = function(task, args)
      local urls = task:get_urls()
      if not urls[1] then
        return nil
      end
      if args[1] then
        return fun.map(function(r) return r[args[1]](r) end, urls), 'string_list'
      end
      return urls,'userdata_list'
    end,
    ['description'] = [[Get list of all urls.
If no arguments specified, returns list of url objects. Otherwise, calls a specific method,
e.g. `get_tld`]],
  },
  -- Get specific urls
  ['specific_urls'] = {
    ['get_value'] = function(task, args)
      local params = args[1] or {}
      params.task = task
      params.no_cache = true
      if params.exclude_flags then
        params.filter = gen_exclude_flags_filter(params.exclude_flags)
      end
      local urls = lua_util.extract_specific_urls(params)
      if not urls[1] then
        return nil
      end
      return urls,'userdata_list'
    end,
    ['description'] = [[Get most specific urls. Arguments are equal to the Lua API function]],
    ['args_schema'] = {ts.shape{
      limit = ts.number + ts.string / tonumber,
      esld_limit = (ts.number + ts.string / tonumber):is_optional(),
      exclude_flags = url_flags_ts,
      flags = url_flags_ts,
      flags_mode = ts.one_of{'explicit'}:is_optional(),
      prefix = ts.string:is_optional(),
      need_content = (ts.boolean + ts.string / lua_util.toboolean):is_optional(),
      need_emails = (ts.boolean + ts.string / lua_util.toboolean):is_optional(),
      need_images = (ts.boolean + ts.string / lua_util.toboolean):is_optional(),
      ignore_redirected = (ts.boolean + ts.string / lua_util.toboolean):is_optional(),
    }}
  },
  -- URLs filtered by flags
  ['urls_filtered'] = {
    ['get_value'] = function(task, args)
      local urls = task:get_urls_filtered(args[1], args[2])
      if not urls[1] then
        return nil
      end
      return urls,'userdata_list'
    end,
    ['description'] = [[Get list of all urls filtered by flags_include/exclude
(see rspamd_task:get_urls_filtered for description)]],
    ['args_schema'] = {ts.array_of{
      url_flags_ts:is_optional(), url_flags_ts:is_optional()
    }}
  },
  -- Get all emails
  ['emails'] = {
    ['get_value'] = function(task, args)
      local urls = task:get_emails()
      if not urls[1] then
        return nil
      end
      if args[1] then
        return fun.map(function(r) return r[args[1]](r) end, urls), 'string_list'
      end
      return urls,'userdata_list'
    end,
    ['description'] = [[Get list of all emails.
If no arguments specified, returns list of url objects. Otherwise, calls a specific method,
e.g. `get_user`]],
  },
  -- Get specific pool var. The first argument must be variable name,
  -- the second argument is optional and defines the type (string by default)
  ['pool_var'] = {
    ['get_value'] = function(task, args)
      local type = args[2] or 'string'
      return task:get_mempool():get_variable(args[1], type),(type)
    end,
    ['description'] = [[Get specific pool var. The first argument must be variable name,
the second argument is optional and defines the type (string by default)]],
    ['args_schema'] = {ts.string, ts.string:is_optional()}
  },
  -- Get value of specific key from task cache
  ['task_cache'] = {
    ['get_value'] = function(task, args)
      local val = task:cache_get(args[1])
      if not val then
        return
      end
      if type(val) == 'table' then
        if not val[1] then
          return
        end
        return val, 'string_list'
      end
      return val, 'string'
    end,
    ['description'] = [[Get value of specific key from task cache. The first argument must be
the key name]],
    ['args_schema'] = {ts.string}
  },
  -- Get specific HTTP request header. The first argument must be header name.
  ['request_header'] = {
    ['get_value'] = function(task, args)
      local hdr = task:get_request_header(args[1])
      if hdr then
        return hdr,'string'
      end

      return nil
    end,
    ['description'] = [[Get specific HTTP request header.
The first argument must be header name.]],
    ['args_schema'] = {ts.string}
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

  The second argument is optional time format, see [os.date](http://pgl.yoyo.org/luai/i/os.date) description]],
    ['args_schema'] = {ts.one_of{'connect', 'message'}:is_optional(),
                       ts.string:is_optional()}
  },
  -- Get text words from a message
  ['words'] = {
    ['get_value'] = function(task, args)
      local how = args[1] or 'stem'
      local tp = task:get_text_parts()

      if tp then
        local rtype = 'string_list'
        if how == 'full' then
          rtype = 'table_list'
        end

        return lua_util.flatten(
            fun.map(function(p)
              return p:get_words(how)
            end, tp)), rtype
      end

      return nil
    end,
    ['description'] = [[Get words from text parts
  - `stem`: stemmed words (default)
  - `raw`: raw words
  - `norm`: normalised words (lowercased)
  - `full`: list of tables
  ]],
    ['args_schema'] = { ts.one_of { 'stem', 'raw', 'norm', 'full' }:is_optional()},
  },
  -- Get queue ID
  ['queueid'] = {
    ['get_value'] = function(task)
      local queueid = task:get_queue_id()
      if queueid then return queueid,'string' end
      return nil
    end,
    ['description'] = [[Get queue ID]],
  },
  -- Get ID of the task being processed
  ['uid'] = {
    ['get_value'] = function(task)
      local uid = task:get_uid()
      if uid then return uid,'string' end
      return nil
    end,
    ['description'] = [[Get ID of the task being processed]],
  },
  -- Get message ID of the task being processed
  ['messageid'] = {
    ['get_value'] = function(task)
      local mid = task:get_message_id()
      if mid then return mid,'string' end
      return nil
    end,
    ['description'] = [[Get message ID]],
  },
  -- Get specific symbol
  ['symbol'] = {
    ['get_value'] = function(task, args)
      local symbol = task:get_symbol(args[1], args[2])
      if symbol then
        return symbol[1],'table'
      end
    end,
    ['description'] = 'Get specific symbol. The first argument must be the symbol name. ' ..
      'The second argument is an optional shadow result name. ' ..
      'Returns the symbol table. See task:get_symbol()',
    ['args_schema'] = {ts.string, ts.string:is_optional()}
  },
  -- Get full scan result
  ['scan_result'] = {
    ['get_value'] = function(task, args)
      local res = task:get_metric_result(args[1])
      if res then
        return res,'table'
      end
    end,
    ['description'] = 'Get full scan result (either default or shadow if shadow result name is specified)' ..
        'Returns the result table. See task:get_metric_result()',
    ['args_schema'] = {ts.string:is_optional()}
  },
  -- Get list of metatokens as strings
  ['metatokens'] = {
    ['get_value'] = function(task)
      local tokens = meta_functions.gen_metatokens(task)
      if not tokens[1] then
        return nil
      end
      local res = {}
      for _, t in ipairs(tokens) do
        table.insert(res, tostring(t))
      end
      return res, 'string_list'
    end,
    ['description'] = 'Get metatokens for a message as strings',
  },
}

return extractors
