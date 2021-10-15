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

local argparse = require "argparse"
local ansicolors = require "ansicolors"
local rspamd_util = require "rspamd_util"
local rspamd_task = require "rspamd_task"
local rspamd_logger = require "rspamd_logger"
local lua_meta = require "lua_meta"
local rspamd_url = require "rspamd_url"
local lua_util = require "lua_util"
local lua_mime = require "lua_mime"
local ucl = require "ucl"

-- Define command line options
local parser = argparse()
    :name "rspamadm mime"
    :description "Mime manipulations provided by Rspamd"
    :help_description_margin(30)
    :command_target("command")
    :require_command(true)

parser:option "-c --config"
      :description "Path to config file"
      :argname("<cfg>")
      :default(rspamd_paths["CONFDIR"] .. "/" .. "rspamd.conf")
parser:mutex(
    parser:flag "-j --json"
          :description "JSON output",
    parser:flag "-U --ucl"
          :description "UCL output",
    parser:flag "-M --messagepack"
        :description "MessagePack output"
)
parser:flag "-C --compact"
      :description "Use compact format"
parser:flag "--no-file"
      :description "Do not print filename"

-- Extract subcommand
local extract = parser:command "extract ex e"
                      :description "Extracts data from MIME messages"
extract:argument "file"
       :description "File to process"
       :argname "<file>"
       :args "+"

extract:flag "-t --text"
       :description "Extracts plain text data from a message"
extract:flag "-H --html"
       :description "Extracts htm data from a message"
extract:option "-o --output"
       :description "Output format ('raw', 'content', 'oneline', 'decoded', 'decoded_utf')"
       :argname("<type>")
       :convert {
          raw = "raw",
          content = "content",
          oneline = "content_oneline",
          decoded = "raw_parsed",
          decoded_utf = "raw_utf"
       }
       :default "content"
extract:flag "-w --words"
       :description "Extracts words"
extract:flag "-p --part"
       :description "Show part info"
extract:flag "-s --structure"
       :description "Show structure info (e.g. HTML tags)"
extract:flag "-i --invisible"
       :description "Show invisible content for HTML parts"
extract:option "-F --words-format"
       :description "Words format ('stem', 'norm', 'raw', 'full')"
       :argname("<type>")
       :convert {
          stem = "stem",
          norm = "norm",
          raw = "raw",
          full = "full",
       }
       :default "stem"


local stat = parser:command "stat st s"
                    :description "Extracts statistical data from MIME messages"
stat:argument "file"
    :description "File to process"
    :argname "<file>"
    :args "+"
stat:mutex(
    stat:flag "-m --meta"
        :description "Lua metatokens",
    stat:flag "-b --bayes"
        :description "Bayes tokens",
    stat:flag "-F --fuzzy"
        :description "Fuzzy hashes"
)
stat:flag "-s --shingles"
    :description "Show shingles for fuzzy hashes"

local urls = parser:command "urls url u"
                   :description "Extracts URLs from MIME messages"
urls:argument "file"
    :description "File to process"
    :argname "<file>"
    :args "+"
urls:mutex(
    urls:flag "-t --tld"
        :description "Get TLDs only",
    urls:flag "-H --host"
        :description "Get hosts only",
    urls:flag "-f --full"
      :description "Show piecewise urls as processed by Rspamd"
)

urls:flag "-u --unique"
    :description "Print only unique urls"
urls:flag "-s --sort"
    :description "Sort output"
urls:flag "--count"
    :description "Print count of each printed element"
urls:flag "-r --reverse"
    :description "Reverse sort order"

local modify = parser:command "modify mod m"
                   :description "Modifies MIME message"
modify:argument "file"
      :description "File to process"
      :argname "<file>"
      :args "+"

modify:option "-a --add-header"
      :description "Adds specific header"
      :argname "<header=value>"
      :count "*"
modify:option "-r --remove-header"
      :description "Removes specific header (all occurrences)"
      :argname "<header>"
      :count "*"
modify:option "-R --rewrite-header"
      :description "Rewrites specific header, uses Lua string.format pattern"
      :argname "<header=pattern>"
      :count "*"
modify:option "-t --text-footer"
      :description "Adds footer to text/plain parts from a specific file"
      :argname "<file>"
modify:option "-H --html-footer"
      :description "Adds footer to text/html parts from a specific file"
      :argname "<file>"

local sign = parser:command "sign"
                     :description "Performs DKIM signing"
sign:argument "file"
      :description "File to process"
      :argname "<file>"
      :args "+"

sign:option "-d --domain"
    :description "Use specific domain"
    :argname "<domain>"
    :count "1"
sign:option "-s --selector"
    :description "Use specific selector"
    :argname "<selector>"
    :count "1"
sign:option "-k --key"
    :description "Use specific key of file"
    :argname "<key>"
    :count "1"
sign:option "-t type"
    :description "ARC or DKIM signing"
    :argname("<arc|dkim>")
    :convert {
      ['arc'] = 'arc',
      ['dkim'] = 'dkim',
    }
    :default 'dkim'
sign:option "-o --output"
    :description "Output format"
    :argname("<message|signature>")
    :convert {
      ['message'] = 'message',
      ['signature'] = 'signature',
    }
    :default 'message'

local dump = parser:command "dump"
                   :description "Dumps a raw message in different formats"
dump:argument "file"
    :description "File to process"
    :argname "<file>"
    :args "+"
-- Duplicate format for convenience
dump:mutex(
    parser:flag "-j --json"
          :description "JSON output",
    parser:flag "-U --ucl"
          :description "UCL output",
    parser:flag "-M --messagepack"
          :description "MessagePack output"
)

local function load_config(opts)
  local _r,err = rspamd_config:load_ucl(opts['config'])

  if not _r then
    rspamd_logger.errx('cannot parse %s: %s', opts['config'], err)
    os.exit(1)
  end

  _r,err = rspamd_config:parse_rcl({'logging', 'worker'})
  if not _r then
    rspamd_logger.errx('cannot process %s: %s', opts['config'], err)
    os.exit(1)
  end
end

local function load_task(opts, fname)
  if not fname then
    fname = '-'
  end

  local res,task = rspamd_task.load_from_file(fname, rspamd_config)

  if not res then
    parser:error(string.format('cannot read message from %s: %s', fname,
        task))
  end

  if not task:process_message() then
    parser:error(string.format('cannot read message from %s: %s', fname,
        'failed to parse'))
  end

  return task
end

local function highlight(fmt, ...)
  return ansicolors.white .. string.format(fmt, ...) .. ansicolors.reset
end

local function maybe_print_fname(opts, fname)
  if not opts.json and not opts['no-file'] then
    rspamd_logger.messagex(highlight('File: %s', fname))
  end
end

local function output_fmt(opts)
  local fmt = 'json'
  if opts.compact then fmt = 'json-compact' end
  if opts.ucl then fmt = 'ucl' end
  if opts.messagepack then fmt = 'msgpack' end

  return fmt
end

-- Print elements in form
-- filename -> table of elements
local function print_elts(elts, opts, func)
  local fun = require "fun"

  if opts.json or opts.ucl then
    io.write(ucl.to_format(elts, output_fmt(opts)))
  else
    fun.each(function(fname, elt)

      if not opts.json and not opts.ucl then
        if func then
          elt = fun.map(func, elt)
        end
        maybe_print_fname(opts, fname)
        fun.each(function(e)
          io.write(e)
          io.write("\n")
        end, elt)
      end
    end, elts)
  end
end

local function extract_handler(opts)
  local out_elts = {}
  local tasks = {}
  local process_func

  if opts.words then
    -- Enable stemming and urls detection
    load_config(opts)
    rspamd_url.init(rspamd_config:get_tld_path())
    rspamd_config:init_subsystem('langdet')
  end

  local function maybe_print_text_part_info(part, out)
    local fun = require "fun"
    if opts.part then
      local t = 'plain text'
      if part:is_html() then
        t = 'html'
      end

      if not opts.json and not opts.ucl then
        table.insert(out,
            rspamd_logger.slog('Part: %s: %s, language: %s, size: %s (%s raw), words: %s',
            part:get_mimepart():get_digest():sub(1,8),
            t,
            part:get_language(),
            part:get_length(), part:get_raw_length(),
            part:get_words_count()))
        table.insert(out,
            rspamd_logger.slog('Stats: %s',
            fun.foldl(function(acc, k, v)
              if acc ~= '' then
                return string.format('%s, %s:%s', acc, k, v)
              else
                return string.format('%s:%s', k,v)
              end
            end, '', part:get_stats())))
      end
    end
  end

  local function maybe_print_mime_part_info(part, out)
    if opts.part then

      if not opts.json and not opts.ucl then
        local mtype,msubtype = part:get_type()
        local det_mtype,det_msubtype = part:get_detected_type()
        table.insert(out,
            rspamd_logger.slog('Mime Part: %s: %s/%s (%s/%s detected), filename: %s (%s detected ext), size: %s',
                part:get_digest():sub(1,8),
                mtype, msubtype,
                det_mtype, det_msubtype,
                part:get_filename(),
                part:get_detected_ext(),
                part:get_length()))
      end
    end
  end

  local function print_words(words, full)
    local fun = require "fun"

    if not full then
      return table.concat(words, ' ')
    else
      return table.concat(
          fun.totable(
              fun.map(function(w)
                -- [1] - stemmed word
                -- [2] - normalised word
                -- [3] - raw word
                -- [4] - flags (table of strings)
                return string.format('%s|%s|%s(%s)',
                    w[3], w[2], w[1], table.concat(w[4], ','))
              end, words)
          ),
          ' '
      )
    end
  end

  for _,fname in ipairs(opts.file) do
    local task = load_task(opts, fname)
    out_elts[fname] = {}

    if not opts.text and not opts.html then
      opts.text = true
      opts.html = true
    end

    if opts.words then
      local howw = opts['words_format'] or 'stem'
      table.insert(out_elts[fname], 'meta_words: ' ..
          print_words(task:get_meta_words(howw), howw == 'full'))
    end

    if opts.text or opts.html then
      local mp = task:get_parts() or {}

      for _,mime_part in ipairs(mp) do
        local how = opts.output
        local part
        if mime_part:is_text() then part = mime_part:get_text() end

        if part and opts.text and not part:is_html() then
          maybe_print_text_part_info(part, out_elts[fname])
          maybe_print_mime_part_info(mime_part, out_elts[fname])
          if not opts.json and not opts.ucl then
            table.insert(out_elts[fname], '\n')
          end

          if opts.words then
            local howw = opts['words_format'] or 'stem'
            table.insert(out_elts[fname], print_words(part:get_words(howw),
                howw == 'full'))
          else
            table.insert(out_elts[fname], tostring(part:get_content(how)))
          end
        elseif part and opts.html and part:is_html() then
          maybe_print_text_part_info(part, out_elts[fname])
          maybe_print_mime_part_info(mime_part, out_elts[fname])
          if not opts.json and not opts.ucl then
            table.insert(out_elts[fname], '\n')
          end

          if opts.words then
            local howw = opts['words_format'] or 'stem'
            table.insert(out_elts[fname], print_words(part:get_words(howw),
                howw == 'full'))
          else
            if opts.structure then
              local hc = part:get_html()
              local res = {}
              process_func = function(elt)
                local fun = require "fun"
                if type(elt) == 'table' then
                  return table.concat(fun.totable(
                      fun.map(
                          function(t)
                            return rspamd_logger.slog("%s", t)
                          end,
                          elt)), '\n')
                else
                  return rspamd_logger.slog("%s", elt)
                end
              end

              hc:foreach_tag('any', function(tag)
                  local elt = {}
                  local ex = tag:get_extra()
                  elt.tag = tag:get_type()
                  if ex then
                    elt.extra = ex
                  end
                  local content = tag:get_content()
                  if content then
                    elt.content = tostring(content)
                  end
                  local style = tag:get_style()
                  if style then
                    elt.style = style
                  end
                  table.insert(res, elt)
              end)
              table.insert(out_elts[fname], res)
            else -- opts.structure
              table.insert(out_elts[fname], tostring(part:get_content(how)))
            end
            if opts.invisible then
              local hc = part:get_html()
              table.insert(out_elts[fname], string.format('invisible content: %s',
                  tostring(hc:get_invisible())))
            end
          end
        end

        if not part then
          maybe_print_mime_part_info(mime_part, out_elts[fname])
        end
      end
    end

    table.insert(out_elts[fname], "")
    table.insert(tasks, task)
  end

  print_elts(out_elts, opts, process_func)
  -- To avoid use after free we postpone tasks destruction
  for _,task in ipairs(tasks) do task:destroy() end
end

local function stat_handler(opts)
  local fun = require "fun"
  local out_elts = {}

  load_config(opts)
  rspamd_url.init(rspamd_config:get_tld_path())
  rspamd_config:init_subsystem('langdet,stat') -- Needed to gen stat tokens

  local process_func

  for _,fname in ipairs(opts.file) do
    local task = load_task(opts, fname)
    out_elts[fname] = {}

    if opts.meta then
      local mt = lua_meta.gen_metatokens_table(task)
      out_elts[fname] = mt
      process_func = function(k, v)
        return string.format("%s = %s", k, v)
      end
    elseif opts.bayes then
      local bt = task:get_stat_tokens()
      out_elts[fname] = bt
      process_func = function(e)
        return string.format('%s (%d): "%s"+"%s", [%s]', e.data, e.win, e.t1 or "",
            e.t2 or "", table.concat(fun.totable(
                fun.map(function(k) return k end, e.flags)), ","))
      end
    elseif opts.fuzzy then
      local parts = task:get_parts() or {}
      out_elts[fname] = {}
      process_func = function(e)
        local ret = string.format('part: %s(%s): %s', e.type, e.file or "", e.digest)
        if opts.shingles and e.shingles then
          local sgl = {}
          for _,s in ipairs(e.shingles) do
            table.insert(sgl, string.format('%s: %s+%s+%s', s[1], s[2], s[3], s[4]))
          end

          ret = ret .. '\n' .. table.concat(sgl, '\n')
        end
        return ret
      end
      for _,part in ipairs(parts) do
        if not part:is_multipart() then
          local text = part:get_text()

          if text then
            local digest,shingles = text:get_fuzzy_hashes(task:get_mempool())
            table.insert(out_elts[fname], {
              digest = digest,
              shingles = shingles,
              type = string.format('%s/%s',
                  ({part:get_type()})[1],
                  ({part:get_type()})[2])
            })
          else
            table.insert(out_elts[fname], {
              digest = part:get_digest(),
              file = part:get_filename(),
              type = string.format('%s/%s',
                  ({part:get_type()})[1],
                  ({part:get_type()})[2])
            })
          end
        end
      end
    end

    task:destroy() -- No automatic dtor
  end

  print_elts(out_elts, opts, process_func)
end

local function urls_handler(opts)
  load_config(opts)
  rspamd_url.init(rspamd_config:get_tld_path())
  local out_elts = {}

  if opts.json then rspamd_logger.messagex('[') end

  for _,fname in ipairs(opts.file) do
    out_elts[fname] = {}
    local task = load_task(opts, fname)
    local elts = {}

    local function process_url(u)
      local s
      if opts.tld then
        s = u:get_tld()
      elseif opts.host then
        s = u:get_host()
      elseif opts.full then
        s = rspamd_logger.slog('%s: %s', u:get_text(), u:to_table())
      else
        s = u:get_text()
      end

      if opts.unique then
        if elts[s] then
          elts[s].count = elts[s].count + 1
        else
          elts[s] = {
            count = 1,
            url = u:to_table()
          }
        end
      else
        if opts.json then
          table.insert(elts, u)
        else
          table.insert(elts, s)
        end
      end
    end

    for _,u in ipairs(task:get_urls(true)) do
      process_url(u)
    end

    local json_elts = {}

    local function process_elt(s, u)
      if opts.unique then
        -- s is string, u is {url = url, count = count }
        if not opts.json then
          if opts.count then
            table.insert(json_elts, string.format('%s : %s', s, u.count))
          else
            table.insert(json_elts, s)
          end
        else
          local tb = u.url
          tb.count = u.count
          table.insert(json_elts, tb)
        end
      else
        -- s is index, u is url or string
        if opts.json then
          table.insert(json_elts, u)
        else
          table.insert(json_elts, u)
        end
      end
    end

    if opts.sort then
      local sfunc
      if opts.unique then
        sfunc = function(t, a, b)
          if t[a].count ~= t[b].count then
            if opts.reverse then
              return t[a].count > t[b].count
            else
              return t[a].count < t[b].count
            end
          else
            -- Sort lexicography
            if opts.reverse then
              return a > b
            else
              return a < b
            end
          end
        end
      else
        sfunc = function(t, a, b)
          local va, vb
          if opts.json then
            va = t[a]:get_text()
            vb = t[b]:get_text()
          else
            va = t[a]
            vb = t[b]
          end
          if opts.reverse then
            return va > vb
          else
            return va < vb
          end
        end
      end


      for s,u in lua_util.spairs(elts, sfunc) do
        process_elt(s, u)
      end
    else
      for s,u in pairs(elts) do
        process_elt(s, u)
      end
    end

    out_elts[fname] = json_elts

    task:destroy() -- No automatic dtor
  end

  print_elts(out_elts, opts)
end

local function newline(task)
  local t = task:get_newlines_type()

  if t == 'cr' then
    return '\r'
  elseif t == 'lf' then
    return '\n'
  end

  return '\r\n'
end

local function modify_handler(opts)
  load_config(opts)
  rspamd_url.init(rspamd_config:get_tld_path())

  local function read_file(file)
    local f = assert(io.open(file, "rb"))
    local content = f:read("*all")
    f:close()
    return content
  end

  local text_footer, html_footer

  if opts['text_footer'] then
    text_footer = read_file(opts['text_footer'])
  end

  if opts['html_footer'] then
    html_footer = read_file(opts['html_footer'])
  end

  for _,fname in ipairs(opts.file) do
    local task = load_task(opts, fname)
    local newline_s = newline(task)
    local seen_cte

    local rewrite = lua_mime.add_text_footer(task, html_footer, text_footer) or {}
    local out = {} -- Start with headers

    local function process_headers_cb(name, hdr)
      for _,h in ipairs(opts['remove_header']) do
        if name:match(h) then
          return
        end
      end

      for _,h in ipairs(opts['rewrite_header']) do
        local hname,hpattern = h:match('^([^=]+)=(.+)$')
        if hname == name then
          local new_value = string.format(hpattern, hdr.decoded)
          new_value = string.format('%s:%s%s',
              name, hdr.separator,
              rspamd_util.fold_header(name,
                  rspamd_util.mime_header_encode(new_value),
                  task:get_newlines_type()))
          out[#out + 1] = new_value
          return
        end
      end

      if rewrite.need_rewrite_ct then
        if name:lower() == 'content-type' then
          local nct = string.format('%s: %s/%s; charset=utf-8',
              'Content-Type', rewrite.new_ct.type, rewrite.new_ct.subtype)
          out[#out + 1] = nct
          return
        elseif name:lower() == 'content-transfer-encoding' then
          out[#out + 1] = string.format('%s: %s',
              'Content-Transfer-Encoding', rewrite.new_cte or 'quoted-printable')
          seen_cte = true
          return
        end
      end

      out[#out + 1] = hdr.raw:gsub('\r?\n?$', '')
    end

    task:headers_foreach(process_headers_cb, {full = true})

    for _,h in ipairs(opts['add_header']) do
      local hname,hvalue = h:match('^([^=]+)=(.+)$')

      if hname and hvalue then
        out[#out + 1] = string.format('%s: %s', hname,
            rspamd_util.fold_header(hname, hvalue, task:get_newlines_type()))
      end
    end

    if not seen_cte and rewrite.need_rewrite_ct then
      out[#out + 1] = string.format('%s: %s',
          'Content-Transfer-Encoding', rewrite.new_cte or 'quoted-printable')
    end

    -- End of headers
    out[#out + 1] = ''

    if rewrite.out then
      for _,o in ipairs(rewrite.out) do
        out[#out + 1] = o
      end
    else
      out[#out + 1] = {task:get_rawbody(), false}
    end

    for _,o in ipairs(out) do
      if type(o) == 'string' then
        io.write(o)
        io.write(newline_s)
      elseif type(o) == 'table' then
        io.flush()
        if type(o[1]) == 'string' then
          io.write(o[1])
        else
          o[1]:save_in_file(1)
        end

        if o[2] then
          io.write(newline_s)
        end
      else
        o:save_in_file(1)
        io.write(newline_s)
      end
    end

    task:destroy() -- No automatic dtor
  end
end

local function sign_handler(opts)
  load_config(opts)
  rspamd_url.init(rspamd_config:get_tld_path())

  local lua_dkim = require("lua_ffi").dkim

  if not lua_dkim then
    io.stderr:write('FFI support is required: please use LuaJIT or install lua-ffi')
    os.exit(1)
  end

  local sign_key
  if rspamd_util.file_exists(opts.key) then
    sign_key = lua_dkim.load_sign_key(opts.key, 'file')
  else
    sign_key = lua_dkim.load_sign_key(opts.key, 'base64')
  end

  if not sign_key then
    io.stderr:write('Cannot load key: ' .. opts.key .. '\n')
    os.exit(1)
  end

  for _,fname in ipairs(opts.file) do
    local task = load_task(opts, fname)
    local ctx = lua_dkim.create_sign_context(task, sign_key, nil, opts.algorithm)

    if not ctx then
      io.stderr:write('Cannot init signing\n')
      os.exit(1)
    end

    local sig = lua_dkim.do_sign(task, ctx, opts.selector, opts.domain)

    if not sig then
      io.stderr:write('Cannot create signature\n')
      os.exit(1)
    end

    if opts.output == 'signature' then
      io.write(sig)
      io.write('\n')
      io.flush()
    else
      local dkim_hdr = string.format('%s: %s%s',
          'DKIM-Signature',
          rspamd_util.fold_header('DKIM-Signature',
              rspamd_util.mime_header_encode(sig),
              task:get_newlines_type()),
          newline(task))
      io.write(dkim_hdr)
      io.flush()
      task:get_content():save_in_file(1)
    end

    task:destroy() -- No automatic dtor
  end
end

local function dump_handler(opts)
  load_config(opts)
  rspamd_url.init(rspamd_config:get_tld_path())

  for _,fname in ipairs(opts.file) do
    local task = load_task(opts, fname)

    if opts.ucl or opts.json or opts.messagepack then
      local ucl_object = lua_mime.message_to_ucl(task)
      io.write(ucl.to_format(ucl_object, output_fmt(opts)))
    else
      task:get_content():save_in_file(1)
    end

    task:destroy() -- No automatic dtor
  end
end

local function handler(args)
  local opts = parser:parse(args)

  local command = opts.command

  if type(opts.file) == 'string' then
    opts.file = {opts.file}
  elseif type(opts.file) == 'none' then
    opts.file = {}
  end

  if command == 'extract' then
    extract_handler(opts)
  elseif command == 'stat' then
    stat_handler(opts)
  elseif command == 'urls' then
    urls_handler(opts)
  elseif command == 'modify' then
    modify_handler(opts)
  elseif command == 'sign' then
    sign_handler(opts)
  elseif command == 'dump' then
    dump_handler(opts)
  else
    parser:error('command %s is not implemented', command)
  end
end

return {
  name = 'mime',
  aliases = {'mime_tool'},
  handler = handler,
  description = parser._description
}