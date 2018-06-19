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
--local rspamd_util = require "rspamd_util"
local rspamd_task = require "rspamd_task"
local rspamd_logger = require "rspamd_logger"
local lua_meta = require "lua_meta"
local rspamd_url = require "rspamd_url"
local lua_util = require "lua_util"
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
      :argname("<file>")
      :default(rspamd_paths["CONFDIR"] .. "/" .. "rspamd.conf")

-- Extract subcommand
local extract = parser:command "extract ex e"
                      :description "Extracts data from MIME messages"
extract:argument "file"
       :description "File to process"
       :argname "<file>"
       :args "+"

extract:mutex(
    extract:flag "-t --text"
           :description "Extracts plain text data from a message",
    extract:flag "-H --html"
           :description "Extracts htm data from a message"
)
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
extract:flag "--no-file"
    :description "Do not print filename"

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
stat:flag "--no-file"
    :description "Do not print filename"

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
    urls:flag "-j --json"
        :description "Full JSON output"

)
urls:flag "-u --unique"
    :description "Print only unique urls"
urls:flag "-s --sort"
    :description "Sort output"
urls:flag "-c --count"
    :description "Print count of each printed element"
urls:flag "-r --reverse"
    :description "Reverse sort order"
urls:flag "--no-file"
    :description "Do not print filename"


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
    parser:error('no file specified')
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

local function extract_handler(opts)
  for _,fname in ipairs(opts.file) do
    local task = load_task(opts, fname)

    maybe_print_fname(opts, fname)

    if opts.text or opts.html then
      local tp = task:get_text_parts() or {}

      for _,part in ipairs(tp) do
        local how = opts.output
        if opts.text and not part:is_html() then
          part:get_content(how):write()
          io.write('\n')
        elseif opts.html and part:is_html() then
          part:get_content(how):write()
          io.write('\n')
        end
      end
    end

    task:destroy() -- No automatic dtor
  end
end

local function stat_handler(opts)
  load_config(opts)
  rspamd_url.init(rspamd_config:get_tld_path())
  rspamd_config:init_subsystem('langdet,stat') -- Needed to gen stat tokens

  for i,fname in ipairs(opts.file) do
    local task = load_task(opts, fname)

    maybe_print_fname(opts, fname)
    if opts.meta then
      local mt = lua_meta.gen_metatokens_table(task)
      for k,v in pairs(mt) do
        rspamd_logger.messagex('%s = %s', k, v)
      end
    elseif opts.bayes then
      local bt = task:get_stat_tokens()
      for _,t in ipairs(bt) do
        rspamd_logger.messagex('%s', t)
      end
    end

    task:destroy() -- No automatic dtor

    if i > 1 then
      rspamd_logger.messagex('')
    end
  end
end

local function urls_handler(opts)
  load_config(opts)
  rspamd_url.init(rspamd_config:get_tld_path())

  if opts.json then rspamd_logger.messagex('[') end

  for i,fname in ipairs(opts.file) do
    maybe_print_fname(opts, fname)
    if opts.json then rspamd_logger.messagex('{"file":"%s",', fname) end
    local task = load_task(opts)
    local elts = {}

    local function process_url(u)
      local s
      if opts.tld then
        s = u:get_tld()
      elseif opts.host then
        s = u:get_host()
      elseif opts.json then
        s = u:get_text()
      else
        s = u:get_text()
      end

      if opts.unique then
        if elts[s] then
          elts[s].count = elts[s].count + 1
        else
          elts[s] = {
            count = 1,
            url = u
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
            rspamd_logger.messagex('%s : %s', s, u.count)
          else
            rspamd_logger.messagex('%s', s)
          end
        else
          local tb = u.url:to_table()
          tb.count = u.count
          table.insert(json_elts, tb)
        end
      else
        -- s is index, u is url or string
        if opts.json then
          local tb = u:to_table()
          table.insert(json_elts, tb)
        else
          rspamd_logger.messagex('%s', u)
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

    if opts.json then
      rspamd_logger.messagex('"urls": %s', ucl.to_format(json_elts, 'json'))
    end

    if opts.json then
      if i == #opts.file then
        rspamd_logger.messagex('}')
      else
        rspamd_logger.messagex('},')
      end
    end

    task:destroy() -- No automatic dtor
  end
  if opts.json then rspamd_logger.messagex(']') end
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