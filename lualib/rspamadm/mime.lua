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
local rspamd_util = require "rspamd_util"
local rspamd_task = require "rspamd_task"
local rspamd_logger = require "rspamd_logger"
local lua_meta = require "lua_meta"

-- Define command line options
local parser = argparse()
    :name "rspamadm mime"
    :description "Mime manipulations provided by Rspamd"
    :help_description_margin(30)
    :command_target("command")
    :require_command(true)

-- Extract subcommand
local extract = parser:command "extract ex e"
                      :description "Extracts data from MIME messages"
extract:argument "file"
       :description "File to process"
       :argname "<file>"
       :args "1"

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

local stat = parser:command "stat st s"
                      :description "Extracts statistical data from MIME messages"
stat:argument "file"
       :description "File to process"
       :argname "<file>"
       :args "1"
stat:mutex(
    stat:flag "-m --meta"
        :description "Lua metatokens",
    stat:flag "-b --bayes"
        :description "Bayes tokens",
    stat:flag "-F --fuzzy"
        :description "Fuzzy hashes"
)

local function extract_handler(opts)
  if not opts.file then
    parser:error('no file specified')
  end

  local res,task = rspamd_task.load_from_file(opts.file)

  if not res then
    parser:error(string.format('cannot read message from %s: %s', opts.file,
        task))
  end

  if not task:process_message() then
    parser:error(string.format('cannot read message from %s: %s', opts.file,
        'failed to parse'))
  end

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

local function stat_handler(opts)
  if not opts.file then
    parser:error('no file specified')
  end

  local res,task = rspamd_task.load_from_file(opts.file)

  if not res then
    parser:error(string.format('cannot read message from %s: %s', opts.file,
        task))
  end

  if not task:process_message() then
    parser:error(string.format('cannot read message from %s: %s', opts.file,
        'failed to parse'))
  end

  if opts.meta then
    local mt = lua_meta.gen_metatokens_table(task)
    for k,v in pairs(mt) do
      rspamd_logger.messagex('%s = %s', k, v)
    end
  end

  task:destroy() -- No automatic dtor
end

local function handler(args)
  local opts = parser:parse(args)

  local command = opts.command

  if command == 'extract' then
    extract_handler(opts)
  elseif command == 'stat' then
    stat_handler(opts)
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