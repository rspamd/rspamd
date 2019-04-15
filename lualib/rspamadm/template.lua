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

local argparse = require "argparse"


-- Define command line options
local parser = argparse()
    :name "rspamadm template"
    :description "Apply jinja templates for strings/files"
    :help_description_margin(30)
parser:argument "file"
      :description "File to process"
      :argname "<file>"
      :args "*"

parser:flag "-n --no-vars"
      :description "Don't add Rspamd internal variables"
parser:option "-e --env"
      :description "Load additional environment vars from specific file (name=value)"
      :argname "<filename>"
      :count "*"
parser:option "-l --lua-env"
      :description "Load additional environment vars from specific file (lua source)"
      :argname "<filename>"
      :count "*"
parser:mutex(
    parser:option "-s --suffix"
          :description "Store files with the new suffix"
          :argname "<suffix>",
    parser:flag "-i --inplace"
      :description "Replace input file(s)"
)

local lua_util = require "lua_util"

local function set_env(opts, env)
  if opts.env then
    for _,fname in ipairs(opts.env) do
      for kv in assert(io.open(fname)):lines() do
        if not kv:match('%s*#.*') then
          local k,v = kv:match('([^=%s]+)%s*=%s*(.+)')

          if k and v then
            env[k] = v
          else
            io.write(string.format('invalid env line in %s: %s\n', fname, kv))
          end
        end
      end
    end
  end

  if opts.lua_env then
    for _,fname in ipairs(opts.env) do
      local ret,res_or_err = pcall(loadfile(fname))

      if not ret then
        io.write(string.format('cannot load %s: %s\n', fname, res_or_err))
      else
        if type(res_or_err) == 'table' then
          for k,v in pairs(res_or_err) do
            env[k] = lua_util.deepcopy(v)
          end
        else
          io.write(string.format('cannot load %s: not a table\n', fname))
        end
      end
    end
  end
end

local function read_file(file)
  local content
  if file == '-' then
    content = io.read("*all")
  else
    local f = assert(io.open(file, "rb"))
    content = f:read("*all")
    f:close()
  end
  return content
end

local function handler(args)
  local opts = parser:parse(args)
  local env = {}
  set_env(opts, env)

  if not opts.file or #opts.file == 0 then opts.file = {'-'} end
  for _,fname in ipairs(opts.file) do
    local content = read_file(fname)
    local res = lua_util.jinja_template(content, env, opts.no_vars)

    if opts.inplace then
      local nfile = string.format('%s.new', fname)
      local out = assert(io.open(nfile, 'w'))
      out:write(content)
      out:close()
      os.rename(nfile, fname)
    elseif opts.suffix then
      local nfile = string.format('%s.%s', opts.suffix)
      local out = assert(io.open(nfile, 'w'))
      out:write(content)
      out:close()
    else
      io.write(res)
    end
  end
end

return {
  handler = handler,
  description = parser._description,
  name = 'template'
}