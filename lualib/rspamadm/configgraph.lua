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

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local rspamd_regexp = require "rspamd_regexp"
local argparse = require "argparse"

-- Define command line options
local parser = argparse()
    :name "rspamadm configgraph"
    :description "Produces graph of Rspamd includes"
    :help_description_margin(30)
parser:option "-c --config"
      :description "Path to config file"
      :argname("<file>")
      :default(rspamd_paths["CONFDIR"] .. "/" .. "rspamd.conf")
parser:flag "-a --all"
      :description('Show all nodes, not just existing ones')


local function process_filename(fname)
  local cdir = rspamd_paths['CONFDIR'] .. '/'
  fname = fname:gsub(cdir, '')
  return fname
end

local function output_dot(opts, nodes, adjastency)
  rspamd_logger.messagex("digraph rspamd {")
  for k,node in pairs(nodes) do
    local attrs = {"shape=box"}
    local skip = false
    if node.exists then
      if node.priority >= 10 then
        attrs[#attrs + 1] = "color=red"
      elseif node.priority > 0 then
        attrs[#attrs + 1] = "color=blue"
      end
    else
      if opts.all then
        attrs[#attrs + 1] = "style=dotted"
      else
        skip = true
      end
    end

    if not skip then
      rspamd_logger.messagex("\"%s\" [%s];", process_filename(k),
          table.concat(attrs, ','))
    end
  end
  for _,adj in ipairs(adjastency) do
    local attrs = {}
    local skip = false

    if adj.to.exists then
      if adj.to.merge then
        attrs[#attrs + 1] = "arrowhead=diamond"
        attrs[#attrs + 1] = "label=\"+\""
      elseif adj.to.priority > 1 then
        attrs[#attrs + 1] = "color=red"
      end
    else
      if opts.all then
        attrs[#attrs + 1] = "style=dotted"
      else
        skip = true
      end
    end

    if not skip then
      rspamd_logger.messagex("\"%s\" -> \"%s\"  [%s];", process_filename(adj.from),
          adj.to.short_path, table.concat(attrs, ','))
    end
  end
  rspamd_logger.messagex("}")
end

local function load_config_traced(opts)
  local glob_traces = {}
  local adjastency = {}
  local nodes = {}

  local function maybe_match_glob(file)
    for _,gl in ipairs(glob_traces) do
      if gl.re:match(file) then
        return gl
      end
    end

    return nil
  end

  local function add_dep(from, node, args)
    adjastency[#adjastency + 1] = {
      from = from,
      to = node,
      args = args
    }
  end

  local function process_node(fname, args)
    local node = nodes[fname]
    if not node then
      node = {
        path = fname,
        short_path = process_filename(fname),
        exists = rspamd_util.file_exists(fname),
        merge = args.duplicate and args.duplicate == 'merge',
        priority = args.priority or 0,
        glob = args.glob,
        try = args.try,
      }
      nodes[fname] = node
    end

    return node
  end

  local function trace_func(cur_file, included_file, args, parent)
    if args.glob then
      glob_traces[#glob_traces + 1] = {
        re = rspamd_regexp.import_glob(included_file, ''),
        parent = cur_file,
        args = args,
        seen = {},
      }
    else
      local node = process_node(included_file, args)
      if opts.all or node.exists then
        local gl_parent = maybe_match_glob(included_file)
        if gl_parent and not gl_parent.seen[cur_file] then
          add_dep(gl_parent.parent, nodes[cur_file], gl_parent.args)
          gl_parent.seen[cur_file] = true
        end
        add_dep(cur_file, node, args)
      end
    end
  end

  local _r,err = rspamd_config:load_ucl(opts['config'], trace_func)
  if not _r then
    rspamd_logger.errx('cannot parse %s: %s', opts['config'], err)
    os.exit(1)
  end

  output_dot(opts, nodes, adjastency)
end


local function handler(args)
  local res = parser:parse(args)

  load_config_traced(res)
end

return {
  handler = handler,
  description = parser._description,
  name = 'configgraph'
}