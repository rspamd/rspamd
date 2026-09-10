--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>

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

-- XLSX content processor: a thin format binding over the shared OOXML
-- pipeline in lua_content/ooxml.

local ooxml = require "lua_content/ooxml"


local exports = {}

exports.extract = function(package, options, state)
  return ooxml.extract(package, options, state, 'xlsx')
end

exports.process = function(input, mpart, task)
  return ooxml.process_document(input, mpart, task, 'xlsx')
end

exports.config = ooxml.config

return exports
