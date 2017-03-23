--[[
Copyright (c) 2011-2015, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- This is main lua config file for rspamd

config['regexp'] = {}

local local_conf = rspamd_paths['CONFDIR']
local local_rules = rspamd_paths['RULESDIR']

dofile(local_rules .. '/global_functions.lua')
dofile(local_rules .. '/regexp/headers.lua')
dofile(local_rules .. '/regexp/misc.lua')
dofile(local_rules .. '/regexp/upstream_spam_filters.lua')
dofile(local_rules .. '/regexp/compromised_hosts.lua')
dofile(local_rules .. '/html.lua')
dofile(local_rules .. '/headers_checks.lua')
dofile(local_rules .. '/subject_checks.lua')
dofile(local_rules .. '/misc.lua')
dofile(local_rules .. '/http_headers.lua')
dofile(local_rules .. '/forwarding.lua')
dofile(local_rules .. '/mid.lua')

local function file_exists(filename)
	local file = io.open(filename)
	if file then
		io.close(file)
		return true
	else
		return false
	end
end

if file_exists(local_conf .. '/rspamd.local.lua') then
	dofile(local_conf .. '/rspamd.local.lua')
else
	-- Legacy lua/rspamd.local.lua
	if file_exists(local_conf .. '/lua/rspamd.local.lua') then
		dofile(local_conf .. '/lua/rspamd.local.lua')
	end
end

if file_exists(local_rules .. '/rspamd.classifiers.lua') then
	dofile(local_rules .. '/rspamd.classifiers.lua')
end
