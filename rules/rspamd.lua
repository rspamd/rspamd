--[[
Copyright (c) 2011-2015, Vsevolod Stakhov <vsevolod@highsecure.ru>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
]]--

-- This is main lua config file for rspamd

local util = require "rspamd_util"

config['regexp'] = {}
local reconf = config['regexp']

local local_conf = rspamd_paths['CONFDIR']
local local_rules = rspamd_paths['RULESDIR']

dofile(local_rules .. '/regexp/headers.lua')
dofile(local_rules .. '/regexp/lotto.lua')
dofile(local_rules .. '/regexp/fraud.lua')
dofile(local_rules .. '/regexp/drugs.lua')
dofile(local_rules .. '/html.lua')
dofile(local_rules .. '/misc.lua')
dofile(local_rules .. '/http_headers.lua')

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
