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

-- Trie is rspamd module designed to define and operate with suffix trie

local tries = {}
local rspamd_logger = require "rspamd_logger"
local rspamd_trie = require "rspamd_trie"

local function split(str, delim, maxNb)
	-- Eliminate bad cases...
	if string.find(str, delim) == nil then
		return { str }
	end
	if maxNb == nil or maxNb < 1 then
		maxNb = 0    -- No limit
	end
	local result = {}
	local pat = "(.-)" .. delim .. "()"
	local nb = 0
	local lastPos
	for part, pos in string.gmatch(str, pat) do
		nb = nb + 1
		result[nb] = part
		lastPos = pos
		if nb == maxNb then break end
	end
	-- Handle the last field
	if nb ~= maxNb then
		result[nb + 1] = string.sub(str, lastPos)
	end
	return result
end

local function add_trie(params)
	local symbol = params[1]
	
	file = io.open(params[2])
	if file then
		local trie = {}
		trie['trie'] = rspamd_trie.create(true)
		num = 0
		for line in file:lines() do
			trie['trie']:add_pattern(line, num)
			num = num + 1
		end
		
		if type(rspamd_config.get_api_version) ~= 'nil' then
			rspamd_config:register_virtual_symbol(symbol, 1.0)
		end
		file:close()
		trie['symbol'] = symbol
		table.insert(tries, trie)
	else
		local patterns = split(params[2], ',')
		local trie = {}
		trie['trie'] = rspamd_trie.create(true)
		for num,pattern in ipairs(patterns) do
			trie['trie']:add_pattern(pattern, num)
		end
		if type(rspamd_config.get_api_version) ~= 'nil' then
			rspamd_config:register_virtual_symbol(symbol, 1.0)
		end
		trie['symbol'] = symbol
		table.insert(tries, trie)
	end
end

function check_trie(task)
	for _,trie in ipairs(tries) do
		if trie['trie']:search_task(task) then
			task:insert_result(trie['symbol'], 1)
			return
		end
		-- Search inside urls
		urls = task:get_urls()
		if urls then
			for _,url in ipairs(urls) do
				if trie['trie']:search_text(url:get_text()) then
					task:insert_result(trie['symbol'], 1)
					return
				end
			end
		end
	end
end

-- Registration
if type(rspamd_config.get_api_version) ~= 'nil' then
	if rspamd_config:get_api_version() >= 1 then
		rspamd_config:register_module_option('trie', 'rule', 'string')
	end
end

local opts =  rspamd_config:get_all_opt('trie')
if opts then
	local strrules = opts['rule']
	if strrules then
		if type(strrules) == 'table' then 
			for _,value in ipairs(strrules) do
				local params = split(value, ':')
				add_trie(params)
			end
		elseif type(strrules) == 'string' then
			local params = split(strrules, ':')
			add_trie (params)
		end
	end
	if table.maxn(tries) then
		if type(rspamd_config.get_api_version) ~= 'nil' then
			rspamd_config:register_callback_symbol('TRIE', 1.0, 'check_trie')
		else
			rspamd_config:register_symbol('TRIE', 1.0, 'check_trie')
		end
	end
end
