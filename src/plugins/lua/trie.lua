-- Trie is rspamd module designed to define and operate with suffix trie

local tries = {}

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
	for part, pos in string.gfind(str, pat) do
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
		trie['trie'] = rspamd_trie:create(true)
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
		trie['trie'] = rspamd_trie:create(true)
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
