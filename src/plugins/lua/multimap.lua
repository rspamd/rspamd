-- Multimap is rspamd module designed to define and operate with different maps

local rules = {}

function split(str, delim, maxNb)
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

function rbl_cb(task, to_resolve, results, err)
	if results then
		local _,_,o4,o3,o2,o1,in_rbl = string.find(to_resolve, '(%d+)%.(%d+)%.(%d+)%.(%d+)%.(.+)')
		-- Get corresponding rule by rbl name
		for _,rule in ipairs(rules) do
			if rule['map'] == in_rbl then
				task:insert_result(rule['symbol'], 1, rule['map'])
				return
			end
		end
	end
end

function check_multimap(task)
	for _,rule in ipairs(rules) do
		if rule['type'] == 'ip' then
			local ip = task:get_from_ip_num()
			if rule['ips']:get_key(ip) then
				task:insert_result(rule['symbol'], 1)
			end
		elseif rule['type'] == 'header' then
			local headers = task:get_message():get_header(rule['header'])
			if headers then
				for _,hv in ipairs(headers) do
					if rule['pattern'] then
						-- extract a part from header
						local _,_,ext = string.find(hv, rule['pattern'])
						if ext then
							if rule['hash']:get_key(ext) then
								task:insert_result(rule['symbol'], 1)
							end
						end
					else
						if rule['hash']:get_key(hv) then
							task:insert_result(rule['symbol'], 1)
						end
					end
				end
			end
		elseif rule['type'] == 'dnsbl' then
			local ip = task:get_from_ip()
			if ip then
				local _,_,o1,o2,o3,o4 = string.find(ip, '(%d+)%.(%d+)%.(%d+)%.(%d+)')
				local rbl_str = o4 .. '.' .. o3 .. '.' .. o2 .. '.' .. o1 .. '.' .. rule['map']
				task:resolve_dns_a(rbl_str, 'rbl_cb')
			end
 		end
	end
end

function add_rule(params)
	local newrule = {
		type = 'ip',
		header = nil,
		pattern = nil,
		map = nil,
		symbol = nil
	}
	for _,param in ipairs(params) do
		local _,_,name,value = string.find(param, '(%w+)%s*=%s*(.+)')
		if not name or not value then
			rspamd_logger:err('invalid rule: '..param)
			return 0
		end
		if name == 'type' then
			if value == 'ip' then
				newrule['type'] = 'ip'
			elseif value == 'dnsbl' then
				newrule['type'] = 'dnsbl'
			elseif value == 'header' then
				newrule['type'] = 'header'
			else
				rspamd_logger:err('invalid rule type: '.. value)
				return 0
			end
		elseif name == 'header' then
			newrule['header'] = value
		elseif name == 'pattern' then
			newrule['pattern'] = value
		elseif name == 'map' then
			newrule['map'] = value
		elseif name == 'symbol' then
			newrule['symbol'] = value
		else	
			rspamd_logger:err('invalid rule option: '.. name)
			return 0
		end

	end
	if not newrule['symbol'] or not newrule['map'] or not newrule['symbol'] then
		rspamd_logger:err('incomplete rule')
		return 0
	end
	if newrule['type'] == 'ip' then
		newrule['ips'] = rspamd_config:add_radix_map (newrule['map'])
	elseif newrule['type'] == 'header' then
		newrule['hash'] = rspamd_config:add_hash_map (newrule['map'])
	end
	table.insert(rules, newrule)
	return 1
end

local opts =  rspamd_config:get_all_opt('multimap')
if opts then
	local strrules = opts['rule']
	if strrules then
		if type(strrules) == 'array' then 
			for _,value in ipairs(strrules) do
				local params = split(value, ',')
				if not add_rule (params) then
					rspamd_logger:err('cannot add rule: "'..value..'"')
				end
			end
		elseif type(strrules) == 'string' then
			local params = split(strrules, ',')
			if not add_rule (params) then
				rspamd_logger:err('cannot add rule: "'..strrules..'"')
			end
		end
	end
end

if table.maxn(rules) > 0 then
	-- add fake symbol to check all maps inside a single callback
	rspamd_config:register_symbol('MULTIMAP', 1.0, 'check_multimap')
end
