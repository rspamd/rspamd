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

function multimap_rbl_cb(task, to_resolve, results, err)
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
			if rule['cdb'] then
				local ip = task:get_from_ip()
				if rule['hash']:lookup(ip) then
					task:insert_result(rule['symbol'], 1)
				end
			else
				local ip = task:get_from_ip_num()
				if rule['ips']:get_key(ip) then
					task:insert_result(rule['symbol'], 1)
				end
			end
		elseif rule['type'] == 'header' then
			local headers = task:get_message():get_header(rule['header'])
			if headers then
				for _,hv in ipairs(headers) do
					if rule['pattern'] then
						-- extract a part from header
						local _,_,ext = string.find(hv, rule['pattern'])
						if ext then
							if rule['cdb'] then
								if rule['hash']:lookup(ext) then
									task:insert_result(rule['symbol'], 1)
								end
							else
								if rule['hash']:get_key(ext) then
									task:insert_result(rule['symbol'], 1)
								end
							end
						end
					else
						if rule['cdb'] then
							if rule['hash']:lookup(hv) then
								task:insert_result(rule['symbol'], 1)
							end
						else
							if rule['hash']:get_key(hv) then
								task:insert_result(rule['symbol'], 1)
							end
						end
					end
				end
			end
		elseif rule['type'] == 'dnsbl' then
			local ip = task:get_from_ip()
			if ip then
				local _,_,o1,o2,o3,o4 = string.find(ip, '(%d+)%.(%d+)%.(%d+)%.(%d+)')
				local rbl_str = o4 .. '.' .. o3 .. '.' .. o2 .. '.' .. o1 .. '.' .. rule['map']
				task:resolve_dns_a(rbl_str, 'multimap_rbl_cb')
			end
		elseif rule['type'] == 'rcpt' then
			-- First try to get rcpt field
			local rcpts = task:get_recipients()
			if rcpts then
				for _,r in ipairs(rcpts) do
					if r['addr'] then
						if rule['pattern'] then
							-- extract a part from header
							local _,_,ext = string.find(r['addr'], rule['pattern'])
							if ext then
								if rule['cdb'] then
									if rule['hash']:lookup(hv) then
										task:insert_result(rule['symbol'], 1)
									end
								else
									if rule['hash']:get_key(hv) then
										task:insert_result(rule['symbol'], 1)
									end
								end
							end
						else
							if rule['cdb'] then
								if rule['hash']:lookup(r['addr']) then
									task:insert_result(rule['symbol'], 1)
								end
							else
								if rule['hash']:get_key(r['addr']) then
									task:insert_result(rule['symbol'], 1)
								end
							end
						end
					end	
				end
			else
				-- Get from headers
				local rcpts = task:get_recipients_headers()
				if rcpts then
					for _,r in ipairs(rcpts) do
						if r['addr'] then
							if rule['pattern'] then
								-- extract a part from header
								local _,_,ext = string.find(r['addr'], rule['pattern'])
								if ext then
									if rule['cdb'] then
										if rule['hash']:lookup(ext) then
											task:insert_result(rule['symbol'], 1)
										end
									else
										if rule['hash']:get_key(ext) then
											task:insert_result(rule['symbol'], 1)
										end
									end
								end
							else
								if rule['cdb'] then
									if rule['hash']:lookup(r['addr']) then
										task:insert_result(rule['symbol'], 1)
									end
								else
									if rule['hash']:get_key(r['addr']) then
										task:insert_result(rule['symbol'], 1)
									end
								end
							end
						end	
					end
				end
			end
		elseif rule['type'] == 'from' then
			-- First try to get from field
			local from = task:get_from()
			if from then
				for _,r in ipairs(from) do
					if r['addr'] then
						if rule['pattern'] then
							-- extract a part from header
							local _,_,ext = string.find(r['addr'], rule['pattern'])
							if ext then
								if rule['cdb'] then
									if rule['hash']:lookup(ext) then
										task:insert_result(rule['symbol'], 1)
									end
								else
									if rule['hash']:get_key(ext) then
										task:insert_result(rule['symbol'], 1)
									end
								end
							end
						else
							if rule['cdb'] then
								if rule['hash']:lookup(r['addr']) then
									task:insert_result(rule['symbol'], 1)
								end
							else
								if rule['hash']:get_key(r['addr']) then
									task:insert_result(rule['symbol'], 1)
								end
							end
						end
					end	
				end
			else
				-- Get from headers
				local from = task:get_from_headers()
				if from then
					for _,r in ipairs(from) do
						if r['addr'] then
							if rule['pattern'] then
								-- extract a part from header
								local _,_,ext = string.find(r['addr'], rule['pattern'])
								if ext then
									if rule['cdb'] then
										if rule['hash']:lookup(ext) then
											task:insert_result(rule['symbol'], 1)
										end
									else
										if rule['hash']:get_key(ext) then
											task:insert_result(rule['symbol'], 1)
										end
									end
								end
							else
								if rule['cdb'] then
									if rule['hash']:lookup(r['addr']) then
										task:insert_result(rule['symbol'], 1)
									end
								else
									if rule['hash']:get_key(r['addr']) then
										task:insert_result(rule['symbol'], 1)
									end
								end
							end
						end	
					end
				end
			end
 		end
	end
end

local function add_multimap_rule(params)
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
			rspamd_logger.err('invalid rule: '..param)
			return nil
		end
		if name == 'type' then
			if value == 'ip' then
				newrule['type'] = 'ip'
			elseif value == 'dnsbl' then
				newrule['type'] = 'dnsbl'
			elseif value == 'header' then
				newrule['type'] = 'header'
			elseif value == 'rcpt' then
				newrule['type'] = 'rcpt'
			elseif value == 'from' then
				newrule['type'] = 'from'
			else
				rspamd_logger.err('invalid rule type: '.. value)
				return nil
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
			rspamd_logger.err('invalid rule option: '.. name)
			return nil
		end

	end
	if not newrule['symbol'] or not newrule['map'] then
		rspamd_logger.err('incomplete rule')
		return nil
	end
	-- Check cdb flag
	if string.find(newrule['map'], '^cdb://.*$') then
		local test = cdb.create(newrule['map'])
		newrule['hash'] = cdb.create(newrule['map'])
		if newrule['hash'] then
			table.insert(rules, newrule)
		else
			rspamd_logger.warn('Cannot add rule: map doesn\'t exists: ' .. newrule['map'])
		end
		newrule['cdb'] = true
	else
		if newrule['type'] == 'ip' then
			newrule['ips'] = rspamd_config:add_radix_map (newrule['map'])
			if newrule['ips'] then
				table.insert(rules, newrule)
			else
				rspamd_logger.warn('Cannot add rule: map doesn\'t exists: ' .. newrule['map'])
			end
		elseif newrule['type'] == 'header' or newrule['type'] == 'rcpt' or newrule['type'] == 'from' then
			newrule['hash'] = rspamd_config:add_hash_map (newrule['map'])
			if newrule['hash'] then
				table.insert(rules, newrule)
			else
				rspamd_logger.warn('Cannot add rule: map doesn\'t exists: ' .. newrule['map'])
			end
		elseif newrule['type'] == 'cdb' then
			newrule['hash'] = rspamd_cdb.create(newrule['map'])
			if newrule['hash'] then
				table.insert(rules, newrule)
			else
				rspamd_logger.warn('Cannot add rule: map doesn\'t exists: ' .. newrule['map'])
			end
		else
			table.insert(rules, newrule)
		end
	end
	return newrule
end

-- Registration
if type(rspamd_config.get_api_version) ~= 'nil' then
	if rspamd_config:get_api_version() >= 1 then
		rspamd_config:register_module_option('multimap', 'rule', 'string')
	end
end

local opts =  rspamd_config:get_all_opt('multimap')
if opts then
	local strrules = opts['rule']
	if strrules then
		if type(strrules) == 'table' then 
			for _,value in ipairs(strrules) do
				local params = split(value, ',')
				local rule = add_multimap_rule (params)
				if not rule then
					rspamd_logger.err('cannot add rule: "'..value..'"')
				else
					if type(rspamd_config.get_api_version) ~= 'nil' then
						rspamd_config:register_virtual_symbol(rule['symbol'], 1.0)
					end
				end
			end
		elseif type(strrules) == 'string' then
			local params = split(strrules, ',')
			local rule = add_multimap_rule (params)
			if not rule then
				rspamd_logger.err('cannot add rule: "'..strrules..'"')
			else
				if type(rspamd_config.get_api_version) ~= 'nil' then
					rspamd_config:register_virtual_symbol(rule['symbol'], 1.0)
				end
			end
		end
	end
end

if table.maxn(rules) > 0 then
	-- add fake symbol to check all maps inside a single callback
	if type(rspamd_config.get_api_version) ~= 'nil' then
		rspamd_config:register_callback_symbol('MULTIMAP', 1.0, 'check_multimap')
	else
		rspamd_config:register_symbol('MULTIMAP', 1.0, 'check_multimap')
	end
end
