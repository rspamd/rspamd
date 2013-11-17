-- Multimap is rspamd module designed to define and operate with different maps

local rules = {}

function revipv6(ip)
	local c = 0
	local i = 1
	local t = {}
	for o in string.gmatch(ip, "%p-%x+%p-") do
		o = string.gsub(o, ":", "")
		while(#o < 4) do
			o = "0" .. o
		end
		t[i] = o
		i = i+1
	end
	if #t < 8 then
		for i=1,8 do
			if(t[i] == nil) then
				c = c+1
			end
		end
		for i=(8-c),#t do
			t[i+c] = t[i]
			t[i] = "0000"
		end
		for i=1,8 do
			if(t[i] == nil) then
				t[i] = "0000"
			end
		end
	end
	x=table.concat(t,"")
	x=string.reverse(x)
	rbl_str = ""
	for i in string.gmatch(x, "%x") do
		rbl_str = rbl_str .. i .. "."
	end
	return rbl_str
end

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

function string.ends(String,End)
	return End=='' or string.sub(String,-string.len(End))==End
end

function multimap_rbl_cb(task, to_resolve, results, err)
	if results then
		local _,_,o4,o3,o2,o1,in_rbl = string.find(to_resolve, '(%d+)%.(%d+)%.(%d+)%.(%d+)%.(.+)')
		-- Get corresponding rule by rbl name
		for _,rule in pairs(rules) do
			if string.ends(in_rbl, rule['map']) then
				task:insert_result(rule['symbol'], 1, rule['map'])
				return
			end
		end
	end
end

function check_multimap(task)
	for _,rule in pairs(rules) do
		if rule['type'] == 'ip' then
			if rule['cdb'] then
				local ip = task:get_from_ip()
				if ip and rule['hash']:lookup(ip) then
					task:insert_result(rule['symbol'], 1)
				end
			else
				local ip = task:get_from_ip_num()
				if ip and rule['ips'] and rule['ips']:get_key(ip) then
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
				if not string.match(ip, ":") and rule['ipv4'] then
					local _,_,o1,o2,o3,o4 = string.find(ip, '(%d+)%.(%d+)%.(%d+)%.(%d+)')
			        	if o1 and o2 and o3 and o4 then
						local rbl_str = o4 .. '.' .. o3 .. '.' .. o2 .. '.' .. o1 .. '.' .. rule['map']
						task:resolve_dns_a(rbl_str, 'multimap_rbl_cb')
					end
				elseif rule['ipv6'] then
					local rbl_str = revipv6(ip) .. rule['map']
					task:resolve_dns_a(rbl_str, 'multimap_rbl_cb')
				end
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

local function add_multimap_rule(newrule)
	if not newrule['symbol'] or not newrule['map'] then
		rspamd_logger.err('incomplete rule')
		return nil
	end
	-- Check cdb flag
	if string.find(newrule['map'], '^cdb://.*$') then
		local test = cdb.create(newrule['map'])
		newrule['hash'] = cdb.create(newrule['map'])
		newrule['cdb'] = true
		if newrule['hash'] then
			table.insert(rules, newrule)
			return newrule
		else
			rspamd_logger.warn('Cannot add rule: map doesn\'t exists: ' .. newrule['map'])
		end
	else
		if newrule['type'] == 'ip' then
			newrule['ips'] = rspamd_config:add_radix_map (newrule['map'], newrule['description'])
			if newrule['ips'] then
				table.insert(rules, newrule)
				return newrule
			else
				rspamd_logger.warn('Cannot add rule: map doesn\'t exists: ' .. newrule['map'])
			end
		elseif newrule['type'] == 'header' or newrule['type'] == 'rcpt' or newrule['type'] == 'from' then
			newrule['hash'] = rspamd_config:add_hash_map (newrule['map'], newrule['description'])
			if newrule['hash'] then
				table.insert(rules, newrule)
				return newrule
			else
				rspamd_logger.warn('Cannot add rule: map doesn\'t exists: ' .. newrule['map'])
			end
		elseif newrule['type'] == 'cdb' then
			newrule['hash'] = rspamd_cdb.create(newrule['map'])
			if newrule['hash'] then
				table.insert(rules, newrule)
				return newrule
			else
				rspamd_logger.warn('Cannot add rule: map doesn\'t exists: ' .. newrule['map'])
			end
		else
			table.insert(rules, newrule)
			return newrule
		end
	end
	return nil
end

-- Registration
if type(rspamd_config.get_api_version) ~= 'nil' then
	if rspamd_config:get_api_version() >= 1 then
		rspamd_config:register_module_option('multimap', 'rule', 'string')
	end
end

local opts =  rspamd_config:get_all_opt('multimap')
if opts then
	for _,m in pairs(opts) do
		if(m['type'] == "dnsbl") then
			if(m['ipv6'] == nil) then
				m['ipv6'] = false
			end
			if(m['ipv4'] == nil) then
				m['ipv4'] = true
			end
		end
		local rule = add_multimap_rule (m)
		if not rule then
			rspamd_logger.err('cannot add rule: "'..value..'"')
		else
			if type(rspamd_config.get_api_version) ~= 'nil' then
				rspamd_config:register_virtual_symbol(m['symbol'], 1.0)
			end
		end
	end
	-- add fake symbol to check all maps inside a single callback
	if type(rspamd_config.get_api_version) ~= 'nil' then
		if rspamd_config.get_api_version() >= 4 then
			rspamd_config:register_callback_symbol_priority('MULTIMAP', 1.0, -1, 'check_multimap')
		else
			rspamd_config:register_callback_symbol('MULTIMAP', 1.0, 'check_multimap')
		end
	end
	rspamd_config:register_symbol('MULTIMAP', 1.0, 'check_multimap')
end
