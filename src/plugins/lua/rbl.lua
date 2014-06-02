local rbls = {}

local function ip_to_rbl(ip, rbl)
	return table.concat(ip:inversed_str_octets(), ".") .. '.' .. rbl
end

local function rbl_cb (task)
	local function rbl_dns_cb(resolver, to_resolve, results, err, key)
		if results then
			local thisrbl = nil
			for k,r in pairs(rbls) do
				if k == key then
					thisrbl = r
					break
				end
			end
			if thisrbl ~= nil then
				if thisrbl['returncodes'] == nil then
					if thisrbl['symbol'] ~= nil then
						task:insert_result(thisrbl['symbol'], 1)
					end
				else
					for _,result in pairs(results) do 
						local ipstr = result:to_string()
						local foundrc = false
						for s,i in pairs(thisrbl['returncodes']) do
							if type(i) == 'string' then
								if string.find(ipstr, "^" .. i .. "$") then
									foundrc = true
									task:insert_result(s, 1)
									break
								end
							elseif type(i) == 'table' then
								for _,v in pairs(i) do
									if string.find(ipstr, "^" .. v .. "$") then
										foundrc = true
										task:insert_result(s, 1)
										break
									end
								end
							end
						end
						if not foundrc then
							if thisrbl['unknown'] and thisrbl['symbol'] then
								task:insert_result(thisrbl['symbol'], 1)
							else
								rspamd_logger.err('RBL ' .. thisrbl['rbl'] .. ' returned unknown result ' .. ipstr)
							end
						end
					end
				end
			end
		end
		task:inc_dns_req()
	end

	local helo = task:get_helo()
	if helo and string.sub(helo,1,1) ~= '[' then
		for k,rbl in pairs(rbls) do
			if rbl['helo'] then
				task:get_resolver():resolve_a(task:get_session(), task:get_mempool(), helo .. '.' .. rbl['rbl'], rbl_dns_cb, k)
			end
		end
	end
	local sender_dns = task:get_hostname()
	if sender_dns ~= nil and sender_dns ~= 'unknown' then
		for k,rbl in pairs(rbls) do
			if rbl['rdns'] then
				task:get_resolver():resolve_a(task:get_session(), task:get_mempool(), sender_dns .. '.' .. rbl['rbl'], rbl_dns_cb, k)
			end
		end
	end
	local rip = task:get_from_ip()
	if rip and (rip:to_string() ~= '0.0.0.0') then
		for k,rbl in pairs(rbls) do
			if (rip:get_version() == 6 and rbl['ipv6'] and rbl['from']) or 
				(rip:get_version() == 4 and rbl['ipv4'] and rbl['from']) then
			task:get_resolver():resolve_a(task:get_session(), task:get_mempool(), 
				ip_to_rbl(rip, rbl['rbl']), rbl_dns_cb, k)
			end
		end
	end
	local recvh = task:get_received_headers()
	for _,rh in ipairs(recvh) do
		if rh['real_ip'] and rh['real_ip']:to_string() ~= '0.0.0.0' then
			for k,rbl in pairs(rbls) do
				if (rh['real_ip']:get_version() == 6 and rbl['ipv6'] and rbl['received']) or
					(rh['real_ip']:get_version() == 4 and rbl['ipv4'] and rbl['received']) then
				task:get_resolver():resolve_a(task:get_session(), task:get_mempool(), 
					ip_to_rbl(rh['real_ip'], rbl['rbl']), rbl_dns_cb, k)
				end
			end
    	end
	end
end

-- Registration
if type(rspamd_config.get_api_version) ~= 'nil' then
	if rspamd_config:get_api_version() >= 1 then
		rspamd_config:register_module_option('rbl', 'rbls', 'map')
		rspamd_config:register_module_option('rbl', 'default_ipv4', 'string')
		rspamd_config:register_module_option('rbl', 'default_ipv6', 'string')
		rspamd_config:register_module_option('rbl', 'default_received', 'string')
		rspamd_config:register_module_option('rbl', 'default_from', 'string')
		rspamd_config:register_module_option('rbl', 'default_rdns', 'string')
		rspamd_config:register_module_option('rbl', 'default_helo', 'string')
		rspamd_config:register_module_option('rbl', 'default_unknown', 'string')
	end
end

-- Configuration
local opts = rspamd_config:get_all_opt('rbl')
if not opts or type(opts) ~= 'table' then
	return
end
if(opts['default_ipv4'] == nil) then
	opts['default_ipv4'] = true
end
if(opts['default_ipv6'] == nil) then
	opts['default_ipv6'] = false
end
if(opts['default_received'] == nil) then
	opts['default_received'] = true
end
if(opts['default_from'] == nil) then
	opts['default_from'] = false
end
if(opts['default_unknown'] == nil) then
	opts['default_unknown'] = false
end
if(opts['default_rdns'] == nil) then
        opts['default_rdns'] = false
end
if(opts['default_helo'] == nil) then
        opts['default_helo'] = false
end
for key,rbl in pairs(opts['rbls']) do
	local o = { "ipv4", "ipv6", "from", "received", "unknown", "rdns", "helo" }
	for i=1,table.maxn(o) do
		if(rbl[o[i]] == nil) then
			rbl[o[i]] = opts['default_' .. o[i]]
		end
	end
	if type(rbl['returncodes']) == 'table' then
		for s,_ in pairs(rbl['returncodes']) do
			if type(rspamd_config.get_api_version) ~= 'nil' then
				rspamd_config:register_virtual_symbol(s, 1)
			end
		end
	end
	if not rbl['symbol'] and type(rbl['returncodes']) ~= 'nil' and not rbl['unknown'] then
		rbl['symbol'] = key
	end
	if type(rspamd_config.get_api_version) ~= 'nil' and rbl['symbol'] then
		rspamd_config:register_virtual_symbol(rbl['symbol'], 1)
	end
	rbls[key] = rbl
end
rspamd_config:register_callback_symbol_priority('RBL', 1.0, 0, rbl_cb)
