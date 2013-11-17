-- Configuration:
-- rbl {
--    default_ipv4 = true;
--    default_ipv6 = false;
--    default_received = true;
--    default_from = false;
--    rbls {
--	xbl {
--	   rbl = "xbl.spamhaus.org";
--         symbol = "RBL_SPAMHAUSXBL";
--         ipv4 = true;
--         ipv6 = false;
--	}
--    }
-- }

local rbls = {}

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

function dns_cb(task, to_resolve, results, err, sym)
	if results then
		task:insert_result(sym, 1)
	end
end

function rbl_cb (task)
	local rip = task:get_from_ip()
	if(rip ~= nil) then
		if not string.match(rip, ":") then
			local _,_,o1,o2,o3,o4 = string.find(rip, '^(%d+)%.(%d+)%.(%d+)%.(%d+)$')
			for _,rbl in pairs(rbls) do
				if(rbl['ipv4'] and rbl['from']) then
					rbl_str = o4 .. '.' .. o3 .. '.' .. o2 .. '.' .. o1 .. '.' .. rbl['rbl']
					task:resolve_dns_a(rbl_str, 'dns_cb', rbl['symbol'])
				end
			end
		else
			for _,rbl in pairs(rbls) do
				if(rbl['ipv6'] and rbl['from']) then
					rbl_str = revipv6(rip) .. rbl['rbl']
					task:resolve_dns_a(rbl_str, 'dns_cb', rbl['symbol'])
				end
			end
		end
	end
	local recvh = task:get_received_headers()
	for _,rh in ipairs(recvh) do
		if rh['real_ip'] then
			if not string.match(rh['real_ip'], ":") then
				local _,_,o1,o2,o3,o4 = string.find(rh['real_ip'], '^(%d+)%.(%d+)%.(%d+)%.(%d+)$')
				if o1 and o2 and o3 and o4 then
					for _,rbl in pairs(rbls) do
						if(rbl['ipv4'] and rbl['received']) then
							rbl_str = o4 .. '.' .. o3 .. '.' .. o2 .. '.' .. o1 .. '.' .. rbl['rbl']
							task:resolve_dns_a(rbl_str, 'dns_cb', rbl['symbol'])
						end
					end
				end
			else
				for _,rbl in pairs(rbls) do
					if(rbl['ipv6'] and rbl['received']) then
						rbl_str = revipv6(rh['real_ip']) .. rbl['rbl']
						task:resolve_dns_a(rbl_str, 'dns_cb', rbl['symbol'])
					end     
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
	end
end

-- Configuration
local opts = rspamd_config:get_all_opt('rbl')
if(opts == nil) then
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
for _,rbl in pairs(opts['rbls']) do
	local o = { "ipv4", "ipv6", "from", "received" }
	for i=1,#o do
		if(rbl[o[i]] == nil) then
			rbl[o[i]] = opts['default_' .. o[i]]
		end
	end
	if type(rspamd_config.get_api_version) ~= 'nil' then
		rspamd_config:register_virtual_symbol(rbl['symbol'], 1)
	end
	table.insert(rbls, {symbol = rbl['symbol'], rbl = rbl['rbl'], ipv6 = rbl['ipv6'], ipv4 = rbl['ipv4'], received = rbl['received'], from = rbl['from']})
	rspamd_config:register_symbol(rbl['symbol'], 1.0, 'rbl_cb')
end
