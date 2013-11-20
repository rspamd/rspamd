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

local function ip_to_rbl(ip, rbl)
	octets = ip:inversed_str_octets()
	local str = ''
	for _,o in ipairs(octets) do
		str = str .. o .. '.'
	end
	str = str .. rbl

	return str
end

local function rbl_cb (task)
	local function rbl_dns_cb(resolver, to_resolve, results, err, sym)
		if results then
			task:insert_result(sym, 1)
		end
		task:inc_dns_req()
	end

	local rip = task:get_from_ip()
	if(rip ~= "0.0.0.0") then
		for _,rbl in pairs(rbls) do
			if (rip:get_version() == "6" and rbl['ipv6'] and rbl['from']) or 
				(rip:get_version() == "4" and rbl['ipv4'] and rbl['from']) then
			task:get_resolver():resolve_a(task:get_session(), task:get_mempool(), 
				ip_to_rbl(rip, rbl['rbl']), rbl_dns_cb, rbl['symbol'])
			end
		end
	end
	local recvh = task:get_received_headers()
	for _,rh in ipairs(recvh) do
		if rh['real_ip'] then
			for _,rbl in pairs(rbls) do
				if (rh['real_ip']:get_version() == "6" and rbl['ipv6'] and rbl['received']) or
					(rh['real_ip']:get_version() == "4" and rbl['ipv4'] and rbl['received']) then
				task:get_resolver():resolve_a(task:get_session(), task:get_mempool(), 
					ip_to_rbl(rh['real_ip'], rbl['rbl']), rbl_dns_cb, rbl['symbol'])
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
for key,rbl in pairs(opts['rbls']) do
	local o = { "ipv4", "ipv6", "from", "received" }
	for i=1,table.maxn(o) do
		if(rbl[o[i]] == nil) then
			rbl[o[i]] = opts['default_' .. o[i]]
		end
	end
	if not rbl['symbol'] then
		rbl['symbol'] = key
	end
	if type(rspamd_config.get_api_version) ~= 'nil' then
		rspamd_config:register_virtual_symbol(rbl['symbol'], 1)
	end
	table.insert(rbls, {symbol = rbl['symbol'], rbl = rbl['rbl'], ipv6 = rbl['ipv6'], ipv4 = rbl['ipv4'], received = rbl['received'], from = rbl['from']})
	rspamd_config:register_symbol(rbl['symbol'], 1.0, rbl_cb)
end
