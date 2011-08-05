-- This plugin is designed for testing received headers via rbl
-- Configuration:
-- .module 'received_rbl' {
--      rbl = "insecure-bl.rambler.ru";
--      rbl = "xbl.spamhaus.org";
--      symbol = "RECEIVED_RBL";
-- };

local symbol = 'RECEIVED_RBL'
local rbls = {}

function dns_cb(task, to_resolve, results, err, sym)
	if results then
		local _,_,o4,o3,o2,o1,in_rbl = string.find(to_resolve, '^(%d+)%.(%d+)%.(%d+)%.(%d+)%.(.+)$')
		local ip = o1 .. '.' .. o2 .. '.' .. o3 .. '.' .. o4
		task:insert_result(sym, 1, in_rbl .. ': ' .. ip)
	end
end

function received_cb (task)
	local recvh = task:get_received_headers()
    for _,rh in ipairs(recvh) do
		if rh['real_ip'] then
			local _,_,o1,o2,o3,o4 = string.find(rh['real_ip'], '^(%d+)%.(%d+)%.(%d+)%.(%d+)$')
			if o1 and o2 and o3 and o4 then
				for _,rbl in ipairs(rbls) do
					rbl_str = o4 .. '.' .. o3 .. '.' .. o2 .. '.' .. o1 .. '.' .. rbl['rbl']
					task:resolve_dns_a(rbl_str, 'dns_cb', rbl['symbol'])
				end
			end
        end
    end
end

-- Registration
if type(rspamd_config.get_api_version) ~= 'nil' then
	if rspamd_config:get_api_version() >= 1 then
		rspamd_config:register_module_option('received_rbl', 'symbol', 'string')
		rspamd_config:register_module_option('received_rbl', 'rbl', 'string')
	end
end

-- Configuration
local opts =  rspamd_config:get_all_opt('received_rbl')
if opts then
    if opts['symbol'] then
        symbol = opts['symbol']
        local rbl_t = {}
        if opts['rbl'] then
			if type(opts['rbl']) == 'table' then
				rbl_t = opts['rbl']
			else
				rbl_t[1] = opts['rbl']
			end
        end
        for _,rbl in ipairs(rbl_t) do
        	local s, _ = string.find(rbl, ':')
			if s then
				local sym = string.sub(rbl, s + 1, -1)
				if type(rspamd_config.get_api_version) ~= 'nil' then
					rspamd_config:register_virtual_symbol(sym, 1)
				end
				table.insert(rbls, {symbol = sym, rbl = rbl})
			else
				table.insert(rbls, {symbol = symbol, rbl = rbl})
			end
		end
        -- Register symbol's callback
        rspamd_config:register_symbol(symbol, 1.0, 'received_cb')
    end
    -- If no symbol defined, do not register this module
end
