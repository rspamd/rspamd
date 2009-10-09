-- This plugin is designed for testing received headers via rbl
-- Configuration:
-- .module 'received_rbl' {
--      rbl = "insecure-bl.rambler.ru";
--      rbl = "xbl.spamhaus.org";
--      metric = "default";
--      symbol = "RECEIVED_RBL";
-- };

local metric = 'default'
local symbol = 'RECEIVED_RBL'
local rbls = {}

function dns_cb(task, to_resolve, results, err)
	if results then
		local _,_,rbl = string.find(to_resolve, '%d+\.%d+\.%d+\.%d+\.(.+)')
		task:insert_result(metric, symbol, 1, rbl)
	end
end

function received_cb (task)
	local recvh = task:get_received_headers()
    for _,rh in ipairs(recvh) do
        for k,v in pairs(rh) do
			if k == 'real_ip' then
				local _,_,o1,o2,o3,o4 = string.find(v, '(%d+)\.(%d+)\.(%d+)\.(%d+)')
				for _,rbl in ipairs(rbls) do
					rbl_str = o4 .. '.' .. o3 .. '.' .. o2 .. '.' .. o1 .. '.' .. rbl
					task:resolve_dns_a(rbl_str, 'dns_cb')
				end
			end
        end
    end
end

-- Configuration
local opts =  rspamd_config:get_all_opt('received_rbl')
if opts then
    if opts['symbol'] then
        symbol = opts['symbol']

	    for n,v in pairs(opts) do
		    if n == 'rbl' then
			    table.insert(rbls, v)
		    elseif n == 'metric' then
			    metric = v
		    end
	    end
        -- Register symbol's callback
        local m = rspamd_config:get_metric(metric)
        m:register_symbol(symbol, 1.0, 'received_cb')
    end
    -- If no symbol defined, do not register this module
end
