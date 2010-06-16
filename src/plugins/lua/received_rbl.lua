-- This plugin is designed for testing received headers via rbl
-- Configuration:
-- .module 'received_rbl' {
--      rbl = "insecure-bl.rambler.ru";
--      rbl = "xbl.spamhaus.org";
--      symbol = "RECEIVED_RBL";
-- };

local symbol = 'RECEIVED_RBL'
local rbls = {}

function dns_cb(task, to_resolve, results, err)
	if results then
		local _,_,o4,o3,o2,o1,in_rbl = string.find(to_resolve, '(%d+)%.(%d+)%.(%d+)%.(%d+)%.(.+)')
		local ip = o1 .. '.' .. o2 .. '.' .. o3 .. '.' .. o4
		-- Find incoming rbl in rbls list
		for _,rbl in ipairs(rbls) do
			if rbl == in_rbl then
				task:insert_result(symbol, 1, rbl .. ': ' .. ip)
			else 
				local s, _ = string.find(rbl, in_rbl)
				if s then
					s, _ = string.find(rbl, ':')
					if s then
						task:insert_result(string.sub(rbl, s + 1, -1), 1, ip)
					else
						task:insert_result(symbol, 1, rbl .. ': ' .. ip)
					end
				end
			end
		end
	end
end

function received_cb (task)
	local recvh = task:get_received_headers()
    for _,rh in ipairs(recvh) do
        for k,v in pairs(rh) do
			if k == 'real_ip' then
				local _,_,o1,o2,o3,o4 = string.find(v, '(%d+)%.(%d+)%.(%d+)%.(%d+)')
				for _,rbl in ipairs(rbls) do
					local rbl_str = ''
					local rb_s,_ = string.find(rbl, ':')
					if rb_s then
						-- We have rbl in form some_rbl:SYMBOL, so get first part
						local actual_rbl = string.sub(rbl, 1, rb_s - 1)
						rbl_str = o4 .. '.' .. o3 .. '.' .. o2 .. '.' .. o1 .. '.' .. actual_rbl
					else
						rbl_str = o4 .. '.' .. o3 .. '.' .. o2 .. '.' .. o1 .. '.' .. rbl
					end
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
        
        if opts['rbl'] then
            rbls = opts['rbl']
        end
        -- Register symbol's callback
        rspamd_config:register_symbol(symbol, 1.0, 'received_cb')
    end
    -- If no symbol defined, do not register this module
end
