-- 0 or 1 received: = spam

local symbol = 'ONCE_RECEIVED'
-- Symbol for strict checks
local symbol_strict = nil
local bad_hosts = {}
local good_hosts = {}
local rspamd_logger = require "rspamd_logger"

local function check_quantity_received (task)
	local function recv_dns_cb(resolver, to_resolve, results, err)
		task:inc_dns_req()
		if not results then
			task:insert_result(symbol_strict, 1)
		else
			rspamd_logger.info(string.format('SMTP resolver failed to resolve: %s is %s', to_resolve, results[1]))
			local i = true
			for _,h in ipairs(bad_hosts) do
				if string.find(results[1], h) then
					-- Check for good hostname
					if good_hosts then
						for _,gh in ipairs(good_hosts) do
							if string.find(results[1], gh) then
								i = false
								break
							end
						end
					end
					if i then
						task:insert_result(symbol_strict, 1, h)
						return
					end
				end
			end
		end
	end

	local recvh = task:get_received_headers()
	if table.maxn(recvh) <= 1 then
		task:insert_result(symbol, 1)
		-- Strict checks
		if symbol_strict then
			local r = recvh[1]
            if not r then
                return
            end
			-- Unresolved host
			if not r['real_hostname'] or string.lower(r['real_hostname']) == 'unknown' or 
				string.match(r['real_hostname'], '^%d+%.%d+%.%d+%.%d+$') then
				
				if r['real_ip'] then
					-- Try to resolve it again
					task:get_resolver():resolve_ptr(task:get_session(), task:get_mempool(), 
						tostring(r['real_ip']), recv_dns_cb)
				else
					task:insert_result(symbol_strict, 1)
				end
		    return
			end

			local i = true
			local hn = string.lower(r['real_hostname'])

			for _,h in ipairs(bad_hosts) do
				if string.find(hn, h) then
					-- Check for good hostname
					if good_hosts then
						for _,gh in ipairs(good_hosts) do
							if string.find(hn, gh) then
								i = false
								break
							end
						end
					end
					if i then
						task:insert_result(symbol_strict, 1, h)
						return
					end
				end
			end
		end
	end
end

-- Registration
if type(rspamd_config.get_api_version) ~= 'nil' then
	if rspamd_config:get_api_version() >= 1 then
		rspamd_config:register_module_option('once_received', 'symbol', 'string')
		rspamd_config:register_module_option('once_received', 'symbol_strict', 'string')
		rspamd_config:register_module_option('once_received', 'bad_host', 'string')
		rspamd_config:register_module_option('once_received', 'good_host', 'string')
	end
end

-- Configuration
local opts =  rspamd_config:get_all_opt('once_received')
if opts then
    if opts['symbol'] then
        local symbol = opts['symbol']

	    for n,v in pairs(opts) do
			if n == 'symbol_strict' then
				symbol_strict = v
				if type(rspamd_config.get_api_version) ~= 'nil' then
					rspamd_config:register_virtual_symbol(symbol_strict, 1.0)
				end
			elseif n == 'bad_host' then
				if type(v) == 'string' then
			    	bad_hosts[1] = v
				else
					bad_hosts = v
				end
			elseif n == 'good_host' then
				if type(v) == 'string' then
			    	good_hosts[1] = v
				else
					good_hosts = v
				end
		    end
	    end

		-- Register symbol's callback
		rspamd_config:register_symbol(symbol, 1.0, check_quantity_received)
	end
end
