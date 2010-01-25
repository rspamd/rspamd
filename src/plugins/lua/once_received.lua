-- 0 or 1 received: = spam

local metric = 'default'
local symbol = 'ONCE_RECEIVED'
-- Symbol for strict checks
local symbol_strict = nil
local bad_hosts = {}
local good_hosts = {}

function check_quantity_received (task)
	local recvh = task:get_received_headers()
	if table.maxn(recvh) <= 1 then
		task:insert_result(metric, symbol, 1)
		-- Strict checks
		if symbol_strict then
			local r = recvh[1]
            if not r then
                return
            end
			-- Unresolved host
			if not r['real_hostname'] or string.lower(r['real_hostname']) == 'unknown' or string.match(r['real_hostname'], '^%d+%.%d+%.%d+%.%d+$') then
				task:insert_result(metric, symbol_strict, 1)
                return
			end

			local i = true
			local hn = string.lower(r['real_hostname'])

			for _,h in ipairs(bad_hosts) do
				if string.find(hn, h) then
					-- Check for good hostname
					for _,gh in ipairs(good_hosts) do
						if string.find(hn, gh) then
							i = false
							break
						end
					end
					if i then
						task:insert_result(metric, symbol_strict, 1, h)
						return
					end
				end
			end
		end
	end
end

-- Configuration
local opts =  rspamd_config:get_all_opt('once_received')
if opts then
    if opts['symbol'] then
        symbol = opts['symbol']

	    for n,v in pairs(opts) do
			if n == 'symbol_strict' then
				symbol_strict = v
			elseif n == 'bad_host' then
			    bad_hosts = v
			elseif n == 'good_host' then
			    good_hosts = v
		    elseif n == 'metric' then
			    metric = v
		    end
	    end

		-- Register symbol's callback
		local m = rspamd_config:get_metric(metric)
		m:register_symbol(symbol, 1.0, 'check_quantity_received')
	end
end
