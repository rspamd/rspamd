-- 0 or 1 received: = spam

local metric = 'default'
local symbol = 'ONCE_RECEIVED'

function check_quantity_received (task)
	local recvh = task:get_received_headers()
	if table.maxn(recvh) <= 1 then
		task:insert_result(metric, symbol, 1)
	end
end

-- Register symbol's callback
local m = rspamd_config:get_metric(metric)
m:register_symbol(symbol, 1.0, 'check_quantity_received')
