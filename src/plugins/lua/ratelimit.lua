-- A plugin that implements ratelimits using redis or kvstorage server

-- Default port for redis upstreams
local default_port = 6379
-- Default settings for limits, 1-st member is burst, second is rate and the third is numeric type 
local settings = {
	-- Limit for all mail per recipient (burst 100, rate 2 per minute)
	to = {[1] = 100, [2] = 0.033333333, [3] = 1},
	-- Limit for all mail per one source ip (burst 30, rate 1.5 per minute)  
	to_ip = {[1] = 30, [2] = 0.025, [3] = 2},
	-- Limit for all mail per one source ip and from address (burst 20, rate 1 per minute)
	to_ip_from = {[1] = 20, [2] = 0.01666666667, [3] = 3}, 
	
	-- Limit for all bounce mail (burst 10, rate 2 per hour)
	bounce_to = {[1] = 10, [2] = 0.000555556, [3] = 4}, 
	-- Limit for bounce mail per one source ip (burst 5, rate 1 per hour)
	bounce_to_ip = {[1] = 5 , [2] = 0.000277778, [3] = 5},
 
        -- Limit for all mail per user (authuser) (burst 20, rate 1 per minute)
	user = {[1] = 20, [2] = 0.01666666667, [3] = 6}

}
-- Senders that are considered as bounce
local bounce_senders = {'postmaster', 'mailer-daemon', '', 'null', 'fetchmail-daemon', 'mdaemon'}
-- Do not check ratelimits for these senders
local whitelisted_rcpts = {'postmaster', 'mailer-daemon'}
local whitelisted_ip = nil
local max_rcpt = 5
local upstreams = nil

local rspamd_logger = require "rspamd_logger"
local rspamd_redis = require "rspamd_redis"
local upstream_list = require "rspamd_upstream_list"

--- Parse atime and bucket of limit
local function parse_limit_data(str)
	local pos,_ = string.find(str, ':')
	if not pos then
		return 0, 0
	else
		local atime = tonumber(string.sub(str, 1, pos - 1))
		local bucket = tonumber(string.sub(str, pos + 1))
		return atime,bucket
	end
end

--- Check specific limit inside redis
local function check_specific_limit (task, limit, key)

	local upstream = upstreams:get_upstream_by_hash(key, task:get_date())
	--- Called when value was set on server
	local function rate_set_key_cb(task, err, data)
		if err then
		  rspamd_logger.info('got error while getting limit: ' .. err)
			upstream:fail()
		else
			upstream:ok()
		end
	end
	--- Called when value is got from server
	local function rate_get_cb(task, err, data)
		if data then
			local atime, bucket = parse_limit_data(data)
			local tv = task:get_timeval()
			local ntime = tv['tv_usec'] / 1000000. + tv['tv_sec']
			-- Leak messages
			bucket = bucket - limit[2] * (ntime - atime);
			if bucket > 0 then
				local lstr = string.format('%.7f:%.7f', ntime, bucket)
				rspamd_redis.make_request(task, upstream:get_ip_string(), upstream:get_port(), rate_set_key_cb, 
							'SET %b %b', key, lstr)
				if bucket > limit[1] then
					task:set_pre_result(rspamd_actions['reject'], 'Ratelimit exceeded: ' .. key)
				end
			else
				rspamd_redis.make_request(task, upstream:get_ip_string(), upstream:get_port(), rate_set_key_cb, 
							'DEL %b', key)
			end
		end
		if err then
		  rspamd_logger.info('got error while getting limit: ' .. err)
			upstream:fail()
		end	
	end
	if upstream then
		rspamd_redis.make_request(task, upstream:get_ip_string(), upstream:get_port(), rate_get_cb, 'GET %b', key)
	end
end

--- Set specific limit inside redis
local function set_specific_limit (task, limit, key)
	local upstream = upstreams:get_upstream_by_hash(key,  task:get_date())
	--- Called when value was set on server
	local function rate_set_key_cb(task, err, data)
		if err then
		  rspamd_logger.info('got error while setting limit: ' .. err)
			upstream:fail()
		else
			upstream:ok()
		end
	end
	--- Called when value is got from server
	local function rate_set_cb(task, err, data)
		if not err and not data then
			--- Add new entry
			local tv = task:get_timeval()
			local atime = tv['tv_usec'] / 1000000. + tv['tv_sec']
			local lstr = string.format('%.7f:1', atime)
			rspamd_redis.make_request(task, upstream:get_ip_string(), upstream:get_port(), rate_set_key_cb, 
							'SET %b %b', key, lstr)
		elseif data then
			local atime, bucket = parse_limit_data(data)
			local tv = task:get_timeval()
			local ntime = tv['tv_usec'] / 1000000. + tv['tv_sec']
			-- Leak messages
			bucket = bucket - limit[2] * (ntime - atime) + 1;
			local lstr = string.format('%.7f:%.7f', ntime, bucket)
			rspamd_redis.make_request(task, upstream:get_ip_string(), upstream:get_port(), rate_set_key_cb, 
							'SET %b %b', key, lstr)
		elseif err then
		  rspamd_logger.info('got error while setting limit: ' .. err)
			upstream:fail()
		end
	end
	if upstream then
		rspamd_redis.make_request(task, upstream:get_ip_string(), upstream:get_port(), rate_set_cb, 'GET %b', key)
	end
end

--- Make rate key
local function make_rate_key(from, to, ip)
	if from and ip then
		return string.format('%s:%s:%s', from, to, ip:to_string())
	elseif from then
		return string.format('%s:%s', from, to)
	elseif ip then
		return string.format('%s:%s', to, ip:to_string())
	elseif to then
		return to
	else
		return nil
	end
end

--- Check whether this addr is bounce
local function check_bounce(from)
	for _,b in ipairs(whitelisted_rcpts) do
		if b == from then
			return true
		end
	end
	return false
end

--- Check or update ratelimit
local function rate_test_set(task, func)
	-- Get initial task data
	local ip = task:get_from_ip()
	if ip and whitelisted_ip then
		if whitelisted_ip:get_key(ip) then
			-- Do not check whitelisted ip
			return
		end
	end
	-- Parse all rcpts 
	local rcpts = task:get_recipients()
	local rcpts_user = {}
	if rcpts then
		if table.maxn(rcpts) > max_rcpt then
			rspamd_logger.info(string.format('message <%s> contains %d recipients, maximum is %d',
				task:get_message_id(), table.maxn(rcpts), max_rcpt))
			return
		end
		for i,r in ipairs(rcpts) do
			rcpts_user[i] = r['user']
		end
	end
	-- Parse from
	local from = task:get_from()
	local from_user = ''
	if from then
		from_user = from[1]['user']
	end
	-- Get user (authuser)
	local auser = task:get_user()
	if auser then
		func(task, settings['user'], make_rate_key (auser, '<auth>', nil))
	end

	if not from_user or not rcpts_user[1] then
		-- Nothing to check
		return
	end
	
	local is_bounce = check_bounce(from_user)
	
	for _,r in ipairs(rcpts) do
		if is_bounce then
			-- Bounce specific limit
			func(task, settings['bounce_to'], make_rate_key ('<>', r['addr'], nil))
			if ip then
				func(task, settings['bounce_to_ip'], make_rate_key ('<>', r['addr'], ip))
			end
		end
		func(task, settings['to'], make_rate_key (nil, r['addr'], nil))
		if ip then
			func(task, settings['to_ip'], make_rate_key (nil, r['addr'], ip))
			func(task, settings['to_ip_from'], make_rate_key (from[1]['addr'], r['addr'], ip))
		end
	end
end

--- Check limit
local function rate_test(task)
	rate_test_set(task, check_specific_limit)
end
--- Update limit
local function rate_set(task)
	rate_test_set(task, set_specific_limit)
end


--- Utility function for split string to table
local function split(str, delim, maxNb)
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

--- Parse a single limit description
local function parse_limit(str)
	local params = split(str, ':', 0)
	
	local function set_limit(limit, burst, rate)
		limit[1] = tonumber(burst)
		limit[2] = tonumber(rate)
	end
	
	if table.maxn(params) ~= 3 then
		rspamd_logger.err('invalid limit definition: ' .. str)
		return
	end
	
	if params[1] == 'to' then
		set_limit(settings['to'], params[2], params[3])
	elseif params[1] == 'to_ip' then
		set_limit(settings['to_ip'], params[2], params[3])
	elseif params[1] == 'to_ip_from' then
		set_limit(settings['to_ip_from'], params[2], params[3])
	elseif params[1] == 'bounce_to' then
		set_limit(settings['bounce_to'], params[2], params[3])
	elseif params[1] == 'bounce_to_ip' then
		set_limit(settings['bounce_to_ip'], params[2], params[3])
        elseif params[1] == 'user' then
                set_limit(settings['user'], params[2], params[3])
	else
		rspamd_logger.err('invalid limit type: ' .. params[1])
	end
end

-- Registration
if rspamd_config:get_api_version() >= 9 then
	rspamd_config:register_module_option('ratelimit', 'servers', 'string')
	rspamd_config:register_module_option('ratelimit', 'bounce_senders', 'string')
	rspamd_config:register_module_option('ratelimit', 'whitelisted_rcpts', 'string')
	rspamd_config:register_module_option('ratelimit', 'whitelisted_ip', 'map')
	rspamd_config:register_module_option('ratelimit', 'limit', 'string')
	rspamd_config:register_module_option('ratelimit', 'max_rcpt', 'uint')
end

local function parse_whitelisted_rcpts(str)
	
end

local opts =  rspamd_config:get_all_opt('ratelimit')
if opts then
	local rates = opts['limit']
	if rates and type(rates) == 'table' then
		for _,r in ipairs(rates) do
			parse_limit(r)
		end
	elseif rates and type(rates) == 'string' then
		parse_limit(rates)
	end
	
	if opts['whitelisted_rcpts'] and type(opts['whitelisted_rcpts']) == 'string' then
		whitelisted_rcpts = split(opts['whitelisted_rcpts'], ',')
	end
	
	if opts['whitelisted_ip'] then
		whitelisted_ip = rspamd_config:add_hash_map (opts['whitelisted_ip'], 'Ratelimit whitelist ip map')
	end
	
	if opts['max_rcpt'] then
		max_rcpt = tonumber (opts['max_rcpt'])
	end
	
	if not opts['servers'] then
		rspamd_logger.err('no servers are specified')
	else
		upstreams = upstream_list.create(opts['servers'], default_port)
		if not upstreams then
			rspamd_logger.err('no servers are specified')
		else
			rspamd_config:register_pre_filter(rate_test)
			rspamd_config:register_post_filter(rate_set)
		end
	end
end

