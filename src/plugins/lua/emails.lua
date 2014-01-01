-- Emails is module for different checks for emails inside messages

-- Rules format:
-- symbol = sym, map = file:///path/to/file, domain_only = yes
-- symbol = sym2, dnsbl = bl.somehost.com, domain_only = no
local rules = {}

-- Check rule for a single email
local function check_email_rule(task, rule, addr)
	local function emails_dns_cb(resolver, to_resolve, results, err)
		task:inc_dns_req()
		if results then
			rspamd_logger.info(string.format('<%s> email: [%s] resolved for symbol: %s', 
				task:get_message():get_message_id(), to_resolve, rule['symbol']))
			task:insert_result(rule['symbol'], 1)
		end
	end
	if rule['dnsbl'] then
		local to_resolve = ''
		if rule['domain_only'] then
			to_resolve = string.format('%s.%s', addr:get_host(), rule['dnsbl'])
		else
			to_resolve = string.format('%s.%s.%s', addr:get_user(), addr:get_host(), rule['dnsbl'])
		end
		task:get_resolver():resolve_a(task:get_session(), task:get_mempool(), 
			to_resolve, emails_dns_cb)
	elseif rule['map'] then
		if rule['domain_only'] then
			local key = addr:get_host()
			if rule['map']:get_key(key) then
				task:insert_result(rule['symbol'], 1)
				rspamd_logger.info(string.format('<%s> email: \'%s\' is found in list: %s', 
					task:get_message():get_message_id(), key, rule['symbol']))
			end
		else
			local key = string.format('%s@%s', addr:get_user(), addr:get_host())
			if rule['map']:get_key(key) then
				task:insert_result(rule['symbol'], 1)
				rspamd_logger.info(string.format('<%s> email: \'%s\' is found in list: %s', 
					task:get_message():get_message_id(), key, rule['symbol']))
			end
		end
	end
end

-- Check email
local function check_emails(task)
	local emails = task:get_emails()
	local checked = {}
	if emails then
		for _,addr in ipairs(emails) do
			local to_check = string.format('%s@%s', addr:get_user(), addr:get_host())
			if not checked['to_check'] then
				for _,rule in ipairs(rules) do
					check_email_rule(task, rule, addr)
				end
				checked[to_check] = true
			end 
		end
	end
end


-- Registration
if type(rspamd_config.get_api_version) ~= 'nil' then
	if rspamd_config:get_api_version() >= 2 then
		rspamd_config:register_module_option('emails', 'rule', 'string')
	else
		rspamd_logger.err('Invalid rspamd version for this plugin')
	end
end

local opts =  rspamd_config:get_all_opt('emails', 'rule')
if opts and type(opts) == 'table' then
	for k,v in pairs(opts) do
		if k == 'rule' and type(v) == 'table' then
			local rule = v
			if not rule['symbol'] then
				rule['symbol'] = k
			end
			if rule['map'] then
				rule['name'] = rule['map']
				rule['map'] = rspamd_config:add_hash_map (rule['name'])
			end
			if not rule['symbol'] or (not rule['map'] and not rule['dnsbl']) then
				rspamd_logger.err('incomplete rule')
			else
				table.insert(rules, rule)
				rspamd_config:register_virtual_symbol(rule['symbol'], 1.0)
			end
		end
	end
end

if table.maxn(rules) > 0 then
	-- add fake symbol to check all maps inside a single callback
	if type(rspamd_config.get_api_version) ~= 'nil' then
		rspamd_config:register_callback_symbol('EMAILS', 1.0, check_emails)
	else
		rspamd_config:register_symbol('EMAILS', 1.0, check_emails)
	end
end
