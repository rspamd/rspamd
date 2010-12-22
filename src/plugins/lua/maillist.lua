-- Module for checking mail list headers

local symbol = 'MAILLIST'

-- EZMLM
-- Mailing-List: .*run by ezmlm
-- Precedence: bulk
-- List-Post: <mailto:
-- List-Help: <mailto:
-- List-Unsubscribe: <mailto:[a-zA-Z\.-]+-unsubscribe@
-- List-Subscribe: <mailto:[a-zA-Z\.-]+-subscribe@
function check_ml_ezmlm(task)
	local message = task:get_message()
	-- Mailing-List
	local header = message:get_header('mailing-list')
	if not header or not string.find(header[1], 'ezmlm$') then
		return false
	end
	-- Precedence
	header = message:get_header('precedence')
	if not header or not string.match(header[1], '^bulk$') then
		return false
	end
	-- Other headers
	header = message:get_header('list-post')
	if not header or not string.find(header[1], '^<mailto:') then
		return false
	end
	header = message:get_header('list-help')
	if not header or not string.find(header[1], '^<mailto:') then
		return false
	end
	-- Subscribe and unsubscribe
	header = message:get_header('list-subscribe')
	if not header or not string.find(header[1], '<mailto:[a-zA-Z.-]+-subscribe@') then
		return false
	end
	header = message:get_header('list-unsubscribe')
	if not header or not string.find(header[1], '<mailto:[a-zA-Z.-]+-unsubscribe@') then
		return false
	end

	return true
end

-- MailMan (the gnu mailing list manager)
-- Precedence: bulk [or list for v2]
-- List-Help: <mailto:
-- List-Post: <mailto:
-- List-Subscribe: .*<mailto:.*=subscribe>
-- List-Id: 
-- List-Unsubscribe: .*<mailto:.*=unsubscribe>
-- List-Archive: 
-- X-Mailman-Version: \d
function check_ml_mailman(task)
	local message = task:get_message()
	-- Mailing-List
	local header = message:get_header('x-mailman-version')
	if not header or not string.find(header[1], '^%d') then
		return false
	end
	-- Precedence
	header = message:get_header('precedence')
	if not header or (not string.match(header[1], '^bulk$') and not string.match(header[1], '^list$')) then
		return false
	end
	-- For reminders we have other headers than for normal messages
	header = message:get_header('x-list-administrivia')
	local subject = message:get_header('subject')
	if (header and string.find(header[1], 'yes')) or (subject and string.find(subject[1], 'mailing list memberships reminder$')) then
		if not message:get_header('errors-to') or not message:get_header('x-beenthere') then
			return false
		end
		header = message:get_header('x-no-archive')
		if not header or not string.find(header[1], 'yes') then
			return false
		end
		return true
	end

	-- Other headers
	header = message:get_header('list-id')
	if not header then
		return false
	end
	header = message:get_header('list-post')
	if not header or not string.find(header[1], '^<mailto:') then
		return false
	end
	header = message:get_header('list-help')
	if not header or not string.find(header[1], '^<mailto:') then
		return false
	end
	-- Subscribe and unsubscribe
	header = message:get_header('list-subscribe')
	if not header or not string.find(header[1], '<mailto:.*=subscribe>') then
		return false
	end
	header = message:get_header('list-unsubscribe')
	if not header or not string.find(header[1], '<mailto:.*=unsubscribe>') then
		return false
	end

	return true

end

-- Subscribe.ru
-- Precedence: normal
-- List-Id: <.*.subscribe.ru>
-- List-Help: <http://subscribe.ru/catalog/.*>
-- List-Subscribe: <mailto:.*-sub@subscribe.ru>
-- List-Unsubscribe: <mailto:.*-unsub@subscribe.ru>
-- List-Archive:  <http://subscribe.ru/archive/.*>
-- List-Owner: <mailto:.*-owner@subscribe.ru>
-- List-Post: NO
function check_ml_subscriberu(task)
	local message = task:get_message()
	-- List-Id
	local header = message:get_header('list-id')
	if not header or not string.find(header[1], '^<.*%.subscribe%.ru>$') then
		return false
	end
	-- Precedence
	header = message:get_header('precedence')
	if not header or not string.match(header[1], '^normal$') then
		return false
	end
	-- Other headers
	header = message:get_header('list-archive')
	if not header or not string.find(header[1], '^<http://subscribe.ru/archive/.*>$') then
		return false
	end
	header = message:get_header('list-owner')
	if not header or not string.find(header[1], '^<mailto:.*-owner@subscribe.ru>$') then
		return false
	end
	header = message:get_header('list-help')
	if not header or not string.find(header[1], '^<http://subscribe.ru/catalog/.*>$') then
		return false
	end
	-- Subscribe and unsubscribe
	header = message:get_header('list-subscribe')
	if not header or not string.find(header[1], '^<mailto:.*-sub@subscribe.ru>$') then
		return false
	end
	header = message:get_header('list-unsubscribe')
	if not header or not string.find(header[1], '^<mailto:.*-unsub@subscribe.ru>$') then
		return false
	end

	return true

end

function check_maillist(task)
	if check_ml_ezmlm(task) then
		task:insert_result(symbol, 1, 'ezmlm')
	elseif check_ml_mailman(task) then
		task:insert_result(symbol, 1, 'mailman')
	elseif check_ml_subscriberu(task) then
		task:insert_result(symbol, 1, 'subscribe.ru')
	end
end
-- Registration
if type(rspamd_config.get_api_version) ~= 'nil' then
	if rspamd_config:get_api_version() >= 1 then
		rspamd_config:register_module_option('maillist', 'symbol', 'string')
	end
end
-- Configuration
local opts =  rspamd_config:get_all_opt('maillist')
if opts then
	if opts['symbol'] then
		symbol = opts['symbol'] 
		rspamd_config:register_symbol(symbol, 1.0, 'check_maillist')
	end
end
