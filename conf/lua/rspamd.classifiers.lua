-- Detect language of message and selects appropriate statfiles for it

-- Common labels for specific statfiles
local many_recipients_label = 'many recipients'
local undisclosed_recipients_label = 'undisclosed recipients'
local list_label = 'maillist'
local long_subject_label = 'long subject'
local different_reply_to_label = 'different reply to'
local has_in_reply_label = 'reply message'

-- Get specific statfiles set based on message rules
local function get_specific_statfiles(classifier, task)
	local spec_st = {}
	-- More 5 recipients
	local st_many = classifier:get_statfile_by_label(many_recipients_label)
	if st_many then
		rcpt = task:get_recipients()
		if rcpt and table.maxn(rcpt) > 5 then
			print(table.maxn(rcpt))
			table.foreach(st_many, function(i,v) table.insert(spec_st,v) end)
		end
	end
	-- Undisclosed
	local st_undisc = classifier:get_statfile_by_label(undisclosed_recipients_label)
	if st_undisc then
		rcpt = task:get_recipients()
		if rcpt and table.maxn(rcpt) == 0 then
			table.foreach(st_undisc, function(i,v) table.insert(spec_st,v) end)
		end
	end
	-- Maillist
	local st_maillist = classifier:get_statfile_by_label(list_label)
	if st_maillist then
		local unsub_header = task:get_raw_header('List-Unsubscribe')
		if unsub_header and unsub_header[1] then
			table.foreach(st_maillist, function(i,v) table.insert(spec_st,v) end)
		end
	end
	-- Long subject
	local st_longsubj = classifier:get_statfile_by_label(long_subject_label)
	if st_longsubj then
		local subj = task:get_raw_header('Subject')
		if subj and subj[1] and string.len(subj[1]['value']) > 150 then
			table.foreach(st_longsubj, function(i,v) table.insert(spec_st,v) end)
		end
	end
	-- Reply-To != To
	local st_replyto = classifier:get_statfile_by_label(different_reply_to_label)
	if st_replyto then
		local to = task:get_raw_header('To')
		local reply_to = task:get_raw_header('Reply-To')
		if to and to[1] and reply_to and reply_to[1] then
			if string.lower(to[1]['value']) ~= string.lower(reply_to[1]['value']) then
				table.foreach(st_replyto, function(i,v) table.insert(spec_st,v) end)
			end
		end
	end
	-- Has In-Reply-To header
	local st_reply = classifier:get_statfile_by_label(has_in_reply_label)
	if st_reply then
		local inrep_header = task:get_raw_header('In-Reply-To')
		if inrep_header and inrep_header[1] then
			table.foreach(st_reply, function(i,v) table.insert(spec_st,v) end)
		end
	end
	
	if table.maxn(spec_st) > 1 then
		return spec_st
	else
		return nil
	end
end

classifiers['bayes'] = function(classifier, task, is_learn, is_spam)
	-- Subfunction for detection of message's language
	local detect_language = function(task)
		local parts = task:get_text_parts()
		for _,p in ipairs(parts) do
			local l = p:get_language()
			if l then
				return l
			end
		end
		return nil
	end

	-- Main procedure
	local selected = {}
	local spec_st = get_specific_statfiles(classifier, task)
	if spec_st then
		if is_learn then
			return spec_st
		else
			-- Merge tables
			table.foreach(spec_st, function(i,v) table.insert(selected,v) end)
		end
	end
	-- Detect statfile by language
	language = detect_language(task)
	if language then
		-- Find statfiles with specified language
		for _,st in ipairs(classifier:get_statfiles()) do
			-- Skip labeled statfiles
			if not st:get_label() then
				local st_l = st:get_param('language')
				if st_l and st_l == language then
					-- Insert statfile with specified language    
					table.insert(selected, st)
				end
			end
		end
		if table.maxn(selected) > 1 then
			return selected
		end
	end

	-- Language not detected or specific language statfiles have not been found
	for _,st in ipairs(classifier:get_statfiles()) do
		-- Skip labeled statfiles
		if not st:get_label() then
			local st_l = st:get_param('language')
			-- Insert only statfiles without language
			if not st_l then
				table.insert(selected, st)
			end
		end
	end
	if table.maxn(selected) > 1 then
		return selected
	end
	
	return nil
end

