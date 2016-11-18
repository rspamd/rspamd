--[[
Copyright (c) 2011-2015, Vsevolod Stakhov <vsevolod@highsecure.ru>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

-- Detect language of message and selects appropriate statfiles for it

local fun = require "fun"

-- Common labels for specific statfiles
local many_recipients_label = 'many recipients'
local undisclosed_recipients_label = 'undisclosed recipients'
local list_label = 'maillist'
local long_subject_label = 'long subject'

-- Get specific statfiles set based on message rules
local function get_specific_statfiles(classifier, task)
	local spec_st = {}
	-- More 5 recipients
	local st_many = classifier:get_statfile_by_label(many_recipients_label)
	if st_many then
		local rcpt = task:get_recipients(2)
		if rcpt and #rcpt > 5 then
			fun.each(function(v) table.insert(spec_st,v) end, st_many)
		end
	end
	-- Undisclosed
	local st_undisc = classifier:get_statfile_by_label(undisclosed_recipients_label)
	if st_undisc then
		local rcpt = task:get_recipients(2)
		if rcpt and #rcpt == 0 then
			fun.each(function(v) table.insert(spec_st,v) end, st_undisc)
		end
	end
	-- Maillist
	local st_maillist = classifier:get_statfile_by_label(list_label)
	if st_maillist then
		local unsub_header = task:get_header_raw('List-Unsubscribe')
		if unsub_header then
			fun.each(function(v) table.insert(spec_st,v) end, st_maillist)
		end
	end
	-- Long subject
	local st_longsubj = classifier:get_statfile_by_label(long_subject_label)
	if st_longsubj then
		local subj = task:get_header_raw('Subject')
		if subj and string.len(subj) > 150 then
			fun.each(function(v) table.insert(spec_st,v) end, st_longsubj)
		end
	end

	if #spec_st > 1 then
		return spec_st
	else
		return nil
	end
end

classifiers['bayes'] = function(classifier, task, is_learn)
	-- Subfunction for detection of message's language
	local detect_language = function()
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
			fun.each(function(v) table.insert(selected,v) end, spec_st)
		end
	end
	-- Detect statfile by language
	local language = detect_language()
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
		if #selected > 1 then
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
	if #selected > 1 then
		return selected
	end

	return nil
end

