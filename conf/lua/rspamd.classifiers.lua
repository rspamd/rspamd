-- Detect language of message and selects appropriate statfiles for it

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
	language = detect_language(task)
	if language then
		-- Find statfiles with specified language
		local selected = {}
		for _,st in pairs(classifier:get_statfiles()) do
			local st_l = st:get_param('language')
			if st_l and st_l == language then
			    -- Insert statfile with specified language    
			    table.insert(selected, st)
			end
		end
		if table.maxn(selected) > 1 then
			return selected
		end
	else
		-- Language not detected
		local selected = {}
		for _,st in ipairs(classifier:get_statfiles()) do
			local st_l = st:get_param('language')
			-- Insert only statfiles without language
			if not st_l then
				table.insert(selected, st)
			end
		end
		if table.maxn(selected) > 1 then
			return selected
		end
	end

	return nil
end

