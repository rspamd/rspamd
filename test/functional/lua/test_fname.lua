rspamd_config.TEST_FNAME = {
  callback = function(task)
    local r = task:get_parts()
    local fnames = {}
    for _,rh in ipairs(r) do
      if rh:get_filename() then
        table.insert(fnames, rh:get_filename())
      end
    end
    return true,1.0,fnames
  end
}