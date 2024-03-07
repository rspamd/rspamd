local replies = require('replies')

local function check(task)
    if replies.replies_check(task) then
        task:insert_result('REPLIES_CHECKED', 1.0, 'OK')
    end
end

rspamd_config:register_symbol({
    name = 'REPLIES_CHECKED',
    score = 1.0,
    callback = check,
})