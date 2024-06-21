local url = require('rspamd_url')
local lua_util = require('lua_util')

local function task_inject_cb (task)
    local url_text = 'http://example.com?redir=https://another.com'
    local url_to_inject = url.create(task:get_mempool(), url_text)
    lua_util.debugm('inj', task, 'MIME_PARTS: %s', task:get_parts())
    task:inject_url(url_to_inject)
    if #(task:get_urls()) == 2 then
        return true
    end
    return false
end

rspamd_config:register_symbol({
    name = 'TEST_INJECT_URL',
    score = 1.0,
    callback = task_inject_cb
})
