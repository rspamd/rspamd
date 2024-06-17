local url = require('rspamd_url')
local lua_util = require('lua_util')

local function task_inject_cb (task)
    local url_text = 'http://example.com?redir=http://another.com'
    local url_to_inject = url.create(task:get_mempool(), url_text)
    task:inject_url(url_to_inject)
    lua_util.debugm('INJECT_URL', task, 'URLS: %s', task:get_urls())
    lua_util.debugm('INJECT_URL', task, 'URL_SIZE: %s', #task:get_urls())
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
