local url = require('rspamd_url')

local function task_inject_cb (task)
    local url_text = 'http://example.com?redir=http://another.com'
    local url = url.create(task:get_mempool(), url_text)
    task:inject_url(url)
    return true
end

rspamd_config:register_symbol({
    name = 'TEST_INJECT_URL',
    score = 1.0,
    callback = task_inject_cb
})
