local lua_mime = require "lua_mime"

rspamd_config:register_symbol({
  name = 'DKIM_TEST_MODIFY_HEADERS',
  score = 0.0,
  callback = function(task)
    -- Modify only the messages being signed, not the ones being verified
    if not task:get_user() then
      return false
    end
    lua_mime.modify_headers(task, {
      remove = { ['From'] = 0 },
      add = {
        ['From'] = {
          order = 1,
          value = 'test <example@cacophony.za.org>',
        },
      },
      order = { 'From' },
    })
    lua_mime.modify_headers(task, {
      add = {
        ['List-Subscribe'] = {
          order = 1,
          value = 'test',
        },
      },
      order = { 'List-Subscribe' },
    })
    -- Appended after any List-Post headers the message already has
    lua_mime.modify_headers(task, {
      add = {
        ['List-Post'] = {
          order = -1,
          value = '<mailto:added@cacophony.za.org>',
        },
      },
      order = { 'List-Post' },
    })
    return true
  end,
})

rspamd_config:register_dependency('DKIM_SIGNED', 'DKIM_TEST_MODIFY_HEADERS')
