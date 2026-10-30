local lua_mime = require "lua_mime"

rspamd_config:register_symbol({
  name = 'DKIM_TEST_MODIFY_HEADERS',
  score = 0.0,
  callback = function(task)
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
    return true
  end,
})

rspamd_config:register_dependency('DKIM_SIGNED', 'DKIM_TEST_MODIFY_HEADERS')
