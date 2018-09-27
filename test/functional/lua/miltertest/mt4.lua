print('Check we will defer messages')

dofile './lib.lua'
dofile './data.lua'

setup()

send_message(innocuous_msg, innocuous_hdrs, 'test-id', 'defer@example.org', {'nerf@example.org'})
check_defer()

teardown()
