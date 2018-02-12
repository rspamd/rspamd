print('Check we will defer messages')

require './lib'
require './data'

setup()

send_message(innocuous_msg, innocuous_hdrs, 'test-id', 'defer@example.org', {'nerf@example.org'})
check_defer()

teardown()
