print('Check we will rewrite subjects')

require './lib'
require './data'

setup()

send_message(gtube_rw_subject)
check_accept()
check_subject_rw()

teardown()
