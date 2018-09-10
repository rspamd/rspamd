print('Check we will rewrite subjects')

dofile './lib.lua'
dofile './data.lua'

setup()

send_message(gtube_rw_subject)
check_accept()
check_subject_rw()

teardown()
