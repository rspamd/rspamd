# Test rspamd gtube using scan file feature

. ${TEST_DIRNAME}/functions.sh

export RSPAMD_CONFIG="$TEST_DIRNAME/configs/trivial.conf"
run_rspamd
run perl "$TEST_DIRNAME/cases/scan_file.pl" "file=$TEST_DIRNAME/messages/gtube.eml"
check_output 'GTUBE'

run perl "$TEST_DIRNAME/cases/scan_file.pl" "path=$TEST_DIRNAME/messages/gtube.eml"
check_output 'GTUBE'

run perl "$TEST_DIRNAME/cases/scan_file.pl" "path=\"$TEST_DIRNAME/messages/gtube.eml\""
check_output 'GTUBE'

# Hex encode every character
_hex_name=`printf "$TEST_DIRNAME/messages/gtube.eml" | hexdump -v -e '/1 "%02x"' | sed 's/\(..\)/%\1/g'`

run perl "$TEST_DIRNAME/cases/scan_file.pl" "file=${_hex_name}"
check_output 'GTUBE'

_hex_name=`printf "\"$TEST_DIRNAME/messages/gtube.eml\"" | hexdump -v -e '/1 "%02x"' | sed 's/\(..\)/%\1/g'`
run perl "$TEST_DIRNAME/cases/scan_file.pl" "path=${_hex_name}"
check_output 'GTUBE'
