*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE}              ${RSPAMD_TESTDIR}/messages/spam_message.eml
${MESSAGE2}             ${RSPAMD_TESTDIR}/messages/spam.eml
${MESSAGE3}             ${RSPAMD_TESTDIR}/messages/freemail.eml
${SETTINGS_GREYLIST}    {symbols_enabled = [GREYLIST_CHECK, GREYLIST_SAVE], symbols = [FOUR_POINTS]}
${SETTINGS_NOGREYLIST}  {symbols_enabled = [GREYLIST_CHECK, GREYLIST_SAVE], symbols = [THREE_POINTS]}
${SETTINGS_RESCORED}    {actions { greylist = 3 }, symbols_enabled = [GREYLIST_CHECK, GREYLIST_SAVE], symbols = [THREE_POINTS]}
${SETTINGS_REJECTED}    {actions { greylist = 3 }, symbols_enabled = [GREYLIST_CHECK, GREYLIST_SAVE], symbols = [TWENTY_POINTS]}
${SETTINGS_FORCED}      {symbols_enabled = [GREYLIST_CHECK, GREYLIST_SAVE, GREY_TEST_FORCE, GREY_TEST_OVERRIDE]}
${SETTINGS_FORCED_SCORE}  {symbols_enabled = [GREYLIST_CHECK, GREYLIST_SAVE, GREY_TEST_FORCE], symbols = [FOUR_POINTS]}
${FORCED_MSG}          ${RSPAMD_TESTDIR}/messages/greylist_forced

*** Test Cases ***
GREYLIST NEW
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_GREYLIST}
  Expect Symbol With Option  GREYLIST  greylisted
  Expect Action  soft reject

GREYLIST EARLY
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_GREYLIST}
  Expect Symbol With Option  GREYLIST  greylisted
  Expect Action  soft reject

GREYLIST NOT GREYLISTED
  Scan File  ${MESSAGE2}
  ...  Settings=${SETTINGS_NOGREYLIST}
  Do Not Expect Symbol  GREYLIST
  Expect Action  no action

GREYLIST REJECTED
  Scan File  ${MESSAGE3}
  ...  Settings=${SETTINGS_REJECTED}
  Do Not Expect Symbol  GREYLIST
  Expect Action  reject

GREYLIST RESCORED
  Scan File  ${MESSAGE2}
  ...  Settings=${SETTINGS_RESCORED}
  Expect Symbol With Option  GREYLIST  greylisted
  Expect Action  soft reject

GREYLIST PASS
  Sleep  4s  Wait greylisting timeout
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_GREYLIST}
  Expect Symbol With Option  GREYLIST  pass
  Expect Action  no action

# A module asks for a longer delay of one message; the global timeout is 4s here,
# the requested delays are 10s (long) and 6s (short). The first scans start the
# clock, the checks after the sleeps below read the outcome.
GREYLIST FORCED DELAY IGNORES SCORE
  Scan File  ${FORCED_MSG}_a.eml  From=forced-a@example.com  Grey-Test=long
  ...  Settings=${SETTINGS_FORCED}
  Expect Symbol With Option  GREYLIST  new record
  Expect Symbol With Option  GREYLIST  by:testmod
  Expect Action  soft reject

GREYLIST FORCED DELAY IS BOUND TO THE BODY
  # Another message of the same sender must not be held: only the body has a record
  Scan File  ${FORCED_MSG}_b.eml  From=forced-a@example.com
  ...  Settings=${SETTINGS_FORCED}
  Do Not Expect Symbol  GREYLIST
  Expect Action  no action

GREYLIST FORCED WITHOUT DELAY KEEPS SCORE GATE
  # What mx_check does: bare forcing still needs the score to reach greylisting
  Scan File  ${FORCED_MSG}_c.eml  From=forced-c@example.com  Grey-Test=plain
  ...  Settings=${SETTINGS_FORCED}
  Do Not Expect Symbol  GREYLIST
  Expect Action  no action

GREYLIST FORCED WITHOUT DELAY COVERS BODY AND ENVELOPE
  # mx_check asks for classic greylisting: another message of the sender is held too
  Scan File  ${FORCED_MSG}_c.eml  From=forced-h@example.com  Grey-Test=plain
  ...  Settings=${SETTINGS_FORCED_SCORE}
  Expect Symbol With Option  GREYLIST  new record
  Expect Action  soft reject
  Scan File  ${FORCED_MSG}_g.eml  From=forced-h@example.com
  ...  Settings=${SETTINGS_FORCED}
  Expect Symbol With Option  GREYLIST  too early
  Expect Action  soft reject

GREYLIST FORCED DELAY AND CLASSIC COVER BODY AND ENVELOPE
  Scan File  ${FORCED_MSG}_h.eml  From=forced-i@example.com  Grey-Test=long,plain
  ...  Settings=${SETTINGS_FORCED_SCORE}
  Expect Symbol With Option  GREYLIST  by:testmod
  Expect Action  soft reject
  Scan File  ${FORCED_MSG}_g.eml  From=forced-i@example.com
  ...  Settings=${SETTINGS_FORCED}
  Expect Symbol With Option  GREYLIST  too early
  Expect Action  soft reject

GREYLIST FORCED DELAY AND CLASSIC WITH LOW SCORE STAYS BODY ONLY
  # The classic request alone would have been dropped by the score gate
  Scan File  ${FORCED_MSG}_i.eml  From=forced-j@example.com  Grey-Test=long,plain
  ...  Settings=${SETTINGS_FORCED}
  Expect Symbol With Option  GREYLIST  by:testmod
  Expect Action  soft reject
  Scan File  ${FORCED_MSG}_g.eml  From=forced-j@example.com
  ...  Settings=${SETTINGS_FORCED}
  Do Not Expect Symbol  GREYLIST
  Expect Action  no action

GREYLIST FORCED DELAY WITH SCORE
  Scan File  ${FORCED_MSG}_d.eml  From=forced-d@example.com  Grey-Test=long
  ...  Settings=${SETTINGS_FORCED_SCORE}
  Expect Symbol With Option  GREYLIST  by:testmod
  Expect Action  soft reject
  Scan File  ${FORCED_MSG}_g.eml  From=forced-d@example.com
  ...  Settings=${SETTINGS_FORCED}
  Expect Action  soft reject

GREYLIST FORCED SHORTER DELAY KEEPS LONGER
  Scan File  ${FORCED_MSG}_e.eml  From=forced-e@example.com  Grey-Test=long,short
  ...  Settings=${SETTINGS_FORCED}
  Expect Action  soft reject
  Scan File  ${FORCED_MSG}_e.eml  From=forced-e@example.com  Grey-Test=short
  ...  Settings=${SETTINGS_FORCED}
  Expect Action  soft reject

GREYLIST FORCED SHORT DELAY FIRST
  Scan File  ${FORCED_MSG}_f.eml  From=forced-f@example.com  Grey-Test=short
  ...  Settings=${SETTINGS_FORCED}
  Expect Action  soft reject

GREYLIST FORCED REQUESTS AGGREGATE IN REVERSE ORDER
  Scan File  ${FORCED_MSG}_a.eml  From=aggregate@example.com  Rcpt=aggregate@example.com  Grey-Test=short,long
  ...  Settings=${SETTINGS_FORCED}
  Expect Symbol With Option  GREYLIST  by:testmod
  Expect Action  soft reject

GREYLIST FORCED BODY AND META HAVE INDEPENDENT WAITS
  Scan File  ${FORCED_MSG}_b.eml  From=independent@example.com  Rcpt=independent@example.com  Grey-Test=short,meta
  ...  Settings=${SETTINGS_FORCED}
  Expect Symbol With Option  GREYLIST  by:metamod
  Expect Action  soft reject

GREYLIST FORCED META ONLY DOES NOT CREATE BODY RECORD
  Scan File  ${FORCED_MSG}_a.eml  From=meta-only@example.com  Rcpt=meta-only@example.com  Grey-Test=meta
  ...  Settings=${SETTINGS_FORCED}
  Expect Symbol With Option  GREYLIST  by:metamod
  Expect Action  soft reject
  Scan File  ${FORCED_MSG}_a.eml  From=unrelated@example.com  Rcpt=meta-only@example.com
  ...  Settings=${SETTINGS_FORCED}
  Do Not Expect Symbol  GREYLIST
  Expect Action  no action

GREYLIST FORCED OTHER PRE-RESULT WINS
  # Greylisting uses the lowest pre-result priority, so a later pre-result overrides it
  Scan File  ${FORCED_MSG}_b.eml  From=forced-g@example.com  Grey-Test=long,override
  ...  Settings=${SETTINGS_FORCED}
  Expect Action  reject

GREYLIST FORCED DELAY OUTLASTS GLOBAL TIMEOUT
  Sleep  7s  Past the global timeout, before the requested delays end
  Scan File  ${FORCED_MSG}_a.eml  From=forced-a@example.com
  ...  Settings=${SETTINGS_GREYLIST}
  Expect Symbol With Option  GREYLIST  by:testmod
  Expect Action  soft reject
  # The same holds when the score alone would greylist
  Scan File  ${FORCED_MSG}_d.eml  From=forced-d@example.com
  ...  Settings=${SETTINGS_GREYLIST}
  Expect Symbol With Option  GREYLIST  by:testmod
  Expect Action  soft reject
  # A shorter request did not shorten the running 10s wait
  Scan File  ${FORCED_MSG}_e.eml  From=forced-e@example.com
  ...  Settings=${SETTINGS_GREYLIST}
  Expect Action  soft reject
  Scan File  ${FORCED_MSG}_a.eml  From=aggregate@example.com  Rcpt=aggregate@example.com
  ...  Settings=${SETTINGS_FORCED}
  Expect Action  soft reject
  Scan File  ${FORCED_MSG}_b.eml  From=independent@example.com  Rcpt=independent@example.com
  ...  Settings=${SETTINGS_FORCED}
  Expect Symbol With Option  GREYLIST  by:metamod
  Expect Action  soft reject
  Scan File  ${FORCED_MSG}_c.eml  From=independent@example.com  Rcpt=independent@example.com
  ...  Settings=${SETTINGS_FORCED}
  Expect Action  soft reject
  Scan File  ${FORCED_MSG}_g.eml  From=forced-d@example.com
  ...  Settings=${SETTINGS_FORCED}
  Expect Action  no action
  Scan File  ${FORCED_MSG}_b.eml  From=meta-only@example.com  Rcpt=meta-only@example.com
  ...  Settings=${SETTINGS_FORCED}
  Expect Symbol With Option  GREYLIST  by:metamod
  Expect Action  soft reject

GREYLIST FORCED LONGER DELAY CREDITS TIME SERVED
  # The 6s wait is over, but 10s were requested now: only the remainder is owed
  Scan File  ${FORCED_MSG}_f.eml  From=forced-f@example.com  Grey-Test=long
  ...  Settings=${SETTINGS_FORCED}
  Expect Symbol With Option  GREYLIST  new record
  Expect Symbol With Option  GREYLIST  by:testmod
  Expect Action  soft reject

GREYLIST FORCED DELAY PASSES WHEN SERVED
  Sleep  4s  Past the requested delays
  Scan File  ${FORCED_MSG}_a.eml  From=forced-a@example.com
  ...  Settings=${SETTINGS_GREYLIST}
  Expect Symbol With Option  GREYLIST  pass
  Expect Action  no action
  # Restarting the full 10s at the later request would still hold this
  Scan File  ${FORCED_MSG}_f.eml  From=forced-f@example.com
  ...  Settings=${SETTINGS_GREYLIST}
  Expect Symbol With Option  GREYLIST  pass
  Expect Action  no action
  Scan File  ${FORCED_MSG}_b.eml  From=independent@example.com  Rcpt=independent@example.com  Grey-Test=short,meta
  ...  Settings=${SETTINGS_FORCED}
  Expect Symbol With Option  GREYLIST  pass
  Expect Action  no action
  Scan File  ${FORCED_MSG}_a.eml  From=meta-only@example.com  Rcpt=meta-only@example.com  Grey-Test=meta
  ...  Settings=${SETTINGS_FORCED}
  Expect Symbol With Option  GREYLIST  pass
  Expect Action  no action
