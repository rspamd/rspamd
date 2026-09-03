*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Test Cases ***

# forged_recipients matches envelope and header addresses by mailbox
# identity: equivalent domains (googlemail.com = gmail.com, the shipped map
# and a test-only class), gmail dots and plus tags are not a mismatch.
# Every test carries its own envelope sender so greylisting sees no repeat.

RCPT GMAIL DOTS - NOT FORGED
  [Documentation]  Dotted To header vs undotted envelope recipient in gmail.com
  Scan File  ${RSPAMD_TESTDIR}/messages/forged_rcpt_gmail_dotted.eml
  ...  From=sender1@forged.example.test
  ...  Rcpt=johndoe@gmail.com
  Do Not Expect Symbol  FORGED_RECIPIENTS

RCPT GOOGLEMAIL TO GMAIL - NOT FORGED
  [Documentation]  To: johndoe@googlemail.com, RCPT TO johndoe@gmail.com
  Scan File  ${RSPAMD_TESTDIR}/messages/forged_rcpt_googlemail.eml
  ...  From=sender2@forged.example.test
  ...  Rcpt=johndoe@gmail.com
  Do Not Expect Symbol  FORGED_RECIPIENTS

RCPT GMAIL TO GOOGLEMAIL - NOT FORGED
  [Documentation]  To: johndoe@gmail.com, RCPT TO johndoe@googlemail.com
  Scan File  ${RSPAMD_TESTDIR}/messages/forged_rcpt_gmail.eml
  ...  From=sender3@forged.example.test
  ...  Rcpt=johndoe@googlemail.com
  Do Not Expect Symbol  FORGED_RECIPIENTS

RCPT GOOGLEMAIL DOTS TO GMAIL - NOT FORGED
  [Documentation]  To: j.o.h.n.doe@googlemail.com, RCPT TO johndoe@gmail.com
  Scan File  ${RSPAMD_TESTDIR}/messages/forged_rcpt_googlemail_dotted.eml
  ...  From=sender4@forged.example.test
  ...  Rcpt=johndoe@gmail.com
  Do Not Expect Symbol  FORGED_RECIPIENTS

RCPT SHIPPED MAP CLASS - NOT FORGED
  [Documentation]  me.com -> icloud.com comes only from the shipped map file
  Scan File  ${RSPAMD_TESTDIR}/messages/forged_rcpt_me_com.eml
  ...  From=sender5@forged.example.test
  ...  Rcpt=user@icloud.com
  Do Not Expect Symbol  FORGED_RECIPIENTS

RCPT TEST MAP CLASS - NOT FORGED
  [Documentation]  A domain pair known only from the second configured map
  Scan File  ${RSPAMD_TESTDIR}/messages/forged_rcpt_equiv.eml
  ...  From=sender6@forged.example.test
  ...  Rcpt=user@equiv-primary.test
  Do Not Expect Symbol  FORGED_RECIPIENTS

RCPT OTHER DOMAIN - FORGED
  [Documentation]  A real mismatch is still reported with the wire addresses
  Scan File  ${RSPAMD_TESTDIR}/messages/forged_rcpt_gmail.eml
  ...  From=sender7@forged.example.test
  ...  Rcpt=someone@else.example.test
  Expect Symbol With Exact Options  FORGED_RECIPIENTS  m:johndoe@gmail.com  s:someone@else.example.test

SENDER GOOGLEMAIL VS GMAIL - NOT FORGED
  [Documentation]  From: johndoe@googlemail.com with MAIL FROM johndoe@gmail.com;
  ...  the task still carries the transmitted From domain
  Scan File  ${RSPAMD_TESTDIR}/messages/forged_from_googlemail.eml
  ...  From=johndoe@gmail.com
  ...  Rcpt=rcpt8@forged.example.test
  Do Not Expect Symbol  FORGED_SENDER
  Expect Symbol With Exact Options  GET_FROM  John Doe,johndoe@googlemail.com,johndoe,googlemail.com

SENDER PLUS TAG - NOT FORGED
  [Documentation]  MAIL FROM johndoe+tag@gmail.com is the From: johndoe@gmail.com mailbox
  Scan File  ${RSPAMD_TESTDIR}/messages/forged_from_gmail.eml
  ...  From=johndoe+tag@gmail.com
  ...  Rcpt=rcpt9@forged.example.test
  Do Not Expect Symbol  FORGED_SENDER

SENDER OTHER USER - FORGED
  [Documentation]  Another user in the same domain is still a forged sender
  Scan File  ${RSPAMD_TESTDIR}/messages/forged_from_gmail.eml
  ...  From=janedoe@gmail.com
  ...  Rcpt=rcpt10@forged.example.test
  Expect Symbol With Exact Options  FORGED_SENDER  johndoe@gmail.com  janedoe@gmail.com
