*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Library         String
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}           ${RSPAMD_TESTDIR}/configs/arc_signing/roundtrip.conf
${MESSAGE_RSA}      ${RSPAMD_TESTDIR}/messages/dmarc/fail_none.eml
${MESSAGE_ED25519}  ${RSPAMD_TESTDIR}/messages/dmarc/ed25519_from.eml
${REDIS_SCOPE}      Suite
${RSPAMD_SCOPE}     Suite
${RSPAMD_URL_TLD}   ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
ARC ROUNDTRIP RSA SIGN AND VERIFY
  # First pass: Sign the message with RSA key and check for ARC_SIGNED
  ${result} =  Scan Message With Rspamc  ${MESSAGE_RSA}  -u  bob@cacophony.za.org  --mime
  Should Contain  ${result.stdout}  ARC_SIGNED

  # Write signed message to robot-save directory for debugging
  ${signed_file} =  Write Mime Message To File  ${result}  rsa_signed.eml

  # Second pass: Verify the ARC signature we just created
  ${verify_result} =  Scan Message With Rspamc  ${signed_file}  --header=Settings-Id:arc_verify
  Should Contain  ${verify_result.stdout}  ARC_ALLOW
  Should Not Contain  ${verify_result.stdout}  ARC_INVALID
  Should Not Contain  ${verify_result.stdout}  ARC_REJECT

  # Cleanup
  Remove File  ${signed_file}

ARC ROUNDTRIP ED25519 SIGN AND VERIFY
  # First pass: Sign the message with ed25519 key and check for ARC_SIGNED
  ${result} =  Scan Message With Rspamc  ${MESSAGE_ED25519}  -u  bob@ed25519.za.org  --mime
  Should Contain  ${result.stdout}  ARC_SIGNED

  # Write signed message to robot-save directory for debugging
  ${signed_file} =  Write Mime Message To File  ${result}  ed25519_signed.eml

  # Second pass: Verify the ARC signature we just created
  ${verify_result} =  Scan Message With Rspamc  ${signed_file}  --header=Settings-Id:arc_verify
  Should Contain  ${verify_result.stdout}  ARC_ALLOW
  Should Not Contain  ${verify_result.stdout}  ARC_INVALID
  Should Not Contain  ${verify_result.stdout}  ARC_REJECT

  # Cleanup
  Remove File  ${signed_file}

ARC ED25519 ALGORITHM CHECK
  # Sign with ed25519 and verify the algorithm is correctly set
  ${result} =  Scan Message With Rspamc  ${MESSAGE_ED25519}  -u  bob@ed25519.za.org  --mime
  Should Contain  ${result.stdout}  ARC_SIGNED
  Should Contain  ${result.stdout}  a=ed25519-sha256
  Should Not Contain  ${result.stdout}  a=rsa-sha256

ARC RSA ALGORITHM CHECK
  # Sign with RSA and verify the algorithm is correctly set
  ${result} =  Scan Message With Rspamc  ${MESSAGE_RSA}  -u  bob@cacophony.za.org  --mime
  Should Contain  ${result.stdout}  ARC_SIGNED
  Should Contain  ${result.stdout}  a=rsa-sha256
  Should Not Contain  ${result.stdout}  a=ed25519-sha256

ARC CHAIN ROUNDTRIP RSA DOUBLE SIGN AND VERIFY
  # First sign: Create i=1
  ${result1} =  Scan Message With Rspamc  ${MESSAGE_RSA}  -u  bob@cacophony.za.org  --mime
  Should Contain  ${result1.stdout}  ARC_SIGNED

  # Write first signed message
  ${signed_file1} =  Write Mime Message To File  ${result1}  rsa_chain_i1.eml

  # Verify i=1 header is present
  Should Contain  ${result1.stdout}  i=1

  # Second sign: Create i=2 (sign the already-signed message)
  ${result2} =  Scan Message With Rspamc  ${signed_file1}  -u  bob@cacophony.za.org  --mime
  Should Contain  ${result2.stdout}  ARC_SIGNED

  # Write second signed message
  ${signed_file2} =  Write Mime Message To File  ${result2}  rsa_chain_i2.eml

  # Verify both i=1 and i=2 headers are present in the chain
  Should Contain  ${result2.stdout}  i=1
  Should Contain  ${result2.stdout}  i=2

  # Verify the whole chain
  ${verify_result} =  Scan Message With Rspamc  ${signed_file2}  --header=Settings-Id:arc_verify
  Should Contain  ${verify_result.stdout}  ARC_ALLOW
  Should Not Contain  ${verify_result.stdout}  ARC_INVALID
  Should Not Contain  ${verify_result.stdout}  ARC_REJECT

  # Cleanup
  Remove File  ${signed_file1}
  Remove File  ${signed_file2}

ARC CHAIN ROUNDTRIP ED25519 DOUBLE SIGN AND VERIFY
  # First sign: Create i=1
  ${result1} =  Scan Message With Rspamc  ${MESSAGE_ED25519}  -u  bob@ed25519.za.org  --mime
  Should Contain  ${result1.stdout}  ARC_SIGNED

  # Write first signed message
  ${signed_file1} =  Write Mime Message To File  ${result1}  ed25519_chain_i1.eml

  # Verify i=1 header is present
  Should Contain  ${result1.stdout}  i=1

  # Second sign: Create i=2 (sign the already-signed message)
  ${result2} =  Scan Message With Rspamc  ${signed_file1}  -u  bob@ed25519.za.org  --mime
  Should Contain  ${result2.stdout}  ARC_SIGNED

  # Write second signed message
  ${signed_file2} =  Write Mime Message To File  ${result2}  ed25519_chain_i2.eml

  # Verify both i=1 and i=2 headers are present in the chain
  Should Contain  ${result2.stdout}  i=1
  Should Contain  ${result2.stdout}  i=2

  # Verify the whole chain
  ${verify_result} =  Scan Message With Rspamc  ${signed_file2}  --header=Settings-Id:arc_verify
  Should Contain  ${verify_result.stdout}  ARC_ALLOW
  Should Not Contain  ${verify_result.stdout}  ARC_INVALID
  Should Not Contain  ${verify_result.stdout}  ARC_REJECT

  # Cleanup
  Remove File  ${signed_file1}
  Remove File  ${signed_file2}

*** Keywords ***
Write Mime Message To File
  [Arguments]  ${mime_result}  ${filename}
  # Save to robot-save directory for artifact preservation
  ${artifact_file} =  Set Variable  ${EXECDIR}/robot-save/${filename}
  Create File  ${artifact_file}  ${mime_result.stdout}
  Log  Saved signed message to ${artifact_file}

  # Also save to temp directory for test use
  ${temp_file} =  Set Variable  ${RSPAMD_TMPDIR}/${filename}
  Create File  ${temp_file}  ${mime_result.stdout}

  # Count ARC headers for debugging
  ${lines} =  Split To Lines  ${mime_result.stdout}
  ${arc_count} =  Set Variable  ${0}
  FOR  ${line}  IN  @{lines}
    ${is_arc_header} =  Run Keyword And Return Status  Should Match Regexp  ${line}  ^ARC-.*:
    IF  ${is_arc_header}
      ${arc_count} =  Evaluate  ${arc_count} + 1
    END
  END
  Log  Total ARC headers found in mime output: ${arc_count}

  # Log first few lines of the created file for debugging
  ${lines} =  Split To Lines  ${mime_result.stdout}
  ${first_10_lines} =  Get Slice From List  ${lines}  0  10
  Log  First 10 lines of signed message file:
  FOR  ${line}  IN  @{first_10_lines}
    Log  ${line}
  END

  # Log any ARC headers found
  FOR  ${line}  IN  @{lines}
    ${is_arc_header} =  Run Keyword And Return Status  Should Match Regexp  ${line}  ^ARC-.*:
    IF  ${is_arc_header}
      Log  Found ARC header: ${line}
    END
  END

  [Return]  ${temp_file}

Write Signed Message To File
  [Arguments]  ${scan_result}  ${filename}
  # DEPRECATED: This method doesn't work with -p flag
  # Use Write Mime Message To File instead
  Log  WARNING: Write Signed Message To File is deprecated, use Write Mime Message To File
  ${temp_file} =  Set Variable  ${RSPAMD_TMPDIR}/${filename}
  Create File  ${temp_file}  ${scan_result.stdout}
  [Return]  ${temp_file}
