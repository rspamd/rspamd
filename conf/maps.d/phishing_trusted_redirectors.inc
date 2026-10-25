# Selected security URL wrappers, trusted only for displayed-domain mismatches.
# This does not declare their destinations safe or bypass phishing-feed checks.
# Keep exact hosts unless the provider documents a dedicated wrapper namespace.

# Proofpoint URL Defense (v1/v2 and v3):
# https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/URL_Decoder_API
urldefense.proofpoint.com
urldefense.com

# Microsoft Safe Links uses <DataCenterLocation>.safelinks.protection.outlook.com:
# https://learn.microsoft.com/en-us/defender-office-365/safe-links-about
*.safelinks.protection.outlook.com

# Mimecast URL Protect (exact regional URL hosts; no provider-wide wildcard):
# https://mimecastsupport.zendesk.com/hc/en-us/articles/34000790117011-Policies-Out-Of-the-Box-Settings
# The US host is also observed in the ham corpus used to validate this policy.
url.us.m.mimecastprotect.com
url.uk.m.mimecastprotect.com

# Barracuda Link Protection:
# https://documentation.campus.barracuda.com/wiki/spaces/EGD/pages/2850935
linkprotect.cudasvc.com

# Cisco Secure Email URL rewriting:
# https://www.cisco.com/c/en/us/support/docs/security/secure-email-gateway/218170-understand-the-url-defang-and-redirect-a.html
secure-web.cisco.com
