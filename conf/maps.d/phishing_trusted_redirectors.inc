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
