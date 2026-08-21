# Normalized CISA ICS full-advisory records for exact defense fallback.
#
# Populate with:
#   python3 -m rag.sync_cve_coverage --no-network
#   python3 -m rag.sync_cve_coverage --cve CVE-YYYY-NNNN --limit 1
#
# Scenario runtime reads these files only. It does not fetch CISA HTML.
