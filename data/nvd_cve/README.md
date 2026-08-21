# Local NVD CVE JSON records for exact-ID canonical lookup.
#
# Populate with:
#   python3 -m rag.ingest_nvd_cve --cve CVE-YYYY-NNNN
#   python3 -m rag.ingest_nvd_cve --from-file path/to/nvd.json
#
# Scenario runtime reads these files only. It does not call the NVD API.
# These records fill CVE-local description/CPE gaps. They are not indexed
# into Chroma and do not replace CISA CSAF or CISA CSV sources.
