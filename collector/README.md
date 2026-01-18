# VulnPulse Data Collector

Downloads vulnerability data from public sources and saves to the local `data/raw/` directory for subsequent processing in the Databricks pipeline.

## Quick Start

```bash
# Fetch all data sources at once
python collector/fetch_all.py

# Or fetch individual sources
python collector/fetch_nvd.py
python collector/fetch_kev.py
python collector/fetch_epss.py
```

## Usage

### Unified Fetch (Recommended)

The `fetch_all.py` script orchestrates collection from all sources:

```bash
cd /path/to/vulnpulse
python collector/fetch_all.py
```

**Features:**
- Fetches from all three data sources in sequence
- Handles errors gracefully (continues if one source fails)
- Provides detailed progress output
- Prints summary with success/failure status for each source

**Example Output:**
```
============================================================
VulnPulse Data Collection
============================================================

[1/3] Fetching NVD (National Vulnerability Database)...
----------------------------------------
Fetching CVEs modified between 2024-01-01 and 2024-01-08...
✓ Successfully downloaded NVD feed with 1,234 CVE_Items

[2/3] Fetching CISA KEV (Known Exploited Vulnerabilities)...
----------------------------------------
✓ Successfully downloaded KEV catalog with 1,100 vulnerabilities

[3/3] Fetching EPSS (Exploit Prediction Scoring System)...
----------------------------------------
✓ Successfully downloaded EPSS scores with 230,000 CVE entries

============================================================
Collection Summary
============================================================

  ✓ Success NVD (National Vulnerability Database)
      1,234 records

  ✓ Success CISA KEV (Known Exploited Vulnerabilities)
      1,100 records

  ✓ Success EPSS (Exploit Prediction Scoring System)
      230,000 records

------------------------------------------------------------
Collection complete: 3/3 sources fetched
============================================================
```

### Individual Fetchers

Each data source has its own fetcher script that can be run independently:

| Script | Description | Default Behavior |
|--------|-------------|------------------|
| `fetch_nvd.py` | Fetches recently modified CVEs from NVD API 2.0 | Last 8 days of modifications |
| `fetch_kev.py` | Fetches CISA Known Exploited Vulnerabilities catalog | Full catalog |
| `fetch_epss.py` | Fetches current EPSS scores | All current scores |

## Data Sources

| Source | Description | URL | Update Frequency |
|--------|-------------|-----|------------------|
| **NVD** | National Vulnerability Database - CVE details, CVSS scores, CWE classifications, affected products (CPE) | https://services.nvd.nist.gov/rest/json/cves/2.0 | Continuous |
| **CISA KEV** | Known Exploited Vulnerabilities - CVEs actively exploited in the wild with remediation deadlines | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | As needed |
| **EPSS** | Exploit Prediction Scoring System - Probability scores (0-1) for exploitation likelihood in next 30 days | https://epss.cyentia.com/epss_scores-current.csv.gz | Daily |

## Output Structure

All data is saved to the `data/raw/` directory with date-stamped filenames:

```
data/raw/
├── nvd/
│   └── nvd_modified_YYYY-MM-DD.json.gz    # Gzipped JSON with CVE details
├── kev/
│   └── cisa_kev_YYYY-MM-DD.json           # JSON with KEV catalog
└── epss/
    └── epss_YYYY-MM-DD.csv                # CSV with EPSS scores
```

### File Formats

**NVD (`nvd_modified_YYYY-MM-DD.json.gz`)**
- Gzipped JSON file
- Contains `CVE_Items` array with vulnerability details
- Includes CVSS v2/v3 scores, descriptions, references, CPE configurations

**KEV (`cisa_kev_YYYY-MM-DD.json`)**
- Plain JSON file
- Contains `vulnerabilities` array
- Each entry has: cveID, vendorProject, product, dateAdded, dueDate, knownRansomwareCampaignUse

**EPSS (`epss_YYYY-MM-DD.csv`)**
- Plain CSV file (comment lines removed)
- Columns: cve, epss, percentile
- EPSS score is probability (0-1), percentile is relative ranking

## Requirements

- Python 3.8+
- `requests` library (included in project requirements.txt)

```bash
pip install -r requirements.txt
```

## Error Handling

- Each fetcher validates downloaded data before saving
- Network errors are caught and reported
- Invalid data formats are detected and reported
- `fetch_all.py` continues with remaining sources if one fails

## Rate Limiting

- **NVD API**: Limited to 5 requests per 30 seconds without API key. The fetcher includes automatic delays.
- **KEV/EPSS**: No rate limiting, but please be respectful of these free services.

## Environment Variables

Optional environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `NVD_API_KEY` | NVD API key for higher rate limits | None (uses public rate limit) |

## Next Steps

After fetching data, upload to Databricks for processing:

```bash
# Upload to Databricks Volumes
make upload

# Or manually using databricks CLI
databricks fs cp -r data/raw/ /Volumes/vulnpulse/bronze/raw_files/
