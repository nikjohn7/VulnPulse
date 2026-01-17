# Data Collector

Downloads vulnerability data from public sources and saves to local `data/raw/` directory.

## Usage

```bash
python fetch_all.py
```

## Data Sources

- **NVD**: National Vulnerability Database (CVE details, CVSS scores)
- **CISA KEV**: Known Exploited Vulnerabilities catalog
- **EPSS**: Exploit Prediction Scoring System

## Output Structure

```
data/raw/
├── nvd/nvd_modified_YYYY-MM-DD.json.gz
├── kev/cisa_kev_YYYY-MM-DD.json
└── epss/epss_YYYY-MM-DD.csv
```
