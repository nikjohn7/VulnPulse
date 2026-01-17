# VulnPulse - Agentic Security Intelligence Assistant

Databricks lakehouse project with agentic RAG system for vulnerability intelligence.

## Project Overview

Build a conversational security intelligence system that answers complex questions about CVEs by retrieving and reasoning across multiple data sources (NVD, CISA KEV, EPSS). The Databricks lakehouse is the foundation; the agentic RAG assistant is the product.

**Target user**: Security teams who need to prioritize vulnerabilities  
**Core capability**: Natural language queries like "What critical vulns affect Apache?" or "Compare CVE-2024-21762 and CVE-2024-1709"

## Tech Stack

- **Platform**: Databricks (Free Edition - serverless only, restricted outbound)
- **Storage**: Delta Lake with Unity Catalog
- **Pipeline**: Lakeflow Declarative Pipelines (DLT) with Expectations
- **Search**: Databricks Vector Search (Delta Sync Index)
- **UI**: Streamlit via Databricks Apps
- **Deployment**: Asset Bundles
- **Local**: Python 3.10+, Databricks CLI

## Architecture

```
Bronze (raw) → Silver (normalized + validated) → Gold (analytics-ready)
                                                      ↓
                                              Vector Search Index
                                                      ↓
                                              Agentic RAG System
                                                      ↓
                                              Streamlit App
```

## Directory Structure

```
vulnpulse/
├── collector/          # Local data download scripts (NVD, KEV, EPSS)
├── databricks/
│   ├── bronze/         # Raw ingestion notebooks
│   ├── silver/         # DLT pipeline with Expectations
│   ├── gold/           # Analytics tables
│   └── vector_search/  # Index creation and queries
├── agent/
│   ├── tools/          # SQL query, vector search, CVE lookup, comparison
│   ├── router.py       # Intent classification
│   ├── synthesizer.py  # Response generation
│   └── orchestrator.py # Main agent loop
├── app/                # Streamlit Databricks App
├── resources/          # Asset Bundle configs
└── docs/               # Documentation
```

## Commands

```bash
# Local data collection
cd collector && python fetch_all.py

# Upload to Databricks Volume
make upload
# Or: databricks fs cp -r data/raw/ dbfs:/Volumes/vulnpulse/bronze/raw_files/

# Deploy with Asset Bundles
databricks bundle validate
databricks bundle deploy
databricks bundle run vulnpulse_daily_refresh

# Run Streamlit locally (for testing)
cd app && streamlit run app.py
```

## Unity Catalog Layout

```
vulnpulse (catalog)
├── bronze (schema)
│   ├── nvd_raw, kev_raw, epss_raw (tables)
│   └── raw_files (volume)
├── silver (schema)
│   ├── cve_core, cve_signals, cve_affected_products
│   └── cve_documents (for Vector Search - has CDF enabled)
├── gold (schema)
│   ├── vuln_enriched (main query table)
│   ├── vendor_risk_agg
│   └── kev_recent
└── agent (schema)
    └── query_logs (optional)
```

## Data Sources

| Source | URL | Format | Update Frequency |
|--------|-----|--------|------------------|
| NVD | nvd.nist.gov/feeds | JSON | Use "modified" feed |
| CISA KEV | cisa.gov/known-exploited-vulnerabilities | JSON/CSV | Daily |
| EPSS | first.org/epss | CSV | Daily |

## Agent Tool Routing

| Query Type | Example | Tool |
|------------|---------|------|
| Direct lookup | "What is CVE-2024-3094?" | `cve_lookup` |
| Filtered search | "Critical vulns in Apache" | `sql_query` |
| Semantic search | "Auth bypass vulnerabilities" | `vector_search` |
| Comparison | "Compare CVE-X and CVE-Y" | `comparison` |
| Trends | "What's exploited this month?" | `sql_query` + aggregation |

## Important Constraints

- **Free Edition limits**: Serverless only, no outbound internet, max 5 concurrent job tasks, 1 Vector Search endpoint, 1 App (auto-stops after 24h)
- **Data ingestion**: Download locally, upload to Volume (no direct API calls from Databricks)
- **Vector Search**: Must use Delta Sync Index (not Direct Vector Access), source table needs Change Data Feed enabled
- **No fake ML**: Don't train classifiers to predict KEV using EPSS - retrieval quality IS the ML problem

## Code Style

- Python: Type hints, docstrings for public functions
- SQL: Uppercase keywords, lowercase identifiers
- Notebooks: Use `# COMMAND ----------` separators, include markdown headers
- DLT: Use `@dlt.table` decorator with `@dlt.expect*` for quality rules

## Verification

Before marking any task complete:
1. Code runs without errors
2. Tables/files are created as expected
3. Sample queries return sensible results
4. Documentation updated if needed

## Current Task

Check `tasks.md` for the current milestone and active tasks. Complete one task fully before moving to the next.

## Reference Files

- `tasks.md` - All tasks with status tracking
- `docs/architecture.md` - Detailed system design
- `docs/agent-design.md` - Agent patterns and tool design