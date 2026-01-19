# VulnPulse Tasks

> **Instructions**: Work on the CURRENT task. When complete, move it to DONE and pull the next from TODO to CURRENT. Each task has requirements and verification criteria—implement however you see fit, but pass all verifications before marking done.

---

## Task Queue

### CURRENT
- 4.2: Create Gold Aggregation Tables

### TODO
- 4.3: Create Vector Search Index Setup
- 4.4: Create Vector Search Query Utilities
- 5.1: Create CVE Lookup Tool
- 5.2: Create SQL Query Tool
- 5.3: Create Vector Search Tool
- 5.4: Create Comparison Tool
- 5.5: Create Intent Router
- 5.6: Create Response Synthesizer
- 5.7: Create Main Orchestrator
- 5.8: Create Agent Test Notebook
- 6.1: Create Streamlit App
- 6.2: Create Asset Bundle Configuration
- 6.3: Create Demo Script and Final Docs

### DONE
- 0.1: Initialize Repository Structure ✓
- 0.2: Create Requirements Files ✓
- 0.3: Create Main README ✓
- 0.4: Create Makefile ✓
- 1.1: Create NVD Fetcher ✓
- 1.2: Create KEV Fetcher ✓
- 1.3: Create EPSS Fetcher ✓
- 1.4: Create Unified Fetch Script ✓
- 2.1: Create Unity Catalog Setup Script ✓
- 2.2: Create Bronze Ingestion Notebook ✓
- 3.1: Create Silver DLT Pipeline - CVE Core ✓
- 3.2: Add Silver DLT Pipeline - CVE Signals ✓
- 3.3: Add Silver DLT Pipeline - CVE Affected Products ✓
- 3.4: Add Silver DLT Pipeline - CVE Documents ✓
- 3.5: Document Data Quality Expectations ✓
- 4.1: Create Gold Enriched Vulnerability Table ✓

---

## Milestone 0: Project Setup

### Task 0.1: Initialize Repository Structure

**Create directories**:
```
vulnpulse/
├── collector/
├── databricks/bronze/
├── databricks/silver/
├── databricks/gold/
├── databricks/vector_search/
├── agent/tools/
├── app/components/
├── resources/
├── docs/
└── data/raw/{nvd,kev,epss}/
```

**Create placeholder files**:
- `collector/__init__.py`, `collector/README.md`
- `agent/__init__.py`, `agent/tools/__init__.py`
- `app/components/__init__.py`
- `docs/architecture.md`, `docs/agent-design.md`
- `.gitignore` (Python defaults + `data/raw/`, `.env`, `__pycache__/`, `.venv/`)

**Verification**: All directories and files exist.

---

### Task 0.2: Create Requirements Files

**Create `requirements.txt`**:
- requests, pandas, pyarrow, python-dotenv, databricks-sdk

**Create `requirements-app.txt`**:
- streamlit, pandas, plotly

**Create `.env.example`**:
- DATABRICKS_HOST, DATABRICKS_TOKEN placeholders

**Verification**: `pip install -r requirements.txt` succeeds.

---

### Task 0.3: Create Main README

**Create `README.md` with**:
1. Title: "VulnPulse: AI-Powered Vulnerability Intelligence"
2. One-paragraph description of what it does
3. Features bullet list (natural language queries, semantic search, risk prioritization, trend analysis)
4. Architecture diagram (Mermaid flowchart: Data Sources → Bronze → Silver → Gold → Vector Search → Agent → App)
5. Quick Start (prerequisites, clone, install, configure, fetch data, deploy)
6. Project structure overview
7. Data sources table (NVD, CISA KEV, EPSS with URLs)
8. License: MIT

**Verification**: README renders correctly in GitHub preview, diagram displays.

---

### Task 0.4: Create Makefile

**Create `Makefile` with targets**:
- `help`: List available commands
- `fetch`: Run `collector/fetch_all.py`
- `upload`: Copy `data/raw/*` to `/Volumes/vulnpulse/bronze/raw_files/` using databricks CLI
- `deploy`: Run `databricks bundle validate && databricks bundle deploy`
- `clean`: Remove local data files

**Verification**: `make help` displays all commands.

---

## Milestone 1: Data Collection

### Task 1.1: Create NVD Fetcher

**Create `collector/fetch_nvd.py`**

**Requirements**:
- Download from: `https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz`
- Save to: `data/raw/nvd/nvd_modified_YYYY-MM-DD.json.gz`
- Validate downloaded file is valid gzipped JSON
- Print count of CVE_Items in the feed

**Verification**: Running script downloads file, prints CVE count (should be hundreds to thousands).

---

### Task 1.2: Create KEV Fetcher

**Create `collector/fetch_kev.py`**

**Requirements**:
- Download from: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Save to: `data/raw/kev/cisa_kev_YYYY-MM-DD.json`
- Print count of vulnerabilities array entries

**Verification**: Running script downloads file, prints count (~1000+ entries).

---

### Task 1.3: Create EPSS Fetcher

**Create `collector/fetch_epss.py`**

**Requirements**:
- Download from: `https://epss.cyentia.com/epss_scores-current.csv.gz`
- Decompress and save to: `data/raw/epss/epss_YYYY-MM-DD.csv`
- Skip comment lines (start with #)
- Print count of CVE scores

**Verification**: Running script downloads CSV, prints count (~200k+ scores).

---

### Task 1.4: Create Unified Fetch Script

**Create `collector/fetch_all.py`**

**Requirements**:
- Import and call all three fetchers
- Handle errors gracefully (continue if one fails)
- Print summary: "Collection complete: X/3 sources fetched"

**Update `collector/README.md`**:
- Usage instructions for fetch_all.py
- Table of data sources and output paths

**Verification**: `python collector/fetch_all.py` fetches all three sources, shows summary.

---

## Milestone 2: Bronze Layer

### Task 2.1: Create Unity Catalog Setup Script

**Create `databricks/setup_catalog.sql`**

**Requirements**:
- Create catalog: `vulnpulse`
- Create schemas: `bronze`, `silver`, `gold`, `agent`
- Create volume: `bronze.raw_files`
- Add COMMENT to each schema explaining its purpose

**Verification**: Running in Databricks SQL creates all objects; `SHOW SCHEMAS IN vulnpulse` shows 4 schemas.

---

### Task 2.2: Create Bronze Ingestion Notebook

**Create `databricks/bronze/ingest.py`** (Databricks notebook format)

**Requirements**:
- Read files from `/Volumes/vulnpulse/bronze/raw_files/{nvd,kev,epss}/`
- Create three Bronze tables: `vulnpulse.bronze.{nvd_raw, kev_raw, epss_raw}`
- Each table must have columns: `cve_id`, `raw_json` (or raw columns for EPSS), `ingest_ts`, `source_file`, `snapshot_date`
- Append mode (don't overwrite existing data)
- Print count for each table after ingestion

**Verification**: Notebook runs without errors; all three tables exist with data; can query `SELECT * FROM vulnpulse.bronze.nvd_raw LIMIT 5`.

---

## Milestone 3: Silver Layer with DLT

### Task 3.1: Create Silver DLT Pipeline - CVE Core

**Create `databricks/silver/pipeline.py`** (DLT notebook)

**Requirements**:
- Create `@dlt.table` named `cve_core`
- Source: `vulnpulse.bronze.nvd_raw`
- Parse raw_json to extract: `cve_id`, `published`, `last_modified`, `description`, `cvss_v3_score`, `cvss_v3_severity`, `cvss_v3_vector`, `cvss_v2_score`, `cwe_id`
- Deduplicate: keep latest record per cve_id based on ingest_ts
- Add expectations:
  - `valid_cve_id`: cve_id IS NOT NULL
  - `valid_cve_format`: cve_id matches pattern `^CVE-[0-9]{4}-[0-9]+$`
  - `has_description`: description IS NOT NULL (use `expect_or_drop`)

**Verification**: DLT pipeline validates; table schema is correct.

---

### Task 3.2: Add Silver DLT Pipeline - CVE Signals

**Add to `databricks/silver/pipeline.py`**

**Requirements**:
- Create `@dlt.table` named `cve_signals`
- Join EPSS scores from `vulnpulse.bronze.epss_raw` (latest per cve_id)
- Join KEV status from `vulnpulse.bronze.kev_raw` (parse JSON to get dateAdded, dueDate, ransomware use, notes)
- Output columns: `cve_id`, `epss_score`, `epss_percentile`, `kev_flag` (boolean), `kev_date_added`, `kev_due_date`, `kev_ransomware_use`, `kev_notes`
- Default `kev_flag` to False when not in KEV
- Add expectation: `valid_epss_range` - epss_score BETWEEN 0 AND 1 (allow null)

**Verification**: Table has correct columns; kev_flag is True for KEV entries, False otherwise.

---

### Task 3.3: Add Silver DLT Pipeline - CVE Affected Products

**Add to `databricks/silver/pipeline.py`**

**Requirements**:
- Create `@dlt.table` named `cve_affected_products`
- Extract CPE data from NVD configurations.nodes.cpe_match
- Parse CPE URI (format: `cpe:2.3:part:vendor:product:version:...`) to extract vendor, product, version
- Only include vulnerable=true CPEs
- Output columns: `cve_id`, `cpe_uri`, `vendor`, `product`, `version`
- Deduplicate on cve_id + cpe_uri

**Verification**: Table contains vendor/product data; can query distinct vendors.

---

### Task 3.4: Add Silver DLT Pipeline - CVE Documents

**Add to `databricks/silver/pipeline.py`**

**Requirements**:
- Create `@dlt.table` named `cve_documents`
- Enable Change Data Feed (required for Vector Search): `table_properties={"delta.enableChangeDataFeed": "true"}`
- Join cve_core + cve_signals + aggregated products
- Create `document_text` column combining: description + vendors + products + CWE (pipe-separated)
- Include metadata columns for filtering: `published`, `cvss_v3_score`, `cvss_v3_severity`, `epss_score`, `kev_flag`, `vendors_str`, `products_str`, `cwe_id`
- Add expectation: `has_document_text` - LENGTH(document_text) > 50 (use `expect_or_drop`)

**Verification**: Table has CDF enabled; document_text is populated; metadata columns present.

---

### Task 3.5: Document Data Quality Expectations

**Create `docs/dq-expectations.md`**

**Requirements**:
- Table showing all expectations across Silver tables
- Columns: Table, Expectation Name, Rule, Type (expect/expect_or_drop/expect_or_fail), Rationale
- Section explaining how to view expectation metrics in DLT UI
- Section on what to do when expectations fail

**Verification**: Document is complete and accurate.

---

## Milestone 4: Gold Layer and Vector Search

### Task 4.1: Create Gold Enriched Vulnerability Table

**Create `databricks/gold/build.py`** (notebook)

**Requirements**:
- Create `vulnpulse.gold.vuln_enriched` by joining Silver tables
- Add `primary_vendor` and `primary_product` (most common per CVE from affected_products)
- Calculate `risk_score` (0-100) using this formula:
  ```
  - KEV=true: 90 + (epss_score * 10)  → range 90-100
  - EPSS > 0.5: 70 + (epss_score * 20) → range 70-90
  - EPSS > 0.1: 40 + (epss_score * 50) → range 45-90
  - Otherwise: cvss_v3_score * 4 → range 0-40
  ```
- Add `risk_tier`: CRITICAL (≥90), HIGH (≥70), MEDIUM (≥40), LOW (<40)
- Include all relevant columns from Silver tables

**Verification**: Table has risk_score and risk_tier; KEV entries have highest scores.

---

### Task 4.2: Create Gold Aggregation Tables

**Add to `databricks/gold/build.py`**

**Requirements**:
- Create `vulnpulse.gold.vendor_risk_agg`:
  - Group by vendor (from all affected_products, not just primary)
  - Columns: vendor, total_cves, kev_count, critical_count, high_count, avg_risk_score, max_risk_score
  - Order by kev_count DESC, avg_risk_score DESC

- Create `vulnpulse.gold.kev_recent`:
  - Filter vuln_enriched to kev_flag=true AND kev_date_added within last 30 days
  - Add days_since_added column
  - Order by kev_date_added DESC

**Verification**: Both tables created; vendor_risk_agg shows vendors ranked by risk; kev_recent shows recent additions.

---

### Task 4.3: Create Vector Search Index Setup

**Create `databricks/vector_search/create_index.py`** (notebook)

**Requirements**:
- Create Vector Search endpoint named `vulnpulse_vs_endpoint` (type: STANDARD)
- Ensure cve_documents table has Change Data Feed enabled
- Create Delta Sync Index:
  - Name: `vulnpulse.silver.cve_documents_index`
  - Source: `vulnpulse.silver.cve_documents`
  - Pipeline type: TRIGGERED (not continuous)
  - Primary key: `cve_id`
  - Embedding source column: `document_text`
  - Embedding model: `databricks-gte-large-en`
- Trigger initial sync
- Include test query to verify index works

**Verification**: Endpoint and index created; test query returns results.

---

### Task 4.4: Create Vector Search Query Utilities

**Create `databricks/vector_search/query.py`** (notebook)

**Requirements**:
- Function `semantic_search(query, num_results=10, kev_only=False, min_cvss=None)`:
  - Connects to the index
  - Applies filters if provided
  - Returns list of dicts with CVE data
- Include example queries demonstrating different search types

**Verification**: Function works; filters apply correctly; returns structured results.

---

## Milestone 5: Agentic RAG System

### Task 5.1: Create CVE Lookup Tool

**Create `agent/tools/cve_lookup.py`**

**Requirements**:
- Function `lookup_cve(cve_id, spark)`: Queries vuln_enriched + affected_products, returns dict or None
- Function `format_cve_summary(cve_data)`: Returns markdown with:
  - CVE ID and risk tier/score
  - Signals table (CVSS, EPSS, KEV status)
  - Description (truncated if long)
  - Affected vendor/product
  - Metadata (published date, CWE)

**Verification**: Looking up a known CVE returns formatted summary; unknown CVE returns appropriate message.

---

### Task 5.2: Create SQL Query Tool

**Create `agent/tools/sql_query.py`**

**Requirements**:
- Dataclass `QueryFilters` with fields: vendors, products, risk_tiers, kev_only, min_cvss, min_epss, date_from, date_to, limit
- Function `build_sql_query(filters)`: Generates SQL WHERE clause from filters
- Function `execute_filtered_search(filters, spark)`: Runs query, returns list of dicts
- Function `format_search_results(results, query_desc)`: Returns markdown table

**Verification**: Building query with various filters produces valid SQL; results format as table.

---

### Task 5.3: Create Vector Search Tool

**Create `agent/tools/vector_search.py`**

**Requirements**:
- Function `semantic_search(query, num_results, kev_only, min_cvss)`: Wraps Vector Search client
- Function `format_semantic_results(results, query)`: Returns markdown with numbered results, CVE details, KEV badges
- Handle case where Vector Search client isn't available (graceful error)

**Verification**: Semantic queries return relevant results; formatting includes severity and KEV indicators.

---

### Task 5.4: Create Comparison Tool

**Create `agent/tools/comparison.py`**

**Requirements**:
- Function `compare_cves(cve_ids, spark)`: Looks up multiple CVEs, sorts by risk_score, builds rationale
- Rationale should explain WHY each CVE ranks where it does (KEV status, EPSS, CVSS, ransomware use)
- Function `format_comparison(comparison)`: Returns markdown table + priority recommendation

**Verification**: Comparing 2-3 CVEs returns ranked list with clear reasoning.

---

### Task 5.5: Create Intent Router

**Create `agent/router.py`**

**Requirements**:
- Enum `QueryIntent`: CVE_LOOKUP, FILTERED_SEARCH, SEMANTIC_SEARCH, COMPARISON, TREND_ANALYSIS, UNKNOWN
- Dataclass `ParsedQuery` with: intent, cve_ids, filters, search_text, raw_query
- Function `classify_intent(query)`: Uses rules to classify:
  - Single CVE ID → CVE_LOOKUP
  - Multiple CVE IDs or comparison words → COMPARISON
  - Trend/recent/new keywords → TREND_ANALYSIS
  - Filter keywords (critical, high, kev, exploited) or vendor names → FILTERED_SEARCH
  - Otherwise → SEMANTIC_SEARCH
- Extract CVE IDs using regex pattern `CVE-\d{4}-\d+`
- Extract filters (risk tiers, kev_only, date ranges, vendors)

**Verification**: Test queries route correctly:
- "What is CVE-2024-3094?" → CVE_LOOKUP
- "Compare CVE-X and CVE-Y" → COMPARISON
- "Critical vulns in Apache" → FILTERED_SEARCH
- "authentication bypass" → SEMANTIC_SEARCH
- "What's exploited this month?" → TREND_ANALYSIS

---

### Task 5.6: Create Response Synthesizer

**Create `agent/synthesizer.py`**

**Requirements**:
- Function `synthesize_response(intent, tool_outputs, original_query)`:
  - Combines outputs from different tools
  - Separates sections with `---`
  - Handles errors gracefully
- Function `format_no_results(query)`: Helpful message with suggestions when nothing found

**Verification**: Multiple tool outputs combine cleanly; errors display nicely; no results gives useful guidance.

---

### Task 5.7: Create Main Orchestrator

**Create `agent/orchestrator.py`**

**Requirements**:
- Class `VulnPulseAgent` with:
  - `__init__(self, spark)`: Store spark session
  - `query(self, user_query)`: Main entry point
    1. Classify intent using router
    2. Execute appropriate tool(s)
    3. Synthesize response
  - `_execute_tools(self, parsed)`: Route to correct tool based on intent
  - `_analyze_trends(self, filters)`: SQL queries for recent KEVs and vendor breakdown

- Factory function `create_agent(spark)`: Returns agent instance

**Verification**: Agent handles all query types end-to-end; returns formatted markdown.

---

### Task 5.8: Create Agent Test Notebook

**Create `databricks/test_agent.py`** (notebook)

**Requirements**:
- Import and instantiate agent
- Test queries for each intent type:
  1. Direct lookup: "What is CVE-2024-3094?"
  2. Filtered search: "Critical vulnerabilities in Apache"
  3. Semantic search: "authentication bypass in web applications"
  4. Comparison: "Compare CVE-2024-21762 and CVE-2024-1709"
  5. Trends: "What vulnerabilities have been exploited this month?"
  6. KEV + vendor: "KEV vulnerabilities affecting Microsoft"
- Each test in separate cell with markdown header

**Verification**: All test queries return appropriate responses without errors.

---

## Milestone 6: Application and Deployment

### Task 6.1: Create Streamlit App

**Create `app/app.py`**

**Requirements**:
- Three tabs: "💬 Assistant", "📋 Priority List", "📈 Dashboard"
- **Assistant tab**:
  - Text input for queries
  - Example queries in expander
  - Display agent responses as markdown
- **Priority List tab**:
  - Filterable table from vuln_enriched
  - Sidebar filters: KEV only, min CVSS, vendor
  - Download CSV button
- **Dashboard tab**:
  - Risk tier distribution chart
  - Top vulnerable vendors table
  - Recent KEV additions list
- **Sidebar**:
  - Data stats (total CVEs, KEV count)
  - Settings/filters

**Create `app/app.yaml`**:
- Streamlit run command for Databricks Apps

**Verification**: App runs locally with `streamlit run app/app.py`; all three tabs functional.

---

### Task 6.2: Create Asset Bundle Configuration

**Create `databricks.yml`**

**Requirements**:
- Bundle name: vulnpulse
- Job `vulnpulse_daily_refresh` with tasks:
  1. bronze_ingest (notebook)
  2. silver_pipeline (depends on 1, pipeline task)
  3. gold_build (depends on 2, notebook)
  4. vector_sync (depends on 3, notebook to trigger index sync)
- Pipeline `silver_pipeline` pointing to silver/pipeline.py
- Targets: dev (development mode), prod (production mode)

**Verification**: `databricks bundle validate` passes.

---

### Task 6.3: Create Demo Script and Final Docs

**Create `docs/demo-script.md`**:
- 10-minute walkthrough with timing for each section
- Key talking points for: Catalog, Pipeline+DQ, Delta time travel, Job DAG, Vector Search, App
- Backup Q&A points

**Update all documentation**:
- README.md: Verify quick start works
- docs/architecture.md: Add component descriptions
- docs/agent-design.md: Explain tool routing logic

**Verification**: Demo script is realistic; all docs are current and accurate.

---

## Quick Reference

| Milestone | Tasks | Focus |
|-----------|-------|-------|
| 0 | 0.1-0.4 | Project structure, requirements, README |
| 1 | 1.1-1.4 | Data collection scripts |
| 2 | 2.1-2.2 | Catalog setup, Bronze ingestion |
| 3 | 3.1-3.5 | Silver DLT pipeline with expectations |
| 4 | 4.1-4.4 | Gold tables, Vector Search |
| 5 | 5.1-5.8 | Agent tools and orchestration |
| 6 | 6.1-6.3 | Streamlit app, deployment, docs |