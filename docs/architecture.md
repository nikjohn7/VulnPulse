# VulnPulse Architecture

## Overview

VulnPulse implements a medallion architecture (Bronze → Silver → Gold) on Databricks, with Vector Search and an agentic RAG layer for natural language queries.

## Architecture Diagram

```mermaid
flowchart TB
    subgraph Sources["Data Sources"]
        NVD[NVD API]
        KEV[CISA KEV]
        EPSS[EPSS Scores]
    end
    
    subgraph Local["Local Collection"]
        Fetch[fetch_all.py]
        Raw[data/raw/]
    end
    
    subgraph Databricks["Databricks Lakehouse"]
        subgraph Bronze["Bronze Layer"]
            Vol[(Volume: raw_files)]
            BT[nvd_raw | kev_raw | epss_raw]
        end
        
        subgraph Silver["Silver Layer (DLT)"]
            Core[cve_core]
            Signals[cve_signals]
            Products[cve_affected_products]
            Docs[cve_documents]
        end
        
        subgraph Gold["Gold Layer"]
            Enriched[vuln_enriched]
            VendorAgg[vendor_risk_agg]
            Recent[kev_recent]
        end
        
        VS[(Vector Search Index)]
    end
    
    subgraph Agent["Agent System"]
        Router[Intent Router]
        Tools[Tool Executor]
        Synth[Response Synthesizer]
    end
    
    App[Streamlit App]
    
    Sources --> Fetch --> Raw --> Vol --> BT
    BT --> Core & Signals & Products
    Core & Signals & Products --> Docs --> VS
    Core & Signals & Products --> Enriched --> VendorAgg & Recent
    VS --> Tools
    Enriched --> Tools
    Router --> Tools --> Synth --> App
```

## Data Flow

```
External Sources (NVD, KEV, EPSS)
    ↓ (local download + upload to Volume)
Bronze Layer (raw data, append-only)
    ↓ (DLT pipeline with Expectations)
Silver Layer (normalized, validated, deduplicated)
    ↓ (aggregation + enrichment)
Gold Layer (analytics-ready tables)
    ↓ (Delta Sync Index)
Vector Search (semantic embeddings)
    ↓ (tool routing)
Agent (intent classification + tool execution)
    ↓
Streamlit App (conversational UI)
```

## Components

### Bronze Layer
- **Purpose**: Immutable raw data storage
- **Tables**: `nvd_raw`, `kev_raw`, `epss_raw`
- **Schema**: Minimal structure with `raw_json`, `ingest_ts`, `source_file`
- **Pattern**: Append-only, never delete

### Silver Layer
- **Purpose**: Cleaned, validated, business-ready data
- **Tables**: 
  - `cve_core`: Core CVE metadata (ID, description, CVSS, CWE)
  - `cve_signals`: Risk signals (EPSS scores, KEV status)
  - `cve_affected_products`: CPE data parsed to vendor/product
  - `cve_documents`: Denormalized text for Vector Search (CDF enabled)
- **Quality**: DLT Expectations enforce data contracts
- **Pattern**: Deduplication, latest record wins

### Gold Layer
- **Purpose**: Aggregated, enriched analytics tables
- **Tables**:
  - `vuln_enriched`: Joined view with calculated risk scores
  - `vendor_risk_agg`: Vendor-level risk metrics
  - `kev_recent`: Recent KEV additions
- **Pattern**: Optimized for query performance

#### Risk Score Calculation (0-100)
```
KEV = true           → 90 + (epss_score × 10)     [90-100]
EPSS > 0.5           → 70 + (epss_score × 20)     [70-90]
EPSS > 0.1           → 40 + (epss_score × 50)     [45-65]
Otherwise            → cvss_v3_score × 4          [0-40]
```
**Risk Tiers**: CRITICAL (≥90), HIGH (70-89), MEDIUM (40-69), LOW (<40)

### Vector Search
- **Index**: `cve_documents_index` (Delta Sync, triggered)
- **Model**: `databricks-gte-large-en`
- **Source**: `cve_documents` table with Change Data Feed
- **Use case**: Semantic search for vulnerability descriptions

### Agent System
- **Router**: Classifies user intent (lookup, search, comparison, trends)
- **Tools**: 
  - `cve_lookup`: Direct CVE ID queries
  - `sql_query`: Filtered searches with WHERE clauses
  - `vector_search`: Semantic similarity search
  - `comparison`: Multi-CVE risk ranking
- **Synthesizer**: Combines tool outputs into markdown responses

## Technology Choices

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Storage | Delta Lake | ACID transactions, time travel, CDF |
| Catalog | Unity Catalog | Governance, lineage, fine-grained access |
| Pipeline | DLT | Declarative, auto-scaling, built-in quality |
| Search | Vector Search | Managed embeddings, Delta Sync integration |
| Deployment | Asset Bundles | GitOps-friendly, environment promotion |
| UI | Streamlit | Rapid prototyping, native Databricks Apps |

## Data Quality Strategy

- **Bronze**: Schema-on-read, validate file integrity only
- **Silver**: Expectations enforce NOT NULL, format patterns, value ranges
- **Gold**: Business logic validation (risk score bounds, tier consistency)

### Key DLT Expectations

| Table | Expectation | Rule | Action |
|-------|-------------|------|--------|
| cve_core | valid_cve_id | `cve_id IS NOT NULL` | expect |
| cve_core | valid_cve_format | `cve_id RLIKE '^CVE-[0-9]{4}-[0-9]+$'` | expect |
| cve_core | has_description | `description IS NOT NULL` | drop |
| cve_signals | valid_epss_range | `epss_score BETWEEN 0 AND 1` | expect |
| cve_documents | has_document_text | `LENGTH(document_text) > 50` | drop |

## Deployment Architecture

```
databricks.yml (Asset Bundle)
├── Job: vulnpulse_daily_refresh
│   ├── Task 1: bronze_ingest (notebook)
│   ├── Task 2: silver_pipeline (DLT, depends on 1)
│   ├── Task 3: gold_build (notebook, depends on 2)
│   └── Task 4: vector_sync (notebook, depends on 3)
└── Targets: dev (development) | prod (production)
```

## Scalability Considerations

- **Current**: Single-node serverless (Free Edition)
- **Future**: 
  - Partition Silver tables by year/month
  - Incremental DLT processing with watermarks
  - Continuous Vector Search sync
  - Multi-cluster job execution
