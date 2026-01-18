# Data Quality Expectations

This document describes the data quality expectations implemented in the VulnPulse Silver layer DLT pipeline. Expectations validate data at ingestion time and provide visibility into data quality metrics.

## Expectations Overview

| Table | Expectation Name | Rule | Type | Rationale |
|-------|------------------|------|------|-----------|
| `cve_core` | `valid_cve_id` | `cve_id IS NOT NULL` | expect | Every CVE record must have an identifier to be useful for lookups and joins |
| `cve_core` | `valid_cve_format` | `cve_id RLIKE '^CVE-[0-9]{4}-[0-9]+$'` | expect | CVE IDs must follow the standard MITRE format (CVE-YYYY-NNNNN) for consistency |
| `cve_core` | `has_description` | `description IS NOT NULL` | expect_or_drop | Records without descriptions provide no value for analysis or Vector Search |
| `cve_signals` | `valid_epss_range` | `epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)` | expect | EPSS scores are probabilities and must be in [0,1] range; null is valid (no score available) |
| `cve_affected_products` | `valid_cve_id` | `cve_id IS NOT NULL` | expect | Product records must link to a CVE to be meaningful |
| `cve_affected_products` | `valid_cpe_uri` | `cpe_uri IS NOT NULL` | expect | CPE URI is the source of vendor/product data; without it, extraction fails |
| `cve_affected_products` | `has_vendor` | `vendor IS NOT NULL` | expect_or_drop | Records without vendor information are not useful for product-based queries |
| `cve_documents` | `valid_cve_id` | `cve_id IS NOT NULL` | expect | Document must have CVE ID as primary key for Vector Search index |
| `cve_documents` | `has_document_text` | `LENGTH(document_text) > 50` | expect_or_drop | Short documents produce poor embeddings; minimum length ensures meaningful search results |

## Expectation Types

DLT provides three types of expectations:

### `@dlt.expect` (Warn)
- **Behavior**: Records that violate the rule are written to the table; violations are logged in metrics
- **Use case**: Data quality issues you want to track but don't want to block data flow
- **Example**: `valid_cve_format` - malformed CVE IDs are rare and worth investigating, but shouldn't block ingestion

### `@dlt.expect_or_drop` (Drop)
- **Behavior**: Records that violate the rule are silently dropped; metrics track dropped records
- **Use case**: Records that provide no value if the rule is violated
- **Example**: `has_description` - CVEs without descriptions can't be searched or analyzed

### `@dlt.expect_or_fail` (Fail)
- **Behavior**: Pipeline fails immediately if any record violates the rule
- **Use case**: Critical invariants where any violation indicates a serious upstream problem
- **Example**: Not used in this pipeline; reserved for cases like schema mismatches

## Viewing Expectation Metrics in DLT UI

### Accessing the Pipeline UI

1. Navigate to **Workflows** > **Delta Live Tables** in the Databricks sidebar
2. Click on the `vulnpulse_silver_pipeline` pipeline
3. Select a completed pipeline run to view results

### Understanding the Pipeline Graph

The graph view shows each table as a node with color-coded quality indicators:

- **Green**: All expectations passed for all records
- **Yellow**: Some records failed `expect` rules (warn) but were still written
- **Red**: Pipeline failed due to `expect_or_fail` violation

### Viewing Detailed Metrics

1. Click on a table node in the graph
2. Select the **Data Quality** tab
3. View metrics for each expectation:
   - **Total records processed**
   - **Records passed**: Count and percentage
   - **Records failed**: Count and percentage
   - **Records dropped** (for `expect_or_drop`): Count

### Example Metrics Display

```
┌─────────────────────────────────────────────────────────────────────┐
│ cve_core                                                            │
├─────────────────────────────────────────────────────────────────────┤
│ Expectation          │ Passed    │ Failed    │ Pass Rate            │
├──────────────────────┼───────────┼───────────┼──────────────────────┤
│ valid_cve_id         │ 245,123   │ 0         │ 100.00%              │
│ valid_cve_format     │ 245,100   │ 23        │ 99.99%               │
│ has_description      │ 244,890   │ 233       │ 99.91% (233 dropped) │
└─────────────────────────────────────────────────────────────────────┘
```

### Accessing Historical Metrics

To view metrics over time:

1. Open the pipeline in DLT UI
2. Click **Settings** > **Event Log**
3. Filter by `expectation` events
4. Export to a notebook for trend analysis

Alternatively, query the event log directly:

```sql
SELECT
    timestamp,
    details:expectation:name AS expectation_name,
    details:expectation:dataset AS table_name,
    details:expectation:passed_records AS passed,
    details:expectation:failed_records AS failed
FROM event_log(TABLE(vulnpulse.silver.cve_core))
WHERE event_type = 'flow_progress'
ORDER BY timestamp DESC
```

## Handling Expectation Failures

### Investigating Warn Failures (`expect`)

When `expect` rules report failures:

1. **Query the affected table** to find violating records:
   ```sql
   -- Find CVEs with malformed IDs
   SELECT cve_id, description
   FROM vulnpulse.silver.cve_core
   WHERE NOT cve_id RLIKE '^CVE-[0-9]{4}-[0-9]+$'
   ```

2. **Trace back to source** in Bronze layer:
   ```sql
   -- Find source records for bad CVE IDs
   SELECT source_file, snapshot_date, raw_json
   FROM vulnpulse.bronze.nvd_raw
   WHERE cve_id NOT RLIKE '^CVE-[0-9]{4}-[0-9]+$'
   ```

3. **Assess impact**:
   - Low failure rate (<0.1%): Typically acceptable noise
   - Medium failure rate (0.1-1%): Investigate pattern in source data
   - High failure rate (>1%): Check for upstream data format changes

4. **Take action**:
   - Document known edge cases (e.g., reserved CVE IDs)
   - Update transformation logic to handle new patterns
   - Contact data source maintainers for persistent issues

### Investigating Drop Failures (`expect_or_drop`)

When `expect_or_drop` rules drop records:

1. **Check drop rates in metrics** - increasing rates may indicate upstream problems:
   ```sql
   -- Monitor dropped records over time
   SELECT
       snapshot_date,
       COUNT(*) AS total_records,
       SUM(CASE WHEN description IS NULL THEN 1 ELSE 0 END) AS would_drop
   FROM vulnpulse.bronze.nvd_raw
   GROUP BY snapshot_date
   ORDER BY snapshot_date DESC
   ```

2. **Understand why records are dropped**:
   - `has_description`: NVD may have reserved/rejected CVEs without descriptions
   - `has_vendor`: CPE entries may have wildcards instead of specific vendors
   - `has_document_text`: Short descriptions produce documents under 50 chars

3. **Decide if rules need adjustment**:
   - If legitimate records are being dropped, loosen the rule
   - If noise is being correctly filtered, no action needed

### Responding to Pipeline Failures (`expect_or_fail`)

If `expect_or_fail` rules are added in the future and trigger:

1. **Pipeline will stop** - no data is written
2. **Check event log** for the specific failing record
3. **Fix upstream data or transformation logic** before re-running
4. **Consider downgrading to `expect_or_drop`** if some failures are acceptable

### Escalation Path

| Failure Pattern | Severity | Action |
|-----------------|----------|--------|
| Isolated failures (<10 records) | Low | Document and monitor |
| Pattern in specific source file | Medium | Check data source for corruption |
| Increasing trend over multiple runs | High | Investigate schema/format changes |
| >5% drop rate | Critical | Pause pipeline, investigate root cause |

## Best Practices

### When Adding New Expectations

1. **Start with `expect`** to understand failure patterns before dropping or failing
2. **Use descriptive names** that explain what's being validated
3. **Document the rationale** for each rule
4. **Set appropriate thresholds** based on data characteristics

### Monitoring Recommendations

1. **Set up alerts** for drop rates exceeding thresholds
2. **Review metrics weekly** during initial deployment
3. **Create a dashboard** tracking expectation pass rates over time
4. **Archive event logs** for compliance and audit purposes

### Tuning Expectations

If expectations are too strict:
- Lower thresholds (e.g., document length from 50 to 30)
- Change `expect_or_drop` to `expect` to keep records visible
- Add `COALESCE` or default values in transformations

If expectations are too loose:
- Add additional rules for edge cases
- Tighten thresholds based on observed data quality
- Upgrade `expect` to `expect_or_drop` if failures are truly invalid

## Expectation SQL Reference

All expectations in this pipeline can be manually tested against Bronze tables:

```sql
-- Test valid_cve_id
SELECT COUNT(*) AS failures
FROM vulnpulse.bronze.nvd_raw
WHERE cve_id IS NULL;

-- Test valid_cve_format
SELECT COUNT(*) AS failures
FROM vulnpulse.bronze.nvd_raw
WHERE NOT cve_id RLIKE '^CVE-[0-9]{4}-[0-9]+$';

-- Test valid_epss_range
SELECT COUNT(*) AS failures
FROM vulnpulse.bronze.epss_raw
WHERE epss_score IS NOT NULL
  AND (epss_score < 0 OR epss_score > 1);

-- Test document text length (simulated)
SELECT COUNT(*) AS would_fail
FROM vulnpulse.silver.cve_core c
LEFT JOIN vulnpulse.silver.cve_signals s ON c.cve_id = s.cve_id
WHERE LENGTH(c.description) <= 50;
```
