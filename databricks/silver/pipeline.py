# Databricks notebook source
# MAGIC %md
# MAGIC # VulnPulse Silver Layer - DLT Pipeline
# MAGIC 
# MAGIC This Delta Live Tables (DLT) pipeline transforms raw vulnerability data from the Bronze layer
# MAGIC into cleaned, validated, and deduplicated Silver tables.
# MAGIC 
# MAGIC ## Tables Created
# MAGIC | Table | Description | Source |
# MAGIC |-------|-------------|--------|
# MAGIC | `cve_core` | Core CVE metadata (ID, description, CVSS, CWE) | `nvd_raw` |
# MAGIC 
# MAGIC ## Data Quality Expectations
# MAGIC - `valid_cve_id`: CVE ID must not be null
# MAGIC - `valid_cve_format`: CVE ID must match pattern `CVE-YYYY-NNNNN`
# MAGIC - `has_description`: Description must not be null (records dropped if violated)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Imports and Configuration

# COMMAND ----------

import dlt
from pyspark.sql import functions as F
from pyspark.sql.window import Window
from pyspark.sql.types import (
    StructType, StructField, StringType, ArrayType, 
    DoubleType, TimestampType, BooleanType
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration

# COMMAND ----------

# Catalog and schema configuration
CATALOG = "vulnpulse"
BRONZE_SCHEMA = "bronze"
SILVER_SCHEMA = "silver"

# Source tables
NVD_RAW_TABLE = f"{CATALOG}.{BRONZE_SCHEMA}.nvd_raw"

# COMMAND ----------

# MAGIC %md
# MAGIC ## Schema Definitions for NVD API 2.0 JSON Parsing
# MAGIC 
# MAGIC The NVD API 2.0 has a different structure than the legacy 1.1 format.
# MAGIC Key paths:
# MAGIC - CVE ID: `cve.id`
# MAGIC - Published: `cve.published`
# MAGIC - Last Modified: `cve.lastModified`
# MAGIC - Description: `cve.descriptions[].value` (where lang='en')
# MAGIC - CVSS v3.1: `cve.metrics.cvssMetricV31[0].cvssData.*`
# MAGIC - CVSS v3.0: `cve.metrics.cvssMetricV30[0].cvssData.*`
# MAGIC - CVSS v2: `cve.metrics.cvssMetricV2[0].cvssData.baseScore`
# MAGIC - CWE: `cve.weaknesses[].description[].value`

# COMMAND ----------

# Define schema for parsing the nested NVD JSON structure
# This schema covers the fields we need to extract

nvd_cve_schema = StructType([
    StructField("cve", StructType([
        StructField("id", StringType(), True),
        StructField("published", StringType(), True),
        StructField("lastModified", StringType(), True),
        StructField("descriptions", ArrayType(StructType([
            StructField("lang", StringType(), True),
            StructField("value", StringType(), True)
        ])), True),
        StructField("metrics", StructType([
            StructField("cvssMetricV31", ArrayType(StructType([
                StructField("cvssData", StructType([
                    StructField("baseScore", DoubleType(), True),
                    StructField("baseSeverity", StringType(), True),
                    StructField("vectorString", StringType(), True)
                ]), True)
            ])), True),
            StructField("cvssMetricV30", ArrayType(StructType([
                StructField("cvssData", StructType([
                    StructField("baseScore", DoubleType(), True),
                    StructField("baseSeverity", StringType(), True),
                    StructField("vectorString", StringType(), True)
                ]), True)
            ])), True),
            StructField("cvssMetricV2", ArrayType(StructType([
                StructField("cvssData", StructType([
                    StructField("baseScore", DoubleType(), True),
                    StructField("vectorString", StringType(), True)
                ]), True)
            ])), True)
        ]), True),
        StructField("weaknesses", ArrayType(StructType([
            StructField("description", ArrayType(StructType([
                StructField("lang", StringType(), True),
                StructField("value", StringType(), True)
            ])), True)
        ])), True)
    ]), True)
])

# COMMAND ----------

# MAGIC %md
# MAGIC ## CVE Core Table
# MAGIC 
# MAGIC Core CVE metadata extracted from NVD raw data.
# MAGIC 
# MAGIC **Deduplication Strategy**: Keep the latest record per CVE ID based on `ingest_ts`.

# COMMAND ----------

@dlt.table(
    name="cve_core",
    comment="Core CVE metadata extracted from NVD data. Deduplicated to keep latest record per CVE ID.",
    table_properties={
        "quality": "silver",
        "pipelines.autoOptimize.managed": "true"
    }
)
@dlt.expect("valid_cve_id", "cve_id IS NOT NULL")
@dlt.expect("valid_cve_format", "cve_id RLIKE '^CVE-[0-9]{4}-[0-9]+$'")
@dlt.expect_or_drop("has_description", "description IS NOT NULL")
def cve_core():
    """
    Creates the cve_core Silver table from NVD raw data.
    
    Extracts:
    - cve_id: CVE identifier
    - published: Publication timestamp
    - last_modified: Last modification timestamp
    - description: English description text
    - cvss_v3_score: CVSS v3.x base score
    - cvss_v3_severity: CVSS v3.x severity rating
    - cvss_v3_vector: CVSS v3.x vector string
    - cvss_v2_score: CVSS v2 base score
    - cwe_id: Primary CWE identifier
    
    Deduplication: Keeps latest record per cve_id based on ingest_ts.
    """
    
    # Read from Bronze NVD raw table
    raw_df = spark.table(NVD_RAW_TABLE)
    
    # Parse the raw_json column using the defined schema
    parsed_df = raw_df.withColumn(
        "parsed",
        F.from_json(F.col("raw_json"), nvd_cve_schema)
    )
    
    # Extract fields from the parsed JSON
    extracted_df = parsed_df.select(
        # CVE ID - prefer from parsed JSON, fallback to existing cve_id column
        F.coalesce(
            F.col("parsed.cve.id"),
            F.col("cve_id")
        ).alias("cve_id"),
        
        # Timestamps - convert ISO strings to timestamps
        F.to_timestamp(F.col("parsed.cve.published")).alias("published"),
        F.to_timestamp(F.col("parsed.cve.lastModified")).alias("last_modified"),
        
        # Description - extract English description
        # Filter descriptions array for lang='en' and get the first value
        F.expr("""
            FILTER(parsed.cve.descriptions, x -> x.lang = 'en')[0].value
        """).alias("description"),
        
        # CVSS v3 metrics - prefer v3.1, fallback to v3.0
        F.coalesce(
            F.col("parsed.cve.metrics.cvssMetricV31")[0]["cvssData"]["baseScore"],
            F.col("parsed.cve.metrics.cvssMetricV30")[0]["cvssData"]["baseScore"]
        ).alias("cvss_v3_score"),
        
        F.coalesce(
            F.col("parsed.cve.metrics.cvssMetricV31")[0]["cvssData"]["baseSeverity"],
            F.col("parsed.cve.metrics.cvssMetricV30")[0]["cvssData"]["baseSeverity"]
        ).alias("cvss_v3_severity"),
        
        F.coalesce(
            F.col("parsed.cve.metrics.cvssMetricV31")[0]["cvssData"]["vectorString"],
            F.col("parsed.cve.metrics.cvssMetricV30")[0]["cvssData"]["vectorString"]
        ).alias("cvss_v3_vector"),
        
        # CVSS v2 score
        F.col("parsed.cve.metrics.cvssMetricV2")[0]["cvssData"]["baseScore"].alias("cvss_v2_score"),
        
        # CWE ID - extract first CWE from weaknesses array
        # Filter for English descriptions and get the first CWE value
        F.expr("""
            FILTER(
                FLATTEN(
                    TRANSFORM(parsed.cve.weaknesses, w -> w.description)
                ),
                x -> x.lang = 'en'
            )[0].value
        """).alias("cwe_id"),
        
        # Keep metadata columns for deduplication
        F.col("ingest_ts"),
        F.col("source_file"),
        F.col("snapshot_date")
    )
    
    # Deduplicate: Keep latest record per cve_id based on ingest_ts
    # Using window function to rank records and filter to keep only the latest
    window_spec = Window.partitionBy("cve_id").orderBy(F.col("ingest_ts").desc())
    
    deduplicated_df = extracted_df.withColumn(
        "row_num",
        F.row_number().over(window_spec)
    ).filter(
        F.col("row_num") == 1
    ).drop("row_num")
    
    # Select final columns in the desired order
    final_df = deduplicated_df.select(
        "cve_id",
        "published",
        "last_modified",
        "description",
        "cvss_v3_score",
        "cvss_v3_severity",
        "cvss_v3_vector",
        "cvss_v2_score",
        "cwe_id"
    )
    
    return final_df

# COMMAND ----------

# MAGIC %md
# MAGIC ## Pipeline Summary
# MAGIC 
# MAGIC This DLT pipeline creates the following Silver tables:
# MAGIC 
# MAGIC | Table | Records | Quality Expectations |
# MAGIC |-------|---------|---------------------|
# MAGIC | `cve_core` | Deduplicated CVEs | valid_cve_id, valid_cve_format, has_description |
# MAGIC 
# MAGIC ### Data Quality Expectations
# MAGIC 
# MAGIC | Expectation | Rule | Type | Rationale |
# MAGIC |-------------|------|------|-----------|
# MAGIC | `valid_cve_id` | `cve_id IS NOT NULL` | expect | Every record must have a CVE ID |
# MAGIC | `valid_cve_format` | `cve_id RLIKE '^CVE-[0-9]{4}-[0-9]+$'` | expect | CVE IDs must follow standard format |
# MAGIC | `has_description` | `description IS NOT NULL` | expect_or_drop | Records without descriptions are not useful |
# MAGIC 
# MAGIC ### Next Steps
# MAGIC 
# MAGIC Future tasks will add additional Silver tables:
# MAGIC - `cve_signals`: EPSS scores and KEV status
# MAGIC - `cve_affected_products`: CPE data parsed to vendor/product
# MAGIC - `cve_documents`: Denormalized text for Vector Search
