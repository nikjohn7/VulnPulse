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
# MAGIC | `cve_signals` | Risk signals (EPSS scores, KEV status) | `epss_raw`, `kev_raw` |
# MAGIC | `cve_affected_products` | Affected vendors/products from CPE data | `nvd_raw` |
# MAGIC | `cve_documents` | Denormalized text for Vector Search (CDF enabled) | All Silver tables |
# MAGIC 
# MAGIC ## Data Quality Expectations
# MAGIC - `valid_cve_id`: CVE ID must not be null
# MAGIC - `valid_cve_format`: CVE ID must match pattern `CVE-YYYY-NNNNN`
# MAGIC - `has_description`: Description must not be null (records dropped if violated)
# MAGIC - `valid_epss_range`: EPSS score must be between 0 and 1 (or null)
# MAGIC - `valid_cpe_uri`: CPE URI must not be null
# MAGIC - `has_vendor`: Vendor must not be null (records dropped if violated)
# MAGIC - `has_document_text`: Document text must be >50 chars (records dropped if violated)

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
KEV_RAW_TABLE = f"{CATALOG}.{BRONZE_SCHEMA}.kev_raw"
EPSS_RAW_TABLE = f"{CATALOG}.{BRONZE_SCHEMA}.epss_raw"

# COMMAND ----------

# MAGIC %md
# MAGIC ## Schema Definitions for JSON Parsing
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
# MAGIC 
# MAGIC ### KEV JSON Structure
# MAGIC Key paths:
# MAGIC - CVE ID: `cveID`
# MAGIC - Date Added: `dateAdded`
# MAGIC - Due Date: `dueDate`
# MAGIC - Ransomware Use: `knownRansomwareCampaignUse`
# MAGIC - Notes: `notes`
# MAGIC - Vendor: `vendorProject`
# MAGIC - Product: `product`

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

# Define schema for parsing KEV JSON structure
kev_vuln_schema = StructType([
    StructField("cveID", StringType(), True),
    StructField("vendorProject", StringType(), True),
    StructField("product", StringType(), True),
    StructField("vulnerabilityName", StringType(), True),
    StructField("dateAdded", StringType(), True),
    StructField("dueDate", StringType(), True),
    StructField("knownRansomwareCampaignUse", StringType(), True),
    StructField("notes", StringType(), True),
    StructField("shortDescription", StringType(), True)
])

# Define schema for parsing NVD configurations/CPE data
# NVD API 2.0 format: cve.configurations[].nodes[].cpeMatch[]
# CPE 2.3 URI format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
nvd_cpe_schema = StructType([
    StructField("cve", StructType([
        StructField("id", StringType(), True),
        StructField("configurations", ArrayType(StructType([
            StructField("nodes", ArrayType(StructType([
                StructField("operator", StringType(), True),
                StructField("negate", BooleanType(), True),
                StructField("cpeMatch", ArrayType(StructType([
                    StructField("vulnerable", BooleanType(), True),
                    StructField("criteria", StringType(), True),
                    StructField("matchCriteriaId", StringType(), True),
                    StructField("versionStartIncluding", StringType(), True),
                    StructField("versionStartExcluding", StringType(), True),
                    StructField("versionEndIncluding", StringType(), True),
                    StructField("versionEndExcluding", StringType(), True)
                ])), True)
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
# MAGIC ## CVE Signals Table
# MAGIC 
# MAGIC Combines EPSS scores and KEV (Known Exploited Vulnerabilities) status for each CVE.
# MAGIC 
# MAGIC **Data Sources**:
# MAGIC - `epss_raw`: EPSS probability scores and percentiles
# MAGIC - `kev_raw`: CISA Known Exploited Vulnerabilities catalog
# MAGIC 
# MAGIC **Deduplication Strategy**: Keep the latest record per CVE ID based on `ingest_ts` for both sources.

# COMMAND ----------

@dlt.table(
    name="cve_signals",
    comment="CVE risk signals combining EPSS scores and KEV status. Deduplicated to keep latest record per CVE ID.",
    table_properties={
        "quality": "silver",
        "pipelines.autoOptimize.managed": "true"
    }
)
@dlt.expect("valid_epss_range", "epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)")
def cve_signals():
    """
    Creates the cve_signals Silver table by joining EPSS and KEV data.
    
    Extracts:
    - cve_id: CVE identifier
    - epss_score: EPSS probability score (0-1)
    - epss_percentile: EPSS percentile ranking
    - kev_flag: Boolean indicating if CVE is in CISA KEV catalog
    - kev_date_added: Date CVE was added to KEV
    - kev_due_date: Remediation due date from KEV
    - kev_ransomware_use: Known ransomware campaign use indicator
    - kev_notes: Additional notes from KEV
    
    Deduplication: Keeps latest record per cve_id based on ingest_ts for both sources.
    """
    
    # =========================================================================
    # Process EPSS Data - Get latest record per CVE
    # =========================================================================
    epss_raw_df = spark.table(EPSS_RAW_TABLE)
    
    # Deduplicate EPSS: Keep latest record per cve_id based on ingest_ts
    epss_window = Window.partitionBy("cve_id").orderBy(F.col("ingest_ts").desc())
    
    epss_df = epss_raw_df.withColumn(
        "row_num",
        F.row_number().over(epss_window)
    ).filter(
        F.col("row_num") == 1
    ).select(
        F.col("cve_id"),
        F.col("epss_score"),
        F.col("epss_percentile")
    )
    
    # =========================================================================
    # Process KEV Data - Parse JSON and get latest record per CVE
    # =========================================================================
    kev_raw_df = spark.table(KEV_RAW_TABLE)
    
    # Parse the raw_json column using the defined schema
    kev_parsed_df = kev_raw_df.withColumn(
        "parsed",
        F.from_json(F.col("raw_json"), kev_vuln_schema)
    )
    
    # Extract fields from parsed JSON
    kev_extracted_df = kev_parsed_df.select(
        F.coalesce(F.col("parsed.cveID"), F.col("cve_id")).alias("cve_id"),
        F.to_date(F.col("parsed.dateAdded"), "yyyy-MM-dd").alias("kev_date_added"),
        F.to_date(F.col("parsed.dueDate"), "yyyy-MM-dd").alias("kev_due_date"),
        F.col("parsed.knownRansomwareCampaignUse").alias("kev_ransomware_use"),
        F.col("parsed.notes").alias("kev_notes"),
        F.col("ingest_ts")
    )
    
    # Deduplicate KEV: Keep latest record per cve_id based on ingest_ts
    kev_window = Window.partitionBy("cve_id").orderBy(F.col("ingest_ts").desc())
    
    kev_df = kev_extracted_df.withColumn(
        "row_num",
        F.row_number().over(kev_window)
    ).filter(
        F.col("row_num") == 1
    ).select(
        F.col("cve_id"),
        F.col("kev_date_added"),
        F.col("kev_due_date"),
        F.col("kev_ransomware_use"),
        F.col("kev_notes"),
        F.lit(True).alias("kev_flag")  # Mark as in KEV
    )
    
    # =========================================================================
    # Join EPSS and KEV data
    # =========================================================================
    # Full outer join to capture all CVEs with either EPSS or KEV data
    joined_df = epss_df.join(
        kev_df,
        on="cve_id",
        how="full_outer"
    )
    
    # Set kev_flag to False for CVEs not in KEV catalog
    final_df = joined_df.select(
        F.col("cve_id"),
        F.col("epss_score"),
        F.col("epss_percentile"),
        F.coalesce(F.col("kev_flag"), F.lit(False)).alias("kev_flag"),
        F.col("kev_date_added"),
        F.col("kev_due_date"),
        F.col("kev_ransomware_use"),
        F.col("kev_notes")
    )
    
    return final_df

# COMMAND ----------

# MAGIC %md
# MAGIC ## CVE Affected Products Table
# MAGIC 
# MAGIC Extracts CPE (Common Platform Enumeration) data from NVD configurations to identify
# MAGIC affected vendors and products for each CVE.
# MAGIC 
# MAGIC **CPE 2.3 URI Format**: `cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other`
# MAGIC 
# MAGIC **Deduplication Strategy**: Keep unique combinations of `cve_id + cpe_uri`.

# COMMAND ----------

@dlt.table(
    name="cve_affected_products",
    comment="Affected vendors and products extracted from NVD CPE configurations. Only includes vulnerable=true CPEs.",
    table_properties={
        "quality": "silver",
        "pipelines.autoOptimize.managed": "true"
    }
)
@dlt.expect("valid_cve_id", "cve_id IS NOT NULL")
@dlt.expect("valid_cpe_uri", "cpe_uri IS NOT NULL")
@dlt.expect_or_drop("has_vendor", "vendor IS NOT NULL")
def cve_affected_products():
    """
    Creates the cve_affected_products Silver table from NVD raw data.
    
    Extracts CPE data from NVD configurations.nodes.cpeMatch and parses
    the CPE 2.3 URI to extract vendor, product, and version information.
    
    Extracts:
    - cve_id: CVE identifier
    - cpe_uri: Full CPE 2.3 URI string
    - vendor: Vendor name extracted from CPE URI
    - product: Product name extracted from CPE URI
    - version: Version string extracted from CPE URI
    
    Filters:
    - Only includes CPEs where vulnerable=true
    
    Deduplication: Keeps unique combinations of cve_id + cpe_uri.
    """
    
    # Read from Bronze NVD raw table
    raw_df = spark.table(NVD_RAW_TABLE)
    
    # Parse the raw_json column using the CPE schema
    parsed_df = raw_df.withColumn(
        "parsed",
        F.from_json(F.col("raw_json"), nvd_cpe_schema)
    )
    
    # Extract CVE ID and configurations
    cve_configs_df = parsed_df.select(
        F.coalesce(
            F.col("parsed.cve.id"),
            F.col("cve_id")
        ).alias("cve_id"),
        F.col("parsed.cve.configurations").alias("configurations"),
        F.col("ingest_ts")
    )
    
    # Explode configurations array to get individual configuration objects
    configs_exploded_df = cve_configs_df.select(
        F.col("cve_id"),
        F.explode_outer(F.col("configurations")).alias("config"),
        F.col("ingest_ts")
    )
    
    # Explode nodes array within each configuration
    nodes_exploded_df = configs_exploded_df.select(
        F.col("cve_id"),
        F.explode_outer(F.col("config.nodes")).alias("node"),
        F.col("ingest_ts")
    )
    
    # Explode cpeMatch array within each node
    cpe_exploded_df = nodes_exploded_df.select(
        F.col("cve_id"),
        F.explode_outer(F.col("node.cpeMatch")).alias("cpe_match"),
        F.col("ingest_ts")
    )
    
    # Filter for vulnerable=true CPEs only and extract CPE URI
    vulnerable_cpes_df = cpe_exploded_df.filter(
        F.col("cpe_match.vulnerable") == True
    ).select(
        F.col("cve_id"),
        F.col("cpe_match.criteria").alias("cpe_uri"),
        F.col("ingest_ts")
    )
    
    # Parse CPE 2.3 URI to extract vendor, product, version
    # CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    # Index:          0   1   2    3      4       5       6      7       8        9          10        11       12
    # We need: vendor (index 3), product (index 4), version (index 5)
    parsed_cpe_df = vulnerable_cpes_df.withColumn(
        "cpe_parts",
        F.split(F.col("cpe_uri"), ":")
    ).select(
        F.col("cve_id"),
        F.col("cpe_uri"),
        # Extract vendor (index 3) - handle cases where CPE might be malformed
        F.when(
            F.size(F.col("cpe_parts")) > 3,
            F.col("cpe_parts")[3]
        ).otherwise(F.lit(None)).alias("vendor"),
        # Extract product (index 4)
        F.when(
            F.size(F.col("cpe_parts")) > 4,
            F.col("cpe_parts")[4]
        ).otherwise(F.lit(None)).alias("product"),
        # Extract version (index 5)
        F.when(
            F.size(F.col("cpe_parts")) > 5,
            F.col("cpe_parts")[5]
        ).otherwise(F.lit(None)).alias("version"),
        F.col("ingest_ts")
    )
    
    # Clean up vendor/product/version values
    # Replace '*' (wildcard) and '-' (not applicable) with null for cleaner data
    cleaned_df = parsed_cpe_df.select(
        F.col("cve_id"),
        F.col("cpe_uri"),
        F.when(
            (F.col("vendor") == "*") | (F.col("vendor") == "-") | (F.col("vendor") == ""),
            F.lit(None)
        ).otherwise(F.col("vendor")).alias("vendor"),
        F.when(
            (F.col("product") == "*") | (F.col("product") == "-") | (F.col("product") == ""),
            F.lit(None)
        ).otherwise(F.col("product")).alias("product"),
        F.when(
            (F.col("version") == "*") | (F.col("version") == "-") | (F.col("version") == ""),
            F.lit(None)
        ).otherwise(F.col("version")).alias("version"),
        F.col("ingest_ts")
    )
    
    # Deduplicate: Keep unique combinations of cve_id + cpe_uri
    # Use window function to keep the latest record for each unique combination
    window_spec = Window.partitionBy("cve_id", "cpe_uri").orderBy(F.col("ingest_ts").desc())
    
    deduplicated_df = cleaned_df.withColumn(
        "row_num",
        F.row_number().over(window_spec)
    ).filter(
        F.col("row_num") == 1
    ).drop("row_num", "ingest_ts")
    
    # Select final columns in the desired order
    final_df = deduplicated_df.select(
        "cve_id",
        "cpe_uri",
        "vendor",
        "product",
        "version"
    )
    
    return final_df

# COMMAND ----------

# MAGIC %md
# MAGIC ## CVE Documents Table
# MAGIC
# MAGIC Denormalized CVE records optimized for Vector Search. Combines data from all Silver tables
# MAGIC into a single document with searchable text and metadata for filtering.
# MAGIC
# MAGIC **Key Features**:
# MAGIC - Change Data Feed enabled (required for Delta Sync Vector Search index)
# MAGIC - `document_text` column for embedding generation
# MAGIC - Metadata columns for filtered similarity search
# MAGIC
# MAGIC **Data Sources**:
# MAGIC - `cve_core`: Description, CVSS, CWE
# MAGIC - `cve_signals`: EPSS, KEV status
# MAGIC - `cve_affected_products`: Vendors and products (aggregated)

# COMMAND ----------

@dlt.table(
    name="cve_documents",
    comment="Denormalized CVE documents for Vector Search. Combines core metadata, risk signals, and affected products into searchable documents.",
    table_properties={
        "quality": "silver",
        "pipelines.autoOptimize.managed": "true",
        "delta.enableChangeDataFeed": "true"  # Required for Vector Search Delta Sync Index
    }
)
@dlt.expect("valid_cve_id", "cve_id IS NOT NULL")
@dlt.expect_or_drop("has_document_text", "LENGTH(document_text) > 50")
def cve_documents():
    """
    Creates the cve_documents Silver table for Vector Search.

    Combines data from:
    - cve_core: Core CVE metadata
    - cve_signals: EPSS and KEV risk signals
    - cve_affected_products: Vendor/product information (aggregated)

    Creates:
    - document_text: Searchable text combining description, vendors, products, CWE
    - Metadata columns for filtered similarity search

    Output columns:
    - cve_id: CVE identifier (primary key)
    - document_text: Combined text for embedding generation
    - published: Publication timestamp
    - cvss_v3_score: CVSS v3.x base score
    - cvss_v3_severity: CVSS v3.x severity rating
    - epss_score: EPSS probability score
    - kev_flag: Boolean indicating KEV status
    - vendors_str: Pipe-separated list of affected vendors
    - products_str: Pipe-separated list of affected products
    - cwe_id: Primary CWE identifier

    Change Data Feed is enabled to support Delta Sync Vector Search index.
    """

    # =========================================================================
    # Read Silver tables using dlt.read()
    # =========================================================================

    # Read cve_core table
    core_df = dlt.read("cve_core")

    # Read cve_signals table
    signals_df = dlt.read("cve_signals")

    # Read cve_affected_products table
    products_df = dlt.read("cve_affected_products")

    # =========================================================================
    # Aggregate affected products per CVE
    # =========================================================================
    # Create pipe-separated lists of vendors and products for each CVE

    products_agg_df = products_df.groupBy("cve_id").agg(
        # Collect distinct vendors and concatenate with pipe separator
        F.concat_ws(
            " | ",
            F.array_distinct(F.collect_list(F.col("vendor")))
        ).alias("vendors_str"),
        # Collect distinct products and concatenate with pipe separator
        F.concat_ws(
            " | ",
            F.array_distinct(F.collect_list(F.col("product")))
        ).alias("products_str")
    )

    # =========================================================================
    # Join all data sources
    # =========================================================================

    # Join cve_core with cve_signals
    joined_df = core_df.join(
        signals_df,
        on="cve_id",
        how="left"
    )

    # Join with aggregated products
    joined_df = joined_df.join(
        products_agg_df,
        on="cve_id",
        how="left"
    )

    # =========================================================================
    # Create document_text column
    # =========================================================================
    # Combine: description | vendors | products | CWE
    # Use COALESCE to handle nulls gracefully

    document_df = joined_df.withColumn(
        "document_text",
        F.concat_ws(
            " | ",
            F.col("description"),
            F.when(
                F.col("vendors_str").isNotNull() & (F.col("vendors_str") != ""),
                F.concat(F.lit("Affected vendors: "), F.col("vendors_str"))
            ),
            F.when(
                F.col("products_str").isNotNull() & (F.col("products_str") != ""),
                F.concat(F.lit("Affected products: "), F.col("products_str"))
            ),
            F.when(
                F.col("cwe_id").isNotNull() & (F.col("cwe_id") != ""),
                F.concat(F.lit("Weakness: "), F.col("cwe_id"))
            )
        )
    )

    # =========================================================================
    # Select final columns
    # =========================================================================

    final_df = document_df.select(
        "cve_id",
        "document_text",
        "published",
        "cvss_v3_score",
        "cvss_v3_severity",
        "epss_score",
        F.coalesce(F.col("kev_flag"), F.lit(False)).alias("kev_flag"),
        "vendors_str",
        "products_str",
        "cwe_id"
    )

    return final_df

# COMMAND ----------

# MAGIC %md
# MAGIC ## Pipeline Summary
# MAGIC
# MAGIC This DLT pipeline creates the following Silver tables:
# MAGIC
# MAGIC | Table | Description | Source | Quality Expectations |
# MAGIC |-------|-------------|--------|---------------------|
# MAGIC | `cve_core` | Core CVE metadata (ID, description, CVSS, CWE) | `nvd_raw` | valid_cve_id, valid_cve_format, has_description |
# MAGIC | `cve_signals` | Risk signals (EPSS scores, KEV status) | `epss_raw`, `kev_raw` | valid_epss_range |
# MAGIC | `cve_affected_products` | Affected vendors/products from CPE data | `nvd_raw` | valid_cve_id, valid_cpe_uri, has_vendor |
# MAGIC | `cve_documents` | Denormalized text for Vector Search | All Silver tables | valid_cve_id, has_document_text |
# MAGIC
# MAGIC ### Data Quality Expectations
# MAGIC
# MAGIC | Table | Expectation | Rule | Type | Rationale |
# MAGIC |-------|-------------|------|------|-----------|
# MAGIC | `cve_core` | `valid_cve_id` | `cve_id IS NOT NULL` | expect | Every record must have a CVE ID |
# MAGIC | `cve_core` | `valid_cve_format` | `cve_id RLIKE '^CVE-[0-9]{4}-[0-9]+$'` | expect | CVE IDs must follow standard format |
# MAGIC | `cve_core` | `has_description` | `description IS NOT NULL` | expect_or_drop | Records without descriptions are not useful |
# MAGIC | `cve_signals` | `valid_epss_range` | `epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)` | expect | EPSS scores must be valid probabilities |
# MAGIC | `cve_affected_products` | `valid_cve_id` | `cve_id IS NOT NULL` | expect | Every record must have a CVE ID |
# MAGIC | `cve_affected_products` | `valid_cpe_uri` | `cpe_uri IS NOT NULL` | expect | Every record must have a CPE URI |
# MAGIC | `cve_affected_products` | `has_vendor` | `vendor IS NOT NULL` | expect_or_drop | Records without vendor are not useful for product analysis |
# MAGIC | `cve_documents` | `valid_cve_id` | `cve_id IS NOT NULL` | expect | Every document must have a CVE ID |
# MAGIC | `cve_documents` | `has_document_text` | `LENGTH(document_text) > 50` | expect_or_drop | Documents must have sufficient text for meaningful embeddings |
# MAGIC
# MAGIC ### Vector Search Integration
# MAGIC
# MAGIC The `cve_documents` table is designed for use with Databricks Vector Search:
# MAGIC
# MAGIC - **Change Data Feed**: Enabled via `delta.enableChangeDataFeed` table property
# MAGIC - **Primary Key**: `cve_id` column uniquely identifies each document
# MAGIC - **Embedding Source**: `document_text` column contains the text to be embedded
# MAGIC - **Metadata Filters**: `cvss_v3_score`, `cvss_v3_severity`, `epss_score`, `kev_flag`, `vendors_str`, `products_str`, `cwe_id`
# MAGIC
# MAGIC To create a Delta Sync Vector Search index on this table:
# MAGIC ```python
# MAGIC from databricks.vector_search.client import VectorSearchClient
# MAGIC
# MAGIC client = VectorSearchClient()
# MAGIC index = client.create_delta_sync_index(
# MAGIC     endpoint_name="vulnpulse_vs_endpoint",
# MAGIC     index_name="vulnpulse.silver.cve_documents_index",
# MAGIC     source_table_name="vulnpulse.silver.cve_documents",
# MAGIC     pipeline_type="TRIGGERED",
# MAGIC     primary_key="cve_id",
# MAGIC     embedding_source_column="document_text",
# MAGIC     embedding_model_endpoint_name="databricks-gte-large-en"
# MAGIC )
# MAGIC ```
