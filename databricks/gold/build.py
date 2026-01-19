# Databricks notebook source
# MAGIC %md
# MAGIC # VulnPulse Gold Layer - Enriched Vulnerability Tables
# MAGIC
# MAGIC This notebook creates the Gold layer analytics tables by joining and enriching data from
# MAGIC the Silver layer. The primary output is the `vuln_enriched` table which serves as the main
# MAGIC query interface for the agentic RAG system.
# MAGIC
# MAGIC ## Tables Created
# MAGIC | Table | Description |
# MAGIC |-------|-------------|
# MAGIC | `vulnpulse.gold.vuln_enriched` | Fully enriched CVE records with risk scoring |
# MAGIC
# MAGIC ## Risk Scoring Formula
# MAGIC The `risk_score` (0-100) is calculated based on multiple signals:
# MAGIC - **KEV = true**: 90 + (epss_score * 10) → range 90-100
# MAGIC - **EPSS > 0.5**: 70 + (epss_score * 20) → range 70-90
# MAGIC - **EPSS > 0.1**: 40 + (epss_score * 50) → range 45-90
# MAGIC - **Otherwise**: cvss_v3_score * 4 → range 0-40
# MAGIC
# MAGIC ## Risk Tiers
# MAGIC | Tier | Score Range | Description |
# MAGIC |------|-------------|-------------|
# MAGIC | CRITICAL | >= 90 | Known exploited or extremely high EPSS |
# MAGIC | HIGH | >= 70 | High EPSS probability |
# MAGIC | MEDIUM | >= 40 | Moderate EPSS or high CVSS |
# MAGIC | LOW | < 40 | Lower priority based on available signals |

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration

# COMMAND ----------

from pyspark.sql import functions as F
from pyspark.sql.window import Window

# Catalog and schema configuration
CATALOG = "vulnpulse"
SILVER_SCHEMA = "silver"
GOLD_SCHEMA = "gold"

# Source Silver tables
CVE_CORE_TABLE = f"{CATALOG}.{SILVER_SCHEMA}.cve_core"
CVE_SIGNALS_TABLE = f"{CATALOG}.{SILVER_SCHEMA}.cve_signals"
CVE_AFFECTED_PRODUCTS_TABLE = f"{CATALOG}.{SILVER_SCHEMA}.cve_affected_products"

# Target Gold tables
VULN_ENRICHED_TABLE = f"{CATALOG}.{GOLD_SCHEMA}.vuln_enriched"

# COMMAND ----------

# MAGIC %md
# MAGIC ## Calculate Primary Vendor and Product
# MAGIC
# MAGIC For each CVE, identify the most common (primary) vendor and product from the affected
# MAGIC products table. This provides a "headline" vendor/product for display and filtering.

# COMMAND ----------

def get_primary_vendor_product(spark):
    """
    Calculate the primary (most common) vendor and product for each CVE.

    Uses window functions to rank vendors and products by occurrence count
    within each CVE and select the most frequent one.

    Returns:
        DataFrame with cve_id, primary_vendor, primary_product
    """

    # Read affected products table
    products_df = spark.table(CVE_AFFECTED_PRODUCTS_TABLE)

    # Count occurrences of each vendor per CVE
    vendor_counts = products_df.groupBy("cve_id", "vendor").agg(
        F.count("*").alias("vendor_count")
    )

    # Rank vendors by count within each CVE (most common first)
    vendor_window = Window.partitionBy("cve_id").orderBy(F.col("vendor_count").desc())

    primary_vendors = vendor_counts.withColumn(
        "vendor_rank",
        F.row_number().over(vendor_window)
    ).filter(
        F.col("vendor_rank") == 1
    ).select(
        F.col("cve_id"),
        F.col("vendor").alias("primary_vendor")
    )

    # Count occurrences of each product per CVE
    product_counts = products_df.groupBy("cve_id", "product").agg(
        F.count("*").alias("product_count")
    )

    # Rank products by count within each CVE (most common first)
    product_window = Window.partitionBy("cve_id").orderBy(F.col("product_count").desc())

    primary_products = product_counts.withColumn(
        "product_rank",
        F.row_number().over(product_window)
    ).filter(
        F.col("product_rank") == 1
    ).select(
        F.col("cve_id"),
        F.col("product").alias("primary_product")
    )

    # Join vendors and products
    primary_df = primary_vendors.join(
        primary_products,
        on="cve_id",
        how="full_outer"
    )

    return primary_df

# COMMAND ----------

# MAGIC %md
# MAGIC ## Risk Score Calculation
# MAGIC
# MAGIC The risk score combines multiple signals into a single 0-100 score:
# MAGIC
# MAGIC 1. **KEV (Known Exploited Vulnerability)**: Highest priority - active exploitation confirmed
# MAGIC 2. **EPSS (Exploit Prediction Scoring System)**: Probability of exploitation in next 30 days
# MAGIC 3. **CVSS (Common Vulnerability Scoring System)**: Technical severity rating
# MAGIC
# MAGIC The formula prioritizes real-world exploitation evidence over theoretical severity.

# COMMAND ----------

def calculate_risk_score():
    """
    Build the risk_score calculation expression.

    Formula:
    - KEV = true: 90 + (epss_score * 10) → range 90-100
    - EPSS > 0.5: 70 + (epss_score * 20) → range 70-90
    - EPSS > 0.1: 40 + (epss_score * 50) → range 45-90
    - Otherwise: cvss_v3_score * 4 → range 0-40

    Note: When EPSS is null, we use 0 for the EPSS component.
    When CVSS is null, we use 5.0 as a conservative default (medium severity).

    Returns:
        Column expression for risk_score
    """

    # Handle nulls: coalesce EPSS to 0, CVSS to 5.0 (medium default)
    epss = F.coalesce(F.col("epss_score"), F.lit(0.0))
    cvss = F.coalesce(F.col("cvss_v3_score"), F.col("cvss_v2_score"), F.lit(5.0))
    kev = F.coalesce(F.col("kev_flag"), F.lit(False))

    risk_score = (
        F.when(
            # KEV vulnerabilities get highest scores (90-100)
            kev == True,
            F.lit(90) + (epss * 10)
        ).when(
            # High EPSS (>0.5) gets high scores (70-90)
            epss > 0.5,
            F.lit(70) + (epss * 20)
        ).when(
            # Moderate EPSS (>0.1) gets medium-high scores (45-90)
            epss > 0.1,
            F.lit(40) + (epss * 50)
        ).otherwise(
            # Low/no EPSS: fall back to CVSS (0-40)
            cvss * 4
        )
    )

    # Cap at 100 and ensure non-negative
    return F.greatest(F.least(risk_score, F.lit(100.0)), F.lit(0.0))


def calculate_risk_tier():
    """
    Build the risk_tier calculation expression based on risk_score.

    Tiers:
    - CRITICAL: >= 90 (KEV or very high EPSS)
    - HIGH: >= 70 (High EPSS)
    - MEDIUM: >= 40 (Moderate EPSS or high CVSS)
    - LOW: < 40 (Lower priority)

    Returns:
        Column expression for risk_tier
    """

    return (
        F.when(F.col("risk_score") >= 90, F.lit("CRITICAL"))
        .when(F.col("risk_score") >= 70, F.lit("HIGH"))
        .when(F.col("risk_score") >= 40, F.lit("MEDIUM"))
        .otherwise(F.lit("LOW"))
    )

# COMMAND ----------

# MAGIC %md
# MAGIC ## Build Enriched Vulnerability Table
# MAGIC
# MAGIC Join all Silver tables and add computed columns:
# MAGIC - `primary_vendor`: Most common vendor for the CVE
# MAGIC - `primary_product`: Most common product for the CVE
# MAGIC - `risk_score`: Calculated 0-100 score
# MAGIC - `risk_tier`: CRITICAL/HIGH/MEDIUM/LOW based on risk_score

# COMMAND ----------

def build_vuln_enriched(spark):
    """
    Build the vuln_enriched Gold table by joining Silver tables and
    adding computed columns for risk scoring.

    Joins:
    - cve_core: Base CVE metadata
    - cve_signals: EPSS and KEV data
    - primary_vendor_product: Computed most common vendor/product

    Computed columns:
    - primary_vendor: Most common vendor for this CVE
    - primary_product: Most common product for this CVE
    - risk_score: 0-100 score based on KEV, EPSS, CVSS
    - risk_tier: CRITICAL/HIGH/MEDIUM/LOW

    Returns:
        DataFrame with enriched CVE data
    """

    # Read Silver tables
    core_df = spark.table(CVE_CORE_TABLE)
    signals_df = spark.table(CVE_SIGNALS_TABLE)

    # Get primary vendor/product
    primary_df = get_primary_vendor_product(spark)

    # Join core with signals
    enriched_df = core_df.join(
        signals_df,
        on="cve_id",
        how="left"
    )

    # Join with primary vendor/product
    enriched_df = enriched_df.join(
        primary_df,
        on="cve_id",
        how="left"
    )

    # Add risk_score and risk_tier
    enriched_df = enriched_df.withColumn(
        "risk_score",
        F.round(calculate_risk_score(), 2)  # Round to 2 decimal places
    ).withColumn(
        "risk_tier",
        calculate_risk_tier()
    )

    # Select final columns in logical order
    final_df = enriched_df.select(
        # Identifiers
        "cve_id",

        # Risk scoring (most important for prioritization)
        "risk_score",
        "risk_tier",

        # KEV signals (highest priority)
        "kev_flag",
        "kev_date_added",
        "kev_due_date",
        "kev_ransomware_use",
        "kev_notes",

        # EPSS signals
        "epss_score",
        "epss_percentile",

        # CVSS metrics
        "cvss_v3_score",
        "cvss_v3_severity",
        "cvss_v3_vector",
        "cvss_v2_score",

        # Primary vendor/product
        "primary_vendor",
        "primary_product",

        # CVE metadata
        "description",
        "cwe_id",
        "published",
        "last_modified"
    )

    return final_df

# COMMAND ----------

# MAGIC %md
# MAGIC ## Execute: Create Gold Tables

# COMMAND ----------

# Build the enriched vulnerability table
print(f"Building {VULN_ENRICHED_TABLE}...")

vuln_enriched_df = build_vuln_enriched(spark)

# Write to Gold table (overwrite for idempotency)
vuln_enriched_df.write.mode("overwrite").saveAsTable(VULN_ENRICHED_TABLE)

# Get row count
row_count = spark.table(VULN_ENRICHED_TABLE).count()
print(f"Created {VULN_ENRICHED_TABLE} with {row_count:,} rows")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Verification: Sample Data

# COMMAND ----------

# Display sample of enriched data ordered by risk_score
print("Sample CVEs ordered by risk_score (descending):")
display(
    spark.table(VULN_ENRICHED_TABLE)
    .orderBy(F.col("risk_score").desc())
    .limit(20)
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Verification: Risk Distribution

# COMMAND ----------

# Show distribution of risk tiers
print("Risk Tier Distribution:")
display(
    spark.table(VULN_ENRICHED_TABLE)
    .groupBy("risk_tier")
    .agg(
        F.count("*").alias("count"),
        F.round(F.avg("risk_score"), 2).alias("avg_risk_score"),
        F.round(F.min("risk_score"), 2).alias("min_risk_score"),
        F.round(F.max("risk_score"), 2).alias("max_risk_score")
    )
    .orderBy(F.col("avg_risk_score").desc())
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Verification: KEV Entries Have Highest Scores

# COMMAND ----------

# Verify KEV entries have highest scores
print("Comparing KEV vs Non-KEV risk scores:")
display(
    spark.table(VULN_ENRICHED_TABLE)
    .groupBy("kev_flag")
    .agg(
        F.count("*").alias("count"),
        F.round(F.avg("risk_score"), 2).alias("avg_risk_score"),
        F.round(F.min("risk_score"), 2).alias("min_risk_score"),
        F.round(F.max("risk_score"), 2).alias("max_risk_score"),
        F.sum(F.when(F.col("risk_tier") == "CRITICAL", 1).otherwise(0)).alias("critical_count")
    )
    .orderBy(F.col("kev_flag").desc())
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Verification: Schema

# COMMAND ----------

# Show final schema
print("vuln_enriched schema:")
spark.table(VULN_ENRICHED_TABLE).printSchema()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Summary
# MAGIC
# MAGIC The Gold `vuln_enriched` table is now ready for use by the agentic RAG system.
# MAGIC
# MAGIC ### Key Features
# MAGIC - **Risk Score**: 0-100 score prioritizing KEV > EPSS > CVSS
# MAGIC - **Risk Tier**: CRITICAL/HIGH/MEDIUM/LOW for quick filtering
# MAGIC - **Primary Vendor/Product**: Most common affected vendor and product
# MAGIC - **Complete Signals**: KEV, EPSS, and CVSS data in one table
# MAGIC
# MAGIC ### Usage Examples
# MAGIC ```sql
# MAGIC -- Get critical vulnerabilities
# MAGIC SELECT * FROM vulnpulse.gold.vuln_enriched WHERE risk_tier = 'CRITICAL';
# MAGIC
# MAGIC -- Get KEV entries with ransomware use
# MAGIC SELECT * FROM vulnpulse.gold.vuln_enriched
# MAGIC WHERE kev_flag = true AND kev_ransomware_use = 'Known';
# MAGIC
# MAGIC -- Get vulnerabilities for a specific vendor
# MAGIC SELECT * FROM vulnpulse.gold.vuln_enriched
# MAGIC WHERE primary_vendor = 'apache' ORDER BY risk_score DESC;
# MAGIC ```
