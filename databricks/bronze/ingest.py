# Databricks notebook source
# MAGIC %md
# MAGIC # VulnPulse Bronze Layer Ingestion
# MAGIC 
# MAGIC This notebook ingests raw vulnerability data files from the Unity Catalog volume
# MAGIC and creates Bronze layer tables with minimal transformation.
# MAGIC 
# MAGIC ## Data Sources
# MAGIC | Source | File Pattern | Format |
# MAGIC |--------|--------------|--------|
# MAGIC | NVD | `nvd_modified_*.json.gz` | Gzipped JSON |
# MAGIC | CISA KEV | `cisa_kev_*.json` | JSON |
# MAGIC | EPSS | `epss_*.csv` | CSV |
# MAGIC 
# MAGIC ## Output Tables
# MAGIC - `vulnpulse.bronze.nvd_raw`
# MAGIC - `vulnpulse.bronze.kev_raw`
# MAGIC - `vulnpulse.bronze.epss_raw`

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration

# COMMAND ----------

# Configuration
CATALOG = "vulnpulse"
SCHEMA = "bronze"
VOLUME_PATH = f"/Volumes/{CATALOG}/{SCHEMA}/raw_files"

# Source directories
NVD_PATH = f"{VOLUME_PATH}/nvd"
KEV_PATH = f"{VOLUME_PATH}/kev"
EPSS_PATH = f"{VOLUME_PATH}/epss"

# Target tables
NVD_TABLE = f"{CATALOG}.{SCHEMA}.nvd_raw"
KEV_TABLE = f"{CATALOG}.{SCHEMA}.kev_raw"
EPSS_TABLE = f"{CATALOG}.{SCHEMA}.epss_raw"

print(f"Volume Path: {VOLUME_PATH}")
print(f"NVD Source: {NVD_PATH}")
print(f"KEV Source: {KEV_PATH}")
print(f"EPSS Source: {EPSS_PATH}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Imports and Setup

# COMMAND ----------

import json
import gzip
import re
from datetime import datetime
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StructType, StructField, StringType, TimestampType, 
    DoubleType, DateType
)

# Current timestamp for ingestion tracking
ingest_timestamp = datetime.now()
print(f"Ingestion Timestamp: {ingest_timestamp}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Helper Functions

# COMMAND ----------

def extract_snapshot_date(filename: str) -> str:
    """Extract date from filename pattern like 'nvd_modified_2024-01-15.json.gz'
    
    Args:
        filename: The filename to extract date from
        
    Returns:
        Date string in YYYY-MM-DD format, or None if not found
    """
    # Match date pattern YYYY-MM-DD in filename
    match = re.search(r'(\d{4}-\d{2}-\d{2})', filename)
    if match:
        return match.group(1)
    return None


def list_files_in_path(path: str) -> list:
    """List all files in a given path using dbutils.
    
    Args:
        path: The path to list files from
        
    Returns:
        List of file paths
    """
    try:
        files = dbutils.fs.ls(path)
        return [f.path for f in files if not f.isDir()]
    except Exception as e:
        print(f"Warning: Could not list files in {path}: {e}")
        return []

# COMMAND ----------

# MAGIC %md
# MAGIC ## 1. Ingest NVD Data
# MAGIC 
# MAGIC Reads gzipped JSON files from NVD, extracts CVE items, and creates the `nvd_raw` table.

# COMMAND ----------

def ingest_nvd():
    """Ingest NVD data from gzipped JSON files into Bronze table.
    
    Each CVE item is stored with its raw JSON and metadata.
    """
    print("=" * 60)
    print("Ingesting NVD Data")
    print("=" * 60)
    
    # List NVD files
    nvd_files = list_files_in_path(NVD_PATH)
    nvd_files = [f for f in nvd_files if f.endswith('.json.gz')]
    
    if not nvd_files:
        print(f"No NVD files found in {NVD_PATH}")
        return 0
    
    print(f"Found {len(nvd_files)} NVD file(s)")
    
    all_records = []
    
    for file_path in nvd_files:
        print(f"Processing: {file_path}")
        
        # Extract filename from path
        filename = file_path.split('/')[-1]
        snapshot_date = extract_snapshot_date(filename)
        
        # Read gzipped JSON file
        # Convert dbfs path to local path for reading
        local_path = file_path.replace("dbfs:", "/dbfs")
        
        try:
            with gzip.open(local_path, 'rt', encoding='utf-8') as f:
                data = json.load(f)
            
            cve_items = data.get('CVE_Items', [])
            print(f"  Found {len(cve_items):,} CVE items")
            
            for item in cve_items:
                # Extract CVE ID from the nested structure
                # NVD API 2.0 format: item['cve']['id']
                # Legacy format: item['cve']['CVE_data_meta']['ID']
                cve_id = None
                
                if 'cve' in item:
                    cve_data = item['cve']
                    if 'id' in cve_data:
                        # NVD API 2.0 format
                        cve_id = cve_data['id']
                    elif 'CVE_data_meta' in cve_data:
                        # Legacy 1.1 format
                        cve_id = cve_data['CVE_data_meta'].get('ID')
                
                if cve_id:
                    all_records.append({
                        'cve_id': cve_id,
                        'raw_json': json.dumps(item),
                        'ingest_ts': ingest_timestamp,
                        'source_file': filename,
                        'snapshot_date': snapshot_date
                    })
                    
        except Exception as e:
            print(f"  Error processing {filename}: {e}")
            continue
    
    if not all_records:
        print("No NVD records to ingest")
        return 0
    
    # Create DataFrame
    schema = StructType([
        StructField("cve_id", StringType(), False),
        StructField("raw_json", StringType(), False),
        StructField("ingest_ts", TimestampType(), False),
        StructField("source_file", StringType(), False),
        StructField("snapshot_date", StringType(), True)
    ])
    
    df = spark.createDataFrame(all_records, schema)
    
    # Convert snapshot_date string to date type
    df = df.withColumn("snapshot_date", F.to_date(F.col("snapshot_date"), "yyyy-MM-dd"))
    
    # Write to table in append mode
    df.write.mode("append").saveAsTable(NVD_TABLE)
    
    record_count = len(all_records)
    print(f"✓ Ingested {record_count:,} NVD records into {NVD_TABLE}")
    
    return record_count

# Execute NVD ingestion
nvd_count = ingest_nvd()

# COMMAND ----------

# MAGIC %md
# MAGIC ## 2. Ingest KEV Data
# MAGIC 
# MAGIC Reads JSON files from CISA KEV catalog and creates the `kev_raw` table.

# COMMAND ----------

def ingest_kev():
    """Ingest CISA KEV data from JSON files into Bronze table.
    
    Each vulnerability is stored with its raw JSON and metadata.
    """
    print("=" * 60)
    print("Ingesting CISA KEV Data")
    print("=" * 60)
    
    # List KEV files
    kev_files = list_files_in_path(KEV_PATH)
    kev_files = [f for f in kev_files if f.endswith('.json')]
    
    if not kev_files:
        print(f"No KEV files found in {KEV_PATH}")
        return 0
    
    print(f"Found {len(kev_files)} KEV file(s)")
    
    all_records = []
    
    for file_path in kev_files:
        print(f"Processing: {file_path}")
        
        # Extract filename from path
        filename = file_path.split('/')[-1]
        snapshot_date = extract_snapshot_date(filename)
        
        # Read JSON file
        local_path = file_path.replace("dbfs:", "/dbfs")
        
        try:
            with open(local_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            vulnerabilities = data.get('vulnerabilities', [])
            print(f"  Found {len(vulnerabilities):,} vulnerabilities")
            
            for vuln in vulnerabilities:
                # Extract CVE ID
                cve_id = vuln.get('cveID')
                
                if cve_id:
                    all_records.append({
                        'cve_id': cve_id,
                        'raw_json': json.dumps(vuln),
                        'ingest_ts': ingest_timestamp,
                        'source_file': filename,
                        'snapshot_date': snapshot_date
                    })
                    
        except Exception as e:
            print(f"  Error processing {filename}: {e}")
            continue
    
    if not all_records:
        print("No KEV records to ingest")
        return 0
    
    # Create DataFrame
    schema = StructType([
        StructField("cve_id", StringType(), False),
        StructField("raw_json", StringType(), False),
        StructField("ingest_ts", TimestampType(), False),
        StructField("source_file", StringType(), False),
        StructField("snapshot_date", StringType(), True)
    ])
    
    df = spark.createDataFrame(all_records, schema)
    
    # Convert snapshot_date string to date type
    df = df.withColumn("snapshot_date", F.to_date(F.col("snapshot_date"), "yyyy-MM-dd"))
    
    # Write to table in append mode
    df.write.mode("append").saveAsTable(KEV_TABLE)
    
    record_count = len(all_records)
    print(f"✓ Ingested {record_count:,} KEV records into {KEV_TABLE}")
    
    return record_count

# Execute KEV ingestion
kev_count = ingest_kev()

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3. Ingest EPSS Data
# MAGIC 
# MAGIC Reads CSV files from EPSS and creates the `epss_raw` table with raw columns.

# COMMAND ----------

def ingest_epss():
    """Ingest EPSS data from CSV files into Bronze table.
    
    EPSS data is stored with raw columns (not as JSON) since it's already tabular.
    """
    print("=" * 60)
    print("Ingesting EPSS Data")
    print("=" * 60)
    
    # List EPSS files
    epss_files = list_files_in_path(EPSS_PATH)
    epss_files = [f for f in epss_files if f.endswith('.csv')]
    
    if not epss_files:
        print(f"No EPSS files found in {EPSS_PATH}")
        return 0
    
    print(f"Found {len(epss_files)} EPSS file(s)")
    
    all_dfs = []
    total_records = 0
    
    for file_path in epss_files:
        print(f"Processing: {file_path}")
        
        # Extract filename from path
        filename = file_path.split('/')[-1]
        snapshot_date = extract_snapshot_date(filename)
        
        try:
            # Read CSV file with header
            df = spark.read.option("header", "true").csv(file_path)
            
            record_count = df.count()
            print(f"  Found {record_count:,} EPSS scores")
            total_records += record_count
            
            # Rename columns to standard names and add metadata
            # EPSS CSV has columns: cve, epss, percentile
            df = df.select(
                F.col("cve").alias("cve_id"),
                F.col("epss").cast(DoubleType()).alias("epss_score"),
                F.col("percentile").cast(DoubleType()).alias("epss_percentile"),
                F.lit(ingest_timestamp).cast(TimestampType()).alias("ingest_ts"),
                F.lit(filename).alias("source_file"),
                F.to_date(F.lit(snapshot_date), "yyyy-MM-dd").alias("snapshot_date")
            )
            
            all_dfs.append(df)
            
        except Exception as e:
            print(f"  Error processing {filename}: {e}")
            continue
    
    if not all_dfs:
        print("No EPSS records to ingest")
        return 0
    
    # Union all DataFrames
    combined_df = all_dfs[0]
    for df in all_dfs[1:]:
        combined_df = combined_df.union(df)
    
    # Write to table in append mode
    combined_df.write.mode("append").saveAsTable(EPSS_TABLE)
    
    print(f"✓ Ingested {total_records:,} EPSS records into {EPSS_TABLE}")
    
    return total_records

# Execute EPSS ingestion
epss_count = ingest_epss()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Ingestion Summary

# COMMAND ----------

print("=" * 60)
print("BRONZE INGESTION SUMMARY")
print("=" * 60)
print(f"Ingestion Timestamp: {ingest_timestamp}")
print("-" * 60)
print(f"NVD Records Ingested:  {nvd_count:>10,}")
print(f"KEV Records Ingested:  {kev_count:>10,}")
print(f"EPSS Records Ingested: {epss_count:>10,}")
print("-" * 60)
print(f"Total Records:         {nvd_count + kev_count + epss_count:>10,}")
print("=" * 60)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Verification Queries
# MAGIC 
# MAGIC Run these queries to verify the ingestion was successful.

# COMMAND ----------

# MAGIC %md
# MAGIC ### NVD Raw Table

# COMMAND ----------

# Verify NVD table
print(f"Table: {NVD_TABLE}")
try:
    nvd_df = spark.table(NVD_TABLE)
    print(f"Total Records: {nvd_df.count():,}")
    print("\nSchema:")
    nvd_df.printSchema()
    print("\nSample Records:")
    display(nvd_df.select("cve_id", "ingest_ts", "source_file", "snapshot_date").limit(5))
except Exception as e:
    print(f"Error querying table: {e}")

# COMMAND ----------

# MAGIC %md
# MAGIC ### KEV Raw Table

# COMMAND ----------

# Verify KEV table
print(f"Table: {KEV_TABLE}")
try:
    kev_df = spark.table(KEV_TABLE)
    print(f"Total Records: {kev_df.count():,}")
    print("\nSchema:")
    kev_df.printSchema()
    print("\nSample Records:")
    display(kev_df.select("cve_id", "ingest_ts", "source_file", "snapshot_date").limit(5))
except Exception as e:
    print(f"Error querying table: {e}")

# COMMAND ----------

# MAGIC %md
# MAGIC ### EPSS Raw Table

# COMMAND ----------

# Verify EPSS table
print(f"Table: {EPSS_TABLE}")
try:
    epss_df = spark.table(EPSS_TABLE)
    print(f"Total Records: {epss_df.count():,}")
    print("\nSchema:")
    epss_df.printSchema()
    print("\nSample Records:")
    display(epss_df.limit(5))
except Exception as e:
    print(f"Error querying table: {e}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## End of Notebook
