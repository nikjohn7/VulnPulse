-- ============================================================================
-- VulnPulse Unity Catalog Setup Script
-- ============================================================================
-- This script creates the Unity Catalog structure for the VulnPulse project.
-- Run this script in Databricks SQL to set up the catalog, schemas, and volumes.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Step 1: Create the main catalog
-- ----------------------------------------------------------------------------
CREATE CATALOG IF NOT EXISTS vulnpulse
COMMENT 'VulnPulse: AI-Powered Vulnerability Intelligence Platform - Contains all vulnerability data and analytics';

-- Switch to the vulnpulse catalog
USE CATALOG vulnpulse;

-- ----------------------------------------------------------------------------
-- Step 2: Create schemas with descriptive comments
-- ----------------------------------------------------------------------------

-- Bronze schema: Raw data ingestion layer
CREATE SCHEMA IF NOT EXISTS bronze
COMMENT 'Bronze layer: Raw vulnerability data ingested from NVD, CISA KEV, and EPSS sources. Data is stored in its original format with minimal transformation.';

-- Silver schema: Cleaned and transformed data layer
CREATE SCHEMA IF NOT EXISTS silver
COMMENT 'Silver layer: Cleaned, validated, and transformed vulnerability data. Contains parsed CVE details, signals (EPSS/KEV), affected products, and document embeddings for vector search.';

-- Gold schema: Business-ready analytics layer
CREATE SCHEMA IF NOT EXISTS gold
COMMENT 'Gold layer: Enriched vulnerability data with risk scores, aggregations, and analytics-ready tables for reporting and dashboards.';

-- Agent schema: AI agent tools and utilities
CREATE SCHEMA IF NOT EXISTS agent
COMMENT 'Agent layer: Tables and utilities supporting the AI-powered vulnerability intelligence agent, including query logs and cached responses.';

-- ----------------------------------------------------------------------------
-- Step 3: Create volume for raw file storage
-- ----------------------------------------------------------------------------

-- Create volume in bronze schema for storing raw data files
CREATE VOLUME IF NOT EXISTS bronze.raw_files
COMMENT 'Storage volume for raw vulnerability data files (NVD JSON, KEV JSON, EPSS CSV) before ingestion into Bronze tables.';

-- ----------------------------------------------------------------------------
-- Step 4: Verification queries
-- ----------------------------------------------------------------------------

-- Verify schemas were created
SHOW SCHEMAS IN vulnpulse;

-- Verify volume was created
SHOW VOLUMES IN vulnpulse.bronze;

-- ============================================================================
-- Expected Output:
-- SHOW SCHEMAS should display: bronze, silver, gold, agent (plus default/information_schema)
-- SHOW VOLUMES should display: raw_files
-- ============================================================================
