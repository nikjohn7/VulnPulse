#!/usr/bin/env python3
"""NVD (National Vulnerability Database) Data Fetcher

Downloads recently modified CVEs from the NVD API 2.0 and saves locally.
The old JSON feeds have been deprecated; this uses the current API.
"""

import gzip
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

# Constants
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUTPUT_DIR = Path(__file__).parent.parent / "data" / "raw" / "nvd"

# API rate limiting: NVD allows 5 requests per 30 seconds without API key
REQUEST_DELAY = 6  # seconds between requests
RESULTS_PER_PAGE = 2000  # max allowed by API


def fetch_nvd(days_back: int = 8) -> int:
    """Download recently modified CVEs from NVD API 2.0 and save locally.
    
    Args:
        days_back: Number of days to look back for modified CVEs (default: 8).
                   NVD recommends 7-8 days for the "modified" feed equivalent.
    
    Returns:
        int: Number of CVEs fetched, or -1 on error.
    """
    # Ensure output directory exists
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Generate filename with current date
    today = datetime.now().strftime("%Y-%m-%d")
    output_file = OUTPUT_DIR / f"nvd_modified_{today}.json.gz"
    
    # Calculate date range for modified CVEs
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days_back)
    
    # Format dates for API (ISO 8601)
    last_mod_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    last_mod_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    
    print(f"Fetching CVEs modified between {start_date.date()} and {end_date.date()}...")
    print(f"Using NVD API 2.0: {NVD_API_URL}")
    
    all_cves = []
    start_index = 0
    total_results = None
    
    try:
        while True:
            # Build request parameters
            params = {
                "lastModStartDate": last_mod_start,
                "lastModEndDate": last_mod_end,
                "startIndex": start_index,
                "resultsPerPage": RESULTS_PER_PAGE,
            }
            
            print(f"  Fetching results {start_index} to {start_index + RESULTS_PER_PAGE}...")
            
            response = requests.get(
                NVD_API_URL,
                params=params,
                headers={"Accept": "application/json"},
                timeout=120
            )
            response.raise_for_status()
            
            data = response.json()
            
            # Get total count on first request
            if total_results is None:
                total_results = data.get("totalResults", 0)
                print(f"  Total CVEs to fetch: {total_results:,}")
            
            # Extract vulnerabilities from response
            vulnerabilities = data.get("vulnerabilities", [])
            all_cves.extend(vulnerabilities)
            
            # Check if we've fetched all results
            if len(all_cves) >= total_results:
                break
            
            # Move to next page
            start_index += RESULTS_PER_PAGE
            
            # Rate limiting - wait between requests
            print(f"  Waiting {REQUEST_DELAY}s for rate limiting...")
            time.sleep(REQUEST_DELAY)
        
        print(f"Fetched {len(all_cves):,} CVEs total")
        
        # Build output structure compatible with downstream processing
        # Using a structure similar to the old feed format for compatibility
        output_data = {
            "CVE_data_type": "CVE",
            "CVE_data_format": "NVD_API_2.0",
            "CVE_data_version": "2.0",
            "CVE_data_timestamp": end_date.isoformat(),
            "CVE_data_numberOfCVEs": len(all_cves),
            "CVE_Items": all_cves  # Note: structure differs from 1.1 format
        }
        
        # Save as gzipped JSON
        with gzip.open(output_file, "wt", encoding="utf-8") as f:
            json.dump(output_data, f)
        
        print(f"Saved to: {output_file}")
        
        # Validate the saved file
        cve_count = validate_and_count(output_file)
        
        if cve_count >= 0:
            print(f"✓ Successfully downloaded NVD feed with {cve_count:,} CVE_Items")
            return cve_count
        else:
            print("✗ Validation failed")
            return -1
            
    except requests.exceptions.RequestException as e:
        print(f"✗ API request failed: {e}")
        return -1
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return -1


def validate_and_count(filepath: Path) -> int:
    """Validate that the file is valid gzipped JSON and count CVE_Items.
    
    Args:
        filepath: Path to the gzipped JSON file.
        
    Returns:
        int: Number of CVE_Items, or -1 if validation fails.
    """
    try:
        with gzip.open(filepath, "rt", encoding="utf-8") as f:
            data = json.load(f)
        
        # Check for expected structure
        if "CVE_Items" not in data:
            print("✗ Invalid NVD feed structure: missing 'CVE_Items' key")
            return -1
        
        cve_items = data["CVE_Items"]
        
        if not isinstance(cve_items, list):
            print("✗ Invalid NVD feed structure: 'CVE_Items' is not a list")
            return -1
        
        return len(cve_items)
        
    except gzip.BadGzipFile:
        print("✗ File is not a valid gzip file")
        return -1
    except json.JSONDecodeError as e:
        print(f"✗ File is not valid JSON: {e}")
        return -1
    except Exception as e:
        print(f"✗ Validation error: {e}")
        return -1


if __name__ == "__main__":
    result = fetch_nvd()
    sys.exit(0 if result >= 0 else 1)
