#!/usr/bin/env python3
"""EPSS (Exploit Prediction Scoring System) Data Fetcher

Downloads the current EPSS scores from FIRST.org/Cyentia and saves locally.
EPSS provides probability scores (0-1) indicating the likelihood that a CVE
will be exploited in the wild within the next 30 days.
"""

import gzip
import io
import sys
from datetime import datetime
from pathlib import Path

import requests

# Constants
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
OUTPUT_DIR = Path(__file__).parent.parent / "data" / "raw" / "epss"


def fetch_epss() -> int:
    """Download EPSS scores and save locally as CSV.
    
    Downloads the gzipped CSV, decompresses it, removes comment lines,
    and saves as a plain CSV file.
    
    Returns:
        int: Number of CVE scores fetched, or -1 on error.
    """
    # Ensure output directory exists
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Generate filename with current date
    today = datetime.now().strftime("%Y-%m-%d")
    output_file = OUTPUT_DIR / f"epss_{today}.csv"
    
    print(f"Fetching EPSS scores...")
    print(f"Source: {EPSS_URL}")
    
    try:
        response = requests.get(
            EPSS_URL,
            headers={"Accept": "application/gzip"},
            timeout=120
        )
        response.raise_for_status()
        
        # Decompress the gzipped content
        compressed_data = io.BytesIO(response.content)
        
        try:
            with gzip.open(compressed_data, "rt", encoding="utf-8") as gz_file:
                raw_content = gz_file.read()
        except gzip.BadGzipFile:
            print("✗ Downloaded file is not a valid gzip file")
            return -1
        
        # Process lines: skip comment lines (starting with #)
        lines = raw_content.splitlines()
        data_lines = []
        header_line = None
        
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                # Skip comment lines
                continue
            if header_line is None:
                # First non-comment line is the header
                header_line = stripped
                data_lines.append(header_line)
            else:
                data_lines.append(stripped)
        
        if header_line is None:
            print("✗ No data found in EPSS file (only comments)")
            return -1
        
        # Count CVE scores (excluding header)
        cve_count = len(data_lines) - 1
        print(f"Fetched {cve_count:,} CVE scores")
        
        # Save as plain CSV
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(data_lines))
            f.write("\n")  # Trailing newline
        
        print(f"Saved to: {output_file}")
        
        # Validate the saved file
        validated_count = validate_and_count(output_file)
        
        if validated_count >= 0:
            print(f"✓ Successfully downloaded EPSS scores with {validated_count:,} CVE entries")
            return validated_count
        else:
            print("✗ Validation failed")
            return -1
            
    except requests.exceptions.RequestException as e:
        print(f"✗ Request failed: {e}")
        return -1
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return -1


def validate_and_count(filepath: Path) -> int:
    """Validate that the file is a valid CSV and count CVE entries.
    
    Args:
        filepath: Path to the CSV file.
        
    Returns:
        int: Number of CVE entries (excluding header), or -1 if validation fails.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
        
        if len(lines) < 2:
            print("✗ CSV file has no data rows")
            return -1
        
        # Check header has expected columns
        header = lines[0].strip().lower()
        if "cve" not in header or "epss" not in header:
            print("✗ Invalid EPSS CSV structure: missing expected columns (cve, epss)")
            return -1
        
        # Count data rows (excluding header)
        data_rows = [line for line in lines[1:] if line.strip()]
        
        # Validate a sample row has the right format
        if data_rows:
            sample = data_rows[0].strip().split(",")
            if len(sample) < 2:
                print("✗ Invalid EPSS CSV structure: rows don't have enough columns")
                return -1
            # Check first column looks like a CVE ID
            if not sample[0].upper().startswith("CVE-"):
                print("✗ Invalid EPSS CSV structure: first column doesn't contain CVE IDs")
                return -1
        
        return len(data_rows)
        
    except Exception as e:
        print(f"✗ Validation error: {e}")
        return -1


if __name__ == "__main__":
    result = fetch_epss()
    sys.exit(0 if result >= 0 else 1)
