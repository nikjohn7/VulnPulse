#!/usr/bin/env python3
"""CISA KEV (Known Exploited Vulnerabilities) Data Fetcher

Downloads the CISA Known Exploited Vulnerabilities catalog and saves locally.
This catalog contains vulnerabilities that have been actively exploited in the wild.
"""

import json
import sys
from datetime import datetime
from pathlib import Path

import requests

# Constants
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUTPUT_DIR = Path(__file__).parent.parent / "data" / "raw" / "kev"


def fetch_kev() -> int:
    """Download CISA KEV catalog and save locally.
    
    Returns:
        int: Number of vulnerabilities fetched, or -1 on error.
    """
    # Ensure output directory exists
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Generate filename with current date
    today = datetime.now().strftime("%Y-%m-%d")
    output_file = OUTPUT_DIR / f"cisa_kev_{today}.json"
    
    print(f"Fetching CISA Known Exploited Vulnerabilities catalog...")
    print(f"Source: {KEV_URL}")
    
    try:
        response = requests.get(
            KEV_URL,
            headers={"Accept": "application/json"},
            timeout=60
        )
        response.raise_for_status()
        
        # Parse JSON to validate structure before saving
        data = response.json()
        
        # Validate expected structure
        if "vulnerabilities" not in data:
            print("✗ Invalid KEV structure: missing 'vulnerabilities' key")
            return -1
        
        vulnerabilities = data["vulnerabilities"]
        
        if not isinstance(vulnerabilities, list):
            print("✗ Invalid KEV structure: 'vulnerabilities' is not a list")
            return -1
        
        vuln_count = len(vulnerabilities)
        print(f"Fetched {vuln_count:,} vulnerabilities")
        
        # Save as JSON
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        
        print(f"Saved to: {output_file}")
        
        # Validate the saved file
        validated_count = validate_and_count(output_file)
        
        if validated_count >= 0:
            print(f"✓ Successfully downloaded KEV catalog with {validated_count:,} vulnerabilities")
            return validated_count
        else:
            print("✗ Validation failed")
            return -1
            
    except requests.exceptions.RequestException as e:
        print(f"✗ Request failed: {e}")
        return -1
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON response: {e}")
        return -1
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return -1


def validate_and_count(filepath: Path) -> int:
    """Validate that the file is valid JSON and count vulnerabilities.
    
    Args:
        filepath: Path to the JSON file.
        
    Returns:
        int: Number of vulnerabilities, or -1 if validation fails.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # Check for expected structure
        if "vulnerabilities" not in data:
            print("✗ Invalid KEV structure: missing 'vulnerabilities' key")
            return -1
        
        vulnerabilities = data["vulnerabilities"]
        
        if not isinstance(vulnerabilities, list):
            print("✗ Invalid KEV structure: 'vulnerabilities' is not a list")
            return -1
        
        return len(vulnerabilities)
        
    except json.JSONDecodeError as e:
        print(f"✗ File is not valid JSON: {e}")
        return -1
    except Exception as e:
        print(f"✗ Validation error: {e}")
        return -1


if __name__ == "__main__":
    result = fetch_kev()
    sys.exit(0 if result >= 0 else 1)
