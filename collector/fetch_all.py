#!/usr/bin/env python3
"""Unified Data Fetcher for VulnPulse

Orchestrates the collection of vulnerability data from all sources:
- NVD (National Vulnerability Database)
- CISA KEV (Known Exploited Vulnerabilities)
- EPSS (Exploit Prediction Scoring System)

This script handles errors gracefully, continuing with remaining sources
if one fails, and provides a summary of the collection results.
"""

import sys
from typing import Tuple

from fetch_nvd import fetch_nvd
from fetch_kev import fetch_kev
from fetch_epss import fetch_epss


def fetch_all() -> Tuple[int, int]:
    """Fetch data from all vulnerability sources.
    
    Calls each fetcher in sequence, handling errors gracefully so that
    a failure in one source doesn't prevent fetching from others.
    
    Returns:
        Tuple[int, int]: (successful_count, total_count) where successful_count
                         is the number of sources that fetched successfully.
    """
    sources = [
        ("NVD (National Vulnerability Database)", fetch_nvd),
        ("CISA KEV (Known Exploited Vulnerabilities)", fetch_kev),
        ("EPSS (Exploit Prediction Scoring System)", fetch_epss),
    ]
    
    total = len(sources)
    successful = 0
    results = []
    
    print("=" * 60)
    print("VulnPulse Data Collection")
    print("=" * 60)
    print()
    
    for idx, (name, fetcher) in enumerate(sources, start=1):
        print(f"[{idx}/{total}] Fetching {name}...")
        print("-" * 40)
        
        try:
            result = fetcher()
            if result >= 0:
                successful += 1
                results.append((name, "✓ Success", f"{result:,} records"))
                print()
            else:
                results.append((name, "✗ Failed", "Validation error"))
                print()
        except Exception as e:
            results.append((name, "✗ Failed", str(e)))
            print(f"✗ Error fetching {name}: {e}")
            print()
    
    # Print summary
    print("=" * 60)
    print("Collection Summary")
    print("=" * 60)
    print()
    
    for name, status, details in results:
        print(f"  {status} {name}")
        print(f"      {details}")
        print()
    
    print("-" * 60)
    print(f"Collection complete: {successful}/{total} sources fetched")
    print("=" * 60)
    
    return successful, total


def main() -> int:
    """Main entry point for the unified fetch script.
    
    Returns:
        int: Exit code (0 if all sources fetched, 1 if any failed).
    """
    successful, total = fetch_all()
    
    # Return 0 only if all sources were fetched successfully
    return 0 if successful == total else 1


if __name__ == "__main__":
    sys.exit(main())
