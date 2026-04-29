"""
nvd_connector.py
─────────────────────────────────────────────────────────────────────────────
Queries the NVD (National Vulnerability Database) REST API v2
to fetch real CVEs for a given software name and version.

NVD API docs: https://nvd.nist.gov/developers/vulnerabilities
Rate limit   : 5 requests per 30 seconds (no API key)
              50 requests per 30 seconds (with API key)

Usage:
    from nvd_connector import fetch_cves_for_software
    cves = fetch_cves_for_software("nginx", "1.18.0")
─────────────────────────────────────────────────────────────────────────────
"""

import time
import requests
from datetime import datetime

# ─── NVD API CONFIG ───────────────────────────────────────────────────────────
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Delay between requests to stay within rate limit
# Without API key: 5 req / 30 sec = 6 seconds per request to be safe
RATE_LIMIT_DELAY = 6

# Max CVEs to return per software — NVD can return hundreds
MAX_CVES = 5

# Request timeout in seconds
TIMEOUT = 15


# ─── MAIN FUNCTION ────────────────────────────────────────────────────────────

def fetch_cves_for_software(software_name: str, software_version: str = None) -> list:
    """
    Query NVD API for CVEs affecting this software and version.

    How it works:
    1. Build a search query using the software name
    2. Send GET request to NVD API
    3. Parse the response and extract CVE details
    4. Return list of CVE dicts in our standard format

    Args:
        software_name   : e.g. "nginx", "mysql", "apache"
        software_version: e.g. "1.18.0", "8.0.32" (optional)

    Returns:
        List of CVE dicts with keys:
        cve, severity, cvss_score, exploit_available,
        patch_available, description
    """

    if not software_name:
        return []

    print(f"🔍 Querying NVD for: {software_name} {software_version or ''}")

    try:
        # ── Step 1: Build query parameters ───────────────────────────────────
        # NVD keywordSearch searches CVE descriptions and titles
        # Using software name gives us relevant CVEs
        params = {
            "keywordSearch": software_name,
            "resultsPerPage": MAX_CVES,
            "startIndex": 0,
        }

        # ── Step 2: Send request to NVD API ───────────────────────────────────
        # We wait before each request to respect rate limits
        time.sleep(RATE_LIMIT_DELAY)

        response = requests.get(
            NVD_BASE_URL,
            params=params,
            timeout=TIMEOUT,
            headers={"User-Agent": "Sentinel-Security-Platform/1.0"}
        )

        # If NVD returns an error status code, return empty list
        if response.status_code != 200:
            print(f"   ⚠️  NVD API returned status {response.status_code}")
            return []

        data = response.json()

        # ── Step 3: Parse CVE results ─────────────────────────────────────────
        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            print(f"   ℹ️  No CVEs found for {software_name}")
            return []

        print(f"   Found {len(vulnerabilities)} CVEs from NVD")

        # ── Step 4: Extract and format each CVE ───────────────────────────────
        cves = []
        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            parsed = parse_cve(cve_data, software_name)
            if parsed:
                cves.append(parsed)

        print(f"   ✅ Returning {len(cves)} CVEs for {software_name}")
        return cves

    except requests.exceptions.Timeout:
        print(f"   ⚠️  NVD API request timed out for {software_name}")
        return []

    except requests.exceptions.ConnectionError:
        print(f"   ⚠️  Could not connect to NVD API (no internet?)")
        return []

    except Exception as e:
        print(f"   ⚠️  NVD API error for {software_name}: {e}")
        return []


# ─── CVE PARSER ───────────────────────────────────────────────────────────────

def parse_cve(cve_data: dict, software_name: str) -> dict:
    """
    Parse one CVE object from the NVD API response into our standard format.

    The NVD API response is deeply nested. This function navigates
    that structure and extracts only the fields we need.

    NVD response structure:
    {
      "id": "CVE-2021-23017",
      "descriptions": [{"lang": "en", "value": "...description..."}],
      "metrics": {
        "cvssMetricV31": [{
          "cvssData": {
            "baseScore": 9.4,
            "baseSeverity": "CRITICAL"
          },
          "exploitabilityScore": 3.9
        }]
      },
      "references": [{"url": "...", "tags": ["Patch", "Exploit"]}]
    }
    """

    try:
        # ── CVE ID ────────────────────────────────────────────────────────────
        cve_id = cve_data.get("id", "UNKNOWN")

        # ── Description (English only) ────────────────────────────────────────
        description = ""
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Skip CVEs with no description
        if not description:
            return None

        # ── CVSS Score and Severity ────────────────────────────────────────────
        # NVD provides CVSS v3.1, v3.0, and v2.0 scores
        # We prefer v3.1 > v3.0 > v2.0
        cvss_score = None
        severity   = "Unknown"

        metrics = cve_data.get("metrics", {})

        # Try CVSS v3.1 first (most modern)
        if "cvssMetricV31" in metrics:
            metric = metrics["cvssMetricV31"][0]
            cvss_data  = metric.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity   = cvss_data.get("baseSeverity", "Unknown").capitalize()

        # Fall back to CVSS v3.0
        elif "cvssMetricV30" in metrics:
            metric = metrics["cvssMetricV30"][0]
            cvss_data  = metric.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity   = cvss_data.get("baseSeverity", "Unknown").capitalize()

        # Fall back to CVSS v2
        elif "cvssMetricV2" in metrics:
            metric = metrics["cvssMetricV2"][0]
            cvss_data  = metric.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            # v2 doesn't have severity — derive from score
            if cvss_score:
                if cvss_score >= 7.0:   severity = "High"
                elif cvss_score >= 4.0: severity = "Medium"
                else:                   severity = "Low"

        # Normalise severity capitalisation
        # NVD returns "CRITICAL" — we want "Critical"
        severity = severity.capitalize()
        if severity.upper() == "CRITICAL": severity = "Critical"
        elif severity.upper() == "HIGH":   severity = "High"
        elif severity.upper() == "MEDIUM": severity = "Medium"
        elif severity.upper() == "LOW":    severity = "Low"

        # ── Exploit and Patch Availability ───────────────────────────────────
        # NVD references list tags like "Exploit", "Patch", "Vendor Advisory"
        # We scan these tags to determine exploit and patch availability
        references = cve_data.get("references", [])
        all_tags   = []
        for ref in references:
            all_tags.extend(ref.get("tags", []))

        # Check for exploit tags
        exploit_tags   = {"Exploit", "Technical Description", "Exploit Code"}
        exploit_available = any(tag in exploit_tags for tag in all_tags)

        # Check for patch tags
        patch_tags     = {"Patch", "Vendor Advisory", "Mitigation", "Third Party Advisory"}
        patch_available   = any(tag in patch_tags for tag in all_tags)

        # ── Build our standard CVE dict ───────────────────────────────────────
        return {
            "cve":               cve_id,
            "severity":          severity,
            "cvss_score":        float(cvss_score) if cvss_score else None,
            "exploit_available": exploit_available,
            "patch_available":   patch_available,
            "description":       description[:500],  # cap at 500 chars
            "source":            "NVD",              # flag as real data
        }

    except Exception as e:
        print(f"   ⚠️  Failed to parse CVE: {e}")
        return None


# ─── FALLBACK FUNCTION ────────────────────────────────────────────────────────

def get_cves_with_fallback(software_name: str, software_version: str,
                            mock_cves: list = None) -> tuple:
    """
    Try to fetch real CVEs from NVD.
    If NVD is unavailable, fall back to mock CVEs from the request body.

    Returns:
        (cves, source) where source is "NVD" or "provided"
    """

    # Try NVD first
    real_cves = fetch_cves_for_software(software_name, software_version)

    if real_cves:
        return real_cves, "NVD"

    # Fall back to whatever CVEs were provided in the POST /assets body
    if mock_cves:
        print(f"   ℹ️  Using provided CVEs as fallback for {software_name}")
        return mock_cves, "provided"

    # No CVEs available at all
    print(f"   ℹ️  No CVEs available for {software_name} {software_version}")
    return [], "none"


# ─── TEST ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("🚀 NVD Connector Test")
    print("=" * 50)

    # Test with nginx — should return real CVEs
    print("\n📋 Testing: nginx 1.18.0")
    cves = fetch_cves_for_software("nginx", "1.18.0")

    if cves:
        for cve in cves:
            print(f"\n  CVE ID    : {cve['cve']}")
            print(f"  Severity  : {cve['severity']}")
            print(f"  CVSS      : {cve['cvss_score']}")
            print(f"  Exploit   : {cve['exploit_available']}")
            print(f"  Patch     : {cve['patch_available']}")
            print(f"  Desc      : {cve['description'][:80]}...")
    else:
        print("  No CVEs returned (NVD may be unavailable)")

    print("\n✅ NVD connector test complete")