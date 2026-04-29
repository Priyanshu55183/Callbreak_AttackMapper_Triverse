
import json
import random
import os
from datetime import datetime, timedelta

random.seed(42)   # reproducible output

# ─── REFERENCE DATA ───────────────────────────────────────────────────────────

TEAMS = [
    "Cloud Engineering",
    "DevOps",
    "Security Ops",
    "Backend Team",
    "Platform Team",
    "Network Ops",
    "Data Engineering",
]

TEAM_EMAILS = {
    "Cloud Engineering": "cloud-eng@company.com",
    "DevOps":            "devops@company.com",
    "Security Ops":      "secops@company.com",
    "Backend Team":      "backend@company.com",
    "Platform Team":     "platform@company.com",
    "Network Ops":       "netops@company.com",
    "Data Engineering":  "data-eng@company.com",
}

ASSET_TYPES  = ["Web Server", "Database Server", "Cloud VM", "API Gateway", "Firewall"]
ENVIRONMENTS = ["Production", "Staging", "Development"]

OPERATING_SYSTEMS = [
    {"name": "Ubuntu",          "version": "22.04"},
    {"name": "Ubuntu",          "version": "20.04"},
    {"name": "Ubuntu",          "version": "18.04"},   # end-of-life — riskier
    {"name": "Windows Server",  "version": "2022"},
    {"name": "Windows Server",  "version": "2019"},
    {"name": "Windows Server",  "version": "2016"},    # older — riskier
    {"name": "CentOS",          "version": "7"},
    {"name": "Debian",          "version": "11"},
    {"name": "Debian",          "version": "10"},
    {"name": "RHEL",            "version": "8"},
]

SOFTWARE_MAP = {
    "Web Server":      [("nginx", "1.18.0"), ("nginx", "1.24.0"),
                        ("apache2", "2.4.52"), ("apache2", "2.4.57"),
                        ("lighttpd", "1.4.65")],
    "Database Server": [("mysql", "8.0.32"), ("mysql", "8.0.28"), ("mysql", "5.7.41"),
                        ("postgresql", "14.5"), ("postgresql", "15.2"),
                        ("mongodb", "6.0.5"), ("redis", "7.0.11")],
    "Cloud VM":        [("docker", "20.10.7"), ("docker", "24.0.5"),
                        ("containerd", "1.6.4"), ("kubernetes", "1.27.3"),
                        ("ansible", "2.14.0")],
    "API Gateway":     [("nginx", "1.18.0"), ("envoy", "1.25.0"),
                        ("kong", "3.2.0"), ("traefik", "2.9.0")],
    "Firewall":        [("iptables", "1.8.7"), ("ufw", "0.36"),
                        ("pf", "6.7"), ("nftables", "1.0.6")],
}

PORT_MAP = {
    "Web Server":      [80, 443, 8080, 8443],
    "Database Server": [3306, 5432, 1433, 27017, 6379],
    "Cloud VM":        [22, 2222, 8080, 9090, 2376],
    "API Gateway":     [80, 443, 8000, 8080, 9000],
    "Firewall":        [22, 443, 8443],
}

INTERNET_EXPOSED_TYPES = {"Web Server", "API Gateway", "Firewall"}


# ─── EXPANDED CVE POOL ────────────────────────────────────────────────────────
# Key improvement: each software now has CVEs across ALL four categories:
#   A: exploit=True,  patch=False  ← most dangerous, was missing before
#   B: exploit=True,  patch=True
#   C: exploit=False, patch=False  ← zero-day without exploit
#   D: exploit=False, patch=True   ← lowest risk

CVE_POOL = {
    "nginx": [
        # A — exploit + no patch (zero-day scenario)
        {"cve": "CVE-2024-7347",  "severity": "Critical", "cvss_score": 9.8,
         "exploit_available": True,  "patch_available": False,
         "description": "Stack-based buffer overflow in nginx HTTP/3 QUIC implementation allowing remote code execution without authentication."},
        # B — exploit + patch
        {"cve": "CVE-2021-23017", "severity": "Critical", "cvss_score": 9.4,
         "exploit_available": True,  "patch_available": True,
         "description": "Off-by-one error in ngx_resolver allowing remote code execution via crafted DNS response."},
        {"cve": "CVE-2022-41741", "severity": "High",     "cvss_score": 7.8,
         "exploit_available": True,  "patch_available": True,
         "description": "Memory corruption in ngx_http_mp4_module when processing specially crafted MP4 files."},
        {"cve": "CVE-2023-44487", "severity": "High",     "cvss_score": 7.5,
         "exploit_available": True,  "patch_available": True,
         "description": "HTTP/2 Rapid Reset Attack enabling denial of service at scale."},
        # C — no exploit + no patch
        {"cve": "CVE-2024-0567",  "severity": "Medium",   "cvss_score": 5.9,
         "exploit_available": False, "patch_available": False,
         "description": "Information disclosure in nginx stub_status module exposing connection state to unauthenticated users."},
        # D — no exploit + patch available
        {"cve": "CVE-2022-41742", "severity": "Medium",   "cvss_score": 5.3,
         "exploit_available": False, "patch_available": True,
         "description": "Worker process crash via specially crafted MP4 file causing denial of service."},
        {"cve": "CVE-2021-3618",  "severity": "Low",      "cvss_score": 3.7,
         "exploit_available": False, "patch_available": True,
         "description": "ALPACA attack — application layer protocol confusion allowing cross-protocol request forgery."},
    ],

    "apache2": [
        # A
        {"cve": "CVE-2024-38473", "severity": "Critical", "cvss_score": 9.1,
         "exploit_available": True,  "patch_available": False,
         "description": "Encoding confusion in Apache mod_proxy allows request smuggling to backend servers without authentication."},
        # B
        {"cve": "CVE-2021-41773", "severity": "Critical", "cvss_score": 9.8,
         "exploit_available": True,  "patch_available": True,
         "description": "Path traversal and remote code execution in Apache HTTP Server 2.4.49."},
        {"cve": "CVE-2022-31813", "severity": "High",     "cvss_score": 9.8,
         "exploit_available": True,  "patch_available": True,
         "description": "Apache may not forward X-Forwarded-* headers, enabling authentication bypass on backend systems."},
        # C
        {"cve": "CVE-2023-45802", "severity": "Medium",   "cvss_score": 5.9,
         "exploit_available": False, "patch_available": False,
         "description": "HTTP/2 stream memory not reclaimed after RST, leading to gradual memory exhaustion."},
        # D
        {"cve": "CVE-2023-31122", "severity": "Medium",   "cvss_score": 5.3,
         "exploit_available": False, "patch_available": True,
         "description": "Out-of-bounds read in mod_macro with specially crafted configuration."},
        {"cve": "CVE-2022-28615", "severity": "Low",      "cvss_score": 2.5,
         "exploit_available": False, "patch_available": True,
         "description": "Read beyond bounds in ap_strcmp_match."},
    ],

    "mysql": [
        # A
        {"cve": "CVE-2024-20961", "severity": "High",     "cvss_score": 8.0,
         "exploit_available": True,  "patch_available": False,
         "description": "Vulnerability in MySQL Server Optimizer allowing unauthenticated remote denial of service via crafted SQL."},
        # B
        {"cve": "CVE-2023-21980", "severity": "High",     "cvss_score": 7.1,
         "exploit_available": True,  "patch_available": True,
         "description": "MySQL Server optimizer allowing unauthorized data access by authenticated attacker."},
        # C
        {"cve": "CVE-2024-20978", "severity": "Medium",   "cvss_score": 4.9,
         "exploit_available": False, "patch_available": False,
         "description": "MySQL Server InnoDB vulnerability allowing privileged attacker to cause repeated crash."},
        # D
        {"cve": "CVE-2022-21595", "severity": "Medium",   "cvss_score": 4.4,
         "exploit_available": False, "patch_available": True,
         "description": "MySQL Server C API vulnerability allowing denial of service by a privileged attacker."},
        {"cve": "CVE-2023-21977", "severity": "Low",      "cvss_score": 2.7,
         "exploit_available": False, "patch_available": True,
         "description": "MySQL Server optimizer allowing privileged attacker to cause minor availability impact."},
    ],

    "mysql 5.7.41": [   # end-of-life version — more unpatched CVEs
        {"cve": "CVE-2023-22005", "severity": "Critical", "cvss_score": 9.8,
         "exploit_available": True,  "patch_available": False,
         "description": "Critical vulnerability in MySQL 5.7 with no patch available — version is end-of-life."},
        {"cve": "CVE-2023-22008", "severity": "High",     "cvss_score": 7.5,
         "exploit_available": True,  "patch_available": False,
         "description": "High severity MySQL 5.7 vulnerability — no patch for end-of-life version."},
        {"cve": "CVE-2022-21595", "severity": "Medium",   "cvss_score": 4.4,
         "exploit_available": False, "patch_available": False,
         "description": "No patch backported for MySQL 5.7 end-of-life branch."},
    ],

    "postgresql": [
        # A
        {"cve": "CVE-2024-0985",  "severity": "High",     "cvss_score": 8.0,
         "exploit_available": True,  "patch_available": False,
         "description": "Late privilege drop in REFRESH MATERIALIZED VIEW CONCURRENTLY allowing privilege escalation."},
        # B
        {"cve": "CVE-2022-1552",  "severity": "High",     "cvss_score": 8.8,
         "exploit_available": True,  "patch_available": True,
         "description": "Autovacuum omits security restricted operations, enabling privilege escalation."},
        # C
        {"cve": "CVE-2024-4317",  "severity": "Medium",   "cvss_score": 3.1,
         "exploit_available": False, "patch_available": False,
         "description": "Visibility restriction on pg_stats_ext and pg_stats_ext_exprs insufficient for non-privileged users."},
        # D
        {"cve": "CVE-2023-2454",  "severity": "High",     "cvss_score": 7.2,
         "exploit_available": False, "patch_available": True,
         "description": "CREATE SCHEMA allows superusers to bypass security policies in pg_catalog."},
        {"cve": "CVE-2022-41862", "severity": "Low",      "cvss_score": 3.7,
         "exploit_available": False, "patch_available": True,
         "description": "libpq may leak memory contents to server in error messages."},
    ],

    "docker": [
        # A
        {"cve": "CVE-2024-21626", "severity": "Critical", "cvss_score": 9.0,
         "exploit_available": True,  "patch_available": False,
         "description": "Container escape via runc process.cwd using leaked file descriptors — no patch for affected versions."},
        # B
        {"cve": "CVE-2022-0847",  "severity": "High",     "cvss_score": 7.8,
         "exploit_available": True,  "patch_available": True,
         "description": "Dirty Pipe — Linux kernel flaw allowing overwrite of read-only files in container environments."},
        {"cve": "CVE-2023-28840", "severity": "High",     "cvss_score": 8.7,
         "exploit_available": False, "patch_available": True,
         "description": "Insufficient encryption of overlay network traffic in Docker Swarm mode."},
        # C
        {"cve": "CVE-2024-23651", "severity": "High",     "cvss_score": 7.4,
         "exploit_available": False, "patch_available": False,
         "description": "Race condition in mount cache poisoning allowing arbitrary file read from host filesystem."},
        # D
        {"cve": "CVE-2023-28841", "severity": "Medium",   "cvss_score": 6.8,
         "exploit_available": False, "patch_available": True,
         "description": "Encrypted overlay network traffic not fully validated in Docker Swarm."},
    ],

    "containerd": [
        # A
        {"cve": "CVE-2023-25173", "severity": "High",     "cvss_score": 7.8,
         "exploit_available": True,  "patch_available": False,
         "description": "Supplementary groups not set up properly, allowing container escape via supplementary group access."},
        # B
        {"cve": "CVE-2022-23648", "severity": "High",     "cvss_score": 7.5,
         "exploit_available": True,  "patch_available": True,
         "description": "containerd allows read access to arbitrary host files via specially crafted image configurations."},
        # D
        {"cve": "CVE-2023-25153", "severity": "Medium",   "cvss_score": 5.5,
         "exploit_available": False, "patch_available": True,
         "description": "OCI image importer memory exhaustion via malicious image manifest."},
    ],

    "kubernetes": [
        # A
        {"cve": "CVE-2024-0793",  "severity": "High",     "cvss_score": 7.5,
         "exploit_available": True,  "patch_available": False,
         "description": "kube-controller-manager crash via malformed CEL admission webhook expression."},
        # B
        {"cve": "CVE-2023-5528",  "severity": "High",     "cvss_score": 8.8,
         "exploit_available": True,  "patch_available": True,
         "description": "Insufficient input sanitization in in-tree storage plugin on Windows nodes allowing privilege escalation."},
        # C
        {"cve": "CVE-2024-3177",  "severity": "Medium",   "cvss_score": 4.3,
         "exploit_available": False, "patch_available": False,
         "description": "Users may launch containers that bypass policy enforcement via subPath volume mount."},
        # D
        {"cve": "CVE-2023-2727",  "severity": "Medium",   "cvss_score": 6.5,
         "exploit_available": False, "patch_available": True,
         "description": "Bypassing policies imposed by the ImagePolicyWebhook admission plugin."},
    ],

    "envoy": [
        # A
        {"cve": "CVE-2024-34362", "severity": "High",     "cvss_score": 7.5,
         "exploit_available": True,  "patch_available": False,
         "description": "Use-after-free in Envoy's HTTP/2 codec causing remote denial of service."},
        # B
        {"cve": "CVE-2023-35943", "severity": "High",     "cvss_score": 8.3,
         "exploit_available": False, "patch_available": True,
         "description": "CORS filter segfault on wildcard origins with empty request origins."},
        # D
        {"cve": "CVE-2023-27487", "severity": "Medium",   "cvss_score": 5.4,
         "exploit_available": False, "patch_available": True,
         "description": "Client may fake the header x-envoy-original-dst-host."},
    ],

    "kong": [
        # A
        {"cve": "CVE-2024-32964", "severity": "Critical", "cvss_score": 9.8,
         "exploit_available": True,  "patch_available": False,
         "description": "Unauthenticated remote code execution in Kong Admin API when improperly exposed."},
        # B
        {"cve": "CVE-2022-35796", "severity": "Critical", "cvss_score": 9.0,
         "exploit_available": True,  "patch_available": True,
         "description": "Elevation of privilege in Kong Gateway due to improper request handling."},
        # D
        {"cve": "CVE-2023-33364", "severity": "Medium",   "cvss_score": 5.4,
         "exploit_available": False, "patch_available": True,
         "description": "Open redirect vulnerability in Kong Manager allowing phishing attacks."},
    ],

    "traefik": [
        # B
        {"cve": "CVE-2022-46153", "severity": "Medium",   "cvss_score": 6.5,
         "exploit_available": True,  "patch_available": True,
         "description": "Authorization bypass vulnerability in Traefik route rules."},
        # C
        {"cve": "CVE-2024-28869", "severity": "Medium",   "cvss_score": 5.3,
         "exploit_available": False, "patch_available": False,
         "description": "Traefik HTTP/3 early data requests bypass HTTPS redirect middleware."},
        # D
        {"cve": "CVE-2023-29013", "severity": "Medium",   "cvss_score": 5.3,
         "exploit_available": False, "patch_available": True,
         "description": "Header injection via HTTP/1.1 headers in Traefik causing request smuggling."},
    ],

    "mongodb": [
        # A
        {"cve": "CVE-2024-1351",  "severity": "High",     "cvss_score": 7.5,
         "exploit_available": True,  "patch_available": False,
         "description": "Incorrect validation in MongoDB Server allows unauthorized data access via crafted BSON."},
        # B
        {"cve": "CVE-2021-32040", "severity": "High",     "cvss_score": 7.5,
         "exploit_available": False, "patch_available": True,
         "description": "Insufficient validation of input on aggregation pipeline stage allowing DoS."},
        # D
        {"cve": "CVE-2022-24272", "severity": "Medium",   "cvss_score": 4.3,
         "exploit_available": False, "patch_available": True,
         "description": "Authenticated user can cause unbounded memory growth via aggregation pipeline."},
    ],

    "redis": [
        # A
        {"cve": "CVE-2023-41056", "severity": "High",     "cvss_score": 8.1,
         "exploit_available": True,  "patch_available": False,
         "description": "Integer overflow in Redis bulk string length handling allowing heap overflow."},
        # B
        {"cve": "CVE-2022-0543",  "severity": "Critical", "cvss_score": 10.0,
         "exploit_available": True,  "patch_available": True,
         "description": "Lua sandbox escape in Redis allowing arbitrary code execution on the host."},
        # D
        {"cve": "CVE-2023-28425", "severity": "Medium",   "cvss_score": 5.5,
         "exploit_available": False, "patch_available": True,
         "description": "LMPOP/ZMPOP commands can trigger assertion failure causing server crash."},
    ],

    "iptables": [
        # C
        {"cve": "CVE-2021-29424", "severity": "Medium",   "cvss_score": 5.3,
         "exploit_available": False, "patch_available": False,
         "description": "iptables legacy mode uses incorrect table when rules for ip6tables exist."},
        # D
        {"cve": "CVE-2012-2663",  "severity": "Low",      "cvss_score": 3.5,
         "exploit_available": False, "patch_available": True,
         "description": "Incomplete blacklist allows traffic bypass via crafted packets."},
    ],

    "ufw": [
        # D
        {"cve": "CVE-2019-7113",  "severity": "Low",      "cvss_score": 3.1,
         "exploit_available": False, "patch_available": True,
         "description": "UFW before 0.36 allows local users to bypass firewall rules via IPv6 misconfiguration."},
    ],

    "pf": [
        # A — still unpatched
        {"cve": "CVE-2021-29629", "severity": "High",     "cvss_score": 7.5,
         "exploit_available": False, "patch_available": False,
         "description": "pf in FreeBSD allows denial of service via malformed ICMP or ICMPv6 packets."},
    ],

    "nftables": [
        # A
        {"cve": "CVE-2023-6111",  "severity": "High",     "cvss_score": 7.8,
         "exploit_available": True,  "patch_available": False,
         "description": "Use-after-free in nftables netfilter subsystem allowing local privilege escalation."},
        # D
        {"cve": "CVE-2022-34918", "severity": "High",     "cvss_score": 7.8,
         "exploit_available": False, "patch_available": True,
         "description": "Type confusion in nftables allowing local attacker to escalate privileges."},
    ],

    "lighttpd": [
        # A
        {"cve": "CVE-2022-22707", "severity": "High",     "cvss_score": 7.0,
         "exploit_available": True,  "patch_available": False,
         "description": "Use-after-free in lighttpd connection handling allowing remote code execution."},
        # D
        {"cve": "CVE-2019-11072", "severity": "Medium",   "cvss_score": 4.8,
         "exploit_available": False, "patch_available": True,
         "description": "Heap-based buffer overflow in lighttpd mod_auth."},
    ],

    "ansible": [
        # C
        {"cve": "CVE-2024-0217",  "severity": "Low",      "cvss_score": 3.3,
         "exploit_available": False, "patch_available": False,
         "description": "Ansible-core writes temporary files with insecure permissions allowing local information disclosure."},
        # D
        {"cve": "CVE-2023-5764",  "severity": "Medium",   "cvss_score": 5.0,
         "exploit_available": False, "patch_available": True,
         "description": "Template injection in Ansible leading to information disclosure."},
    ],
}


# ─── HELPER FUNCTIONS ─────────────────────────────────────────────────────────

def random_ip():
    return (f"{random.randint(10,192)}."
            f"{random.randint(0,255)}."
            f"{random.randint(0,255)}."
            f"{random.randint(1,254)}")

def random_date(days_back=180):
    """Return a date string between today and days_back days ago."""
    return (datetime.now() - timedelta(days=random.randint(1, days_back))).strftime("%Y-%m-%d")

def get_open_ports(asset_type):
    pool = PORT_MAP.get(asset_type, [22, 80, 443])
    return random.sample(pool, k=min(random.randint(1, 3), len(pool)))

def get_software(asset_type, tier):
    """Pick software — lower tiers get older/riskier versions."""
    options = SOFTWARE_MAP.get(asset_type, [("unknown", "1.0.0")])
    name, version = random.choice(options)
    return {"name": name, "version": version}

def get_cves_for_tier(software_name, tier):
    """
    Select CVEs based on risk tier.

    Tier logic:
      critical → must include at least one category-A CVE (exploit + no patch)
      high     → likely includes exploitable CVEs, mix of patched/unpatched
      medium   → mostly patched CVEs, maybe one unpatched without exploit
      low      → 0-1 low-severity CVEs, all patched
    """
    pool = CVE_POOL.get(software_name, [])
    if not pool:
        return []

    # Split pool into categories
    cat_a = [v for v in pool if     v["exploit_available"] and not v["patch_available"]]
    cat_b = [v for v in pool if     v["exploit_available"] and     v["patch_available"]]
    cat_c = [v for v in pool if not v["exploit_available"] and not v["patch_available"]]
    cat_d = [v for v in pool if not v["exploit_available"] and     v["patch_available"]]

    if tier == "critical":
        selected = []
        # Always include a cat-A CVE if available
        if cat_a:
            selected.append(random.choice(cat_a))
        # Add 1-2 more from B or C
        extras = random.sample(cat_b + cat_c, k=min(random.randint(1, 2), len(cat_b + cat_c)))
        selected.extend(extras)
        return selected if selected else random.sample(pool, k=min(2, len(pool)))

    elif tier == "high":
        selected = []
        # 60% chance of a cat-A CVE
        if cat_a and random.random() < 0.6:
            selected.append(random.choice(cat_a))
        # Fill with B CVEs
        b_count = random.randint(1, 2)
        selected.extend(random.sample(cat_b, k=min(b_count, len(cat_b))))
        return selected if selected else random.sample(pool, k=min(2, len(pool)))

    elif tier == "medium":
        selected = []
        # 20% chance of a cat-A, mostly C and D
        if cat_a and random.random() < 0.2:
            selected.append(random.choice(cat_a))
        elif cat_c:
            selected.append(random.choice(cat_c))
        if cat_d:
            selected.extend(random.sample(cat_d, k=min(1, len(cat_d))))
        return selected if selected else random.sample(pool, k=min(1, len(pool)))

    else:  # low
        if not cat_d:
            return []
        # 50% chance of no CVEs at all (clean asset)
        if random.random() < 0.5:
            return []
        return [random.choice(cat_d)]


# ─── RISK SCORE FORMULA ───────────────────────────────────────────────────────
# Rewritten to align with all 13 ML features in features.py
# Each component maps directly to a feature the model learns from

def compute_risk_score(asset):
    """
    Composite risk score (0-100) aligned with features.py:

    Component                  Weight   Feature(s)
    ─────────────────────────────────────────────
    Max CVSS score             25%      cvss_score, max_cvss
    Exploit availability       20%      exploit_available
    Unpatched exploit count    20%      exploit_unpatched_count
    Internet exposure          15%      internet_exposed
    Criticality                10%      criticality_encoded, is_high_criticality
    Environment                 5%      environment_encoded
    Patch status                3%      patch_available
    Scan staleness              2%      days_since_scan

    Calibrated so that:
      Critical profile (high cvss + exploit + exposed + prod) → ~80-95
      High profile     (exploit or exposed, some unpatched)   → ~60-79
      Medium profile   (some CVEs, mostly patched, internal)  → ~40-59
      Low profile      (0-1 low CVEs, patched, dev)           → ~10-39
    """
    vulns = asset.get("vulnerabilities", [])

    # CVSS component (0-25)
    cvss_scores = [v.get("cvss_score") or 0.0 for v in vulns]
    max_cvss    = max(cvss_scores) if cvss_scores else 0.0
    cvss_component = (max_cvss / 10.0) * 25

    # Exploit component (0 or 20)
    has_exploit = any(v.get("exploit_available", False) for v in vulns)
    exploit_component = 20 if has_exploit else 0

    # Unpatched exploit component (0-20) — key new signal
    exploit_unpatched = sum(
        1 for v in vulns
        if v.get("exploit_available", False) and not v.get("patch_available", True)
    )
    unpatched_exploit_component = min(exploit_unpatched * 10, 20)

    # Exposure component (0 or 15)
    exposure_component = 15 if asset.get("internet_exposed") else 0

    # Criticality component (0-10)
    crit_map = {"Low": 0, "Medium": 5, "High": 10}
    crit_component = crit_map.get(asset.get("criticality", "Low"), 0)

    # Environment component (0-5)
    env_map = {"Development": 0, "Staging": 2, "Production": 5}
    env_component = env_map.get(asset.get("environment", "Development"), 0)

    # Patch status (0 or 3) — penalise any unpatched CVEs
    all_patched = all(v.get("patch_available", True) for v in vulns) if vulns else True
    patch_component = 0 if all_patched else 3

    # Scan staleness (0-2)
    last_scan = asset.get("last_scan_date", "")
    try:
        last_scan_date  = datetime.strptime(last_scan[:10], "%Y-%m-%d")
        days_since_scan = (datetime.now() - last_scan_date).days
    except Exception:
        days_since_scan = 90
    stale_component = min(days_since_scan / 90.0, 1.0) * 2

    raw = (cvss_component + exploit_component + unpatched_exploit_component
           + exposure_component + crit_component + env_component
           + patch_component + stale_component)

    # Calibrated noise (±4 points) — realistic variation without destroying tier separation
    noise = random.uniform(-4.0, 4.0)
    return round(min(max(raw + noise, 0.0), 100.0), 1)


# ─── TIER SCORE BANDS ────────────────────────────────────────────────────────
# Clamp raw score to per-tier band so distribution matches targets.
# Raw formula still runs first — signal is real, band just enforces range.
TIER_BANDS = {
    "critical": (81, 100),   # train.py Critical threshold is >=80
    "high":     (61,  79),   # train.py High is 60-79
    "medium":   (41,  59),   # train.py Medium is 40-59
    "low":      ( 5,  39),   # floor at 5 to avoid degenerate 0-scores
}

def compute_risk_score_tiered(asset, tier):
    floor, ceiling = TIER_BANDS.get(tier, (0, 100))
    raw = compute_risk_score(asset)
    return round(min(max(raw, float(floor)), float(ceiling)), 1)


# ─── TIER PROFILES ────────────────────────────────────────────────────────────
# Each tier specifies the environment/criticality/exposure constraints
# that make a realistic asset at that risk level

TIER_PROFILES = {
    "critical": {
        "environments":   ["Production"],
        "criticalities":  ["High"],
        "exposed_chance": 0.85,   # 85% internet exposed
        "scan_days_back": 90,     # often stale scans
        "orphan_chance":  0.15,
    },
    "high": {
        "environments":   ["Production", "Production", "Staging"],
        "criticalities":  ["High", "High", "Medium"],
        "exposed_chance": 0.50,
        "scan_days_back": 60,
        "orphan_chance":  0.10,
    },
    "medium": {
        "environments":   ["Production", "Staging", "Staging", "Development"],
        "criticalities":  ["Medium", "Medium", "Low"],
        "exposed_chance": 0.20,
        "scan_days_back": 30,
        "orphan_chance":  0.08,
    },
    "low": {
        "environments":   ["Development", "Development", "Staging"],
        "criticalities":  ["Low", "Low", "Medium"],
        "exposed_chance": 0.05,
        "scan_days_back": 14,
        "orphan_chance":  0.05,
    },
}

# Target distribution — 300 total
TIER_COUNTS = {
    "critical": 45,   # 15%
    "high":     75,   # 25%
    "medium":  105,   # 35%
    "low":      75,   # 25%
}


# ─── ASSET GENERATION ─────────────────────────────────────────────────────────

def generate_asset(asset_id: str, tier: str) -> dict:
    profile     = TIER_PROFILES[tier]
    asset_type  = random.choice(ASSET_TYPES)
    environment = random.choice(profile["environments"])
    criticality = random.choice(profile["criticalities"])
    os_info     = random.choice(OPERATING_SYSTEMS)
    software    = get_software(asset_type, tier)

    # Internet exposure
    if asset_type in INTERNET_EXPOSED_TYPES:
        internet_exposed = random.random() < profile["exposed_chance"]
    else:
        # Non-exposed types still have a small chance for realism
        internet_exposed = random.random() < (profile["exposed_chance"] * 0.2)

    # Scan date — critical/high assets are often scanned less frequently (ironic but realistic)
    last_scan_date = random_date(days_back=profile["scan_days_back"])

    # Owner
    if random.random() < profile["orphan_chance"]:
        owner = {"team": None, "email": None, "status": "orphan"}
    else:
        team  = random.choice(TEAMS)
        owner = {"team": team, "email": TEAM_EMAILS[team], "status": "assigned"}

    # CVEs
    vulns = get_cves_for_tier(software["name"], tier)

    asset = {
        "asset_id":         asset_id,
        "asset_type":       asset_type,
        "environment":      environment,
        "criticality":      criticality,
        "ip_address":       random_ip(),
        "domain":           (
            f"{asset_id.lower()}.company.com"
            if internet_exposed
            else f"{asset_id.lower()}.internal.company.com"
        ),
        "internet_exposed": internet_exposed,
        "os": {
            "name":    os_info["name"],
            "version": os_info["version"],
        },
        "software":        software,
        "open_ports":      get_open_ports(asset_type),
        "owner":           owner,
        "last_scan_date":  last_scan_date,
        "vulnerabilities": vulns,
    }

    asset["risk_score"] = compute_risk_score_tiered(asset, tier)
    return asset


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    assets   = []
    asset_id = 1000

    for tier, count in TIER_COUNTS.items():
        for _ in range(count):
            asset = generate_asset(f"ASSET-{asset_id}", tier)
            assets.append(asset)
            asset_id += 1

    # Shuffle so tiers aren't in blocks in the JSON / DB
    random.shuffle(assets)

    # ── Save ──────────────────────────────────────────────────────────────────
    os.makedirs("data", exist_ok=True)
    with open("data/assets_v2.json", "w") as f:
        json.dump(assets, f, indent=2)

    # ── Stats ─────────────────────────────────────────────────────────────────
    total    = len(assets)
    orphans  = sum(1 for a in assets if a["owner"]["status"] == "orphan")
    exposed  = sum(1 for a in assets if a["internet_exposed"])
    exploit_unpatched = sum(
        1 for a in assets
        if any(v["exploit_available"] and not v["patch_available"]
               for v in a["vulnerabilities"])
    )

    scores = [a["risk_score"] for a in assets]
    critical_count = sum(1 for s in scores if s >= 80)
    high_count     = sum(1 for s in scores if 60 <= s < 80)
    medium_count   = sum(1 for s in scores if 40 <= s < 60)
    low_count      = sum(1 for s in scores if s < 40)

    print(f"Generated {total} assets → data/assets_v2.json")
    print()
    print("Risk distribution:")
    print(f"  Critical (>=80) : {critical_count:>4}  ({critical_count/total*100:.1f}%)")
    print(f"  High    (60-79) : {high_count:>4}  ({high_count/total*100:.1f}%)")
    print(f"  Medium  (40-59) : {medium_count:>4}  ({medium_count/total*100:.1f}%)")
    print(f"  Low     (<40)   : {low_count:>4}  ({low_count/total*100:.1f}%)")
    print()
    print("Dataset signals:")
    print(f"  Orphan assets              : {orphans}")
    print(f"  Internet-exposed           : {exposed}")
    print(f"  Assets with exploit+no patch: {exploit_unpatched}")
    print()
    print("Score stats:")
    print(f"  Min : {min(scores):.1f}")
    print(f"  Max : {max(scores):.1f}")
    print(f"  Mean: {sum(scores)/len(scores):.1f}")
    print()
    print("Next steps:")
    print("  1. python migrate.py      ← load into PostgreSQL")
    print("  2. python ingest.py       ← sync to ChromaDB")
    print("  3. python ml/train.py     ← retrain ML models")


if __name__ == "__main__":
    main()