#!/usr/bin/env python3
"""
parse_cvrf.py -- normalise a Microsoft CVRF (Common Vulnerability Reporting
Framework) security update document into per-CVE records, assign the
reported-facts buckets, and raise data-quality flags.

This script performs PARSING and BUCKETING ONLY. Every value it emits is
either copied from the source document or derived from it by a mechanical
rule. It makes no severity judgements and applies no analyst model.

Standard library only. No third-party dependencies. Runs anywhere Python 3.8+
runs, inside an LLM code sandbox or on a local machine.

Usage:
    python3 parse_cvrf.py 2026-Sep.xml                 # summary to stdout
    python3 parse_cvrf.py 2026-Sep.xml --json out.json # full records to file
    python3 parse_cvrf.py 2026-Sep.xml --verify        # upload check only

Output JSON structure:
    {
      "document":  {...}                 document-level metadata
      "verify":    {...}                 upload verification results
      "counts":    {...}                 bucket counts
      "flags":     {flag_name: [cve...]} data-quality flags
      "records":   [ {...}, ... ]        one normalised record per CVE
    }
"""

import argparse
import calendar
import datetime
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict

NS = {
    "cvrf": "http://www.icasi.org/CVRF/schema/cvrf/1.1",
    "vuln": "http://www.icasi.org/CVRF/schema/vuln/1.1",
    "prod": "http://www.icasi.org/CVRF/schema/prod/1.1",
}

# ---------------------------------------------------------------------------
# Pass-through product families.
#
# Bucket 01 removes vulnerabilities Microsoft is relaying from an upstream
# vendor rather than fixing itself. The test is deliberately conservative:
# an entry is pass-through only if BOTH
#   (a) the assigning CNA is not Microsoft, AND
#   (b) every affected product belongs to one of these families.
# An entry with a non-Microsoft CNA that also affects a Microsoft-shipped
# product (e.g. an OpenSSL bug that also lands in Visual Studio) is RETAINED,
# because a customer does have to patch the Microsoft product.
# ---------------------------------------------------------------------------
PASSTHROUGH_FAMILIES = {
    "chromium_edge": lambda n: n == "Microsoft Edge (Chromium-based)",
    "azure_linux": lambda n: bool(
        re.search(r"azure linux|mariner", n, re.I)
        or re.match(r"^(cbl|azl)", n, re.I)
    ),
}

# Products distributed through a mobile app store rather than Windows Update.
MOBILE_RE = re.compile(r"\bfor (Android|iOS)\b|iOS and iPadOS", re.I)

# Component tags treated as a separate review track (see SET_ASIDES below).
VSCODE_RE = re.compile(r"Visual Studio Code", re.I)

# ---------------------------------------------------------------------------
# CWE classification sets, version 2026-09-11.
#
# INFORMED BY MITRE's categories, which were consulted to catch classes that
# had never happened to appear in the data:
#   CWE-1399  Comprehensive Categorization: Memory Safety
#   CWE-1401  Comprehensive Categorization: Concurrency
# Both category IDs are PROHIBITED for mapping real vulnerabilities -- use the
# member weaknesses, never the category ID.
#
# THESE LISTS DO NOT DECIDE THE CLASSIFICATION. They resolve the obvious cases
# so an analyst does not have to. Two things override them, and neither can be
# automated:
#   1. The published CWE is often contradicted by the same record's FAQ,
#      description or CVSS vector. Classify on what the record as a whole says.
#   2. The governing test is whether exploitation would require overcoming the
#      platform's memory-safety mitigations (ASLR, DEP, CFG, ACG, heap
#      hardening). If it would not, the entry belongs in Half 1 whatever list
#      its CWE appears on.
# See SKILL.md for the full reasoning and the documented departures.
#
# These sets are used ONLY by the analyst-classification helper; nothing in the
# reported-facts bucketing depends on them.
# ---------------------------------------------------------------------------
MEMORY_SAFETY_CWES = {
    "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-123", "CWE-124",
    "CWE-125", "CWE-126", "CWE-127", "CWE-129", "CWE-131", "CWE-170",
    "CWE-190", "CWE-191", "CWE-197", "CWE-415", "CWE-416", "CWE-466",
    "CWE-476", "CWE-562", "CWE-587", "CWE-590", "CWE-680", "CWE-681",
    "CWE-690", "CWE-761", "CWE-762", "CWE-763", "CWE-786", "CWE-787",
    "CWE-788", "CWE-805", "CWE-806", "CWE-822", "CWE-823", "CWE-824",
    "CWE-825", "CWE-908",
}

CONCURRENCY_CWES = {
    "CWE-362", "CWE-363", "CWE-364", "CWE-366", "CWE-367", "CWE-368",
    "CWE-412", "CWE-413", "CWE-414", "CWE-432", "CWE-567", "CWE-591",
    "CWE-609", "CWE-663", "CWE-667", "CWE-689", "CWE-764", "CWE-765",
    "CWE-820", "CWE-821", "CWE-828", "CWE-831", "CWE-832", "CWE-833",
    "CWE-1223",
}

CWE_SET_VERSION = "2026-09-11"

# ---------------------------------------------------------------------------
# Watchlist for "Server Products & Network-Reachable Components of Established
# Interest" (SKILL.md Part 3, sublist 2).
#
# ANALYST LAYER. This is a judgement about what usually matters, not a fact
# about any release. Matched as case-insensitive SUBSTRINGS against the
# component Tag, because Microsoft fragments functional areas across many tag
# names (DNS appears as both "Windows DNS" and "Role: DNS Server"; remote
# access spans five tags). Exact matching silently misses half the hits.
#
# The list will always be incomplete -- Microsoft invents component names
# constantly -- which is why entries meeting every numeric condition but
# matching nothing here must still be reported, as a residual list.
# ---------------------------------------------------------------------------
WATCHLIST = {
    "Identity & authentication": [
        "Active Directory", "AD CS", "AD FS", "Kerberos",
        "Key Distribution Center", "lsasrv", "Local Security Authority",
        "Netlogon", "LDAP", "Credential Guard", "Credential Providers",
        "Smart Card", "Online Certificate Status", "Authentication Methods",
        "Entra", "Azure Active Directory", "Digest Authentication",
        "Host Guardian", "Winlogon", "Microsoft Account", "MSAL",
        "Windows Hello",
    ],
    "Mail & collaboration servers": [
        "Exchange Server", "SharePoint", "Skype for Business",
        "Microsoft Teams",
    ],
    "Database & data platform": [
        "SQL Server", "Azure SQL", "Cosmos DB", "OLE DB", "Dynamics",
        "Power BI", "Microsoft Fabric",
    ],
    "Core network services": [
        "DNS", "DHCP Server", "DHCP Client", "TCP/IP", "Schannel", "QUIC",
        "HTTP.sys", "HTTP Protocol Stack", "HTTP Print Provider",
        "Message Queuing", "RPC Runtime", "RPC API", "Winsock",
        "Ancillary Function Driver", "IP Helper",
        "Internet Connection Sharing", "Network Address Translation",
        "NDIS", "Link Layer Topology",
    ],
    "Remote access & VPN": [
        "Routing and Remote Access", "RRAS", "Secure Socket Tunneling",
        "SSTP", "IKE Extension", "Remote Access Connection Manager",
        "Remote Access API", "Remote Desktop", "RDP Client",
    ],
    "File & storage services": [
        "SMB Server", "SMB Client", "Network File System", "NFS", "iSCSI",
        "Distributed File System", "DFS", "WebClient", "Work Folder",
        "Failover Cluster", "Storage Spaces", "BranchCache",
    ],
    "Management & deployment": [
        "Deployment Services", "Windows Update Stack", "Windows Installer",
        "Modern Device Management", "Management Instrumentation",
        "Management Services", "Autopilot", "Group Policy",
        "Remote Registry", "IP Address Management", "IPAM",
        "Print Spooler", "Fax Service", "WSUS",
    ],
    "Virtualization & isolation": [
        "Hyper-V", "Secure Kernel Mode", "VBS Enclave",
        "Virtualization-Based Security", "Virtual Trusted Platform Module",
        "Device Health Attestation", "Azure Attestation",
        "Container Isolation",
    ],
    "Developer & automation platforms": [
        "Visual Studio", ".NET", "ASP.NET", "PowerShell", "Azure CLI",
        "Azure Arc", "Power Automate", "Copilot Studio", "HPC Pack",
        "Azure CycleCloud", "Azure HDInsight", "Azure Kubernetes",
    ],
    "Cryptography & boot integrity": [
        "Secure Boot", "Boot Manager", "BitLocker", "TPM", "Key Guard",
    ],
    "Remote shell & transfer": ["OpenSSH", "Telnet", "FTP"],
}

# FAQ phrases that narrate a preview/reading-pane trigger. Needed because the
# Preview Pane FAQ field is sometimes wrong -- one release carried a 9.8
# Outlook RCE whose Preview Pane answer was "No" while its exploitation FAQ
# described exactly a reading-pane trigger.
READING_PANE_NARRATION = re.compile(
    r"rendered in the preview pane"
    r"|viewing the message in the .{0,25}Reading Pane"
    r"|preview(ed)? in the Reading Pane",
    re.I,
)

IMPACT_SUFFIXES = [
    "Remote Code Execution",
    "Elevation of Privilege",
    "Information Disclosure",
    "Denial of Service",
    "Security Feature Bypass",
    "Spoofing",
    "Tampering",
]


def clean(s):
    """Strip embedded markup and collapse whitespace."""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s or "")).strip()


def patch_tuesday(year, month):
    """Second Tuesday of the given month."""
    tuesdays = [
        d
        for d in calendar.Calendar().itermonthdates(year, month)
        if d.month == month and d.weekday() == calendar.TUESDAY
    ]
    return tuesdays[1]


def current_release_slug(today=None):
    """
    Return (year, month, 'YYYY-Mon') for the release a user most likely wants.

    On or after this month's Patch Tuesday -> this month.
    Before it -> last month, whose data is the most recent published.
    """
    today = today or datetime.date.today()
    pt = patch_tuesday(today.year, today.month)
    if today >= pt:
        y, m = today.year, today.month
    else:
        y, m = (today.year, today.month - 1) if today.month > 1 else (today.year - 1, 12)
    return y, m, "%d-%s" % (y, calendar.month_abbr[m])


def cvrf_url(slug):
    return "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/" + slug


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def product_map(root):
    pt = root.find("prod:ProductTree", NS)
    if pt is None:
        return {}
    tag = "{%s}FullProductName" % NS["prod"]
    return {f.get("ProductID"): f.text for f in pt.iter(tag)}


def parse_document(root):
    title_el = root.find("cvrf:DocumentTitle", NS)
    dt = root.find("cvrf:DocumentTracking", NS)
    out = {"title": clean(title_el.text) if title_el is not None else None}
    for field in ("InitialReleaseDate", "CurrentReleaseDate"):
        el = dt.find("cvrf:%s" % field, NS) if dt is not None else None
        out[field] = el.text if el is not None else None
    return out


def parse_vuln(v, pm):
    """Normalise one Vulnerability element into a flat record."""
    cve_el = v.find("vuln:CVE", NS)
    cve = cve_el.text if cve_el is not None else None

    title_el = v.find("vuln:Title", NS)
    title = clean(title_el.text) if title_el is not None else ""

    cwe_el = v.find("vuln:CWE", NS)
    cwe_id = cwe_el.get("ID") if cwe_el is not None else None
    cwe_name = clean(cwe_el.text) if cwe_el is not None else None

    # Threat elements repeat once per affected ProductID. Deduplicate on read
    # so every consumer downstream sees one value per threat type.
    impacts, severities, exploit_status = set(), set(), None
    for th in v.findall("vuln:Threats/vuln:Threat", NS):
        d = th.find("vuln:Description", NS)
        if d is None or not d.text:
            continue
        t = th.get("Type")
        if t == "Impact":
            impacts.add(d.text)
        elif t == "Severity":
            severities.add(d.text)
        elif t == "Exploit Status":
            exploit_status = d.text

    # ScoreSets repeat per product too. Keep the distinct ones.
    scoresets = set()
    for ss in v.findall("vuln:CVSSScoreSets/vuln:ScoreSet", NS):
        base = ss.find("vuln:BaseScore", NS)
        temp = ss.find("vuln:TemporalScore", NS)
        vec = ss.find("vuln:Vector", NS)
        scoresets.add(
            (
                base.text if base is not None else None,
                temp.text if temp is not None else None,
                vec.text if vec is not None else None,
            )
        )
    scoresets = sorted(scoresets)

    pids = set()
    for st in v.findall("vuln:ProductStatuses/vuln:Status", NS):
        for p in st.findall("vuln:ProductID", NS):
            pids.add(p.text)
    products = sorted({pm.get(p, "[unmapped:%s]" % p) for p in pids})

    notes = {"Description": None, "Tag": None, "CNA": None,
             "CustomerActionRequired": None, "FAQ": []}
    for n in v.findall("vuln:Notes/vuln:Note", NS):
        ntype, ntitle, body = n.get("Type"), n.get("Title"), clean(n.text)
        if ntype == "Description" or ntitle == "Description":
            notes["Description"] = body
        elif ntype == "Tag":
            notes["Tag"] = body
        elif ntype == "CNA":
            notes["CNA"] = body
        elif ntitle == "Customer Action Required":
            notes["CustomerActionRequired"] = body
        elif ntype == "FAQ":
            notes["FAQ"].append(body)

    acks = [
        clean(a.text)
        for a in v.findall("vuln:Acknowledgments/vuln:Acknowledgment/vuln:Name", NS)
        if a.text
    ]

    revisions = []
    for rv in v.findall("vuln:RevisionHistory/vuln:Revision", NS):
        num = rv.find("cvrf:Number", NS)
        dt = rv.find("cvrf:Date", NS)
        revisions.append(
            {"number": num.text if num is not None else None,
             "date": dt.text if dt is not None else None}
        )

    # Derived CVSS fields, from the first distinct scoreset.
    base_score = vector = None
    av = pr = ui = sc = ac = None
    if scoresets and scoresets[0][2]:
        base_score = float(scoresets[0][0]) if scoresets[0][0] else None
        vector = scoresets[0][2]
        for key, name in (("AV", "av"), ("PR", "pr"), ("UI", "ui"), ("AC", "ac")):
            m = re.search(r"\b%s:([A-Z])" % key, vector)
            if m:
                locals()  # no-op; explicit assignment below for clarity
        av = (re.search(r"\bAV:([A-Z])", vector) or [None, None])[1]
        pr = (re.search(r"\bPR:([A-Z])", vector) or [None, None])[1]
        ui = (re.search(r"\bUI:([A-Z])", vector) or [None, None])[1]
        ac = (re.search(r"\bAC:([A-Z])", vector) or [None, None])[1]
        sc = (re.search(r"/S:([A-Z])", vector) or [None, None])[1]

    severity = (
        "Critical" if "Critical" in severities
        else "Important" if "Important" in severities
        else "Moderate" if "Moderate" in severities
        else "Low" if "Low" in severities
        else None
    )

    exploited = disclosed = None
    if exploit_status:
        exploited = "Exploited:Yes" in exploit_status
        disclosed = "Publicly Disclosed:Yes" in exploit_status

    return {
        "cve": cve,
        "title": title,
        "component": notes["Tag"],
        "cwe_id": cwe_id,
        "cwe_name": cwe_name,
        "impacts": sorted(impacts),
        "severity": severity,
        "severities_raw": sorted(severities),
        "exploit_status": exploit_status,
        "exploited": exploited,
        "publicly_disclosed": disclosed,
        "base_score": base_score,
        "vector": vector,
        "av": av, "ac": ac, "pr": pr, "ui": ui, "scope": sc,
        "scoreset_count": len(scoresets),
        "products": products,
        "product_count": len(products),
        "cna": notes["CNA"],
        "customer_action_required": notes["CustomerActionRequired"],
        "description": notes["Description"],
        "faqs": notes["FAQ"],
        "acknowledgments": acks,
        "revisions": revisions,
    }


# ---------------------------------------------------------------------------
# Bucketing -- reported facts only
# ---------------------------------------------------------------------------


def assign_buckets(rec, set_asides):
    """
    Return (bucket, pool, notes). Bucket is the top-level disposition; pool
    applies only to records that reach 'for_processing'.
    """
    names = rec["products"]

    # Bucket 01 -- pass-through.
    if rec["cna"] and rec["cna"] != "Microsoft" and names:
        for family, test in PASSTHROUGH_FAMILIES.items():
            if all(test(n) for n in names):
                return "passthrough", None, family

    # Bucket 02 -- Microsoft states no customer action is required.
    if rec["customer_action_required"] != "Yes":
        return "no_customer_action", None, None

    # Denial of service.
    if "Denial of Service" in rec["impacts"]:
        return "denial_of_service", None, None

    # Optional set-asides. These are REVIEW-TRACK choices, not exclusions,
    # and each can be switched off independently.
    if set_asides.get("mobile") and names and all(MOBILE_RE.search(n) for n in names):
        return "set_aside_mobile", None, None
    if set_asides.get("vscode") and rec["component"] and VSCODE_RE.search(rec["component"]):
        return "set_aside_vscode", None, None

    # Pools. An entry with no usable vector cannot be pooled -- it is held
    # for manual CVSS lookup rather than guessed at.
    if not rec["av"]:
        return "for_processing", "unpooled_no_cvss", None
    if rec["severity"] in ("Critical", "Important"):
        if rec["av"] in ("N", "A"):
            return "for_processing", "pool1", None
        if rec["av"] in ("L", "P"):
            return "for_processing", "pool2", None
    return "for_processing", "pool3", None


# ---------------------------------------------------------------------------
# Data-quality flags -- each is a single mechanical check
# ---------------------------------------------------------------------------


def quality_flags(rec):
    flags = []
    joined_faq = " ".join(rec["faqs"])
    desc = rec["description"] or ""

    # Missing fields.
    if not rec["vector"]:
        flags.append("no_cvss_scoreset")
    if not rec["cwe_id"]:
        flags.append("no_cwe")
    if not rec["acknowledgments"]:
        flags.append("no_acknowledgment")
    if not rec["faqs"]:
        flags.append("no_faq")
    if not rec["description"]:
        flags.append("no_description")
    if any(n.startswith("[unmapped:") for n in rec["products"]):
        flags.append("unmapped_product_id")
    if len(rec["severities_raw"]) > 1:
        flags.append("severity_varies_by_product")

    # Title impact suffix vs Impact threat field.
    for suffix in IMPACT_SUFFIXES:
        if rec["title"].endswith(suffix + " Vulnerability"):
            if rec["impacts"] and suffix not in rec["impacts"]:
                flags.append("title_impact_mismatch")
            break

    # Description locality vs attack vector.
    if rec["av"] == "L" and re.search(r"over a network", desc, re.I):
        flags.append("desc_network_but_vector_local")
    if rec["av"] == "N" and re.search(r"\blocally\b", desc, re.I):
        flags.append("desc_local_but_vector_network")

    # User interaction contradictions.
    if rec["ui"] == "N" and re.search(
        r"convince|entice|persuade|open a specially crafted", joined_faq, re.I
    ):
        flags.append("ui_none_but_faq_describes_user_action")
    if rec["ui"] == "R" and re.search(
        r"no user interaction|without user interaction", joined_faq, re.I
    ):
        flags.append("ui_required_but_faq_says_none")

    # Privilege contradictions.
    if rec["pr"] == "N" and re.search(
        r"\ban? authenticated attacker|\ban authorized attacker", joined_faq + " " + desc, re.I
    ):
        flags.append("pr_none_but_text_says_authenticated")
    if rec["pr"] in ("L", "H") and re.search(
        r"\ban? unauthenticated attacker|\ban unauthorized attacker", desc, re.I
    ):
        flags.append("pr_required_but_desc_says_unauthenticated")

    # Duplicate FAQ question stems with differing answers.
    stems = defaultdict(set)
    for f in rec["faqs"]:
        if "?" in f:
            stem, _, body = f.partition("?")
            stems[stem.strip().lower()].add(body.strip())
    if any(len(v) > 1 for v in stems.values()):
        flags.append("contradictory_duplicate_faq")

    # Exploit status vs temporal exploit-code maturity.
    if rec["exploited"] and rec["vector"] and "/E:U" in rec["vector"]:
        flags.append("exploited_but_temporal_says_unproven")

    return flags


# ---------------------------------------------------------------------------
# Verification of the uploaded document
# ---------------------------------------------------------------------------


def verify_document(doc, n_entries, expected_slug=None):
    """
    Catch the two ways a wrong file silently corrupts everything downstream:
    an 'Early Security Updates' preview document, and a file for the wrong
    month.
    """
    out = {"ok": True, "problems": [], "warnings": []}
    title = doc.get("title") or ""

    if re.search(r"\bEarly\b", title, re.I):
        out["ok"] = False
        out["problems"].append(
            "DocumentTitle contains 'Early' (%r). This is the pre-Patch-Tuesday "
            "preview document, not the monthly release. Re-download." % title
        )

    ird = doc.get("InitialReleaseDate")
    if ird:
        try:
            d = datetime.date.fromisoformat(ird[:10])
            pt = patch_tuesday(d.year, d.month)
            if d != pt:
                out["warnings"].append(
                    "InitialReleaseDate %s is not the second Tuesday of its month (%s). "
                    "Out-of-band or revised release?" % (d, pt)
                )
            if expected_slug:
                slug = "%d-%s" % (d.year, calendar.month_abbr[d.month])
                if slug != expected_slug:
                    out["ok"] = False
                    out["problems"].append(
                        "Document is for %s but %s was requested." % (slug, expected_slug)
                    )
        except ValueError:
            out["warnings"].append("InitialReleaseDate %r is not parseable." % ird)
    else:
        out["warnings"].append("No InitialReleaseDate in the document.")

    if n_entries < 300:
        out["warnings"].append(
            "Only %d vulnerability entries. Recent monthly releases have run "
            "several hundred to over a thousand. Verify this is a full release."
            % n_entries
        )
    return out


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def run(path, set_asides=None, expected_slug=None):
    set_asides = set_asides if set_asides is not None else {"mobile": True, "vscode": True}
    root = ET.parse(path).getroot()
    pm = product_map(root)
    doc = parse_document(root)

    records = []
    for v in root.findall("vuln:Vulnerability", NS):
        rec = parse_vuln(v, pm)
        if not rec["cve"]:
            continue
        bucket, pool, note = assign_buckets(rec, set_asides)
        rec["bucket"], rec["pool"], rec["bucket_note"] = bucket, pool, note
        rec["flags"] = quality_flags(rec)
        records.append(rec)

    verify = verify_document(doc, len(records), expected_slug)

    counts = {
        "total_entries": len(records),
        "by_bucket": dict(Counter(r["bucket"] for r in records)),
        "by_pool": dict(Counter(r["pool"] for r in records if r["pool"])),
    }
    for pool in ("pool1", "pool2", "pool3"):
        sub = [r for r in records if r["pool"] == pool]
        counts[pool + "_by_severity"] = dict(Counter(r["severity"] for r in sub))
        counts[pool + "_components"] = Counter(
            r["component"] or "[no tag]" for r in sub
        ).most_common(10)
        # Part 2: the analyst half-split, stored here so the JSON output
        # carries it as well as the printed summary.
        counts[pool + "_by_half"] = dict(
            Counter("%s/%s" % (r["severity"], "Half 2" if is_half2(r) else "Half 1")
                    for r in sub))
    counts["cwe_distribution"] = Counter(
        r["cwe_id"] or "[none]" for r in records if r["bucket"] == "for_processing"
    ).most_common()
    counts["exploited"] = [r["cve"] for r in records if r["exploited"]]
    counts["publicly_disclosed"] = [r["cve"] for r in records if r["publicly_disclosed"]]

    flags = defaultdict(list)
    for r in records:
        if r["bucket"] != "for_processing":
            continue
        for f in r["flags"]:
            flags[f].append(r["cve"])

    return {"document": doc, "verify": verify, "counts": counts,
            "flags": dict(flags), "records": records}


def print_summary(out, brief=False):
    """
    Print the analyst-facing summary.

    Every section carries a line of context before its numbers. The reader may
    never have seen this tool before, and a bare table of bucket names means
    nothing to them.
    """
    d, v, c = out["document"], out["verify"], out["counts"]
    recs = out["records"]
    print("=" * 70)
    print("DOCUMENT")
    print("=" * 70)
    print("  Title:            %s" % d.get("title"))
    print("  InitialRelease:   %s" % d.get("InitialReleaseDate"))
    print("  CurrentRelease:   %s" % d.get("CurrentReleaseDate"))
    print("  Entries:          %d" % c["total_entries"])
    ird, crd = d.get("InitialReleaseDate"), d.get("CurrentReleaseDate")
    if ird and crd and ird[:10] != crd[:10]:
        print("  NOTE: Microsoft has revised this document since first release.")
        print("        You are seeing its current state, not its state on")
        print("        release day. Revisions add, remove and re-score entries.")
    print()
    print("VERIFICATION: %s" % ("PASS" if v["ok"] else "FAIL"))
    for p in v["problems"]:
        print("  PROBLEM: %s" % p)
    for w in v["warnings"]:
        print("  warning: %s" % w)
    if not v["ok"]:
        print()
        print("  Stop here. Do not process this document.")
        return

    print()
    print("=" * 70)
    print("PART 1 -- REPORTED FACTS")
    print("=" * 70)
    print("  Everything below comes from a field Microsoft published or from a")
    print("  mechanical rule applied to one. None of it is a judgement call,")
    print("  and any of it can be checked against the source file.")
    print()
    print("  BUCKETS -- every entry lands in exactly one:")
    b = c["by_bucket"]
    gloss = [
        ("passthrough", "Pass-through",
         "relayed from an upstream vendor (Chromium, Azure Linux),"
         " not Microsoft-authored"),
        ("no_customer_action", "No customer action required",
         "already mitigated by Microsoft; nothing to install"),
        ("denial_of_service", "Denial of service",
         "availability impact only; set aside by standing rule"),
        ("set_aside_mobile", "Set aside: mobile app stores",
         "patched through an app store, not Windows Update"),
        ("set_aside_vscode", "Set aside: Visual Studio Code",
         "auto-updating, separate cadence"),
        ("for_processing", "FOR PROCESSING",
         "everything left; this is what gets triaged"),
    ]
    for key, label, why in gloss:
        print("    %-32s %5d   %s" % (label, b.get(key, 0), why))

    print()
    print("  POOLS -- the for-processing set divided by attack vector:")
    pools = [
        ("pool1", "Pool 1", "reachable over a network or an adjacent network"),
        ("pool2", "Pool 2", "requires local or physical access"),
        ("pool3", "Pool 3", "everything else; usually empty, kept as a safety net"),
    ]
    for key, label, why in pools:
        n = c["by_pool"].get(key, 0)
        print("    %-32s %5d   %s" % (label, n, why))
        if n:
            sev = c.get(key + "_by_severity", {})
            print("        by severity: %s"
                  % (", ".join("%s %d" % (k, x) for k, x in sorted(sev.items()))
                     or "none"))
    nc = c["by_pool"].get("unpooled_no_cvss", 0)
    print("    %-32s %5d   %s" % ("UNPOOLED -- no CVSS vector", nc,
                                  "cannot be pooled; manual lookup required"))

    print()
    print("  MICROSOFT-REPORTED EXPLOITATION STATUS:")
    print("    Exploited:          %s"
          % (", ".join(c["exploited"]) if c["exploited"] else "none"))
    print("    Publicly disclosed: %s"
          % (", ".join(c["publicly_disclosed"]) if c["publicly_disclosed"]
             else "none"))

    # No-customer-action entries are LISTED, not merely counted. They are
    # often the most severe entries in a release.
    na = [r for r in recs if r["bucket"] == "no_customer_action"]
    if na:
        print()
        print("  NO CUSTOMER ACTION REQUIRED -- %d entries, listed in full."
              % len(na))
        print("  Microsoft has already mitigated these, typically in a cloud")
        print("  service. There is nothing to install. They are listed because")
        print("  they are frequently the most severe entries in a release and")
        print("  say something about the state of Microsoft's own estate.")
        for r in sorted(na, key=lambda x: -(x["base_score"] or 0)):
            print("      %-5s %-9s %-42s %s"
                  % (r["base_score"] if r["base_score"] is not None else "-",
                     r["severity"] or "-", (r["component"] or "?")[:42], r["cve"]))

    if nc:
        print()
        print("  NO CVSS SCORESET -- %d entries. LOOK EACH ONE UP MANUALLY" % nc)
        print("  in the Security Update Guide and supply the vector. These have")
        print("  no attack vector, so no vector-based filter will ever see them.")
        for r in recs:
            if r["pool"] == "unpooled_no_cvss":
                print("      %-9s %-42s %s"
                      % (r["severity"] or "-", (r["component"] or "?")[:42],
                         r["cve"]))

    if brief:
        print_analyst_classification(out)
        return

    # --- set-asides and DoS, listed or summarised ---
    for key, label in (("set_aside_mobile", "SET ASIDE: mobile app stores"),
                       ("set_aside_vscode", "SET ASIDE: Visual Studio Code")):
        rows = [r for r in recs if r["bucket"] == key]
        if rows:
            print()
            print("  %s -- %d entries, listed in full." % (label, len(rows)))
            for r in sorted(rows, key=lambda x: -(x["base_score"] or 0)):
                print("      %-5s %-9s %-42s %s"
                      % (r["base_score"] if r["base_score"] is not None else "-",
                         r["severity"] or "-", (r["component"] or "?")[:42],
                         r["cve"]))
    dos = [r for r in recs if r["bucket"] == "denial_of_service"]
    if dos:
        print()
        print("  DENIAL OF SERVICE -- %d entries, summarised by component." % len(dos))
        print("  Set aside by standing rule. Listed by component rather than by")
        print("  CVE because the count can run high; ask for the full list if")
        print("  availability matters for your environment.")
        for comp, n in Counter(r["component"] or "[no tag]" for r in dos).most_common():
            print("      %4d  %s" % (n, comp))

    print()
    print("  COMPONENT CONCENTRATION -- top components per pool. Concentration")
    print("  is the fastest signal that a release is unusual; one recent month")
    print("  had 61 entries in a single service.")
    for key, label in (("pool1", "Pool 1"), ("pool2", "Pool 2")):
        rows = c.get(key + "_components", [])
        if rows:
            print("    %s:" % label)
            for name, n in rows:
                print("      %4d  %s" % (n, name))

    print()
    print("  CWE DISTRIBUTION -- as published by Microsoft, top 20. No")
    print("  interpretation here; the classification model is Part 2.")
    for cwe, n in c["cwe_distribution"][:20]:
        print("      %4d  %s" % (n, cwe))

    print()
    print("  DATA-QUALITY FLAGS -- observations about Microsoft's published")
    print("  data, not about the vulnerabilities. They matter because they")
    print("  show how much weight any single field deserves.")
    if not out["flags"]:
        print("      none")
    for f, cves in sorted(out["flags"].items(), key=lambda kv: -len(kv[1])):
        print("      %4d  %s" % (len(cves), f))

    print_analyst_classification(out)
    print_obvious_interest(out["records"])


def print_analyst_classification(out):
    """Part 2. The half split, per pool, by severity."""
    c = out["counts"]
    print()
    print("=" * 70)
    print("PART 2 -- ANALYST CLASSIFICATION  (a model, not reported data)")
    print("=" * 70)
    print("  Microsoft does not publish this split. It divides entries by")
    print("  whether exploitation would require overcoming the platform's")
    print("  memory-safety mitigations -- ASLR, DEP, CFG, ACG, heap hardening.")
    print()
    print("    Half 1  logic, type safety and everything else. Exploitation")
    print("            proceeds through well-formed memory; those mitigations")
    print("            have nothing to catch.")
    print("    Half 2  memory and concurrency safety. The mitigations bite.")
    print()
    print("  CWE sets version %s, informed by MITRE's CWE-1399 and CWE-1401"
          % CWE_SET_VERSION)
    print("  with documented departures. The CWE field is often contradicted")
    print("  by the same record's FAQ or CVSS vector, so treat this split as a")
    print("  starting point and override it where the record warrants.")
    for key, label in (("pool1", "Pool 1  network / adjacent"),
                       ("pool2", "Pool 2  local / physical"),
                       ("pool3", "Pool 3  remainder")):
        by = c.get(key + "_by_half", {})
        if not by:
            continue
        print()
        print("  %s" % label)
        for sev in ("Critical", "Important", "Moderate", "Low", "None"):
            for half in ("Half 1", "Half 2"):
                k = "%s/%s" % (sev, half)
                if k in by:
                    print("      %-10s %-8s %5d" % (sev, half, by[k]))


# ---------------------------------------------------------------------------
# Part 3 helpers -- ANALYST LAYER. Nothing in the reported-facts bucketing
# depends on any of this. See SKILL.md Part 3 for the reasoning, the
# approaches that were considered and set aside, and the honest limitations.
# ---------------------------------------------------------------------------


def watchlist_group(component):
    """Return the watchlist group a component falls in, or None."""
    if not component:
        return None
    for group, terms in WATCHLIST.items():
        for t in terms:
            if t.lower() in component.lower():
                return group
    return None


def is_half2(rec):
    return rec["cwe_id"] in MEMORY_SAFETY_CWES or rec["cwe_id"] in CONCURRENCY_CWES


def vulns_of_obvious_interest(records):
    """
    Build the four sublists. Each excludes entries already listed above it.
    Returns an ordered list of (title, hits, residual) triples; residual is
    populated only for sublist 2.
    """
    inscope = [r for r in records if r["bucket"] == "for_processing" and r["vector"]]
    out, used = [], set()

    def take(rows):
        rows = [r for r in rows if r["cve"] not in used]
        used.update(r["cve"] for r in rows)
        return rows

    out.append((
        "1. Network-reachable, high-scored, more-exploitable class "
        "(AV:N, CVSS >= 9.0, Half 1)",
        take([r for r in inscope
              if r["pool"] == "pool1" and r["av"] == "N"
              and (r["base_score"] or 0) >= 9.0 and not is_half2(r)]),
        None,
    ))

    # The zero-click test runs BEFORE sublist 2 claims entries, because a
    # reading-pane RCE in a non-watchlist component would otherwise be
    # swallowed by sublist 2's residual and never reach sublist 3.
    zeroclick = take([r for r in inscope
                      if r["av"] == "N" and r["ui"] == "N"
                      and "Remote Code Execution" in r["impacts"]
                      and (_preview_pane(r) == "YES"
                           or READING_PANE_NARRATION.search(" ".join(r["faqs"])))])

    numeric = [r for r in inscope
               if r["pool"] == "pool1" and (r["base_score"] or 0) >= 9.5
               and r["ui"] == "N" and r["pr"] in ("N", "L")
               and r["cve"] not in used]
    hits = take([r for r in numeric if watchlist_group(r["component"])])
    residual = take([r for r in numeric if not watchlist_group(r["component"])])
    out.append((
        "2. Server products & network-reachable components of established "
        "interest (CVSS >= 9.5, UI:N, PR:N or L)",
        hits, residual,
    ))

    out.append((
        "3. Zero-click document rendering "
        "(preview/reading pane, AV:N, UI:N, RCE)",
        zeroclick, None,
    ))

    out.append((
        "4. Hyper-V with scope change (guest-to-host boundary)",
        take([r for r in inscope
              if r["component"] and "hyper-v" in r["component"].lower()
              and r["scope"] == "C"]),
        None,
    ))
    return out


def _preview_pane(rec):
    m = re.search(
        r"preview pane an attack vector for this vulnerability\?\s*(Yes|No)",
        " ".join(rec["faqs"]), re.I)
    return m.group(1).upper() if m else None


def print_obvious_interest(records):
    """Component-led rendering. One line per component, not one per CVE."""
    print()
    print("=" * 68)
    print("PART 3 -- SOME VULNERABILITIES OF OBVIOUS INTEREST")
    print("=" * 68)
    print("  A surfacing aid, not a priority list. Every sublist is gated on")
    print("  score, vector or a component list, so every sublist misses things.")
    print("  Spoofing and trust-decision bugs in particular are systematically")
    print("  under-scored by CVSS. See SKILL.md Part 3 for the limitations.")
    for title, hits, residual in vulns_of_obvious_interest(records):
        print()
        groups = defaultdict(list)
        for r in hits:
            groups[r["component"] or "[no tag]"].append(r)
        print("  %s" % title)
        print("      [%d components, %d CVEs]" % (len(groups), len(hits)))
        for comp, rows in sorted(
                groups.items(),
                key=lambda kv: (-max(x["base_score"] or 0 for x in kv[1]), kv[0])):
            rows.sort(key=lambda x: -(x["base_score"] or 0))
            top = rows[0]
            crit = sum(1 for x in rows if x["severity"] == "Critical")
            vary = len({(x["av"], x["pr"], x["ui"], x["scope"]) for x in rows}) > 1
            print("      %-46s [%d]  top %.1f  %d Critical"
                  % (comp[:46], len(rows), top["base_score"] or 0, crit))
            print("          AV:%s PR:%s UI:%s S:%s%s  %s"
                  % (top["av"], top["pr"], top["ui"], top["scope"],
                     "  (vectors vary)" if vary else "",
                     ", ".join(x["cve"] for x in rows)))
        if residual:
            print("      -- met every numeric condition, matched no watchlist entry"
                  " (%d):" % len(residual))
            for r in sorted(residual, key=lambda x: -(x["base_score"] or 0)):
                print("          %.1f  %s  %s"
                      % (r["base_score"] or 0, r["cve"], r["component"]))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", help="path to the CVRF XML file")
    ap.add_argument("--json", metavar="OUT", help="write full records to this file")
    ap.add_argument("--verify", action="store_true",
                    help="run upload verification only and exit")
    ap.add_argument("--expect", metavar="YYYY-Mon",
                    help="slug the document is expected to be for, e.g. 2026-Sep")
    ap.add_argument("--no-mobile-setaside", action="store_true",
                    help="do not separate mobile app store products")
    ap.add_argument("--no-vscode-setaside", action="store_true",
                    help="do not separate Visual Studio Code")
    ap.add_argument("--brief", action="store_true",
                    help="short overview only: verification, buckets, pools, "
                         "half split, exploitation status and the no-CVSS "
                         "exception list")
    args = ap.parse_args()

    set_asides = {"mobile": not args.no_mobile_setaside,
                  "vscode": not args.no_vscode_setaside}
    out = run(args.path, set_asides, args.expect)

    if args.verify:
        print(json.dumps({"document": out["document"], "verify": out["verify"],
                          "entries": out["counts"]["total_entries"]}, indent=2))
        return 0 if out["verify"]["ok"] else 1

    print_summary(out, brief=args.brief)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(out, fh, indent=1)
        print("\nFull records written to %s" % args.json)
    return 0 if out["verify"]["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
