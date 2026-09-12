---
name: msrc-triage
description: Acquire, verify, parse and categorise a Microsoft Patch Tuesday security update release (MSRC CVRF XML) and produce a monthly triage report. Use this whenever the user mentions Patch Tuesday, MSRC, CVRF, a monthly Microsoft security release, a file named like 2026-Sep.xml, the Security Update Guide, or asks to triage, sort, bucket, summarise or get an overview of a month's Microsoft vulnerabilities — including when they only say something like "let's do this month's patches" or "the September release is out."
---

# Microsoft Patch Tuesday: monthly triage report

Version 2.2.

**Script paths below are relative to this skill's directory.** If the script
is not found, give its full path — a relative path resolves against the
caller's working directory, not this one.

This produces one report on one month's Microsoft security release. It stops
where analyst judgement begins: it does not decide what to patch first, does
not rank products, and does not assess individual vulnerabilities.

A companion script, `parse_cvrf.py`, does all parsing and categorisation and
prints the figures the report needs. It uses only the Python standard
library. The workflow and the selection criteria are described in prose
here; the CWE sets, the curated product list, the data-quality checks and
the scoreset handling live in the script and are documented by comments
there.

---

## Step 1 — Establish the date and work out the month

Compute today's date from the environment. Do not assume it. A stale date
produces a link to the wrong month and the user will not notice until the
whole pass has run on the wrong file.

Microsoft publishes each release at:

    https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/YYYY-Mon

`Mon` is the three-letter English month abbreviation — `2026-Sep`, `2026-Aug`.

Patch Tuesday is the **second Tuesday of the month**. If today is on or after
this month's second Tuesday, the user wants this month. If before, this
month's data does not exist yet and they want last month.

State which month you selected and why.

---

## Step 2 — Have the user download the file

The file cannot be fetched programmatically in most environments. Hand over
the URL and let the browser do it.

**Present the URL as a rendered markdown link, not as code.** A URL inside
backticks or a code fence renders as literal text the user cannot click or
long-press. That defeats the whole instruction and is worse on mobile, where
press-and-hold needs a real link. Offer the bare URL separately as a
copy-paste fallback.

Tell them, in substance — note that the example is deliberately not fenced:

Here is this month's release data: [September 2026 security update data](https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep)

**Save it to a file rather than opening it in the browser.** In a desktop
browser, right-click and choose "Save Link As". On mobile, press and hold,
then choose save or download.

Opening it directly is a bad idea: releases run to tens of megabytes of XML,
and browsers that try to render that often hang or crash the tab.

If the link does not render where you are, the URL is
https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep — copy it into a
browser address bar and use the browser's save option.

Then upload the saved file. If you want a different month, say which.

Do not try to fetch the URL yourself first. Network access to Microsoft's API
is blocked in most AI execution environments, and community mirrors have
served the wrong document — see Step 3.

---

## Step 3 — Verify before processing

A wrong file does not announce itself. It parses cleanly, produces plausible
numbers, and silently corrupts everything downstream.

1. **DocumentTitle must not contain "Early".** Microsoft publishes a
   pre-Patch-Tuesday preview called "*Month Year* Early Security Updates". A
   community mirror was observed serving this under the normal filename.
2. **InitialReleaseDate should be the second Tuesday** of the month it
   claims, and should match the month requested.

**Only two conditions stop the run:** an "Early" preview document, and a
month mismatch against `--expect`. A release date that is not the second
Tuesday produces a warning, not a stop — out-of-band releases happen.

    python3 parse_cvrf.py <file> --verify --expect 2026-Sep

**There is no entry-count plausibility check, deliberately.** Version 1.0 had
one and it fired spuriously on perfectly good files. Monthly volume has
changed too far too fast for any threshold to carry information. **Never
characterise a month as large or small against an assumed norm.**

---

## Step 4 — Parse

    python3 parse_cvrf.py <file> --expect 2026-Sep

Add `--json out.json` for the full records. Add `--analyst` for a full
category membership dump — that is for whoever maintains the curated product
list and the CWE sets, not for the monthly report.

**Three ways this gets used.** Say which one applies if it is not obvious.

1. *A model with code execution.* The normal path. Run the script, read the
   figures, write the report from them.
2. *A model without code execution.* Someone runs the script elsewhere and
   pastes its printed output — about two hundred lines — into the
   conversation. Do not ask for `--json`; the JSON runs to megabytes and will
   not fit.
3. *No model at all.* `--markdown` emits a finished report with fixed
   wording. Less fluent than a written one, entirely usable, and it depends
   on no model.

Entries are removed in this order, and the order matters:

**1. CNA pass-through.** A CNA is the organisation that assigns a CVE number.
Where that organisation is not Microsoft *and* no Microsoft-authored product
is affected, Microsoft is distributing someone else's code and relaying their
fix. Microsoft ships the code; Microsoft did not write it. Both conditions
must hold — an OpenSSL flaw that also lands in Visual Studio is retained,
because a customer still has to patch something Microsoft ships.

**2. Exploited or publicly disclosed.** Pulled out next so that no *later*
category can bury one. Version 1.0 filed an exploited CVE into the
denial-of-service bucket, where it vanished from every downstream view.

Pass-through runs first deliberately: relayed third-party fixes are not
Microsoft's code and do not belong in any Microsoft count. The consequence
is that a relayed exploited fix — an exploited Chromium bug reaching Edge —
is categorised as pass-through and is **not counted as exploited**.

That is settled and intentional. Microsoft does not call those out in the
figures it gives the press, and this tool follows Microsoft's own counts so
that readers see the same numbers Microsoft promotes. Do not add logic to
count them. The exploited and disclosed headline counters exclude
pass-through, so they can never report an entry the exploited table does not
list.

**3. No customer action required.** Microsoft-operated cloud infrastructure,
already fixed, published only for transparency. **Frequently among the most
severe entries in a release** — one month put nine Critical cloud CVEs here
including two rated 10.0. Nothing to install, but say what they were.

**4. Denial of service only.** Set aside by standing rule — but ONLY when
denial of service is the sole impact. An entry carrying it alongside remote
code execution or elevation of privilege stays in. A Critical guest-to-host
Hyper-V escape with a secondary DoS label was being discarded whole.

**5. iOS or Android app.** Patched through an app store, not Windows Update.

**6. Visual Studio Code.** Auto-updating on its own cadence.

**7. Records missing CVSS data.** No vector and no score, so no filter can
place them. **This is its own category, not part of the remainder.** The two
differ in lifespan: missing data is usually filled in by a later Microsoft
revision, while a medium-severity entry stays medium. List these individually
and tell the user to look each up in the Security Update Guide.

**8. Medium or low severity.** The genuine remainder.

**9. The main body**, divided by attack vector into network-or-adjacent and
local-or-physical.

**The main body is everything left** after the set-asides and the
exploited/disclosed removal. It has four sub-classifications:

- network or adjacent vector, Critical or Important
- local or physical vector, Critical or Important
- below Important
- incomplete data in the version being analysed

Only the two vector sub-classifications can be split by reachability or by
type, so the analysis section works on those alone. **Any table counting only
those two must say so** rather than borrowing the name "main body".

---

## Step 5 — Write the report

Follow this structure. Tables carry the content; prose is short.

### Hard limits

- Opening paragraphs: **two or three sentences each, and no more than three
  of them** before the first table.
- Prose between tables: **one to three sentences**. Enough to say what the
  table counts and why those entries were selected.
- **Every table states its population** — which severities it includes and
  what filter produced it. Not a footnote; a line under the heading.
- **Do not carry conversational formatting preferences into the report.**
  Paragraph numbering, per-reply timestamps, decision lists and similar
  conventions belong to the conversation, not to the artifact. This governs
  the report only; keep using whatever conventions the conversation calls
  for around it.
- **Do not call the report's author anything.** Not "the analyst", not "we".
  Say "analysis" with no creating entity.
- Tooling problems, if any, go at the very end as a short list, and never
  displace the report.
- **Include the data-quality observations.** They are observations about
  Microsoft's records, not about the vulnerabilities, and they show how much
  weight any single field deserves. `--markdown` carries them as a "Notes on
  the source data" section; a written report should do the same.

### Structure

**Title:** Microsoft Patch Tuesday — *Month Year*

**Opening.** What this is: an initial sort, a starting point for review, not
a patching recommendation. When it was released. Whether the document has
been **revised since release** — the script computes this from
InitialReleaseDate against CurrentReleaseDate; never assert it. Note that
Microsoft revises and corrects frequently, so anything flagged incomplete may
since have been filled in.

Then the headline counts: total entries, how many are Microsoft-authored, how
many of those are Critical and Important, how many exploited, how many
publicly disclosed. Then the main body total.

**Table: main body by sub-classification.** Rows for network or
adjacent, local or physical, medium or low, and records missing CVSS data.
Asterisk the last with a footnote explaining that no vector or score means
they cannot be placed.

**Table: main body by effect.** Counts the whole main body. Elevation of
privilege, remote code
execution, and so on. Note that an entry can carry more than one effect, so
counts exceed the total.

**Table: where the main body concentrates.** Top components, counted within
the two vector sub-classifications only — say so, since the other two have no
reachability group. Add one line: high counts usually mean a component was
audited heavily, not that it is more dangerous.

**Section: what was set aside, and why.** One short paragraph per category,
in removal order, each with its count. Use the term **CNA pass-through** and
explain it briefly. Give the exploited and disclosed entries a table with
CVE, component, severity, CVSS, vector and status. Give the missing-CVSS
records a table. Name two or three of the Visual Studio Code entries if any
are notable.

**Section: analysis.** State plainly that this applies a split Microsoft does
not publish. Then the four selections below.

**Section: methodology.** Four or five lines. Where the data comes from. That
the split and the curated product list are applied here rather than
published. Then the repo pointer.

**Attribution block** at the very end. Two forms, because the provenance
differs. When a model wrote the narrative, use this one verbatim — the script
prints it at the foot of its output:

> Skill and scripting created by @arekfurt with LLM assistance. The data is
> Microsoft's. The selection criteria are the author's. The narrative text
> was generated by an AI model and may contain views, conclusions or advice
> the author does not hold. Use and distribute freely with this attribution
> and disclaimer. Created in good faith, but this report may contain
> important errors or omissions.

`--markdown` output carries the other form, which claims the wording as the
author's because in that mode it is.

---

## The analysis section

### The selections overlap

The four selections below are **not** mutually exclusive. They answer
different questions, and an entry qualifying for two is a signal rather than
a duplication. An earlier version made them exclusive, and the broad first
selection silently claimed entries the narrow third one existed to surface.

### The split

**More commonly exploited vulnerability types** against **memory and
concurrency safety vulnerabilities**.

Memory safety bugs are exploited less often in practice because platform
mitigations raise the cost. Concurrency bugs are exploited less often because
winning a race reliably is hard. **Both are tendencies across a class, not
predictions about any single entry**, and the report must say so. Do not
claim that exploiting a given entry would have to defeat any particular
mitigation.

Present it as one table: reachability against severity against type.

Two categories only. Entries whose CWE is absent, or present but on neither
list, fall into **more commonly exploited** — the lists name the memory and
concurrency side, and everything else falls through by design. In practice
almost all of it is ordinary logic: missing authorization, link following,
cross-site scripting, deserialization. Do not surface this to the reader; a
genuinely absent CWE already raises a data-quality observation.

`--analyst` output labels the two as `COMMON` and `MEMCON`.

### Selection 1 — Vulnerabilities warranting particular attention

Network-reachable, CVSS 9.0 or above, and of a more commonly exploited type.
Critical and Important both included.

This is the report's most important list: individual vulnerabilities someone
should look at. Say that selection is mechanical and makes no judgement about
how widely a product is deployed, so the list will sometimes include obscure
entries — and that a reader should read them before discarding them. That is
the point of the list, not a defect in it.

### Selection 2 — Key products and components under fire

Network-reachable, CVSS 9.5 or above, no user interaction, no more than low
privileges, **and on a curated list of products and components judged
notable**. Critical and Important both included.

This is guidance on what to prioritise, so its unit is the **product**, not
the CVE. **Give each functional area its own sub-heading and its own small
table** — not one wide table with an area column repeating the same names
down the page. One row per product within each area, with CVEs as the only
crammed field.

**Say that the list is curated.** A product can be absent because it scored
lower *or* simply because it is not on the list. Always show the entries that
met every numeric test but matched nothing on it, **with their CVE numbers**
so they can be looked up — that residual shows what the list filters out, and
is often as informative as the table above it.

### Selection 3 — Code execution from previewing a file or message

Remote code execution triggered when a file or message is rendered in a
preview or reading pane, with no opening and no clicking.

The Preview Pane FAQ field alone is not enough. Most entries answering "Yes"
are ordinary open-a-document bugs, and the field is sometimes wrong — one
release carried a 9.8 Outlook RCE whose Preview Pane answer was "No" while
its own exploitation FAQ described a reading-pane trigger. So also match FAQ
text narrating the trigger.

**Known limit, worth stating if it comes up:** this catches preview and
reading pane rendering only. Other no-interaction file triggers exist — a
crafted .lnk executing when Explorer renders its icon, thumbnail extraction,
search indexer parsing — and are the same class. Microsoft's FAQ language
does not currently describe them in a way this can match.

### Selection 4 — Escapes from a virtual machine to its host

Hyper-V entries with a scope change, meaning impact crosses out of the guest
VM into the host.

Selections overlap, so a network-vector Hyper-V entry appears both here and
in Selection 2. That is expected.

---

## Approaches considered and set aside

Recorded so a later revision does not rediscover the same dead ends.

**Domain privilege escalation.** Text matching fails: most hits on "domain"
or "Active Directory" are the component name inside a boilerplate sentence.
In one release twelve of seventeen matches were noise, while the single most
domain-relevant entry — a Kerberos capture-replay RCE — matched no phrase at
all. Entries that genuinely describe cross-principal impact share no
vocabulary. A structural rule works better but is brittle across months.

**Trust-decision weaknesses.** A rule matching certificate-validation,
signature-verification, authentication-bypass and origin-validation CWEs,
with network vector and low or no privileges, is principled and narrow — it
returned twelve entries from nine hundred in one release, and would catch the
profile of CVE-2020-0601 (CurveBall). Set aside because it depends entirely
on Microsoft's CWE assignment being correct, and releases routinely show CWE
fields contradicted by their own records.

---

## The honest limitation

Every selection is gated on score, vector or a curated list, so every
selection misses things.

The calibration case: **CVE-2020-0601, CurveBall**, the NSA-reported Windows
CryptoAPI certificate-validation flaw, scored **8.1** with
`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` and listed in CISA's KEV catalogue. It
would fail a 9.0 floor, fail a 9.5 floor, and fail any no-interaction
condition — and the `UI:R` label is questionable, since "the victim connects
to something" is ordinary protocol operation rather than user interaction in
any meaningful sense.

Spoofing and trust-decision bugs are systematically under-scored by CVSS:
they yield no availability impact and collect a user-interaction flag for
normal use. Say this plainly rather than implying completeness.

---

## Requirements

**Code execution is required for the normal path.** Releases run to tens of
megabytes of XML with hundreds or thousands of entries, which cannot be
processed by reading the file into a conversation. Without code execution,
someone runs the script elsewhere and pastes its **printed figures** — about
two hundred lines — into the conversation, or uses `--markdown` and needs no
model at all. **Do not ask for `--json`:** it runs to megabytes and will not
fit in any chat context.

**Network access to Microsoft's API is usually blocked** in AI execution
environments. The download is the user's step, by design.

**Community mirrors are not reliable.** A GitHub mirror was observed serving
the "Early Security Updates" preview under the normal monthly filename.

**Published CVE totals will not match.** Press and vendor summaries count
differently — one release saw published totals of 966, 973, 1,169 and 1,170
for the same month, partly because some counts exclude CVEs published earlier
in the month. If a total is quoted anywhere, say which denominator it uses.

---

# Appendices

Reference material. The workflow above is complete without these.

## Appendix A — parse_cvrf.py

Standard library only, Python 3.8+. Save as `parse_cvrf.py`.

```python
#!/usr/bin/env python3
"""
parse_cvrf.py v2.1 -- normalise a Microsoft CVRF (Common Vulnerability
Reporting Framework) security update document, assign categories, raise
data-quality flags, and either print the figures a monthly report needs or
emit a complete report in markdown.

PARSING AND CATEGORISATION. Every value is either copied from the source
document or derived by a mechanical rule, EXCEPT two things that are the
work of whoever maintains this tool and are labelled as such everywhere:
the split between "more commonly exploited types" and "memory and
concurrency safety", and the curated list of notable products.

Standard library only. Python 3.8+.

    python3 parse_cvrf.py FILE                    # figures for a report
    python3 parse_cvrf.py FILE --markdown         # a finished report, no AI
    python3 parse_cvrf.py FILE --verify           # upload check only
    python3 parse_cvrf.py FILE --json OUT         # full records
    python3 parse_cvrf.py FILE --analyst          # membership dump

Paths: when invoked from a skill directory, give the full path to this
script. Relative paths resolve against the caller's working directory, not
the skill's.

v2.2: "main body" now means EVERYTHING left after the set-asides, with four
sub-classifications inside it. Entries whose CWE is absent or unlisted are
classified as more commonly exploited rather than called out separately.
Exploited and publicly disclosed counts follow Microsoft's own promoted
figures, so relayed third-party fixes are not counted -- see CATEGORY_ORDER.
Plus eleven fixes from a second external review, each reproduced by
execution: a malformed BaseScore raising no flag, broken pluralisation in
the markdown templates, no data-quality section in markdown, set-aside
categories out of order, a residual naming components but no CVEs, --analyst
dumping on a failed verification, and prose that contradicted the code.

v2.1 fixes, all from an external review that reproduced each by execution:
  - Multiple scoresets no longer crash on a missing BaseScore, and the
    authoritative score is chosen by numeric value rather than by string
    sort. A string sort put "10.0" before "7.8" before "9.8"; one release
    would have filed a 9.8 network entry as a 7.8 local one.
  - Denial of service is set aside only when it is the ONLY impact. A
    Critical guest-to-host Hyper-V escape carrying a secondary DoS label
    was being discarded whole.
  - The four analysis selections may now OVERLAP. Previously the first
    claimed entries the third needed, and the preview-pane selection came
    back empty whenever a qualifying entry was not memory-safety.
  - Entries with no CWE get a third classification rather than defaulting
    into the more-commonly-exploited half.
  - "Customer action required" is set aside only on an explicit "No";
    anything else is flagged rather than silently removed.
  - The exploited and disclosed headline counters exclude pass-through, so
    they cannot report entries the exploited table does not list.
  - Edge and Visual Studio Code matching is substring-based like every
    other matcher, and pass-through no longer requires every product to be
    in the SAME third-party family.
  - Month abbreviations are hardcoded English, not locale-dependent.
  - Duplicate CVE ids are detected and flagged.
"""

import argparse
import calendar
import datetime
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict

NS = {
    "cvrf": "http://www.icasi.org/CVRF/schema/cvrf/1.1",
    "vuln": "http://www.icasi.org/CVRF/schema/vuln/1.1",
    "prod": "http://www.icasi.org/CVRF/schema/prod/1.1",
}

VERSION = "2.2"
CWE_SET_VERSION = "2026-09-11"
REPO_URL = "https://github.com/arekfurt/CopingWithPatchTuesday"

# calendar.month_abbr follows LC_TIME. The URL slug must be English.
MONTH_ABBR = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

ATTRIB_TEMPLATE = (
    "Skill and scripting created by @arekfurt with LLM assistance. "
    "The data is Microsoft's. The selection criteria and the wording of this "
    "report are the author's. "
    "Use and distribute freely with this attribution and disclaimer. "
    "Created in good faith, but this report may contain important errors or "
    "omissions."
)
ATTRIB_AI = (
    "Skill and scripting created by @arekfurt with LLM assistance. "
    "The data is Microsoft's. The selection criteria are the author's. "
    "The narrative text was generated by an AI model and may contain views, "
    "conclusions or advice the author does not hold. "
    "Use and distribute freely with this attribution and disclaimer. "
    "Created in good faith, but this report may contain important errors or "
    "omissions."
)

# ---------------------------------------------------------------------------
# CNA pass-through families.
#
# Substring tests, consistent with every other matcher here. An entry is
# pass-through when the assigning CNA is not Microsoft AND every affected
# product matches SOME third-party family -- not necessarily the same one,
# since an entry can legitimately span Edge and Azure Linux.
#
# Both conditions must hold. An OpenSSL flaw that also lands in Visual Studio
# is RETAINED, because a customer still has to patch something Microsoft
# ships.
# ---------------------------------------------------------------------------
PASSTHROUGH_TESTS = [
    ("chromium_edge", lambda n: bool(re.search(r"Microsoft Edge \(Chromium", n, re.I))),
    ("azure_linux", lambda n: bool(re.search(r"azure linux|mariner", n, re.I)
                                   or re.match(r"^(cbl|azl)", n, re.I))),
]

MOBILE_RE = re.compile(r"\bfor (Android|iOS)\b|iOS and iPadOS", re.I)
VSCODE_RE = re.compile(r"Visual Studio Code", re.I)

IMPACT_SUFFIXES = [
    "Remote Code Execution", "Elevation of Privilege", "Information Disclosure",
    "Denial of Service", "Security Feature Bypass", "Spoofing", "Tampering",
]

# ---------------------------------------------------------------------------
# CWE sets, version 2026-09-11. MAINTAINER'S JUDGEMENT, not Microsoft's data.
#
# Informed by MITRE's CWE-1399 (Memory Safety) and CWE-1401 (Concurrency),
# consulted to catch classes that had never happened to appear in the data.
# Both category IDs are PROHIBITED for mapping real vulnerabilities -- use
# the members, never the category.
#
# Deliberate departures from MITRE membership:
#   ADDED, not in CWE-1399: CWE-170, 190, 191, 197, 476, 681, 908. MITRE
#     files the integer-arithmetic family elsewhere; these are included
#     because their consequence is a memory-safety failure.
#   HELD OUT, in CWE-1399: CWE-134 (format string), 188, 198, 244, 401, 789.
#     CWE-134 is the one reviewers ask about. It is held out because the
#     weakness itself is input handling rather than a memory access error,
#     and because at least one kept entry was retained on the basis that
#     format-string flaws are not memory safety. Revisit if a month turns
#     on it.
#   CWE-843 type confusion stays OUT. Confusions where one object is treated
#     as a LARGER type land outside the allocation and are heap overflows by
#     another name. Confusions between same-sized objects corrupt nothing --
#     the program does the wrong thing with well-formed memory. Published
#     records never say which kind an entry is.
#   CWE-1401 members excluded as inapplicable: Java/EJB/POSIX-signal patterns
#     (479, 543, 558, 572, 574, 1058, 1088, 1096) and hardware logic
#     (1232, 1234, 1264, 1298).
#
# These lists resolve the obvious cases. They do not decide the
# classification. The published CWE is often contradicted by the same
# record's FAQ or CVSS vector, and whether exploitation would really have to
# defeat platform mitigations is a tendency the CWE only indicates.
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

TYPE_COMMON = "more commonly exploited"
TYPE_MEMORY = "memory or concurrency safety"

# Entries whose CWE is absent, or present but on neither list, fall into
# TYPE_COMMON. This is deliberate and is NOT surfaced to the report reader.
# The lists name the memory and concurrency side only; everything else falls
# through by design, and in practice almost all of it is ordinary logic --
# missing authorization, link following, cross-site scripting, deserialization.
# One release had 139 of 888 entries in that state and 0 with no CWE at all.
# Calling them undetermined would claim an uncertainty that does not exist.
# The rare genuinely-absent CWE already raises a no_cwe quality flag.

# ---------------------------------------------------------------------------
# Curated list of notable products. MAINTAINER'S JUDGEMENT, used ONLY by the
# "key products and components under fire" selection. A product can be absent
# because it scored lower OR because it is not on this list, which is why
# entries meeting every numeric test but matching nothing here are always
# reported separately.
#
# Substring matching, because Microsoft fragments functional areas across
# many component names.
# ---------------------------------------------------------------------------
WATCHLIST = {
    "Identity and domain infrastructure": [
        "Active Directory", "AD CS", "AD FS", "Kerberos",
        "Key Distribution Center", "lsasrv", "Local Security Authority",
        "Netlogon", "LDAP", "Credential Guard", "Credential Providers",
        "Smart Card", "Online Certificate Status", "Authentication Methods",
        "Entra", "Azure Active Directory", "Digest Authentication",
        "Host Guardian", "Winlogon", "Microsoft Account", "MSAL",
        "Windows Hello",
    ],
    "Core network services": [
        "DNS", "DHCP Server", "DHCP Client", "TCP/IP", "Schannel", "QUIC",
        "HTTP.sys", "HTTP Protocol Stack", "HTTP Print Provider",
        "Message Queuing", "RPC Runtime", "RPC API", "Winsock",
        "Ancillary Function Driver", "IP Helper",
        "Internet Connection Sharing", "Network Address Translation",
        "NDIS", "RNDIS", "Link Layer Topology",
    ],
    "Remote access and VPN": [
        "Routing and Remote Access", "RRAS", "Secure Socket Tunneling",
        "SSTP", "IKE Extension", "Remote Access Connection Manager",
        "Remote Access API", "Remote Desktop", "RDP Client",
    ],
    "File and storage services": [
        "SMB Server", "SMB Client", "Network File System", "NFS", "iSCSI",
        "Distributed File System", "DFS", "WebClient", "Work Folder",
        "Failover Cluster", "Storage Spaces", "BranchCache",
    ],
    "Virtualization and isolation": [
        "Hyper-V", "Secure Kernel Mode", "VBS Enclave",
        "Virtualization-Based Security", "Virtual Trusted Platform Module",
        "Device Health Attestation", "Azure Attestation",
        "Container Isolation",
    ],
    "Mail and collaboration servers": [
        "Exchange Server", "SharePoint", "Skype for Business",
        "Microsoft Teams",
    ],
    "Database and data platform": [
        "SQL Server", "Azure SQL", "Cosmos DB", "OLE DB", "Dynamics",
        "Power BI", "Microsoft Fabric",
    ],
    "Management and deployment": [
        "Deployment Services", "Windows Update Stack", "Windows Installer",
        "Modern Device Management", "Management Instrumentation",
        "Management Services", "Autopilot", "Group Policy", "Remote Registry",
        "IP Address Management", "IPAM", "Print Spooler", "Fax Service",
        "WSUS",
    ],
    "Cryptography and boot integrity": [
        "Secure Boot", "Boot Manager", "BitLocker", "TPM", "Key Guard",
    ],
    "Developer and automation platforms": [
        "Visual Studio", ".NET", "ASP.NET", "PowerShell", "Azure CLI",
        "Azure Arc", "Power Automate", "Copilot Studio", "HPC Pack",
        "Azure CycleCloud", "Azure HDInsight", "Azure Kubernetes",
    ],
    "Remote shell and transfer": ["OpenSSH", "Telnet", "FTP"],
}
AREA_ORDER = list(WATCHLIST.keys())

# KNOWN LIMIT: catches preview and reading pane rendering only. Other
# no-interaction file triggers exist -- a crafted .lnk executing when
# Explorer renders its icon, thumbnail extraction, search indexer parsing --
# and are the same class. Microsoft's FAQ language does not currently
# describe them in a way this can match.
READING_PANE_NARRATION = re.compile(
    r"rendered in the preview pane"
    r"|viewing the message in the .{0,25}Reading Pane"
    r"|preview(ed)? in the Reading Pane",
    re.I,
)


def clean(s):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s or "")).strip()


def strip_cvss_prefix(vec):
    """Remove any CVSS version prefix and the temporal tail."""
    if not vec:
        return "-"
    return re.sub(r"^CVSS:[\d.]+/", "", vec).split("/E:")[0]


def patch_tuesday(year, month):
    tuesdays = [d for d in calendar.Calendar().itermonthdates(year, month)
                if d.month == month and d.weekday() == calendar.TUESDAY]
    return tuesdays[1]


def current_release_slug(today=None):
    today = today or datetime.date.today()
    pt = patch_tuesday(today.year, today.month)
    if today >= pt:
        y, m = today.year, today.month
    else:
        y, m = ((today.year, today.month - 1) if today.month > 1
                else (today.year - 1, 12))
    return y, m, "%d-%s" % (y, MONTH_ABBR[m])


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
    t = root.find("cvrf:DocumentTitle", NS)
    dt = root.find("cvrf:DocumentTracking", NS)
    out = {"title": clean(t.text) if t is not None else None}
    for field in ("InitialReleaseDate", "CurrentReleaseDate"):
        el = dt.find("cvrf:%s" % field, NS) if dt is not None else None
        out[field] = el.text if el is not None else None
    out["revised"] = _revised(out.get("InitialReleaseDate"),
                              out.get("CurrentReleaseDate"))
    return out


def _revised(ird, crd):
    """
    True only when both timestamps parse and differ. Comparing raw strings
    would report a false revision if the two fields ever differ in format
    (fractional seconds, offset versus Z).
    """
    if not ird or not crd:
        return None
    def norm(s):
        s = s.strip().replace("Z", "+00:00")
        try:
            return datetime.datetime.fromisoformat(s).replace(tzinfo=None)
        except ValueError:
            try:
                return datetime.datetime.fromisoformat(s[:19])
            except ValueError:
                return None
    a, b = norm(ird), norm(crd)
    if a is None or b is None:
        return None
    return a != b


def parse_vuln(v, pm):
    cve_el = v.find("vuln:CVE", NS)
    cve = cve_el.text if cve_el is not None else None
    title_el = v.find("vuln:Title", NS)
    title = clean(title_el.text) if title_el is not None else ""
    cwe_el = v.find("vuln:CWE", NS)
    cwe_id = cwe_el.get("ID") if cwe_el is not None else None
    cwe_name = clean(cwe_el.text) if cwe_el is not None else None

    # Threat and ScoreSet elements repeat once per affected ProductID.
    # Deduplicate on read.
    impacts, severities = set(), set()
    exploit_statuses = set()
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
            exploit_statuses.add(d.text)

    scoresets = []
    unparseable_base = False
    for ss in v.findall("vuln:CVSSScoreSets/vuln:ScoreSet", NS):
        b = ss.find("vuln:BaseScore", NS)
        tm = ss.find("vuln:TemporalScore", NS)
        ve = ss.find("vuln:Vector", NS)
        bad_base = False
        try:
            base = float(b.text) if b is not None and b.text else None
        except ValueError:
            base = None
            bad_base = True
        if bad_base:
            unparseable_base = True
        entry = (base, tm.text if tm is not None else None,
                 ve.text if ve is not None else None)
        if entry not in scoresets:
            scoresets.append(entry)

    # Choose the authoritative scoreset by NUMERIC base score, preferring one
    # that actually carries a vector. Sorting the raw tuples would compare
    # None with str (crash) and would order "10.0" before "7.8" (wrong).
    scored = [s for s in scoresets if s[0] is not None and s[2]]
    if not scored:
        scored = [s for s in scoresets if s[2]]
    chosen = max(scored, key=lambda s: (s[0] if s[0] is not None else -1)) \
        if scored else (None, None, None)

    distinct_bases = {s[0] for s in scoresets if s[0] is not None}
    distinct_vectors = {s[2] for s in scoresets if s[2]}

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

    acks = [clean(a.text) for a in
            v.findall("vuln:Acknowledgments/vuln:Acknowledgment/vuln:Name", NS)
            if a.text]

    base_score, _, vector = chosen
    av = pr = ui = ac = sc = None
    if vector:
        def m(pat):
            g = re.search(pat, vector)
            return g.group(1) if g else None
        av, pr, ui, ac = (m(r"\bAV:([A-Z])"), m(r"\bPR:([A-Z])"),
                          m(r"\bUI:([A-Z])"), m(r"\bAC:([A-Z])"))
        sc = m(r"/S:([A-Z])")

    severity = next((s for s in ("Critical", "Important", "Moderate", "Low")
                     if s in severities), None)
    exploit_status = sorted(exploit_statuses)[0] if exploit_statuses else None
    joined_status = " ".join(exploit_statuses)
    exploited = "Exploited:Yes" in joined_status if exploit_statuses else None
    disclosed = ("Publicly Disclosed:Yes" in joined_status
                 if exploit_statuses else None)

    return {
        "cve": cve, "title": title, "component": notes["Tag"],
        "cwe_id": cwe_id, "cwe_name": cwe_name,
        "impacts": sorted(impacts), "severity": severity,
        "severities_raw": sorted(severities),
        "exploit_status": exploit_status,
        "exploit_status_count": len(exploit_statuses),
        "exploited": exploited, "publicly_disclosed": disclosed,
        "base_score": base_score, "vector": vector,
        "av": av, "ac": ac, "pr": pr, "ui": ui, "scope": sc,
        "scoreset_count": len(scoresets),
        "unparseable_base": unparseable_base,
        "distinct_base_scores": sorted(distinct_bases),
        "distinct_vector_count": len(distinct_vectors),
        "products": products, "product_count": len(products),
        "cna": notes["CNA"],
        "customer_action_required": notes["CustomerActionRequired"],
        "description": notes["Description"], "faqs": notes["FAQ"],
        "acknowledgments": acks,
    }


# ---------------------------------------------------------------------------
# Categorisation. ORDER MATTERS.
#
# CNA pass-through runs first: relayed third-party fixes are not Microsoft's
# code and do not belong in any Microsoft count. This is also why a relayed
# exploited fix -- an exploited Chromium bug reaching Edge -- is NOT counted
# as exploited here. Microsoft does not call those out in the figures it
# gives the press, and this tool follows Microsoft's own counts so that
# readers see the same numbers. Settled; do not add logic for it. Exploited and disclosed
# entries are pulled out second, so that no LATER category can bury one --
# and because pass-through runs first, the exploited and disclosed headline
# counters deliberately exclude pass-through, so they can never report an
# entry the exploited table does not list.
# ---------------------------------------------------------------------------

CATEGORY_ORDER = [
    ("passthrough", "CNA pass-through"),
    ("exploited_disclosed", "Exploited or publicly disclosed"),
    ("no_customer_action", "No customer action required"),
    ("denial_of_service", "Denial of service only"),
    ("mobile", "iOS or Android app"),
    ("vscode", "Visual Studio Code"),
    ("missing_cvss", "Records missing CVSS data"),
    ("remainder", "Medium or low severity"),
    ("network", "Main body -- network or adjacent"),
    ("local", "Main body -- local or physical"),
]
# The MAIN BODY is everything left after the set-asides and the
# exploited/disclosed removal. It has four sub-classifications. Only the two
# vector groups can be split by reachability or by type, so any table
# operating on those alone says so rather than borrowing the name.
MAIN_BODY = ("network", "local", "remainder", "missing_cvss")
VECTOR_GROUPS = ("network", "local")


def categorise(rec):
    names = rec["products"]
    blob = " ".join([rec["component"] or "", rec["title"] or ""])

    if rec["cna"] and rec["cna"] != "Microsoft" and names:
        if all(any(test(n) for _, test in PASSTHROUGH_TESTS) for n in names):
            return "passthrough", "third-party product only"

    if rec["exploited"] or rec["publicly_disclosed"]:
        return "exploited_disclosed", None

    # Explicit "No" only. An absent or unexpected value is NOT treated as
    # already-fixed cloud infrastructure; it stays in and is flagged.
    car = (rec["customer_action_required"] or "").strip().lower()
    if car == "no":
        return "no_customer_action", None

    # Only when denial of service is the SOLE impact. A Critical Hyper-V
    # guest-to-host escape carrying a secondary DoS label must not be
    # discarded as a DoS.
    if rec["impacts"] and set(rec["impacts"]) == {"Denial of Service"}:
        return "denial_of_service", None

    if MOBILE_RE.search(blob) or (names and all(MOBILE_RE.search(n) for n in names)):
        return "mobile", None

    if VSCODE_RE.search(blob):
        return "vscode", None

    if not rec["vector"]:
        return "missing_cvss", None

    if rec["severity"] not in ("Critical", "Important"):
        return "remainder", None

    return ("network" if rec["av"] in ("N", "A") else "local"), None


def vuln_type(rec):
    if rec["cwe_id"] in MEMORY_SAFETY_CWES or rec["cwe_id"] in CONCURRENCY_CWES:
        return TYPE_MEMORY
    return TYPE_COMMON


# ---------------------------------------------------------------------------
# Data-quality flags -- mechanical checks on Microsoft's published data
# ---------------------------------------------------------------------------


def quality_flags(rec):
    flags = []
    faq = " ".join(rec["faqs"])
    desc = rec["description"] or ""

    if not rec["vector"]:
        flags.append("no_cvss_scoreset")
    # A BaseScore that will not parse leaves base_score None while the vector
    # survives, so the entry is categorised normally but drops out of every
    # score gate. Every other data problem here raises a flag; so does this.
    if rec.get("unparseable_base") or (rec["vector"] and rec["base_score"] is None):
        flags.append("base_score_unparseable")
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
    if len(rec["distinct_base_scores"]) > 1:
        flags.append("score_varies_by_product")
    if rec["distinct_vector_count"] > 1:
        flags.append("vector_varies_by_product")
    if rec["exploit_status_count"] > 1:
        flags.append("exploit_status_varies_by_product")

    car = (rec["customer_action_required"] or "").strip().lower()
    if car not in ("yes", "no"):
        flags.append("customer_action_required_unclear")

    for suffix in IMPACT_SUFFIXES:
        if rec["title"].endswith(suffix + " Vulnerability"):
            if rec["impacts"] and suffix not in rec["impacts"]:
                flags.append("title_impact_mismatch")
            break

    if rec["av"] == "L" and re.search(r"over a network", desc, re.I):
        flags.append("desc_network_but_vector_local")
    if rec["av"] == "N" and re.search(r"\blocally\b", desc, re.I):
        flags.append("desc_local_but_vector_network")

    if rec["ui"] == "N" and re.search(
            r"convince|entice|persuade|open a specially crafted", faq, re.I):
        flags.append("ui_none_but_faq_describes_user_action")
    if rec["ui"] == "R" and re.search(
            r"no user interaction|without user interaction", faq, re.I):
        flags.append("ui_required_but_faq_says_none")

    if rec["pr"] == "N" and re.search(
            r"\ban? authenticated attacker|\ban authorized attacker",
            faq + " " + desc, re.I):
        flags.append("pr_none_but_text_says_authenticated")
    if rec["pr"] in ("L", "H") and re.search(
            r"\ban? unauthenticated attacker|\ban unauthorized attacker",
            desc, re.I):
        flags.append("pr_required_but_desc_says_unauthenticated")

    stems = defaultdict(set)
    for f in rec["faqs"]:
        if "?" in f:
            stem, _, body = f.partition("?")
            stems[stem.strip().lower()].add(body.strip())
    if any(len(v) > 1 for v in stems.values()):
        flags.append("contradictory_duplicate_faq")

    if rec["exploited"] and rec["vector"] and "/E:U" in rec["vector"]:
        flags.append("exploited_but_temporal_says_unproven")

    bs = rec["base_score"]
    if bs is not None and rec["severity"]:
        if (bs >= 9.0 and rec["severity"] == "Important") or \
           (bs < 7.0 and rec["severity"] == "Critical"):
            flags.append("severity_vs_score_divergence")

    return flags


# ---------------------------------------------------------------------------
# Verification
#
# There is NO entry-count plausibility check. Version 1.0 had one; it fired
# spuriously on perfectly good files. Monthly volume has changed too far too
# fast for any threshold to carry information. Do not reintroduce it.
#
# Only two conditions STOP the run: an "Early" preview document, and a
# month mismatch against --expect. Everything else is a warning. The skill
# prose must say the same.
# ---------------------------------------------------------------------------


def verify_document(doc, expected_slug=None):
    out = {"ok": True, "problems": [], "warnings": []}
    title = doc.get("title") or ""

    if re.search(r"\bEarly\b", title, re.I):
        out["ok"] = False
        out["problems"].append(
            "DocumentTitle contains 'Early' (%r). This is the "
            "pre-Patch-Tuesday preview document, not the monthly release. "
            "Re-download." % title)

    ird = doc.get("InitialReleaseDate")
    if ird:
        try:
            d = datetime.date.fromisoformat(ird[:10])
            pt = patch_tuesday(d.year, d.month)
            if d != pt:
                out["warnings"].append(
                    "InitialReleaseDate %s is not the second Tuesday of its "
                    "month (%s). Out-of-band or revised release? This is a "
                    "warning, not a stop condition." % (d, pt))
            if expected_slug:
                slug = "%d-%s" % (d.year, MONTH_ABBR[d.month])
                if slug != expected_slug:
                    out["ok"] = False
                    out["problems"].append(
                        "Document is for %s but %s was requested."
                        % (slug, expected_slug))
        except ValueError:
            out["warnings"].append(
                "InitialReleaseDate %r is not parseable." % ird)
    else:
        out["warnings"].append("No InitialReleaseDate in the document.")
    return out


# ---------------------------------------------------------------------------
# Selections.
#
# These OVERLAP by design. They answer different questions, and an entry
# qualifying for two is a signal rather than a duplication. An earlier
# version made them mutually exclusive, which meant the broad first
# selection claimed entries the narrow third one existed to surface.
# ---------------------------------------------------------------------------


def watchlist_area(component):
    if not component:
        return None
    for area, terms in WATCHLIST.items():
        for t in terms:
            if t.lower() in component.lower():
                return area
    return None


def _preview_pane(rec):
    m = re.search(
        r"preview pane an attack vector for this vulnerability\?\s*(Yes|No)",
        " ".join(rec["faqs"]), re.I)
    return m.group(1).upper() if m else None


def selections(records):
    body = [r for r in records if r["category"] in VECTOR_GROUPS]
    out = {}

    out["attention"] = [
        r for r in body
        if r["category"] == "network" and r["av"] == "N"
        and (r["base_score"] or 0) >= 9.0 and r["vuln_type"] == TYPE_COMMON]

    numeric = [r for r in body
               if r["category"] == "network" and (r["base_score"] or 0) >= 9.5
               and r["ui"] == "N" and r["pr"] in ("N", "L")]
    out["under_fire"] = [r for r in numeric if watchlist_area(r["component"])]
    out["under_fire_residual"] = [r for r in numeric
                                  if not watchlist_area(r["component"])]

    out["preview_rce"] = [
        r for r in body
        if r["av"] == "N" and r["ui"] == "N"
        and "Remote Code Execution" in r["impacts"]
        and (_preview_pane(r) == "YES"
             or READING_PANE_NARRATION.search(" ".join(r["faqs"])))]

    out["vm_escape"] = [
        r for r in body
        if r["component"] and "hyper-v" in r["component"].lower()
        and r["scope"] == "C"]
    return out


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def run(path, expected_slug=None):
    root = ET.parse(path).getroot()
    pm = product_map(root)
    doc = parse_document(root)

    records, seen = [], Counter()
    for v in root.findall("vuln:Vulnerability", NS):
        rec = parse_vuln(v, pm)
        if not rec["cve"]:
            continue
        seen[rec["cve"]] += 1
        rec["category"], rec["category_note"] = categorise(rec)
        rec["vuln_type"] = vuln_type(rec)
        rec["flags"] = quality_flags(rec)
        records.append(rec)
    dupes = [c for c, n in seen.items() if n > 1]
    for rec in records:
        if rec["cve"] in dupes:
            rec["flags"].append("duplicate_cve_id")

    verify = verify_document(doc, expected_slug)
    by_cat = Counter(r["category"] for r in records)
    body = [r for r in records if r["category"] in MAIN_BODY]
    vec = [r for r in records if r["category"] in VECTOR_GROUPS]
    ms = [r for r in records if r["category"] != "passthrough"]

    counts = {
        "total_entries": len(records),
        "microsoft_authored": len(ms),
        "by_category": dict(by_cat),
        "main_body": len(body),
        "vector_groups": len(vec),
        "duplicate_cve_ids": dupes,
        # Counted over Microsoft-authored entries only, so these can never
        # report entries the exploited/disclosed table does not list.
        "exploited": [r["cve"] for r in ms if r["exploited"]],
        "publicly_disclosed": [r["cve"] for r in ms if r["publicly_disclosed"]],
        "impacts_main_body": Counter(
            i for r in body for i in r["impacts"]).most_common(),
        "severity_all_microsoft": dict(Counter(r["severity"] for r in ms)),
    }
    for cat in VECTOR_GROUPS:
        sub = [r for r in records if r["category"] == cat]
        counts[cat + "_by_severity"] = dict(Counter(r["severity"] for r in sub))
        counts[cat + "_by_type"] = dict(Counter(
            "%s / %s" % (r["severity"], r["vuln_type"]) for r in sub))
        counts[cat + "_components"] = Counter(
            r["component"] or "[no tag]" for r in sub).most_common(6)

    flags = defaultdict(list)
    for r in records:
        if r["category"] == "passthrough":
            continue
        for f in r["flags"]:
            flags[f].append(r["cve"])

    return {"document": doc, "verify": verify, "counts": counts,
            "flags": dict(flags), "records": records,
            "selections": selections(records), "version": VERSION,
            "cwe_set_version": CWE_SET_VERSION}


def month_name(doc):
    ird = doc.get("InitialReleaseDate")
    if ird:
        try:
            d = datetime.date.fromisoformat(ird[:10])
            return "%s %d" % (calendar.month_name[d.month] or MONTH_ABBR[d.month],
                              d.year)
        except ValueError:
            pass
    return doc.get("title") or "this release"


# ---------------------------------------------------------------------------
# Output: figures for an AI-written report
# ---------------------------------------------------------------------------


def print_report_data(out):
    d, v, c, recs = out["document"], out["verify"], out["counts"], out["records"]
    cat = {k: [r for r in recs if r["category"] == k] for k, _ in CATEGORY_ORDER}

    print("=" * 72)
    print("DOCUMENT")
    print("=" * 72)
    print("  Title:              %s" % d.get("title"))
    print("  InitialReleaseDate: %s" % d.get("InitialReleaseDate"))
    print("  CurrentReleaseDate: %s" % d.get("CurrentReleaseDate"))
    if d.get("revised") is True:
        print("  REVISED since release. Say so in the report.")
    elif d.get("revised") is False:
        print("  Not revised since release. Say so in the report.")
    else:
        print("  Revision status could not be determined from the timestamps.")
    print("  Entries:            %d" % c["total_entries"])
    if c["duplicate_cve_ids"]:
        print("  DUPLICATE CVE IDS: %s" % ", ".join(c["duplicate_cve_ids"]))
    print()
    print("VERIFICATION: %s" % ("PASS" if v["ok"] else "FAIL"))
    for p in v["problems"]:
        print("  PROBLEM: %s" % p)
    for w in v["warnings"]:
        print("  warning: %s" % w)
    if not v["ok"]:
        print("\n  Stop. Do not process this document.")
        return
    print()
    print("  No entry-count plausibility check is performed. Monthly volume")
    print("  has changed too much too fast for a threshold to mean anything.")
    print("  Do not characterise the month as large or small against a norm.")

    sev = c["severity_all_microsoft"]
    print()
    print("=" * 72)
    print("HEADLINE FIGURES")
    print("=" * 72)
    print("  Total entries in document ........... %d" % c["total_entries"])
    print("  Authored by Microsoft ............... %d" % c["microsoft_authored"])
    print("      Critical ........................ %d" % sev.get("Critical", 0))
    print("      Important ....................... %d" % sev.get("Important", 0))
    print("  Exploited in the wild ............... %d  %s"
          % (len(c["exploited"]), ", ".join(c["exploited"]) or ""))
    print("  Publicly disclosed .................. %d  %s"
          % (len(c["publicly_disclosed"]),
             ", ".join(c["publicly_disclosed"]) or ""))
    print("  MAIN BODY ........................... %d" % c["main_body"])
    print("      placeable by vector ............. %d" % c["vector_groups"])

    print()
    print("  Main body, by sub-classification:")
    for key, label in (("network", "Network or adjacent subnet"),
                       ("local", "Local or physical access required")):
        s = c[key + "_by_severity"]
        print("      %-34s Critical %-4d Important %-4d Total %d"
              % (label, s.get("Critical", 0), s.get("Important", 0),
                 len(cat[key])))
    for key, label in (("remainder", "Medium or low severity"),
                       ("missing_cvss", "Records missing CVSS data")):
        rows = cat[key]
        print("      %-34s Critical %-4d Important %-4d Total %d"
              % (label,
                 sum(1 for r in rows if r["severity"] == "Critical"),
                 sum(1 for r in rows if r["severity"] == "Important"),
                 len(rows)))

    print()
    print("  Main body, by effect (an entry may carry more than one):")
    for imp, n in c["impacts_main_body"]:
        print("      %-30s %d" % (imp, n))

    print()
    print("  Concentration among the two vector sub-classifications only,")
    print("  Critical and Important together:")
    for key, label in (("network", "Network or adjacent"),
                       ("local", "Local or physical")):
        print("      %s:" % label)
        for name, n in c[key + "_components"]:
            print("          %4d  %s" % (n, name))

    print()
    print("=" * 72)
    print("SET ASIDE, IN REMOVAL ORDER")
    print("=" * 72)
    for key, label in CATEGORY_ORDER:
        if key in MAIN_BODY:
            continue
        print("  %-34s %d" % (label, len(cat[key])))

    ed = cat["exploited_disclosed"]
    if ed:
        print()
        print("  EXPLOITED OR PUBLICLY DISCLOSED -- full rows:")
        for r in sorted(ed, key=lambda x: -(x["base_score"] or 0)):
            st = [s for s, on in (("Exploited", r["exploited"]),
                                  ("Publicly disclosed", r["publicly_disclosed"]))
                  if on]
            print("      %-16s %-32s %-9s %-5s %-30s %s"
                  % (r["cve"], (r["component"] or "?")[:32], r["severity"] or "-",
                     r["base_score"] if r["base_score"] is not None else "-",
                     strip_cvss_prefix(r["vector"]), " + ".join(st)))
            print("          status: %s" % r["exploit_status"])

    na = cat["no_customer_action"]
    if na:
        print()
        print("  NO CUSTOMER ACTION REQUIRED -- Microsoft-operated cloud")
        print("  infrastructure, already fixed. Frequently among the most")
        print("  severe entries in a release.")
        for r in sorted(na, key=lambda x: -(x["base_score"] or 0)):
            print("      %-16s %-40s %-9s %s"
                  % (r["cve"], (r["component"] or "?")[:40],
                     r["severity"] or "-",
                     r["base_score"] if r["base_score"] is not None else "-"))

    for key, label in (("vscode", "VISUAL STUDIO CODE"),
                       ("mobile", "iOS OR ANDROID APP")):
        rows = cat[key]
        if rows:
            print()
            print("  %s:" % label)
            for r in sorted(rows, key=lambda x: -(x["base_score"] or 0)):
                print("      %-16s %-40s %-9s %s"
                      % (r["cve"], (r["component"] or "?")[:40],
                         r["severity"] or "-",
                         r["base_score"] if r["base_score"] is not None else "-"))

    mc = cat["missing_cvss"]
    if mc:
        print()
        print("  RECORDS MISSING CVSS DATA -- no vector, no score, so no")
        print("  filter can place them. Look each up in the Security Update")
        print("  Guide. Check the download's publication date first;")
        print("  Microsoft often adds this in a later revision.")
        for r in mc:
            print("      %-16s %-40s %s"
                  % (r["cve"], (r["component"] or "?")[:40], r["severity"] or "-"))

    print()
    print("=" * 72)
    print("ANALYSIS  (a split Microsoft does not publish)")
    print("=" * 72)
    print("  More commonly exploited types vs memory and concurrency safety.")
    print("  Tendencies across a class, not predictions about any one entry.")
    print("  CWE sets version %s." % CWE_SET_VERSION)
    print()
    for key, label in (("network", "Network or adjacent"),
                       ("local", "Local or physical")):
        bt = c[key + "_by_type"]
        print("  %s" % label)
        for sv in ("Critical", "Important"):
            for ty in (TYPE_COMMON, TYPE_MEMORY):
                print("      %-10s %-34s %d"
                      % (sv, ty, bt.get("%s / %s" % (sv, ty), 0)))

    sel = out["selections"]
    print()
    print("  The four selections below OVERLAP by design. They answer")
    print("  different questions; an entry in two is a signal, not an error.")

    print()
    print("  VULNERABILITIES WARRANTING PARTICULAR ATTENTION  [%d]"
          % len(sel["attention"]))
    print("  Network-reachable, 9.0+, more commonly exploited type.")
    print("  Mechanical selection: expect obscure products, read before")
    print("  discarding. Critical and Important both included.")
    for r in sorted(sel["attention"], key=lambda x: -(x["base_score"] or 0)):
        print("      %-5s %-9s %-32s %-30s %s"
              % (r["base_score"], r["severity"] or "-",
                 (r["component"] or "?")[:32], strip_cvss_prefix(r["vector"]),
                 r["cve"]))
    if not sel["attention"]:
        print("      none this month")

    print()
    print("  KEY PRODUCTS AND COMPONENTS UNDER FIRE  [%d]"
          % len(sel["under_fire"]))
    print("  Network-reachable, 9.5+, UI:N, PR:N or L, and on the curated")
    print("  list of notable products. Absence may mean a lower score OR")
    print("  simply that the product is not on the list.")
    by_area = defaultdict(lambda: defaultdict(list))
    for r in sel["under_fire"]:
        by_area[watchlist_area(r["component"])][r["component"]].append(r)
    for area in AREA_ORDER:
        if area not in by_area:
            continue
        print("      %s" % area)
        for comp, rows in sorted(by_area[area].items()):
            rows.sort(key=lambda x: -(x["base_score"] or 0))
            print("          %-42s %-5s %-9s %s"
                  % (comp[:42], rows[0]["base_score"], rows[0]["severity"],
                     ", ".join(x["cve"] for x in rows)))
    if not sel["under_fire"]:
        print("      none this month")
    if sel["under_fire_residual"]:
        print("      Met every numeric test but NOT on the curated list [%d]:"
              % len(sel["under_fire_residual"]))
        for r in sorted(sel["under_fire_residual"],
                        key=lambda x: -(x["base_score"] or 0)):
            print("          %-5s %-42s %s"
                  % (r["base_score"], (r["component"] or "?")[:42], r["cve"]))

    print()
    print("  CODE EXECUTION FROM PREVIEWING A FILE OR MESSAGE  [%d]"
          % len(sel["preview_rce"]))
    print("  RCE triggered by rendering in a preview or reading pane, with no")
    print("  opening and no clicking. Critical and Important both included.")
    for r in sorted(sel["preview_rce"], key=lambda x: -(x["base_score"] or 0)):
        print("      %-5s %-9s %-40s %s"
              % (r["base_score"], r["severity"] or "-",
                 (r["component"] or "?")[:40], r["cve"]))
    if not sel["preview_rce"]:
        print("      none this month")

    print()
    print("  ESCAPES FROM A VIRTUAL MACHINE TO ITS HOST  [%d]"
          % len(sel["vm_escape"]))
    print("  Hyper-V entries whose impact crosses out of the guest VM.")
    print("  Critical and Important both included.")
    for r in sorted(sel["vm_escape"], key=lambda x: -(x["base_score"] or 0)):
        print("      %-5s %-9s %-32s %-30s %s"
              % (r["base_score"], r["severity"] or "-",
                 (r["component"] or "?")[:32], strip_cvss_prefix(r["vector"]),
                 r["cve"]))
    if not sel["vm_escape"]:
        print("      none this month")

    print()
    print("=" * 72)
    print("DATA-QUALITY FLAGS  (about Microsoft's published data)")
    print("=" * 72)
    if not out["flags"]:
        print("  none")
    for f, cves in sorted(out["flags"].items(), key=lambda kv: -len(kv[1])):
        print("  %4d  %s" % (len(cves), f))

    print()
    print("-" * 72)
    print("If an AI model writes the report from these figures, use this")
    print("attribution verbatim:")
    print()
    print(ATTRIB_AI)
    print("Methodology and caveats: %s" % REPO_URL)


# ---------------------------------------------------------------------------
# Output: a complete report in markdown, no AI required
# ---------------------------------------------------------------------------


def plural(n, singular, plural_form=None):
    """'1 record is' / '5 records are'. A count of exactly one is the common
    case for exploited CVEs, so hardcoded plurals surface most months."""
    word = singular if n == 1 else (plural_form or singular + "s")
    return "%d %s" % (n, word)


def isare(n):
    return "is" if n == 1 else "are"


def _md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(x) for x in r) + " |")
    return "\n".join(out)


def print_markdown(out):
    d, v, c, recs = out["document"], out["verify"], out["counts"], out["records"]
    cat = {k: [r for r in recs if r["category"] == k] for k, _ in CATEGORY_ORDER}
    sel = out["selections"]
    P = print

    P("# Microsoft Patch Tuesday — %s" % month_name(d))
    P("")
    P("An initial sort of Microsoft's published security update data. A "
      "starting point for review, not a patching recommendation.")
    P("")
    rel = (d.get("InitialReleaseDate") or "?")[:10]
    if d.get("revised") is True:
        revtext = ("The document has been revised since release; this reflects "
                   "its state as of %s, not release day."
                   % (d.get("CurrentReleaseDate") or "?")[:10])
    elif d.get("revised") is False:
        revtext = "The document has not been revised since release."
    else:
        revtext = "Revision status could not be determined from the document."
    P("Released %s. %s Microsoft revises and corrects these records "
      "frequently, so anything flagged below as incomplete may since have "
      "been filled in." % (rel, revtext))
    P("")
    if not v["ok"]:
        P("**VERIFICATION FAILED.** " + " ".join(v["problems"]))
        P("")
        P("No further analysis is offered on a document that failed "
          "verification.")
        return
    sev = c["severity_all_microsoft"]
    P("The release contains **%s**, of which **%d %s authored by "
      "Microsoft**. Of those, **%d %s rated Critical** and **%d Important**. "
      "Microsoft reports **%d as exploited in the wild** and **%d as publicly "
      "disclosed**."
      % (plural(c["total_entries"], "vulnerability entry", "vulnerability entries"),
         c["microsoft_authored"], isare(c["microsoft_authored"]),
         sev.get("Critical", 0), isare(sev.get("Critical", 0)),
         sev.get("Important", 0), len(c["exploited"]),
         len(c["publicly_disclosed"])))
    P("")
    P("After the categories in the next section are removed, the **main body "
      "is %s**." % plural(c["main_body"], "vulnerability", "vulnerabilities"))
    P("")
    P("**Main body by sub-classification** — all %d." % c["main_body"])
    P("")
    rows = []
    for key, label in (("network", "Network or adjacent subnet"),
                       ("local", "Local or physical access required"),
                       ("remainder", "Medium or low severity"),
                       ("missing_cvss", "Records missing CVSS data\\*")):
        g = cat[key]
        rows.append([label,
                     sum(1 for r in g if r["severity"] == "Critical"),
                     sum(1 for r in g if r["severity"] == "Important"),
                     len(g)])
    P(_md_table(["Reachability", "Critical", "Important", "Total"], rows))
    P("")
    P("\\* Microsoft published no attack vector or score for these, so they "
      "cannot be placed by reachability. They are listed individually below.")
    P("")
    P("**Main body by effect** — all %d. An entry can carry more than one "
      "effect, so counts exceed the total." % c["main_body"])
    P("")
    P(_md_table(["Effect", "Count"],
                [[i, n] for i, n in c["impacts_main_body"]]))
    P("")
    P("**Where the main body concentrates** — the components carrying the "
      "most entries, Critical and Important together, counted within the two "
      "reachability sub-classifications only. The %s below Important or with "
      "incomplete data %s no reachability group and %s excluded. High counts "
      "usually mean a component was audited heavily, not that it is more "
      "dangerous."
      % (plural(c["main_body"] - c["vector_groups"], "entry", "entries"),
         "has" if (c["main_body"] - c["vector_groups"]) == 1 else "have",
         isare(c["main_body"] - c["vector_groups"])))
    P("")
    net, loc = c["network_components"], c["local_components"]
    rows = []
    for i in range(max(len(net), len(loc))):
        a = ("%s" % net[i][0], net[i][1]) if i < len(net) else ("", "")
        b = ("%s" % loc[i][0], loc[i][1]) if i < len(loc) else ("", "")
        rows.append([a[0], a[1], b[0], b[1]])
    P(_md_table(["Network or adjacent", "n", "Local or physical", "n"], rows))
    P("")
    P("---")
    P("")
    P("## What was set aside, and why")
    P("")
    setaside = c["total_entries"] - c["main_body"]
    P("%d of the %d entries were removed before the main body was formed, in "
      "the order below." % (setaside, c["total_entries"]))
    P("")
    P("**%d %s CNA pass-through.** A CNA is the organisation that assigns a "
      "CVE number. Where that organisation is not Microsoft and no "
      "Microsoft-authored product is affected, Microsoft is distributing "
      "someone else's code and relaying their fix. Microsoft ships the code; "
      "Microsoft did not write it. Counts of exploited and publicly disclosed "
      "vulnerabilities in this report exclude these, following Microsoft's "
      "own published figures."
      % (len(cat["passthrough"]), isare(len(cat["passthrough"]))))
    P("")
    ed = cat["exploited_disclosed"]
    P("**%d %s reported by Microsoft as exploited in the wild or publicly "
      "disclosed.** Pulled out next, so that no later category can bury one."
      % (len(ed), isare(len(ed))))
    if ed:
        P("")
        rows = []
        for r in sorted(ed, key=lambda x: -(x["base_score"] or 0)):
            st = [s for s, on in (("Exploited", r["exploited"]),
                                  ("Publicly disclosed", r["publicly_disclosed"]))
                  if on]
            rows.append([r["cve"], r["component"] or "?", r["severity"] or "-",
                         r["base_score"] if r["base_score"] is not None else "-",
                         "`%s`" % strip_cvss_prefix(r["vector"]),
                         " + ".join(st)])
        P(_md_table(["CVE", "Component", "Severity", "CVSS", "Vector",
                     "Status"], rows))
    P("")
    na = cat["no_customer_action"]
    P("**%d %s in Microsoft-operated cloud infrastructure and require no "
      "customer action.** Microsoft has already fixed them and published them "
      "only for transparency. These are frequently among the most severe "
      "entries in a release." % (len(na), isare(len(na))))
    if na:
        P("")
        P(_md_table(["CVE", "Component", "Severity", "CVSS"],
                    [[r["cve"], r["component"] or "?", r["severity"] or "-",
                      r["base_score"] if r["base_score"] is not None else "-"]
                     for r in sorted(na, key=lambda x: -(x["base_score"] or 0))]))
    P("")
    P("**%d %s denial of service only** and %s set aside from further "
      "sorting. Entries carrying denial of service alongside another effect "
      "are kept."
      % (len(cat["denial_of_service"]), isare(len(cat["denial_of_service"])),
         isare(len(cat["denial_of_service"]))))
    P("")
    mob = cat["mobile"]
    P("")
    P("**%d %s iOS or Android app %s**, patched through an app store."
      % (len(mob), isare(len(mob)),
         "vulnerability" if len(mob) == 1 else "vulnerabilities"))
    if mob:
        P("")
        P(_md_table(["CVE", "Component", "Severity", "CVSS"],
                    [[r["cve"], r["component"] or "?", r["severity"] or "-",
                      r["base_score"] if r["base_score"] is not None else "-"]
                     for r in sorted(mob, key=lambda x: -(x["base_score"] or 0))]))
    vsc = cat["vscode"]
    P("")
    P("**%d %s Visual Studio Code**, which updates on its own cadence rather "
      "than through Windows Update." % (len(vsc), isare(len(vsc))))
    if vsc:
        top = sorted(vsc, key=lambda x: -(x["base_score"] or 0))[:3]
        P("The highest %s %s."
          % (isare(len(top)),
             ", ".join("%s at %s" % (r["cve"], r["base_score"]) for r in top)))
    mc = cat["missing_cvss"]
    if mc:
        P("")
        P("**%d %s missing CVSS data.** With no attack vector and no "
          "score, no filter can place them. They need manual lookup in the "
          "Security Update Guide. Check the publication date of any download "
          "before concluding data is absent — Microsoft often adds it in a "
          "later revision."
          % (len(mc), "record is" if len(mc) == 1 else "records are"))
        P("")
        P(_md_table(["CVE", "Component", "Severity"],
                    [[r["cve"], r["component"] or "?", r["severity"] or "-"]
                     for r in mc]))
    P("")
    P("---")
    P("")
    P("## Analysis")
    P("")
    P("This section applies a split Microsoft does not publish: **more "
      "commonly exploited vulnerability types** against **memory and "
      "concurrency safety vulnerabilities**. Memory safety bugs are exploited "
      "less often in practice because platform mitigations raise the cost; "
      "concurrency bugs because winning a race reliably is hard. Both are "
      "tendencies across a class, not predictions about any single entry. "
      "CWE sets version %s." % CWE_SET_VERSION)
    P("")
    P("**Main body by type** — the %s in the two reachability "
      "sub-classifications, which are the only ones that carry both a "
      "severity and a vector."
      % plural(c["vector_groups"], "entry", "entries"))
    P("")
    hdr = ["Reachability", "Critical, more commonly exploited",
           "Critical, memory or concurrency", "Important, more commonly "
           "exploited", "Important, memory or concurrency"]
    rows = []
    for key, label in (("network", "Network or adjacent"),
                       ("local", "Local or physical")):
        bt = c[key + "_by_type"]
        rows.append([label,
                     bt.get("Critical / " + TYPE_COMMON, 0),
                     bt.get("Critical / " + TYPE_MEMORY, 0),
                     bt.get("Important / " + TYPE_COMMON, 0),
                     bt.get("Important / " + TYPE_MEMORY, 0)])
    P(_md_table(hdr, rows))
    P("")
    P("The four selections below overlap by design. They answer different "
      "questions, and an entry appearing in two is a signal rather than a "
      "duplication.")
    P("")
    P("### Vulnerabilities warranting particular attention")
    P("")
    P("Reachable over a network, scored 9.0 or above, and of a more commonly "
      "exploited type. Critical and Important both included. Selection is "
      "mechanical and makes no judgement about how widely a product is "
      "deployed, so expect obscure entries — read them before discarding "
      "them.")
    P("")
    if sel["attention"]:
        P(_md_table(["Component", "Severity", "CVSS", "Vector", "CVE"],
                    [[r["component"] or "?", r["severity"] or "-",
                      r["base_score"], "`%s`" % strip_cvss_prefix(r["vector"]),
                      r["cve"]]
                     for r in sorted(sel["attention"],
                                     key=lambda x: -(x["base_score"] or 0))]))
    else:
        P("No entries met these conditions this month.")
    P("")
    P("### Key products and components under fire")
    P("")
    P("Products with at least one network-reachable vulnerability scored 9.5 "
      "or above requiring no user interaction and no more than low "
      "privileges. Critical and Important both included.")
    P("")
    P("Only products on a maintained list of components judged notable can "
      "appear here. A product may be absent because it scored lower, or "
      "simply because it is not on that list.")
    P("")
    if sel["under_fire"]:
        by_area = defaultdict(lambda: defaultdict(list))
        for r in sel["under_fire"]:
            by_area[watchlist_area(r["component"])][r["component"]].append(r)
        for area in AREA_ORDER:
            if area not in by_area:
                continue
            P("")
            P("#### %s" % area)
            P("")
            rows = []
            for comp, g in sorted(by_area[area].items()):
                g.sort(key=lambda x: -(x["base_score"] or 0))
                rows.append([comp, g[0]["base_score"], g[0]["severity"] or "-",
                             ", ".join(x["cve"] for x in g)])
            P(_md_table(["Product or component", "Top CVSS", "Severity",
                         "CVEs"], rows))
    else:
        P("No entries met these conditions this month.")
    if sel["under_fire_residual"]:
        P("")
        P("%s met every numeric test but %s in components outside that list. "
          "That residual is often as informative as the table above it."
          % (plural(len(sel["under_fire_residual"]), "entry", "entries"),
             isare(len(sel["under_fire_residual"]))))
        P("")
        P(_md_table(["Component", "CVSS", "Severity", "CVE"],
                    [[r["component"] or "?", r["base_score"],
                      r["severity"] or "-", r["cve"]]
                     for r in sorted(sel["under_fire_residual"],
                                     key=lambda x: -(x["base_score"] or 0))]))
    P("")
    P("### Code execution from previewing a file or message")
    P("")
    P("Remote code execution triggered when a file or message is rendered in "
      "a preview or reading pane, with no opening and no clicking. Critical "
      "and Important both included. This detection covers preview and reading "
      "pane rendering only; other no-interaction file triggers exist and are "
      "not caught.")
    P("")
    if sel["preview_rce"]:
        P(_md_table(["Component", "Severity", "CVSS", "CVE"],
                    [[r["component"] or "?", r["severity"] or "-",
                      r["base_score"], r["cve"]]
                     for r in sorted(sel["preview_rce"],
                                     key=lambda x: -(x["base_score"] or 0))]))
    else:
        P("No entries met these conditions this month.")
    P("")
    P("### Escapes from a virtual machine to its host")
    P("")
    P("Hyper-V vulnerabilities whose impact crosses out of the guest VM into "
      "the host. Critical and Important both included.")
    P("")
    if sel["vm_escape"]:
        P(_md_table(["Component", "Severity", "CVSS", "Vector", "CVE"],
                    [[r["component"] or "?", r["severity"] or "-",
                      r["base_score"], "`%s`" % strip_cvss_prefix(r["vector"]),
                      r["cve"]]
                     for r in sorted(sel["vm_escape"],
                                     key=lambda x: -(x["base_score"] or 0))]))
    else:
        P("No entries met these conditions this month.")
    P("")
    P("---")
    P("")
    P("## Notes on the source data")
    P("")
    P("These are observations about Microsoft's published records, not about "
      "the vulnerabilities. They matter because they show how much weight any "
      "single field deserves.")
    P("")
    if out["flags"]:
        P(_md_table(["Observation", "Entries"],
                    [[f.replace("_", " "), len(cves)]
                     for f, cves in sorted(out["flags"].items(),
                                           key=lambda kv: -len(kv[1]))]))
    else:
        P("No data-quality problems were detected in this document.")
    P("")
    P("---")
    P("")
    P("## Methodology")
    P("")
    P("Data is Microsoft's published CVRF document for the month, from the "
      "MSRC API. The category counts come from fields Microsoft publishes.")
    P("")
    P("Two things in the Analysis section do not. The first is the split "
      "between more commonly exploited vulnerability types and memory and "
      "concurrency safety vulnerabilities, assigned from each entry's CWE. "
      "The second is the key products and components table, whose contents "
      "depend on a curated list of products judged to be of particular "
      "importance.")
    P("")
    P("Full methodology, the CWE lists, the product list and caveats: %s"
      % REPO_URL)
    P("")
    P("---")
    P("")
    P(ATTRIB_TEMPLATE)


def print_analyst_dump(out):
    recs = out["records"]
    print("=" * 72)
    print("ANALYST DUMP -- full category membership")
    print("parser %s | CWE sets %s" % (VERSION, CWE_SET_VERSION))
    print("Type column: COMMON = more commonly exploited (includes entries")
    print("whose CWE is absent or on neither list), MEMCON = memory or")
    print("concurrency safety.")
    print("=" * 72)
    short = {TYPE_COMMON: "COMMON", TYPE_MEMORY: "MEMCON"}
    for key, label in CATEGORY_ORDER:
        rows = [r for r in recs if r["category"] == key]
        print()
        print("%s  [%d]" % (label.upper(), len(rows)))
        for r in sorted(rows, key=lambda x: (-(x["base_score"] or 0), x["cve"])):
            print("  %-16s %-5s %-9s %-7s %-30s %-9s %-42s %s"
                  % (r["cve"],
                     r["base_score"] if r["base_score"] is not None else "-",
                     r["severity"] or "-", short[r["vuln_type"]],
                     strip_cvss_prefix(r["vector"]), r["cwe_id"] or "-",
                     (r["component"] or "?")[:42], ",".join(r["flags"])))
    print()
    print("SELECTIONS (overlapping):")
    for k, rows in out["selections"].items():
        print("  %-24s %d  %s"
              % (k, len(rows), ", ".join(r["cve"] for r in rows)))


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", help="path to the CVRF XML file")
    ap.add_argument("--markdown", action="store_true",
                    help="emit a complete report in markdown, no AI required")
    ap.add_argument("--json", metavar="OUT", help="write full records to a file")
    ap.add_argument("--verify", action="store_true",
                    help="run upload verification only and exit")
    ap.add_argument("--expect", metavar="YYYY-Mon",
                    help="slug the document should be for, e.g. 2026-Sep")
    ap.add_argument("--analyst", action="store_true",
                    help="dump full category membership; for whoever maintains "
                         "the curated list and CWE sets, not for the report")
    args = ap.parse_args()

    if not os.path.exists(args.path):
        sys.stderr.write("No such file: %s\n" % args.path)
        return 2

    out = run(args.path, args.expect)
    ok = out["verify"]["ok"]

    if args.verify:
        print(json.dumps({"document": out["document"], "verify": out["verify"],
                          "entries": out["counts"]["total_entries"]}, indent=2))
        return 0 if ok else 1

    if args.markdown:
        print_markdown(out)
    elif args.analyst:
        if not ok:
            sys.stderr.write("VERIFICATION FAILED: %s\n"
                             % "; ".join(out["verify"]["problems"]))
        print_analyst_dump(out)
    else:
        print_report_data(out)

    # Consistent failure handling: nothing is written on a failed verification.
    if args.json:
        if not ok:
            sys.stderr.write(
                "Verification failed; JSON not written. Re-download.\n")
        else:
            with open(args.json, "w") as fh:
                json.dump(out, fh, indent=1)
            print("\nFull records written to %s" % args.json)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
```

## Appendix B — tests/make_fixtures.py

Regression tests. No network and no real release file needed. Save as
`tests/make_fixtures.py` alongside the parser and run before shipping any
change.

```python
#!/usr/bin/env python3
"""
Build synthetic CVRF documents exercising the defects fixed in v2.1, then
assert the parser categorises each one correctly.

Every fixture here corresponds to a bug that was reproduced by execution in
an external review of v2.0. Run this before shipping any change.

    python3 tests/make_fixtures.py
"""
import io, os, sys, tempfile
import contextlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import parse_cvrf as P

HEAD = '''<?xml version="1.0" encoding="utf-8"?>
<cvrfdoc xmlns="http://www.icasi.org/CVRF/schema/cvrf/1.1"
 xmlns:cvrf="http://www.icasi.org/CVRF/schema/cvrf/1.1"
 xmlns:vuln="http://www.icasi.org/CVRF/schema/vuln/1.1"
 xmlns:prod="http://www.icasi.org/CVRF/schema/prod/1.1">
<cvrf:DocumentTitle>January 2099 Security Updates</cvrf:DocumentTitle>
<cvrf:DocumentTracking>
<cvrf:InitialReleaseDate>2099-01-13T07:00:00</cvrf:InitialReleaseDate>
<cvrf:CurrentReleaseDate>2099-01-13T07:00:00</cvrf:CurrentReleaseDate>
</cvrf:DocumentTracking>
<prod:ProductTree>
{products}
</prod:ProductTree>
{vulns}
</cvrfdoc>
'''

def product(pid, name):
    return '<prod:FullProductName ProductID="%s">%s</prod:FullProductName>' % (pid, name)

def vuln(cve, title="Test Vulnerability", cwe=("CWE-122", "Heap-based Buffer Overflow"),
         impacts=("Remote Code Execution",), severity="Critical",
         scoresets=(("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),),
         pids=("1",), cna="Microsoft", car="Yes", exploit=None, faqs=()):
    parts = ['<vuln:Vulnerability xmlns:vuln="http://www.icasi.org/CVRF/schema/vuln/1.1">']
    parts.append("<vuln:Title>%s</vuln:Title>" % title)
    parts.append("<vuln:CVE>%s</vuln:CVE>" % cve)
    if cwe:
        parts.append('<vuln:CWE ID="%s">%s</vuln:CWE>' % cwe)
    parts.append("<vuln:ProductStatuses><vuln:Status Type=\"Known Affected\">")
    for p in pids:
        parts.append("<vuln:ProductID>%s</vuln:ProductID>" % p)
    parts.append("</vuln:Status></vuln:ProductStatuses>")
    parts.append("<vuln:Threats>")
    for p in pids:
        for i in impacts:
            parts.append('<vuln:Threat Type="Impact"><vuln:Description>%s'
                         '</vuln:Description></vuln:Threat>' % i)
        if severity:
            parts.append('<vuln:Threat Type="Severity"><vuln:Description>%s'
                         '</vuln:Description></vuln:Threat>' % severity)
    if exploit:
        parts.append('<vuln:Threat Type="Exploit Status"><vuln:Description>%s'
                     '</vuln:Description></vuln:Threat>' % exploit)
    parts.append("</vuln:Threats>")
    if scoresets:
        parts.append("<vuln:CVSSScoreSets>")
        for ss in scoresets:
            parts.append("<vuln:ScoreSet>")
            if ss[0] is not None:
                parts.append("<vuln:BaseScore>%s</vuln:BaseScore>" % ss[0])
            if ss[1] is not None:
                parts.append("<vuln:Vector>%s</vuln:Vector>" % ss[1])
            parts.append("</vuln:ScoreSet>")
        parts.append("</vuln:CVSSScoreSets>")
    parts.append("<vuln:Notes>")
    parts.append('<vuln:Note Type="Description" Title="Description">test</vuln:Note>')
    parts.append('<vuln:Note Type="Tag" Title="Tag">%s</vuln:Note>' % title.split(" Test")[0])
    parts.append('<vuln:Note Type="CNA" Title="CNA">%s</vuln:Note>' % cna)
    if car is not None:
        parts.append('<vuln:Note Type="Other" Title="Customer Action Required">%s</vuln:Note>' % car)
    for f in faqs:
        parts.append('<vuln:Note Type="FAQ" Title="FAQ">%s</vuln:Note>' % f)
    parts.append("</vuln:Notes>")
    parts.append("</vuln:Vulnerability>")
    return "".join(parts)


def build(products, vulns):
    fd, path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    with open(path, "w") as fh:
        fh.write(HEAD.format(products="\n".join(products), vulns="\n".join(vulns)))
    return path


def check(name, path, cve, expect_category=None, expect_score=None,
          expect_av=None, expect_type=None, in_selection=None):
    out = P.run(path)
    rec = next((r for r in out["records"] if r["cve"] == cve), None)
    if rec is None:
        return "FAIL  %s: %s not parsed" % (name, cve)
    problems = []
    if expect_category and rec["category"] != expect_category:
        problems.append("category %s != %s" % (rec["category"], expect_category))
    if expect_score is not None and rec["base_score"] != expect_score:
        problems.append("score %s != %s" % (rec["base_score"], expect_score))
    if expect_av and rec["av"] != expect_av:
        problems.append("av %s != %s" % (rec["av"], expect_av))
    if expect_type and rec["vuln_type"] != expect_type:
        problems.append("type %r != %r" % (rec["vuln_type"], expect_type))
    if in_selection:
        sel = out["selections"].get(in_selection, [])
        if not any(r["cve"] == cve for r in sel):
            problems.append("absent from selection %s" % in_selection)
    return ("PASS  " + name) if not problems else ("FAIL  %s: %s" % (name, "; ".join(problems)))


def markdown_of(path):
    """Capture --markdown output for assertion."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        P.print_markdown(P.run(path))
    return buf.getvalue()


def check_md(name, path, must_contain=(), must_not_contain=()):
    txt = markdown_of(path)
    problems = []
    for t in must_contain:
        if t not in txt:
            problems.append("missing %r" % t)
    for t in must_not_contain:
        if t in txt:
            problems.append("unexpectedly present %r" % t)
    return ("PASS  " + name) if not problems else ("FAIL  %s: %s"
                                                   % (name, "; ".join(problems)))


def main():
    PRODS = [product("1", "Windows 11 Version 24H2 for x64-based Systems"),
             product("2", "Microsoft Edge (Chromium-based)"),
             product("3", "Microsoft Edge (Chromium-based) Extended Stable"),
             product("4", "azl3 openssl 3.3.5-5 on Azure Linux 3.0")]
    results = []

    # 1. Mixed scoresets, one without a BaseScore. v2.0 raised TypeError.
    p = build(PRODS, [vuln("CVE-2099-0001",
        scoresets=((None, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
                   ("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")))])
    results.append(check("mixed scoresets do not crash", p, "CVE-2099-0001",
                         expect_score=9.8, expect_av="N"))

    # 2. Lexicographic sort would pick 7.8 over 9.8.
    p = build(PRODS, [vuln("CVE-2099-0002",
        scoresets=(("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
                   ("7.8", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")))])
    results.append(check("highest score wins, not string order", p,
                         "CVE-2099-0002", expect_score=9.8, expect_av="N",
                         expect_category="network"))

    # 3. Critical scope-changed Hyper-V with a SECONDARY DoS impact.
    p = build(PRODS, [vuln("CVE-2099-0003", title="Windows Hyper-V Test",
        impacts=("Remote Code Execution", "Denial of Service"),
        scoresets=(("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),))])
    results.append(check("secondary DoS is not set aside", p, "CVE-2099-0003",
                         expect_category="network", in_selection="vm_escape"))

    # 4. DoS as the only impact IS set aside.
    p = build(PRODS, [vuln("CVE-2099-0004", impacts=("Denial of Service",))])
    results.append(check("DoS-only is set aside", p, "CVE-2099-0004",
                         expect_category="denial_of_service"))

    # 5. Preview-pane RCE that is NOT memory-safety must still reach
    #    the preview selection, even though selection 1 also claims it.
    p = build(PRODS, [vuln("CVE-2099-0005", title="Microsoft Office Outlook Test",
        cwe=("CWE-20", "Improper Input Validation"),
        faqs=("Is the Preview Pane an attack vector for this vulnerability? Yes",))])
    results.append(check("preview selection is not starved", p, "CVE-2099-0005",
                         in_selection="preview_rce"))
    results.append(check("  and also appears in attention", p, "CVE-2099-0005",
                         in_selection="attention"))

    # 6. Absent Customer Action Required must NOT be set aside.
    p = build(PRODS, [vuln("CVE-2099-0006", title="Windows TCP/IP Test", car=None)])
    results.append(check("absent customer-action note stays in", p,
                         "CVE-2099-0006", expect_category="network"))

    # 7. Explicit No IS set aside.
    p = build(PRODS, [vuln("CVE-2099-0007", car="No")])
    results.append(check("explicit No is set aside", p, "CVE-2099-0007",
                         expect_category="no_customer_action"))

    # 8. Edge variant name must still be pass-through.
    p = build(PRODS, [vuln("CVE-2099-0008", pids=("2", "3"), cna="Chrome")])
    results.append(check("Edge variant name is pass-through", p,
                         "CVE-2099-0008", expect_category="passthrough"))

    # 9. Mixed Edge + Azure Linux is still pass-through.
    p = build(PRODS, [vuln("CVE-2099-0009", pids=("2", "4"), cna="openssl")])
    results.append(check("mixed third-party families are pass-through", p,
                         "CVE-2099-0009", expect_category="passthrough"))

    # 10. Third-party CNA that also hits a Microsoft product is RETAINED.
    p = build(PRODS, [vuln("CVE-2099-0010", pids=("1", "4"), cna="openssl")])
    results.append(check("third-party CNA plus MS product is retained", p,
                         "CVE-2099-0010", expect_category="network"))

    # 11. A missing CWE classifies as more commonly exploited, deliberately.
    #     The lists name the memory and concurrency side only; everything else
    #     falls through, and a genuinely absent CWE still raises no_cwe.
    p = build(PRODS, [vuln("CVE-2099-0011", cwe=None)])
    results.append(check("missing CWE falls through to the common type", p,
                         "CVE-2099-0011", expect_type=P.TYPE_COMMON))
    o = P.run(p)
    results.append(("PASS  " if "no_cwe" in o["records"][0]["flags"] else "FAIL  ")
                   + "  and still raises no_cwe")

    # 12b. 10.0 vs 9.8 -- the case a max-by-STRING bug would fail. Fixture 2
    #      above catches min-by-string; this one catches max-by-string.
    p = build(PRODS, [vuln("CVE-2099-0013",
        scoresets=(("9.8", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
                   ("10.0", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")))])
    results.append(check("10.0 beats 9.8, not string order", p,
                         "CVE-2099-0013", expect_score=10.0, expect_av="N"))

    # 12c. A BaseScore that will not parse must raise a flag rather than
    #      silently dropping the entry out of every score gate.
    p = build(PRODS, [vuln("CVE-2099-0014",
        scoresets=(("N/A", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),))])
    o = P.run(p)
    r = o["records"][0]
    ok = ("base_score_unparseable" in r["flags"] and r["category"] == "network")
    results.append(("PASS  " if ok else "FAIL  ")
                   + "unparseable BaseScore is flagged, not silent")

    # 12d. --markdown: pluralisation on a count of exactly one.
    p = build(PRODS, [vuln("CVE-2099-0015", pids=("2",), cna="Chrome"),
                      vuln("CVE-2099-0016", car="No"),
                      vuln("CVE-2099-0017")])
    results.append(check_md("markdown says '1 is', never '1 are'", p,
                            must_not_contain=("**1 are ", "1 records are",
                                              "1 entries ")))

    # 12e. --markdown: set-aside order matches CATEGORY_ORDER.
    p = build(PRODS, [vuln("CVE-2099-0018", title="Teams for Android Test",
                           pids=("1",)),
                      vuln("CVE-2099-0019", title="Visual Studio Code Test")])
    txt = markdown_of(p)
    ok = txt.index("iOS or Android app") < txt.index("Visual Studio Code**")
    results.append(("PASS  " if ok else "FAIL  ")
                   + "markdown set-asides follow removal order")

    # 12f. --markdown: data-quality section is present.
    results.append(check_md("markdown carries a source-data section", p,
                            must_contain=("Notes on the source data",)))

    # 12g. --markdown: a failed verification produces no analysis.
    fd, bad = tempfile.mkstemp(suffix=".xml"); os.close(fd)
    good = open(p).read().replace("January 2099 Security Updates",
                                  "January 2099 Early Security Updates")
    open(bad, "w").write(good)
    results.append(check_md("markdown stops on failed verification", bad,
                            must_contain=("VERIFICATION FAILED",),
                            must_not_contain=("## Analysis",)))

    # 13. Exploited entry that is ALSO pass-through: pass-through wins by
    #     design, and the headline counters must not report it.
    p = build(PRODS, [vuln("CVE-2099-0012", pids=("2",), cna="Chrome",
        exploit="Publicly Disclosed:No;Exploited:Yes")])
    out = P.run(p)
    ok = (out["counts"]["exploited"] == []
          and out["counts"]["by_category"].get("passthrough") == 1)
    results.append(("PASS  " if ok else "FAIL  ")
                   + "exploited counters exclude pass-through")

    for r in results:
        print(r)
    fails = [r for r in results if r.startswith("FAIL")]
    print()
    print("%d passed, %d failed" % (len(results) - len(fails), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
```

## Appendix C — porting notes

These describe moving this material to another platform. Where they refer to
copying "the body of SKILL.md", they mean everything in this document above
the Appendices heading.

Version 2.2. The substance is platform-neutral by design. Only a thin wrapper
is Anthropic-specific.

### Three ways this gets used

**1. A model with code execution.** The normal path. The model runs
`parse_cvrf.py`, reads the printed figures and writes the report.

**2. A model without code execution.** Someone runs the script elsewhere and
pastes its printed output into the conversation. That output is about two
hundred lines and fits comfortably.

**Do not use `--json` for this.** An 11 MB release produces roughly 3 MB of
JSON — several hundred thousand tokens. It will not fit in any chat context.
The printed figures are what the report needs; the JSON is for programmatic
consumers.

**3. No model at all.** `--markdown` emits a finished report with fixed
wording. Less fluent than a model-written one, entirely usable, and it
depends on no AI.

### What is Claude-specific

Only the YAML frontmatter at the top of `SKILL.md` — the `name` and
`description` fields — and the `.skill` package format. Nothing in the body
depends on the frontmatter having been read.

### What transfers unchanged

- The entire body of `SKILL.md` below the frontmatter.
- `parse_cvrf.py`, standard-library Python 3.8+.
- The report structure and its hard limits.

### OpenAI (Custom GPT or Project)

1. Copy everything in `SKILL.md` below the `---` frontmatter block into the
   GPT's Instructions field, or a project's custom instructions.
2. Upload `parse_cvrf.py` as a knowledge file.
3. Enable Code Interpreter for path 1 above. Without it, use path 2.

Acquisition and verification work the same way: the user downloads the CVRF
from Microsoft's URL and uploads it.

### Google Gemini (Gem)

Same approach. Body text into the Gem's instructions, script attached, code
execution enabled if available.

### Command reference

```
python3 parse_cvrf.py FILE                      # figures for a report
python3 parse_cvrf.py FILE --markdown           # finished report, no AI
python3 parse_cvrf.py FILE --verify --expect 2026-Sep
python3 parse_cvrf.py FILE --json records.json  # full records, for code
python3 parse_cvrf.py FILE --analyst            # membership dump
python3 tests/make_fixtures.py                  # regression tests
```

`--analyst` prints every category's full membership with each entry's type
assignment and data-quality flags, plus the four selections. It is for
whoever maintains the curated product list and the CWE sets.

Nothing is written on a failed verification, including `--json`.

### Attribution differs by mode

`--markdown` output claims the wording as the author's, because in that mode
it is. When a model writes the narrative, the attribution must say so — the
script prints the correct form at the foot of its figures output. The two
forms are not interchangeable.

### Regression tests

`tests/make_fixtures.py` builds synthetic CVRF documents exercising every
defect fixed in v2.1 and asserts the parser handles each correctly. It needs
no network and no real release file. Run it before shipping any change.

Each fixture corresponds to a bug that was reproduced by execution in an
external review — a crash on mixed scoresets, a score chosen by string sort,
a Critical entry discarded for a secondary denial-of-service label, a
selection starved by an earlier one, an entry removed for a missing note.

### If you reimplement the parser in another language

**Per-product element repetition.** `Threat` and `ScoreSet` elements repeat
once for every affected ProductID. A 30-SKU entry carries thirty identical
severity elements and thirty identical scoresets. Deduplicate on read.

**Choosing among scoresets.** After deduplication an entry can still carry
several distinct scoresets. Choose by numeric base score, not by sorting the
raw values — string ordering puts "10.0" before "7.8" before "9.8", and one
such entry filed a network 9.8 as a local 7.8. Prefer a scoreset that
actually carries a vector, and flag the divergence.

**Category order matters.** Pass-through first, then exploited and disclosed.
Getting that order wrong can bury an exploited vulnerability inside a later
category. A consequence of pass-through running first is that relayed
third-party fixes are never counted as exploited. That is deliberate: this
tool follows Microsoft's own published figures so readers see the same
numbers Microsoft promotes.

**"Main body" means everything left** after the set-asides, with four
sub-classifications inside it. Only the two vector groups can be split by
reachability or type; tables counting only those must say so.

**Denial of service must be the sole impact** before an entry is set aside.

**Pluralise counts.** A count of exactly one is the common case for exploited
CVEs, and hardcoded plurals produce "1 records are missing" in the one output
mode no human reviews before publication.

**File size.** In PowerShell, casting a large file with `[xml]` works but is
slow and memory-hungry. `XmlReader` streaming is the better approach. In
Python, `ElementTree` handles a 12 MB release in about a second and 70 MB of
memory, so streaming is unnecessary there.

### Architecture, if you extend it

1. **Parser** — read the XML, normalise, emit one record per CVE plus
   data-quality flags. Pure mechanical work.
2. **Categorisation** — consume normalised records only, never the XML.
3. **Analysis and report** — the split, the curated list, the selections and
   the writing.

Layers 1 and 2 port cleanly to any language.
