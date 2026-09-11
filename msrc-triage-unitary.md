---
name: msrc-triage
description: Acquire, verify, parse and bucket a Microsoft Patch Tuesday security update release (MSRC CVRF XML) into an initial at-a-glance overview and a structured set of buckets ready for analyst review. Use this whenever the user mentions Patch Tuesday, MSRC, CVRF, a monthly Microsoft security release, a file named like 2026-Sep.xml, the Security Update Guide, or asks to triage, sort, bucket, or get an overview of a month's Microsoft vulnerabilities — including when they only say something like "let's do this month's patches" or "the September release is out."
---

# Microsoft Patch Tuesday: acquisition, verification and initial bucketing

This document describes a repeatable first pass over a single month's
Microsoft security release. It ends where analyst judgement begins.

The work divides into two parts, and keeping them separate is the point.

**Part 1 reports facts.** Every number comes from a field Microsoft
published or from a mechanical rule applied to one. A reader can check any
of it against the source file.

**Part 2 applies a classification model** that is the analyst's, not
Microsoft's. It is useful, it is also revisable, and it is labelled as such
so nobody mistakes it for reported data.

A companion script, `parse_cvrf.py`, does all the parsing and bucketing. It
uses only the Python standard library and runs anywhere, including outside
any AI tool. Everything it produces is described in prose below as well, so
the logic is followable without running it.

---

## Before anything else: establish the date

Compute today's date from the environment rather than assuming it. A stale
date produces a link to the wrong month, and the user will not notice until
the whole pass has been run on the wrong file.

---

## Step 1 — Work out which release the user wants

Microsoft publishes each monthly release at a predictable URL:

```
https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/YYYY-Mon
```

where `Mon` is the three-letter English month abbreviation — `2026-Sep`,
`2026-Aug`, `2026-Jan`.

Patch Tuesday is **the second Tuesday of the month**. So:

- If today is on or after this month's second Tuesday, the user almost
  certainly wants **this month**.
- If today is before it, this month's data does not exist yet. They want
  **last month**.

State which month you have selected and why, so an incorrect assumption is
visible immediately.

---

## Step 2 — Have the user download the file

The file cannot be fetched programmatically in most environments. Hand the
user the URL and let their browser do it.

**Present the URL as a rendered markdown link, not as code.** A URL inside
backticks or a code fence renders as literal text the user cannot click or
long-press, which defeats the whole "right-click and Save Link As"
instruction and is worse on mobile, where press-and-hold needs a real link.
Give the bare URL separately, as a copy-paste fallback.

Tell them, in substance — note the link form, and that the example below is
deliberately not in a code fence:

Here is this month's release data: [September 2026 security update data](https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep)

**Save it to a file rather than opening it in the browser.** In a desktop
browser, right-click the link and choose "Save Link As". On mobile, press
and hold, then choose the save or download option.

Opening it directly is a bad idea: recent releases are 20–25 MB of XML, and
browsers that try to render that will often hang or crash the tab.

If the link does not render where you are, the URL is
https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep — copy it into a
browser address bar and use the browser's save option.

Then upload the saved file here. If you want a different month instead,
tell me which and I will give you that URL.

Do not attempt to fetch the URL yourself first and fall back to asking.
Network access to Microsoft's API is blocked in most AI execution
environments, and community mirrors of this data have served the wrong
document — see Step 3.

---

## Step 3 — Verify the uploaded file before processing it

This step exists because a wrong file does not announce itself. It parses
cleanly, produces plausible numbers, and silently corrupts everything
downstream.

Check three things:

1. **DocumentTitle must not contain "Early".** Microsoft publishes a
   pre-Patch-Tuesday preview called "*Month Year* Early Security Updates".
   It is a different, much smaller document. A community mirror was
   observed serving this file under the normal monthly filename.
2. **InitialReleaseDate should be the second Tuesday** of the month it
   claims, and should match the month requested.
3. **Entry count should be plausible.** Recent monthly releases have run
   from several hundred to over a thousand CVEs. A couple of hundred
   suggests a preview or a partial file.

If the title check or the month check fails, **stop and tell the user to
re-download**. Do not proceed on a document that failed verification.

Run: `python3 parse_cvrf.py <file> --verify --expect 2026-Sep`

---

## Step 4 — Parse and bucket

Run one of:

```
python3 parse_cvrf.py <file> --expect 2026-Sep              # full output
python3 parse_cvrf.py <file> --expect 2026-Sep --brief      # overview only
python3 parse_cvrf.py <file> --expect 2026-Sep --json out.json
```

The script **lists** the no-customer-action entries, the set-aside entries
and the no-CVSS exception list in full, rather than only counting them, and
summarises denial-of-service entries by component. Counting without listing
was an early defect: the prose said to list them and the tool did not.

The script normalises every vulnerability entry and assigns it to exactly
one bucket. The rules, in order:

### Bucket: pass-through

Microsoft relays some fixes from upstream vendors rather than authoring
them. An entry is pass-through when **both**:

- the assigning CNA is not Microsoft, **and**
- every affected product belongs to a third-party-distributed family —
  Chromium-based Edge, or Azure Linux / Mariner / CBL packages.

Both conditions matter. An entry with a non-Microsoft CNA that *also*
affects a Microsoft-shipped product — an OpenSSL flaw that lands in Visual
Studio, say — is **retained**, because a customer still has to patch
something Microsoft ships.

### Bucket: no customer action required

Microsoft sets a "Customer Action Required" note to `No` on
already-mitigated cloud service CVEs, published for transparency. There is
nothing to install.

**Report the count and list these, do not discard them silently.** They are
often the most severe entries in a release — a recent month put nine
Critical cloud CVEs here including two rated 10.0, all authorization or
authentication failures in identity services. Nothing to patch, but a
significant fact about the release.

### Bucket: denial of service

Entries whose Impact includes Denial of Service. Reported as a count, set
aside from further triage.

### Optional set-asides

These are **review-track choices, not exclusions**, and each can be turned
off independently. They exist because these products patch through channels
other than Windows Update and often warrant separate handling:

- **Mobile app store distribution** — products named "… for Android" or
  "… for iOS". Disable with `--no-mobile-setaside`.
- **Visual Studio Code** — auto-updating and on a separate cadence.
  Disable with `--no-vscode-setaside`.

If the user has not expressed a preference, tell them these set-asides are
active and can be switched off. A user who cares specifically about VS Code
would be surprised to find it pre-segregated.

### The remainder: pools

Everything left is "for processing" and is divided by attack vector and
severity:

- **Pool 1** — `AV:N` or `AV:A`, severity Critical or Important.
  Network-reachable. Usually worked first.
- **Pool 2** — `AV:L` or `AV:P`, severity Critical or Important.
- **Pool 3** — everything else. Often empty; it exists as a safety net so
  nothing falls through unnoticed.

**Unpooled — no CVSS vector.** Some entries ship with no CVSS ScoreSet at
all. They have no attack vector, so they cannot be pooled. **Never guess or
silently drop them.** Report them as a named exception list and tell the
user to look each one up manually in the Security Update Guide and supply
the vector. In a recent month five entries had no scoreset, and four were
silently skipped by vector-based filtering until the gap was caught — one
of them a Critical Outlook RCE where the preview pane was a confirmed
attack vector.

---

## Step 5 — Output

Use this structure every month, so releases are comparable.

### Part 1 — Reported facts

```
DOCUMENT
  Title, InitialReleaseDate, CurrentReleaseDate, total entries
  Verification result

BUCKETS
  Pass-through                       n
  No customer action required        n   (list them — often the most severe)
  Denial of service                  n
  Set aside: mobile app stores       n
  Set aside: Visual Studio Code      n
  For processing                     n

POOLS
  Pool 1  network / adjacent, Critical or Important    n
            by severity
  Pool 2  local / physical, Critical or Important      n
            by severity
  Pool 3  remainder                                    n
  UNPOOLED  no CVSS vector — manual lookup required    n
            (list every CVE)

EXPLOITED / PUBLICLY DISCLOSED
  Listed individually. These are Microsoft-reported facts, taken from the
  Exploit Status field.

COMPONENTS
  Top components by count, per pool. Concentration is the fastest signal
  that a release is unusual — one recent month had 61 entries in a single
  service, which said more about the month than any severity breakdown did.

CWE DISTRIBUTION
  Raw counts as reported. No interpretation here.

DATA-QUALITY FLAGS
  One line per check, with counts. These are observations about Microsoft's
  published data, not about the vulnerabilities.
```

Report every data-quality flag the script raises. The checks are:

| Flag | What it means |
|---|---|
| `no_cvss_scoreset` | No CVSS at all. Requires manual lookup. |
| `no_cwe` | No CWE element. |
| `no_acknowledgment` | No credited finder. |
| `no_faq` | No FAQ notes; exploitation path undocumented. |
| `no_description` | Description note absent or empty. |
| `unmapped_product_id` | A ProductID with no matching product name. |
| `severity_varies_by_product` | Severity differs across affected products. |
| `title_impact_mismatch` | Title says one impact, the Impact field says another. |
| `desc_network_but_vector_local` | Description says "over a network", vector says `AV:L`. |
| `desc_local_but_vector_network` | Description says "locally", vector says `AV:N`. |
| `ui_none_but_faq_describes_user_action` | `UI:N` but the FAQ describes convincing a user to act. |
| `ui_required_but_faq_says_none` | `UI:R` but the FAQ says no interaction is needed. |
| `pr_none_but_text_says_authenticated` | `PR:N` but the text describes an authenticated attacker. |
| `pr_required_but_desc_says_unauthenticated` | `PR:L`/`PR:H` but the description says unauthorized. |
| `contradictory_duplicate_faq` | The same FAQ question appears twice with different answers. |
| `exploited_but_temporal_says_unproven` | Flagged exploited but the temporal vector says `E:U`. |

These are worth reporting because they materially affect how much weight
any single field deserves. Microsoft's FAQ text in particular is often
boilerplate that contradicts the record's own CWE or CVSS vector.

### Part 2 — Analyst classification

Label this section clearly as a model applied on top of the reported data,
not as reported data itself.

The classification splits vulnerabilities by whether platform memory-safety
mitigations are likely to obstruct exploitation:

- **Half 2 — memory and concurrency safety.** Exploitation requires
  corrupting memory in ways ASLR, DEP, CFG and heap hardening are designed
  to obstruct.
- **Half 1 — logic, type safety and everything else.** Exploitation
  proceeds through well-formed memory; those mitigations have nothing to
  catch.

### The CWE sets, version 2026-09-11

These sets are **informed by** MITRE's own categories, which were consulted
to catch classes that had simply never come up in the data:

- **CWE-1399, Comprehensive Categorization: Memory Safety** (37 members)
- **CWE-1401, Comprehensive Categorization: Concurrency** (37 members)

Both category IDs are marked PROHIBITED for mapping real vulnerabilities —
they are organisational groupings, so use the member weaknesses, never the
category ID itself.

**MITRE's membership is a reference, not the authority here.** It is used to
populate the obvious cases — weaknesses that plainly concern memory or
concurrency safety. It does not settle the ambiguous ones, and it does not
override the test below.

**Memory safety (38):**

```
CWE-119, 120, 121, 122, 123, 124, 125, 126, 127, 129, 131, 170, 190, 191,
CWE-197, 415, 416, 466, 476, 562, 587, 590, 680, 681, 690, 761, 762, 763,
CWE-786, 787, 788, 805, 806, 822, 823, 824, 825, 908
```

**Concurrency (25):**

```
CWE-362, 363, 364, 366, 367, 368, 412, 413, 414, 432, 567, 591, 609, 663,
CWE-667, 689, 764, 765, 820, 821, 828, 831, 832, 833, 1223
```

### Documented departures from MITRE

Every difference from MITRE's membership is deliberate. Record them: an
undocumented divergence is indistinguishable from an oversight.

**Seven added that MITRE does not list under CWE-1399.** MITRE files the
integer-arithmetic family elsewhere and treats the overflow consequence as
the separate CWE-680 chain. They are included here because the mitigation
test asks about consequence, not root cause:

```
CWE-170  Improper Null Termination            (produces an over-read)
CWE-190  Integer Overflow or Wraparound
CWE-191  Integer Underflow
CWE-197  Numeric Truncation Error
CWE-476  NULL Pointer Dereference
CWE-681  Incorrect Conversion between Numeric Types
CWE-908  Use of Uninitialized Resource
```

**Six MITRE members held out as debatable.** Each is memory-*related* but
fails the mitigation test — nothing is corrupted, so ASLR, DEP, CFG and
heap hardening have nothing to catch:

```
CWE-134  Use of Externally-Controlled Format String
         Memory corruption is the classic consequence, but the weakness
         itself is input handling. Revisit if a month turns on it.
CWE-188  Reliance on Data/Memory Layout — a design assumption
CWE-198  Use of Incorrect Byte Ordering — a correctness bug
CWE-244  Improper Clearing of Heap Memory Before Release — disclosure,
         not an access violation
CWE-401  Missing Release of Memory after Effective Lifetime — a leak;
         availability, not corruption
CWE-789  Memory Allocation with Excessive Size Value — usually DoS
```

**Twelve CWE-1401 members excluded as inapplicable.** Eight are language or
framework specific — Java, EJB and POSIX-signal patterns that do not arise
in the Windows components Microsoft reports on (CWE-479, 543, 558, 572,
574, 1058, 1088, 1096). Four are hardware logic and cannot appear in a
software patch release (CWE-1232, 1234, 1264, 1298).

**CWE-843 type confusion is deliberately excluded.** Type confusion splits
into two behaviours. Confusions where one object is treated as a *larger*
type, so reads and writes land outside the allocation, are heap overflows
by another name and the mitigations engage. Confusions where both objects
are validly allocated and the same size corrupt nothing — the program
merely does the wrong thing with well-formed memory, and mitigations
designed to detect corruption see nothing amiss. The second kind is more
dangerous per instance for exactly that reason. Published records never say
which kind a given entry is, so the class stays in Half 1.

### The lists are a starting point, not the decision

The sets above resolve the clear cases quickly. They do not resolve every
case, and applying them mechanically will sometimes produce the wrong
answer. Two situations call for overriding the list:

**1. The published CWE looks wrong.** Microsoft's CWE assignment is
frequently contradicted by other fields in the same record — the FAQ text,
the description, or the CVSS vector. A record tagged with a memory-safety
CWE whose own FAQ describes a credential disclosure, or tagged with a logic
CWE whose FAQ describes a heap over-read, is telling you something the CWE
field alone does not. Where the rest of an entry gives reason to doubt the
CWE, weigh that evidence and classify on what the record as a whole says.

**2. The mitigations would not be in the way.** This is the governing test,
and the CWE lists are only a proxy for it:

> Would exploitation require overcoming the platform's memory-safety
> mitigations — ASLR, DEP, CFG, ACG, arbitrary code guard, heap hardening —
> and the general difficulty those impose on this class of bug on modern
> Microsoft platforms?

If the answer is no — if the bug can be exploited without defeating any of
that — it belongs in **Half 1**, regardless of which list its CWE appears
on. Half 1 is not "not about memory"; it is "the hard part of exploiting
this is not the part the mitigations make hard."

This is why CWE-843 type confusion sits in Half 1 despite being
memory-adjacent. It is also why an entry may move between halves on the
strength of a single sentence in a FAQ. Exercise the judgement; the lists
exist to spare you from exercising it thirty times on obvious cases, not to
replace it on the cases that matter.

**Re-check the MITRE categories periodically.** They gain members between
CWE releases, and consulting them catches classes that have not yet
appeared in any month's data. Version-stamp the sets whenever a split is
reported, and treat month-over-month comparisons of Part 2 with that in
mind. Part 1 is unaffected by any of these revisions.

Report, for each pool:

```
Pool N
  Critical  + Half 1 (more exploitable types)     n
  Critical  + Half 2 (memory / concurrency)       n
  Important + Half 1                              n
  Important + Half 2                              n
```

Pool 3 rarely needs the breakdown.

Also break out **zero-days and publicly disclosed entries** here, with the
Exploit Status text quoted, since these usually warrant separate treatment
in any published output.

---

## Part 3 — Some vulnerabilities of obvious interest

Label this section as judgement too. It is a **surfacing aid, not a
priority list**: it says "these are the kinds of entry that usually repay a
second look," not "patch these first."

Present it **component-led**, not one row per CVE. Group the hits under
their component, show the count, the top score, how many are Critical, and
the CVE numbers. A month where one service has eight entries should read as
one line saying so, not as eight near-identical rows. This also removes any
need for a per-component cap.

Four sublists, applied in order, each excluding entries already listed
above it.

### 1. Network-reachable, high-scored, more-exploitable class

```
Pool 1  +  AV:N  +  CVSS >= 9.0  +  Half 1
```

High-scored network entries where the mitigations are not the obstacle.
Small by construction — most high scores in any month are memory-safety.

### 2. Server products and network-reachable components of established interest

```
Pool 1  +  CVSS >= 9.5  +  UI:N  +  PR:N or PR:L  +  component watchlist match
```

Every constraint here earns its place. Without `UI:N` the list fills with
document and media parsers that qualify only on Microsoft's Critical
rating. Without the privilege constraint it picks up bugs needing
administrator access already. Without the score floor it returns most of
the release.

The watchlist is below. **It is a judgement about what usually matters, not
a fact about the release**, and different readers will weigh these
differently — someone running Exchange but no AD CS has different
priorities. Say so when presenting the output, and also present the
entries that met every numeric condition but matched no watchlist entry.
That residual list is often the more interesting half: it shows what the
watchlist is filtering out.

**Match on substrings, not exact tags.** Microsoft fragments functional
areas across many component names — DNS appears as both "Windows DNS" and
"Role: DNS Server"; remote access spans RRAS, SSTP, IKE Extension, Remote
Access Connection Manager and Remote Access API; identity spans a dozen
tags. Exact matching silently misses half of what it should catch.

```
Identity & authentication
    Active Directory, AD CS, AD FS, Kerberos, Key Distribution Center,
    lsasrv, Local Security Authority, Netlogon, LDAP, Credential Guard,
    Credential Providers, Smart Card, Online Certificate Status,
    Authentication Methods, Entra, Azure Active Directory,
    Digest Authentication, Host Guardian, Winlogon, Microsoft Account,
    MSAL, Windows Hello

Mail & collaboration servers
    Exchange Server, SharePoint, Skype for Business, Microsoft Teams

Database & data platform
    SQL Server, Azure SQL, Cosmos DB, OLE DB, Dynamics, Power BI,
    Microsoft Fabric

Core network services
    DNS, DHCP Server, DHCP Client, TCP/IP, Schannel, QUIC, HTTP.sys,
    HTTP Protocol Stack, HTTP Print Provider, Message Queuing,
    RPC Runtime, RPC API, Winsock, Ancillary Function Driver, IP Helper,
    Internet Connection Sharing, Network Address Translation, NDIS,
    Link Layer Topology

Remote access & VPN
    Routing and Remote Access, RRAS, Secure Socket Tunneling, SSTP,
    IKE Extension, Remote Access Connection Manager, Remote Access API,
    Remote Desktop, RDP Client

File & storage services
    SMB Server, SMB Client, Network File System, NFS, iSCSI,
    Distributed File System, DFS, WebClient, Work Folder,
    Failover Cluster, Storage Spaces, BranchCache

Management & deployment
    Deployment Services, Windows Update Stack, Windows Installer,
    Modern Device Management, Management Instrumentation,
    Management Services, Autopilot, Group Policy, Remote Registry,
    IP Address Management, IPAM, Print Spooler, Fax Service, WSUS

Virtualization & isolation
    Hyper-V, Secure Kernel Mode, VBS Enclave,
    Virtualization-Based Security, Virtual Trusted Platform Module,
    Device Health Attestation, Azure Attestation, Container Isolation

Developer & automation platforms
    Visual Studio, .NET, ASP.NET, PowerShell, Azure CLI, Azure Arc,
    Power Automate, Copilot Studio, HPC Pack, Azure CycleCloud,
    Azure HDInsight, Azure Kubernetes

Cryptography & boot integrity
    Secure Boot, Boot Manager, BitLocker, TPM, Key Guard

Remote shell & transfer
    OpenSSH, Telnet, FTP
```

**Microsoft invents new component names constantly**, so this list will
always be incomplete. That is the reason the unmatched residual must be
shown rather than discarded.

### 3. Zero-click document rendering

```
(Preview Pane FAQ = Yes  OR  any FAQ narrates a reading-pane trigger)
   +  AV:N  +  UI:N  +  impact includes Remote Code Execution
```

Entries where a crafted file or message executes code when it is merely
**rendered**, with no opening and no clicking. Microsoft scores these
`UI:N` because rendering is automatic.

**The Preview Pane field alone is not sufficient**, for two reasons. Most
entries answering Yes are ordinary `UI:R` open-a-document bugs, so the
field over-selects. And the field is sometimes simply wrong: a release
produced a 9.8 Outlook RCE whose Preview Pane question answered **No**
while its own exploitation FAQ said "simply viewing the message in the
Outlook Reading Pane could trigger the vulnerability, without the recipient
opening the message or clicking anything in it."

So also match the FAQ text for narration of the trigger — phrases like
"rendered in the preview pane", "viewing the message in the Reading Pane",
"previewed in the Reading Pane". This is a keyword match, no judgement
required. In one release it caught a third entry the field alone would have
missed entirely: a Graphics Component 9.8 with no Preview Pane question at
all but the same wording in its FAQ.

Where the Preview Pane field and the FAQ narration disagree, or where
narration appears on a `UI:R` entry, **report it as a data-quality flag**
rather than silently including or excluding it.

### 4. Hyper-V with scope change

```
component matches Hyper-V  +  S:C
```

The guest-to-host boundary. A scope change on a hypervisor component means
the impact crosses out of the VM, which is the highest-value bug class in
virtualization and worth separating from everything else regardless of
score.

Note the story may split: a network-vector Hyper-V entry will usually be
caught by sublist 2 first, leaving the local ones here. Say so when it
happens rather than letting a reader think these are all of them.

### Approaches considered and set aside

Record these so a later revision does not rediscover the same dead ends.

**Domain privilege escalation.** Attractive in principle. Text matching
fails: most hits on "domain" or "Active Directory" are the component name
inside a boilerplate sentence, and in one release twelve of seventeen
matches were noise while the single most domain-relevant entry — a Kerberos
capture-replay RCE — matched no phrase at all. The entries that genuinely
describe cross-principal impact share no vocabulary: "take over the
mailboxes of all users", "impersonate", "impersonation". A structural rule
on domain-infrastructure components plus escalation impact plus low
privilege works better, but is complex enough to be brittle across months.
Left out deliberately.

**Trust-decision weaknesses.** A rule matching certificate-validation,
signature-verification, authentication-bypass and origin-validation CWEs,
with `AV:N|A` and `PR:N|L` and no score or UI condition, is principled and
narrow — it returned twelve entries from nine hundred in one release. It
would catch the profile of CVE-2020-0601 (CurveBall), the NSA-reported
CryptoAPI certificate-validation flaw. It was set aside for one reason: it
depends entirely on Microsoft's CWE assignment being correct, and releases
routinely show CWE fields contradicted by the same record's own FAQ and
CVSS vector. A rule that fails silently when the input field is wrong is
worse than no rule.

### The honest limitation of this whole section

Every sublist above is gated on score, vector or a component list, so every
sublist will miss things.

The calibration case: **CVE-2020-0601, CurveBall**, scored **8.1** with
`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`. A certificate-validation flaw
allowing a spoofed code-signing certificate to be accepted as trusted,
reported by NSA, added to CISA's KEV catalogue. It would fail a 9.0 score
floor, fail a 9.5 floor, and fail any `UI:N` condition — and the `UI:R`
label is questionable in the first place, since "the victim connects to
something" is the normal operation of the protocols involved, not user
interaction in any meaningful sense.

Spoofing and trust-decision bugs are systematically under-scored by CVSS,
because they typically yield `A:N` and get `UI:R` for what is really just
ordinary use. Say this plainly when presenting the section. The four
sublists are a surfacing aid, not a claim to completeness.


## Presenting the output

**Assume the reader has never seen this tool before.** They do not know what
"Pool 2" means, why denial of service is set aside, or that Half 1 and Half 2
are a classification someone invented rather than something Microsoft
publishes. A bare table of bucket names and counts is unreadable to anyone
who has not already internalised the pipeline.

So:

**Give every section a line of context before its numbers.** What the bucket
is, why the pool is divided that way, what the half split is measuring. The
script does this in its printed output; if you are summarising rather than
reproducing that output, carry the glosses across.

**Say which parts are facts and which are judgement, every time.** Part 1 is
checkable against the source file. Part 2 is a model. Part 3 is a surfacing
aid with known blind spots. Readers who cannot tell these apart will treat
the analyst's classification as Microsoft's, which is the single most
damaging misreading available.

**Lead with a plain-language characterisation of the month**, then the
numbers. Something a reader can act on: how big it is relative to recent
months, whether anything is being exploited, whether one component dominates,
whether any data-quality problem needs manual work before the numbers can be
trusted. Reproducing 280 lines of console output with no summary is not an
overview.

**Do not assume a defect-hunting frame.** If asked to test the tooling, report
what you find — but still produce a legible summary of the release itself. The
two are not alternatives.

**Use `--brief` when the user wants an overview** rather than a working
document. It gives verification, buckets, pools, exploitation status, the
no-CVSS exception list and the Part 2 split in about ninety lines instead of
nearly three hundred.

---

## Where this ends

This pass produces an overview and a sorted starting point. It does not
decide what belongs on a priority list, does not rank components, and does
not assess individual vulnerabilities. Those require reading records and
exercising judgement about deployment, reachability and exploitability that
no mechanical rule captures.

Hand the user the Part 1 and Part 2 output and let them drive from there.

---

## Requirements and limitations

**Code execution is required.** Recent releases are 20–25 MB of XML with
over a thousand entries. This cannot be processed by reading the file into
a conversation. If no code execution is available, the user should run
`parse_cvrf.py` locally and upload its JSON output instead.

**Network access to Microsoft's API is usually blocked** in AI execution
environments. The download is the user's step, by design.

**Community mirrors are not reliable.** A GitHub mirror of MSRC data was
observed serving the "Early Security Updates" preview document under the
normal monthly filename. Use Microsoft's API URL.

**Published CVE totals will not match.** Press and vendor summaries count
differently — one recent month saw published totals of 966, 973, 1,169 and
1,170 for the same release, partly because some counts exclude CVEs
published earlier in the month. If a total is quoted anywhere, say which
denominator it uses.

---

## Appendix A — parse_cvrf.py

The companion script in full. Write it to a file and run it, or reimplement
the logic from the description above. Standard library only, Python 3.8+.

```python
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
```

---

## Appendix B — porting notes

The substance of this skill is platform-neutral by design. Only a thin
wrapper is Anthropic-specific.

## What is Claude-specific

Only the YAML frontmatter at the top of `SKILL.md` — the `name` and
`description` fields, and the `.skill` package format. The frontmatter
controls when Claude decides to consult the skill. Nothing in the body
depends on it having been read.

## What transfers unchanged

- The entire body of `SKILL.md` below the frontmatter.
- `parse_cvrf.py`, which is standard-library Python 3.8+ with no imports
  beyond `argparse`, `calendar`, `datetime`, `json`, `re`, `sys`,
  `xml.etree.ElementTree` and `collections`.
- The output templates.

## OpenAI (Custom GPT or Project)

1. Copy everything in `SKILL.md` **below** the `---` frontmatter block into
   the GPT's Instructions field, or into a project's custom instructions.
2. Upload `parse_cvrf.py` as a knowledge file.
3. Enable Code Interpreter. It is required — the file is too large to
   process by reading it into context.

The acquisition and verification steps work the same way: the user
downloads the CVRF from Microsoft's URL and uploads it.

## Google Gemini (Gem)

Same approach. Body text into the Gem's instructions, script as an attached
file, code execution enabled.

## Any platform without code execution

The parsing cannot be done conversationally at this file size. Tell the user
to run the script locally:

```
python3 parse_cvrf.py 2026-Sep.xml --json records.json
```

and upload `records.json`, which is far smaller and already normalised. The
model can then work from the structured output.

## Local-only use, no LLM

`parse_cvrf.py` is usable on its own:

```
python3 parse_cvrf.py 2026-Sep.xml                       # printed summary
python3 parse_cvrf.py 2026-Sep.xml --verify --expect 2026-Sep
python3 parse_cvrf.py 2026-Sep.xml --json records.json   # full records
python3 parse_cvrf.py 2026-Sep.xml --no-vscode-setaside  # disable a set-aside
```

## If you reimplement the parser in another language

Two implementation details cause most of the trouble:

**Per-product element repetition.** `Threat` and `ScoreSet` elements repeat
once for every affected ProductID. A 30-SKU entry carries thirty identical
"Important" severity elements and thirty identical scoresets. Deduplicate on
read, in the parsing layer, rather than leaving every consumer to rediscover
it.

**File size.** In PowerShell, casting a 25 MB file with `[xml]` works but is
slow and memory-hungry. `XmlReader` streaming is the better approach at this
size and is worth building in from the start rather than retrofitting.

## Architecture, if you extend it

Three layers, deliberately separable:

1. **Parser** — read the XML, normalise, emit one record per CVE plus
   data-quality flags. Pure mechanical work.
2. **Bucketing** — consume normalised records only, never the XML. Assign
   buckets and pools.
3. **Analyst** — everything requiring judgement. Not automated, and should
   not be.

Layers 1 and 2 port cleanly to any language. Layer 3 is prose.
