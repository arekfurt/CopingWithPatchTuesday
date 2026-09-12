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
