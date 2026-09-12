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
