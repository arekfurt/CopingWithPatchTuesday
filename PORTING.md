# Porting this to other platforms

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
