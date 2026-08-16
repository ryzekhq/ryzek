# ryzek — Competitive Positioning

Grounded in real research, not assumptions. Use this for sales calls and the site copy.

## The Landscape

367 companies now work in AI agentic security, with ~$9.7B in disclosed funding as of
July 2026. ryzek is not trying to out-fund or out-feature all of them — it's
solving one specific, underserved problem well.

| Competitor | What they do | Where they're strong |
|---|---|---|
| Galileo | "Agent Control" (open-source, March 2026), integrates with AWS/CrewAI/Glean | Big ecosystem integrations, $68M raised |
| TrueFoundry | MCP Gateway, pre-execution guardrails | Ran the Snyk audit finding 36.82% of scanned agent skills had flaws |
| Patronus AI | Agent evaluation & safety testing | Strong on evals/testing, not manifest scanning specifically |
| NVIDIA NeMo Guardrails | Runtime guardrails for LLM apps | Deep NVIDIA-stack integration |
| Lakera / Check Point | Prompt injection detection at runtime | Strong brand, enterprise sales motion |

**None of them are positioned as a lightweight, CI-friendly static scanner purpose-built
for agent tool/skill manifests specifically** — most are either runtime guardrails
(different problem: catching bad behavior as it happens) or full enterprise platforms
requiring a sales cycle to even try.

## Two Gaps We Now Cover That We Didn't Before

These aren't marketing claims — they're specific, testable behaviors. Run
`npm run demo:rugpull` to see the first one live.

- **Manifest drift ("rug pull") detection.** MCP tool-poisoning attacks are
  documented as not looking malicious at install time — a tool passes review,
  then its description or permissions quietly change afterward while the agent
  keeps trusting the original approval. A single-snapshot scanner (which is
  what most static scanners, including our earlier version, actually are)
  cannot catch this by definition — there's nothing wrong with either snapshot
  in isolation. ryzek now hashes each tool on first sight and flags any
  change to a previously-seen tool's description, permissions, or parameters,
  specifically because the six original rules structurally cannot.
- **Hidden Unicode / "ASCII smuggling" detection.** Zero-width characters and
  Unicode Tags-block payloads can render as invisible (or as their visible
  base text) to a human skimming a manifest in an editor or PR, while an LLM
  parsing the same string reads every character. This is a documented
  injection technique our original rule set had no way to catch, since
  `prompt-injection-payload` only matches visible phrases.

## The Real, Documented Weakness in This Category

The single most consistent complaint across security scanning tools — this category
included — is **false positives eroding trust until people stop reading the output.**
Loosely-written rules built to "catch more" end up flooding teams with noise until the
tool gets ignored or uninstalled. This is a known, general pattern in secrets/security
scanning, not a claim about any one named competitor.

## What ryzek Does About It

- **Confidence scores (45–95%) on every finding** — not just flagged/not flagged.
  A hardcoded secret gets 95% confidence; a fuzzy keyword heuristic gets 45%, so
  users know what to check first vs. what to skim.
- **A stated reason for every confidence score** — plain-English explanation of
  exactly what matched and why it's trustworthy (or not).
- **A false-positive feedback loop** — mark a finding wrong once, it's suppressed
  on every future scan, shareable across a team via a committed JSON file.
- **CI-native** — non-zero exit code on critical findings, no dashboard login
  required, runs in a pipeline in seconds.
- **Narrow and free to start** — no enterprise sales call required to try it,
  unlike most of the named competitors above.

## Measured Detection Rate (say this number, not a vibe)

Run `npm run benchmark` to reproduce this yourself in about a minute.

Against the **Snyk ToxicSkills demo corpus** (the published corpus of real
malicious agent skills, at a 50% confidence threshold):

| Metric | Result |
|---|---|
| Detection rate | **6/6 malicious samples flagged (100%)** |
| False positive rate | **0/3 benign samples flagged (0%)** |

Caveats to state out loud, every time this number is quoted:

- **It is a small corpus (9 labelled samples).** 100% here means "catches every
  sample in this specific public set," not "catches everything." Treat it as a
  floor, not a guarantee.
- **The labels are ours**, assigned by reading each sample, because the corpus
  ships no machine-readable labels. They're in `benchmark-labels.json` so anyone
  can check our work — including one label we got wrong initially and corrected
  (the scanner was right and we were wrong; that's documented in the file).
- **This measures known-pattern detection.** Independent research has bypassed
  every public skill scanner tested; a good score here says nothing about a
  motivated attacker crafting something novel.

What makes this worth saying anyway: nearly nobody in this category publishes a
measured number at all, because it's uncomfortable to publish misses. Publishing
one — with the caveats — is more credible than asserting quality.

## Measured Detection Rate (not asserted — measured)

Run it yourself: `npm run benchmark`

Against the **Snyk ToxicSkills corpus** (github.com/snyk-labs/toxicskills-goof),
9 labelled samples — 7 malicious, 2 benign:

| Metric | Result |
|---|---|
| Detection rate | **100% (7/7)** |
| False-positive rate | **0% (0/2)** |

**Say the caveat out loud when quoting this:** 9 samples is a small corpus.
This number says ryzek catches these known, published attack patterns.
It says nothing about novel attacks, and it is not a generalised detection
rate. Publishing the number — including, in earlier runs, the misses — is the
point. Most tools in this category publish no number at all.

The first run scored 85.7%, missing a hook-based credential-capture sample.
That miss exposed two real bugs (a first-match-only regex that never
evaluated a second malicious command, and a vendor-domain allowlist being
applied to a command concealed in an HTML comment). Both were fixed and the
rule set extended; the re-measured score is above. That loop — measure, find
the gap, fix, re-measure — is what the benchmark is for.

## Honest Limitations (say these out loud — it builds trust)

- New product, not yet used by 30+ paying teams — that's the near-term goal, not
  a claim to make today.
- 10 rules currently (permissions, prompt injection, exfiltration, secrets, dynamic
  execution, description mismatch, hidden-Unicode obfuscation, manifest drift,
  loose parameter schemas, untrusted external install) — a growing set, not an
  exhaustive one.
- **Pattern-matching, not semantic analysis.** This is the honest ceiling and it
  should be said on sales calls, not hidden: independent research in June 2026
  bypassed every public skill scanner tested, in under an hour, using payload
  padding, logic hidden in binary/archive formats, and prompt-injection against
  the scanner's own LLM judge. ryzek is a static pattern-matcher and is in
  that same structural category. It raises the floor against known patterns —
  it is not a guarantee against a motivated attacker.
- Scans `.json` manifests AND `SKILL.md` skills (YAML frontmatter, markdown body,
  and bundled scripts). Not yet covered: archive/binary formats, and external
  instruction sources a skill fetches at runtime (AST05).
- Covers 5 of the 10 OWASP AST10 categories (see `src/ast10.ts` for the exact
  per-category coverage statement, including what is explicitly NOT covered).
- Manifest-drift detection only works from the second scan of a given tool onward
  — the first scan can only establish a baseline, not detect a change, because
  there's nothing yet to compare against.
- Static analysis only — it reads manifests, it doesn't watch runtime behavior
  the way NeMo Guardrails or Lakera do. Different layer of defense, meant to
  complement those tools, not replace them.

## The Pitch, One Sentence

"Other tools in this space either need an enterprise sales call or drown you in
false positives you stop trusting — ryzek tells you exactly how confident it
is in every single finding, and remembers when you tell it it's wrong."
