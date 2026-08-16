# ryzek

**A static security scanner for AI agent skills and tool manifests.**
Scans `SKILL.md` bundles and JSON tool manifests for prompt injection, hidden
instructions, credential exfiltration, over-broad permissions, and
post-approval tampering — with a confidence score and a stated reason on
every finding.

Runs in CI in seconds. No dashboard login. No sales call.

```bash
npx ryzek ./skills
```

---

## Why another scanner

Most tools in this space are either **runtime guardrails** (catching bad
behaviour as it happens — a different layer of defence) or **enterprise
platforms** that need a sales cycle before you can even try them.

ryzek is neither. It's a fast static check you run before a skill ever
reaches an agent, built around one specific problem the category is bad at:

> **False positives erode trust until people stop reading the output.**

Loosely-written rules built to "catch more" flood teams with noise until the
tool gets ignored or uninstalled. ryzek's answer:

- **A confidence score on every finding (20–95%)** — not just flagged/not
  flagged. A hardcoded AWS key scores 95%. A fuzzy keyword heuristic scores
  45%. You know what to check first and what to skim.
- **A stated reason for every score** — plain English: exactly what matched,
  and why that's trustworthy or not.
- **A feedback loop that remembers** — mark a finding wrong once, it's
  suppressed on every future scan. Commit the file and your whole team
  inherits it.

---

## Measured detection rate

Most scanners assert quality. This one publishes a number you can reproduce:

```bash
git clone --depth 1 https://github.com/snyk-labs/toxicskills-goof.git /tmp/toxicskills-goof
npm run benchmark
```

Against the **Snyk ToxicSkills corpus** (9 labelled samples — 7 malicious,
2 benign):

| Metric | Result |
|---|---|
| Detection rate | **100%** (7/7) |
| False-positive rate | **0%** (0/2) |

**Read the caveat before quoting that.** Nine samples is a small corpus. This
says ryzek catches these known, published attack patterns. It says
nothing about novel attacks, and it is not a generalised detection rate.

It's also worth knowing how that number moved: the **first run scored 85.7%**.
The single miss — a credential-capture hook hidden in YAML frontmatter —
exposed three real bugs, including a parser that silently dropped nested
frontmatter so the payload was invisible to every rule, and a regex that only
ever evaluated the first match in a file. Both are fixed. The `MISSED` section
of the benchmark output is the useful part; the score is a side effect.

---

## What it detects

| Rule | Catches | OWASP AST10 |
|---|---|---|
| `prompt-injection-payload` | Instructions aimed at the agent, not the user | AST01, AST04 |
| `concealed-instruction` | Commands hidden in HTML comments; auto-executing frontmatter hooks | AST04, AST01 |
| `unicode-obfuscation` | Zero-width and Tags-block characters (ASCII smuggling) | AST04 |
| `untrusted-external-install` | Prose directing downloads from paste sites and anonymous hosts | AST05, AST01 |
| `exfiltration-pattern` | Sensitive-data access combined with outbound network capability | AST01, AST03 |
| `hardcoded-secret` | Live credentials left in a manifest | AST04 |
| `excessive-permissions` | Unusually broad or dangerous permission requests | AST03 |
| `loose-parameter-schema` | Unconstrained high-risk parameters (RCE/SSRF precondition) | AST03, AST04 |
| `dynamic-execution` | `curl \| bash`, `eval`, obfuscated execution | AST01 |
| `description-capability-mismatch` | Read-only descriptions hiding write/delete capability | AST04 |
| `manifest-drift` | **Post-approval changes to an already-reviewed skill** | AST07, AST02 |
| `opaque-payload` | Bundled binaries, archives, disguised executables, large encoded blobs | AST02, AST01 |

### Drift detection — the one worth calling out

MCP tool-poisoning ("rug pull") attacks don't look malicious at install time.
A skill passes review, gets approved, and *then* its description or
permissions quietly change while the agent keeps trusting the original
approval.

A single-snapshot scanner cannot catch this by definition — there's nothing
wrong with either snapshot in isolation. ryzek hashes each skill on first
sight and flags any later change, even one that trips no other rule.

See it in 30 seconds:

```bash
npm run demo:rugpull
```

---

## Install & usage

**Run it without installing anything:**

```bash
npx ryzek ./skills
```

**Or install it globally:**

```bash
npm install -g ryzek
ryzek ./skills
```

**Or use it as a library:**

```ts
import { loadManifestsFromDir, scanTools, allRules } from "ryzek";

const tools = loadManifestsFromDir("./skills");
const results = scanTools(tools, allRules);
const critical = results.filter(r => r.overallSeverity === "critical");
```

### Common commands

```bash
ryzek ./skills                      # scan
ryzek ./skills --sarif out.sarif    # GitHub Code Scanning output
ryzek ./skills --verify              # strict CI gate (lockfile mode)
ryzek license status                 # check tier and usage
```

**Exit codes:** `0` clean · `2` critical findings · `3` scan limit reached.

Requires Node 18+.

### Marking a false positive

```bash
ryzek ./skills --mark-false-positive <ruleId> "<skillName>"
```

Writes `.ryzek-feedback.json`. Commit it to share suppressions across a
team.

### Accepting an intentional change

```bash
ryzek ./skills --update-baseline "<skillName>"
```

### GitHub Actions

```yaml
- run: npx ryzek ./skills --sarif results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Finding skills you forgot you installed

Skills install quietly — from a marketplace, a README's curl command, a
teammate's PR — and no central registry lists what an agent is actually
allowed to run on your machine. The realistic failure isn't scanning your
skills and missing something; it's not knowing a skill was installed at all.

```bash
ryzek discover                      # walk the known install locations
ryzek discover --path /custom/dir   # add a location
```

Checks the conventional directories for Claude Code, Gemini, Cursor, Codex,
and project-local `.claude/skills`, `.agents/skills`, and `./skills`. It lists
what it finds and does not open, execute, or transmit anything — scanning is a
separate, explicit step.

## Scanning automatically before every commit

A scanner you have to remember gets run once at setup and never again — which
is exactly when a post-approval change would slip through, since drift
detection only helps if something re-scans.

```bash
ryzek hook install ./skills   # install the git pre-commit hook
ryzek hook uninstall
```

The hook blocks a commit **only on critical findings**; lower severities print
but let the commit through, because a hook that blocks on everything gets
disabled within a day. It never overwrites an existing pre-commit hook, and
`git commit --no-verify` still bypasses it.

---

## Reporting a bug or bypass

```bash
ryzek report false-negative --rule <ruleId> --sample ./that-skill/SKILL.md
ryzek report false-positive --rule <ruleId>
ryzek report bug --message "what happened"
```

Writes a pre-filled Markdown report to your current folder. **It sends nothing** —
you read it, remove anything sensitive, then paste it into an issue or email it.
A security tool that auto-uploaded the files it was pointed at would be doing the
exact thing this scanner flags as critical.

Accepted bypass reports go into the benchmark corpus and are credited in the
release notes.

---

## Telemetry

**Off by default. Nothing is collected unless you turn it on.**

```bash
ryzek telemetry on     # opt in
ryzek telemetry off    # opt out
ryzek telemetry        # check status
```

If enabled, what is sent is limited to: a randomly generated install ID, the
ryzek version, your OS platform, and counts (tools scanned, findings by
severity).

**Never sent:** manifest or skill content, tool names, file names, paths,
findings detail, matched text, licence keys, or anything identifying a person,
company, or codebase.

This is a security tool that runs over files which may contain credentials.
Silent telemetry in that context would be a betrayal of the trust the tool
depends on, so it is opt-in and the first run says so plainly.

---

## Honest limitations

Stated up front, because a security tool that oversells itself is worse than
no security tool.

- **This is a pattern matcher, not semantic analysis.** Independent research
  in 2026 bypassed *every* public skill scanner tested, in under an hour,
  using payload padding, logic hidden in binary formats, and prompt injection
  against scanners' own LLM judges. ryzek is in that same structural
  category. It raises the floor against known patterns. It is not a guarantee
  against a motivated attacker.
- **Static analysis only.** It reads manifests and bundles; it does not watch
  runtime behaviour. It complements runtime guardrails, it doesn't replace
  them.
- **Binary inspection is detection, not analysis.** Ryzek flags bundled
  executables, archives, filename-disguised binaries (by magic bytes), and
  large encoded blobs, and it decompresses gzip so the contents get scanned.
  It cannot tell you what a compiled binary *does* — no static text scanner
  can. Zip extraction is not supported, because it would require a runtime
  dependency this project deliberately avoids.
- **Drift detection needs a second scan.** The first can only establish a
  baseline.
- **Covers 6 of 10 OWASP AST10 categories.** See `src/ast10.ts` for the exact
  per-category statement, including what is explicitly *not* covered.
- **New project.** Not yet validated by a large user base. The benchmark
  number above is what exists in place of a track record.

---

## Tiers

| | Free | Pro | Enterprise |
|---|---|---|---|
| Scans/month | 100 | 1,000 | Unlimited |
| All detection rules | ✅ | ✅ | ✅ |
| Usage dashboard | — | ✅ | ✅ |

Free needs no key and works fully offline. See `license-server/README.md` to
run the licensing server.

---

## Contributing

The most useful contribution is **a sample that gets past it.** If you find a
bypass, open an issue with the sample — that's worth more than a feature
request, and it goes straight into the benchmark corpus.

## License

See `LICENSE`.
