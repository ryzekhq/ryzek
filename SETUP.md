# ryzek — Setup Guide (follow one step at a time)

## What you need first

1. **Node.js** — free, official, from nodejs.org
   - Go to https://nodejs.org
   - Download the "LTS" version (the recommended one, not "Current")
   - Install it like any normal app (click Next/Next/Finish)

2. **VS Code** — free code editor, from code.visualstudio.com (you already have this)

3. **The ryzek folder** — unzip ryzek.zip somewhere easy to find,
   e.g. your Desktop or Documents folder.

## Step by step

1. Open VS Code.
2. File → Open Folder → select the unzipped `ryzek` folder.
3. Open the built-in terminal: View → Terminal (or press Ctrl + ` on
   Windows/Linux, Cmd + ` on Mac).
4. In that terminal, type this and press Enter:
   ```
   npm install
   ```
   This downloads the small set of tools ryzek depends on. Only needs
   to be done once. Takes a minute or two.

5. Then type this and press Enter:
   ```
   npm run build
   ```
   This turns the code into a runnable program.

6. Now run it against the test files that come with it, to prove it works:
   ```
   node dist/cli.js fixtures/malicious
   ```
   You should see several flagged findings with confidence scores — that's
   correct, those test files are deliberately broken to prove the scanner
   catches real problems.

7. To scan clean files (should show 0 flagged):
   ```
   node dist/cli.js fixtures/clean
   ```

8. To scan your own manifest files later: put your `.json` tool manifest
   files in any folder, then run:
   ```
   node dist/cli.js path/to/that/folder
   ```

9. To see the rug-pull detection story live (good for a call — it's a
   30-second, self-cleaning demo):
   ```
   npm run demo:rugpull
   ```

## Two commands worth knowing about

**Marking a false positive** (unchanged): if a finding is wrong for your
case, silence it forever with:
```
node dist/cli.js path/to/folder --mark-false-positive <ruleId> "<toolName>"
```

**Acknowledging an intentional manifest change**: the first time ryzek
sees a tool, it just remembers it (nothing to compare against yet). On every
scan after that, if the tool's description/permissions/parameters changed,
it gets flagged as `manifest-drift` — even if the new version doesn't look
obviously dangerous on its own. If you made that change on purpose, tell
ryzek to accept the new version as the baseline:
```
node dist/cli.js path/to/folder --update-baseline "<toolName>"
```
Run it with no tool name to re-baseline every tool in the folder at once.

## About "using my laptop as a server"

You don't need a server to develop or test this — everything above runs
directly on your laptop, no hosting required. A "server" only becomes
relevant later, if you want:
- A hosted web dashboard other people can log into (not built yet)
- To run scans automatically in a customer's CI pipeline (they'd run it on
  their own machines/CI, not yours)

For now — cold calls, demos, and selling — running it live on your laptop
during a call is exactly the right approach. No server needed yet.

## GitHub Code Scanning (SARIF)

To make findings appear in a repo's Security tab alongside CodeQL/Dependabot
instead of buried in CI logs:

```
node dist/cli.js path/to/manifests --sarif results.sarif
```

Then in a GitHub Actions workflow, upload it:

```yaml
- name: Upload ryzek results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Findings are tagged with their OWASP AST10 category, and anything you've
marked as a false positive is emitted as a SARIF suppression (shown as
dismissed) rather than silently dropped.

## Licensing

ryzek has three tiers: **Free** (100 scans/month, no key needed),
**Pro** (1,000 scans/month + admin dashboard), and **Enterprise**
(unlimited). Free tier works fully offline — nothing below is required
unless you're on Pro/Enterprise.

```
ryzek license set <your-key>      # activate a Pro/Enterprise key
ryzek license status              # check current tier and usage
```

The license server itself (validation + usage tracking + the Pro/Enterprise
dashboard) lives in `license-server/` — see `license-server/README.md` for
running it and issuing keys.

## If something goes wrong

- `npm install` fails → check you're in the right folder (should contain a
  file called `package.json`) — type `ls` (Mac/Linux) or `dir` (Windows) to
  check what's in the current folder.
- `node dist/cli.js` says "command not found" → run `npm run build` again
  first, it needs to finish without red error text.
- Anything else — paste the exact red error text back to me and I'll tell
  you exactly what it means.

## Measuring detection rate (benchmark)

To reproduce the published detection number yourself:

```
git clone https://github.com/snyk-labs/toxicskills-goof.git ../toxicskills-goof
npm run benchmark
```

That corpus contains **real malicious skills** — it's a research sample set.
Clone it, don't install or run anything from it.

The benchmark prints detection rate, false-positive rate, and — importantly —
exactly which samples were missed. The misses are the useful part; they tell
you what to build next.

## Strict CI verification (--verify)

A normal scan reports drift as a finding. `--verify` treats the committed
baseline as a lockfile and fails the build on *any* change:

```
node dist/cli.js path/to/manifests --verify
```

Exit codes: `0` verified, `4` mismatch, `1` no baseline yet. Commit
`.ryzek-baseline.json` to your repo so CI has something to check against.
Intentional changes: re-run with `--update-baseline` and commit the result.
