# Benchmarks

Measures ryzek against a corpus of samples with known ground-truth
labels, so the project can state a **measured** detection rate rather than
asserting quality.

## Running it

The corpus isn't vendored here (it contains live malicious samples — don't
commit those into your own repo). Clone it first:

```
git clone --depth 1 https://github.com/snyk-labs/toxicskills-goof.git /tmp/toxicskills-goof
npm run benchmark
```

Point at a different corpus with `CORPUS=/path/to/corpus npm run benchmark`.

## Adding your own corpus

Create a labels file in the same shape as `toxicskills-labels.json`:

```json
{
  "corpusName": "...",
  "source": "...",
  "samples": [
    { "path": "relative/path/SKILL.md", "malicious": true, "note": "why" }
  ]
}
```

Paths are matched by suffix, so they stay stable regardless of where the
corpus is checked out.

## Read the misses, not the score

The score is the least useful line of the output. The `MISSED` section is
what tells you which rule to write next — the first run of this benchmark
scored 85.7% and the single miss exposed two genuine bugs. Treat a rising
score as a side effect of fixing real gaps, not as the goal.
