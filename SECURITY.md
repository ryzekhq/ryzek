# Security

## Reporting a vulnerability

Found a way past ryzek, or a security issue in the tool itself?

**Please don't open a public issue for an active exploit.** Email
`security@ryzek.dev` instead, and expect a reply within 72 hours.

Bypass samples are the single most valuable contribution to this project.
A sample that gets past the scanner goes straight into the benchmark corpus,
and the fix ships with the miss documented. That loop is the point — see the
benchmark section of the README for how a real miss drove three bug fixes.

---

## Why this project is open source

This comes up, so it's worth stating plainly.

ryzek reads your skill manifests, which may contain credentials or
proprietary logic. Asking people to run a closed-source binary over that
material would be a bigger security ask than anything the tool protects
against. Every serious tool in this category publishes its source for the
same reason.

**Publishing detection logic does not weaken it.** The rules describe attack
patterns that are already publicly documented — OWASP AST10, published CVEs,
and public research corpora. An attacker doesn't need to read this repo to
learn that `curl | bash` is suspicious.

Security that depends on nobody reading the code isn't security.

---

## What actually needs protecting

Source visibility is not the risk. These are:

### 1. Your npm account

The realistic attack on a published package is **account takeover** — someone
takes your npm credentials and publishes a malicious version under your name,
which then runs on every user's machine.

**Enable 2FA before you publish anything:**

```bash
npm profile enable-2fa auth-and-writes
```

This is the single highest-value security step in this document. Do it first.

### 2. Never committing secrets

`.gitignore` in this repo already excludes:

- `license-server/data/db.json` — live customer license keys and emails
- `.env` files and any `*.key` / `*.pem`
- Local runtime state (`.ryzek-*`)

**Before your first push**, verify nothing sensitive is staged:

```bash
git status
git ls-files | grep -iE "env|key|secret|db.json"
```

If a secret was ever committed, removing it in a later commit is **not
enough** — it stays in history. Rotate the credential and rewrite history
with `git filter-repo` or BFG.

### 3. The license server, if you host it

This is the part that holds customer data, and it's the piece worth being
careful with — not the scanner source.

- Don't expose it from a home network. Use a VPS or managed host.
- Put it behind HTTPS. Never plain HTTP for anything carrying license keys.
- Back up `data/db.json` — it's your customer record.
- The dashboard currently authenticates by license key alone. That's adequate
  for early use but should get real auth before it holds anything sensitive.

### 4. Dependency supply chain

ryzek ships with **zero runtime dependencies** — a deliberate choice.
Every dependency is a package that could be compromised and would then run
inside your users' CI. Keep it that way where possible, and run `npm audit`
before each release.

---

## Scope

ryzek is a **static pattern matcher**. Independent research in 2026
bypassed every public skill scanner tested. This tool raises the floor against
known, documented patterns. It is not a guarantee, and it does not replace
runtime guardrails or human review of skills you don't trust.
