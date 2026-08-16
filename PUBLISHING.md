# Publishing checklist

All placeholders are filled in. Details on record:

| Item | Value |
|---|---|
| Package name | `ryzek` |
| Version | 1.2.0 |
| GitHub | github.com/ryzekhq/ryzek |
| Domain | ryzek.dev |
| Security contact | security@ryzek.dev |
| General contact | hello@ryzek.dev |
| Licence | MIT, © 2026 Ryzek |

---

## 1. Check the npm name is free

```bash
npm view ryzek
```

- **404 / "not found"** → free, continue.
- **Returns a version** → taken. Change `"name"` in package.json to
  `"@ryzekhq/ryzek"` and publish with `npm publish --access public`.
  Everything else stays the same.

## 2. Enable npm 2FA — do this before publishing

```bash
npm profile enable-2fa auth-and-writes
```

The realistic attack on a published package is account takeover: someone gets
your credentials and ships a malicious version under your name, which then
runs on every user's machine. This is the highest-value security step here.

## 3. Publish

```bash
npm login
npm publish
```

`prepublishOnly` runs the build automatically, so `dist/` is always fresh.

Verify from a clean folder:

```bash
cd /tmp && npx ryzek@latest ./some-skills-folder
```

## 4. Push to GitHub

```bash
git init
git add -A
git commit -m "Ryzek v1.2.0"
git branch -M main
git remote add origin https://github.com/ryzekhq/ryzek.git
git push -u origin main
```

**Before pushing, confirm nothing sensitive is staged:**

```bash
git status
git ls-files | grep -iE "env|key|secret|db.json"
```

`.gitignore` already excludes the licence database, `.env` files, keys, and
local runtime state — but check anyway. A secret removed in a later commit
stays in history.

## 5. Host the site

`site/index.html` is a single self-contained file.

1. Rename it to `index.html` (already named that)
2. Cloudflare dashboard → **Workers & Pages** → Create → Pages → Upload assets
3. Drag the file in → Deploy
4. Custom domains → add `ryzek.dev`

**If you use `site/coming-soon.html` instead:** its email form currently
validates and shows a confirmation but **stores nothing**. Wire it to
Formspree, Buttondown, or ConvertKit first, or you'll collect zero addresses
while appearing to work.

## 6. Before announcing anywhere

- [ ] `npx ryzek@latest` works from a clean machine
- [ ] Repo public, README renders correctly on GitHub
- [ ] `security@ryzek.dev` tested and not landing in spam
- [ ] Gmail filter: mail to `@ryzek.dev` → never send to spam
- [ ] `npm run benchmark` passes (clone the corpus into `./corpus` first)

## 7. Version bumps

```bash
npm version patch   # 1.2.0 -> 1.2.1   bug fixes
npm version minor   # 1.2.0 -> 1.3.0   new rules or features
npm publish
```

Tag releases in git so a published detection rate is always traceable to a
specific build.
