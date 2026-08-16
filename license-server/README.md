# ryzek license server

A basic license validation + usage tracking + admin dashboard server. This
is what `ryzek license set <key>` talks to, and what powers the Pro/
Enterprise usage dashboard.

## What it does

- **Validates license keys** (`POST /api/validate`) — checks a key exists,
  isn't revoked, isn't expired, and returns its tier.
- **Records usage** (`POST /api/usage`) — the CLI reports scan counts here
  after each scan (best-effort; scans are never blocked by this failing).
- **Serves an admin dashboard** (`GET /dashboard?key=...`) for Pro/
  Enterprise users — usage this month, a 6-month trend, and recent scan
  history. Free-tier keys get a polite "upgrade to see this" response
  instead of data.

Storage is a single JSON file (`data/db.json`) — no database server to run.
That's the right amount of infrastructure for where this product is right
now; swap it for real a database later if usage volume ever justifies it.

## Running it

```
npm install
npm run build
npm start
```

Runs on **port 8787** by default (`PORT=... npm start` to change it). The
CLI expects it at `http://localhost:8787` by default — override with the
`RYZEK_LICENSE_SERVER` environment variable on the machine running
`ryzek` if you host this somewhere else.

### On hardware

Same answer as everywhere else in this project: this doesn't need a
powerful machine. It's a small Node process reading and writing one JSON
file — negligible CPU, negligible RAM, no GPU involved anywhere. Running it
on the same PC you use for everything else, in the background, is fine.

**One thing that does matter if real customers depend on this**: right now
it only runs on `localhost`, so it's only reachable from the same machine.
Making it reachable from other machines (your customers' CI runners, for
instance) means either port-forwarding + a static IP or dynamic DNS, or
hosting it somewhere with a public address (a small VPS is the common,
low-effort option). That's a real decision with real tradeoffs — worth a
separate conversation before you flip that switch, not something to do by
accident.

## Issuing license keys

There's no self-serve signup or payment integration yet — this is a manual
admin tool for after someone pays you directly:

```
npm run create-license -- pro alice@example.com
npm run create-license -- enterprise bob@bigco.com
npm run create-license -- pro carol@example.com 2027-01-01   # optional expiry
```

This prints a key like `sk-scan-pro-<random>`. Give it to the customer —
they activate it with:

```
ryzek license set sk-scan-pro-<random>
```

To revoke a key (e.g. a refund, a chargeback), there's no CLI wrapper yet —
edit `data/db.json` directly and set that key's `"status"` to `"revoked"`,
or add a small script following the same pattern as `create-license.ts` if
you'll be doing this often enough to want one.

## API reference

| Endpoint | Method | Body / Query | Returns |
|---|---|---|---|
| `/health` | GET | — | `{ ok: true }` |
| `/api/validate` | POST | `{ key }` | `{ valid, tier, ownerEmail? }` or `{ valid: false, reason }` |
| `/api/usage` | POST | `{ key, month, scanCount, events[] }` | `{ ok, totalThisMonth }` |
| `/api/dashboard-data` | GET | `?key=...` | Usage summary JSON (403 for free-tier or invalid keys) |
| `/dashboard` | GET | `?key=...` | HTML admin dashboard |

## What this deliberately doesn't do (yet)

Said plainly, so it's a decision and not an accident:

- **No payment/signup flow.** Keys are minted manually via `create-license`.
- **No auth on the dashboard beyond the key itself.** Anyone with a valid
  Pro/Enterprise key can view that key's own usage — there's no separate
  admin login. Fine for now; would need real auth before this handles
  anything sensitive.
- **No real database.** A JSON file is enough for hundreds of customers.
  It is not the right choice once you're at a scale where concurrent writes
  are a real risk (multiple scans reporting usage in the same instant) —
  the file-write isn't atomic against a true race, only against
  sequential calls.
- **CLI enforcement is per-machine, not truly global in real time.** The
  local monthly counter on each machine is the source of truth for
  blocking that machine — the server aggregates for the dashboard, but a
  key used from two machines simultaneously could each locally allow up to
  the limit before the server-side total is checked. Fine at this scale;
  worth revisiting if a customer starts running this across a large fleet.
