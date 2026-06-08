# proton-sync

Bidirectional sync daemon between **ProtonMail Contacts** and a
**Synology CardDAV Server**.

```
ProtonMail Contacts  <──── proton-sync ────>  Synology CardDAV Server
```

Changes on either side are detected via ETag comparison against a local
SQLite cache and propagated to the other side on every sync pass.

---

## Architecture

```
cmd/proton-sync/
  main.go                        <- CLI entry point (auth / sync / daemon)
internal/
  auth/
    auth.go                      <- AES-256-GCM encrypted auth.json, scrypt KDF
    prompt.go                    <- interactive terminal helpers
  proton/
    client.go                    <- go-proton-api wrapper (SRP login, OTP, keyring)
  synology/
    client.go                    <- RFC 6352 CardDAV client (PROPFIND, REPORT, PUT, DELETE)
  sync/
    engine.go                    <- bidirectional sync logic + conflict resolution
  cache/
    cache.go                     <- SQLite state store (ETag tracking per UID)
```

---

## Setup

### 1. Build

```bash
go build -o proton-sync ./cmd/proton-sync
```

### 2. Bootstrap credentials

```bash
./proton-sync auth
```

Prompts for:

| Prompt | Description |
|---|---|
| ProtonMail username | your `@proton.me` or custom domain address |
| ProtonMail account password | the password you use to log in to proton.me |
| Synology CardDAV URL | e.g. `https://nas.example.org:5006` |
| Synology username | local DSM account with CardDAV access |
| Synology password | |
| Address book path | e.g. `/carddav/principal/addressbooks/proton/` |

> **Note — two-password mode:** A small number of older Proton accounts
> use a separate *mailbox password* to decrypt the private key (distinct
> from the login password). If you have never heard of this, you do not
> have it. The bootstrap will also ask for it; leave that prompt blank
> and it is ignored.

At the end a **bridge password** is generated and printed **once**.
Save it securely — it is the AES-256-GCM key for `auth.json` and
cannot be recovered.

```
auth.json layout (on disk, encrypted):
  {
    "bridge_password_hint": "set BRIDGE_PASSWORD env var or enter at prompt",
    "salt":   "<base64 scrypt salt>",
    "nonce":  "<base64 AES-GCM nonce>",
    "cipher": "<base64 AES-256-GCM ciphertext>"
  }
```

### 3. Set bridge password

```bash
export BRIDGE_PASSWORD=<generated value>
```

Or enter it interactively when prompted.

### 4. Handle two-factor authentication (TOTP)

If your Proton account has **2FA enabled**, a one-time code is required
every time `sync` or `daemon` starts — it is needed to authenticate the
Proton session, not during the initial `auth` bootstrap.

Supply the TOTP code in one of two ways:

```bash
# Option A — environment variable (recommended for automated/daemon use)
export PROTON_TOTP=$(your-totp-generator)
./proton-sync daemon

# Option B — interactive prompt (default when PROTON_TOTP is not set)
./proton-sync sync
# TOTP code: 123456
```

For unattended daemon use, generate the TOTP from a CLI tool such as
`oathtool` or `pass otp` and inject it via the env var:

```bash
export PROTON_TOTP=$(oathtool --totp -b "$PROTON_TOTP_SECRET")
./proton-sync daemon
```

### 5. Sync once (test)

```bash
./proton-sync sync
```

### 6. Run as daemon

```bash
./proton-sync daemon   # interval = sync_interval_sec from config (default 300 s)
```

---

## Conflict policy: `duplicate`

When the same contact UID is modified on **both** sides between two sync
passes, both versions are preserved:

- The Proton version is written to Synology under UID `{uid}-conflict-proton`
- The Synology version is written to Proton under UID `{uid}-conflict-synology`
- Both copies are labelled in `FN` with the corresponding suffix

No data is lost. Merge duplicates manually in any CardDAV client
(Synology Contacts, Apple Contacts, DAVx5).

Other policies via `conflict_policy` in the encrypted config:

| Value | Behaviour |
|---|---|
| `duplicate` | **default** — preserve both, create labelled copies |
| `proton-wins` | Proton version overwrites Synology |
| `synology-wins` | Synology version overwrites Proton |

---

## Docker

```bash
# Bootstrap on the host first:
./proton-sync auth

# Run the daemon:
BRIDGE_PASSWORD=<value> PROTON_TOTP=$(oathtool --totp -b "$SECRET") \
  docker compose up -d
```

The container mounts `auth.json` read-only and persists `sync-cache.db`
in a named Docker volume.

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `BRIDGE_PASSWORD` | yes (or prompted) | Unlocks `auth.json`; generated once during `proton-sync auth` |
| `PROTON_TOTP` | if 2FA enabled | Current TOTP one-time code. Read at `sync`/`daemon` startup. If unset and 2FA is active, the user is prompted interactively. |

All other credentials live encrypted inside `auth.json`.

---

## Sync behaviour matrix

| Scenario | Action |
|---|---|
| New contact on Proton | Created on Synology |
| New contact on Synology | Created on Proton |
| Updated on Proton only | Written to Synology |
| Updated on Synology only | Written to Proton |
| Updated on both (conflict) | Duplicated with conflict suffix on both sides |
| Deleted on Proton | Deleted from Synology |
| Deleted on Synology | Deleted from Proton |
| First run (empty cache) | Full push Proton → Synology; pull Synology-only contacts |

---

## Security notes

- `auth.json` is AES-256-GCM encrypted. Key derived with scrypt
  (`N=32768, r=8, p=1`) from the bridge password.
- Decrypted credentials are held in memory only; never written to disk
  in plaintext.
- TOTP/2FA is evaluated at `sync`/`daemon` start (Proton session
  establishment). Supply via `PROTON_TOTP` for non-interactive use.
- No network port is exposed — the daemon only makes outbound connections.
- The Synology CardDAV URL should use HTTPS.

---

## Dependencies

| Package | Purpose |
|---|---|
| [go-proton-api](https://github.com/ProtonMail/go-proton-api) | Proton HTTP client + SRP auth |
| [gopenpgp/v2](https://github.com/ProtonMail/gopenpgp) | OpenPGP sign/verify contact cards |
| [go-vcard](https://github.com/emersion/go-vcard) | vCard 3.0/4.0 encode/decode |
| [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite) | Pure-Go SQLite (no CGO) |
| [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) | scrypt KDF |
| [golang.org/x/term](https://pkg.go.dev/golang.org/x/term) | Secure password prompts |
