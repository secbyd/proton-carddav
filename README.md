# proton-carddav

RFC 6352 CardDAV bridge for ProtonMail. Exposes your ProtonMail contacts as a
standard CardDAV address book compatible with Apple Contacts, DAVx⁵, Evolution,
Thunderbird (CardBook), and any other RFC 6352 client.

## How it works

```
CardDAV client  ←──HTTP/HTTPS──→  proton-carddav  ←──Proton API──→  ProtonMail
```

The bridge:

- Authenticates with Proton using SRP (via `go-proton-api`).
- Decrypts signed/encrypted contact cards using the user’s primary keyring.
- Merges multiple Proton card types into a single vCard 4.0 response.
- On writes, rebuilds and re-signs the Proton card structure before uploading.

## Quick start

```bash
export PROTON_USERNAME=you@proton.me
export PROTON_PASSWORD=youraccountpassword
# Only needed in two-password mode:
# export PROTON_MBOX_PASSWORD=yourmailboxpassword
export CARDDAV_BASE_URL=https://carddav.example.org
export CARDDAV_LISTEN=:8080
export CARDDAV_BASIC_USER=dav
export CARDDAV_BASIC_PASS=changeme

go run ./cmd/proton-carddav
```

Or with Docker:

```bash
docker build -t proton-carddav .
docker run --rm -p 8080:8080 \
  -e PROTON_USERNAME=you@proton.me \
  -e PROTON_PASSWORD=secret \
  -e CARDDAV_BASIC_USER=dav \
  -e CARDDAV_BASIC_PASS=changeme \
  proton-carddav
```

## Reverse proxy (TLS)

Always front the bridge with HTTPS. Example Caddy snippet:

```
carddav.example.org {
    reverse_proxy localhost:8080
}
```

## Client configuration

| Field | Value |
|---|---|
| Server URL | `https://carddav.example.org/dav/principals/me/` |
| Username | value of `CARDDAV_BASIC_USER` |
| Password | value of `CARDDAV_BASIC_PASS` |
| Address book path | auto-discovered via `PROPFIND` |

For iOS/macOS: **Settings → Mail → Accounts → Add Account → Other → Add CardDAV Account**.

## URL layout

```
/.well-known/carddav                         → 301 → /dav/principals/me/
/dav/principals/me/                          → DAV principal
/dav/addressbooks/me/                        → addressbook home
/dav/addressbooks/me/contacts/               → addressbook collection
/dav/addressbooks/me/contacts/{uid}.vcf      → vCard resource
```

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `PROTON_USERNAME` | ✓ | Proton account username |
| `PROTON_PASSWORD` | ✓ | Proton account password |
| `PROTON_MBOX_PASSWORD` | | Mailbox password (two-password mode only) |
| `CARDDAV_BASE_URL` | | External base URL (default: `http://localhost:8080`) |
| `CARDDAV_LISTEN` | | Listen address (default: `:8080`) |
| `CARDDAV_BASIC_USER` | | HTTP Basic Auth username |
| `CARDDAV_BASIC_PASS` | | HTTP Basic Auth password |

## Security notes

- Always run behind HTTPS. HTTP Basic Auth over plain HTTP exposes credentials.
- The bridge holds your decrypted Proton keyring in memory. Run on trusted infrastructure.
- For TOTP 2FA, wire `protonapi.WithTwoFactor(...)` into `loginProton` in `main.go`.
- Run as a non-root user inside Docker.

## Architecture

```
cmd/proton-carddav/
  main.go             ← auth, config, HTTP server bootstrap
internal/
  dav/
    server.go         ← HTTP method handlers, URL routing (RFC 6352)
    xml.go            ← DAV/CardDAV XML structures and property builders
  proton/
    bridge.go         ← Proton API adapter (list, get, upsert, delete)
```

## Known limitations

- Single-user only (one Proton account per bridge instance).
- `addressbook-query` filter expressions are not evaluated server-side; all
  contacts are returned and the client filters locally.
- Sync tokens are in-memory monotonic timestamps — a restart triggers a full
  client re-sync.
- TOTP / hardware-key 2FA requires additional wiring in `main.go`.

## Dependencies

- [go-proton-api](https://github.com/ProtonMail/go-proton-api) — Proton HTTP client + SRP auth
- [gopenpgp](https://github.com/ProtonMail/gopenpgp) — OpenPGP for card sign/decrypt
- [go-vcard](https://github.com/emersion/go-vcard) — vCard 3.0/4.0 encode/decode
