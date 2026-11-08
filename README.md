# PKIServer

A small HTTP server that publishes X.509 material for an offline CA: signing (CA)
certificates, CRLs (including pre-signed, post-dated ones) and end-entity certificates.
It never holds a private key; everything it accepts must verify against roots the admin
installed on the server.

## Running

```
java -jar PKIServer.jar [--config config.json]
```

`config.json` (all keys optional; paths are relative to the config file):

```json
{
  "listen": "0.0.0.0:8080",
  "trustedProxies": ["127.0.0.1"],
  "dataDir": "data",
  "limits": {
    "maxUploadBytes": 1048576,
    "uploadsPerMinutePerIp": 60,
    "crlMaxFutureDays": 366,
    "coverageWarningDays": 30
  },
  "notifications": {
    "webhook": {"url": "https://hooks.example.com/pki"}
  }
}
```

## Notifications

Optional. With a `webhook` and/or `email` under `notifications`, the server checks every
`checkIntervalMinutes` (and at startup) for:

- **CRL coverage running low**: the last `nextUpdate` across a CA's current and pending
  CRLs is less than `limits.coverageWarningDays` away (`crl-coverage-low`);
- **stale CRL**: the current CRL is past its `nextUpdate` (`crl-stale`);
- **signing certificate nearing expiry**: less than `certExpiryWarningDays` left, or
  already expired while still installed (`signing-cert-expiring`);
- **published end-entity certificate nearing expiry**: less than `certExpiryWarningDays`
  left (`cert-expiring`). Once it has expired it is no longer reported.

An alert is sent when it first appears and repeated every `repeatHours` while it stays
active (`0`: only once). Alerts due at the same check go out together, one message per
channel. A failed delivery is retried at the next check. Which alerts were sent is kept in
memory only, so active alerts are sent again after a restart.

```json
"notifications": {
  "name": "pki.siggi.io",
  "certExpiryWarningDays": 30,
  "checkIntervalMinutes": 60,
  "repeatHours": 24,
  "webhook": {
    "url": "https://hooks.example.com/pki",
    "headers": {"Authorization": "Bearer …"}
  },
  "email": {
    "host": "smtp.example.com",
    "port": 587,
    "security": "starttls",
    "username": "pki@example.com",
    "password": "…",
    "from": "pki@example.com",
    "to": ["admin@example.com"]
  }
}
```

- `name` identifies the server in messages (default: the host name).
- The webhook gets a `POST` with a JSON body; any `2xx` counts as delivered. `text` makes
  it work as-is with Slack/Mattermost-style incoming webhooks:

  ```json
  {
    "server": "pki.siggi.io",
    "text": "PKIServer pki.siggi.io: 1 alert\n- CRL coverage of \"tls2\" runs out at …",
    "alerts": [{"type": "crl-coverage-low", "slug": "tls2", "at": "2026-12-01T00:00:00Z",
                "message": "CRL coverage of \"tls2\" runs out at …"}]
  }
  ```

  `serial` is added for `cert-expiring`; `at` is when coverage ends, the stale CRL's
  `nextUpdate`, or the certificate's `notAfter`.
- Email is plain text over SMTP. `security` is `starttls` (default, port 587; the mail is
  not sent if the server doesn't offer STARTTLS), `tls` (implicit TLS, port 465) or `none`
  (port 25). TLS certificates are checked against the JDK trust store and the host name.
  `username`/`password` (optional, together) use `AUTH PLAIN`. `to` is one address or a
  list.

## Deployment

PKIServer doesn't do TLS: it runs behind a reverse proxy that serves the public files on
plain HTTP (AIA and CRL Distribution Point fetchers often can't do HTTPS) and `/api/*` on
HTTPS only. Uploads are accepted only from an address in `trustedProxies` that sets
`X-Forwarded-Proto: https`. See [`deploy/README.md`](deploy/README.md) for the Docker
image, an example config, a docker compose + nginx setup and the proxy requirements.

## Installing roots

Roots (trust anchors) are never accepted over HTTP. They enter the server in one of two
ways: with the admin CLI, or by placing their files in the data directory by hand. Either
way, the server picks them up when it (re)starts.

### Admin CLI

```
java -jar PKIServer.jar [--config config.json] add-root <slug> <file>
java -jar PKIServer.jar [--config config.json] list
java -jar PKIServer.jar [--config config.json] remove <slug>
```

The commands work on the `dataDir` from the config file; `--data-dir <dir>` uses `<dir>`
instead (no config file needed).

- `add-root <slug> <file>` installs a root certificate (DER or PEM, exactly one
  certificate) under `<slug>`. The slug is chosen freely: it doesn't have to match the CN,
  e.g. the root `CN=Siggi.io` can be installed as `root2026`. It is refused unless:
  - the slug is URL-safe: only `a-z 0-9 - . _ ~`, not `.` or `..`, and not a reserved
    server path (`api`, `index.html`, `favicon.ico`, `robots.txt`, `.well-known`);
  - the slug is unused, and no installed certificate has the same subject and key;
  - the certificate is self-signed (subject = issuer), has `basicConstraints` `CA:TRUE`,
    and its signature verifies with its own public key.

  Installing the identical certificate under the same slug again is a no-op.
- `list` shows every signing certificate: slug, role (root/intermediate), subject,
  expiry, the current CRL's number and the number of published end-entity certificates.
- `remove <slug>` deletes a signing certificate together with its CRLs and end-entity
  certificates. It warns about installed certificates issued by it, which will no longer
  validate.

Exit codes: `0` success, `1` refused or failed, `2` usage error.

### By hand

Create `ca/<slug>/` in the data directory and put the certificate in it as `cert.der`:

```
mkdir -p data/ca/root2026
cp Siggi.io.crt data/ca/root2026/cert.der
```

That's all. `cert.der` may also be PEM (it is rewritten as DER at startup), and
`meta.json` is created at startup. The directory name is the slug, so it must use only
`a-z 0-9 - . _ ~`; directories with other names are ignored (and logged). If two
directories hold certificates with the same subject and key, the first by name wins and
the other is ignored. Hand-placed roots go through the same checks as `add-root` in the
startup integrity check (below), but only when the server starts, so prefer the CLI,
which reports problems right away.

To remove a CA by hand, stop the server and delete its `ca/<slug>/` directory.

## Data directory layout

DER files are the source of truth. The JSON files next to them are derived and rebuilt
at startup when missing or out of date (only `receivedAt`, `uploadedAt` and CRL states
are read back from them). Every write goes to a temporary file followed by an atomic
rename; leftover `.*.tmp` files are deleted at startup.

```
data/
  ca/<slug>/                     one directory per signing certificate; the name is its slug
    cert.der                     the signing certificate (the only file needed)
    meta.json                    role (root/intermediate), subject, issuer, serial,
                                 SPKI SHA-256, cert SHA-256, validity
    crl/
      <crlNumber>.crl            accepted CRLs, file name = CRL Number in decimal
      <crlNumber>.json           state (current/pending/superseded), thisUpdate,
                                 nextUpdate, receivedAt, SHA-256
      discarded.json             numbers + hashes of discarded pre-signed CRLs
    certs/<serial>/              end-entity certs issued by <slug>; serial in lowercase
                                 hex without leading zeros
      certificate.der
      meta.json                  subject, SANs, validity, SHA-256, uploadedAt
```

A certificate's role is derived from the certificate itself: it is a root if it is
self-signed and its signature verifies with its own key, otherwise an intermediate.

### Startup integrity check

At startup the server re-parses every stored file, rebuilds the metadata from the DER, and
re-verifies everything before serving it:

- roots: self-signed, `CA:TRUE`;
- intermediates: `CA:TRUE`, `keyCertSign` (if they have a Key Usage), and a valid path
  (PKIX) through installed intermediates that passed this check to an installed root;
- CRLs: signed by their CA, which has `cRLSign` (if it has a Key Usage), full CRL,
  `nextUpdate` after `thisUpdate`;
- end-entity certificates: not a CA, and a valid path through the CA they are stored under.

Expiry and revocation are not checked here: published objects stay published. Anything
that fails is logged (`Not serving …`) and withheld: not served, and not used to validate
other objects (e.g. everything issued below a removed root). Its files stay on disk
untouched, and its slug, CRL Number or serial stays taken, so fixing the cause (e.g.
reinstalling the root) and restarting brings it back. Slugs are never re-derived.

## Public files

Served over plain HTTP, for `GET` and `HEAD`:

| URL | Content |
|---|---|
| `/<slug>.der` (alias `/<slug>.crt`) | signing certificate, DER, `application/pkix-cert` |
| `/<slug>.pem` | signing certificate, PEM, `application/x-pem-file` |
| `/` (alias `/index.html`) | index page: signing certificates, their CRL status and coverage; published end-entity certificates and their revocation status |

Responses carry an `ETag` (and, for certificates, `Last-Modified`), and conditional
requests (`If-None-Match`, `If-Modified-Since`) get `304 Not Modified`. Certificates are
cacheable for an hour; the index page is `no-cache`.

## CRL coverage report

`GET /api/crl/<slug>` (read-only, no upload needed, but like all of `/api/*` only over
HTTPS through a trusted proxy) returns JSON describing a CA's CRLs:

```json
{
  "slug": "tls2",
  "now": "2026-11-08T00:00:00Z",
  "current": {"number": "2", "thisUpdate": "…", "nextUpdate": "…", "sha256": "…", "stale": false},
  "pending": [{"number": "3", "thisUpdate": "…", "nextUpdate": "…", "sha256": "…"}],
  "highestCrlNumber": "3",
  "nextCrlNumber": "4",
  "coverageUntil": "2026-11-28T00:00:00Z",
  "coverageRemainingSeconds": 1728000,
  "coverageWarningDays": 30,
  "coverageWarning": true
}
```

`highestCrlNumber` counts every CRL ever accepted, including superseded and discarded
ones, so the next CRL must use at least `nextCrlNumber`. `coverageUntil` is the last
`nextUpdate` across the current and pending CRLs. `coverageWarning` is set when that is
less than `limits.coverageWarningDays` away (or already past). The index page shows the
same information per CA.

## Certificate status

`GET /api/certificate/<slug>/<serial>` (read-only, HTTPS through a trusted proxy like the
rest of `/api/*`) returns the status of a published end-entity certificate:

```json
{
  "issuer": "tls2",
  "serial": "a3f1",
  "subject": "CN=www.example.com",
  "subjectAltNames": ["DNS:www.example.com"],
  "notBefore": "…", "notAfter": "…", "sha256": "…", "uploadedAt": "…",
  "now": "2026-11-08T00:00:00Z",
  "status": "revoked",
  "revoked": true,
  "revocation": {
    "revokedCa": null,
    "revokedSerial": "a3f1",
    "revocationDate": "2026-11-07T12:00:00Z",
    "reason": "keyCompromise",
    "crlIssuer": "tls2",
    "crlNumber": "5"
  },
  "urls": {"certificate": "/tls2/a3f1/certificate.pem", "chain": "…", "fullchain": "…", "der": "…"}
}
```

`status` is `revoked`, `expired`, `not-yet-valid` or `valid` (in that order of
precedence). A certificate counts as revoked when its issuer's current CRL lists it, or
when a signing certificate above it is listed in its own issuer's current CRL; then
`revokedCa` names that CA. `reason` is null when the CRL entry has no reason code.
Unknown slug or serial: `404`; malformed: `400`. The index page lists the same status for
every published end-entity certificate.

[`examples/upload-crls.py`](examples/upload-crls.py) is a signer-side helper that uploads a
batch of pre-signed CRLs and prints this report; see [`examples/README.md`](examples/README.md).
