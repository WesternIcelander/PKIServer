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
  }
}
```

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
the other is ignored. Unlike `add-root`, hand-placed files aren't checked for being a
self-signed CA when loaded, so prefer the CLI unless you have a reason not to.

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

## Public files

Served over plain HTTP, for `GET` and `HEAD`:

| URL | Content |
|---|---|
| `/<slug>.der` (alias `/<slug>.crt`) | signing certificate, DER, `application/pkix-cert` |
| `/<slug>.pem` | signing certificate, PEM, `application/x-pem-file` |
| `/` (alias `/index.html`) | index page: signing certificates, their CRL status and coverage |

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
