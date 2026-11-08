# Examples

## `upload-crls.py`: upload pre-signed CRLs, print the coverage report

A signer-side helper (Python 3, standard library only) that uploads a batch of CRLs to
`POST /api/crl` and then prints the coverage report (`GET /api/crl/<slug>`) of every CA it
uploaded for.

```
examples/upload-crls.py https://pki.example.com crls/            # every *.crl / *.pem in crls/
examples/upload-crls.py https://pki.example.com crl-12.pem crl-13.crl
examples/upload-crls.py https://pki.example.com -s tls2          # report only
```

- CRLs may be DER or PEM (a PEM file may hold several). Directories are scanned for
  `*.crl` and `*.pem`; PEM files there without a CRL (e.g. the CA certificate) are skipped.
- All CRLs go to the server in one PEM request, which processes them in increasing CRL
  Number order, so the order of the files doesn't matter. The request must fit in the
  server's `maxUploadBytes` (1 MiB by default); split very large batches by number.
- For each CRL it prints the result: `current`, `pending` with its activation time, or the
  rejection reason. If an immediately effective CRL discarded pre-signed backups, it lists
  them: sign a fresh set numbered above that CRL and upload it.
- The coverage report shows the current and pending CRLs, the next CRL Number to use, and
  when coverage runs out, with a warning if that is within the server's
  `coverageWarningDays`.

Options: `-s/--slug SLUG` (also report on this CA, repeatable), `--cacert FILE` (CA bundle
for the server's TLS certificate), `-H 'Name: value'` (extra header, e.g. for proxy
authentication), `--dry-run` (only read the files), `--timeout SECONDS`.

The API only works over HTTPS, so the URL must be `https://`. `--allow-http` permits
`http://` for local testing only, e.g. against a server on localhost that lists
`127.0.0.1` in `trustedProxies`:

```
examples/upload-crls.py --allow-http -H 'X-Forwarded-Proto: https' http://127.0.0.1:8080 crls/
```

Exit codes: `0` all accepted and no coverage warning, `1` a CRL was rejected or a request
failed, `2` usage error, `3` all accepted but coverage runs out within the warning
threshold (handy for cron).
