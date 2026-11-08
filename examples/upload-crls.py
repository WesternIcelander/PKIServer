#!/usr/bin/env python3
"""Upload a batch of (pre-signed) CRLs to a PKIServer and print the coverage report.

Usage:
    upload-crls.py [options] BASE_URL [FILE_OR_DIR ...]

Every FILE is a CRL in DER or PEM form (a PEM file may hold several CRLs). A DIR is
searched (not recursively) for *.crl and *.pem files; PEM files there without a CRL
(e.g. the CA certificate) are skipped. All CRLs are sent to
POST /api/crl in a single PEM request, so the server processes them in increasing CRL
Number order regardless of the order they are given in. Afterwards the coverage report
(GET /api/crl/<slug>) of every CA that a CRL was uploaded for, plus every --slug, is
printed.

With no files, only the coverage reports of the --slug CAs are printed.

The API only accepts HTTPS (uploads are unauthenticated: a not-yet-valid CRL must not be
captured in transit), so BASE_URL must be https:// unless --allow-http is given.

Exit codes:
    0  every CRL was accepted and no coverage warning
    1  a CRL was rejected, or a request failed
    2  usage error
    3  everything was accepted, but a CA's coverage runs out within the server's
       warning threshold (coverageWarningDays)

Only the Python 3 standard library is needed.
"""

import argparse
import base64
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

PEM_CRL = re.compile(
    rb"-----BEGIN X509 CRL-----\s*(.+?)\s*-----END X509 CRL-----", re.DOTALL
)
SLUG = re.compile(r"^[a-z0-9._~-]+$")

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_COVERAGE = 3


class UsageError(Exception):
    pass


def pem_block(der):
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN X509 CRL-----\n" + "\n".join(lines) + "\n-----END X509 CRL-----\n"


def read_crls(path, skip_other_pem=False):
    """The CRLs in one file, as PEM blocks."""
    with open(path, "rb") as f:
        data = f.read()
    blocks = PEM_CRL.findall(data)
    if blocks:
        return [pem_block(base64.b64decode(b"".join(b.split()))) for b in blocks]
    if b"-----BEGIN" in data:
        if skip_other_pem:
            print(f"skipping {path}: no X509 CRL in this PEM file", file=sys.stderr)
            return []
        raise UsageError(f"{path}: no X509 CRL in this PEM file")
    if not data.startswith(b"\x30"):
        raise UsageError(f"{path}: neither a DER nor a PEM CRL")
    return [pem_block(data)]


def collect_files(args):
    """[(path, found by scanning a directory)]"""
    files = []
    for arg in args:
        if os.path.isdir(arg):
            found = sorted(
                os.path.join(arg, name)
                for name in os.listdir(arg)
                if name.lower().endswith((".crl", ".pem"))
                and os.path.isfile(os.path.join(arg, name))
            )
            if not found:
                raise UsageError(f"{arg}: no *.crl or *.pem files in this directory")
            files.extend((f, True) for f in found)
        elif os.path.isfile(arg):
            files.append((arg, False))
        else:
            raise UsageError(f"{arg}: no such file or directory")
    return files


class Client:
    def __init__(self, base_url, headers, context, timeout):
        self.base_url = base_url.rstrip("/")
        self.headers = headers
        self.context = context
        self.timeout = timeout

    def request(self, method, path, body=None, content_type=None):
        """(status, parsed JSON or None, raw text) of one API request."""
        req = urllib.request.Request(self.base_url + path, data=body, method=method)
        for name, value in self.headers:
            req.add_header(name, value)
        req.add_header("Accept", "application/json")
        if content_type:
            req.add_header("Content-Type", content_type)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.context) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        text = raw.decode("utf-8", "replace")
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        return status, parsed, text


def parse_time(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def fmt_time(s):
    if not s:
        return "-"
    return parse_time(s).strftime("%Y-%m-%d %H:%M:%S UTC")


def fmt_duration(seconds):
    if seconds <= 0:
        return "expired " + fmt_duration(-seconds) + " ago" if seconds < 0 else "now"
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def print_upload_results(results):
    """Prints one line per CRL; returns (slugs, any rejected)."""
    slugs = []
    rejected = False
    for r in results:
        who = r.get("slug") or r.get("issuer", "?")
        number = r.get("number", "?")
        result = r.get("result", "?")
        if result == "rejected":
            rejected = True
            print(f"  {who} #{number}: REJECTED: {r.get('error', 'no reason given')}")
        else:
            line = f"  {who} #{number}: {result}"
            if result == "pending" and r.get("activatesAt"):
                line += f", activates {fmt_time(r['activatesAt'])}"
            line += f", nextUpdate {fmt_time(r.get('nextUpdate'))}"
            if r.get("unchanged"):
                line += " (already on the server)"
            print(line)
        discarded = r.get("discarded") or []
        if discarded:
            numbers = ", ".join("#" + d.get("number", "?") for d in discarded)
            print(f"    discarded pre-signed CRLs: {numbers}")
            print("    -> sign and upload a fresh set of backups numbered above this CRL")
        if r.get("slug") and r["slug"] not in slugs:
            slugs.append(r["slug"])
    return slugs, rejected


def print_coverage(slug, report):
    """Prints a coverage report; returns True if it carries a coverage warning."""
    print(f"{slug}:")
    current = report.get("current")
    if current:
        stale = "  STALE (past nextUpdate)" if current.get("stale") else ""
        print(f"  current   #{current.get('number')}: thisUpdate {fmt_time(current.get('thisUpdate'))},"
              f" nextUpdate {fmt_time(current.get('nextUpdate'))}{stale}")
    else:
        print("  current   none")
    pending = report.get("pending") or []
    if not pending:
        print("  pending   none")
    for p in pending:
        print(f"  pending   #{p.get('number')}: thisUpdate {fmt_time(p.get('thisUpdate'))},"
              f" nextUpdate {fmt_time(p.get('nextUpdate'))}")
    print(f"  highest CRL Number used: {report.get('highestCrlNumber', '-')}"
          f" (next CRL must be numbered at least {report.get('nextCrlNumber', '-')})")
    until = report.get("coverageUntil")
    warning = bool(report.get("coverageWarning"))
    if until:
        remaining = report.get("coverageRemainingSeconds")
        left = f" ({fmt_duration(remaining)})" if remaining is not None else ""
        print(f"  coverage until: {fmt_time(until)}{left}")
    else:
        print("  coverage until: - (no CRL)")
    if warning:
        print(f"  WARNING: coverage runs out within {report.get('coverageWarningDays', '?')} days;"
              " upload more pre-signed CRLs")
    return warning


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Upload a batch of pre-signed CRLs to a PKIServer and print the coverage report.",
        epilog="Exit codes: 0 ok, 1 rejected or failed, 2 usage, 3 coverage warning.",
    )
    parser.add_argument("base_url", metavar="BASE_URL",
                        help="the server, e.g. https://pki.example.com")
    parser.add_argument("paths", metavar="FILE_OR_DIR", nargs="*",
                        help="CRL files (DER or PEM) or directories holding *.crl / *.pem files")
    parser.add_argument("-s", "--slug", action="append", default=[],
                        help="also print the coverage report of this CA (repeatable)")
    parser.add_argument("--cacert", metavar="FILE",
                        help="CA bundle to verify the server's TLS certificate with")
    parser.add_argument("-H", "--header", action="append", default=[], metavar="'NAME: VALUE'",
                        help="extra request header, e.g. for authentication at the proxy (repeatable)")
    parser.add_argument("--allow-http", action="store_true",
                        help="allow a plain http:// BASE_URL (testing only: CRLs travel unencrypted)")
    parser.add_argument("--timeout", type=float, default=30, help="request timeout in seconds (default 30)")
    parser.add_argument("--dry-run", action="store_true",
                        help="read and check the CRL files, but upload nothing")
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return EXIT_USAGE if e.code else EXIT_OK

    try:
        url = urllib.parse.urlsplit(args.base_url)
        if url.scheme not in ("http", "https") or not url.netloc:
            raise UsageError(f"{args.base_url}: not an http(s) URL")
        if url.scheme == "http" and not args.allow_http:
            raise UsageError("the API only accepts HTTPS; use an https:// URL"
                             " (or --allow-http for testing)")
        for slug in args.slug:
            if not SLUG.match(slug):
                raise UsageError(f"{slug}: not a valid slug")
        headers = []
        for h in args.header:
            name, sep, value = h.partition(":")
            if not sep or not name.strip():
                raise UsageError(f"{h}: expected 'Name: value'")
            headers.append((name.strip(), value.strip()))
        if not args.paths and not args.slug:
            raise UsageError("nothing to do: give CRL files to upload or --slug to report on")
        files = collect_files(args.paths)
        blocks = []
        for path, scanned in files:
            blocks.extend(read_crls(path, skip_other_pem=scanned))
        if args.paths and not blocks:
            raise UsageError("no CRLs found")
    except (UsageError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE

    if args.dry_run:
        print(f"{len(blocks)} CRL(s) in {len(files)} file(s); not uploading (--dry-run)")
        return EXIT_OK

    context = ssl.create_default_context(cafile=args.cacert) if url.scheme == "https" else None
    client = Client(args.base_url, headers, context, args.timeout)
    failed = False
    slugs = []

    try:
        if blocks:
            print(f"Uploading {len(blocks)} CRL(s) from {len(files)} file(s) to {client.base_url}/api/crl")
            status, body, text = client.request(
                "POST", "/api/crl", "".join(blocks).encode("ascii"), "application/x-pem-file")
            if isinstance(body, dict) and isinstance(body.get("crls"), list):
                slugs, rejected = print_upload_results(body["crls"])
                failed = rejected or status != 200
            else:
                failed = True
                message = body.get("error") if isinstance(body, dict) else text.strip()
                print(f"  upload failed: HTTP {status}: {message}")
            print()

        for slug in args.slug:
            if slug not in slugs:
                slugs.append(slug)

        warning = False
        if slugs:
            print("Coverage:")
        for slug in slugs:
            status, body, text = client.request("GET", "/api/crl/" + urllib.parse.quote(slug))
            if status == 200 and isinstance(body, dict):
                warning |= print_coverage(slug, body)
            else:
                failed = True
                message = body.get("error") if isinstance(body, dict) else text.strip()
                print(f"{slug}:\n  coverage report failed: HTTP {status}: {message}")
    except (urllib.error.URLError, OSError, ssl.SSLError) as e:
        reason = getattr(e, "reason", e)
        print(f"error: request to {client.base_url} failed: {reason}", file=sys.stderr)
        return EXIT_FAILED

    if failed:
        return EXIT_FAILED
    if warning:
        return EXIT_COVERAGE
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
