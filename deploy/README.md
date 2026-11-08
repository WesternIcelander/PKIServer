# Deploying PKIServer

PKIServer speaks plain HTTP only and always runs behind a reverse proxy that terminates TLS:

- **Public files** (`/<slug>.der`, `.crt`, `.pem`, `.crl`, `.crl.pem`, `/<slug>/<serial>/…`,
  the index page) must be reachable over **plain HTTP**. AIA `caIssuers` and CRL
  Distribution Point fetchers often don't do HTTPS, and the URLs baked into certificates
  (`http://pki.example.com/tls2.der`) can't change later. Serving them over HTTPS as well
  is fine.
- **`/api/*`** (uploads and the coverage report) is accepted **over HTTPS only**. Uploads
  are unauthenticated, so HTTPS is what keeps a not-yet-valid CRL from being captured in
  transit and replayed later.

PKIServer decides whether a request came over HTTPS from two things, and needs both:

1. the TCP connection comes from an address in `trustedProxies` in `config.json`; and
2. the proxy set `X-Forwarded-Proto: https` (the last value counts, so a proxy that appends
   to a client-supplied header works too, but replacing it is cleaner).

Anything else gets `403` before the request body is read. With no `trustedProxies`,
uploads are disabled altogether.

## Files

| File | |
|---|---|
| [`../Dockerfile`](../Dockerfile) | runtime image around the shaded jar |
| [`config.example.json`](config.example.json) | example `config.json` for the compose setup |
| [`docker-compose.yml`](docker-compose.yml) | PKIServer + nginx on a private network |
| [`nginx.conf`](nginx.conf) | reverse proxy: port 80 public files, port 443 everything |

## Docker

The image runs the jar built on the host (SiggiHTTP comes from the siggi.io Maven
repository, which a plain container build can't reach):

```
mvn package
docker build -t pkiserver .
```

Inside the container:

- the config is `/etc/pkiserver/config.json` (the example config is baked in as a default;
  mount your own over it, read-only);
- the data directory is the volume `/data` (`"dataDir": "/data"`); it is also the working
  directory, where SiggiHTTP caches Cloudflare's address list (`cloudflare-ips.txt`);
- the server listens on port 8080 and runs as the unprivileged user `pkiserver`
  (uid 10001), which must be able to write `/data`.

### With docker compose (PKIServer + nginx)

```
cd deploy
cp config.example.json config.json
mkdir tls && cp /path/to/fullchain.pem /path/to/privkey.pem tls/
# set server_name in nginx.conf
docker compose up -d --build
```

The compose file puts both containers on a private network (`172.30.0.0/24`) where nginx
has the fixed address `172.30.0.2` and every other container gets an address from
`172.30.0.128/25`, and it **does not publish PKIServer's port**: only nginx publishes
ports 80 and 443. `trustedProxies` is exactly nginx's address, so nothing else can claim
to be the HTTPS proxy. If you change the subnet, change `trustedProxies` with it.

### Admin commands

Arguments to the container are appended to the server's command line, so the admin CLI
runs as a one-off container on the same volume. Changes are picked up when the server
restarts:

```
docker compose run --rm -v /path/to/Siggi.io.crt:/tmp/root.crt:ro pkiserver add-root root2026 /tmp/root.crt
docker compose run --rm pkiserver list
docker compose restart pkiserver
```

## Reverse proxy requirements

Whatever proxy you use (the nginx config here, Caddy, HAProxy, a load balancer):

- **Port 80 must not redirect to HTTPS** for this host name, and the host must not send
  HSTS (or be covered by an `includeSubDomains` HSTS policy on a parent domain if browsers
  should fetch it too). Many default proxy setups redirect everything; switch that off here.
  Caddy, for instance, needs an explicit `http://pki.example.com` site block.
- **Set `X-Forwarded-Proto` to the scheme the client used** on both ports: `http` on 80,
  `https` on 443 (nginx: `proxy_set_header X-Forwarded-Proto $scheme;`). Never pass a
  client-supplied value through unchanged.
- **Set `X-Forwarded-For`** to the client address. PKIServer uses it (only from trusted
  proxies) for the per-IP upload rate limit; without it, every upload counts against the
  proxy's own address.
- Optionally refuse `/api/*` on port 80 at the proxy, as `nginx.conf` does, so a request
  body sent over plain HTTP isn't forwarded at all. PKIServer refuses it either way.
- Allow request bodies at least as large as `limits.maxUploadBytes` (default 1 MiB) on 443.

Uploading clients must send a `Content-Type` such as `application/pkix-cert`,
`application/pkix-crl` or `application/x-pem-file`, not a form type: PKIServer refuses
`application/x-www-form-urlencoded` bodies (which is what `curl --data-binary` sends by
default) without reading them. For example:

```
curl -H 'Content-Type: application/pkix-crl' --data-binary @tls2-5.crl https://pki.example.com/api/crl
```

### `trustedProxies`

List only the address(es) the proxy connects to PKIServer **from**, as seen by PKIServer,
and make sure nothing else can connect from those addresses:

- **Proxy on the same host, no Docker:** listen on loopback only and trust loopback:
  `"listen": "127.0.0.1:8080"`, `"trustedProxies": ["127.0.0.1", "::1"]`.
- **Both in Docker:** the compose setup above, with a fixed proxy address and PKIServer's
  port unpublished.
- **Never trust the Docker bridge gateway** (e.g. `172.17.0.1`, or a range like
  `172.16.0.0/12`) while PKIServer's port is published. Connections relayed by Docker's
  userland proxy, from the host and in some setups from outside, arrive from the gateway
  address, so any client could then set `X-Forwarded-Proto: https` itself.
- **Proxy on another machine:** trust its address only, and firewall PKIServer's port so
  only the proxy can reach it.

### Cloudflare in front

If the host name is proxied through Cloudflare, Cloudflare must not "Always Use HTTPS" for
it (that redirects port 80), and the origin proxy must still connect to PKIServer itself:
Cloudflare's addresses are not trusted proxies. SiggiHTTP does accept `X-Forwarded-For`
from Cloudflare's address ranges for the client address (rate limiting), but never treats
them as the HTTPS proxy. With "Flexible" SSL Cloudflare talks to the origin over plain HTTP,
so the origin sees `http` and uploads are refused; use "Full (strict)".
