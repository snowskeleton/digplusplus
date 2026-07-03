# diggui

A web-based DNS toolkit. Look up DNS records, trace resolution paths from the root servers, and check email authentication configuration (SPF, DKIM, DMARC) and domain registrar info — all from a browser, with no `dig` binary required.

## Features

- **DNS lookup** — query any record type (A, AAAA, MX, TXT, NS, CNAME, PTR, SOA, CAA, DS, DNSKEY, SRV, TLSA, ANY, and more) against any nameserver
- **Trace mode** — iterative resolution from root hints, following referrals hop by hop (equivalent to `dig +trace`)
- **Short mode** — returns only record data, no metadata
- **Email checks** — SPF policy, DMARC policy, DKIM selector probing, and WHOIS/registrar lookup
- **Provider detection** — fingerprints MX and NS records to identify common providers (Google Workspace, Cloudflare, Route 53, etc.)
- **Authoritative TTL** — for cached responses, also fetches the TTL as set at the authoritative server

## Running

### Docker (recommended)

```bash
docker compose up -d
```

The app listens on port `8000`.

### Local development

```bash
pip install -r requirements.txt
python app.py
```

Runs on port `5000` by default. Set `PORT` to override.

## API

All endpoints accept `POST` with a JSON body and return JSON.

### `POST /api/dig`

| Field    | Type    | Description                                      |
|----------|---------|--------------------------------------------------|
| `domain` | string  | Domain name or IP address (required)             |
| `type`   | string  | Record type (default: `A`)                       |
| `server` | string  | Nameserver IP to query (default: system resolver)|
| `trace`  | boolean | Enable trace mode (default: `false`)             |
| `short`  | boolean | Return data values only (default: `false`)       |

### `POST /api/spf`
### `POST /api/dmarc`
### `POST /api/dkim`
### `POST /api/registrar`

Each accepts `{ "domain": "example.com" }` and returns parsed results for the respective check.

## Stack

- [Flask](https://flask.palletsprojects.com/) — web framework
- [dnspython](https://www.dnspython.org/) — DNS resolution (no `dig` binary dependency)
- [Gunicorn](https://gunicorn.org/) — production WSGI server
