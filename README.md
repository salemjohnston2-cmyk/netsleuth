# NetSleuth API v1.0
Passive reconnaissance. One endpoint.

---

## Authentication
All requests require your API key in the header:
```
x-api-key: NS-XXXXXXXXXXXXXXXX
```

---

## Endpoints

### Scan a domain (default — 4 modules)
```
curl https://your-railway-url.up.railway.app/v1/scan/tesla.com \
  -H "x-api-key: NS-XXXXXXXXXXXXXXXX"
```

### Scan with all 12 free modules
```
curl "https://your-railway-url.up.railway.app/v1/scan/tesla.com?modules=all" \
  -H "x-api-key: NS-XXXXXXXXXXXXXXXX"
```

### Scan with specific modules
```
curl "https://your-railway-url.up.railway.app/v1/scan/tesla.com?modules=whois,dns,emails,adminpanels" \
  -H "x-api-key: NS-XXXXXXXXXXXXXXXX"
```

### Check your key status
```
curl https://your-railway-url.up.railway.app/v1/status \
  -H "x-api-key: NS-XXXXXXXXXXXXXXXX"
```

### List available modules
```
curl https://your-railway-url.up.railway.app/v1/modules
```

---

## Free Modules

| Module       | What it returns                                              |
|--------------|--------------------------------------------------------------|
| whois        | Registrar, creation/expiry dates, nameservers, status        |
| subdomains   | All subdomains from certificate transparency logs            |
| dns          | A, AAAA, MX, TXT, NS, CNAME, SOA records                    |
| ip           | IP address, geolocation, ISP, ASN, reverse DNS              |
| headers      | Response headers, detected tech stack, missing sec headers   |
| robots       | Disallowed paths, sitemaps, user-agent rules                 |
| emails       | Exposed email addresses associated with the domain           |
| sourcecode   | Scripts, HTML comments, API paths, emails in page source     |
| endpoints    | Common API endpoints that respond (graphql, swagger, etc)    |
| adminpanels  | Admin/login panel paths that respond (200, 301, 302, 403)    |
| backlinks    | Subdomains and crawled URLs from CommonCrawl index           |
| indexing     | Indexed pages count and sample URLs from CommonCrawl         |

---

## Premium Modules (Pro tier)

| Module   | What it returns                             |
|----------|---------------------------------------------|
| ports    | Open ports and services via Shodan          |
| deepsubs | Expanded subdomain enumeration (10k+ words) |
| traffic  | Monthly traffic estimates and sources       |

---

## Response Format
```json
{
  "target": "tesla.com",
  "timestamp": "2026-04-26T00:00:00.000Z",
  "elapsed": "2.41s",
  "modules_run": 4,
  "tier": "starter",
  "requests_remaining": 94,
  "results": {
    "whois": { ... },
    "dns": { ... },
    "subdomains": { ... },
    "ip": { ... }
  }
}
```

---

## Tiers

| Tier    | Requests | Modules        | Price |
|---------|----------|----------------|-------|
| Starter | 100      | All 12 free    | $15   |
| Pro     | 500      | Free + Premium | $25   |

---

## Legal
For authorized testing only. You must own the domain or have written permission to scan it.
NetSleuth performs passive reconnaissance using public data sources only.
Abuse of this API will result in immediate key revocation.

---

## Deploy (Railway)

**Environment variables to set in Railway:**

| Variable     | Value                                              |
|--------------|----------------------------------------------------|
| KEYS_DATA    | `{"NS-YOURKEY":{"tier":"starter","limit":100}}`    |
| ADMIN_SECRET | any strong password you choose                     |

**Generate a new key:**
```
curl -X POST https://your-railway-url.up.railway.app/admin/key \
  -H "Content-Type: application/json" \
  -d '{"secret":"your_admin_secret","tier":"starter","limit":100}'
```
Then add the returned key to your KEYS_DATA env var.
