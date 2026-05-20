# Bug Report 2: Host blacklist canonicalization bypass for proxy-header stripping

## Summary
When proxy headers are conditionally stripped using host blacklist mode, the host check uses direct string equality and can be bypassed with host formatting variants (for example `:port` form).

## Affected code
- `/home/runner/work/zuul/zuul/zuul-core/src/main/java/com/netflix/netty/common/proxyprotocol/StripUntrustedProxyHeadersHandler.java`
  - `checkBlacklist(...)` compares:
  - `h.equalsIgnoreCase(req.headers().get(HttpHeaderNames.HOST))`
  - no host canonicalization prior to compare

## Why this matters
If blacklist-based stripping is used as a trust control, non-canonical Host variants can keep spoofable forwarding headers.

## Reproducible low-impact PoC
Assumption: blacklist contains `api.example.com`.

1. Request expected to trigger strip:
```bash
curl -isk 'https://TARGET/SAFE_ENDPOINT' \
  -H 'Host: api.example.com' \
  -H 'X-Forwarded-For: 1.2.3.4' \
  -H 'X-Real-IP: 1.2.3.4'
```

2. Variant request with port suffix:
```bash
curl -isk 'https://TARGET/SAFE_ENDPOINT' \
  -H 'Host: api.example.com:443' \
  -H 'X-Forwarded-For: 1.2.3.4' \
  -H 'X-Real-IP: 1.2.3.4'
```

3. Compare behavior where forwarded headers are consumed/logged/reflected by downstream.

## Expected secure behavior
Host canonicalization should make equivalent host forms evaluate consistently for security decisions.

## Actual behavior
Exact-match string compare may allow bypass of blacklist-based stripping.

## Evidence to attach
- Raw request/response pairs for both Host forms
- Any downstream proof that spoofed forwarding headers were retained in variant case
- Config proof that blacklist mode is enabled

## Impact (if confirmed in production behavior)
- Bypass of IP-based trust/audit controls relying on forwarding-header sanitization.

## Likelihood
Needs more proof (deployment-dependent), but code-level weakness is concrete.

## Scope / bounty eligibility
Potentially in scope if demonstrated against Netflix in-scope target with clear security impact.

## Suggested remediation
- Canonicalize Host before compare (strip port, normalize FQDN form), or
- avoid host-based conditional trust for forwarding-header stripping.

