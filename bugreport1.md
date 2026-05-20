# Bug Report 1: X-Forwarded-Host trust-boundary confusion

## Summary
`X-Forwarded-Host` can be preserved from untrusted client input and forwarded downstream, creating a trust-boundary risk if origin services use it for redirects, URL generation, auth decisions, or tenant routing.

## Affected code
- `/home/runner/work/zuul/zuul/zuul-core/src/main/java/com/netflix/netty/common/proxyprotocol/StripUntrustedProxyHeadersHandler.java`
  - strips: `x-forwarded-for`, `x-forwarded-port`, `x-forwarded-proto`, `x-forwarded-proto-version`, `x-real-ip`
  - does **not** strip `x-forwarded-host`
- `/home/runner/work/zuul/zuul/zuul-core/src/main/java/com/netflix/zuul/util/ProxyUtils.java`
  - `OVERWRITE_XF_HEADERS` default is `false`
  - if `X-Forwarded-Host` already exists, it is kept

## Why this matters
If downstream code trusts `X-Forwarded-Host`, client-controlled values can influence security-sensitive behavior.

## Reproducible low-impact PoC
Use any harmless endpoint that reflects absolute URLs or redirects.

1. Baseline request:
```bash
curl -isk 'https://TARGET/SAFE_ENDPOINT'
```

2. Inject `X-Forwarded-Host`:
```bash
curl -isk 'https://TARGET/SAFE_ENDPOINT' \
  -H 'X-Forwarded-Host: attacker.example'
```

3. Compare responses:
- `Location` header differences
- absolute URL generation differences
- any host-based behavior changes

## Expected secure behavior
Untrusted client-supplied forwarding headers should be stripped or overwritten at the edge.

## Actual behavior
`X-Forwarded-Host` may survive and propagate to origin unless explicitly overwritten.

## Evidence to attach
- Raw request/response pair (baseline vs injected)
- Timestamps and request IDs
- Exact endpoint used
- Diff showing only header change and resulting behavior change

## Impact (if confirmed in production behavior)
- Open redirect primitives
- host-header style confusion in auth/callback logic
- tenant/policy misrouting

## Likelihood
Likely valid as a trust-boundary issue; impact depends on downstream header trust.

## Scope / bounty eligibility
Likely in scope if reproduced on Netflix in-scope assets with a clear security impact.

## Suggested remediation
- Strip `X-Forwarded-Host` from untrusted sources in `StripUntrustedProxyHeadersHandler`, or
- enforce overwrite for all forwarded headers at ingress with strict trusted-proxy policy.

