# Bugs

The findings below are based only on directly verifiable code paths in this repository, with no speculative assumptions.

## 1) Authentication bypass via unsigned `userAuthCookie` in push auth
- **CWE:** CWE-565 (Reliance on Cookies without Validation and Integrity Checking)
- **CVSS v3.1:** **9.1** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
- **Affected file:** `/home/runner/work/zuul/zuul/zuul-sample/src/main/java/com/netflix/zuul/sample/push/SamplePushAuthHandler.java`

### Evidence
`SamplePushAuthHandler#doAuth` accepts any non-empty `userAuthCookie` value as authenticated identity (`customerId`) and returns successful auth without signature, MAC, expiry, or server-side session verification.

### Impact
An attacker can forge `userAuthCookie` and impersonate arbitrary users on push channels (WebSocket/SSE) in deployments using this sample auth path.

### PoC
1. Start sample server in push mode (WebSocket/SSE).
2. Send handshake with forged cookie:
   ```http
   GET /push/ws HTTP/1.1
   Host: target
   Upgrade: websocket
   Connection: Upgrade
   Sec-WebSocket-Version: 13
   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
   Cookie: userAuthCookie=victimCustomer123
   ```
3. Observe authenticated push session established as `victimCustomer123`.

---

## 2) X-Forwarded-* trust bypass through host blacklist exact-match check
- **CWE:** CWE-807 (Reliance on Untrusted Inputs in a Security Decision)
- **CVSS v3.1:** **7.5** (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N)
- **Affected file:** `/home/runner/work/zuul/zuul/zuul-core/src/main/java/com/netflix/netty/common/proxyprotocol/StripUntrustedProxyHeadersHandler.java`

### Evidence
`checkBlacklist` strips proxy headers only when `Host` exactly equals a blacklist entry:
- `h.equalsIgnoreCase(req.headers().get(HttpHeaderNames.HOST))`

No normalization is applied (e.g., stripping `:port`, case variants with port, trailing dot canonicalization), so blacklist checks can be bypassed.

### Impact
When `allowProxyHeadersWhen=ALWAYS` with host blacklist protection, an attacker can preserve spoofed `X-Forwarded-For`/`X-Real-IP` values by sending a host variant not exactly equal to blacklist entry, potentially bypassing IP-based controls/auditing.

### PoC
Assume blacklist contains `api.example.com`.

Request:
```http
GET / HTTP/1.1
Host: api.example.com:443
X-Forwarded-For: 1.2.3.4
X-Real-IP: 1.2.3.4
```

Expected security behavior: strip spoofable forwarding headers.
Actual behavior: blacklist comparison fails (`api.example.com` != `api.example.com:443`), headers remain.

---

## 3) Deprecated/insecure TLS protocol versions enabled in sample SSL configuration
- **CWE:** CWE-757 (Selection of Less-Secure Algorithm During Negotiation)
- **CVSS v3.1:** **5.9** (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N)
- **Affected file:** `/home/runner/work/zuul/zuul/zuul-sample/src/main/java/com/netflix/zuul/sample/SampleServerStartup.java`

### Evidence
`WWW_PROTOCOLS` includes legacy protocols:
- `TLSv1.1`, `TLSv1`, and `SSLv3`

These are passed into server SSL configuration for HTTPS/mTLS startup modes.

### Impact
If sample SSL modes are used, clients may negotiate weak/deprecated protocols, increasing risk of downgrade/cryptographic attacks inconsistent with modern TLS baselines.

### PoC
1. Run sample with `SERVER_TYPE` set to `HTTP2` or `HTTP_MUTUAL_TLS`.
2. Attempt legacy protocol handshake:
   ```bash
   openssl s_client -connect 127.0.0.1:7001 -tls1
   ```
   (or `-ssl3` where supported by client tooling)
3. If handshake succeeds, weak protocol negotiation is confirmed.
