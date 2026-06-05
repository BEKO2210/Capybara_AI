# Webhook Security — Verifying Signatures

Every outbound webhook is signed so you can prove it came from Capybara_AI and
was not tampered with in transit.

## The signature

For each delivery, Capybara_AI computes an HMAC-SHA256 over the **raw request
body** using the shared `secret` you configured, and sends it in a header:

```
X-Capybara-Signature: sha256=<hex>
X-Capybara-Event: document.uploaded
Content-Type: application/json
```

Body shape:

```json
{ "event": "document.uploaded", "data": { ... }, "timestamp": "2026-…Z" }
```

**Always verify the signature over the raw bytes** (do not re-serialize the JSON
first) and compare in **constant time**. Reject on mismatch.

## Node.js

```js
import { createHmac, timingSafeEqual } from 'node:crypto';

export function verify(rawBody, header, secret) {
  const expected = 'sha256=' + createHmac('sha256', secret).update(rawBody).digest('hex');
  const a = Buffer.from(header ?? ''), b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}
// Express: use express.raw({ type: 'application/json' }) so req.body is a Buffer.
```

## Python

```python
import hmac, hashlib

def verify(raw_body: bytes, header: str, secret: str) -> bool:
    expected = "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header or "")
# Flask: use request.get_data() to get the raw bytes.
```

## curl (manual check)

```bash
# Recompute the signature from a captured body and compare to the header.
printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -hex | sed 's/^.*= /sha256=/'
```

## Operational notes

- **Delivery + retries:** up to 3 attempts with backoff (1s, 5s, 30s by default;
  tune via `WEBHOOK_MAX_RETRIES` / `WEBHOOK_TIMEOUT_MS`). After the final failure
  the delivery is **dead-lettered** (`status = failed`); inspect attempts at
  `GET /api/admin/webhooks/:id/deliveries`.
- **Idempotency:** retries mean your endpoint may receive the same event more
  than once — make handlers idempotent (e.g. dedupe on `data` ids).
- **Secret storage:** the secret is stored AES-256-GCM encrypted per tenant and
  never returned by the API after creation.
- **Respond fast:** return `2xx` quickly (within the timeout) and process
  asynchronously; a non-2xx or timeout triggers a retry.
