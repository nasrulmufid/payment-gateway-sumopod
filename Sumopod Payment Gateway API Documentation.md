# Sumopod Payment Gateway API Documentation

## Supported Payment Methods

| Method | Code | Settlement Time | Fee |
| :--- | :--- | :--- | :--- |
| **QRIS** | `qris` | Settles in 2 days | 0.7% + Rp 300 |

---

## Create Payment

To create a new payment, make a `POST` request to the API endpoint.

### Request (cURL)

```bash
curl -X POST https://api-pay.sumopod.com/payments \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: YOUR_API_KEY" \
  -d '{
    "order_id": "INV-2026-001",
    "amount": 50000,
    "currency": "IDR",
    "expires_in_hours": 24,
    "success_return_url": "https://your-site.com/success",
    "cancel_return_url": "https://your-site.com/cancel",
    "payment_method_type_code": "QRIS"
  }'
```

**Parameters:**
*   `expires_in_hours`: *(Optional)* Defaults to 24 hours if omitted. Maximum allowed is 24 hours.
*   `success_return_url` and `cancel_return_url`: *(Optional)* Override your project's configured return URLs for this payment only.
*   `payment_method_type_code`: *(Optional)* Get it from the "Supported Payment Methods" list.

### Response

```json
{
  "payment_id": "uuid",
  "order_id": "INV-2026-001",
  "amount": 50000,
  "fee": 750,
  "net_amount": 49250,
  "payment_link_url": "https://pay.sumopod.com/...",
  "status": "pending",
  "expires_at": "2026-01-01T12:00:00Z"
}
```

---

## Webhook Events

Configure your webhook URL in the **Settings** tab. We'll send HTTP POST requests to your URL when payment events occur.

### Supported Events

| Event | Description |
| :--- | :--- |
| `payment.completed` | Payment has been successfully completed |
| `payment.failed` | Payment has failed |
| `payment.expired` | Payment link has expired without payment |
| `payment.test` | Test event sent from Settings page |

### Webhook Payload

```json
{
  "event_type": "payment.completed",
  "data": {
    "payment_id": "uuid",
    "order_id": "INV-2026-001",
    "amount": 50000,
    "fee": 750,
    "net_amount": 49250,
    "status": "completed",
    "payment_method": "qris",
    "paid_at": "2026-06-18T12:00:00Z",
    "settled_at": "2026-06-20T12:00:00Z",
    "completed_at": "2026-06-20T12:00:00Z"
  }
}
```

**Timestamp Descriptions:**
*   `paid_at`: Timestamp when payment was completed by customer.
*   `settled_at`: Estimated timestamp when funds settle into available balance (T+2).
*   `completed_at`: Equals `settled_at` for backward compatibility.

> **Expected Response**
> Your endpoint must respond with a `2xx` status code within 10 seconds. If we don't receive a successful response, the webhook will be marked as failed and can be resent from the Webhooks tab.

---

## Verifying Webhook Signatures

Every request includes three headers so you can confirm it really came from us: `svix-id`, `svix-timestamp`, and `svix-signature`. Get your project's signing secret from the Settings tab, then recompute the signature and compare it to the header. Never trust the payload without checking this.

Use the raw, unparsed request body. A single re-formatted whitespace character will break the signature match. We recommend using Svix's official verification libraries instead of hand-rolling this in production.

### Node.js

```javascript
const crypto = require("crypto");

function verifyWebhookSignature(secret, svixId, svixTimestamp, svixSignature, rawBody) {
  const secretBytes = Buffer.from(secret.replace("whsec_", ""), "base64");
  const signedContent = `${svixId}.${svixTimestamp}.${rawBody}`;

  const expectedSignature = crypto
    .createHmac("sha256", secretBytes)
    .update(signedContent)
    .digest("base64");

  // svix-signature may contain multiple space-separated "v1,<sig>" values
  // (this happens for ~24h after rotating the secret)
  const signatures = svixSignature.split(" ").map((s) => s.split(",")[1]);
  return signatures.includes(expectedSignature);
}

// Express route, use express.raw() so req.body stays unparsed
app.post("/webhook", express.raw({ type: "application/json" }), (req, res) => {
  const isValid = verifyWebhookSignature(
    process.env.WEBHOOK_SECRET, // whsec_...
    req.headers["svix-id"],
    req.headers["svix-timestamp"],
    req.headers["svix-signature"],
    req.body.toString("utf8")
  );

  if (!isValid) {
    return res.status(401).send("Invalid signature");
  }

  const event = JSON.parse(req.body);
  console.log("Verified webhook:", event.event_type);
  res.sendStatus(200);
});
```

### PHP

```php
<?php

function verifyWebhookSignature(string $secret, string $svixId, string $svixTimestamp, string $svixSignature, string $rawBody): bool
{
    $secretBytes = base64_decode(str_replace('whsec_', '', $secret));
    $signedContent = "{$svixId}.{$svixTimestamp}.{$rawBody}";

    $expectedSignature = base64_encode(hash_hmac('sha256', $signedContent, $secretBytes, true));

    // svix-signature may contain multiple space-separated "v1,<sig>" values
    // (this happens for ~24h after rotating the secret)
    foreach (explode(' ', $svixSignature) as $part) {
        [$version, $signature] = explode(',', $part, 2);
        if (hash_equals($expectedSignature, $signature)) {
            return true;
        }
    }

    return false;
}

$rawBody = file_get_contents('php://input');

$isValid = verifyWebhookSignature(
    getenv('WEBHOOK_SECRET'), // whsec_...
    $_SERVER['HTTP_SVIX_ID'],
    $_SERVER['HTTP_SVIX_TIMESTAMP'],
    $_SERVER['HTTP_SVIX_SIGNATURE'],
    $rawBody
);

if (!$isValid) {
    http_response_code(401);
    exit('Invalid signature');
}

$event = json_decode($rawBody, true);
echo "Verified webhook: {$event['event_type']}";
```

### Golang

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func verifyWebhookSignature(secret, svixID, svixTimestamp, svixSignature string, rawBody []byte) bool {
	secretBytes, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	signedContent := svixID + "." + svixTimestamp + "." + string(rawBody)

	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(signedContent))
	expectedSignature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// svix-signature may contain multiple space-separated "v1,<sig>" values
	// (this happens for ~24h after rotating the secret)
	for _, part := range strings.Fields(svixSignature) {
		sig := strings.TrimPrefix(part, "v1,")
		if hmac.Equal([]byte(sig), []byte(expectedSignature)) {
			return true
		}
	}
	return false
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	valid := verifyWebhookSignature(
		"whsec_...", // your project's signing secret
		r.Header.Get("Svix-Id"),
		r.Header.Get("Svix-Timestamp"),
		r.Header.Get("Svix-Signature"),
		body,
	)

	if !valid {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	fmt.Fprintln(w, "Verified webhook")
}
```

---

## Verifying the Webhook Token

As a simpler alternative to signature verification, every request also includes an `X-Webhook-Token` header. Get your project's webhook token from the Settings tab, then compare it directly. No HMAC computation needed.

### Node.js

```javascript
// Express route
app.post("/webhook", express.json(), (req, res) => {
  const expected = process.env.WEBHOOK_TOKEN; // whtok_...
  const received = req.headers["x-webhook-token"];

  if (expected !== received) {
    return res.status(401).send("Invalid webhook token");
  }

  console.log("Verified webhook:", req.body.event_type);
  res.sendStatus(200);
});
```

### PHP

```php
<?php

$expected = getenv('WEBHOOK_TOKEN'); // whtok_...
$received = $_SERVER['HTTP_X_WEBHOOK_TOKEN'] ?? '';

if ($expected !== $received) {
    http_response_code(401);
    exit('Invalid webhook token');
}

$event = json_decode(file_get_contents('php://input'), true);
echo "Verified webhook: {$event['event_type']}";
```

### Golang

```go
package main

import (
	"encoding/json"
	"net/http"
)

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	expected := "whtok_..." // your project's webhook token
	received := r.Header.Get("X-Webhook-Token")

	if expected != received {
		http.Error(w, "Invalid webhook token", http.StatusUnauthorized)
		return
	}

	var event map[string]interface{}
	json.NewDecoder(r.Body).Decode(&event)
	w.WriteHeader(http.StatusOK)
}
```