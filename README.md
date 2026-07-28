[![](https://img.shields.io/nuget/v/soenneker.webhooks.signing.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.webhooks.signing/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.webhooks.signing/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.webhooks.signing/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.webhooks.signing.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.webhooks.signing/)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Webhooks.Signing
### A .NET utility for securely signing outgoing webhooks using the Standard Webhooks specification.

Implements the symmetric HMAC-SHA256 signing scheme from the [Standard Webhooks specification](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md).

## Installation

```bash
dotnet add package Soenneker.Webhooks.Signing
```

## Usage

Register the utility with dependency injection:

```csharp
services.AddWebhooksSigningUtilAsSingleton();
```

Generate a Standard Webhooks secret once and store it securely:

```csharp
string secret = signingUtil.GenerateSecret();
// whsec_<base64-encoded 32-byte key>
```

Pass an object to `Create`. It is serialized once with `JsonUtil.SerializeToUtf8Bytes`, and the
returned byte array is the exact payload that was signed:

```csharp
const string webhookId = "msg_2KWPBgLlAfxdpx2AI54pPJ85f4W";
DateTimeOffset attemptTime = DateTimeOffset.UtcNow;

var webhook = new
{
    Type = "contact.created",
    Data = new { Id = "abc" }
};

SignedWebhook signed = signingUtil.Create(
    webhookId,
    attemptTime,
    webhook,
    secret);

foreach ((string name, string value) in signed.Headers.ToDictionary())
    request.Headers.TryAddWithoutValidation(name, value);

request.Content = new ByteArrayContent(signed.Payload);
request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json")
{
    CharSet = "utf-8"
};
```

The generated headers follow the Standard Webhooks symmetric signature scheme:

```text
webhook-id: msg_2KWPBgLlAfxdpx2AI54pPJ85f4W
webhook-timestamp: 1674087231
webhook-signature: v1,<base64 HMAC-SHA256 signature>
```

For zero-downtime secret rotation, pass all active secrets to `Create`. The resulting
`webhook-signature` header contains the signatures separated by spaces:

```csharp
SignedWebhook signed = signingUtil.Create(
    webhookId,
    attemptTime,
    webhook,
    [currentSecret, previousSecret]);
```

String and byte overloads are also available when the payload is already serialized. Payload bytes
are signed exactly; do not parse and reserialize the body between signing and sending:

```csharp
string signature = signingUtil.Sign(webhookId, unixTimestamp, payloadBytes, secret);
```
