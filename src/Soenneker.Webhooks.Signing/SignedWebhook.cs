namespace Soenneker.Webhooks.Signing;

/// <summary>
/// A serialized webhook payload and the headers calculated from those exact payload bytes.
/// </summary>
public sealed record SignedWebhook
{
    public SignedWebhook(byte[] payload, WebhookSigningHeaders headers)
    {
        Payload = payload;
        Headers = headers;
    }

    /// <summary>
    /// The exact UTF-8 JSON payload bytes that were signed and must be sent as the request body.
    /// </summary>
    public byte[] Payload { get; }

    /// <summary>
    /// The Standard Webhooks metadata and signature headers for <see cref="Payload"/>.
    /// </summary>
    public WebhookSigningHeaders Headers { get; }
}
