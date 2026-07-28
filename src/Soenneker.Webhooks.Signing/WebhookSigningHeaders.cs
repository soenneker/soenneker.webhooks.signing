using System.Collections.Generic;
using System.Globalization;

namespace Soenneker.Webhooks.Signing;

/// <summary>
/// The metadata headers required by a Standard Webhooks delivery.
/// </summary>
public sealed record WebhookSigningHeaders
{
    public WebhookSigningHeaders(string webhookId, long timestamp, string signature)
    {
        WebhookId = webhookId;
        Timestamp = timestamp;
        Signature = signature;
    }

    /// <summary>
    /// The stable identifier for the webhook event.
    /// </summary>
    public string WebhookId { get; }

    /// <summary>
    /// The Unix timestamp, in seconds, of this delivery attempt.
    /// </summary>
    public long Timestamp { get; }

    /// <summary>
    /// One or more space-delimited, versioned signatures.
    /// </summary>
    public string Signature { get; }

    /// <summary>
    /// Returns the headers using their specification-defined names and invariant values.
    /// </summary>
    public IReadOnlyDictionary<string, string> ToDictionary()
    {
        return new Dictionary<string, string>(3, System.StringComparer.OrdinalIgnoreCase)
        {
            [WebhooksSigningConstants.WebhookIdHeader] = WebhookId,
            [WebhooksSigningConstants.WebhookTimestampHeader] = Timestamp.ToString(CultureInfo.InvariantCulture),
            [WebhooksSigningConstants.WebhookSignatureHeader] = Signature
        };
    }
}
