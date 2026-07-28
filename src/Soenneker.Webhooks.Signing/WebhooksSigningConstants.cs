namespace Soenneker.Webhooks.Signing;

/// <summary>
/// Constants defined by the Standard Webhooks symmetric signature scheme.
/// </summary>
public static class WebhooksSigningConstants
{
    /// <summary>
    /// The HTTP header containing the stable webhook message identifier.
    /// </summary>
    public const string WebhookIdHeader = "webhook-id";

    /// <summary>
    /// The HTTP header containing the delivery-attempt Unix timestamp.
    /// </summary>
    public const string WebhookTimestampHeader = "webhook-timestamp";

    /// <summary>
    /// The HTTP header containing one or more versioned webhook signatures.
    /// </summary>
    public const string WebhookSignatureHeader = "webhook-signature";

    /// <summary>
    /// The prefix applied to Base64-encoded symmetric signing secrets.
    /// </summary>
    public const string SecretPrefix = "whsec_";

    /// <summary>
    /// The Standard Webhooks version identifier for HMAC-SHA256 signatures.
    /// </summary>
    public const string SignatureVersion = "v1";

    /// <summary>
    /// The serialized HMAC-SHA256 signature prefix, including its delimiter.
    /// </summary>
    public const string SignaturePrefix = SignatureVersion + ",";

    /// <summary>
    /// The minimum symmetric signing-secret length permitted by the specification, in bytes.
    /// </summary>
    public const int MinimumSecretLength = 24;

    /// <summary>
    /// The default generated symmetric signing-secret length, in bytes.
    /// </summary>
    public const int DefaultSecretLength = 32;

    /// <summary>
    /// The maximum symmetric signing-secret length permitted by the specification, in bytes.
    /// </summary>
    public const int MaximumSecretLength = 64;

    /// <summary>
    /// The HMAC-SHA256 signature length, in bytes.
    /// </summary>
    public const int SignatureLength = 32;

    internal const int StackAllocationThreshold = 1024;
}
