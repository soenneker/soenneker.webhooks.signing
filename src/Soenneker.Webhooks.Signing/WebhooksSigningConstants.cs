namespace Soenneker.Webhooks.Signing;

/// <summary>
/// Constants defined by the Standard Webhooks symmetric signature scheme.
/// </summary>
public static class WebhooksSigningConstants
{
    public const string WebhookIdHeader = "webhook-id";
    public const string WebhookTimestampHeader = "webhook-timestamp";
    public const string WebhookSignatureHeader = "webhook-signature";

    public const string SecretPrefix = "whsec_";
    public const string SignatureVersion = "v1";
    public const string SignaturePrefix = SignatureVersion + ",";

    public const int MinimumSecretLength = 24;
    public const int DefaultSecretLength = 32;
    public const int MaximumSecretLength = 64;
    public const int SignatureLength = 32;

    internal const int StackAllocationThreshold = 1024;
}
