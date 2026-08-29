using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using Soenneker.Enums.JsonOptions;

namespace Soenneker.Webhooks.Signing.Abstract;

/// <summary>
/// A .NET utility for securely signing outgoing webhooks using the Standard Webhooks specification.
/// </summary>
public interface IWebhooksSigningUtil
{
    /// <summary>
    /// Generates a cryptographically secure Standard Webhooks secret in <c>whsec_&lt;base64&gt;</c> format.
    /// </summary>
    /// <param name="length">The number of random key bytes. The Standard Webhooks specification permits 24 through 64 bytes.</param>
    /// <returns>The text produced by generate Secret.</returns>
    string GenerateSecret(int length = WebhooksSigningConstants.DefaultSecretLength);

    /// <summary>
    /// Determines whether a value is a canonical Standard Webhooks symmetric signing secret.
    /// </summary>
    /// <param name="secret">The value to validate. A valid value uses the <c>whsec_&lt;base64&gt;</c> format and decodes to between 24 and 64 bytes.</param>
    /// <returns>true if a value is a canonical Standard Webhooks symmetric signing secret; otherwise, false.</returns>
    [Pure]
    bool IsValidSecret(string? secret);

    /// <summary>
    /// Creates an HMAC-SHA256 <c>v1</c> signature for a UTF-8 payload.
    /// </summary>
    /// <param name="webhookId">The stable, producer-controlled webhook message identifier.</param>
    /// <param name="timestamp">The delivery-attempt timestamp.</param>
    /// <param name="payload">Payload processed by the operation.</param>
    /// <param name="secret">A base64-encoded secret, optionally prefixed with <c>whsec_</c>.</param>
    /// <returns>The newly created resulting text.</returns>
    [Pure]
    string Sign(string webhookId, DateTimeOffset timestamp, string payload, string secret);

    /// <summary>
    /// Creates an HMAC-SHA256 <c>v1</c> signature for a UTF-8 payload.
    /// </summary>
    /// <param name="webhookId">The stable, producer-controlled webhook message identifier.</param>
    /// <param name="timestamp">The delivery-attempt Unix timestamp, in seconds.</param>
    /// <param name="payload">Payload processed by the operation.</param>
    /// <param name="secret">A base64-encoded secret, optionally prefixed with <c>whsec_</c>.</param>
    /// <returns>The newly created resulting text.</returns>
    [Pure]
    string Sign(string webhookId, long timestamp, string payload, string secret);

    /// <summary>
    /// Creates an HMAC-SHA256 <c>v1</c> signature for an exact binary payload.
    /// </summary>
    /// <param name="webhookId">The stable, producer-controlled webhook message identifier.</param>
    /// <param name="timestamp">The delivery-attempt Unix timestamp, in seconds.</param>
    /// <param name="payload">Payload processed by the operation.</param>
    /// <param name="secret">A base64-encoded secret, optionally prefixed with <c>whsec_</c>.</param>
    /// <returns>The newly created resulting text.</returns>
    [Pure]
    string Sign(string webhookId, long timestamp, ReadOnlyMemory<byte> payload, string secret);

    /// <summary>
    /// Creates an HMAC-SHA256 <c>v1</c> signature for exact binary payload bytes.
    /// </summary>
    /// <param name="webhookId">The stable, producer-controlled webhook message identifier.</param>
    /// <param name="timestamp">The delivery-attempt timestamp.</param>
    /// <param name="payload">Payload processed by the operation.</param>
    /// <param name="secret">A base64-encoded secret, optionally prefixed with <c>whsec_</c>.</param>
    /// <returns>The newly created resulting text.</returns>
    [Pure]
    string Sign(string webhookId, DateTimeOffset timestamp, ReadOnlyMemory<byte> payload, string secret);

    /// <summary>
    /// Creates a space-delimited signature header using each supplied secret, enabling zero-downtime secret rotation.
    /// </summary>
    /// <param name="webhookId">The stable, producer-controlled webhook message identifier.</param>
    /// <param name="timestamp">The delivery-attempt Unix timestamp, in seconds.</param>
    /// <param name="payload">Payload processed by the operation.</param>
    /// <param name="secrets">secrets to process.</param>
    /// <returns>The newly created resulting text.</returns>
    [Pure]
    string Sign(string webhookId, long timestamp, string payload, IEnumerable<string> secrets);

    /// <summary>
    /// Creates a space-delimited signature header for exact binary payload bytes using each supplied secret.
    /// </summary>
    /// <param name="webhookId">The stable, producer-controlled webhook message identifier.</param>
    /// <param name="timestamp">The delivery-attempt Unix timestamp, in seconds.</param>
    /// <param name="payload">Payload processed by the operation.</param>
    /// <param name="secrets">secrets to process.</param>
    /// <returns>The newly created resulting text.</returns>
    [Pure]
    string Sign(string webhookId, long timestamp, ReadOnlyMemory<byte> payload, IEnumerable<string> secrets);

    /// <summary>
    /// Creates the complete set of Standard Webhooks headers for an outgoing UTF-8 payload.
    /// </summary>
    /// <param name="webhookId">The stable, producer-controlled webhook message identifier.</param>
    /// <param name="timestamp">The delivery-attempt timestamp.</param>
    /// <param name="payload">Payload processed by the operation.</param>
    /// <param name="secrets">One or more active signing secrets.</param>
    /// <returns>The newly created webhook Signing Headers.</returns>
    [Pure]
    WebhookSigningHeaders CreateHeaders(string webhookId, DateTimeOffset timestamp, string payload, IEnumerable<string> secrets);

    /// <summary>
    /// Creates the complete set of Standard Webhooks headers for exact binary payload bytes.
    /// </summary>
    /// <param name="webhookId">The stable, producer-controlled webhook message identifier.</param>
    /// <param name="timestamp">The delivery-attempt timestamp.</param>
    /// <param name="payload">Payload processed by the operation.</param>
    /// <param name="secrets">One or more active signing secrets.</param>
    /// <returns>The newly created webhook Signing Headers.</returns>
    [Pure]
    WebhookSigningHeaders CreateHeaders(string webhookId, DateTimeOffset timestamp, ReadOnlyMemory<byte> payload, IEnumerable<string> secrets);

    /// <summary>
    /// Serializes an object once and returns both the exact JSON payload and its Standard Webhooks headers.
    /// </summary>
    /// <param name="webhookId">The stable, producer-controlled webhook message identifier.</param>
    /// <param name="timestamp">The delivery-attempt timestamp.</param>
    /// <param name="payload">Payload processed by the operation.</param>
    /// <param name="secret">A base64-encoded secret, optionally prefixed with <c>whsec_</c>.</param>
    /// <param name="optionType">The optional <see cref="JsonOptionType"/> used by JsonUtil. Web options are used by default.</param>
    /// <returns>The resulting signed Webhook.</returns>
    [Pure]
    SignedWebhook Create(string webhookId, DateTimeOffset timestamp, object payload, string secret, JsonOptionType? optionType = null);

    /// <summary>
    /// Serializes an object once and returns both the exact JSON payload and its Standard Webhooks headers,
    /// using every supplied secret for zero-downtime rotation.
    /// </summary>
    /// <param name="webhookId">The stable, producer-controlled webhook message identifier.</param>
    /// <param name="timestamp">The delivery-attempt timestamp.</param>
    /// <param name="payload">Payload processed by the operation.</param>
    /// <param name="secrets">One or more active signing secrets.</param>
    /// <param name="optionType">The optional <see cref="JsonOptionType"/> used by JsonUtil. Web options are used by default.</param>
    /// <returns>The resulting signed Webhook.</returns>
    [Pure]
    SignedWebhook Create(string webhookId, DateTimeOffset timestamp, object payload, IEnumerable<string> secrets,
        JsonOptionType? optionType = null);
}
