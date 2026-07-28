using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Soenneker.Enums.JsonOptions;
using Soenneker.Extensions.Arrays.Bytes;
using Soenneker.Extensions.String;
using Soenneker.Utils.Json;
using Soenneker.Webhooks.Signing.Abstract;

namespace Soenneker.Webhooks.Signing;

/// <inheritdoc cref="IWebhooksSigningUtil"/>
public sealed class WebhooksSigningUtil : IWebhooksSigningUtil
{
    public string GenerateSecret(int length = WebhooksSigningConstants.DefaultSecretLength)
    {
        if (length is < WebhooksSigningConstants.MinimumSecretLength or > WebhooksSigningConstants.MaximumSecretLength)
            throw new ArgumentOutOfRangeException(nameof(length), length,
                $"Secret length must be between {WebhooksSigningConstants.MinimumSecretLength} and {WebhooksSigningConstants.MaximumSecretLength} bytes.");

        byte[] secret = RandomNumberGenerator.GetBytes(length);

        try
        {
            return WebhooksSigningConstants.SecretPrefix + secret.ToBase64String();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    public string Sign(string webhookId, DateTimeOffset timestamp, string payload, string secret)
    {
        return Sign(webhookId, timestamp.ToUnixTimeSeconds(), payload, secret);
    }

    public string Sign(string webhookId, long timestamp, string payload, string secret)
    {
        ArgumentNullException.ThrowIfNull(payload);
        byte[] payloadBytes = payload.ToBytes();

        try
        {
            return SignCore(webhookId, timestamp, payloadBytes, secret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payloadBytes);
        }
    }

    public string Sign(string webhookId, long timestamp, ReadOnlyMemory<byte> payload, string secret)
    {
        return SignCore(webhookId, timestamp, payload.Span, secret);
    }

    public string Sign(string webhookId, DateTimeOffset timestamp, ReadOnlyMemory<byte> payload, string secret)
    {
        return SignCore(webhookId, timestamp.ToUnixTimeSeconds(), payload.Span, secret);
    }

    public string Sign(string webhookId, long timestamp, string payload, IEnumerable<string> secrets)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(secrets);
        byte[] payloadBytes = payload.ToBytes();

        try
        {
            return Sign(webhookId, timestamp, payloadBytes, secrets);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payloadBytes);
        }
    }

    public string Sign(string webhookId, long timestamp, ReadOnlyMemory<byte> payload, IEnumerable<string> secrets)
    {
        ArgumentNullException.ThrowIfNull(secrets);

        var signatures = new List<string>(2);

        foreach (string secret in secrets)
            signatures.Add(SignCore(webhookId, timestamp, payload.Span, secret));

        if (signatures.Count == 0)
            throw new ArgumentException("At least one signing secret is required.", nameof(secrets));

        return string.Join(' ', signatures);
    }

    public WebhookSigningHeaders CreateHeaders(string webhookId, DateTimeOffset timestamp, string payload, IEnumerable<string> secrets)
    {
        long unixTimestamp = timestamp.ToUnixTimeSeconds();
        string signature = Sign(webhookId, unixTimestamp, payload, secrets);

        return new WebhookSigningHeaders(webhookId, unixTimestamp, signature);
    }

    public WebhookSigningHeaders CreateHeaders(string webhookId, DateTimeOffset timestamp, ReadOnlyMemory<byte> payload, IEnumerable<string> secrets)
    {
        long unixTimestamp = timestamp.ToUnixTimeSeconds();
        string signature = Sign(webhookId, unixTimestamp, payload, secrets);

        return new WebhookSigningHeaders(webhookId, unixTimestamp, signature);
    }

    public SignedWebhook Create(string webhookId, DateTimeOffset timestamp, object payload, string secret, JsonOptionType? optionType = null)
    {
        ArgumentNullException.ThrowIfNull(payload);

        byte[] serializedPayload = JsonUtil.SerializeToUtf8Bytes(payload, optionType);
        long unixTimestamp = timestamp.ToUnixTimeSeconds();
        string signature = SignCore(webhookId, unixTimestamp, serializedPayload, secret);
        var headers = new WebhookSigningHeaders(webhookId, unixTimestamp, signature);

        return new SignedWebhook(serializedPayload, headers);
    }

    public SignedWebhook Create(string webhookId, DateTimeOffset timestamp, object payload, IEnumerable<string> secrets,
        JsonOptionType? optionType = null)
    {
        ArgumentNullException.ThrowIfNull(payload);

        byte[] serializedPayload = JsonUtil.SerializeToUtf8Bytes(payload, optionType);
        WebhookSigningHeaders headers = CreateHeaders(webhookId, timestamp, serializedPayload, secrets);

        return new SignedWebhook(serializedPayload, headers);
    }

    private static string SignCore(string webhookId, long timestamp, ReadOnlySpan<byte> payload, string secret)
    {
        ValidateWebhookId(webhookId);
        byte[] key = DecodeSecret(secret);

        Span<byte> timestampBytes = stackalloc byte[20];

        if (!Utf8Formatter.TryFormat(timestamp, timestampBytes, out int timestampLength))
            throw new InvalidOperationException("The webhook timestamp could not be formatted.");

        int prefixLength = Encoding.UTF8.GetByteCount(webhookId) + 1 + timestampLength + 1;
        byte[]? rented = null;
        Span<byte> signedContent = prefixLength + payload.Length <= WebhooksSigningConstants.StackAllocationThreshold
            ? stackalloc byte[prefixLength + payload.Length]
            : (rented = ArrayPool<byte>.Shared.Rent(prefixLength + payload.Length)).AsSpan(0, prefixLength + payload.Length);

        try
        {
            int written = Encoding.UTF8.GetBytes(webhookId, signedContent);
            signedContent[written++] = (byte) '.';
            timestampBytes[..timestampLength].CopyTo(signedContent[written..]);
            written += timestampLength;
            signedContent[written++] = (byte) '.';
            payload.CopyTo(signedContent[written..]);

            Span<byte> hash = stackalloc byte[WebhooksSigningConstants.SignatureLength];
            HMACSHA256.HashData(key, signedContent, hash);

            return WebhooksSigningConstants.SignaturePrefix + hash.ToBase64String();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(signedContent);

            if (rented is not null)
                ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static byte[] DecodeSecret(string secret)
    {
        if (secret.IsNullOrWhiteSpace())
            throw new ArgumentException("A signing secret is required.", nameof(secret));

        ReadOnlySpan<char> encoded = secret.AsSpan();

        if (encoded.StartsWith(WebhooksSigningConstants.SecretPrefix, StringComparison.Ordinal))
            encoded = encoded[WebhooksSigningConstants.SecretPrefix.Length..];

        if (encoded.IsEmpty)
            throw new ArgumentException("A signing secret is required.", nameof(secret));

        int paddingLength = (4 - encoded.Length % 4) % 4;
        string padded = paddingLength == 0 ? encoded.ToString() : string.Concat(encoded, new string('=', paddingLength));

        try
        {
            byte[] decoded = padded.ToBytesFromBase64();

            if (decoded.IsEmpty())
                throw new ArgumentException("A signing secret is required.", nameof(secret));

            return decoded;
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("The signing secret must be base64 encoded, optionally prefixed with 'whsec_'.", nameof(secret), exception);
        }
    }

    private static void ValidateWebhookId(string webhookId)
    {
        if (webhookId.IsNullOrWhiteSpace())
            throw new ArgumentException("A webhook ID is required.", nameof(webhookId));

        if (webhookId.ContainsAny('.'))
            throw new ArgumentException("The webhook ID cannot contain '.'.", nameof(webhookId));
    }
}
