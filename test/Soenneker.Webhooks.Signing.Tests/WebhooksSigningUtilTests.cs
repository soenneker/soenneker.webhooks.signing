using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Soenneker.Extensions.Arrays.Bytes;
using Soenneker.Extensions.String;
using Soenneker.Tests.HostedUnit;
using Soenneker.Webhooks.Signing.Abstract;

namespace Soenneker.Webhooks.Signing.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public sealed class WebhooksSigningUtilTests : HostedUnitTest
{
    private readonly IWebhooksSigningUtil _util;

    public WebhooksSigningUtilTests(Host host) : base(host)
    {
        _util = Resolve<IWebhooksSigningUtil>(true);
    }

    [Test]
    public async Task Default()
    {
        await Assert.That(_util).IsNotNull();
    }

    [Test]
    public async Task Sign_should_match_cross_platform_hmac_vector()
    {
        const string id = "msg_2KWPBgLlAfxdpx2AI54pPJ85f4W";
        const long timestamp = 1674087231;
        const string payload = "{\"type\":\"contact.created\",\"data\":{\"id\":\"abc\"}}";
        const string secret = "whsec_MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

        string signature = _util.Sign(id, timestamp, payload, secret);

        await Assert.That(signature).IsEqualTo("v1,l1ytmx7htbiP0EZxAAsV+JGKDDnInwvjMdEwx95QIsA=");
    }

    [Test]
    public async Task Sign_should_treat_string_as_exact_utf8_bytes()
    {
        const string id = "msg_unicode";
        const long timestamp = 1720000000;
        const string secret = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";
        string payload = "{\"message\":\"Hello, 世界 👋\",\"padding\":\"" + new string('x', 2048) + "\"}";

        string stringSignature = _util.Sign(id, timestamp, payload, secret);
        string byteSignature = _util.Sign(id, timestamp, payload.ToBytes(), secret);

        await Assert.That(stringSignature).IsEqualTo(byteSignature);
    }

    [Test]
    public async Task Sign_should_support_rotation_and_create_complete_headers()
    {
        const string id = "msg_rotation";
        var timestamp = DateTimeOffset.FromUnixTimeSeconds(1730000000);
        string[] secrets =
        [
            "whsec_MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
            "whsec_YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODg="
        ];

        WebhookSigningHeaders headers = _util.CreateHeaders(id, timestamp, "{}", secrets);
        IReadOnlyDictionary<string, string> values = headers.ToDictionary();
        string[] signatures = headers.Signature.Split(' ');

        await Assert.That(signatures.Length).IsEqualTo(2);
        await Assert.That(values[WebhooksSigningConstants.WebhookIdHeader]).IsEqualTo(id);
        await Assert.That(values[WebhooksSigningConstants.WebhookTimestampHeader]).IsEqualTo("1730000000");
        await Assert.That(values[WebhooksSigningConstants.WebhookSignatureHeader]).IsEqualTo(headers.Signature);
    }

    [Test]
    public async Task GenerateSecret_should_return_a_32_byte_standard_secret()
    {
        string secret = _util.GenerateSecret();
        byte[] bytes = secret[WebhooksSigningConstants.SecretPrefix.Length..].ToBytesFromBase64();

        await Assert.That(secret.StartsWith(WebhooksSigningConstants.SecretPrefix, StringComparison.Ordinal)).IsTrue();
        await Assert.That(bytes.Length).IsEqualTo(WebhooksSigningConstants.DefaultSecretLength);
    }

    [Test]
    public async Task Create_should_serialize_once_and_sign_the_returned_payload()
    {
        const string id = "msg_object";
        const string secret = "whsec_MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
        var timestamp = DateTimeOffset.FromUnixTimeSeconds(1740000000);
        var payload = new
        {
            EventType = "contact.created",
            Data = new
            {
                Id = 42,
                DisplayName = "Jane Doe"
            }
        };

        SignedWebhook signedWebhook = _util.Create(id, timestamp, payload, secret);
        string expectedSignature = _util.Sign(id, timestamp, signedWebhook.Payload, secret);

        await Assert.That(signedWebhook.Payload.ToStr()).IsEqualTo(
            "{\"eventType\":\"contact.created\",\"data\":{\"id\":42,\"displayName\":\"Jane Doe\"}}");
        await Assert.That(signedWebhook.Headers.Signature).IsEqualTo(expectedSignature);
    }
}
