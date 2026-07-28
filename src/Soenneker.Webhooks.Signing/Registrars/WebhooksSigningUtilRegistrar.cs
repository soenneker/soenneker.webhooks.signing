using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Soenneker.Webhooks.Signing.Abstract;

namespace Soenneker.Webhooks.Signing.Registrars;

/// <summary>
/// A .NET utility for securely signing outgoing webhooks using the Standard Webhooks specification.
/// </summary>
public static class WebhooksSigningUtilRegistrar
{
    /// <summary>
    /// Adds <see cref="IWebhooksSigningUtil"/> as a singleton service. <para/>
    /// </summary>
    public static IServiceCollection AddWebhooksSigningUtilAsSingleton(this IServiceCollection services)
    {
        services.TryAddSingleton<IWebhooksSigningUtil, WebhooksSigningUtil>();

        return services;
    }

    /// <summary>
    /// Adds <see cref="IWebhooksSigningUtil"/> as a scoped service. <para/>
    /// </summary>
    public static IServiceCollection AddWebhooksSigningUtilAsScoped(this IServiceCollection services)
    {
        services.TryAddScoped<IWebhooksSigningUtil, WebhooksSigningUtil>();

        return services;
    }
}
