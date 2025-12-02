using System;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Provides helper methods for searching and retrieving certificates from the Windows certificate store.
/// </summary>
/// <remarks>
/// This static class simplifies certificate lookup operations by searching across multiple store locations
/// (LocalMachine and CurrentUser) to accommodate both server/agent and developer contexts.
/// </remarks>
namespace SecSealKit.Crypto.Utilities;
public static class CertificateStoreHelper
{
    /// <summary>
    /// Searches for a certificate by thumbprint in the Windows certificate store.
    /// </summary>
    /// <param name="thumbprint">The thumbprint (SHA-1 hash) of the certificate to find. Spaces are automatically removed.</param>
    /// <returns>
    /// An <see cref="X509Certificate2"/> object if a matching certificate is found; otherwise, <c>null</c>.
    /// The search prioritizes LocalMachine\My store first, then falls back to CurrentUser\My store.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="thumbprint"/> is null, empty, or contains only whitespace.</exception>
    public static X509Certificate2 FindCertificate(string thumbprint)
    {
#pragma warning disable CS8603 // we return null on purpose
        if (string.IsNullOrWhiteSpace(thumbprint))
            throw new ArgumentNullException(nameof(thumbprint));

        // Clean thumbprint
        thumbprint = thumbprint.Replace(" ", "").ToUpperInvariant();

        // 1. Try LocalMachine (Server/Agent context)
        var cert = FindInStore(StoreName.My, StoreLocation.LocalMachine, thumbprint);
        if (cert != null) return cert;

        // 2. Try CurrentUser (Developer context)
        cert = FindInStore(StoreName.My, StoreLocation.CurrentUser, thumbprint);
        if (cert != null) return cert;

        return null;
    }

    private static X509Certificate2 FindInStore(StoreName storeName, StoreLocation location, string thumbprint)
    {
        using (var store = new X509Store(storeName, location))
        {
            store.Open(OpenFlags.ReadOnly);
            var certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
            return certs.Count > 0 ? certs[0] : null;
        }
    }
}

#pragma warning restore CS8603
