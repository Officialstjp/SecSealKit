using System;
using System.Linq;
using SecSealKit.Crypto.Authentication;
using SecSealKit.Crypto.Formats;
using SecSealKit.Crypto.KeyDerivation;
using SecSealKit.Crypto.Utilities;

namespace SecSealKit.Crypto.Engines;

/// <summary>
/// SCSIG1 (Sealed Cryptographic Signature v1) signature engine.
/// </summary>
/// <remarks>
/// <para>
/// Implements integrity-only signatures using HMAC-SHA256:
/// 1. Derive signing key: PBKDF2-HMAC-SHA1 -> 32 Bytes
/// 2. Sign: HMAC-SHA256(data) with domain separation
/// 3. Package: SCSIG1 signature format
/// </para>
/// </remarks>
internal class Scsig1Engine : ISignatureEngine
{
    private readonly IKeyDerivation _kdf;
    private readonly IMac _mac;
    private readonly Scsig1Format _format;

    private const int DerivedKeyLength = 32;
    private const int SaltLength = 16;

    /// <summary>
    /// Creates a new SCSIG1 signature engine with the specified crypto primitives
    /// </summary>
    public Scsig1Engine(IKeyDerivation kdf,IMac mac, Scsig1Format format)
    {
        _kdf = kdf ?? throw new ArgumentNullException(nameof(kdf));
        _mac = mac ?? throw new ArgumentNullException(nameof(kdf));
        _format = format ?? throw new ArgumentNullException(nameof(format));
    }

    /// <summary>
    /// Signs data and produces a SCSIG1 signature string.
    /// </summary>
    public string Sign(byte[] data, byte[] passphrase, int iterations)
    {
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        if (passphrase == null)
        {
            throw new ArgumentNullException(nameof(passphrase));
        }

        // Generate random salt
        byte[] salt = CryptoRandom.GetBytes(SaltLength);

        byte[]? derivedKey = null;
        byte[]? signature = null;

        try
        {
            // Derive signing key using domain-separated salt
            derivedKey = _kdf.DeriveKey(passphrase, salt, iterations, DerivedKeyLength);

            // Sign the data
            signature = _mac.Compute(data, derivedKey);

            // Build signature string
            return _format.Build(iterations, salt, signature);
        }
        finally
        {
            if (derivedKey != null)
                SecureMemory.ClearPinned(derivedKey);
        }
    }

    /// <summary>
    /// Verifies a SCSIG1 signature against data.
    /// </summary>
    /// <returns>True if signature is valid; false otherwise.</returns>
    public bool Verify(byte[] data, string signatureString, byte[] passphrase)
    {
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        if (string.IsNullOrWhiteSpace(signatureString))
        {
            throw new ArgumentException("Signature string cannot be null or empty.", nameof(signatureString));
        }

        if (passphrase == null)
        {
            throw new ArgumentNullException(nameof(passphrase));
        }

        byte[]? derivedKey = null;

        try
        {
            // Parse the signature
            var parsed = _format.Parse(signatureString);

            // Derive the same signing key
            derivedKey = _kdf.DeriveKey(passphrase, parsed.Salt, parsed.Iterations, DerivedKeyLength);

            // Verify signature using constant-time comparison
            return _mac.Verify(data, derivedKey, parsed.Signature);
        }
        catch (FormatException)
        {
            // Invalid signature format = verification failed
            return false;
        }
        finally
        {
            if (derivedKey != null)
                SecureMemory.ClearPinned(derivedKey);
        }
    }
}
