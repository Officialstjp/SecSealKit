using System;
using System.Security.Cryptography;

namespace SecSealKit.Crypto.Utilities;
/// <summary>
/// Provides cryptographically secure random number generation using the system's CSPRNG.
/// </summary>
internal static class CryptoRandom
{
    /// <summary>
    /// Generates a cryptographically secure random byte array.
    /// </summary>
    /// <param name="length">The number of random bytes to generate.</param>
    /// <returns>A byte array filled with cryptographically secure random data.</returns>
    /// <exception cref="ArgumentException">Thrown if length is less than 1.</exception>
    /// <remarks>
    /// Uses RNGCryptoServiceProvider for .NET Standard 2.0 compatibility.
    /// </remarks>
    public static byte[] GetBytes(int length)
    {
        if (length < 1)
        {
            throw new ArgumentException("Length must be at least 1 byte.", nameof(length));
        }

        var buffer = new byte[length];

        // (RandomNumberGenerator.Create() returns this implementation)
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(buffer);
        }

        return buffer;
    }

    /// <summary>
    /// Fills an existing buffer with cryptographically secure random bytes.
    /// </summary>
    /// <param name="buffer">The buffer to fill with random data.</param>
    /// <exception cref="ArgumentNullException">Thrown if buffer is null.</exception>
    public static void FillBuffer(byte[] buffer)
    {
        if (buffer == null)
        {
            throw new ArgumentNullException(nameof(buffer));
        }

        if (buffer.Length == 0)
        {
            return; // No-op for empty buffers
        }

        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(buffer);
        }
    }
}
