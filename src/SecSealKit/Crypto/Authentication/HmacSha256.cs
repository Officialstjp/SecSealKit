/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Stefan Ploch */

using System;
using System.Security.Cryptography;
using SecSealKit.Crypto.Utilities;

namespace SecSealKit.Crypto.Authentication;
/// <summary>
/// HMAC-SHA256 message authentication code implementation.
/// </summary>
/// <remarks>
/// <para>
/// HMAC (Hash-based Message Authentication Code) provides data integrity and authenticity
/// using a secret key. HMAC-SHA256 produces a 32-byte (256-bit) authentication tag.
/// </para>
/// <para>
/// This implementation uses constant-time comparison for tag verification to prevent
/// timing attacks that could leak information about the expected MAC value.
/// </para>
/// <para>
/// In the SCS1 envelope format, HMAC is computed over (IV || Ciphertext) in an
/// encrypt-then-MAC construction, which is the recommended approach for authenticated encryption.
/// </para>
/// </remarks>
internal class HmacSha256Mac : IMac
{
    private const int MacLength = 32; // HMAC-SHA256 produces 32 bytes

    /// <summary>
    /// Computes HMAC-SHA256 over input data.
    /// </summary>
    /// <param name="data">Data to authenticate.</param>
    /// <param name="key">HMAC key (recommended 32+ bytes for full strength).</param>
    /// <returns>32-byte HMAC-SHA256 tag.</returns>
    /// <exception cref="ArgumentNullException">If data or key is null.</exception>
    public byte[] Compute(byte[] data, byte[] key)
    {
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        if (key == null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        using (var hmac = new HMACSHA256(key))
        {
            return hmac.ComputeHash(data);
        }
    }

    /// <summary>
    /// Verifies an HMAC-SHA256 tag against data using constant-time comparison.
    /// </summary>
    /// <param name="data">Data to verify.</param>
    /// <param name="key">HMAC key.</param>
    /// <param name="expectedMac">Expected MAC tag to compare against.</param>
    /// <returns>True if MAC is valid; false otherwise.</returns>
    /// <exception cref="ArgumentNullException">If data or key is null.</exception>
    /// <remarks>
    /// This method uses <see cref="ConstantTime.Equals"/> to prevent timing attacks.
    /// Invalid MAC lengths are rejected without computation to save resources.
    /// </remarks>
    public bool Verify(byte[] data, byte[] key, byte[] expectedMac)
    {
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        if (key == null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        // Reject invalid MAC lengths early (not timing-sensitive)
        if (expectedMac == null || expectedMac.Length != MacLength)
        {
            return false;
        }

        // Compute the actual MAC
        byte[] actualMac = Compute(data, key);

        try
        {
            // Constant-time comparison prevents timing attacks
            return ConstantTime.Equals(actualMac, expectedMac, MacLength);
        }
        finally
        {
            // Clear the computed MAC from memory
            SecureMemory.Clear(actualMac);
        }
    }
}
