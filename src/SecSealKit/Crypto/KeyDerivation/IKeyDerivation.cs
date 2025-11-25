/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Stefan Ploch */

namespace SecSealKit.Crypto.KeyDerivation;

public interface IKeyDerivation
{
    /// <summary>
    /// Derives a key from the given password, salt, and iteration count.
    /// </summary>
    /// <param name="password">The input password.</param>
    /// <param name="salt">The salt value.</param>
    /// <param name="iterations">The number of iterations.</param>
    /// <param name="keyLength">The desired length of the derived key in bytes.</param>
    /// <returns>The derived key as a byte array.</returns>
    byte[] DeriveKey(byte[] password, byte[] salt, int iterations, int keyLength);
}
