using System;
using System.Security.Cryptography;
using SecSealKit.Crypto.Utilities;

namespace SecSealKit.Crypto.KeyDerivation
{
    /// <summary>
    /// PBKDF2-HMAC-SHA1 key derivation implementation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Uses PBKDF2 (Password-Based Key Derivation Function 2) with HMAC-SHA1 as the PRF.
    /// While SHA1 is deprecated for digital signatures, it remains acceptable for PBKDF2
    /// as the primary security comes from iteration count, not hash collision resistance.
    /// </para>
    /// <para>
    /// This implementation includes domain separation for SCS1 envelopes by appending
    /// the constant "|scs1|" to the salt, preventing key reuse across different contexts.
    /// </para>
    /// </remarks>
    internal class Pbkdf2HmacSha1 : IKeyDerivation
    {
        private const string DomainSeparator = "|scs1|";
        private const int MinimumIterations = 10000;

        /// <summary>
        /// Derives a cryptographic key from a passphrase using PBKDF2-HMAC-SHA1 with domain separation.
        /// </summary>
        /// <param name="passphrase">The passphrase bytes to derive from.</param>
        /// <param name="salt">The base salt (domain separator will be appended).</param>
        /// <param name="iterations">Number of PBKDF2 iterations (minimum 10,000).</param>
        /// <param name="keyLength">Desired output key length in bytes.</param>
        /// <returns>Derived key bytes.</returns>
        /// <exception cref="ArgumentNullException">If passphrase or salt is null.</exception>
        /// <exception cref="ArgumentException">If iterations or keyLength are invalid.</exception>
        public byte[] DeriveKey(byte[] passphrase, byte[] salt, int iterations, int keyLength)
        {
            if (passphrase == null)
            {
                throw new ArgumentNullException(nameof(passphrase));
            }

            if (salt == null)
            {
                throw new ArgumentNullException(nameof(salt));
            }

            if (iterations < MinimumIterations)
            {
                throw new ArgumentException(
                    $"Iterations must be >= {MinimumIterations} for security.",
                    nameof(iterations));
            }

            if (keyLength < 1)
            {
                throw new ArgumentException(
                    "Key length must be at least 1 byte.",
                    nameof(keyLength));
            }

            // Apply domain separation: salt' = salt || "|scs1|"
            byte[] domainSeparatedSalt = CreateDomainSeparatedSalt(salt);

            try
            {
                // Use Rfc2898DeriveBytes (PBKDF2) with HMAC-SHA1
                using (var pbkdf2 = new Rfc2898DeriveBytes(
                    passphrase,
                    domainSeparatedSalt,
                    iterations))
                {
                    return pbkdf2.GetBytes(keyLength);
                }
            }
            finally
            {
                // Clear the combined salt from memory
                SecureMemory.Clear(domainSeparatedSalt);
            }
        }

        /// <summary>
        /// Creates a domain-separated salt by appending the SCS1 domain tag.
        /// </summary>
        /// <param name="baseSalt">The original salt value.</param>
        /// <returns>A new byte array containing salt || "|scs1|".</returns>
        private byte[] CreateDomainSeparatedSalt(byte[] baseSalt)
        {
            byte[] domainTag = System.Text.Encoding.UTF8.GetBytes(DomainSeparator);
            byte[] combined = new byte[baseSalt.Length + domainTag.Length];

            Buffer.BlockCopy(baseSalt, 0, combined, 0, baseSalt.Length);
            Buffer.BlockCopy(domainTag, 0, combined, baseSalt.Length, domainTag.Length);

            return combined;
        }
    }
}
