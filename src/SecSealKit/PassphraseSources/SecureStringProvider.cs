/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Stefan Ploch */

using System;
using System.Security;
using SecSealKit.Crypto.Utilities;

namespace SecSealKit.PassphraseSources
{
    /// <summary>
    /// Provides passphrase bytes from a PowerShell SecureString.
    /// </summary>
    internal class SecureStringProvider : IPassphraseProvider
    {
        private readonly SecureString _secureString;

        /// <summary>
        /// Creates a new provider for a SecureString passphrase.
        /// </summary>
        /// <param name="secureString">The SecureString containing the passphrase.</param>
        /// <exception cref="ArgumentNullException">If secureString is null.</exception>
        public SecureStringProvider(SecureString secureString)
        {
            _secureString = secureString ?? throw new ArgumentNullException(nameof(secureString));
        }

        /// <summary>
        /// Gets the passphrase as UTF-8 encoded bytes.
        /// </summary>
        /// <returns>Passphrase bytes. The caller MUST clear this array after use.</returns>
        /// <remarks>
        /// The returned byte array contains sensitive data and should be cleared
        /// with <see cref="SecureMemory.ClearPinned"/> as soon as possible.
        /// </remarks>
        public byte[] GetPassphrase()
        {
            return SecureMemory.SecureStringToBytes(_secureString);
        }
    }
}
