/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Stefan Ploch */

using System;
using System.Linq;
using SecSealKit.Crypto.Authentication;
using SecSealKit.Crypto.Ciphers;
using SecSealKit.Crypto.Formats;
using SecSealKit.Crypto.KeyDerivation;
using SecSealKit.Crypto.Utilities;

namespace SecSealKit.Crypto.Engines;

/// <summary>
/// SCS1 (Sealed Cryptographic Secret v1) encryption/decryption engine.
/// </summary>
/// <remarks>
/// Implements authenticated encryption using the encrypt-then-MAC construction:
/// 1. Derive keys: PBKDF2-HMAC-SHA1 -> 64 bytes (32 enc + 32 mac)
/// 2. Encrypt: AES-256-CBC with random IV
/// 3. Authenticate: HMAC-SHA256 over (IV || Ciphertext)
/// 4. Package: SCS1 envelope format
internal class Scs1Engine : ISealEngine
{
    private readonly IKeyDerivation _kdf;
    private readonly ICipher _cipher;
    private readonly IMac _mac;
    private readonly Scs1Format _format;

    // Key derivation produces 64 Bytes: 32 for encryption, 32 for MAC
    private const int DerivedKeyLength = 64;
    private const int EncryptionKeyLength = 32;
    private const int MacKeyLength = 32;

    // Random data lengths
    private const int SaltLength = 16; // 16+ bytes recommended
    private const int IvLength = 16;   // AES block size for IV

    /// <summary>
    /// Creates a new SCS1 engine with the specified crypto primitives.
    /// </summary>
    /// <param name="kdf">Key derivation function (PBKDF2-HMAC-SHA1).</param>
    /// <param name="cipher">Symmetric cipher (AES-256-CBC).</param
    /// <param name="mac">Message authentication code (HMAC-SHA256).</param>
    /// <param name="format">Envelope format (SCS1).</param>
    public Scs1Engine(IKeyDerivation kdf, ICipher cipher, IMac mac, Scs1Format format)
    {
        _kdf = kdf ?? throw new ArgumentNullException(nameof(kdf));
        _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
        _mac = mac ?? throw new ArgumentNullException(nameof(mac));
        _format = format ?? throw new ArgumentNullException(nameof(format));
    }

    /// <summary>
    /// Encrypts plaintext into an SCS1 envelope.
    /// </summary>
    /// <param name="plaintext">Data to encrypt.</param>
    /// <param name="passphrase">Passphrase bytes for key derivation.</param>
    /// <param name="iterations">PBKDF2 iteration count (default: 200000).</param>
    /// <returns>SCS1 envelope string.</returns>
    /// <exception cref="ArgumentNullException">If plaintext or passphrase is null.</exception>
    /// <exception cref="ArgumentException">If iterations is too low.</exception>
    public string Seal(byte[] plaintext, byte[] passphrase, int iterations)
    {
        if (plaintext == null)
        {
            throw new ArgumentNullException(nameof(plaintext));
        }

        if (passphrase == null)
        {
            throw new ArgumentNullException(nameof(passphrase));
        }

        // Generate random salt and IV
        byte[] salt = CryptoRandom.GetBytes(SaltLength);
        byte[] iv = CryptoRandom.GetBytes(IvLength);

        byte[]? derivedKey = null;
        byte[]? encryptionKey = null;
        byte[]? macKey = null;
        byte[]? cipherText = null;
        byte[]? macInput = null;
        byte[]? macTag = null;

        try
        {
            // Derive keys
            derivedKey = _kdf.DeriveKey(passphrase, salt, iterations, DerivedKeyLength);

            // Split derived key: first 32 bytes for encryption, last 32 for MAC
            encryptionKey = derivedKey.Take(EncryptionKeyLength).ToArray();
            macKey = derivedKey.Skip(EncryptionKeyLength).Take(MacKeyLength).ToArray();

            cipherText = _cipher.Encrypt(plaintext, encryptionKey, iv);

            // Compute MAC over (IV || CipherTExt) for encrypt-then-mac
            macInput = new byte[iv.Length + cipherText.Length];
            Buffer.BlockCopy(iv, 0, macInput, 0, iv.Length);
            Buffer.BlockCopy(cipherText, 0, macInput, iv.Length, cipherText.Length);
            macTag = _mac.Compute(macInput, macKey);

            return _format.Build(iterations, salt, iv, cipherText, macTag);
        }
        finally
        {
            // Clear all sensitive data from memory
            if (derivedKey != null) SecureMemory.ClearPinned(derivedKey);
            if (encryptionKey != null) SecureMemory.ClearPinned(encryptionKey);
            if (macKey != null) SecureMemory.ClearPinned(macKey);
            if (macInput != null) SecureMemory.Clear(macInput);
            // ciphertext and macTag are not sensitive (output)
        }
    }

    /// <summary>
    /// Decrypts an SCS1 envelope and verifies authenticity.
    /// </summary>
    /// <param name="envelope">SCS1 envelope string.</param>
    /// <param name="passphrase">Passphrase bytes for key derivation.</param>
    /// <returns>Decrypted plaintext bytes.</returns>
    /// <exception cref="ArgumentException">If envelope is invalid.</exception>
    /// <exception cref="FormatException">If envelope format is corrupted.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// If MAC verification fails (wrong passphrase or tampered data).
    /// </exception>
    public byte[] Unseal(string envelope, byte[] passphrase)
    {
        if (string.IsNullOrWhiteSpace(envelope))
        {
            throw new ArgumentException("Envelope cannot be null or empty.", nameof(envelope));
        }

        if (passphrase == null)
        {
            throw new ArgumentNullException(nameof(passphrase));
        }

        // Parse envelope
        var parsed = _format.Parse(envelope);

        byte[]? derivedKey = null;
        byte[]? encryptionKey = null;
        byte[]? macKey = null;
        byte[]? macInput = null;
        byte[]? plaintext = null;

        try
        {
            // Derive keys (same process as Seal)
            derivedKey = _kdf.DeriveKey(passphrase, parsed.Salt, parsed.Iterations, DerivedKeyLength);

            encryptionKey = derivedKey.Take(EncryptionKeyLength).ToArray();
            macKey = derivedKey.Skip(EncryptionKeyLength).Take(MacKeyLength).ToArray();

            // Verify MAC (MUST happen before decryption)
            macInput = new byte[parsed.IV.Length + parsed.CipherText.Length];
            Buffer.BlockCopy(parsed.IV, 0, macInput, 0, parsed.IV.Length);
            Buffer.BlockCopy(parsed.CipherText, 0, macInput, parsed.IV.Length, parsed.CipherText.Length);

            bool macValid = _mac.Verify(macInput, macKey, parsed.MAC);

            if (!macValid)
            {
                throw new System.Security.Cryptography.CryptographicException(
                    "MAC verification failed. The envelope has been tampered with or the passphrase is incorrect.");
            }

            // Decrypt (only after MAC verification succeeds)
            plaintext = _cipher.Decrypt(parsed.CipherText, encryptionKey, parsed.IV);

            return plaintext;
        }
        finally
        {
            // Clear all sensitive data from memory
            if (derivedKey != null) SecureMemory.ClearPinned(derivedKey);
            if (encryptionKey != null) SecureMemory.ClearPinned(encryptionKey);
            if (macKey != null) SecureMemory.ClearPinned(macKey);
            if (macInput != null) SecureMemory.Clear(macInput);

            // Clear plaintext if an exception occurred
            if (plaintext != null && plaintext.Length > 0)
            {
                // Only clear if we're throwing an exception (caller owns the data on success)
                // This is handled by the caller's finally block
            }
        }
    }
}
