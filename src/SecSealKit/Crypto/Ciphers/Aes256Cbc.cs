using System;
using System.Security.Cryptography;

namespace SecSealKit.Crypto.Ciphers;

/// <summary>
/// AES-256-CBC cipher implementation with PKCS7 padding.
/// </summary>
/// <remarks>
/// <para>
/// Uses AES (Advanced Encryption Standard) with:
/// - 256-bit-key size
/// - CBC (Cipher Block Chaining) mode
/// - PKCS7 padding for arbitrary-length messages
/// </para>
/// <para>
/// CBC requires an IV (Initialization Vector) for semantic security.
/// The IV must be random and unique for each encryption.
/// </para>
/// <para>
/// Important: This cipher provides confidentiality only, not authenticity.
/// Always combine with HMAC (encrypt-then-MAC) to prevent tampering.
/// </para>
/// </remarks>
internal class Aes256Cbc : ICipher
{
    private const int KeySize = 256;
    private const int BlockSize = 128;
    private const int KeyBytes = KeySize / 8; // 32 Bytes
    private const int IvBytes = BlockSize / 8; // 16 Bytes

    /// <summary>
    /// Encrypts plaintext using AES-256-CBC with PKCS7 padding.
    /// </summary>
    /// <param name="plaintext">Data to encrypt.</param>
    /// <param name="key">256-bit (32-byte) encryption key.</param>
    /// <param name="iv">128-bit (16-byte) initialization vector.</param>
    /// <returns>Ciphertext bytes.</returns>
    /// <exception cref="ArgumentNullException">If any parameter is null.</exception>
    /// <exception cref="ArgumentException">If key or IV length is invalid.</exception>
    public byte[] Encrypt(byte[] plaintext, byte[] key, byte[] iv)
    {
        ValidateInputs(plaintext, key, iv);

        using (var aes = Aes.Create())
        {
            ConfigureAes(aes, key, iv);

            using (var encryptor = aes.CreateEncryptor())
            {
                return encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
            }
        }
    }

    /// <summary>
    /// Decrypts ciphertext using AES-256-CBC with PKCS7 padding.
    /// </summary>
    /// <param name="ciphertext">Data to decrypt.</param>
    /// <param name="key">256-bit (32-byte) encryption key.</param>
    /// <param name="iv">128-bit (16-byte) initialization vector.</param>
    /// <returns>Plaintext bytes.</returns>
    /// <exception cref="ArgumentNullException">If any parameter is null.</exception>
    /// <exception cref="ArgumentException">If key or IV length is invalid.</exception>
    /// <exception cref="CryptographicException">If decryption fails (wrong key, corrupted data, etc.).</exception>
    public byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] iv)
    {
        ValidateInputs(ciphertext, key, iv);

        using (var aes = Aes.Create())
        {
            ConfigureAes(aes, key, iv);

            using (var decryptor = aes.CreateDecryptor())
            {
                return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
            }
        }
    }

    /// <summary>
    /// Validates that all inputs are non-null and have correct lengths.
    /// </summary>
    private void ValidateInputs(byte[] data, byte[] key, byte[] iv)
    {
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        if (key == null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        if (iv == null)
        {
            throw new ArgumentNullException(nameof(iv));
        }

        if (key.Length != KeyBytes)
        {
            throw new ArgumentException(
                $"Key must be exactly {KeyBytes} bytes (256 bits). Provided: {key.Length} bytes.",
                nameof(key));
        }

        if (iv.Length != IvBytes)
        {
            throw new ArgumentException(
                $"IV must be exactly {IvBytes} bytes (128 bits). Provided: {iv.Length} bytes.",
                nameof(iv));
        }
    }

    /// <summary>
    /// Configures the AES instance with the required parameters.
    /// </summary>
    private void ConfigureAes(Aes aes, byte[] key, byte[] iv)
    {
        aes.KeySize = KeySize;
        aes.BlockSize = BlockSize;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;
        aes.IV = iv;
    }
}
