namespace SecSealKit.Crypto.Ciphers;

/// <summary>
/// Cipher interface for encryption and decryption operations.
/// </summary>
public interface ICipher
{
    /// <summary>
    /// Encrypts a plaintext.
    /// </summary>
    /// <param name="plaintext">Data to encrypt.</param>
    /// <param name="key">256-bit (32-byte) encryption key.</param>
    /// <param name="iv">128-bit (16-byte) initialization vector.</param>
    /// <returns>Ciphertext bytes.</returns>
    /// <exception cref="ArgumentNullException">If any parameter is null.</exception>
    /// <exception cref="ArgumentException">If key or IV length is invalid.</exception>
    byte[] Encrypt(byte[] plaintext, byte[] key, byte[] iv);

    /// <summary>
    /// Decrypts a ciphertext.
    /// </summary>
    /// <param name="ciphertext">Data to decrypt.</param>
    /// <param name="key">256-bit (32-byte) encryption key.</param>
    /// <param name="iv">128-bit (16-byte) initialization vector.</param>
    /// <returns>Plaintext bytes.</returns>
    /// <exception cref="ArgumentNullException">If any parameter is null.</exception>
    /// <exception cref="ArgumentException">If key or IV length is invalid.</exception>
    /// <exception cref="CryptographicException">If decryption fails (wrong key, corrupted data, etc.).</exception>
    byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] iv);
}
