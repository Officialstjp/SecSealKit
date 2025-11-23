using System;
using System.IO;
using System.Security.Cryptography;

namespace SecSealKit.PassphraseSources;

internal class DpapiKeyfileProvider : IPassphraseProvider
{
    // <summary>
    /// Provides passphrase bytes from a DPAPI-protected keyfile.
    /// </summary>
    /// <remarks>
    /// DPAPI (Data Protection API) keyfiles are encrypted using Windows DPAPI with
    /// CurrentUser scope, meaning only the user who created the file can decrypt it.
    /// The keyfile itself is just a binary blob that DPAPI can decrypt.
    /// Security considerations:
    /// - DPAPI keys are tied to the user's Windows login credentials
    /// - If the user's password changes, DPAPI can still decrypt (it's profile-based)
    /// - If the user profile is deleted/corrupted, keyfiles become unreadable
    /// - Administrator accounts can potentially access other users' DPAPI keys
    /// </remarks>
    private readonly string _keyfilePath;

    public DpapiKeyfileProvider(string keyfilePath)
    {
        _keyfilePath = keyfilePath ?? throw new ArgumentNullException(nameof(keyfilePath));
    }

    /// <summary>
    /// Reads and decrypts the keyfile using DPAPI.
    /// </summary>
    /// <returns>Passphrase bytes from the keyfile.</returns>
    /// <exception cref="FileNotFoundException">If the keyfile doesn't exist.</exception>
    /// <exception cref="CryptographicException">If DPAPI decryption fails (wrong user, corrupted file).</exception>
    public byte[] GetPassphrase()
    {
        if (!File.Exists(_keyfilePath))
        {
            throw new FileNotFoundException(
                $"DPAPI keyfile not found: {_keyfilePath}",
                _keyfilePath);
        }

        byte[] encryptedData;
        try
        {
            encryptedData = File.ReadAllBytes(_keyfilePath);
        }
        catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
        {
            throw new InvalidOperationException(
                $"Failed to read keyfile '{_keyfilePath}': {ex.Message}",
                ex);
        }

        try
        {
            // Decrypt using DPAPI with CurrentUser scope
            // This only works if the current user created the file
            byte[] decryptedData = ProtectedData.Unprotect(
                encryptedData,
                optionalEntropy: null,
                scope: DataProtectionScope.CurrentUser);

            return decryptedData;
        }
        catch (CryptographicException ex)
        {
            throw new CryptographicException(
                $"Failed to decrypt DPAPI keyfile '{_keyfilePath}'. " +
                "The file may have been created by a different user or is corrupted.",
                ex);
        }
    }
}
