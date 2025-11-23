using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecSealKit.Crypto.Formats;

/// <summary>
/// SCS1 (Sealed Cryptographic Secret) envelope format parser and builder.
/// </summary>
/// <remarks>
/// The SCS1 format is a dollar-delimited string containing all parameters needed for authenticated decryption.
/// Format specifications:
/// """
/// SCS1$kdf=PBKDF2-SHA1$iter=N$salt=B64$IV=B64$ct=B64$mac=B64
/// """
/// Where:
/// - kdf: Key derivation function (always "PBKDF2-SHA1" for SCS1)
/// - iter: PBKDF2 iteration count (integer >= 10000)
/// - salt: Base64-encoded salt for KDF (16+ bytes recommended)
/// - IV: Base64-encoded AES initialization vector (exactly 16 bytes)
/// - ct: Base64-encoded ciphertext (variable length)
/// - mac: Base64-encoded HMAC-SHA256 tag (exactly 32 bytes)
/// </remarks>
internal class Scs1Format : IEnvelopeFormat
{
    private const string FormatVersion = "Scs1";
    private const string KdfIdentifier = "PBKDF2-SHA1";
    private const int MinIterations = 10000;
    private const int MinSaltLength = 16;
    private const int IvLength = 16;
    private const int MacLength = 32;

    /// <summary>
    /// Parses an SCS1 envelope string into structured components.
    /// </summary>
    /// <param name="envelopeString">The SCS1 envelope string to parse.</param>
    /// <returns>An EnvelopeData object containing all parsed fields.</returns>
    /// <exception cref="ArgumentException">If the envelope string is null or empty.</exception>
    /// <exception cref="FormatException">If the envelope format is invalid or corrupted.</exception>
    public EnvelopeData Parse(string envelopeString)
    {
        if (string.IsNullOrWhiteSpace(envelopeString))
        {
            throw new ArgumentException("Envelope string cannot be null or empty.", nameof(envelopeString));
        }

        // Split on dollar signs
        string[] parts = envelopeString.Split('$');

        // Validate format identifier
        if (parts.Length < 2 || parts[0] != FormatVersion)
        {
            throw new FormatException($"Invalid envelope format. Expected '{FormatVersion}$...' but got '{parts[0]}$...'");
        }

        // Parse key-value pairs
        var fields = ParseFields(parts.Skip(1));

        // Validate and extract required fields
        ValidateKdf(fields);
        int iterations = ParseIterations(fields);
        byte[] salt = ParseBase64Field(fields, "salt", "Salt");
        byte[] iv = ParseBase64Field(fields, "IV", "Initialization Vector");
        byte[] ciphertext = ParseBase64Field(fields, "ct", "CipherText");
        byte[] mac = ParseBase64Field(fields, "mac", "MAC");

        // Validate field lengths
        ValidateFieldLengths(salt, iv, mac);

        return new EnvelopeData
        {
            Iterations = iterations,
            Salt = salt,
            IV = iv,
            CipherText = ciphertext,
            MAC = mac
        };
    }

    /// <summary>
    /// Builds an SCS1 envelope string from structured components.
    /// </summary>
    /// <param name="iterations">PBKDF2 iteration count.</param>
    /// <param name="salt">Salt bytes for KDF.</param>
    /// <param name="iv">AES initialization vector.</param>
    /// <param name="ciphertext">Encrypted data.</param>
    /// <param name="mac">HMAC-SHA256 authentication tag.</param>
    /// <returns>A properly formatted SCS1 envelope string.</returns>
    /// <exception cref="ArgumentException">If any parameter is invalid.</exception>
    public string Build(int iterations, byte[] salt, byte[] iv, byte[] ciphertext, byte[] mac)
    {
        // Validate inputs
        if (iterations < MinIterations)
        {
            throw new ArgumentException(
                $"Iterations must be >= {MinIterations}. Provided: {iterations}",
                nameof(iterations));
        }

        if (salt == null || salt.Length < MinSaltLength)
        {
            throw new ArgumentException(
                $"Salt must be at least {MinSaltLength} bytes. Provided: {salt?.Length ?? 0} bytes",
                nameof(salt));
        }

        if (iv == null || iv.Length != IvLength)
        {
            throw new ArgumentException(
                $"IV must be exactly {IvLength} bytes. Provided: {iv?.Length ?? 0} bytes",
                nameof(iv));
        }

        if (ciphertext == null || ciphertext.Length == 0)
        {
            throw new ArgumentException("Ciphertext cannot be null or empty.", nameof(ciphertext));
        }

        if (mac == null || mac.Length != MacLength)
        {
            throw new ArgumentException(
                $"MAC must be exactly {MacLength} bytes (HMAC-SHA256). Provided: {mac?.Length ?? 0} bytes",
                nameof(mac));
        }

        // Build the envelope string
        var sb = new StringBuilder();
        sb.Append(FormatVersion);
        sb.Append("$kdf=").Append(KdfIdentifier);
        sb.Append("$iter=").Append(iterations);
        sb.Append("$salt=").Append(Convert.ToBase64String(salt));
        sb.Append("$IV=").Append(Convert.ToBase64String(iv));
        sb.Append("$ct=").Append(Convert.ToBase64String(ciphertext));
        sb.Append("$mac=").Append(Convert.ToBase64String(mac));

        return sb.ToString();
    }

    /// <summary>
    /// Parse key=value pairs from envelope parts.
    /// </summary>
    private Dictionary<string, string> ParseFields(IEnumerable<string> parts)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (string part in parts)
        {
            string[] kv = part.Split(new[] { '=' }, 2);
            if (kv.Length == 2)
            {
                fields[kv[0].Trim()] = kv[1].Trim();
            }
        }

        return fields;
    }

    /// <summary>
    /// Validates that the KDF field is present and correct.
    /// </summary>
    private void ValidateKdf(Dictionary<string, string> fields)
    {
        if (!fields.TryGetValue("kdf", out string? kdfValue))
        {
            throw new FormatException("Missing required field: 'kdf'");
        }

        if (!string.Equals(kdfValue, KdfIdentifier, StringComparison.OrdinalIgnoreCase))
        {
            throw new FormatException($"Unsupported KDF: '{kdfValue}'. Expected '{KdfIdentifier}' for SCS1 format.");
        }
    }

    /// <summary>
    /// Parses and validates the iteration count.
    /// </summary>
    private int ParseIterations(Dictionary<string, string> fields)
    {
        if (!fields.TryGetValue("iter", out string? iterStr))
        {
            throw new FormatException("Missing required field: 'iter'");
        }

        if (!int.TryParse(iterStr, out int iterations))
        {
            throw new FormatException($"Invalid iteration count: '{iterStr}' is not a valid integer.");
        }

        if (iterations < MinIterations)
        {
            throw new FormatException(
                $"Iteration count too low: {iterations} (minimum: {MinIterations})");
        }

        return iterations;
    }

    /// <summary>
    /// Parses a Base64-encoded field from the envelope.
    /// </summary>
    private byte[] ParseBase64Field(Dictionary<string, string> fields, string fieldName, string displayName)
    {
        if (!fields.TryGetValue(fieldName, out string? base64Value))
        {
            throw new FormatException($"Missing required field: '{fieldName}' ({displayName})");
        }

        try
        {
            return Convert.FromBase64String(base64Value);
        }
        catch (FormatException ex)
        {
            throw new FormatException(
                $"Invalid Base64 encoding in field '{fieldName}' ({displayName}): {ex.Message}",
                ex);
        }
    }

    /// <summary>
    /// Validates that binary fields have the expected lengths.
    /// </summary>
    private void ValidateFieldLengths(byte[] salt, byte[] iv, byte[] mac)
    {
        if (salt.Length < MinSaltLength)
        {
            throw new FormatException(
                $"Salt too short: {salt.Length} bytes (minimum: {MinSaltLength} bytes)");
        }

        if (iv.Length != IvLength)
        {
            throw new FormatException(
                $"Invalid IV length: {iv.Length} bytes (expected: {IvLength} bytes)");
        }

        if (mac.Length != MacLength)
        {
            throw new FormatException(
                $"Invalid MAC length: {mac.Length} bytes (expected: {MacLength} bytes for HMAC-SHA256)");
        }
    }
}

