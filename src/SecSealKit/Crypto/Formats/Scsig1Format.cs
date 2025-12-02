using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecSealKit.Crypto.Formats;

/// <summary>
/// SCSIG1 (Sealed Cryptographic Signature v1) format parser and builder.
/// </summary>
/// <remarks>
/// <para>
/// The SCSIG1 format is a doller-delimet string containing all parameters needed for signature verification.
/// Data is not encrypted. SCSIG1 provides integrity-only signatures.
/// Format specifications:
/// </para>
/// <para>
/// Where:
/// - kdf: Key derivation function (PBKDF2-SHA1 for SCSIG1)
/// - iter: PBKDF2 iteration count (integer >= 10000)
/// - salt: Base64-encoded salt for KDF (16+ bytes)
/// - sig: Base64-encoded HMAC-SHA256 signature (32 bytes)
/// </para>
/// </remarks>
internal class Scsig1Format : ISignatureFormat
{
    private const string FormatVersion = "SCSIG1";
    private const string KdfIdentifier  = "PBKDF2-SHA1";
    private const int MinIterations = 10000;
    private const int MinSaltLength = 16;
    private const int SignatureLength = 32;

    /// <summary>
    /// Parses a SCSIG1 string into structured components
    /// </summary>
    /// <param name="signatureString">The SCSIG1 signtaure string to parse.</param>
    /// <returns>A SignatureData  object containing all parsed fields.</returns>
    /// <exception cref="ArgumentException">If the signature string is null or empty.</excpetion>
    /// <exception cref="FormatException">If the signature format is invalid.</exception>
    public SignatureData Parse(string signatureString)
    {
        if (string.IsNullOrWhiteSpace(signatureString))
        {
            throw new ArgumentException("Signature string cannot be null or empty.", nameof(signatureString));
        }

        // Split on dollar
        string[] parts = signatureString.Split('$');

        if (parts.Length < 2 || parts[0] != FormatVersion)
        {
            throw new FormatException(
                $"Invalid signature format. Expected '{FormatVersion}$...' but got '{parts[0]}$...'");
        }

        var fields = ParseFields(parts.Skip(1));

        // Validate and extract required fields
        ValidateKdf(fields);
        int iterations = ParseIterations(fields);
        byte[] salt = ParseBase64Field(fields, "salt", "Salt");
        byte[] signature = ParseBase64Field(fields, "sig", "Signature");

        ValidateFieldLengths(salt, signature);

        return new SignatureData
        {
            Iterations = iterations,
            Salt = salt,
            Signature = signature
        };
    }

    /// <summary>
    /// Builds a SCSIG1 signature string from structured components.
    /// </summary>
    /// <param name="iterations">PBKDF2 iteration count.</param>
    /// <param name="salt">Salt bytes for KDF.</param>
    /// <param name="signature">HMAC-SHA256 signature bytes.</param>
    /// <returns>A properly formatted SCSIG1 signature string.</returns>
    /// <exception cref="ArgumentException">If any parameter is invalid.</exception>
    public string Build(int iterations, byte[] salt, byte[] signature)
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

        if (signature == null || signature.Length != SignatureLength)
        {
            throw new ArgumentException(
                $"Signature must be exactly {SignatureLength} bytes (HMAC-SHA256). Provided: {signature?.Length ?? 0} bytes",
                nameof(signature));
        }

        // Build the signature string
        var sb = new StringBuilder();
        sb.Append(FormatVersion);
        sb.Append("$kdf=").Append(KdfIdentifier);
        sb.Append("$iter=").Append(iterations);
        sb.Append("$salt=").Append(Convert.ToBase64String(salt));
        sb.Append("$sig=").Append(Convert.ToBase64String(signature));

        return sb.ToString();
    }

    private Dictionary<string, string> ParseFields(IEnumerable<string> parts)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var part in parts)
        {
            var keyValue = part.Split(new[] { '=' }, 2);
            if (keyValue.Length == 2)
            {
                fields[keyValue[0].Trim()] = keyValue[1].Trim();
            }
        }

        return fields;
    }

    private void ValidateKdf(Dictionary<string, string> fields)
    {
        if (!fields.TryGetValue("kdf", out string? kdfValue))
        {
            throw new FormatException("Missing 'kdf' field in signature.");
        }
        if (kdfValue != KdfIdentifier)
        {
            throw new FormatException($"Unsupported KDF '{kdfValue}'. Expected '{KdfIdentifier}'.");
        }
    }

    private int ParseIterations(Dictionary<string, string> fields)
    {
        if (!fields.TryGetValue("iter", out string? iterValue))
        {
            throw new FormatException("Missing required field: 'iter'");
        }

        if (!int.TryParse(iterValue, out int iterations) || iterations < MinIterations)
        {
            throw new FormatException(
                $"Invalid iteration count '{iterValue}'. Must be an integer >= {MinIterations}.");
        }
        return iterations;
    }

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

    private void ValidateFieldLengths(byte[] salt, byte[] signature)
    {
        if (salt.Length < MinSaltLength)
        {
            throw new FormatException(
                $"Salt too short: {salt.Length} bytes (minimum: {MinSaltLength} bytes)");
        }

        if (signature.Length != SignatureLength)
        {
            throw new FormatException(
                $"Invalid signature length: {signature.Length} bytes (expected: {SignatureLength} bytes for HMAC-SHA256)");
        }
    }
}

/// <summary>
/// Represents the structured data contained in an SCSIG1 signature
/// </summary>
public class SignatureData
{
    public int Iterations { get; set; }
    public byte[] Salt { get; set; } = Array.Empty<byte>();
    public byte[] Signature { get; set; } = Array.Empty<byte>();
}
