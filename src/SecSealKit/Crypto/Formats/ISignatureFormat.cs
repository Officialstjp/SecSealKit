using SecSealKit.Crypto.Formats;

namespace SecSealKit.Crypto.Formats;

/// <summary>
/// Interface for signature format parsers and builders
/// </summary>
public interface ISignatureFormat
{
    /// <summary>
    /// Builds a signature string from structured components
    /// </summary>
    /// <param name="iterations">PBKDF2 iteration count</param>
    /// <param name="salt">Base64-encoded salt for KDF (16+ bytes)</param>
    /// <param name="signature">Base64-encoded HMAC-SHA256 signature string (32 Bytes)</param>
    /// <returns></returns>
    string Build(int iterations, byte[] salt, byte[] signature);

    /// <summary>
    /// Parses a signature string into structured components
    /// </summary>
    /// <param name="signatureString">Base64-encoded HMAC-SHA256 signature string to parse</param>
    /// <returns></returns>
    public SignatureData Parse(string signatureString);
}
