using System;
using SecSealKit.Crypto.Formats;

namespace SecSealKit.Crypto.Formats;

/// <summary>
/// Represents the structured data contained in an SCS1 envelope.
/// </summary>
public class EnvelopeData
{
    public int Iterations { get; set; }
    public byte[] Salt { get; set; } = Array.Empty<byte>();
    public byte[] IV { get; set; } = Array.Empty<byte>();
    public byte[] CipherText { get; set; } = Array.Empty<byte>();
    public byte[] MAC { get; set; } = Array.Empty<byte>();
}

/// <summary>
/// Interface for envelope formats used in sealing and unsealing data.
/// </summary>
public interface IEnvelopeFormat
{
    /// <summary>
    /// Formats the sealed data into an envelope string.
    /// </summary>
    /// <param name="kdf">Key derivation function identifier.</param>
    /// <param name="iterations">Number of iterations for the KDF.</param>
    /// <param name="salt">Salt used in the KDF.</param>
    /// <param name="iv">Initialization vector used in encryption.</param>
    /// <param name="ciphertext">The encrypted data.</param>
    /// <param name="mac">Message authentication code.</param>
    /// <returns>Formatted envelope string.</returns>
    string Build(int iterations, byte[] salt, byte[] iv, byte[] ciphertext, byte[] mac);

    /// <summary>
    /// Parses an envelope string into its components.
    /// </summary>
    /// <param name="envelope">The envelope string to parse.</param>
    /// <returns>Tuple containing KDF, iterations, salt, IV, ciphertext, and MAC.</returns>
    EnvelopeData Parse(string envelope);
}
