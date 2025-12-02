namespace SecSealKit.Crypto.Engines
{
    /// <summary>
    /// Interface for digital signature engines.
    /// </summary>
    public interface ISignatureEngine
    {
        /// <summary>
        /// Signs data and produces a signature string.
        /// </summary>
        string Sign(byte[] data, byte[] passphrase, int iterations);

        /// <summary>
        /// Verifies a signature against data. Returns true if valid, false otherwise.
        /// </summary>
        bool Verify(byte[] data, string signatureString, byte[] passphrase);
    }
}
