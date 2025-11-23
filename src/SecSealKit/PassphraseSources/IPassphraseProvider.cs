namespace SecSealKit.PassphraseSources
{
    /// <summary>
    /// Interface for passphrase providers that supply credentials to the crypto engine.
    /// </summary>
    public interface IPassphraseProvider
    {
        /// <summary>
        /// Retrieves the passphrase as a byte array.
        /// </summary>
        /// <returns>
        /// Passphrase bytes encoded as UTF-8.
        /// The caller is responsible for clearing this array from memory after use.
        /// </returns>
        byte[] GetPassphrase();
    }
}
