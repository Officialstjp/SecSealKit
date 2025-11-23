namespace SecSealKit.Crypto.Engines;

public interface ISealEngine
{
    /// <summary>
    /// Encrypts plaintext using the specified passphrase.
    /// </summary>
    /// <param name="plaintext"></param>
    /// <param name="passphrase"></param>
    /// <returns>Envelope string</returns>
    public string Seal(byte[] plaintext, byte[] passphrase, int iterations);

    /// <summary>
    /// Decrypts an envelope using the specified passphrase.
    /// </summary>
    /// <param name="envelope"></param>
    /// <param name="passphrase"></param>
    /// <returns>Decrpyted plaintext bytes</returns>
    public byte[] Unseal(string envelope, byte[] passphrase);
}
