namespace SecSealKit.Crypto.Authentication;

public interface IMac
{
    /// <summary>
    /// Computes the Message Authentication Code (MAC) for the given data using the specified key.
    /// </summary>
    /// <param name="data">The input data to compute the MAC for.</param>
    /// <param name="key">The secret key used for MAC computation.</param>
    /// <returns>The computed MAC as a byte array.</returns>
    byte[] Compute(byte[] data, byte[] key);

    /// <summary>
    /// Verifies the provided MAC against the computed MAC for the given data and key.
    /// </summary>
    /// <param name="data">The input data to verify the MAC for.</param>
    /// <param name="key">The secret key used for MAC computation.</param>
    /// <param name="expectedMac">The expected MAC to verify against.</param>
    /// <returns>True if the MAC is valid; otherwise, false.</returns>
    bool Verify(byte[] data, byte[] key, byte[] expectedMac);
}
