using System;

namespace SecSealKit.Crypto.Utilities;
/// <summary>
/// Timing-safe comparison utilities to prevent timing attacks.
/// </summary>
internal static class ConstantTime
{
    /// <summary>
    /// Compares two byte arrays in constant time.
    /// This prevents timing attacks where an attacker could learn information
    /// about the expected value by measuring comparison time.
    /// </summary>
    /// <param name="a">First byte array.</param>
    /// <param name="b">Second byte array.</param>
    /// <returns>True if arrays are equal, false otherwise.</returns>
    public static bool Equals(byte[] a, byte[] b)
    {
        if (a == null && b == null)
        {
            return true;
        }

        if (a == null || b == null)
        {
            return false;
        }

        // Length comparison is not timing-sensitive (length is not secret)
        if (a.Length != b.Length)
        {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.Length; i++)
        {
            result |= a[i] ^ b[i];
        }

        // result is 0 only if all bytes were equal
        return result == 0;
    }

    /// <summary>
    /// Compares two byte arrays for equality in constant time, with explicit length checking
    /// </summary>
    /// <param name="a"></param>
    /// <param name="b"></param>
    /// <param name="expectedLength"></param>
    /// <returns></returns>
    public static bool Equals(byte[] a, byte[] b, int expectedLength)
    {
        if (a == null || b == null)
        {
            return false;
        }

        if (a.Length != expectedLength || b.Length != expectedLength)
        {
            return false;
        }

        return Equals(a, b);
    }

    /// <summary>
    /// Securely clears a byte array by overwriting with zeros.
    /// </summary>
    /// <param name="buffer">Buffer to clear.</param>
    public static void Clear(byte[] buffer)
    {
        if (buffer != null)
        {
            Array.Clear(buffer, 0, buffer.Length);
        }
    }
}
