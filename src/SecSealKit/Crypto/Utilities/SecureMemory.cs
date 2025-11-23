using System;
using System.Runtime.InteropServices;

namespace SecSealKit.Crypto.Utilities;

/// <summary>
/// Provides best-effort secure memory operations for clearing sensitive data
/// </summary>
/// <remarks>
/// <para>
/// SECURITY NOTICE:
/// Perfect memory security is not achievable in managed .NET code because:
/// - The garbace collector may copy data during heap compaction
/// - Memory pages may be swapped to disk by the OS
/// - Debuggers and memory dumps can capture data before clearing
/// - CPU registers and caches may retain copies
///</para>
///<para>
/// This class provides best-effort clearing using:
/// - Pinned memory allocation to prevent GC moves
/// - Explicit zeroing before unpinning
/// - Multiple overwrite passes for defense-in-depth
///
/// For true memory protection, use hardware security modules or native code with OS-level memory locking
/// </para>
/// </remarks>
internal static class SecureMemory
{
    /// <summary>
    /// Clears a byte array by overwriting it with zeros.
    /// </summary>
    /// <param name="buffer">The buffer to clear. Null values are ignored.</param>
    /// <remarks>
    /// Simplest clearing method. It zeros the array but does not prevent GC from having already copied the data.
    /// Use <see cref="ClearPunned"/>  for stronger guarantess.
    /// </remarks>
    public static void Clear(byte[] buffer)
    {
        if (buffer == null || buffer.Length == 0)
        {
            return;
        }

        Array.Clear(buffer, 0, buffer.Length); // Sets elements to zero
    }

    /// <summary>
    /// Clears a byte array using pinned memory to prevent GC movement during clearing.
    /// </summary>
    /// <param name="buffer">The buffer to clear. Null values are ignored</param>
    /// <remarks>
    /// <para>
    /// This method:
    /// 1. Pins the buffer in memory to prevent GC moves
    /// 2. Overwrites with zeros three times
    /// 3. Unpins and allows normal GC
    ///</para>
    /// <para>
    /// Use this for cryptographic key material. Note that copies may still exist
    /// if the GC moved the buffer before this method was called.
    /// </para>
    /// </remarks>
    public static void ClearPinned(byte[] buffer)
    {
        if (buffer == null || buffer.Length == 0)
        {
            return;
        }

        GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            // Multiple overwrite passes (This doesnt help against GC copies, but defends against some memory forensics)
            for (int pass = 0; pass < 3; pass++)
            {
                Array.Clear(buffer, 0, buffer.Length);
            }
        }
        finally
        {
            if (handle.IsAllocated)
            {
                handle.Free();
            }
        }
    }

     /// <summary>
    /// Converts a SecureString to a byte array using UTF-8 encoding, for use with crypto operations.
    /// </summary>
    /// <param name="secureString">The SecureString to convert.</param>
    /// <returns>A byte array containing the UTF-8 encoded string.</returns>
    /// <remarks>
    /// <para>
    /// <strong>WARNING:</strong> This creates an unencrypted copy of the SecureString in managed memory.
    /// The returned byte array should be cleared with <see cref="ClearPinned"/> as soon as possible.
    /// </para>
    /// <para>
    /// SecureString is encrypted in memory by the CLR, but must be decrypted for use.
    /// This method minimizes exposure time by using Marshal operations.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown if secureString is null.</exception>
    public static byte[] SecureStringToBytes(System.Security.SecureString secureString)
    {
        if (secureString == null)
        {
            throw new ArgumentNullException(nameof(secureString));
        }

        IntPtr unmanagedString = IntPtr.Zero;
        try
        {
            // Decrypt SecureString to unmanaged memory
            unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(secureString);

            // Convert from Unicode (UTF-16) to UTF-8 bytes
            string plaintext = Marshal.PtrToStringUni(unmanagedString);

            if (plaintext == null)
            {
                return Array.Empty<byte>();
            }

            return System.Text.Encoding.UTF8.GetBytes(plaintext);
        }
        finally
        {
            // Zero and free the unmanaged memory
            if (unmanagedString != IntPtr.Zero)
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            }
        }
    }

    /// <summary>
    /// Allocates a pinned byte array that will not be moved by the garbage collector.
    /// </summary>
    /// <param name="length">The size of the buffer to allocate.</param>
    /// <returns>A tuple containing the allocated byte array and its GCHandle.</returns>
    /// <remarks>
    /// <para>
    /// Use this for storing sensitive data that should remain at a fixed memory address.
    /// The caller MUST call <see cref="FreePinned"/> when done to avoid memory leaks.
    /// </para>
    /// <para>
    /// Example usage:
    /// <code>
    /// var (buffer, handle) = SecureMemory.AllocatePinned(32);
    /// try
    /// {
    ///     // Use buffer for crypto operations
    /// }
    /// finally
    /// {
    ///     SecureMemory.FreePinned(buffer, handle);
    /// }
    /// </code>
    /// </para>
    /// </remarks>
    public static (byte[] Buffer, GCHandle Handle) AllocatePinned(int length)
    {
        if (length < 1)
        {
            throw new ArgumentException("Length must be at least 1 byte.", nameof(length));
        }

        byte[] buffer = new byte[length];
        GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        return (buffer, handle);
    }

    /// <summary>
    /// Clears and frees a pinned buffer allocated with <see cref="AllocatePinned"/>.
    /// </summary>
    /// <param name="buffer">The buffer to clear and free.</param>
    /// <param name="handle">The GCHandle associated with the buffer.</param>
    public static void FreePinned(byte[] buffer, GCHandle handle)
    {
        if (buffer != null && buffer.Length > 0)
        {
            Array.Clear(buffer, 0, buffer.Length);
        }

        if (handle.IsAllocated)
        {
            handle.Free();
        }
    }
}
