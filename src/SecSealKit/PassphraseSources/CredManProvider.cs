using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace SecSealKit.PassphraseSources
{
    /// <summary>
    /// Provides passphrase bytes from Windows Credential Manager.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Windows Credential Manager (CredMan) is the built-in Windows credential storage system.
    /// Credentials are encrypted using DPAPI and stored in the user's Windows Vault.
    /// </para>
    /// <para>
    /// This provider uses P/Invoke to call the native CredRead API from advapi32.dll
    /// to retrieve stored credentials by target name.
    /// </para>
    /// <para>
    /// Security considerations:
    /// - Credentials are encrypted per-user (same security model as DPAPI)
    /// - Only the user who stored the credential can read it
    /// - Administrator accounts may be able to enumerate/access credentials
    /// - Credentials persist across reboots and survive user password changes
    /// </para>
    /// </remarks>
    internal class CredManProvider : IPassphraseProvider
    {
        private readonly string _targetName;

        /// <summary>
        /// Creates a new provider for a Windows Credential Manager entry.
        /// </summary>
        /// <param name="targetName">The credential target name (identifier in CredMan).</param>
        /// <exception cref="ArgumentException">If targetName is null or empty.</exception>
        public CredManProvider(string targetName)
        {
            if (string.IsNullOrWhiteSpace(targetName))
            {
                throw new ArgumentException("Target name cannot be null or empty.", nameof(targetName));
            }

            _targetName = targetName;
        }

        /// <summary>
        /// Retrieves the passphrase from Windows Credential Manager.
        /// </summary>
        /// <returns>Passphrase bytes from the stored credential.</returns>
        /// <exception cref="InvalidOperationException">If the credential is not found or cannot be read.</exception>
        public byte[] GetPassphrase()
        {
            IntPtr credPtr = IntPtr.Zero;

            try
            {
                // Call native CredRead API
                bool success = CredRead(
                    _targetName,
                    CRED_TYPE_GENERIC,
                    0, // Reserved, must be 0
                    out credPtr);

                if (!success)
                {
                    int errorCode = Marshal.GetLastWin32Error();

                    if (errorCode == ERROR_NOT_FOUND)
                    {
                        throw new InvalidOperationException(
                            $"Credential not found in Windows Credential Manager: '{_targetName}'. " +
                            "Use 'cmdkey /add:{targetName} /pass:...' to create it.");
                    }

                    throw new Win32Exception(errorCode,
                        $"Failed to read credential '{_targetName}' from Windows Credential Manager.");
                }

                // Marshal the native CREDENTIAL structure
                CREDENTIAL cred = Marshal.PtrToStructure<CREDENTIAL>(credPtr);

                if (cred.CredentialBlobSize == 0 || cred.CredentialBlob == IntPtr.Zero)
                {
                    throw new InvalidOperationException(
                        $"Credential '{_targetName}' exists but has no password data.");
                }

                // Copy the password bytes from unmanaged memory
                byte[] passwordBytes = new byte[cred.CredentialBlobSize];
                Marshal.Copy(cred.CredentialBlob, passwordBytes, 0, cred.CredentialBlobSize);

                // Windows stores passwords as UTF-16LE, convert to UTF-8 for consistency
                string password = Encoding.Unicode.GetString(passwordBytes);
                return Encoding.UTF8.GetBytes(password);
            }
            finally
            {
                // Free the credential structure allocated by CredRead
                if (credPtr != IntPtr.Zero)
                {
                    CredFree(credPtr);
                }
            }
        }

        #region P/Invoke Declarations

        private const int CRED_TYPE_GENERIC = 1;
        private const int ERROR_NOT_FOUND = 1168;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredRead(
            string target,
            int type,
            int reservedFlag,
            out IntPtr credentialPtr);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern void CredFree(IntPtr buffer);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDENTIAL
        {
            public int Flags;
            public int Type;
            public IntPtr TargetName;
            public IntPtr Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public int CredentialBlobSize;
            public IntPtr CredentialBlob;
            public int Persist;
            public int AttributeCount;
            public IntPtr Attributes;
            public IntPtr TargetAlias;
            public IntPtr UserName;
        }

        #endregion
    }
}
