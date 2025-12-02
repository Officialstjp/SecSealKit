/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Stefan Ploch */

using System;
using System.IO;
using System.Management.Automation;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SecSealKit.Crypto.Authentication;
using SecSealKit.Crypto.Ciphers;
using SecSealKit.Crypto.Engines;
using SecSealKit.Crypto.Formats;
using SecSealKit.Crypto.KeyDerivation;
using SecSealKit.Crypto.Utilities;
using SecSealKit.PassphraseSources;

namespace SecSealKit.Cmdlets;

/// <summary>
/// <para type="synopsis">Decrypts data from an SCS1 authenticated envelope using AES-256-CbC + HMAC-SHA256.</para>
/// <para type="description">
/// Unportect-Secret decrypts and authenticates data from an SCS1 envelope created by Protect-Secret.
/// The function verifies the HMAC-SHA256 authentication tag before attempting decryption, providing protection against tampering.
/// </para>
/// <example>
///     <code>Unprotect-Secret -InFile secret.scs1 -PassphraseSecure (Read-Host -AsSecureString) -AsPlainText</code>
///     <para>Decrypts a file and outputs as plaintext string.</para>
/// </example>
/// <example>
///     <code>Unprotect-Secret -InFile db.scs1 -FromKeyFile app.key -OutFile decrypted.bin</code>
///     <para>Decrypts using a DPAPI keyfile and saves to a file.</para>
/// </example>
/// </summary>
[Cmdlet(VerbsSecurity.Unprotect, "Secret", DefaultParameterSetName = "File")]
[Alias("Unseal-Secret")]
[OutputType(typeof(byte[]), typeof(string))]
public sealed class UnprotectSecretCommand : PSCmdlet
{
    # region Parameters

    // Input sources
    [Parameter(Mandatory = true, ParameterSetName = "File", Position = 0)]
    [ValidateNotNullOrEmpty]
    public string? InFile { get; set; }

    [Parameter(Mandatory = true, ParameterSetName = "Envelope", ValueFromPipeline = true)]
    [ValidateNotNullOrEmpty]
    public string? Envelope { get; set; }

    // Output options
    [Parameter]
    public SwitchParameter AsPlainText { get; set; }

    [Parameter]
    public SwitchParameter AsBytes { get; set; }

    [Parameter]
    [ValidateNotNullOrEmpty]
    public string? OutFile { get; set; }

    // Passphrase sources
    [Parameter]
    public SecureString? PassphraseSecure { get; set; }


    [Parameter]
    [ValidateNotNullOrEmpty]
    public string? FromCredMan { get; set; }

    [Parameter]
    [ValidateNotNullOrEmpty]
    public string? FromKeyfile { get; set; }

    [Parameter]
    [ValidateNotNullOrEmpty]
    public string? FromEnv { get; set; }

    #endregion

    private IPassphraseProvider? _passphraseProvider;

    protected override void BeginProcessing()
    {
        base.BeginProcessing();

        // Validate passphrase sources
        int passphraseSourceCount = 0;
        if (PassphraseSecure != null) passphraseSourceCount++;
        if (!string.IsNullOrEmpty(FromCredMan)) passphraseSourceCount++;
        if (!string.IsNullOrEmpty(FromKeyfile)) passphraseSourceCount++;
        if (!string.IsNullOrEmpty(FromEnv)) passphraseSourceCount++;

        if (passphraseSourceCount == 0)
        {
            WriteVerbose("No passphrase source provided. Assuming SCSPK1 (Certificate) envelope.");
        }
        else if (passphraseSourceCount > 1)
        {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("Cannot specify multiple passphrase sources"),
                "MultiplePassphraseSources",
                ErrorCategory.InvalidArgument,
                null));
        }

        // Create the appropriate passphrase provider
        try
        {
            if (PassphraseSecure != null)
            {
                WriteVerbose("Using SecureString passphrase");
                _passphraseProvider = new SecureStringProvider(PassphraseSecure);
            }
            else if (!string.IsNullOrEmpty(FromKeyfile) && FromKeyfile != null)
            {
                WriteVerbose($"Using DPAPI keyfile: {FromKeyfile}");
                _passphraseProvider = new DpapiKeyfileProvider(FromKeyfile);
            }
            else if (!string.IsNullOrEmpty(FromCredMan) && FromCredMan != null)
            {
                WriteVerbose($"Using Windows Credential Manager: {FromCredMan}");
                _passphraseProvider = new CredManProvider(FromCredMan);
            }
            else if (!string.IsNullOrEmpty(FromEnv))
            {
                WriteVerbose($"Using environment variable: {FromEnv}");
                string? envValue = Environment.GetEnvironmentVariable(FromEnv);
                if (string.IsNullOrEmpty(envValue))
                {
                    ThrowTerminatingError(new ErrorRecord(
                        new ArgumentException($"Environment variable '{FromEnv}' is not set or is empty"),
                        "EnvVarNotFound",
                        ErrorCategory.ObjectNotFound,
                        FromEnv));
                }
                var secureEnv = new SecureString();
                foreach (char c in envValue)
                {
                    secureEnv.AppendChar(c);
                }
                secureEnv.MakeReadOnly();
                _passphraseProvider = new SecureStringProvider(secureEnv);
            }
        }
        catch (Exception ex)
        {
            ThrowTerminatingError(new ErrorRecord(
                ex,
                "PassphraseProviderCreationFailed",
                ErrorCategory.InvalidOperation,
                null));
        }
    }

    protected override void ProcessRecord()
    {
        byte[]? passphrase = null;
        byte[]? plaintext = null;

        try
        {
            // Step 1: Get the envelope string
            string envelopeString = GetEnvelopeString();
            WriteVerbose($"Envelope length: {envelopeString.Length}");

            if (envelopeString.StartsWith("SCSPK1$"))
            {
                WriteVerbose("Detected SCSPK1 envelope. Attempting certificate decryption...");
                var engine = new Scspk1Engine();
                plaintext = engine.Unprotect(envelopeString);
            }
            else
            {
                // Step 2: Get the passphrase
                if (_passphraseProvider == null)
                {
                    {
                     ThrowTerminatingError(new ErrorRecord(
                        new ArgumentException("Symmetric envelope. A passphrase is required, but no passphrase source was provided."),
                        "PassphraseRequired",
                        ErrorCategory.InvalidArgument,
                        null));
                    }
                }
                else
                {
                    passphrase = _passphraseProvider.GetPassphrase();
                }

                if (passphrase == null || passphrase.Length == 0)
                {
                    ThrowTerminatingError(new ErrorRecord(
                        new ArgumentException("Failed to retrieve passphrase from the specified source"),
                        "PassphraseRetrievalFailed",
                        ErrorCategory.InvalidOperation,
                        null));
                }

                WriteVerbose($"Passphrase retrieved");

                // Step 3: Create crypto engine with dependencies
                var kdf = new Pbkdf2HmacSha1();
                var cipher = new Aes256Cbc();
                var mac = new HmacSha256Mac();
                var format = new Scs1Format();
                var engine = new Scs1Engine(kdf, cipher, mac, format);

                WriteVerbose("Verifying MAC and decrypting...");

# pragma warning disable CS8604 // We throw if passphrase is null above

                // Step 4: Unseal the envelope
                plaintext = engine.Unseal(envelopeString, passphrase);

# pragma warning restore CS8604

                WriteVerbose($"Decryption successful ({plaintext.Length} bytes)");
            }

            // Step 5: Output the plaintext
            OutputPlaintext(plaintext);
        }
        catch (System.Security.Cryptography.CryptographicException ex)
        {
            WriteError(new ErrorRecord(
                new InvalidOperationException(
                    "MAC verification failed. The envelope may have been tampered with or the passphrase is incorrect.",
                    ex),
                "MacVerificationFailed",
                ErrorCategory.SecurityError,
                InFile ?? Envelope));
        }
        catch (FormatException ex)
        {
            WriteError(new ErrorRecord(
                new InvalidOperationException($"Invalid envelope format: {ex.Message}", ex),
                "InvalidEnvelopeFormat",
                ErrorCategory.InvalidData,
                InFile ?? Envelope));
        }
        catch (Exception ex)
        {
            WriteError(new ErrorRecord(
                ex,
                "UnsealFailed",
                ErrorCategory.InvalidOperation,
                InFile ?? Envelope));
        }
        finally
        {
            // Clear sensitive data from memory
            if (passphrase != null)
            {
                SecureMemory.ClearPinned(passphrase);
            }

            // Only clear plaintext if we're not returning it
            // (the caller owns it if WriteObject succeeded)
            if (plaintext != null && plaintext.Length > 0)
            {
                // If an exception was thrown, clear it
                // Otherwise, the caller is responsible for the data
            }
        }
    }

    private string GetEnvelopeString()
    {
        if (!string.IsNullOrEmpty(Envelope) && Envelope != null)
        {
            return Envelope;
        }
        else if (!string.IsNullOrEmpty(InFile))
        {
            if (!File.Exists(InFile))
            {
                throw new FileNotFoundException($"Envelope file not found: {InFile}", InFile);
            }
            return File.ReadAllText(InFile, Encoding.UTF8).Trim();
        }
        else
        {
            throw new InvalidOperationException("No envelope source specified");
        }
    }

    private void OutputPlaintext(byte[] plaintext)
    {
        if (!string.IsNullOrEmpty(OutFile))
        {
            File.WriteAllBytes(OutFile, plaintext);
            WriteVerbose($"Plaintext written to: {OutFile}");
            WriteObject($"Unsealed to: {OutFile}");
        }
        else if (AsPlainText)
        {
            string text = Encoding.UTF8.GetString(plaintext);
            WriteObject(text);
        }
        else
        {
            // Default: output as byte array
            WriteObject(plaintext);
        }
    }
}

