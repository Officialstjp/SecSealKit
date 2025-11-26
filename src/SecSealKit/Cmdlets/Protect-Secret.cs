/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Stefan Ploch */

using System;
using System.IO;
using System.Management.Automation;
using System.Security;
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
/// <para type="synopsis">Encrypts data into an SCS1 authenticated envelope using AES-256-CBC + HMAC-SHA256.</para>
/// <para type="description">
/// Protect-Secret encrypts small secrets or data into a tamper-evident SCS1 envelope format.
/// The envelope uses AES-256-CBC encryption with HMAC-SHA256 authenticated and PBKDF2-HMAC-SHA1 key derivation.
/// Passphrases can be soruced from DPAPI keyfiles, Windows Credential Manager, SecureString objects or
/// environment variables to keep secrets out of source code.
/// </para>
/// <example>
///     <code>Protect-Secret -InputString "my-api-key" -OutFile secret.scs1 -PassphraseSecure (Read-Host -AsSecureString)</code>
///     <para>Encrypts a string and saves to a file using SecureString passphrase.</para>
/// </example>
/// <example>
///     <code>Protect-Secret -InFile ".\my-secret-data.format" -FromKeyFile app.key -OutFile nothing-to-see.scs1</code>
///     <para>Encrypts a file and saves to a file using Keyfile passphrase.</para>
/// </summary>
[Cmdlet(VerbsSecurity.Protect, "Secret", DefaultParameterSetName = "String")]
[Alias("Seal-Secret")]
[OutputType(typeof(string))]
public sealed class ProtectSecretCommand : PSCmdlet
{
    # region Parameters

    // Input sources (mutually exclusive)
    [Parameter(Mandatory = true, ParameterSetName = "String", Position = 0, ValueFromPipeline = true)]
    [ValidateNotNullOrEmpty]
    public string? InputString { get; set; }

    [Parameter(Mandatory = true, ParameterSetName = "Bytes")]
    [ValidateNotNull]
    public byte[]? InputBytes { get; set; }

    [Parameter(Mandatory = true, ParameterSetName = "File")]
    [ValidateNotNullOrEmpty]
    public string? InFile { get; set; }

    // Output
    [Parameter(Position = 1)]
    [ValidateNotNullOrEmpty]
    public string? OutFile { get; set; }

    // Crypto parameters
    [Parameter]
    [ValidateRange(10000, int.MaxValue)]
    public int Iterations { get; set; } = 200000;

    // Passphrase sources (mutually exclusive, validated in BeginProcessing)
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

        // Validate exactly one passphrase source
        int passphraseSourceCount = 0;
        if (PassphraseSecure != null) passphraseSourceCount++;
        if (!string.IsNullOrEmpty(FromCredMan)) passphraseSourceCount++;
        if (!string.IsNullOrEmpty(FromKeyfile)) passphraseSourceCount++;
        if (!string.IsNullOrEmpty(FromEnv)) passphraseSourceCount++;

        if (passphraseSourceCount == 0)
        {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("A passphrase source must be specified."),
                "NoPassphraseSource",
                ErrorCategory.InvalidArgument,
                null));
        }
        else if (passphraseSourceCount > 1)
        {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("Only one passphrase source can be specified."),
                "MultiplePassphraseSources",
                ErrorCategory.InvalidArgument,
                null));
        }

        // Create the appropriate passphrase provider
        try
        {
            if (PassphraseSecure != null)
            {
                WriteVerbose("Using SecureString passphrase.");
                _passphraseProvider = new SecureStringProvider(PassphraseSecure);
            }
            else if (!string.IsNullOrEmpty(FromKeyfile) && FromKeyfile != null)
            {
                WriteVerbose($"Using DPAPI keyfle: {FromKeyfile}");
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
                // Convert environment variable to SecureString
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
        byte[]? plaintext = null;
        byte[]? passphrase = null;
        string? envelope = null;

        try
        {
            // Step 1: Get the plaintext bytes
            plaintext = GetPlainTextBytes();
            WriteVerbose($"Plaintext size: {plaintext.Length} bytes");

            // Step 2: Get the passphrase
            if (_passphraseProvider == null)
            {
                throw new InvalidOperationException("Passphrase provider not initialized");
            }
            passphrase = _passphraseProvider.GetPassphrase();
            WriteVerbose($"Passphrase retrieved");

            // Step 3: Create crypto engine with dependencies
            var kdf = new Pbkdf2HmacSha1();
            var cipher = new Aes256Cbc();
            var mac = new HmacSha256Mac();
            var format = new Scs1Format();
            var engine = new Scs1Engine(kdf, cipher, mac, format);

            WriteVerbose($"Encrypting with {Iterations} PBKDF2 iterations...");

            // Step 4: Seal the data
            envelope = engine.Seal(plaintext, passphrase, Iterations);
            WriteVerbose("Encryption complete");

            // Step 5: Output the envelope
            if (!string.IsNullOrEmpty(OutFile))
            {
                File.WriteAllText(OutFile, envelope, Encoding.UTF8);
                WriteVerbose($"Envelope written to: {OutFile}");
                WriteObject($"Sealed to: {OutFile}");
            }
            else
            {
                WriteObject(envelope);
            }
        }
        catch(Exception ex)
        {
            WriteError(new ErrorRecord(
                ex,
                "SealFailed",
                ErrorCategory.InvalidOperation,
                InputString ?? InFile ?? (object?)InputBytes ?? FromEnv));
        }
        finally
        {
            // Clear memory
            if (plaintext != null)
            {
                SecureMemory.ClearPinned(plaintext);
            }
            if (passphrase != null)
            {
                SecureMemory.ClearPinned(passphrase);
            }
        }
    }

    private byte[] GetPlainTextBytes()
    {
        if (!string.IsNullOrEmpty(InputString))
        {
            return Encoding.UTF8.GetBytes(InputString);
        }
        else if (InputBytes != null)
        {
            return InputBytes;
        }
        else if (!string.IsNullOrEmpty(InFile))
        {
            if (!File.Exists(InFile))
            {
                throw new FileNotFoundException($"Input file not found: {InFile}", InFile);
            }
            return File.ReadAllBytes(InFile);
        }
        else
        {
            throw new InvalidOperationException("No input source specified");
        }
    }

}
