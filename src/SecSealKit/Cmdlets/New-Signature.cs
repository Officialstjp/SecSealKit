using System;
using System.IO;
using System.Management.Automation;
using System.Security;
using System.Text;
using SecSealKit.Crypto.Authentication;
using SecSealKit.Crypto.Engines;
using SecSealKit.Crypto.Formats;
using SecSealKit.Crypto.KeyDerivation;
using SecSealKit.Crypto.Utilities;
using SecSealKit.PassphraseSources;

namespace SecSealKit.Cmdlets;

/// <summary>
/// <para type="synopsis">Creates a detached SCSIG1 digital signature for data using HMAC-SHA256.</para>
/// <para type="description">
/// Sign-Data creates an integrity-only signature for arbitrary data without encryption.
/// The signature uses PBKDF2-HMAC-SHA1 key derivation followed by HMAC-SHA256 signing.
/// This provides data authentication and integrity verification without confidentiality.
/// </para>
/// <example>
///   <code>Sign-Data -InputString "my-artifact" -PassphraseSecure (Read-Host -AsSecureString) -OutFile artifact.sig</code>
///   <para>Signs a string and saves the signature to a file.</para>
/// </example>
/// </summary>
///
[Cmdlet(VerbsCommon.New, "Signature")]
[Alias("Sign-Data")]
[OutputType(typeof(string))]
public sealed class NewSignatureCommand : PSCmdlet
{
    # region Parameters

    [Parameter(Mandatory = true, ParameterSetName = "String", Position = 0, ValueFromPipeline = true)]
    [ValidateNotNullOrEmpty]
    public string? InputString { get; set; }

    [Parameter(Mandatory = true, ParameterSetName = "Bytes")]
    [ValidateNotNull]
    public byte[]? InputBytes { get; set; }

    [Parameter(Mandatory = true, ParameterSetName = "File")]
    [ValidateNotNullOrEmpty]
    public string? InFile { get; set; }

    [Parameter(Position = 1)]
    [ValidateNotNullOrEmpty]
    public string? OutFile { get; set; }

    [Parameter]
    [ValidateRange(10000, int.MaxValue)]
    public int Iterations { get; set; } = 200000;

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

#pragma warning disable CS8618 // Requires parameter definition, gets initialized in BeginProcessing()
    private IPassphraseProvider _passphraseProvider;
#pragma warning restore CS8618

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
        byte[]? data = null;
        byte[]? passphrase = null;
        string? signature = null;

        try
        {
            // Get data to sign
            data = GetDataBytes();
            WriteVerbose($"Data to sign {data.Length} bytes");

            // Get passphrase
            if (_passphraseProvider == null)
                throw new InvalidOperationException("Passphrase provider not initialized");

            passphrase = _passphraseProvider.GetPassphrase();
            WriteVerbose($"Passphrase retrieved.");

            // Create signing engine
            var kdf = new Pbkdf2HmacSha1();
            var mac = new HmacSha256Mac();
            var format = new Scsig1Format();
            var engine = new Scsig1Engine(kdf, mac, format);

            WriteVerbose($"Signing with {Iterations} PBKDF2 iterations...");

            // Sign
            signature = engine.Sign(data, passphrase, Iterations);
            WriteVerbose("Signing complete");

            if (!string.IsNullOrEmpty(OutFile))
            {
                File.WriteAllText(OutFile, signature, Encoding.UTF8);
                WriteVerbose($"Signature written to: {OutFile}");
                WriteObject($"Signed to {OutFile}");
            }
            else
            {
                WriteObject(signature);
            }
        }
        catch (Exception ex)
        {
            WriteError(new ErrorRecord(ex, "SignFailed", ErrorCategory.InvalidOperation, InputString ?? InFile ?? "(Bytes)"));
        }
        finally
        {
            if (data != null)
                SecureMemory.ClearPinned(data);

            if (passphrase != null)
                SecureMemory.ClearPinned(passphrase);
        }
    }


    private byte[] GetDataBytes()
    {
        if (!string.IsNullOrEmpty(InputString))
            return Encoding.UTF8.GetBytes(InputString);
        else if (InputBytes != null)
            return InputBytes;
        else if (!string.IsNullOrEmpty(InFile))
        {
            if (!File.Exists(InFile))
                throw new FileNotFoundException($"Input file not found: {InFile}", InFile);
            return File.ReadAllBytes(InFile);
        }
        throw new InvalidOperationException("No input specified");
    }
}
