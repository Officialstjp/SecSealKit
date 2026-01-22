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
/// <para type="synopsis">Verifies a detached SCSIG1 digital signature against data using HMAC-SHA256.</para>
/// <para type="description">
/// Verify-Data checks the integrity and authenticity of data using a detached SCSIG1 signature
/// created by Sign-Data. The function re-derives the signing key using the same passphrase
/// and compares signatures using constant-time comparison to prevent timing attacks.
/// </para>
/// <example>
///   <code>Verify-Data -InputString "my-artifact" -SignatureFile artifact.sig -PassphraseSecure (Read-Host -AsSecureString)</code>
///   <para>Verifies a signature returns $true or $false.</para>
/// </example>
/// </summary>
[Cmdlet(VerbsData.Compare, "Signature")]
[Alias("Verify-Data")]
[OutputType(typeof(bool))]
public sealed class CompareSignatureCommand : PSCmdlet
{
    #region Parameters

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
    public string? Signature { get; set; }

    [ValidateNotNullOrEmpty]
    public string? SignatureFile { get; set; }


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

        try
        {
            // Get data
            data = GetDataBytes();
            WriteVerbose($"Data to verify: {data.Length} bytes");

            // Get signature
            string signatureString = GetSignatureString();
            WriteVerbose($"Signature length: {signatureString.Length} characters");

            // Get passphrase
            if (_passphraseProvider == null)
                throw new InvalidOperationException("Passphrase provider not initialized");

            passphrase = _passphraseProvider.GetPassphrase();
            WriteVerbose($"Passphrase retrieved ({passphrase.Length} bytes)");

            // Create verification engine
            var kdf = new Pbkdf2HmacSha1();
            var mac = new HmacSha256Mac();
            var format = new Scsig1Format();
            var engine = new Scsig1Engine(kdf, mac, format);

            WriteVerbose("Verifying signature...");

            // Verify
            bool isValid = engine.Verify(data, signatureString, passphrase);
            WriteVerbose($"Signature valid: {isValid}");

            WriteObject(isValid);
        }
        catch (Exception ex)
        {
            WriteError(new ErrorRecord(ex, "VerifyFailed", ErrorCategory.InvalidOperation, InputString ?? InFile ?? SignatureFile));
        }
        finally
        {
            if (data != null) SecureMemory.ClearPinned(data);
            if (passphrase != null) SecureMemory.ClearPinned(passphrase);
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
                throw new FileNotFoundException($"Data file not found: {InFile}", InFile);
            return File.ReadAllBytes(InFile);
        }
        throw new InvalidOperationException("No input specified");
    }

    private string GetSignatureString()
    {
        if (!string.IsNullOrEmpty(Signature))
        {
            return Signature!;  // Not null after IsNullOrEmpty check
        }
        else if (!string.IsNullOrEmpty(SignatureFile))
        {
            if (!File.Exists(SignatureFile))
                throw new FileNotFoundException($"Signature file not found: {SignatureFile}", SignatureFile);
            return File.ReadAllText(SignatureFile, Encoding.UTF8).Trim();
        }
        throw new InvalidOperationException("No signature specified");
    }
}
