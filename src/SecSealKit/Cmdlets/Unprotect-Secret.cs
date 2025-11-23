using System;
using System.Management.Automation;
using System.Security;
using System.Text;

namespace SecSealKit.Cmdlets;

[Cmdlet(VerbsSecurity.Unprotect, "Secret", DefaultParameterSetName = "File")]
[Alias("Unseal-Secret")]
[OutputType(typeof(byte[]), typeof(string))]
public sealed class UnsealSecretCommand : PSCmdlet
{
    // Input Sources
    [Parameter(Mandatory = true, ParameterSetName = "File", Position = 0)]
    [ValidateNotNullOrEmpty]
    public string? InputFile { get; set; }

    [Parameter(Mandatory = true, ParameterSetName = "Envelope", ValueFromPipeline = true)]
    [ValidateNotNullOrEmpty]
    public string? Envelope { get; set; }

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
    public string? FromCredMan { get; set; }

    [Parameter]
    public string? FromKeyFile { get; set; }

    [Parameter]
    public string? FromEnv { get; set; }

    protected override void BeginProcessing()
    {
        base.BeginProcessing();
    }

    protected override void ProcessRecord()
    {
        try
        {
            // TODO:

            WriteVerbose("Unseal-Secret Scaffolding");

            byte[] plaintext = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F }; // Hello

            if (OutFile != null)
            {
                System.IO.File.WriteAllBytes(OutFile, plaintext);
                WriteVerbose($"Plaintext written to {OutFile}");
            }
            else if (AsPlainText)
            {
                WriteObject(Encoding.UTF8.GetString(plaintext));
            }
            else
            {
                WriteObject(plaintext);
            }
        }
        catch (Exception ex)
        {
            WriteError(new ErrorRecord(ex, "UnsealFailed", ErrorCategory.InvalidOperation, null));
        }
    }
}
