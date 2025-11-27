using System;
using System.IO;
using System.Management.Automation;
using System.Text;
using Newtonsoft.Json;
using SecSealKit.Crypto.Formats;

namespace SecSealKit.Cmdlets;

// Note: -AsJson currently doesnt work:
/*
Get-EnvelopeMetadata: Self referencing loop detected for property 'Value' with type
'System.Management.Automation.PSMethod`1[System.Management.Automation.MethodGroup`1[System.Func`1[System.String]]]'. Path 'ToString'.
*/

/// <summary>
/// <para type="synopsis">Displays metadata and structure information from an SCS1 envelope without decryption.</para>
/// <para type="description">
/// Inspect-Envelope parses and displays the cryptographic parameters and metadata from
/// an SCS1 envelope without requiring the passphrase or performing decryption. Can be used for auditing envelope formats,
/// checking iteration counts, and verifying envelope integrity before attempting unsealing operations.
/// </para>
/// <example>
///     <code>Inspect-Envelope -InFile secret.scs1</code>
///     <para>Displays enevelope metadata for secret.scs1.</para>
/// </example>
/// </summary>
[Cmdlet(VerbsCommon.Get, "EnvelopeMetadata")]
[Alias("Inspect-Envelope")]
[OutputType(typeof(PSCustomObject))]
public sealed class InspectEnvelopeCommand : PSCmdlet
{
    # region Parameters

    [Parameter(Mandatory = true, ParameterSetName = "File", Position = 0)]
    [ValidateNotNullOrEmpty]
    public string? InFile { get; set; }

    [Parameter(Mandatory = true, ParameterSetName = "Envelope", ValueFromPipeline = true)]
    [ValidateNotNullOrEmpty]
    public string? Envelope { get; set; }

    [Parameter]
    public SwitchParameter AsJson { get; set; }

    #endregion

    protected override void ProcessRecord()
    {
        try
        {
            // Get envelope string
            string envelopeString = GetEnvelopeString();
            WriteVerbose($"Envelope length: {envelopeString.Length} characters");

            // Parse
            var format = new Scs1Format();
            var parsed = format.Parse(envelopeString);

            // Build output object
            var metadata = new PSObject();
            metadata.Properties.Add(new PSNoteProperty("Format", "SCS1"));
            metadata.Properties.Add(new PSNoteProperty("Version", "1"));
            metadata.Properties.Add(new PSNoteProperty("KDF", "PBKDF2-HMAC-SHA1"));
            metadata.Properties.Add(new PSNoteProperty("Iterations", parsed.Iterations));
            metadata.Properties.Add(new PSNoteProperty("SaltBytes", parsed.Salt));
            metadata.Properties.Add(new PSNoteProperty("SaltHex", BitConverter.ToString(parsed.Salt).Replace("-", "")));
            metadata.Properties.Add(new PSNoteProperty("IVBytes", parsed.IV));
            metadata.Properties.Add(new PSNoteProperty("IVHex", BitConverter.ToString(parsed.IV).Replace("-", "")));
            metadata.Properties.Add(new PSNoteProperty("CiphertextBytes", parsed.CipherText));
            metadata.Properties.Add(new PSNoteProperty("Cipher", "AES-256-CBC"));
            metadata.Properties.Add(new PSNoteProperty("MAC", parsed.MAC));
            metadata.Properties.Add(new PSNoteProperty("MACHex", BitConverter.ToString(parsed.MAC).Replace("-", "")));
            metadata.Properties.Add(new PSNoteProperty("EnvelopeSize", envelopeString.Length));
            metadata.Properties.Add(new PSNoteProperty("EstimatedPlaintextSize",
                EstimatePlaintextSize(parsed.CipherText.Length)));

            // Add security recommendations
            var recommendations = new System.Collections.Generic.List<string>();
            if (parsed.Iterations < 100000)
            {
                recommendations.Add("[!] Iterations below 100.000 (current: {0}). Consider re-encrypting with higher iterations.".Replace("{0}", parsed.Iterations.ToString()));
            }
            if (parsed.Salt.Length < 16)
            {
                recommendations.Add("[!] Salt shorter than 16 bytes (current: {0}). Recommended mininum: 16 bytes.".Replace("{0}", parsed.Salt.Length.ToString()));
            }
            metadata.Properties.Add(new PSNoteProperty("Recommendations", recommendations.ToArray()));

            if (AsJson)
            {
                var dict = new System.Collections.Generic.Dictionary<string, object>();
                foreach (var prop in metadata.Properties)
                {
                    dict[prop.Name] = prop.Value;
                }
                var json = JsonConvert.SerializeObject(dict);
                WriteObject(json);
            }
            else
            {
                WriteObject(metadata);
            }
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
                "InspectFailed",
                ErrorCategory.InvalidOperation,
                InFile ?? Envelope));
        }
    }

    private string GetEnvelopeString()
    {
        if (!string.IsNullOrEmpty(Envelope) && Envelope != null)
        {
            return Envelope;
        }
        else if(!string.IsNullOrEmpty(InFile))
        {
            if (!File.Exists(InFile))
            {
                throw new FileNotFoundException($"Envelope file not found: {InFile}");
            }
            return File.ReadAllText(InFile, Encoding.UTF8).Trim();
        }
        else
        {
            throw new InvalidOperationException("No envelope source specified");
        }
    }

    private string EstimatePlaintextSize(int ciphertextBytes)
    {
        // AES-CBC with PKCS7 padding: plaintext + (1 to 16 padding bytes)
        // Ciphertext will be multiple of 16, plaintext could be slightly smaller
        int minPlaintext = ciphertextBytes - 16;
        return $"{minPlaintext}-{ciphertextBytes} bytes (estimated, PKCS7 padding)";
    }
}
