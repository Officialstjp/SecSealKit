using System;
using System.Collections.Generic;
using System.Text;

namespace SecSealKit.Crypto.Formats;

public class Scspk1Envelope
{
    public string KeyId { get; set; } = string.Empty; // Thumbprint
    public byte[] EncryptedKey { get; set; } = Array.Empty<byte>();
    public byte[] IV { get; set; } = Array.Empty<byte>();
    public byte[] CipherText { get; set; } = Array.Empty<byte>();
    public byte[] Mac { get; set; } = Array.Empty<byte>();

    public override string ToString()
    {
        return $"SCSPK1$kid={KeyId}$ek={Convert.ToBase64String(EncryptedKey)}$iv={Convert.ToBase64String(IV)}$ct={Convert.ToBase64String(CipherText)}$mac={Convert.ToBase64String(Mac)}";
    }

    public static Scspk1Envelope Parse (string envelope)
    {
        if (!envelope.StartsWith("SCSPK1$"))
            throw new ArgumentException("Invalid format: Expected `SCSPK1$` but got '" + envelope.Substring(0, 7) + "'.");

        var parts = envelope.Split('$');
        var dict = new Dictionary<string, string>();

        // Skip index 0 (format identifier)
        for (int i = 1; i < parts.Length; i++)
        {
            var segment = parts[i];
            var eqIndex = segment.IndexOf('=');
            if (eqIndex >0)
            {
                var key = segment.Substring(0, eqIndex);
                var val = segment.Substring(eqIndex + 1);
                dict[key] = val;
            }
        }

        if (!dict.ContainsKey("kid") || !dict.ContainsKey("ek") || !dict.ContainsKey("iv") || !dict.ContainsKey("ct") || !dict.ContainsKey("mac"))
            throw new ArgumentException("Invalid SCSPK1 format: Missing required fields.");

        return new Scspk1Envelope
        {
            KeyId = dict["kid"],
            EncryptedKey = Convert.FromBase64String(dict["ek"]),
            IV = Convert.FromBase64String(dict["iv"]),
            CipherText = Convert.FromBase64String(dict["ct"]),
            Mac = Convert.FromBase64String(dict["mac"])
        };
    }
}

