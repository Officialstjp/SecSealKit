using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SecSealKit.Crypto.Authentication;
using SecSealKit.Crypto.Ciphers;
using SecSealKit.Crypto.Utilities;
using SecSealKit.Crypto.Formats;

namespace SecSealKit.Crypto.Engines;

public class Scspk1Engine
{
    private const int SessionKeySize = 64;

    public string Protect(byte[] plaintext, X509Certificate2 cert)
    {
        if (cert == null) throw new ArgumentNullException(nameof(cert));

        // 1. Generate Session Key
        byte[] sessionKey = CryptoRandom.GetBytes(SessionKeySize);
        byte[] encKey = sessionKey.Take(32).ToArray();
        byte[] macKey = sessionKey.Skip(32).Take(32).ToArray();

        // 2. Encrypt Session Key (RSA-OAEP)
        byte[] encryptedSessionKey;
        using (RSA rsa = cert.GetRSAPublicKey())
        {
            if (rsa == null) throw new ArgumentException("Certificate does not have an RSA public key.");
            encryptedSessionKey = rsa.Encrypt(sessionKey, RSAEncryptionPadding.OaepSHA256);
        }

        // 3. Encrypt payload (AES-CBC)
        var cipher = new Aes256Cbc();
        var iv = CryptoRandom.GetBytes(16);
        var ciphertext = cipher.Encrypt(plaintext, encKey, iv);

        // 4. Construct Envelope for MAC
        string kid = cert.Thumbprint;
        string ekB64 = Convert.ToBase64String(encryptedSessionKey);
        string ivB64 = Convert.ToBase64String(iv);
        string ctB64 = Convert.ToBase64String(ciphertext);

        // MAC Input: "SCSPK1" || $ || "kid=" || ...
        string macInputStr = $"SCSPK1$kid={kid}$ek={ekB64}$iv={ivB64}$ct={ctB64}";
        byte[] macInput = Encoding.UTF8.GetBytes(macInputStr);

        var hmac = new HmacSha256Mac();
        byte[] mac = hmac.Compute(macInput, macKey);

        // 5. Return full string
        return $"{macInputStr}$mac={Convert.ToBase64String(mac)}";
    }

    public byte[] Unprotect(string envelopeString)
    {
        // 1. Parse
        var envelope = Scspk1Envelope.Parse(envelopeString);

        // 2. Find Cert
        var cert = CertificateStoreHelper.FindCertificate(envelope.KeyId);
        if (cert == null)
        {
            throw new CryptographicException($"Certificate with thumbprint '{envelope.KeyId}' not found in Machine or User store.");
        }

        if (!cert.HasPrivateKey)
        {
            throw new CryptographicException($"Certificate '{envelope.KeyId}' found, but private key is missing or not accessible");
        }

        // 3. Decrypt Session Key
        byte[] sessionKey;
        using (RSA rsa = cert.GetRSAPrivateKey())
        {
            if (rsa == null) throw new CryptographicException("Could not acquire RSA private key.");
            try
            {
                sessionKey = rsa.Decrypt(envelope.EncryptedKey, RSAEncryptionPadding.OaepSHA256);
            }
            catch (CryptographicException)
            {
                throw new CryptographicException("Failed to decrypt session key. Ensure the correct certificate is used.");
            }
        }

        if (sessionKey.Length != SessionKeySize)
            throw new CryptographicException("Invalid session key length");

        byte[] encKey = sessionKey.Take(32).ToArray();
        byte[] macKey = sessionKey.Skip(32).Take(32).ToArray();

        // 4. Verify mac
        // Reconstruct the header + Ct part
        string macInputStr = $"SCSPK1$kid={envelope.KeyId}$ek={Convert.ToBase64String(envelope.EncryptedKey)}$iv={Convert.ToBase64String(envelope.IV)}$ct={Convert.ToBase64String(envelope.CipherText)}";
        byte[] macInput = Encoding.UTF8.GetBytes(macInputStr);

        var hmac = new HmacSha256Mac();
        byte[] computedMac = hmac.Compute(macInput, macKey);

        if (!ConstantTime.Equals(computedMac, envelope.Mac))
        {
            throw new CryptographicException("Integrity check failed (MAC mismatch).");
        }

        // 5. Decrypt payload
        var cipher = new Aes256Cbc();
        return cipher.Decrypt(envelope.CipherText, encKey, envelope.IV);
    }
}
