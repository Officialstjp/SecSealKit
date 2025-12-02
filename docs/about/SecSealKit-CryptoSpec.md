# SecSealKit Cryptography Specification (SCS1)

Status: Draft for MVP implementation

This document specifies the envelope, key derivation, authenticated encryption, and signature formats for SecSealKit.

## 1. Envelope Overview

Envelope format (string):
SCS1 = Sealed Cryptographic Secret v1

```
SCS1$kdf=PBKDF2-SHA1$iter=<N>$salt=<b64>$IV=<b64>$ct=<b64>$mac=<b64>
```

Where:
- kdf: PBKDF2-HMAC-SHA1
- iter: integer ≥ 10000 (MVP default: 200000)
- salt: 16–32 bytes (base64)
- iv: 16 bytes (base64) for AES-CBC
- ct: ciphertext (base64) of PKCS7-padded plaintext
- mac: HMAC-SHA256 over canonicalized associated data and ciphertext

Canonicalization and parsing rules:
- Fields appear exactly in the order shown.
- Parameter keys are lowercase tokens; values must be URL-safe characters; b64 is standard (no URL variant); trailing '=' allowed.
- All fields required; reject unknown keys for SCS1.
- Whitespace around tokens is not allowed; reject if present.

## 2. Key Derivation

Inputs:
- passphrase: UTF-8 bytes (no normalization beyond UTF-8)
- salt: random 16 bytes minimum (recommend 16)
- iterations: default 200000 (configurable)
- dkLen: 64 bytes

Algorithm:
- PBKDF2 with HMAC-SHA1 (RFC 2898), dkLen = 64
- Domain separation: salt' = salt || "|scs1|" (ASCII). PBKDF2 is applied to salt'.
- Split derived key: EncKey = DK[0..31], MacKey = DK[32..63]

Security notes:
- SHA1 usage limited to PRF for PBKDF2; MAC uses SHA256.
- Iterations chosen to balance PS 5.1 performance; allow override.

## 3. Authenticated Encryption (Encrypt-then-MAC)

Cipher:
- AES-256-CBC with random 16-byte IV
- Padding: PKCS7 (mandatory)

MAC:
- HMAC-SHA256
- Message to MAC (ASCII bytes unless stated otherwise):

```
"SCS1" || 0x24 || "kdf=PBKDF2-SHA1" || 0x24 || "iter=" || IterDec || 0x24 ||
"salt=" || Base64(salt) || 0x24 || "IV=" || Base64(iv) || 0x24 || "ct=" || Base64(ct)
```

Where 0x24 is the ASCII '$'. The mac field is not included in the MAC input. Using ASCII avoids ambiguity.

Verification:
1) Parse and validate envelope structure and base64 fields
2) Recompute HMAC-SHA256 and constant-time-compare with provided mac (fixed-time byte-wise comparison)
3) If equal, proceed to AES-256-CBC decryption; otherwise fail

## 4. Signature Format (Integrity Only)

Signature string format:

```
SCSIG1$kdf=PBKDF2-SHA1$iter=<N>$salt=<b64>$sig=<b64>
```

Purpose:
- Provide integrity-only signing over arbitrary payloads without encryption.

Key derivation for signatures:
- PBKDF2-HMAC-SHA1 with dkLen=32 using same passphrase sources; salt and iter independent of envelope settings
- Signing key = DK (32 bytes) used directly as HMAC-SHA256 key

Message to sign:
- Canonical payload bytes as provided by the caller
- For strings, UTF-8 without BOM

Verification:
- Re-derive key with salt/iter from signature
- Compute HMAC-SHA256 over payload; compare to sig (constant time)

## 5. Randomness Requirements

- salt: 16 random bytes (minimum)
- iv: 16 random bytes
- RNG: System.Security.Cryptography.RandomNumberGenerator

## 6. Hybrid Encryption (SCSPK1)

Status: Draft

This formats implements "Sealed Secrets" using RSA-OAEP and AES-CBC. It allows encryption using a public certificate
and decryption using the corresponding private key in the Windows Certificate Store.

### 6.1 Envelope Format

Format (string): `SCSPK1$kid=<Thumbprint>$ek=<b64>$iv=<b64>$ct=<b64>$mac=<b64>`

Where:
- **kid**: Key ID. The SHA-1 thumbprint of the X.509 Certificate (uppercase hex). Used for key lookup.
- **el**: Encrypted Session Key (Base64). The 64-byte Session Key encrypted using RSA-OAEP-SHA256 with the certificate's public key.
- **iv**: 16 bytes (Base64) random IV for AES-CBC.
- **ct**: Ciphertext (Base64) of the payload.
- **mac**: HMAC-SHA256 (Base64) over the header and ciphertext.

### 7.2 Session Key Generation

For every encryption operation, a new randon Session Key is generated:
- Length: 64 bytes
- Source: Cryptographically Secure PRNG
- Splitting:
  - `EncKey` = SessionKey[0..31] (32 Bytes)
  - `MacKey` = SessionKey[32.63] (32 Bytes)

### 7.3 Encryption Process (Protect)

1. Generate random 64-byte Session Key.
2. Encrypt payload using AES-256-CBC (PKCS7 padding) with `EncKey` and random `IV`.
3. Encrypt the 64-byte Session Key using the Certificate`s Public Key:
   - Algorithm: RSA
   - Padding: OAEP (SHA-256)
4. Compute MAC using `MacKey`.
5. Construct envelope string.

### 7.4 Decryption Process (Unprotect)

1. Parse `kid` from envelope.
2. Locate Certificate in Windows Certificate Stores (`LocalMachine\My` or `CurrentUser\My`) matching `kid`.
3. Aquire RSA Private Key (transparently handles TPM/Software keys).
4. Decrypt `ek` using RSA-OAEP-SHA256 to recover 64-byte Session Key.
5. Split Session Key into `EncKey` and `MacKey`.
6. Verify `mac` (Constant Time).
7. Decrypt `ct` using `EncKey`.


### 7.5 MAC Calculation

The MAC ensures integrity of the ciphertext and the metadata (preventing ID swapping).

Input to HMAC-SHA256:
`"SCSPK1" || 0x24 || "kid=" || Thumbprint || 0x24 ||"ek=" || Base64(ek) || 0x24 || "iv=" || Base64(iv) || 0x24 || "ct=" || Base64(ct)`

(0x24 is '$').

### 7.6 Security Considerations

- **RSA Padding**: OAEP with SHA-256 is mandatory. PKCS1-v1.5 is forbidden.
- **Key Size**: Certificates should be RSA 2048 or 4096 bits.
- **TPM**: If the certificate is TPM-backed, the private key operation occurs in hardware. The application only sees the handle.

## . Errors and Edge Cases

- Reject envelopes with missing/extra fields or unknown parameters
- Reject b64 decoding errors
- Reject iter < 10000 (policy)
- Reject iv length != 16
- Reject salt length < 16
- For empty plaintext, PKCS7 yields a full block; allow and handle
- MAC mismatch → return VerifyFailed without attempting decryption

## . Interoperability Notes

- SCS1 explicitly targets PS 5.1. SCS2 (AES-GCM) to be specified separately; both must remain parseable side-by-side.
- Passphrase sources are external to this spec; provider interface defines how passphrase bytes are obtained.
- Crypto backend selection (builtin vs experimental) does not change the envelope; outputs must be semantically identical.
