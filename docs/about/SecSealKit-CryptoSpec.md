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

## 6. Errors and Edge Cases

- Reject envelopes with missing/extra fields or unknown parameters
- Reject b64 decoding errors
- Reject iter < 10000 (policy)
- Reject iv length != 16
- Reject salt length < 16
- For empty plaintext, PKCS7 yields a full block; allow and handle
- MAC mismatch → return VerifyFailed without attempting decryption

## 7. Interoperability Notes

- SCS1 explicitly targets PS 5.1. SCS2 (AES-GCM) to be specified separately; both must remain parseable side-by-side.
- Passphrase sources are external to this spec; provider interface defines how passphrase bytes are obtained.
- Crypto backend selection (builtin vs experimental) does not change the envelope; outputs must be semantically identical.
