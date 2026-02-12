SECURE DATA TRANSFER ARCHITECTURE

OVERVIEW

This system implements a secure file transfer protocol over TCP using
modern cryptography. It establishes a secure session using X25519
(Elliptic Curve Diffie-Hellman), derives a symmetric session key using
HKDF, and encrypts data using AES-256-GCM.

LAYERED ARCHITECTURE

1.  TRANSPORT LAYER (TCP)

    -   Provides reliable, ordered byte stream.
    -   No encryption at this level.
    -   Receiver connects to sender (server).
    -   All security is implemented above TCP.

2.  SESSION ESTABLISHMENT (X25519 ECDH)

    -   Both sides generate ephemeral key pairs.
    -   Each side sends its public key.
    -   Shared secret is derived locally using private key × other
        public key.
    -   Shared secret is never transmitted.
    -   Provides Perfect Forward Secrecy.

3.  KEY DERIVATION (HKDF-SHA256)

    -   Raw shared secret is passed into HKDF.
    -   HKDF extracts and expands secure key material.
    -   Produces a 32-byte session key (AES-256).
    -   Both sides independently derive identical session keys.

4.  SECURE DATA ENCRYPTION (AES-256-GCM)

    -   Session key is used to initialize AES-GCM engine.
    -   Sender generates 12-byte random nonce.
    -   Dataset is encrypted.
    -   AES-GCM produces ciphertext and authentication tag.
    -   Provides:
        -   Confidentiality
        -   Integrity
        -   Authentication (tamper detection)

5.  APPLICATION FRAMING (STRUCTURED PROTOCOL) Since TCP is stream-based,
    framing is added:

        [32 bytes] Receiver public key
        [32 bytes] Sender public key
        [4 bytes]  Nonce length
        [Nonce]
        [4 bytes]  Ciphertext length
        [Ciphertext]

    This allows the receiver to parse data correctly even if TCP splits
    packets.

MESSAGE FLOW

Receiver (Client) Sender (Server)

Generate key pair Connect to server Send public key ———————> Generate
key pair Receive public key Send public key <——————— Receive public key

Derive shared secret HKDF -> Session key

                                      Derive shared secret
                                      HKDF -> Session key

                                      Encrypt dataset (AES-GCM)
                                      Send framed encrypted data  ---------->

Receive encrypted data Decrypt using session key Save dataset

SECURITY PROPERTIES ACHIEVED

-   Confidentiality (AES-256-GCM)
-   Integrity (Authentication Tag)
-   Perfect Forward Secrecy (Ephemeral X25519)
-   Strong Key Derivation (HKDF-SHA256)
-   Structured message framing over TCP

LIMITATIONS

-   No identity authentication (vulnerable to MITM attack).
-   Message size is visible.
-   No replay protection.
-   No certificate validation.

CONCLUSION

This architecture implements a custom secure session protocol over TCP
using: X25519 for key exchange HKDF-SHA256 for key derivation
AES-256-GCM for authenticated encryption It closely resembles the core
structure of TLS 1.3 but without certificate-based authentication.
