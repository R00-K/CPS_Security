import socket
import struct
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000

def recv_exact(sock, length):
    """Receive exactly 'length' bytes."""
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        data += chunk
    return data

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((SERVER_HOST, SERVER_PORT))
    print("[RECEIVER] Connected to sender.")

    # Generate ephemeral key pair
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Send our public key first
    s.sendall(public_key.public_bytes_raw())

    # Receive sender public key
    sender_pub_bytes = recv_exact(s, 32)
    sender_pub = x25519.X25519PublicKey.from_public_bytes(sender_pub_bytes)

    # Derive shared secret
    shared_secret = private_key.exchange(sender_pub)

    # Derive session key
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure data channel"
    ).derive(shared_secret)

    aesgcm = AESGCM(session_key)

    # ---- Receive framed encrypted data ----

    # Receive nonce
    nonce_len = struct.unpack(">I", recv_exact(s, 4))[0]
    nonce = recv_exact(s, nonce_len)

    # Receive ciphertext
    ciphertext_len = struct.unpack(">I", recv_exact(s, 4))[0]
    ciphertext = recv_exact(s, ciphertext_len)

    print("[RECEIVER] Encrypted data received.")

    # Decrypt
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    # Save file
    with open("received_dataset.bin", "wb") as f:
        f.write(plaintext)

    print("[RECEIVER] Dataset decrypted and saved successfully.")

