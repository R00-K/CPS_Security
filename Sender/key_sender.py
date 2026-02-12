import os
import socket
import struct
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "0.0.0.0"
PORT = 5000

# Create server socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen(1)
    print("[SENDER] Waiting for receiver to connect...")

    conn, addr = server.accept()
    with conn:
        print(f"[SENDER] Connected to {addr}")

        # Generate ephemeral key
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Receive receiver's public key first
        receiver_pub_bytes = conn.recv(32)
        receiver_pub = x25519.X25519PublicKey.from_public_bytes(receiver_pub_bytes)

        # Send sender public key
        conn.sendall(public_key.public_bytes_raw())

        # Derive shared secret
        shared_secret = private_key.exchange(receiver_pub)

        # Derive session key
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"secure data channel"
        ).derive(shared_secret)

        aesgcm = AESGCM(session_key)

        # Read dataset
        with open("dataset.bin", "rb") as f:
            data = f.read()

        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        # Send framed encrypted data
        conn.sendall(struct.pack(">I", len(nonce)))
        conn.sendall(nonce)
        conn.sendall(struct.pack(">I", len(ciphertext)))
        conn.sendall(ciphertext)

        print("[SENDER] Secure dataset sent.")

print("[SENDER] Transfer complete.")

