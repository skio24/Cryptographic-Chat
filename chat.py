#!/usr/bin/env python3
"""
chat.py — a complete, working, end-to-end encrypted chat app in one file.

WHAT THIS IS
------------
Two people run this script on two machines (or two terminals on one
machine) and chat over a real TCP connection. Every message is encrypted
on the sender's side and only decrypted on the receiver's side. A relay
server sits in between and forwards bytes it cannot read.

HOW TO RUN IT
-------------
    Terminal 1 (relay):   python3 chat.py server 5050
    Terminal 2 (Alice):   python3 chat.py client 127.0.0.1 5050
    Terminal 3 (Bob):     python3 chat.py client 127.0.0.1 5050

Type a message and press Enter in either client terminal. Ctrl+C to quit.


THE FOUR-LAYER CRYPTO DESIGN — AND WHY EACH LAYER EXISTS
=========================================================

1. X25519 (Diffie-Hellman on Curve25519)
   Establishes a shared secret between two people who've never met, over
   a channel an attacker can watch. Chosen over RSA because:
     - key generation is essentially free, so a brand-new throwaway
       keypair can be made every session. That's WHY forward secrecy is
       even possible here — nothing long-term-secret ever gets created,
       so there's nothing long-lived for an attacker to later steal.
     - the "encrypt a session key with the peer's RSA public key" pattern
       means whoever holds that RSA private key can decrypt every past
       session if the key is ever compromised — the opposite of what we
       want.
     - it's a small, simple design that sidesteps a long history of
       implementation bugs (timing side channels, invalid-curve attacks)
       that have shown up in RSA and older NIST-curve code. It's why
       Signal, WhatsApp, iMessage, and WireGuard all use it.

2. HKDF-SHA256 (key derivation)
   A raw Diffie-Hellman output should NOT be used directly as an AES key —
   it's a point on a curve, not uniformly random bytes, and reusing one
   secret for everything is poor hygiene anyway. HKDF does two things:
   "extract" whitens the raw secret into something uniformly random, and
   "expand" stamps out several cryptographically-independent keys from
   that one secret by changing a label string. That's used here to split
   one shared secret into TWO separate chain keys — one per direction of
   traffic — so Alice's key material is never mixed with Bob's.

3. The ratchet (HMAC-SHA256, used as a one-way pump)
   This is the piece that gives FORWARD SECRECY. Before every message,
   the current chain key produces (a) a one-time message key and (b) a
   new chain key — then the old chain key is discarded. HMAC cannot be
   run backwards, so if an attacker steals today's chain key, they can
   predict tomorrow's keys but can never reconstruct yesterday's. This is
   the same mechanism as the symmetric half of Signal's Double Ratchet.

4. AES-256-GCM (authenticated encryption)
   Encrypts AND authenticates each message in a single step (an "AEAD"
   cipher). Chosen over, say, AES-CBC + a separate HMAC because:
     - GCM produces ciphertext and a tamper-evident tag together, so
       there's no risk of the classic mistake of forgetting to check the
       MAC before decrypting, or checking it in the wrong order.
     - it's hardware-accelerated on virtually every modern CPU (AES-NI),
       so it stays fast despite doing more work than plain AES.
     - a 256-bit key gives a wide security margin for negligible cost.
   GCM's one hard rule is "never reuse a nonce with the same key." Since
   every message already gets its own one-time key from the ratchet, a
   fixed nonce would technically even be safe here — but this code still
   generates a fresh random 12-byte nonce per message anyway, as cheap
   defense-in-depth in case that assumption is ever broken by a future
   change.


WHAT THIS DOES *NOT* PROTECT AGAINST
=====================================
Worth saying out loud in an interview — naming these shows you understand
the edges of your own design, not just the happy path:

  - Man-in-the-middle at the handshake: there's no signature or identity
    check on the public keys traded in step 1, so someone controlling the
    network at that exact moment could substitute their own key. Signal
    solves this with long-term signed identity keys plus a manual
    "safety number" check between users.
  - Forward-secret, but not a full Double Ratchet: there's no repeated
    fresh DH exchange mixed in as the conversation continues (only the
    initial one), so this doesn't have Signal's "post-compromise
    security" — the ability to recover security again after a total key
    compromise.
  - No persistence: closing a client throws away all key state, by
    design, to keep this demo simple.
"""

import argparse
import hashlib
import hmac
import os
import socket
import struct
import sys
import threading

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# =====================================================================
# PART 1 — CRYPTOGRAPHIC CORE
# =====================================================================

def generate_keypair():
    """
    Make a fresh, random X25519 keypair.
    Called once per session per person — never reused, never saved to
    disk. Throwing this away after the session is what makes forward
    secrecy possible: there's no long-lived secret left for anyone to
    later steal.
    """
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def derive_shared_secret(my_private_key, their_public_key) -> bytes:
    """
    The actual Diffie-Hellman step: my_private_key * their_public_key.
    Both sides compute this and land on the exact same 32 bytes, without
    that value ever crossing the network.
    """
    return my_private_key.exchange(their_public_key)


def hkdf(key_material: bytes, info: bytes, length: int = 32) -> bytes:
    """
    HKDF-SHA256. 'info' is a label that lets one secret produce many
    independent-looking keys — change the label, get a completely
    different (but reproducible) key. Both sides use the same label
    strings, so they derive matching keys independently.
    """
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(key_material)


def derive_root_key(shared_secret: bytes) -> bytes:
    return hkdf(shared_secret, info=b"crypto-chat root key")


def derive_direction_chain_key(root_key: bytes, direction_label: bytes) -> bytes:
    """direction_label is e.g. b'A->B' or b'B->A' — see RatchetState below."""
    return hkdf(root_key, info=direction_label)


def ratchet_step(chain_key: bytes):
    """
    One ratchet step. Returns (message_key, next_chain_key).

    Both outputs come from the SAME chain key, but HMAC with a different
    single-byte tag (0x01 vs 0x02) — this "domain separation" trick means
    knowing message_key tells you nothing about next_chain_key, and vice
    versa. This exact construction is Signal's KDF_CK.

    Why this gives forward secrecy: HMAC is a one-way function. Given
    chain_key_N you can walk FORWARD to chain_key_N+1, N+2, ... but there
    is no computation that walks backward to chain_key_N-1. So stealing
    a chain key exposes the future, never the past.
    """
    message_key = hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
    next_chain_key = hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
    return message_key, next_chain_key


def encrypt(message_key: bytes, counter: int, plaintext: bytes) -> bytes:
    """
    AES-256-GCM encrypt. Returns nonce(12 bytes) || ciphertext+tag, which
    is exactly what gets sent over the network.

    The message counter is passed in as "associated data" (AAD) — it gets
    authenticated but not encrypted. That binds each ciphertext to its
    exact position in the conversation, so a captured message can't later
    be replayed at a different position without decryption failing.
    """
    aesgcm = AESGCM(message_key)
    nonce = os.urandom(12)  # 12 bytes (96 bits) is GCM's recommended nonce size
    aad = struct.pack(">Q", counter)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def decrypt(message_key: bytes, counter: int, blob: bytes) -> bytes:
    """
    Inverse of encrypt(). Raises an exception if the tag doesn't match —
    i.e. if the ciphertext was tampered with, corrupted, or encrypted
    under a different key/counter than claimed. That exception IS the
    tamper detection; there's no separate integrity check needed because
    GCM is authenticated encryption.
    """
    aesgcm = AESGCM(message_key)
    nonce, ciphertext = blob[:12], blob[12:]
    aad = struct.pack(">Q", counter)
    return aesgcm.decrypt(nonce, ciphertext, aad)


class RatchetState:
    """
    Holds both ratchet chains for one side of the conversation.

    Why TWO chains instead of one shared chain? If Alice and Bob shared a
    single ratchet, they'd have to strictly take turns, and any
    simultaneous send would desync their chains. Giving each direction
    its own independent chain (derived from the same root key with
    different labels) means Alice can ratchet-and-send on A->B whenever
    she wants, completely independently of when Bob ratchets-and-sends on
    B->A. Both sides compute both chains identically because they share
    the same root_key and the same two label strings.
    """

    def __init__(self, root_key: bytes, my_role: str):
        if my_role == "A":
            self.send_chain = derive_direction_chain_key(root_key, b"A->B")
            self.recv_chain = derive_direction_chain_key(root_key, b"B->A")
        else:
            self.send_chain = derive_direction_chain_key(root_key, b"B->A")
            self.recv_chain = derive_direction_chain_key(root_key, b"A->B")
        self.send_counter = 0
        self.recv_counter = 0
        self.lock = threading.Lock()

    def next_send_key(self):
        with self.lock:
            msg_key, self.send_chain = ratchet_step(self.send_chain)
            counter = self.send_counter
            self.send_counter += 1
        return msg_key, counter

    def next_recv_key(self):
        with self.lock:
            msg_key, self.recv_chain = ratchet_step(self.recv_chain)
            counter = self.recv_counter
            self.recv_counter += 1
        return msg_key, counter


# =====================================================================
# PART 2 — NETWORK FRAMING
# =====================================================================
# TCP is just a stream of bytes with no built-in concept of "one message".
# So every frame is sent as: 4-byte big-endian length, then that many
# bytes of payload. This is the simplest standard way to carve a byte
# stream back into discrete messages.

def recv_all(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def recv_frame(sock):
    header = recv_all(sock, 4)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    return recv_all(sock, length)


def send_frame(sock, payload: bytes):
    sock.sendall(struct.pack(">I", len(payload)) + payload)


# =====================================================================
# PART 3 — SERVER: a dumb relay that never sees plaintext
# =====================================================================
# Why a relay at all, instead of a direct connection? In the real world
# two chat clients are usually behind NATs/firewalls and can't connect
# straight to each other. A relay server that both sides can reach solves
# that — and because everything it forwards is already ciphertext, the
# server operator (or anyone who hacks the server) still can't read a
# single message. That's the actual meaning of "end-to-end" encryption:
# security doesn't depend on trusting the thing in the middle.

def relay(src, dst, label):
    try:
        while True:
            frame = recv_frame(src)
            if frame is None:
                break
            send_frame(dst, frame)
    except (ConnectionResetError, OSError):
        pass
    finally:
        print(f"[server] {label} disconnected, closing session.")
        for s in (dst, src):
            try:
                s.close()
            except OSError:
                pass


def run_server(port: int):
    HOST = "0.0.0.0"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, port))
        srv.listen(2)
        print(f"[server] Listening on {HOST}:{port} — waiting for 2 clients...")

        conn_a, addr_a = srv.accept()
        print(f"[server] Client A connected from {addr_a}")
        conn_b, addr_b = srv.accept()
        print(f"[server] Client B connected from {addr_b}")

        # Tell each client which role it got, so both sides label their
        # ratchet chains the same way (see RatchetState above).
        send_frame(conn_a, b"ROLE:A")
        send_frame(conn_b, b"ROLE:B")

        t1 = threading.Thread(target=relay, args=(conn_a, conn_b, "A"), daemon=True)
        t2 = threading.Thread(target=relay, args=(conn_b, conn_a, "B"), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        print("[server] Session ended.")


# =====================================================================
# PART 4 — CLIENT: handshake, then send/receive loop
# =====================================================================

def receiver_loop(sock, state: RatchetState):
    """Runs in a background thread so incoming messages can appear at any time,
    even while you're in the middle of typing your own."""
    while True:
        frame = recv_frame(sock)
        if frame is None:
            print("\n[client] Connection closed by peer.")
            os._exit(0)
        msg_key, counter = state.next_recv_key()
        try:
            plaintext = decrypt(msg_key, counter, frame)
            print(f"\rpeer> {plaintext.decode('utf-8', errors='replace')}\nyou> ", end="", flush=True)
        except Exception:
            print(
                f"\r[client] WARNING: message {counter} failed authentication "
                f"(tampering or corruption) — discarded.\nyou> ",
                end="", flush=True,
            )


def run_client(host: str, port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    print(f"[client] Connected to {host}:{port}. Waiting for peer...")

    my_role = recv_frame(sock).decode().split(":")[1]  # "A" or "B"
    print(f"[client] Assigned role: {my_role}")

    # --- The ECDH handshake happens here ---
    # Only the PUBLIC keys ever touch the network. Private keys never leave
    # this process, and are never written to disk.
    my_private, my_public = generate_keypair()
    send_frame(sock, my_public.public_bytes_raw())
    peer_public_bytes = recv_frame(sock)
    peer_public = X25519PublicKey.from_public_bytes(peer_public_bytes)

    shared_secret = derive_shared_secret(my_private, peer_public)
    root_key = derive_root_key(shared_secret)
    state = RatchetState(root_key, my_role)

    print("[client] Secure session established (X25519 + ratcheted AES-256-GCM).")
    print("[client] Type a message and press Enter. Ctrl+C to quit.\n")

    t = threading.Thread(target=receiver_loop, args=(sock, state), daemon=True)
    t.start()

    try:
        while True:
            msg = input("you> ")
            if not msg:
                continue
            msg_key, counter = state.next_send_key()
            blob = encrypt(msg_key, counter, msg.encode("utf-8"))
            send_frame(sock, blob)
    except (KeyboardInterrupt, EOFError):
        print("\n[client] Closing connection.")
        sock.close()


# =====================================================================
# ENTRY POINT
# =====================================================================

def main():
    parser = argparse.ArgumentParser(description="End-to-end encrypted chat (single file).")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    server_parser = subparsers.add_parser("server", help="Run the relay server.")
    server_parser.add_argument("port", type=int, nargs="?", default=5050)

    client_parser = subparsers.add_parser("client", help="Run a chat client.")
    client_parser.add_argument("host")
    client_parser.add_argument("port", type=int, nargs="?", default=5050)

    args = parser.parse_args()

    if args.mode == "server":
        run_server(args.port)
    elif args.mode == "client":
        run_client(args.host, args.port)


if __name__ == "__main__":
    main()
