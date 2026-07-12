# chat.py — End-to-End Encrypted Chat (Cryptographic Chat Application)

A working, real-socket, end-to-end encrypted chat app in one Python file.
Two people can run this and talk over a genuine TCP connection, with a
relay server in between that can never read a single message.

Built as a cybersecurity internship portfolio piece to demonstrate
practical understanding of key exchange, key derivation, forward secrecy,
and authenticated encryption — not just "import a crypto library and call
it secure."
**Internship ID:** `CITS6344`

## Requirements

```bash
pip install cryptography
```

Python 3.8+ recommended.

## How to run it

Open three terminals (or three machines on the same network):

```bash
# Terminal 1 — the relay server
python3 chat.py server 5050

# Terminal 2 — Alice
python3 chat.py client 127.0.0.1 5050

# Terminal 3 — Bob
python3 chat.py client 127.0.0.1 5050
```

Type a message and press Enter in either client. It appears, decrypted,
in the other. Ctrl+C to quit. To run across two real machines, replace
`127.0.0.1` with the server machine's actual IP address and make sure
port 5050 is reachable.

## The crypto design, in one paragraph

Each client generates a fresh, throwaway X25519 keypair every session and
performs a Diffie-Hellman exchange to get a shared secret. That secret is
run through HKDF-SHA256 to derive a root key, which is split into two
independent chain keys — one per direction of traffic. Before every
message, the sender's chain key is put through an HMAC-SHA256 ratchet
step that produces a one-time message key and a new chain key, and the
old one is discarded. Each message is then sealed with AES-256-GCM using
that one-time key, a random nonce, and the message's position (counter)
as authenticated associated data.

## Why each piece was chosen

| Layer | Choice | Why |
|---|---|---|
| Key exchange | X25519 (ECDH) | Key generation is nearly free, so a new throwaway keypair can be made every session and discarded after — that's what makes forward secrecy possible. RSA's usual pattern (encrypt a session key with a long-term public key) means a single future key compromise unlocks every past session; X25519 avoids that by design. |
| Key derivation | HKDF-SHA256 | A raw ECDH output isn't uniform random bytes and shouldn't be used directly as an AES key. HKDF whitens it and lets multiple independent keys be derived from one secret via different labels — used here to split traffic into two separate directional chains. |
| Forward secrecy | HMAC-SHA256 ratchet | HMAC only runs forward, never backward. Each step produces a message key and a new chain key from the old one, which is then thrown away — so stealing today's chain key never exposes yesterday's messages. Same mechanism as the symmetric half of Signal's Double Ratchet. |
| Encryption | AES-256-GCM | An AEAD cipher — encrypts and authenticates in one step, so there's no risk of the classic bug of decrypting before verifying a MAC. Hardware-accelerated (AES-NI) on virtually all modern CPUs, so the extra integrity guarantee is nearly free. |
| Nonce | Random 12 bytes per message | GCM's one hard rule is "never reuse a nonce under the same key." Since every message already gets a unique one-time key from the ratchet, a fixed nonce would technically be safe here too — but a random one is used anyway as cheap defense-in-depth. |
| Anti-replay | Counter in AAD | The message counter is authenticated (but not encrypted) alongside the ciphertext, binding it to its exact position in the conversation so a captured message can't be replayed elsewhere without decryption failing. |
| Transport | Length-prefixed TCP frames | TCP is just a byte stream with no message boundaries, so a 4-byte length prefix is the simplest standard way to split it back into discrete messages. |
| Server | Dumb relay | The server only ever forwards ciphertext between two connected clients — it cannot decrypt anything. That's the actual meaning of "end-to-end": security doesn't depend on trusting whatever's in the middle. |

## What this does *not* protect against

Worth stating upfront in an interview — naming these shows you understand
the edges of your own design, not just the happy path:

- **No identity authentication at handshake.** The public keys traded in
  step 1 aren't signed or verified, so someone controlling the network at
  that exact moment could substitute their own key (a classic
  man-in-the-middle). Signal solves this with long-term signed identity
  keys plus a manual "safety number" check between users — a natural next
  feature to add (Ed25519 signing keys + an out-of-band fingerprint
  check).
- **Forward-secret, but not a full Double Ratchet.** There's no repeated
  fresh DH exchange mixed in as the conversation continues (only the
  initial one), so this doesn't have Signal's "post-compromise security"
  — the ability to recover security again after a total key compromise.
- **No persistence.** Closing a client discards all key state, by design,
  to keep this a self-contained demo rather than a production messenger.
- **Metadata is still visible to the server** — message timing and sizes,
  even though content is not.

## Project structure

This app is intentionally kept to a single file (`chat.py`) so it's easy
to hand to someone and easy to read top to bottom. It contains, in order:

1. **Cryptographic core** — key generation, HKDF, the ratchet, AES-GCM
   encrypt/decrypt, and the `RatchetState` class that tracks both
   directional chains for one side of the conversation.
2. **Network framing** — length-prefixed send/receive helpers over TCP.
3. **Server** — the relay loop.
4. **Client** — the handshake, then the send/receive loop.
5. **CLI entry point** — `argparse`-based dispatch between `server` and
   `client` modes.
