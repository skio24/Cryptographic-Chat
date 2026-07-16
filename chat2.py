import tkinter as tk
from tkinter import scrolledtext

# Cryptographic libraries
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey
)

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# CRYPTOGRAPHY
# ============================================================

# Generate a private key and its matching public key
def generate_keypair():

    private = X25519PrivateKey.generate()

    return private, private.public_key()


# Create a shared secret using X25519 key exchange
def derive_shared_secret(private, public):

    return private.exchange(public)


# Use HKDF to derive a new cryptographic key
def hkdf(data, info):

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info
    ).derive(data)


# Create the initial root key
def derive_root_key(secret):

    return hkdf(
        secret,
        b"crypto-chat-root"
    )


# Create separate keys for Alice → Bob and Bob → Alice
def derive_chain_key(root, label):

    return hkdf(
        root,
        label
    )


# Create a message key and move to the next chain key
def ratchet_step(chain_key):

    # Key used to encrypt the current message
    message_key = hmac.new(
        chain_key,
        b"\x01",
        hashlib.sha256
    ).digest()

    # New key for the next message
    next_chain_key = hmac.new(
        chain_key,
        b"\x02",
        hashlib.sha256
    ).digest()

    return message_key, next_chain_key


# Encrypt a message using AES-GCM
def encrypt(key, message):

    # Random nonce for AES-GCM
    nonce = os.urandom(12)

    # Encrypt the message
    ciphertext = AESGCM(key).encrypt(
        nonce,
        message.encode(),
        None
    )

    # Store nonce together with ciphertext
    return nonce + ciphertext


# Decrypt an encrypted message
def decrypt(key, data):

    # Extract the nonce
    nonce = data[:12]

    # Extract the encrypted data
    ciphertext = data[12:]

    # Decrypt and return the message
    return AESGCM(key).decrypt(
        nonce,
        ciphertext,
        None
    ).decode()


# ============================================================
# RATCHET STATE
# ============================================================

# Stores the encryption state for one chat participant
class RatchetState:

    def __init__(self, root_key, role):

        # Alice uses A -> B for sending
        # Bob uses B -> A for sending
        if role == "A":

            self.send_chain = derive_chain_key(
                root_key,
                b"A->B"
            )

            self.recv_chain = derive_chain_key(
                root_key,
                b"B->A"
            )

        else:

            self.send_chain = derive_chain_key(
                root_key,
                b"B->A"
            )

            self.recv_chain = derive_chain_key(
                root_key,
                b"A->B"
            )

    # Get the key for the next outgoing message
    def send_key(self):

        key, self.send_chain = ratchet_step(
            self.send_chain
        )

        return key

    # Get the key for the next incoming message
    def receive_key(self):

        key, self.recv_chain = ratchet_step(
            self.recv_chain
        )

        return key


# ============================================================
# NORMAL CHAT
# ============================================================

# Represents a normal secure conversation
class NormalChat:

    def __init__(self):

        # Generate Alice's keys
        alice_private, alice_public = generate_keypair()

        # Generate Bob's keys
        bob_private, bob_public = generate_keypair()

        # Alice creates a shared secret with Bob
        alice_secret = derive_shared_secret(
            alice_private,
            bob_public
        )

        # Bob creates the same shared secret with Alice
        bob_secret = derive_shared_secret(
            bob_private,
            alice_public
        )

        # Create Alice's encryption state
        self.alice = RatchetState(
            derive_root_key(alice_secret),
            "A"
        )

        # Create Bob's encryption state
        self.bob = RatchetState(
            derive_root_key(bob_secret),
            "B"
        )

    # Alice sends a message to Bob
    def alice_to_bob(self, message):

        # Alice encrypts the message
        encrypted = encrypt(
            self.alice.send_key(),
            message
        )

        # Bob decrypts the message
        return decrypt(
            self.bob.receive_key(),
            encrypted
        )

    # Bob sends a message to Alice
    def bob_to_alice(self, message):

        # Bob encrypts the message
        encrypted = encrypt(
            self.bob.send_key(),
            message
        )

        # Alice decrypts the message
        return decrypt(
            self.alice.receive_key(),
            encrypted
        )


# ============================================================
# MITM CHAT
# ============================================================

# Represents the MITM attack
class MITMChat:

    def __init__(self):

        # --------------------------------------------------------
        # ALICE <-> MITM
        # --------------------------------------------------------

        # Alice's key pair
        alice_private, alice_public = generate_keypair()

        # MITM creates a fake key pair for Alice
        mitm_private_a, mitm_public_a = generate_keypair()

        # Alice thinks she is creating a secret with Bob
        alice_secret = derive_shared_secret(
            alice_private,
            mitm_public_a
        )

        # MITM creates the same secret with Alice
        mitm_a_secret = derive_shared_secret(
            mitm_private_a,
            alice_public
        )

        # --------------------------------------------------------
        # MITM <-> BOB
        # --------------------------------------------------------

        # Bob's key pair
        bob_private, bob_public = generate_keypair()

        # MITM creates another fake key pair for Bob
        mitm_private_b, mitm_public_b = generate_keypair()

        # Bob creates a secret with the MITM
        bob_secret = derive_shared_secret(
            bob_private,
            mitm_public_b
        )

        # MITM creates the same secret with Bob
        mitm_b_secret = derive_shared_secret(
            mitm_private_b,
            bob_public
        )

        # Alice's encryption state
        self.alice = RatchetState(
            derive_root_key(alice_secret),
            "A"
        )

        # MITM's connection with Alice
        self.mitm_from_alice = RatchetState(
            derive_root_key(mitm_a_secret),
            "B"
        )

        # MITM's connection with Bob
        self.mitm_to_bob = RatchetState(
            derive_root_key(mitm_b_secret),
            "A"
        )

        # Bob's encryption state
        self.bob = RatchetState(
            derive_root_key(bob_secret),
            "B"
        )

    # Alice sends a message to Bob through the MITM
    def alice_to_bob(self, message):

        # Alice encrypts the message
        encrypted = encrypt(
            self.alice.send_key(),
            message
        )

        # MITM decrypts the message
        intercepted = decrypt(
            self.mitm_from_alice.receive_key(),
            encrypted
        )

        # --------------------------------------------------------
        # ATTACKER MODIFIES THE MESSAGE
        # --------------------------------------------------------

        modified = intercepted

        # Example message modification
        if "5 PM" in modified:

            modified = modified.replace(
                "5 PM",
                "8 PM"
            )

        # MITM encrypts the modified message again
        encrypted = encrypt(
            self.mitm_to_bob.send_key(),
            modified
        )

        # Bob decrypts the modified message
        final_message = decrypt(
            self.bob.receive_key(),
            encrypted
        )

        return intercepted, modified, final_message

    # Bob sends a message to Alice
    def bob_to_alice(self, message):

        # Bob encrypts the message
        encrypted = encrypt(
            self.bob.send_key(),
            message
        )

        # Alice decrypts the message
        return decrypt(
            self.alice.receive_key(),
            encrypted
        )


# ============================================================
# GUI HELPER FUNCTIONS
# ============================================================

# Background colours used by the application
BG = "#111827"
BOX = "#1f2937"
WHITE = "white"


# Create a separate window for Alice, Bob, or the MITM
def create_chat_window(title):

    window = tk.Toplevel()

    window.title(title)

    window.geometry(
        "400x450"
    )

    window.configure(
        bg=BG
    )

    return window


# Add a message to a chat window
def add_message(box, sender, message):

    # Enable editing temporarily
    box.config(
        state="normal"
    )

    # Add the message
    box.insert(
        tk.END,
        f"{sender}: {message}\n\n"
    )

    # Disable editing again
    box.config(
        state="disabled"
    )

    # Automatically scroll to the latest message
    box.see(
        tk.END
    )


# ============================================================
# MAIN APPLICATION
# ============================================================

class App:

    def __init__(self, root):

        self.root = root

        self.root.title(
            "Cryptographic Chat Demo"
        )

        self.root.geometry(
            "400x250"
        )

        self.root.configure(
            bg=BG
        )

        # Create normal chat
        self.normal_chat = NormalChat()

        # MITM will be created only when the attack starts
        self.mitm_chat = None

        # Store the separate windows
        self.alice_window = None
        self.bob_window = None
        self.mitm_window = None

        # Show the main controller
        self.build_controller()

    # ========================================================
    # MAIN CONTROLLER
    # ========================================================

    def build_controller(self):

        tk.Label(
            self.root,
            text="CRYPTOGRAPHIC CHAT",
            font=("Arial", 20, "bold"),
            fg=WHITE,
            bg=BG
        ).pack(
            pady=20
        )

        tk.Label(
            self.root,
            text="STEP 1: NORMAL CHAT",
            font=("Arial", 13, "bold"),
            fg="#22c55e",
            bg=BG
        ).pack()

        # Open Alice and Bob windows
        tk.Button(
            self.root,
            text="OPEN ALICE & BOB",
            command=self.open_normal_chat,
            padx=20,
            pady=8
        ).pack(
            pady=15
        )

        # Start the MITM demonstration
        tk.Button(
            self.root,
            text="START MITM ATTACK",
            command=self.start_mitm,
            bg="#dc2626",
            fg=WHITE,
            padx=20,
            pady=8
        ).pack()

    # ========================================================
    # STEP 1: NORMAL CHAT
    # ========================================================

    def open_normal_chat(self):

        # Prevent opening duplicate windows
        if self.alice_window:

            return

        # Create Alice's window
        self.alice_window = create_chat_window(
            "Alice"
        )

        # Create Bob's window
        self.bob_window = create_chat_window(
            "Bob"
        )

        # Build Alice's GUI
        self.build_alice_gui(
            self.alice_window,
            normal=True
        )

        # Build Bob's GUI
        self.build_bob_gui(
            self.bob_window,
            normal=True
        )

    # Create Alice's interface
    def build_alice_gui(self, window, normal):

        tk.Label(
            window,
            text="ALICE",
            font=("Arial", 20, "bold"),
            fg="#60a5fa",
            bg=BG
        ).pack(
            pady=10
        )

        # Alice's chat area
        box = scrolledtext.ScrolledText(
            window,
            height=15,
            bg=BOX,
            fg=WHITE,
            state="disabled"
        )

        box.pack(
            padx=10,
            pady=10,
            fill=tk.BOTH,
            expand=True
        )

        # Alice's message input
        entry = tk.Entry(
            window
        )

        entry.pack(
            side=tk.LEFT,
            padx=10,
            pady=10,
            fill=tk.X,
            expand=True
        )

        # Send Alice's message
        def send():

            message = entry.get().strip()

            if not message:

                return

            # Normal communication
            if normal:

                received = self.normal_chat.alice_to_bob(
                    message
                )

                add_message(
                    box,
                    "Alice",
                    message
                )

                add_message(
                    self.bob_box,
                    "Alice",
                    received
                )

            # MITM communication
            else:

                intercepted, modified, final = (
                    self.mitm_chat.alice_to_bob(
                        message
                    )
                )

                add_message(
                    box,
                    "Alice",
                    message
                )

                add_message(
                    self.mitm_box,
                    "INTERCEPTED",
                    intercepted
                )

                add_message(
                    self.mitm_box,
                    "MODIFIED",
                    modified
                )

                add_message(
                    self.bob_box,
                    "Alice",
                    final
                )

            # Clear the input box
            entry.delete(
                0,
                tk.END
            )

        tk.Button(
            window,
            text="SEND",
            command=send
        ).pack(
            side=tk.RIGHT,
            padx=10,
            pady=10
        )

        # Save Alice's widgets
        window.entry = entry

        window.box = box

    # Create Bob's interface
    def build_bob_gui(self, window, normal):

        tk.Label(
            window,
            text="BOB",
            font=("Arial", 20, "bold"),
            fg="#22c55e",
            bg=BG
        ).pack(
            pady=10
        )

        # Bob's chat area
        box = scrolledtext.ScrolledText(
            window,
            height=15,
            bg=BOX,
            fg=WHITE,
            state="disabled"
        )

        box.pack(
            padx=10,
            pady=10,
            fill=tk.BOTH,
            expand=True
        )

        # Bob's message input
        entry = tk.Entry(
            window
        )

        entry.pack(
            side=tk.LEFT,
            padx=10,
            pady=10,
            fill=tk.X,
            expand=True
        )

        # Send Bob's message
        def send():

            message = entry.get().strip()

            if not message:

                return

            # Normal communication
            if normal:

                received = self.normal_chat.bob_to_alice(
                    message
                )

                add_message(
                    box,
                    "Bob",
                    message
                )

                add_message(
                    self.alice_window.box,
                    "Bob",
                    received
                )

            # MITM communication
            else:

                received = self.mitm_chat.bob_to_alice(
                    message
                )

                add_message(
                    box,
                    "Bob",
                    message
                )

                add_message(
                    self.alice_window.box,
                    "Bob",
                    received
                )

            # Clear the input box
            entry.delete(
                0,
                tk.END
            )

        tk.Button(
            window,
            text="SEND",
            command=send
        ).pack(
            side=tk.RIGHT,
            padx=10,
            pady=10
        )

        # Save Bob's widgets
        window.entry = entry

        window.box = box

        # Used to display messages from Alice
        self.bob_box = box

    # ========================================================
    # STEP 2: MITM ATTACK
    # ========================================================

    def start_mitm(self):

        # Open Alice and Bob if not already open
        if not self.alice_window:

            self.open_normal_chat()

        # Create the MITM session
        self.mitm_chat = MITMChat()

        # Create the MITM window
        self.mitm_window = create_chat_window(
            "MITM ATTACKER"
        )

        self.mitm_window.geometry(
            "500x450"
        )

        tk.Label(
            self.mitm_window,
            text="⚠ MITM ATTACK ACTIVE",
            font=("Arial", 20, "bold"),
            fg="#ef4444",
            bg=BG
        ).pack(
            pady=10
        )

        # MITM activity log
        self.mitm_box = scrolledtext.ScrolledText(
            self.mitm_window,
            height=20,
            bg=BOX,
            fg=WHITE,
            state="disabled"
        )

        self.mitm_box.pack(
            padx=10,
            pady=10,
            fill=tk.BOTH,
            expand=True
        )

        # Display the attack path
        add_message(
            self.mitm_box,
            "SYSTEM",
            "Alice ↔ MITM ↔ Bob"
        )

        add_message(
            self.mitm_box,
            "SYSTEM",
            "Attack is active."
        )

        # Rebuild Alice and Bob GUIs for MITM mode
        self.build_alice_gui(
            self.alice_window,
            normal=False
        )

        self.build_bob_gui(
            self.bob_window,
            normal=False
        )


# ============================================================
# START APPLICATION
# ============================================================

root = tk.Tk()

app = App(root)

root.mainloop()
