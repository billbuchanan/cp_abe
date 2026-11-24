
"""
Educational post-quantum multi-authority AND-policy encryption.

Uses:
    ML-KEM-768       - Post-quantum key encapsulation (FIPS 203)
    HKDF-SHA256      - Derive attribute share-wrapping keys
    AES-256-GCM      - Authenticated encryption
    XOR secret shares - Require every policy attribute

This is NOT a collusion-resistant MA-CP-ABE construction.

Requires cryptography >= 47.0.0.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


FORMAT = "ma-attribute-ml-kem-768-demo-v1"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(txt: str) -> bytes:
    return base64.b64decode(txt, validate=True)


def _xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("XOR inputs must have equal lengths")
    return bytes(x ^ y for x, y in zip(a, b))


def _policy_aad(policy: list[str]) -> bytes:
    """Canonical representation of the encryption policy."""
    return json.dumps(
        [FORMAT, policy],
        separators=(",", ":"),
        ensure_ascii=True
    ).encode("ascii")


def _share_aad(policy: list[str], attribute: str) -> bytes:
    """Bind a wrapped share to its attribute and complete policy."""
    return _policy_aad(policy) + b"|" + attribute.encode("utf-8")


def _wrap_key(shared: bytes, context: bytes) -> bytes:
    """Derive an AES-256 wrapping key from the ML-KEM shared secret."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ma-mlkem-attribute-v1|" + context,
    ).derive(shared)


# ---------------------------------------------------------
# ATTRIBUTE AUTHORITY
# ---------------------------------------------------------

@dataclass
class Authority:
    """Each authority controls its own attribute key pairs."""

    name: str

    def __post_init__(self):
        self._private: dict[str, MLKEM768PrivateKey] = {}

    def add_attribute(self, attribute: str) -> None:
        if attribute in self._private:
            raise ValueError("Attribute already exists")

        # Generate an ML-KEM-768 key pair.
        self._private[attribute] = MLKEM768PrivateKey.generate()

    def public_keys(self) -> dict[str, MLKEM768PublicKey]:
        return {
            f"{self.name}:{name}": sk.public_key()
            for name, sk in self._private.items()
        }

    def issue_key(self, attribute: str) -> MLKEM768PrivateKey:
        """
        Educational example only.

        Real systems must authenticate users and verify
        eligibility before issuing attribute credentials.
        """
        return self._private[attribute]


# ---------------------------------------------------------
# ENCRYPTION
# ---------------------------------------------------------

def encrypt(
    message: bytes,
    policy: list[str],
    public_keys: Mapping[str, MLKEM768PublicKey],
) -> dict:
    """
    Encrypt for an AND policy.

    Every attribute in the policy is required for decryption.
    """

    if not policy or len(policy) != len(set(policy)):
        raise ValueError("Policy must be nonempty without duplicates")

    if any(a not in public_keys for a in policy):
        raise ValueError("Missing public key for required attribute")

    policy = sorted(policy)

    # Generate a random AES-256 data-encryption key.
    data_key = os.urandom(32)

    # Encrypt the original message.
    aad = _policy_aad(policy)
    nonce = os.urandom(12)

    ciphertext = AESGCM(data_key).encrypt(
        nonce, message, aad
    )

    output = {
        "format": FORMAT,
        "policy": policy,
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
        "wrapped_shares": {},
    }

    # Split the data key into XOR shares.
    previous = bytes(32)

    for index, name in enumerate(policy):

        if index < len(policy) - 1:
            share = os.urandom(32)
        else:
            share = _xor(data_key, previous)

        previous = _xor(previous, share)

        # ML-KEM ENCAPSULATION
        #
        # The recipient's public key creates:
        #   shared_secret : 32 bytes
        #   kem_ct        : 1088 bytes
        #
        shared_secret, kem_ct = public_keys[name].encapsulate()

        # Derive an AES-256 key for the attribute share.
        share_aad = _share_aad(policy, name)

        wrapping_key = _wrap_key(
            shared_secret,
            share_aad
        )

        # Encrypt the attribute share.
        share_nonce = os.urandom(12)

        wrapped_share = AESGCM(wrapping_key).encrypt(
            share_nonce,
            share,
            share_aad
        )

        output["wrapped_shares"][name] = {
            "kem_ciphertext": _b64(kem_ct),
            "nonce": _b64(share_nonce),
            "payload": _b64(wrapped_share),
        }

    return output


# ---------------------------------------------------------
# DECRYPTION
# ---------------------------------------------------------

def decrypt(
    ciphertext: dict,
    private_keys: Mapping[str, MLKEM768PrivateKey],
) -> bytes:
    """
    Recover the plaintext when all required private
    attribute keys are available.
    """

    if ciphertext.get("format") != FORMAT:
        raise ValueError("Unknown ciphertext format")

    policy = ciphertext["policy"]

    if (
        not isinstance(policy, list)
        or not policy
        or any(not isinstance(a, str) for a in policy)
        or len(policy) != len(set(policy))
        or sorted(policy) != policy
    ):
        raise ValueError("Invalid policy")

    if any(name not in private_keys for name in policy):
        raise PermissionError("Required attribute key missing")

    if set(ciphertext["wrapped_shares"]) != set(policy):
        raise ValueError("Invalid wrapped share collection")

    # Reconstruct the AES-256 data key.
    data_key = bytes(32)

    for name in policy:

        item = ciphertext["wrapped_shares"][name]

        # Recover the ML-KEM ciphertext.
        kem_ct = _unb64(item["kem_ciphertext"])

        # ML-KEM DECAPSULATION
        #
        # Recovers the same 32-byte shared secret
        # created during encapsulation.
        #
        shared_secret = private_keys[name].decapsulate(
            kem_ct
        )

        share_aad = _share_aad(policy, name)

        # Recreate the wrapping key.
        wrapping_key = _wrap_key(
            shared_secret,
            share_aad
        )

        # Decrypt the attribute share.
        share = AESGCM(wrapping_key).decrypt(
            _unb64(item["nonce"]),
            _unb64(item["payload"]),
            share_aad
        )

        if len(share) != 32:
            raise ValueError("Invalid share length")

        data_key = _xor(data_key, share)

    # Decrypt the original message.
    aad = _policy_aad(policy)

    return AESGCM(data_key).decrypt(
        _unb64(ciphertext["nonce"]),
        _unb64(ciphertext["ciphertext"]),
        aad
    )


# ---------------------------------------------------------
# EXAMPLE
# ---------------------------------------------------------

if __name__ == "__main__":

    # Create two independent attribute authorities.
    aa1 = Authority("University")
    aa2 = Authority("Company")

    # Assign attributes to each authority.
    aa1.add_attribute("Researcher")
    aa1.add_attribute("Professor")

    aa2.add_attribute("Finance")
    aa2.add_attribute("Manager")

    # Publish the attribute public keys.
    public_keys = {
        **aa1.public_keys(),
        **aa2.public_keys(),
    }

    # AND access policy:
    # Researcher AND Finance AND Manager.
    policy = [
        "University:Researcher",
        "Company:Finance",
        "Company:Manager",
    ]

    msg = "Hello"
    print("Original message:", msg)

    # Encrypt.
    encrypted = encrypt(
        msg.encode("utf-8"),
        policy,
        public_keys
    )

    print("\nPolicy:", encrypted["policy"])
    print("ML-KEM ciphertext sizes:")

    for name, item in encrypted["wrapped_shares"].items():
        print(name, len(_unb64(item["kem_ciphertext"])), "bytes")

    # Issue the required private keys.
    user_keys = {
        "University:Researcher":
            aa1.issue_key("Researcher"),

        "Company:Finance":
            aa2.issue_key("Finance"),

        "Company:Manager":
            aa2.issue_key("Manager"),
    }

    # Decrypt.
    recovered = decrypt(encrypted, user_keys)

    print("\nDecrypted message:", recovered.decode("utf-8"))

    # Verify correctness.
    assert recovered == msg.encode("utf-8")

    # Check missing-attribute behaviour.
    incomplete_keys = {
        "University:Researcher":
            aa1.issue_key("Researcher"),

        "Company:Finance":
            aa2.issue_key("Finance"),
    }

    try:
        decrypt(encrypted, incomplete_keys)
        raise AssertionError("Unexpected decryption success")
    except PermissionError:
        print("Missing attribute: access denied")

    # Optional: view the JSON ciphertext.
    print("\nCiphertext JSON:")
    print(json.dumps(encrypted, indent=2))
