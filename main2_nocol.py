
"""
Post-quantum multi-authority access-controlled encryption.

ML-KEM-768 + HKDF-SHA256 + AES-256-GCM.

Properties:
- Independent authorities manage user entitlements.
- Each user has an independent ML-KEM key pair.
- Encryption checks the complete AND policy per user.
- Only individually eligible users receive key envelopes.
- Ineligible users cannot decrypt by pooling ML-KEM keys.

NOT a formal CP-ABE construction.
Requires trusted sender-side authorisation and key registry.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


FORMAT = "recipient-ma-mlkem-v1"


def context(policy: list[str], user_id: str) -> bytes:
    """Canonical domain-separated encryption context."""
    return json.dumps(
        [FORMAT, policy, user_id],
        separators=(",", ":"),
    ).encode("utf-8")


def derive_key(secret: bytes, aad: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"recipient-ma-mlkem-wrap-v1|" + aad,
    ).derive(secret)


# --------------------------------------------------
# USER KEYS
# --------------------------------------------------

@dataclass
class User:
    user_id: str
    private_key: MLKEM768PrivateKey = field(
        default_factory=MLKEM768PrivateKey.generate,
        repr=False,
    )

    def public_key(self) -> MLKEM768PublicKey:
        return self.private_key.public_key()


# --------------------------------------------------
# TRUSTED USER-KEY DIRECTORY
# --------------------------------------------------

class UserDirectory:

    def __init__(self):
        self.public_keys: dict[str, MLKEM768PublicKey] = {}

    def register(self, user: User):
        if user.user_id in self.public_keys:
            raise ValueError("Duplicate user identity")

        # Trusted registration is assumed.
        # Real systems must authenticate this binding.
        self.public_keys[user.user_id] = user.public_key()


# --------------------------------------------------
# ATTRIBUTE AUTHORITIES
# --------------------------------------------------

class Authority:

    def __init__(self, name: str):
        self.name = name
        self.entitlements: dict[str, set[str]] = {}

    def grant(self, user_id: str, attribute: str):
        """
        Trusted authority operation.

        Real systems must verify user eligibility.
        """
        self.entitlements.setdefault(user_id, set()).add(attribute)

    def revoke(self, user_id: str, attribute: str):
        self.entitlements.get(user_id, set()).discard(attribute)

    def has_attribute(self, user_id: str, attribute: str) -> bool:
        return attribute in self.entitlements.get(user_id, set())


# --------------------------------------------------
# MULTI-AUTHORITY ACCESS CONTROL
# --------------------------------------------------

class AccessController:

    def __init__(self, authorities: dict[str, Authority]):
        self.authorities = authorities

    def authorised(self, user_id: str, policy: list[str]) -> bool:

        for item in policy:
            authority_name, attribute = item.split(":", 1)

            authority = self.authorities.get(authority_name)

            if authority is None:
                return False

            if not authority.has_attribute(user_id, attribute):
                return False

        return True


def validate_policy(policy: list[str]) -> list[str]:

    if not isinstance(policy, list):
        raise ValueError("Policy must be a list")

    if not 1 <= len(policy) <= 64:
        raise ValueError("Invalid policy length")

    if any(
        not isinstance(a, str)
        or ":" not in a
        or not a.split(":", 1)[0]
        or not a.split(":", 1)[1]
        for a in policy
    ):
        raise ValueError("Invalid authority-qualified attribute")

    if len(policy) != len(set(policy)):
        raise ValueError("Duplicate policy attributes")

    return sorted(policy)


# --------------------------------------------------
# ENCRYPTION
# --------------------------------------------------

def encrypt(
    message: bytes,
    policy: list[str],
    directory: UserDirectory,
    access: AccessController,
) -> dict:

    policy = validate_policy(policy)

    # Find individually authorised recipients.
    recipients = [
        uid
        for uid in sorted(directory.public_keys)
        if access.authorised(uid, policy)
    ]

    if not recipients:
        raise PermissionError("No authorised recipients")

    # One AES-256 key encrypts the message.
    data_key = os.urandom(32)

    message_nonce = os.urandom(12)

    message_aad = context(policy, "")

    encrypted_message = AESGCM(data_key).encrypt(
        message_nonce,
        message,
        message_aad,
    )

    envelopes = {}

    for uid in recipients:

        # ML-KEM encapsulation to the USER'S public key,
        # rather than an attribute-level public key.
        shared_secret, kem_ct = (
            directory.public_keys[uid].encapsulate()
        )

        aad = context(policy, uid)

        wrapping_key = derive_key(shared_secret, aad)

        wrap_nonce = os.urandom(12)

        # Encrypt the data key for this recipient.
        wrapped_key = AESGCM(wrapping_key).encrypt(
            wrap_nonce,
            data_key,
            aad,
        )

        envelopes[uid] = {
            "kem_ciphertext": kem_ct.hex(),
            "nonce": wrap_nonce.hex(),
            "wrapped_key": wrapped_key.hex(),
        }

    return {
        "format": FORMAT,
        "policy": policy,
        "nonce": message_nonce.hex(),
        "ciphertext": encrypted_message.hex(),
        "envelopes": envelopes,
    }


# --------------------------------------------------
# DECRYPTION
# --------------------------------------------------

def decrypt(ciphertext: dict, user: User) -> bytes:

    if ciphertext.get("format") != FORMAT:
        raise ValueError("Incorrect ciphertext format")

    policy = validate_policy(ciphertext["policy"])

    if policy != ciphertext["policy"]:
        raise ValueError("Noncanonical policy")

    uid = user.user_id

    if uid not in ciphertext["envelopes"]:
        raise PermissionError(
            "User is not an authorised recipient"
        )

    envelope = ciphertext["envelopes"][uid]

    kem_ct = bytes.fromhex(envelope["kem_ciphertext"])

    if len(kem_ct) != 1088:
        raise ValueError("Invalid ML-KEM ciphertext")

    # Only the recipient's own private key can recover
    # the encapsulated shared secret.
    shared_secret = user.private_key.decapsulate(kem_ct)

    aad = context(policy, uid)

    wrapping_key = derive_key(shared_secret, aad)

    wrap_nonce = bytes.fromhex(envelope["nonce"])

    if len(wrap_nonce) != 12:
        raise ValueError("Invalid wrapping nonce")

    data_key = AESGCM(wrapping_key).decrypt(
        wrap_nonce,
        bytes.fromhex(envelope["wrapped_key"]),
        aad,
    )

    if len(data_key) != 32:
        raise ValueError("Invalid data key")

    message_nonce = bytes.fromhex(ciphertext["nonce"])

    if len(message_nonce) != 12:
        raise ValueError("Invalid message nonce")

    return AESGCM(data_key).decrypt(
        message_nonce,
        bytes.fromhex(ciphertext["ciphertext"]),
        context(policy, ""),
    )


# --------------------------------------------------
# EXAMPLE: COLLUSION TEST
# --------------------------------------------------

if __name__ == "__main__":

    university = Authority("University")
    company = Authority("Company")

    access = AccessController({
        "University": university,
        "Company": company,
    })

    # Four users, four independent ML-KEM key pairs.
    alice = User("Alice")
    bob = User("Bob")
    carol = User("Carol")
    dave = User("Dave")

    directory = UserDirectory()

    for user in (alice, bob, carol, dave):
        directory.register(user)

    # Alice has one attribute.
    university.grant("Alice", "Researcher")

    # Bob has another attribute.
    company.grant("Bob", "Finance")

    # Carol has another attribute.
    company.grant("Carol", "Manager")

    # Dave has all three attributes.
    university.grant("Dave", "Researcher")
    company.grant("Dave", "Finance")
    company.grant("Dave", "Manager")

    policy = [
        "University:Researcher",
        "Company:Finance",
        "Company:Manager",
    ]

    msg = b"Hello"

    encrypted = encrypt(
        msg,
        policy,
        directory,
        access,
    )

    print("Policy:", encrypted["policy"])

    print(
        "Authorised recipients:",
        list(encrypted["envelopes"])
    )

    # Dave possesses all required attributes.
    recovered = decrypt(encrypted, dave)

    print("Dave decrypts:", recovered)

    assert recovered == msg

    # Each individually ineligible user fails.
    for user in (alice, bob, carol):

        try:
            decrypt(encrypted, user)
            raise AssertionError("Unexpected access")

        except PermissionError:
            print(user.user_id, "access denied")

    # All three users have independent private keys.
    # None has an envelope in this ciphertext.
    colluding_users = (alice, bob, carol)

    print(
        "Colluders eligible:",
        any(
            u.user_id in encrypted["envelopes"]
            for u in colluding_users
        )
    )

    print("Collusion test complete")
