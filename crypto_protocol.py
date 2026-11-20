"""
Educational textbook RSA blind-signature operations.

This is intentionally a learning implementation. It is NOT RFC 9474 and
must not be used to protect real money, credentials, identity, or production
systems. Production deployments should use a reviewed RFC 9474 implementation.
"""
import hashlib
import math

DOMAIN = b"BlindToken-v1:"


def message_integer(message: bytes) -> int:
    digest = hashlib.sha256(DOMAIN + message).digest()
    return int.from_bytes(digest, "big")


def fixed_length_bytes(value: int, length: int) -> bytes:
    return value.to_bytes(length, byteorder="big")


def blind_sign(blinded_message: bytes, private_key) -> bytes:
    numbers = private_key.private_numbers()
    public_numbers = numbers.public_numbers
    n, d = public_numbers.n, numbers.d
    k = (n.bit_length() + 7) // 8

    if len(blinded_message) != k:
        raise ValueError(f"Blinded message must be exactly {k} bytes.")

    blinded_integer = int.from_bytes(blinded_message, "big")
    if not 1 <= blinded_integer < n:
        raise ValueError("Blinded message is outside the RSA modulus.")

    signature_integer = pow(blinded_integer, d, n)
    return fixed_length_bytes(signature_integer, k)


def verify_signature(message: bytes, signature: bytes, public_key) -> bool:
    numbers = public_key.public_numbers()
    n, e = numbers.n, numbers.e
    k = (n.bit_length() + 7) // 8

    if len(signature) != k:
        return False

    signature_integer = int.from_bytes(signature, "big")
    if not 1 <= signature_integer < n:
        return False

    recovered = pow(signature_integer, e, n)
    expected = message_integer(message)
    return recovered == expected
