import json

import pytest

from cryptogo.encryption.file_vault import (
    TAG_SIZE_BYTES,
    VaultAuthenticationError,
    decrypt_bytes,
    encrypt_bytes,
)


def test_encrypt_decrypt_roundtrip_returns_identical_plaintext():
    plaintext = b"Documento secreto de prueba"
    file_key, header, nonce, ciphertext, tag = encrypt_bytes(
        plaintext,
        original_filename="prueba.txt",
    )

    recovered = decrypt_bytes(file_key, header, nonce, ciphertext, tag)
    assert recovered == plaintext


def test_wrong_key_fails():
    plaintext = b"Contenido importante"
    file_key, header, nonce, ciphertext, tag = encrypt_bytes(plaintext, "doc.txt")

    wrong_key = b"\x00" * 32
    assert wrong_key != file_key

    with pytest.raises(VaultAuthenticationError):
        decrypt_bytes(wrong_key, header, nonce, ciphertext, tag)


def test_modified_ciphertext_fails():
    plaintext = b"Hola mundo"
    file_key, header, nonce, ciphertext, tag = encrypt_bytes(plaintext, "doc.txt")

    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01

    with pytest.raises(VaultAuthenticationError):
        decrypt_bytes(file_key, header, nonce, bytes(tampered), tag)


def test_modified_metadata_fails():
    plaintext = b"Archivo con AAD"
    file_key, header, nonce, ciphertext, tag = encrypt_bytes(plaintext, "original.txt")

    parsed = json.loads(header.decode("utf-8"))
    parsed["original_filename"] = "modificado.txt"
    tampered_header = json.dumps(
        parsed,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    with pytest.raises(VaultAuthenticationError):
        decrypt_bytes(file_key, tampered_header, nonce, ciphertext, tag)


def test_multiple_encryptions_produce_different_outputs():
    plaintext = b"Mismo contenido, distinto cifrado"

    k1, h1, n1, c1, t1 = encrypt_bytes(plaintext, "a.txt")
    k2, h2, n2, c2, t2 = encrypt_bytes(plaintext, "a.txt")

    # Deben ser diferentes por nueva clave/nonce/timestamp
    assert k1 != k2
    assert n1 != n2

    # Puede cambiar header por timestamp, y ciphertext/tag por key/nonce
    assert h1 != h2 or c1 != c2 or t1 != t2

    r1 = decrypt_bytes(k1, h1, n1, c1, t1)
    r2 = decrypt_bytes(k2, h2, n2, c2, t2)

    assert r1 == plaintext
    assert r2 == plaintext


def test_tag_has_expected_size():
    plaintext = b"test"
    _, _, _, _, tag = encrypt_bytes(plaintext, "x.txt")
    assert len(tag) == TAG_SIZE_BYTES