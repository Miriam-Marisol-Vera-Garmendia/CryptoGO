import pytest
from ecies.keys import PrivateKey

from cryptogo.encryption.hybrid_vault import (
    HybridVaultAuthenticationError,
    HybridVaultFormatError,
    HybridVaultSignatureError,
    decrypt_file_for_recipient,
    encrypt_file_for_recipients,
    generate_signing_keypair,
)


def generate_demo_users():
    users = {}

    for name in ["alice", "bob", "carol"]:
        sk = PrivateKey("secp256k1")
        users[name] = {
            "private_key": sk.to_hex(),
            "public_key": sk.public_key.to_hex(True)
        }

        # Generar par de llaves Ed25519 para firmar/verificar en los tests
        priv_sign, pub_sign, _ = generate_signing_keypair()
        users[name]["signing_private"] = priv_sign
        users[name]["signing_public"] = pub_sign

    return users


def test_two_users_can_decrypt(tmp_path):
    users = generate_demo_users()

    original = tmp_path / "secret.txt"
    original.write_text("hola mundo", encoding="utf-8")

    container = tmp_path / "vault_container"

    encrypt_file_for_recipients(
        original,
        container,
        {
            "alice": users["alice"]["public_key"],
            "bob": users["bob"]["public_key"],
        },
        users["alice"]["signing_private"],
    )

    out_alice = tmp_path / "alice.txt"
    decrypt_file_for_recipient(
        container,
        users["alice"]["private_key"],
        users["alice"]["public_key"],
        out_alice,
        users["alice"]["signing_public"],
    )
    assert out_alice.read_text(encoding="utf-8") == "hola mundo"

    out_bob = tmp_path / "bob.txt"
    decrypt_file_for_recipient(
        container,
        users["bob"]["private_key"],
        users["bob"]["public_key"],
        out_bob,
        users["alice"]["signing_public"],
    )
    assert out_bob.read_text(encoding="utf-8") == "hola mundo"


def test_unauthorized_user_cannot_decrypt(tmp_path):
    users = generate_demo_users()

    original = tmp_path / "secret.txt"
    original.write_text("secreto", encoding="utf-8")
    container = tmp_path / "vault_container"

    encrypt_file_for_recipients(
        original,
        container,
        {
            "alice": users["alice"]["public_key"],
            "bob": users["bob"]["public_key"],
        },
        users["alice"]["signing_private"],
    )

    with pytest.raises(HybridVaultFormatError):
        decrypt_file_for_recipient(
            container,
            users["carol"]["private_key"],
            users["carol"]["public_key"],
            tmp_path / "carol.txt",
            users["alice"]["signing_public"],
        )


def test_tampered_recipients_fails(tmp_path):
    users = generate_demo_users()

    original = tmp_path / "secret.txt"
    original.write_text("secreto", encoding="utf-8")
    container = tmp_path / "vault_container"

    encrypt_file_for_recipients(
        original,
        container,
        {
            "alice": users["alice"]["public_key"],
            "bob": users["bob"]["public_key"],
        },
        users["alice"]["signing_private"],
    )

    recipients_path = container / "recipients"
    data = bytearray(recipients_path.read_bytes())
    data[-1] ^= 0x01
    recipients_path.write_bytes(bytes(data))

    with pytest.raises((HybridVaultAuthenticationError, HybridVaultFormatError, HybridVaultSignatureError)):
        decrypt_file_for_recipient(
            container,
            users["alice"]["private_key"],
            users["alice"]["public_key"],
            tmp_path / "out.txt",
            users["alice"]["signing_public"],
        )


def test_wrong_private_key_fails(tmp_path):
    users = generate_demo_users()

    original = tmp_path / "secret.txt"
    original.write_text("secreto", encoding="utf-8")
    container = tmp_path / "vault_container"

    encrypt_file_for_recipients(
        original,
        container,
        {
            "alice": users["alice"]["public_key"],
            "bob": users["bob"]["public_key"],
        },
        users["alice"]["signing_private"],
    )

    with pytest.raises(HybridVaultAuthenticationError):
        decrypt_file_for_recipient(
            container,
            users["bob"]["private_key"],
            users["alice"]["public_key"],
            tmp_path / "out.txt",
            users["alice"]["signing_public"],
        )


def test_removing_recipient_breaks_access(tmp_path):
    users = generate_demo_users()

    original = tmp_path / "secret.txt"
    original.write_text("secreto", encoding="utf-8")
    container = tmp_path / "vault_container"

    encrypt_file_for_recipients(
        original,
        container,
        {
            "alice": users["alice"]["public_key"],
            "bob": users["bob"]["public_key"],
        },
        users["alice"]["signing_private"],
    )

    recipients_path = container / "recipients"
    data = recipients_path.read_bytes()
    recipients_path.write_bytes(data[:-20])

    with pytest.raises((HybridVaultAuthenticationError, HybridVaultFormatError, HybridVaultSignatureError)):
        decrypt_file_for_recipient(
            container,
            users["alice"]["private_key"],
            users["alice"]["public_key"],
            tmp_path / "out.txt",
            users["alice"]["signing_public"],
        )