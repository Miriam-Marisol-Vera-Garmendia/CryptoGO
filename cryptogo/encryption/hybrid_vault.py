from __future__ import annotations

import hashlib
import json
import os
import struct
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from ecies import decrypt as ecies_decrypt
from ecies import encrypt as ecies_encrypt


MAGIC = "CRYPTOGO_HYBRID_VAULT"
CONTAINER_VERSION = 3
AEAD_ALGORITHM = "ChaCha20-Poly1305"
KEY_ENCRYPTION_ALGORITHM = "ECIES-secp256k1"
KEY_SIZE_BYTES = 32
NONCE_SIZE_BYTES = 12
TAG_SIZE_BYTES = 16


class HybridVaultError(Exception):
    """Base exception for hybrid vault errors."""


class HybridVaultAuthenticationError(HybridVaultError):
    """Raised when authentication fails."""


class HybridVaultFormatError(HybridVaultError):
    """Raised when the encrypted container format is invalid."""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def public_key_fingerprint(public_key_hex: str) -> str:
    public_key_bytes = bytes.fromhex(public_key_hex)
    return hashlib.sha256(public_key_bytes).hexdigest()[:32]


def _canonical_json(data: dict) -> bytes:
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _build_header(original_filename: str, plaintext_size: int, recipients_count: int) -> dict:
    return {
        "magic": MAGIC,
        "container_version": CONTAINER_VERSION,
        "aead_algorithm": AEAD_ALGORITHM,
        "key_encryption_algorithm": KEY_ENCRYPTION_ALGORITHM,
        "key_size_bytes": KEY_SIZE_BYTES,
        "nonce_size_bytes": NONCE_SIZE_BYTES,
        "tag_size_bytes": TAG_SIZE_BYTES,
        "created_at": _utc_now_iso(),
        "original_filename": original_filename,
        "plaintext_size": plaintext_size,
        "recipients_count": recipients_count,
    }


def _validate_header(header_bytes: bytes) -> dict:
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HybridVaultFormatError("Header inválido: no es JSON UTF-8 válido.") from exc

    required_fields = {
        "magic",
        "container_version",
        "aead_algorithm",
        "key_encryption_algorithm",
        "key_size_bytes",
        "nonce_size_bytes",
        "tag_size_bytes",
        "created_at",
        "original_filename",
        "plaintext_size",
        "recipients_count",
    }

    missing = required_fields - set(header.keys())
    if missing:
        raise HybridVaultFormatError(f"Header incompleto. Faltan campos: {sorted(missing)}")

    if header["magic"] != MAGIC:
        raise HybridVaultFormatError("Magic inválido en header.")
    if header["container_version"] != CONTAINER_VERSION:
        raise HybridVaultFormatError("Versión de contenedor no soportada.")
    if header["aead_algorithm"] != AEAD_ALGORITHM:
        raise HybridVaultFormatError("Algoritmo AEAD no soportado.")
    if header["key_encryption_algorithm"] != KEY_ENCRYPTION_ALGORITHM:
        raise HybridVaultFormatError("Algoritmo de cifrado de clave no soportado.")
    if header["key_size_bytes"] != KEY_SIZE_BYTES:
        raise HybridVaultFormatError("Tamaño de clave inesperado en header.")
    if header["nonce_size_bytes"] != NONCE_SIZE_BYTES:
        raise HybridVaultFormatError("Tamaño de nonce inesperado en header.")
    if header["tag_size_bytes"] != TAG_SIZE_BYTES:
        raise HybridVaultFormatError("Tamaño de tag inesperado en header.")
    if not isinstance(header["plaintext_size"], int) or header["plaintext_size"] < 0:
        raise HybridVaultFormatError("plaintext_size inválido.")
    if not isinstance(header["recipients_count"], int) or header["recipients_count"] < 2:
        raise HybridVaultFormatError("recipients_count inválido.")

    return header


def save_recipients_binary(path: Path, recipients: list[dict]) -> None:
    data = b""
    data += struct.pack(">I", len(recipients))

    for recipient in recipients:
        id_bytes = recipient["id"].encode("utf-8")
        key_id_bytes = recipient["key_id"].encode("utf-8")
        enc_key_bytes = recipient["encrypted_key"]

        data += struct.pack(">H", len(id_bytes))
        data += id_bytes

        data += struct.pack(">H", len(key_id_bytes))
        data += key_id_bytes

        data += struct.pack(">I", len(enc_key_bytes))
        data += enc_key_bytes

    (path / "recipients").write_bytes(data)


def load_recipients_binary(path: Path) -> list[dict]:
    data = (path / "recipients").read_bytes()

    recipients = []
    offset = 0

    if len(data) < 4:
        raise HybridVaultFormatError("Archivo recipients inválido o incompleto.")

    count = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4

    for _ in range(count):
        if offset + 2 > len(data):
            raise HybridVaultFormatError("Archivo recipients truncado (id_len).")
        id_len = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2

        if offset + id_len > len(data):
            raise HybridVaultFormatError("Archivo recipients truncado (id).")
        user_id = data[offset:offset + id_len].decode("utf-8")
        offset += id_len

        if offset + 2 > len(data):
            raise HybridVaultFormatError("Archivo recipients truncado (key_id_len).")
        key_id_len = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2

        if offset + key_id_len > len(data):
            raise HybridVaultFormatError("Archivo recipients truncado (key_id).")
        key_id = data[offset:offset + key_id_len].decode("utf-8")
        offset += key_id_len

        if offset + 4 > len(data):
            raise HybridVaultFormatError("Archivo recipients truncado (enc_len).")
        enc_len = struct.unpack(">I", data[offset:offset + 4])[0]
        offset += 4

        if offset + enc_len > len(data):
            raise HybridVaultFormatError("Archivo recipients truncado (encrypted_key).")
        enc_key = data[offset:offset + enc_len]
        offset += enc_len

        recipients.append({
            "id": user_id,
            "key_id": key_id,
            "encrypted_key": enc_key,
        })

    if offset != len(data):
        raise HybridVaultFormatError("Archivo recipients tiene bytes extra o está corrupto.")

    return recipients


def _read_container(container_dir: Path) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    if not container_dir.exists() or not container_dir.is_dir():
        raise HybridVaultFormatError("El contenedor no existe o no es un directorio válido.")

    try:
        header_bytes = (container_dir / "header").read_bytes()
        recipients_bytes = (container_dir / "recipients").read_bytes()
        nonce = (container_dir / "nonce").read_bytes()
        ciphertext = (container_dir / "ciphertext").read_bytes()
        tag = (container_dir / "authentication_tag").read_bytes()
    except FileNotFoundError as exc:
        raise HybridVaultFormatError(f"Falta un componente del contenedor: {exc}") from exc

    if len(nonce) != NONCE_SIZE_BYTES:
        raise HybridVaultFormatError("Nonce inválido: tamaño incorrecto.")
    if len(tag) != TAG_SIZE_BYTES:
        raise HybridVaultFormatError("Authentication tag inválido: tamaño incorrecto.")

    return header_bytes, recipients_bytes, nonce, ciphertext, tag


def _write_container(
    container_dir: Path,
    header_bytes: bytes,
    recipients: list[dict],
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
) -> None:
    container_dir.mkdir(parents=True, exist_ok=False)
    (container_dir / "header").write_bytes(header_bytes)
    save_recipients_binary(container_dir, recipients)
    (container_dir / "nonce").write_bytes(nonce)
    (container_dir / "ciphertext").write_bytes(ciphertext)
    (container_dir / "authentication_tag").write_bytes(tag)


def encrypt_file_for_recipients(
    input_path: str | Path,
    output_dir: str | Path,
    recipient_public_keys: dict[str, str],
) -> Path:
    input_path = Path(input_path)
    output_dir = Path(output_dir)

    if not input_path.exists() or not input_path.is_file():
        raise FileNotFoundError(f"Archivo de entrada no encontrado: {input_path}")

    if len(recipient_public_keys) < 2:
        raise ValueError("Debes proporcionar al menos 2 recipients.")

    plaintext = input_path.read_bytes()
    file_key = ChaCha20Poly1305.generate_key()
    nonce = os.urandom(NONCE_SIZE_BYTES)

    recipients = []
    seen_key_ids = set()

    for user_id, public_key_hex in recipient_public_keys.items():
        key_id = public_key_fingerprint(public_key_hex)
        if key_id in seen_key_ids:
            raise ValueError("Hay claves públicas duplicadas entre recipients.")
        seen_key_ids.add(key_id)

        encrypted_key = ecies_encrypt(public_key_hex, file_key)
        recipients.append({
            "id": user_id,
            "key_id": key_id,
            "encrypted_key": encrypted_key,
        })

    header = _build_header(
        original_filename=input_path.name,
        plaintext_size=len(plaintext),
        recipients_count=len(recipients),
    )
    header_bytes = _canonical_json(header)

    temp_dir = output_dir.parent / f"{output_dir.name}_temp"
    if temp_dir.exists():
        raise FileExistsError(f"Ya existe el directorio temporal: {temp_dir}")

    temp_dir.mkdir(parents=True, exist_ok=False)
    try:
        save_recipients_binary(temp_dir, recipients)
        recipients_bytes = (temp_dir / "recipients").read_bytes()
    finally:
        temp_file = temp_dir / "recipients"
        if temp_file.exists():
            temp_file.unlink()
        temp_dir.rmdir()

    aad = header_bytes + recipients_bytes

    aead = ChaCha20Poly1305(file_key)
    combined = aead.encrypt(nonce, plaintext, aad)
    ciphertext = combined[:-TAG_SIZE_BYTES]
    tag = combined[-TAG_SIZE_BYTES:]

    _write_container(
        container_dir=output_dir,
        header_bytes=header_bytes,
        recipients=recipients,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
    )

    return output_dir


def decrypt_file_for_recipient(
    container_dir: str | Path,
    recipient_private_key_hex: str,
    recipient_public_key_hex: str,
    output_path: str | Path,
) -> Path:
    container_dir = Path(container_dir)
    output_path = Path(output_path)

    header_bytes, recipients_bytes, nonce, ciphertext, tag = _read_container(container_dir)
    header = _validate_header(header_bytes)
    recipients = load_recipients_binary(container_dir)

    if header["recipients_count"] != len(recipients):
        raise HybridVaultFormatError("El número de recipients no coincide con el header.")

    my_key_id = public_key_fingerprint(recipient_public_key_hex)

    entry = None
    for recipient in recipients:
        if recipient["key_id"] == my_key_id:
            entry = recipient
            break

    if entry is None:
        raise HybridVaultFormatError("No existe una entrada de recipient para esta clave pública.")

    try:
        file_key = ecies_decrypt(recipient_private_key_hex, entry["encrypted_key"])
    except Exception as exc:
        raise HybridVaultAuthenticationError(
            "No fue posible recuperar la file key con la clave privada proporcionada."
        ) from exc

    if len(file_key) != KEY_SIZE_BYTES:
        raise HybridVaultFormatError("La file key recuperada tiene tamaño inválido.")

    aad = header_bytes + recipients_bytes
    combined = ciphertext + tag

    aead = ChaCha20Poly1305(file_key)
    try:
        plaintext = aead.decrypt(nonce, combined, aad)
    except InvalidTag as exc:
        raise HybridVaultAuthenticationError(
            "Falló la autenticación del contenedor. "
            "El header, recipients, nonce, ciphertext o tag fueron alterados."
        ) from exc

    if len(plaintext) != header["plaintext_size"]:
        raise HybridVaultFormatError("El tamaño del plaintext descifrado no coincide con el header.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(plaintext)
    return output_path