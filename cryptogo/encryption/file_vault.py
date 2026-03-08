from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


MAGIC = "CRYPTOGO_VAULT"
CONTAINER_VERSION = 1
AEAD_ALGORITHM = "ChaCha20-Poly1305"
KEY_SIZE_BYTES = 32
NONCE_SIZE_BYTES = 12
TAG_SIZE_BYTES = 16


class VaultError(Exception):
    """Base exception for vault errors."""


class VaultAuthenticationError(VaultError):
    """Raised when AEAD authentication fails."""


class VaultFormatError(VaultError):
    """Raised when the encrypted container format is invalid."""


@dataclass(frozen=True)
class VaultHeader:
    magic: str
    container_version: int
    aead_algorithm: str
    key_size_bytes: int
    nonce_size_bytes: int
    tag_size_bytes: int
    created_at: str
    original_filename: Optional[str]
    plaintext_size: int

    def to_dict(self) -> dict:
        return {
            "magic": self.magic,
            "container_version": self.container_version,
            "aead_algorithm": self.aead_algorithm,
            "key_size_bytes": self.key_size_bytes,
            "nonce_size_bytes": self.nonce_size_bytes,
            "tag_size_bytes": self.tag_size_bytes,
            "created_at": self.created_at,
            "original_filename": self.original_filename,
            "plaintext_size": self.plaintext_size,
        }


def _canonical_json(data: dict) -> bytes:
    """
    Serialize metadata deterministically so it can be used as AAD.
    """
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def generate_file_key() -> bytes:
    """
    Generates a fresh 256-bit key for one file.
    """
    return ChaCha20Poly1305.generate_key()


def _build_header(
    original_filename: Optional[str],
    plaintext_size: int,
) -> VaultHeader:
    return VaultHeader(
        magic=MAGIC,
        container_version=CONTAINER_VERSION,
        aead_algorithm=AEAD_ALGORITHM,
        key_size_bytes=KEY_SIZE_BYTES,
        nonce_size_bytes=NONCE_SIZE_BYTES,
        tag_size_bytes=TAG_SIZE_BYTES,
        created_at=_utc_now_iso(),
        original_filename=original_filename,
        plaintext_size=plaintext_size,
    )


def _write_container(
    container_dir: Path,
    header_bytes: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
) -> None:
    container_dir.mkdir(parents=True, exist_ok=False)

    (container_dir / "header").write_bytes(header_bytes)
    (container_dir / "nonce").write_bytes(nonce)
    (container_dir / "ciphertext").write_bytes(ciphertext)
    (container_dir / "authentication_tag").write_bytes(tag)


def _read_container(container_dir: Path) -> tuple[bytes, bytes, bytes, bytes]:
    if not container_dir.exists() or not container_dir.is_dir():
        raise VaultFormatError("El contenedor no existe o no es un directorio válido.")

    try:
        header_bytes = (container_dir / "header").read_bytes()
        nonce = (container_dir / "nonce").read_bytes()
        ciphertext = (container_dir / "ciphertext").read_bytes()
        tag = (container_dir / "authentication_tag").read_bytes()
    except FileNotFoundError as exc:
        raise VaultFormatError(f"Falta un componente del contenedor: {exc}") from exc

    if len(nonce) != NONCE_SIZE_BYTES:
        raise VaultFormatError("Nonce inválido: tamaño incorrecto.")

    if len(tag) != TAG_SIZE_BYTES:
        raise VaultFormatError("Authentication tag inválido: tamaño incorrecto.")

    return header_bytes, nonce, ciphertext, tag


def _validate_header(header_bytes: bytes) -> dict:
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VaultFormatError("Header inválido: no es JSON UTF-8 válido.") from exc

    required_fields = {
        "magic",
        "container_version",
        "aead_algorithm",
        "key_size_bytes",
        "nonce_size_bytes",
        "tag_size_bytes",
        "created_at",
        "original_filename",
        "plaintext_size",
    }

    missing = required_fields - set(header.keys())
    if missing:
        raise VaultFormatError(f"Header incompleto. Faltan campos: {sorted(missing)}")

    if header["magic"] != MAGIC:
        raise VaultFormatError("Magic inválido en header.")

    if header["container_version"] != CONTAINER_VERSION:
        raise VaultFormatError("Versión de contenedor no soportada.")

    if header["aead_algorithm"] != AEAD_ALGORITHM:
        raise VaultFormatError("Algoritmo AEAD no soportado en este módulo.")

    if header["key_size_bytes"] != KEY_SIZE_BYTES:
        raise VaultFormatError("Tamaño de clave inesperado en header.")

    if header["nonce_size_bytes"] != NONCE_SIZE_BYTES:
        raise VaultFormatError("Tamaño de nonce inesperado en header.")

    if header["tag_size_bytes"] != TAG_SIZE_BYTES:
        raise VaultFormatError("Tamaño de tag inesperado en header.")

    if not isinstance(header["plaintext_size"], int) or header["plaintext_size"] < 0:
        raise VaultFormatError("plaintext_size inválido.")

    return header


def encrypt_bytes(
    plaintext: bytes,
    original_filename: Optional[str] = None,
) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    """
    Encrypts plaintext and returns:
    (file_key, header_bytes, nonce, ciphertext, tag)
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext debe ser bytes o bytearray.")

    file_key = generate_file_key()
    nonce = os.urandom(NONCE_SIZE_BYTES)

    header = _build_header(
        original_filename=original_filename,
        plaintext_size=len(plaintext),
    )
    header_bytes = _canonical_json(header.to_dict())

    aead = ChaCha20Poly1305(file_key)
    combined = aead.encrypt(nonce, bytes(plaintext), header_bytes)

    ciphertext = combined[:-TAG_SIZE_BYTES]
    tag = combined[-TAG_SIZE_BYTES:]

    return file_key, header_bytes, nonce, ciphertext, tag


def decrypt_bytes(
    file_key: bytes,
    header_bytes: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
) -> bytes:
    """
    Decrypts a container payload and validates metadata via AAD.
    """
    if not isinstance(file_key, (bytes, bytearray)) or len(file_key) != KEY_SIZE_BYTES:
        raise VaultFormatError("La clave simétrica debe tener 32 bytes.")

    _validate_header(header_bytes)

    if len(nonce) != NONCE_SIZE_BYTES:
        raise VaultFormatError("Nonce inválido.")

    if len(tag) != TAG_SIZE_BYTES:
        raise VaultFormatError("Tag inválido.")

    combined = ciphertext + tag
    aead = ChaCha20Poly1305(bytes(file_key))

    try:
        plaintext = aead.decrypt(nonce, combined, header_bytes)
    except InvalidTag as exc:
        raise VaultAuthenticationError(
            "Falló la autenticación del contenedor. "
            "La clave, el nonce, el ciphertext o los metadatos fueron alterados."
        ) from exc

    header = _validate_header(header_bytes)
    expected_size = header["plaintext_size"]
    if len(plaintext) != expected_size:
        raise VaultFormatError("El tamaño del plaintext descifrado no coincide con el header.")

    return plaintext


def encrypt_file(input_path: str | Path, output_dir: str | Path) -> bytes:
    """
    Encrypts a file into a directory container:
        output_dir/
         ├── header
         ├── nonce
         ├── ciphertext
         └── authentication_tag

    Returns the generated per-file symmetric key.
    """
    input_path = Path(input_path)
    output_dir = Path(output_dir)

    if not input_path.exists() or not input_path.is_file():
        raise FileNotFoundError(f"Archivo de entrada no encontrado: {input_path}")

    plaintext = input_path.read_bytes()

    file_key, header_bytes, nonce, ciphertext, tag = encrypt_bytes(
        plaintext=plaintext,
        original_filename=input_path.name,
    )

    _write_container(
        container_dir=output_dir,
        header_bytes=header_bytes,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
    )

    return file_key


def decrypt_file(
    container_dir: str | Path,
    file_key: bytes,
    output_path: str | Path,
) -> Path:
    """
    Decrypts a directory container and writes the recovered file.
    """
    container_dir = Path(container_dir)
    output_path = Path(output_path)

    header_bytes, nonce, ciphertext, tag = _read_container(container_dir)

    plaintext = decrypt_bytes(
        file_key=file_key,
        header_bytes=header_bytes,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(plaintext)
    return output_path