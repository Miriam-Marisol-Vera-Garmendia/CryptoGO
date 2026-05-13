"""
key_manager.py — D5: Sistema de Gestión Segura de Claves
=========================================================

Protege claves privadas ECIES y Ed25519 mediante cifrado basado en contraseña.

Formato del keystore (directorio):
    keystore/
    ├── metadata         — JSON: versión, algoritmos, fechas, key_id, signer_id
    ├── salt             — 32 bytes aleatorios para Scrypt
    ├── nonce            — 12 bytes aleatorios para ChaCha20-Poly1305
    └── encrypted_key    — clave privada cifrada (ciphertext + tag de 16 bytes)

KDF: Scrypt con N=2^17, r=8, p=1 → clave de 32 bytes para ChaCha20-Poly1305.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ─── Constantes ───────────────────────────────────────────────────────────────

KEYSTORE_VERSION   = 1
KEYSTORE_MAGIC     = "CRYPTOGO_KEYSTORE"

# Scrypt KDF
KDF_ALGORITHM      = "scrypt"
KDF_SALT_BYTES     = 32
KDF_N              = 2 ** 17      # factor de costo (CPU/Memoria)
KDF_R              = 8
KDF_P              = 1
KDF_KEY_BYTES      = 32

# AEAD para envolver la clave privada
WRAP_ALGORITHM     = "ChaCha20-Poly1305"
WRAP_NONCE_BYTES   = 12
WRAP_TAG_BYTES     = 16

# Tipos de clave soportados
KEY_TYPE_ECIES   = "ECIES-secp256k1"   # hex string de 32 bytes
KEY_TYPE_ED25519 = "Ed25519"            # bytes raw de 32 bytes


# ─── Excepciones ──────────────────────────────────────────────────────────────

class KeyManagerError(Exception):
    """Base de errores del gestor de claves."""

class KeyManagerAuthError(KeyManagerError):
    """Contraseña incorrecta o keystore manipulado."""

class KeyManagerFormatError(KeyManagerError):
    """Formato de keystore inválido o incompleto."""


# ─── Utilidades internas ──────────────────────────────────────────────────────

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _canonical_json(data: dict) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _derive_key(password: str | bytes, salt: bytes) -> bytes:
    """
    Deriva una clave de 32 bytes a partir de una contraseña usando Scrypt.

    Parámetros elegidos para alta resistencia a ataques de fuerza bruta:
      N=2^17 (~128 MB RAM por operación, ~0.5 s en hardware moderno)
      r=8, p=1 (estándar recomendado)
    """
    if isinstance(password, str):
        password = password.encode("utf-8")
    kdf = Scrypt(salt=salt, length=KDF_KEY_BYTES, n=KDF_N, r=KDF_R, p=KDF_P)
    return kdf.derive(password)


def _encrypt_key_material(key_material: bytes, password: str | bytes) -> tuple[bytes, bytes, bytes]:
    """
    Cifra material de clave con una contraseña derivada.

    Returns:
        (salt, nonce, ciphertext_with_tag)
    """
    salt  = os.urandom(KDF_SALT_BYTES)
    nonce = os.urandom(WRAP_NONCE_BYTES)
    wrapping_key = _derive_key(password, salt)
    aead = ChaCha20Poly1305(wrapping_key)
    # AAD = salt + nonce (vincula los parámetros KDF al ciphertext)
    aad = salt + nonce
    ciphertext_with_tag = aead.encrypt(nonce, key_material, aad)
    return salt, nonce, ciphertext_with_tag


def _decrypt_key_material(
    salt: bytes,
    nonce: bytes,
    ciphertext_with_tag: bytes,
    password: str | bytes,
) -> bytes:
    """
    Descifra material de clave con la contraseña.

    Raises:
        KeyManagerAuthError: Si la contraseña es incorrecta o el keystore fue alterado.
    """
    wrapping_key = _derive_key(password, salt)
    aead = ChaCha20Poly1305(wrapping_key)
    aad = salt + nonce
    try:
        return aead.decrypt(nonce, ciphertext_with_tag, aad)
    except InvalidTag as exc:
        raise KeyManagerAuthError(
            "Contraseña incorrecta o el keystore fue modificado."
        ) from exc


# ─── API pública ──────────────────────────────────────────────────────────────

def protect_private_key(
    key_material: bytes | str,
    key_type: str,
    password: str | bytes,
    keystore_dir: str | Path,
    *,
    key_id: Optional[str] = None,
    label: Optional[str] = None,
) -> Path:
    """
    Cifra y almacena una clave privada protegida por contraseña.

    Args:
        key_material:  Clave privada. Para ECIES: hex string. Para Ed25519: bytes raw.
        key_type:      KEY_TYPE_ECIES o KEY_TYPE_ED25519.
        password:      Contraseña del usuario.
        keystore_dir:  Directorio de destino (no debe existir).
        key_id:        Identificador opcional (se genera uno si no se proporciona).
        label:         Etiqueta legible opcional.

    Returns:
        Path del directorio keystore creado.
    """
    keystore_dir = Path(keystore_dir)
    if keystore_dir.exists():
        raise FileExistsError(f"El keystore ya existe: {keystore_dir}")

    # Normalizar material de clave a bytes
    if key_type == KEY_TYPE_ECIES:
        if isinstance(key_material, str):
            raw = bytes.fromhex(key_material)
        else:
            raw = bytes(key_material)
    elif key_type == KEY_TYPE_ED25519:
        raw = bytes(key_material)
    else:
        raise KeyManagerFormatError(f"Tipo de clave no soportado: {key_type}")

    if len(raw) != 32:
        raise KeyManagerFormatError("La clave privada debe tener exactamente 32 bytes.")

    # Cifrar
    salt, nonce, ciphertext_with_tag = _encrypt_key_material(raw, password)

    # Construir metadata
    if key_id is None:
        import hashlib
        key_id = hashlib.sha256(raw).hexdigest()[:32]

    metadata = {
        "magic":          KEYSTORE_MAGIC,
        "version":        KEYSTORE_VERSION,
        "key_type":       key_type,
        "key_id":         key_id,
        "label":          label,
        "created_at":     _utc_now_iso(),
        "kdf":            KDF_ALGORITHM,
        "kdf_n":          KDF_N,
        "kdf_r":          KDF_R,
        "kdf_p":          KDF_P,
        "kdf_key_bytes":  KDF_KEY_BYTES,
        "wrap_algorithm": WRAP_ALGORITHM,
    }

    # Escribir keystore
    keystore_dir.mkdir(parents=True, exist_ok=False)
    (keystore_dir / "metadata").write_bytes(_canonical_json(metadata))
    (keystore_dir / "salt").write_bytes(salt)
    (keystore_dir / "nonce").write_bytes(nonce)
    (keystore_dir / "encrypted_key").write_bytes(ciphertext_with_tag)

    return keystore_dir


def recover_private_key(
    keystore_dir: str | Path,
    password: str | bytes,
) -> tuple[bytes | str, str, dict]:
    """
    Recupera una clave privada desde un keystore protegido por contraseña.

    Args:
        keystore_dir: Directorio keystore.
        password:     Contraseña del usuario.

    Returns:
        (key_material, key_type, metadata)
        - key_material: hex string para ECIES, bytes para Ed25519.
        - key_type:     KEY_TYPE_ECIES o KEY_TYPE_ED25519.
        - metadata:     Diccionario con metadatos del keystore.

    Raises:
        KeyManagerAuthError:   Si la contraseña es incorrecta.
        KeyManagerFormatError: Si el keystore está dañado o incompleto.
    """
    keystore_dir = Path(keystore_dir)

    if not keystore_dir.exists() or not keystore_dir.is_dir():
        raise KeyManagerFormatError("El directorio keystore no existe.")

    try:
        metadata_bytes  = (keystore_dir / "metadata").read_bytes()
        salt            = (keystore_dir / "salt").read_bytes()
        nonce           = (keystore_dir / "nonce").read_bytes()
        ciphertext_tag  = (keystore_dir / "encrypted_key").read_bytes()
    except FileNotFoundError as exc:
        raise KeyManagerFormatError(f"Componente faltante en el keystore: {exc}") from exc

    # Validar metadata
    try:
        metadata = json.loads(metadata_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KeyManagerFormatError("Metadata del keystore corrupta.") from exc

    if metadata.get("magic") != KEYSTORE_MAGIC:
        raise KeyManagerFormatError("Magic inválido en el keystore.")
    if metadata.get("version") != KEYSTORE_VERSION:
        raise KeyManagerFormatError("Versión de keystore no soportada.")

    # Validar parámetros KDF
    if len(salt) != KDF_SALT_BYTES:
        raise KeyManagerFormatError("Salt con tamaño inválido.")
    if len(nonce) != WRAP_NONCE_BYTES:
        raise KeyManagerFormatError("Nonce con tamaño inválido.")

    # Descifrar (lanza KeyManagerAuthError si la contraseña es incorrecta)
    raw = _decrypt_key_material(salt, nonce, ciphertext_tag, password)

    if len(raw) != 32:
        raise KeyManagerFormatError("Material de clave descifrado con tamaño inesperado.")

    key_type = metadata.get("key_type", "")
    if key_type == KEY_TYPE_ECIES:
        return raw.hex(), key_type, metadata
    elif key_type == KEY_TYPE_ED25519:
        return raw, key_type, metadata
    else:
        raise KeyManagerFormatError(f"Tipo de clave desconocido en metadata: {key_type}")


def backup_keystore(
    keystore_dir: str | Path,
    backup_dir: str | Path,
) -> Path:
    """
    Crea una copia de seguridad del keystore cifrado.

    El backup ya está cifrado (la contraseña nunca se almacena),
    por lo que puede guardarse en cualquier lugar.

    Args:
        keystore_dir: Directorio keystore original.
        backup_dir:   Directorio de destino del backup (no debe existir).

    Returns:
        Path del directorio de backup creado.
    """
    import shutil
    keystore_dir = Path(keystore_dir)
    backup_dir   = Path(backup_dir)

    if not keystore_dir.exists():
        raise FileNotFoundError(f"Keystore de origen no encontrado: {keystore_dir}")
    if backup_dir.exists():
        raise FileExistsError(f"El directorio de backup ya existe: {backup_dir}")

    shutil.copytree(keystore_dir, backup_dir)
    return backup_dir


def rotate_key(
    old_keystore_dir: str | Path,
    old_password: str | bytes,
    new_keystore_dir: str | Path,
    new_password: str | bytes,
    *,
    label: Optional[str] = None,
) -> tuple[Path, bytes | str]:
    """
    Rota una clave privada existente:
      1. Recupera la clave del keystore antiguo con la contraseña antigua.
      2. Genera una NUEVA clave del mismo tipo.
      3. Almacena la nueva clave en un keystore nuevo con la nueva contraseña.

    La clave nueva debe distribuirse a los destinatarios relevantes.

    Returns:
        (new_keystore_path, new_key_material)
    """
    from cryptogo.encryption.hybrid_vault import generate_ecies_keypair, generate_signing_keypair

    # Recuperar clave antigua para determinar tipo
    _, key_type, old_metadata = recover_private_key(old_keystore_dir, old_password)

    # Generar nueva clave del mismo tipo
    if key_type == KEY_TYPE_ECIES:
        new_priv_hex, new_pub_hex = generate_ecies_keypair()
        new_material = new_priv_hex
        new_raw = bytes.fromhex(new_priv_hex)
    elif key_type == KEY_TYPE_ED25519:
        new_priv_bytes, new_pub_bytes, _ = generate_signing_keypair()
        new_material = new_priv_bytes
        new_raw = new_priv_bytes
    else:
        raise KeyManagerFormatError(f"Tipo de clave no soportado para rotación: {key_type}")

    rotated_label = label or f"rotated-from-{old_metadata.get('key_id', 'unknown')[:8]}"
    new_ks = protect_private_key(
        key_material=new_raw,
        key_type=key_type,
        password=new_password,
        keystore_dir=new_keystore_dir,
        label=rotated_label,
    )

    return new_ks, new_material


def get_keystore_info(keystore_dir: str | Path) -> dict:
    """
    Retorna la metadata del keystore SIN revelar la clave privada ni requerir contraseña.
    Útil para inspección e inventario.
    """
    keystore_dir = Path(keystore_dir)
    try:
        metadata_bytes = (keystore_dir / "metadata").read_bytes()
    except FileNotFoundError as exc:
        raise KeyManagerFormatError("Metadata del keystore no encontrada.") from exc

    try:
        return json.loads(metadata_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KeyManagerFormatError("Metadata corrupta.") from exc
