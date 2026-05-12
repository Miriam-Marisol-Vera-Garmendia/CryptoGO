from __future__ import annotations

import hashlib
import io
import json
import os
import struct
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from ecies import decrypt as ecies_decrypt
from ecies import encrypt as ecies_encrypt
from ecies.utils import generate_key

MAGIC                    = "CRYPTOGO_HYBRID_VAULT"
CONTAINER_VERSION        = 4          # incrementado por D4 (agrega firma digital)
AEAD_ALGORITHM           = "ChaCha20-Poly1305"
KEY_ENCRYPTION_ALGORITHM = "ECIES-secp256k1"
SIGNATURE_ALGORITHM      = "Ed25519"  # algoritmo de firma digital
KEY_SIZE_BYTES           = 32
NONCE_SIZE_BYTES         = 12
TAG_SIZE_BYTES           = 16
ED25519_SIG_BYTES        = 64         # firma Ed25519 siempre tiene exactamente 64 bytes
ED25519_PUB_BYTES        = 32         # clave pública Ed25519: 32 bytes
MAX_FILE_SIZE            = 100 * 1024 * 1024  # 100 MB - límite máximo de tamaño de archivo

# KDF (Scrypt) para protección local de llaves privadas ECIES
KDF_SALT_BYTES        = 32
KDF_N                 = 2 ** 17
KDF_R                 = 8
KDF_P                 = 1
ENCRYPTED_KEY_VERSION = 1


# ──────────────────────────────────────────────────────────────────────────────
#  Excepciones
# ──────────────────────────────────────────────────────────────────────────────

class HybridVaultError(Exception):
    """Excepción base para errores del vault."""

class HybridVaultAuthenticationError(HybridVaultError):
    """Lanzada cuando falla la autenticación AEAD o el descifrado ECIES."""

class HybridVaultFormatError(HybridVaultError):
    """Lanzada cuando el formato del contenedor es inválido o está incompleto."""

class HybridVaultSignatureError(HybridVaultError):
    """
    Lanzada cuando la firma digital Ed25519 no es válida.

    Esto indica que el contenedor fue modificado después de ser firmado,
    o que la clave pública del firmante proporcionada no corresponde al firmante real.
    El descifrado NO se realiza cuando se lanza esta excepción.
    """

class HybridVaultFileSizeError(HybridVaultError):
    """Lanzada cuando el archivo a cifrar excede el tamaño máximo permitido."""

class HybridVaultRateLimitError(HybridVaultError):
    """Lanzada cuando se excede el límite de intentos de operación sensible."""


#  Utilidades internas
# ──────────────────────────────────────────────────────────────────────────────

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _canonical_json(data: dict) -> bytes:
    """Serialización determinista de un dict como JSON UTF-8 con claves ordenadas."""
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def public_key_fingerprint(public_key_hex: str) -> str:
    """
    Huella digital de una clave pública ECIES (secp256k1).
    SHA-256 del raw de la clave, truncado a 32 caracteres hex (16 bytes).
    """
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:32]


def signer_id_from_public_key(ed25519_public_key_bytes: bytes) -> str:
    """
    Identificador del firmante: SHA-256 completo (64 hex chars) de la clave
    pública Ed25519 en formato raw (32 bytes).
    """
    return hashlib.sha256(ed25519_public_key_bytes).hexdigest()


# ──────────────────────────────────────────────────────────────────────────────
#  Generación de claves ECIES (para cifrado)
# ──────────────────────────────────────────────────────────────────────────────

def generate_ecies_keypair() -> tuple[str, str]:
    """
    Genera un par de claves ECIES (secp256k1) para cifrado.
    """
    sk = generate_key()
    return sk.secret.hex(), sk.public_key.format(compressed=False).hex()


# ──────────────────────────────────────────────────────────────────────────────
#  Generación de claves Ed25519 (para firma digital)
# ──────────────────────────────────────────────────────────────────────────────

def generate_signing_keypair() -> tuple[bytes, bytes, str]:
    """
    Genera un par de claves Ed25519 para firma digital.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key  = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    sid = signer_id_from_public_key(public_bytes)
    return private_bytes, public_bytes, sid


# ──────────────────────────────────────────────────────────────────────────────
#  Firma digital Ed25519
# ──────────────────────────────────────────────────────────────────────────────

def _build_signed_data(
    header_bytes:     bytes,
    recipients_bytes: bytes,
    nonce:            bytes,
    ciphertext:       bytes,
    tag:              bytes,
) -> bytes:
    """
    Construye el blob de datos que se firma y se verifica.

    Datos firmados (en orden):
        header_bytes     — metadatos del contenedor (algoritmos, versión, fecha, etc.)
        recipients_bytes — lista de recipients con key_ids y llaves cifradas
        nonce            — nonce de ChaCha20-Poly1305
        ciphertext       — contenido cifrado del archivo
        tag              — etiqueta de autenticación AEAD (Poly1305)
    """
    return header_bytes + recipients_bytes + nonce + ciphertext + tag


def sign_container(
    signed_data:       bytes,
    signing_priv_bytes: bytes,
) -> bytes:
    """
    Firma el blob de datos del contenedor con Ed25519.

    Args:
        signed_data:        Blob devuelto por _build_signed_data().
        signing_priv_bytes: Clave privada Ed25519 en formato raw (32 bytes).
    """
    private_key = Ed25519PrivateKey.from_private_bytes(signing_priv_bytes)
    return private_key.sign(signed_data)


def verify_signature(
    signed_data:        bytes,
    signature:          bytes,
    signing_pub_bytes:  bytes,
) -> None:
    """
    Verifica la firma Ed25519 del contenedor.

    Flujo requerido por D4:
        1. Leer contenedor.
        2. Extraer metadata + ciphertext.
        3. Verificar firma  ← esta función.
        4. Si válida: proceder a descifrar.
        5. Si inválida: rechazar (raise HybridVaultSignatureError).

    Args:
        signed_data:       Mismo blob que se firmó (_build_signed_data).
        signature:         64 bytes leídos del archivo 'signature'.
        signing_pub_bytes: Clave pública Ed25519 raw del firmante (32 bytes).

    Raises:
        HybridVaultSignatureError: Si la firma no es válida.
        HybridVaultFormatError:    Si la firma tiene tamaño incorrecto.
    """
    if len(signature) != ED25519_SIG_BYTES:
        raise HybridVaultFormatError(
            f"Firma inválida: se esperaban {ED25519_SIG_BYTES} bytes, "
            f"se recibieron {len(signature)}."
        )
    if len(signing_pub_bytes) != ED25519_PUB_BYTES:
        raise HybridVaultFormatError(
            f"Clave pública del firmante inválida: se esperaban {ED25519_PUB_BYTES} bytes."
        )
    try:
        public_key = Ed25519PublicKey.from_public_bytes(signing_pub_bytes)
        public_key.verify(signature, signed_data)
    except Exception as exc:
        raise HybridVaultSignatureError(
            "La firma digital Ed25519 del contenedor NO es válida.\n"
            "El contenedor pudo haber sido modificado, o la clave pública "
            "del firmante no corresponde al firmante real."
        ) from exc


# ──────────────────────────────────────────────────────────────────────────────
#  Protección de llaves privadas con KDF  (Scrypt + ChaCha20-Poly1305)
# ──────────────────────────────────────────────────────────────────────────────

def protect_private_key(private_key_hex: str, password: str) -> bytes:
    """
    Cifra una llave privada ECIES con contraseña usando Scrypt + ChaCha20-Poly1305.

    Formato del blob devuelto:
        [1B  version]
        [32B salt  (Scrypt)]
        [12B nonce (ChaCha20-Poly1305)]
        [var ciphertext + 16B tag]
    """
    if not password:
        raise ValueError("La contraseña no puede estar vacía.")

    salt  = os.urandom(KDF_SALT_BYTES)
    kdf   = Scrypt(salt=salt, length=KEY_SIZE_BYTES, n=KDF_N, r=KDF_R, p=KDF_P)
    key   = kdf.derive(password.encode("utf-8"))
    nonce = os.urandom(NONCE_SIZE_BYTES)
    aead  = ChaCha20Poly1305(key)

    buf = io.BytesIO()
    buf.write(struct.pack("B", ENCRYPTED_KEY_VERSION))
    buf.write(salt)
    buf.write(nonce)
    buf.write(aead.encrypt(nonce, private_key_hex.encode("utf-8"), None))
    return buf.getvalue()


def recover_private_key(protected_bytes: bytes, password: str) -> str:
    """
    Recupera la llave privada ECIES a partir del blob cifrado y la contraseña.

    Raises:
        HybridVaultAuthenticationError: Si la contraseña es incorrecta.
        HybridVaultFormatError:         Si el formato del blob es inválido.
    """
    if len(protected_bytes) < 1 + KDF_SALT_BYTES + NONCE_SIZE_BYTES + TAG_SIZE_BYTES + 1:
        raise HybridVaultFormatError("Blob de llave protegida demasiado corto.")

    buf     = io.BytesIO(protected_bytes)
    version = struct.unpack("B", buf.read(1))[0]
    if version != ENCRYPTED_KEY_VERSION:
        raise HybridVaultFormatError(
            f"Versión de llave protegida no soportada: {version}."
        )

    salt     = buf.read(KDF_SALT_BYTES)
    nonce    = buf.read(NONCE_SIZE_BYTES)
    combined = buf.read()

    kdf = Scrypt(salt=salt, length=KEY_SIZE_BYTES, n=KDF_N, r=KDF_R, p=KDF_P)
    key = kdf.derive(password.encode("utf-8"))

    try:
        return ChaCha20Poly1305(key).decrypt(nonce, combined, None).decode("utf-8")
    except InvalidTag as exc:
        raise HybridVaultAuthenticationError(
            "Contraseña incorrecta o blob de llave protegida alterado."
        ) from exc


# ──────────────────────────────────────────────────────────────────────────────
#  Cabecera (header)
# ──────────────────────────────────────────────────────────────────────────────

def _build_header(
    original_filename: str,
    plaintext_size:    int,
    recipients_count:  int,
    signer_id:         str,
) -> dict:
    """
    Construye el header del contenedor.
    """
    return {
        "magic":                    MAGIC,
        "container_version":        CONTAINER_VERSION,
        "aead_algorithm":           AEAD_ALGORITHM,
        "key_encryption_algorithm": KEY_ENCRYPTION_ALGORITHM,
        "signature_algorithm":      SIGNATURE_ALGORITHM,
        "key_size_bytes":           KEY_SIZE_BYTES,
        "nonce_size_bytes":         NONCE_SIZE_BYTES,
        "tag_size_bytes":           TAG_SIZE_BYTES,
        "created_at":               _utc_now_iso(),
        "original_filename":        original_filename,
        "plaintext_size":           plaintext_size,
        "recipients_count":         recipients_count,
        "signer_id":                signer_id,
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
        "signature_algorithm",
        "key_size_bytes",
        "nonce_size_bytes",
        "tag_size_bytes",
        "created_at",
        "original_filename",
        "plaintext_size",
        "recipients_count",
        "signer_id",
    }

    missing = required_fields - set(header.keys())
    if missing:
        raise HybridVaultFormatError(
            f"Header incompleto. Faltan campos: {sorted(missing)}"
        )

    if header["magic"] != MAGIC:
        raise HybridVaultFormatError("Magic inválido en header.")
    if header["container_version"] != CONTAINER_VERSION:
        raise HybridVaultFormatError(
            f"Versión de contenedor no soportada: {header['container_version']}. "
            f"Se esperaba: {CONTAINER_VERSION}."
        )
    if header["aead_algorithm"] != AEAD_ALGORITHM:
        raise HybridVaultFormatError("Algoritmo AEAD no soportado.")
    if header["key_encryption_algorithm"] != KEY_ENCRYPTION_ALGORITHM:
        raise HybridVaultFormatError("Algoritmo de cifrado de clave no soportado.")
    if header["signature_algorithm"] != SIGNATURE_ALGORITHM:
        raise HybridVaultFormatError("Algoritmo de firma no soportado.")
    if header["key_size_bytes"] != KEY_SIZE_BYTES:
        raise HybridVaultFormatError("Tamaño de clave inesperado en header.")
    if header["nonce_size_bytes"] != NONCE_SIZE_BYTES:
        raise HybridVaultFormatError("Tamaño de nonce inesperado en header.")
    if header["tag_size_bytes"] != TAG_SIZE_BYTES:
        raise HybridVaultFormatError("Tamaño de tag inesperado en header.")
    if not isinstance(header["plaintext_size"], int) or header["plaintext_size"] < 0:
        raise HybridVaultFormatError("plaintext_size inválido.")
    if not isinstance(header["recipients_count"], int) or header["recipients_count"] < 1:
        raise HybridVaultFormatError("recipients_count inválido (debe ser ≥ 1).")
    if not isinstance(header["signer_id"], str) or len(header["signer_id"]) != 64:
        raise HybridVaultFormatError("signer_id inválido (debe ser SHA-256 hex de 64 chars).")

    return header


# ──────────────────────────────────────────────────────────────────────────────
#  Serialización binaria de recipients (en memoria)
# ──────────────────────────────────────────────────────────────────────────────

def _serialize_recipients(recipients: list[dict]) -> bytes:
    """Serializa la lista de recipients a bytes (completamente en memoria)."""
    buf = io.BytesIO()
    buf.write(struct.pack(">I", len(recipients)))
    for r in recipients:
        id_b     = r["id"].encode("utf-8")
        key_id_b = r["key_id"].encode("utf-8")
        enc_key  = r["encrypted_key"]
        buf.write(struct.pack(">H", len(id_b)));     buf.write(id_b)
        buf.write(struct.pack(">H", len(key_id_b))); buf.write(key_id_b)
        buf.write(struct.pack(">I", len(enc_key)));  buf.write(enc_key)
    return buf.getvalue()


def _deserialize_recipients(data: bytes) -> list[dict]:
    """Deserializa recipients desde bytes."""
    if len(data) < 4:
        raise HybridVaultFormatError("Archivo recipients inválido o incompleto.")

    recipients = []
    offset     = 0
    count      = struct.unpack(">I", data[offset:offset + 4])[0]
    offset    += 4

    for _ in range(count):

        def _read(fmt: str, label: str) -> bytes:
            nonlocal offset
            sz = struct.calcsize(fmt)
            if offset + sz > len(data):
                raise HybridVaultFormatError(f"Recipients truncado ({label}_len).")
            (length,) = struct.unpack(fmt, data[offset:offset + sz])
            offset   += sz
            if offset + length > len(data):
                raise HybridVaultFormatError(f"Recipients truncado ({label}).")
            val     = data[offset:offset + length]
            offset += length
            return val

        recipients.append({
            "id":            _read(">H", "id").decode("utf-8"),
            "key_id":        _read(">H", "key_id").decode("utf-8"),
            "encrypted_key": _read(">I", "encrypted_key"),
        })

    if offset != len(data):
        raise HybridVaultFormatError("Archivo recipients tiene bytes extra o está corrupto.")

    return recipients


# ──────────────────────────────────────────────────────────────────────────────
#  I/O del contenedor en disco
# ──────────────────────────────────────────────────────────────────────────────

def _write_container(
    container_dir:    Path,
    header_bytes:     bytes,
    recipients_bytes: bytes,
    nonce:            bytes,
    ciphertext:       bytes,
    tag:              bytes,
    signature:        bytes,
) -> None:
    """
    Escribe el contenedor de forma atómica usando un directorio temporal + rename.

    Estructura del contenedor (D4):
        container_dir/
         ├── header            — JSON con metadatos y signer_id
         ├── recipients        — lista binaria de recipients con llaves cifradas
         ├── nonce             — nonce de ChaCha20-Poly1305
         ├── ciphertext        — contenido cifrado del archivo
         ├── authentication_tag — tag Poly1305
         └── signature         — firma Ed25519 de 64 bytes (raw)
    """
    tmp_dir = container_dir.parent / f".tmp_{container_dir.name}_{os.getpid()}"
    tmp_dir.mkdir(parents=True, exist_ok=False)
    try:
        (tmp_dir / "header").write_bytes(header_bytes)
        (tmp_dir / "recipients").write_bytes(recipients_bytes)
        (tmp_dir / "nonce").write_bytes(nonce)
        (tmp_dir / "ciphertext").write_bytes(ciphertext)
        (tmp_dir / "authentication_tag").write_bytes(tag)
        (tmp_dir / "signature").write_bytes(signature)
        tmp_dir.rename(container_dir)
    except Exception:
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise


def _read_container(
    container_dir: Path,
) -> tuple[bytes, bytes, bytes, bytes, bytes, bytes]:
    """
    Lee todos los componentes del contenedor de una sola vez.
    """
    if not container_dir.exists() or not container_dir.is_dir():
        raise HybridVaultFormatError("El contenedor no existe o no es un directorio válido.")

    try:
        header_bytes     = (container_dir / "header").read_bytes()
        recipients_bytes = (container_dir / "recipients").read_bytes()
        nonce            = (container_dir / "nonce").read_bytes()
        ciphertext       = (container_dir / "ciphertext").read_bytes()
        tag              = (container_dir / "authentication_tag").read_bytes()
        signature        = (container_dir / "signature").read_bytes()
    except FileNotFoundError as exc:
        raise HybridVaultFormatError(
            f"Falta un componente del contenedor: {exc}"
        ) from exc

    if len(nonce) != NONCE_SIZE_BYTES:
        raise HybridVaultFormatError("Nonce inválido: tamaño incorrecto.")
    if len(tag) != TAG_SIZE_BYTES:
        raise HybridVaultFormatError("Authentication tag inválido: tamaño incorrecto.")
    # Validación temprana del tamaño de la firma antes de cualquier operación
    if len(signature) != ED25519_SIG_BYTES:
        raise HybridVaultSignatureError(
            f"Archivo 'signature' tiene tamaño incorrecto ({len(signature)} bytes). "
            f"Se esperaban {ED25519_SIG_BYTES} bytes. "
            "El contenedor pudo haber sido manipulado."
        )

    return header_bytes, recipients_bytes, nonce, ciphertext, tag, signature


# ──────────────────────────────────────────────────────────────────────────────
#  API pública
# ──────────────────────────────────────────────────────────────────────────────

def encrypt_file_for_recipients(
    input_path:            str | Path,
    output_dir:            str | Path,
    recipient_public_keys: dict[str, str],
    signing_private_key:   bytes,
) -> Path:
    """
    Cifra un archivo para uno o más destinatarios y firma el contenedor con Ed25519.

    Flujo (D4): Encrypt → Add metadata → Sign → Store

    Args:
        input_path:            Ruta del archivo a cifrar.
        output_dir:            Directorio destino del contenedor (no debe existir).
        recipient_public_keys: {nombre: ecies_public_key_hex} — al menos 1.
        signing_private_key:   Clave privada Ed25519 raw (32 bytes) del firmante.

    Returns:
        Path del directorio contenedor creado.

    Raises:
        FileNotFoundError: Si el archivo de entrada no existe.
        ValueError:        Si no hay recipients, hay claves duplicadas, o la clave
                           de firma tiene tamaño incorrecto.
        FileExistsError:   Si output_dir ya existe.
    """
    input_path = Path(input_path)
    output_dir = Path(output_dir)

    if not input_path.exists() or not input_path.is_file():
        raise FileNotFoundError(f"Archivo de entrada no encontrado: {input_path}")
    if len(recipient_public_keys) < 1:
        raise ValueError("Debes proporcionar al menos 1 recipient.")
    if output_dir.exists():
        raise FileExistsError(
            f"Ya existe el directorio destino: {output_dir}. "
            "Elige otra carpeta o renombra el existente."
        )
    if len(signing_private_key) != 32:
        raise ValueError(
            f"La clave privada Ed25519 debe tener 32 bytes, "
            f"se recibieron {len(signing_private_key)}."
        )

    # ── Validación de tamaño de archivo ──────────────────────────────────────
    file_size = input_path.stat().st_size
    if file_size > MAX_FILE_SIZE:
        raise HybridVaultFileSizeError(
            f"Archivo demasiado grande: {file_size / (1024 * 1024):.2f}MB. "
            f"Tamaño máximo permitido: {MAX_FILE_SIZE / (1024 * 1024):.0f}MB."
        )

    # ── 1. Leer plaintext ────────────────────────────────────────────────────
    plaintext = input_path.read_bytes()

    # ── 2. Generar file_key y nonce ──────────────────────────────────────────
    file_key = ChaCha20Poly1305.generate_key()
    nonce    = os.urandom(NONCE_SIZE_BYTES)

    # ── 3. Construir lista de recipients ────────────────────────────────────
    recipients   = []
    seen_key_ids = set()
    for user_id, public_key_hex in recipient_public_keys.items():
        key_id = public_key_fingerprint(public_key_hex)
        if key_id in seen_key_ids:
            raise ValueError(f"Clave pública duplicada para el recipient '{user_id}'.")
        seen_key_ids.add(key_id)
        recipients.append({
            "id":            user_id,
            "key_id":        key_id,
            "encrypted_key": ecies_encrypt(public_key_hex, file_key),
        })

    # ── 4. Calcular signer_id y construir header ─────────────────────────────
    signing_pub_bytes = Ed25519PrivateKey.from_private_bytes(
        signing_private_key
    ).public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

    sid          = signer_id_from_public_key(signing_pub_bytes)
    header       = _build_header(
        original_filename = input_path.name,
        plaintext_size    = len(plaintext),
        recipients_count  = len(recipients),
        signer_id         = sid,
    )
    header_bytes     = _canonical_json(header)
    recipients_bytes = _serialize_recipients(recipients)

    # ── 5. Cifrar con AEAD (D2/D3) ───────────────────────────────────────────
    aad      = header_bytes + recipients_bytes
    combined = ChaCha20Poly1305(file_key).encrypt(nonce, plaintext, aad)
    ciphertext = combined[:-TAG_SIZE_BYTES]
    tag        = combined[-TAG_SIZE_BYTES:]

    # ── 6. Firmar el contenedor completo con Ed25519 (D4) ────────────────────
    # Datos firmados = header + recipients + nonce + ciphertext + tag
    # (todo lo necesario para detectar cualquier modificación post-cifrado)
    signed_data = _build_signed_data(header_bytes, recipients_bytes, nonce, ciphertext, tag)
    signature   = sign_container(signed_data, signing_private_key)

    # ── 7. Escritura atómica ─────────────────────────────────────────────────
    _write_container(
        container_dir    = output_dir,
        header_bytes     = header_bytes,
        recipients_bytes = recipients_bytes,
        nonce            = nonce,
        ciphertext       = ciphertext,
        tag              = tag,
        signature        = signature,
    )

    return output_dir


def decrypt_file_for_recipient(
    container_dir:             str | Path,
    recipient_private_key_hex: str,
    recipient_public_key_hex:  str,
    output_path:               str | Path,
    signing_public_key:        bytes,
) -> tuple[Path, dict]:
    """
    Descifra un contenedor verificando primero la firma digital.

    Flujo (D4):
        1. Leer todos los componentes del contenedor.
        2. Validar formato del header.
        3. Verificar firma Ed25519 → si inválida: rechazar (raise HybridVaultSignatureError).
        4. Solo si la firma es válida: recuperar file_key con ECIES.
        5. Descifrar con AEAD.

    Args:
        container_dir:             Ruta del directorio contenedor.
        recipient_private_key_hex: Clave privada ECIES del destinatario (hex).
        recipient_public_key_hex:  Clave pública ECIES del destinatario (hex).
        output_path:               Ruta donde guardar el archivo descifrado.
        signing_public_key:        Clave pública Ed25519 raw del firmante (32 bytes).

    Returns:
        (output_path, info_dict)

    Raises:
        HybridVaultSignatureError:       Si la firma es inválida (el contenedor
                                         fue modificado o el firmante no coincide).
        HybridVaultAuthenticationError:  Si ECIES o AEAD fallan.
        HybridVaultFormatError:          Si el contenedor está dañado.
    """
    container_dir = Path(container_dir)
    output_path   = Path(output_path)

    # ── 1. Leer todos los componentes de una sola vez ────────────────────────
    header_bytes, recipients_bytes, nonce, ciphertext, tag, signature = \
        _read_container(container_dir)

    # ── 2. Validar formato del header ────────────────────────────────────────
    header     = _validate_header(header_bytes)
    recipients = _deserialize_recipients(recipients_bytes)

    if header["recipients_count"] != len(recipients):
        raise HybridVaultFormatError("El número de recipients no coincide con el header.")

    # ── 3. VERIFICAR FIRMA ANTES DE DESCIFRAR ────────────────────────────────
    signed_data = _build_signed_data(header_bytes, recipients_bytes, nonce, ciphertext, tag)
    verify_signature(signed_data, signature, signing_public_key)
    # Si verify_signature no lanza excepción, la firma es válida → continuar

    # ── 4. Localizar entrada del destinatario ────────────────────────────────
    my_key_id = public_key_fingerprint(recipient_public_key_hex)
    entry     = next((r for r in recipients if r["key_id"] == my_key_id), None)
    if entry is None:
        raise HybridVaultFormatError(
            "No existe una entrada de recipient para esta clave pública."
        )

    # ── 5. Recuperar file_key con ECIES ──────────────────────────────────────
    try:
        file_key = ecies_decrypt(recipient_private_key_hex, entry["encrypted_key"])
    except Exception as exc:
        raise HybridVaultAuthenticationError(
            "No fue posible recuperar la file key con la clave privada proporcionada."
        ) from exc

    if len(file_key) != KEY_SIZE_BYTES:
        raise HybridVaultFormatError("La file key recuperada tiene tamaño inválido.")

    # ── 6. Descifrar con AEAD ────────────────────────────────────────────────
    aad      = header_bytes + recipients_bytes
    combined = ciphertext + tag
    try:
        plaintext = ChaCha20Poly1305(file_key).decrypt(nonce, combined, aad)
    except InvalidTag as exc:
        raise HybridVaultAuthenticationError(
            "Falló la autenticación AEAD del contenedor. "
            "El header, recipients, nonce, ciphertext o tag fueron alterados."
        ) from exc

    if len(plaintext) != header["plaintext_size"]:
        raise HybridVaultFormatError(
            "El tamaño del plaintext descifrado no coincide con el header."
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(plaintext)

    return output_path, {
        "original_filename": header.get("original_filename"),
        "created_at":        header.get("created_at"),
        "signer_id":         header.get("signer_id"),
        "recipients":        [{"id": r["id"], "key_id": r["key_id"]} for r in recipients],
        "plaintext_size":    header.get("plaintext_size"),
    }


def get_container_info(container_dir: str | Path) -> dict:
    """
    Extrae metadatos de un contenedor sin descifrarlo ni verificar la firma.

    Útil para inspeccionar recipients, fecha de creación, signer_id, etc.
    """
    container_dir = Path(container_dir)
    header_bytes, recipients_bytes, *_ = _read_container(container_dir)
    header     = _validate_header(header_bytes)
    recipients = _deserialize_recipients(recipients_bytes)

    return {
        "original_filename": header.get("original_filename"),
        "created_at":        header.get("created_at"),
        "container_version": header.get("container_version"),
        "signature_algorithm": header.get("signature_algorithm"),
        "signer_id":         header.get("signer_id"),
        "recipients":        [{"id": r["id"], "key_id": r["key_id"]} for r in recipients],
        "plaintext_size":    header.get("plaintext_size"),
    }
