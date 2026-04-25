
import os
import sys
import tempfile
import pytest
from pathlib import Path

# Permite ejecutar desde la raíz del proyecto
sys.path.insert(0, str(Path(__file__).parent))

from encryption.hybrid_vault import (
    encrypt_file_for_recipients,
    decrypt_file_for_recipient,
    generate_ecies_keypair,
    generate_signing_keypair,
    HybridVaultSignatureError,
    HybridVaultFormatError,
    HybridVaultAuthenticationError,
)


# ──────────────────────────────────────────────────────────────────────────────
#  Fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_dir(tmp_path):
    return tmp_path

@pytest.fixture
def alice_ecies():
    """Par de claves ECIES de Alice (destinataria)."""
    priv, pub = generate_ecies_keypair()
    return {"priv": priv, "pub": pub}

@pytest.fixture
def signer_keys():
    """Par de claves Ed25519 del firmante."""
    priv_bytes, pub_bytes, sid = generate_signing_keypair()
    return {"priv": priv_bytes, "pub": pub_bytes, "sid": sid}

@pytest.fixture
def other_signer_keys():
    """Par de claves Ed25519 de un firmante diferente (para test 4)."""
    priv_bytes, pub_bytes, sid = generate_signing_keypair()
    return {"priv": priv_bytes, "pub": pub_bytes, "sid": sid}

@pytest.fixture
def plaintext_file(tmp_path):
    """Archivo de prueba con contenido conocido."""
    p = tmp_path / "documento_secreto.txt"
    p.write_bytes(b"Contenido confidencial para prueba de firma digital D4.")
    return p

@pytest.fixture
def valid_container(tmp_path, plaintext_file, alice_ecies, signer_keys):
    """Contenedor cifrado y firmado correctamente."""
    container_dir = tmp_path / "contenedor_valido"
    encrypt_file_for_recipients(
        input_path            = plaintext_file,
        output_dir            = container_dir,
        recipient_public_keys = {"alice": alice_ecies["pub"]},
        signing_private_key   = signer_keys["priv"],
    )
    return container_dir

# ──────────────────────────────────────────────────────────────────────────────
#  Test 1: Firma válida → archivo aceptado
# ──────────────────────────────────────────────────────────────────────────────

def test_firma_valida_archivo_aceptado(tmp_path, valid_container, alice_ecies, signer_keys):
    """
    Caso 1: Firma válida → el archivo se descifra correctamente.

    Verifica que el flujo completo Encrypt → Sign → Verify → Decrypt
    funciona cuando todos los datos son correctos y no han sido modificados.
    """
    output = tmp_path / "resultado.txt"

    result_path, info = decrypt_file_for_recipient(
        container_dir             = valid_container,
        recipient_private_key_hex = alice_ecies["priv"],
        recipient_public_key_hex  = alice_ecies["pub"],
        output_path               = output,
        signing_public_key        = signer_keys["pub"],
    )

    assert result_path.exists(), "El archivo descifrado debe existir."
    assert result_path.read_bytes() == b"Contenido confidencial para prueba de firma digital D4."
    assert info["signer_id"] == signer_keys["sid"], "El signer_id debe coincidir."
    assert info["original_filename"] == "documento_secreto.txt"


# ──────────────────────────────────────────────────────────────────────────────
#  Test 2: Ciphertext alterado → rechazado
# ──────────────────────────────────────────────────────────────────────────────

def test_ciphertext_alterado_rechazado(tmp_path, valid_container, alice_ecies, signer_keys):
    """
    Caso 2: Si el ciphertext es modificado después de firmar, la verificación
    de la firma debe fallar y el descifrado debe ser rechazado.

    Esto demuestra que la firma cubre el ciphertext (no solo los metadatos).
    """
    # Alterar el ciphertext
    ciphertext_path = valid_container / "ciphertext"
    original = ciphertext_path.read_bytes()
    # Flip del primer byte
    tampered = bytes([original[0] ^ 0xFF]) + original[1:]
    ciphertext_path.write_bytes(tampered)

    output = tmp_path / "no_debe_crearse.txt"

    with pytest.raises(HybridVaultSignatureError):
        decrypt_file_for_recipient(
            container_dir             = valid_container,
            recipient_private_key_hex = alice_ecies["priv"],
            recipient_public_key_hex  = alice_ecies["pub"],
            output_path               = output,
            signing_public_key        = signer_keys["pub"],
        )

    assert not output.exists(), "El archivo NO debe haberse creado cuando la firma falla."


# ──────────────────────────────────────────────────────────────────────────────
#  Test 3: Metadatos alterados → rechazado
# ──────────────────────────────────────────────────────────────────────────────

def test_metadatos_alterados_rechazado(tmp_path, valid_container, alice_ecies, signer_keys):
    """
    Caso 3: Si el header (metadatos) es modificado después de firmar, la
    verificación de la firma debe fallar.

    Esto demuestra que la firma cubre los metadatos (header_bytes), protegiéndolos
    contra ataques de manipulación de contexto.
    """
    import json

    header_path = valid_container / "header"
    header = json.loads(header_path.read_bytes().decode("utf-8"))

    # Modificar el nombre del archivo original en los metadatos
    header["original_filename"] = "archivo_falso_inyectado.exe"

    # Reescribir el header alterado (serialización no canónica a propósito)
    header_path.write_bytes(json.dumps(header).encode("utf-8"))

    output = tmp_path / "no_debe_crearse.txt"

    with pytest.raises(HybridVaultSignatureError):
        decrypt_file_for_recipient(
            container_dir             = valid_container,
            recipient_private_key_hex = alice_ecies["priv"],
            recipient_public_key_hex  = alice_ecies["pub"],
            output_path               = output,
            signing_public_key        = signer_keys["pub"],
        )

    assert not output.exists(), "El archivo NO debe haberse creado cuando la firma falla."


# ──────────────────────────────────────────────────────────────────────────────
#  Test 4: Clave pública incorrecta → rechazado
# ──────────────────────────────────────────────────────────────────────────────

def test_clave_publica_incorrecta_rechazada(
    tmp_path, valid_container, alice_ecies, signer_keys, other_signer_keys
):
    """
    Caso 4: Si se usa la clave pública de un firmante diferente para verificar,
    la verificación debe fallar.

    Esto demuestra protección contra suplantación de identidad del remitente:
    solo quien posea la clave privada correspondiente puede haber firmado el contenedor.
    """
    output = tmp_path / "no_debe_crearse.txt"

    # Intentar verificar con la clave pública del firmante equivocado
    with pytest.raises(HybridVaultSignatureError):
        decrypt_file_for_recipient(
            container_dir             = valid_container,
            recipient_private_key_hex = alice_ecies["priv"],
            recipient_public_key_hex  = alice_ecies["pub"],
            output_path               = output,
            signing_public_key        = other_signer_keys["pub"],  # clave incorrecta
        )

    assert not output.exists(), "El archivo NO debe haberse creado con clave de firmante incorrecta."


# ──────────────────────────────────────────────────────────────────────────────
#  Test 5: Firma eliminada → rechazado
# ──────────────────────────────────────────────────────────────────────────────

def test_firma_eliminada_rechazada(tmp_path, valid_container, alice_ecies, signer_keys):
    """
    Caso 5: Si el archivo 'signature' es eliminado del contenedor, el sistema
    debe rechazar el descifrado.

    Esto demuestra que la firma es un requisito obligatorio y no opcional.
    Un atacante no puede simplemente borrar la firma para evadir la verificación.
    """
    # Eliminar el archivo de firma
    (valid_container / "signature").unlink()

    output = tmp_path / "no_debe_crearse.txt"

    # Debe lanzar HybridVaultFormatError (componente faltante) o
    # HybridVaultSignatureError (según el punto de detección)
    with pytest.raises((HybridVaultFormatError, HybridVaultSignatureError)):
        decrypt_file_for_recipient(
            container_dir             = valid_container,
            recipient_private_key_hex = alice_ecies["priv"],
            recipient_public_key_hex  = alice_ecies["pub"],
            output_path               = output,
            signing_public_key        = signer_keys["pub"],
        )

    assert not output.exists(), "El archivo NO debe haberse creado sin firma presente."


# ──────────────────────────────────────────────────────────────────────────────
#  Ejecución directa (sin pytest)
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback

    tests = [
        test_firma_valida_archivo_aceptado,
        test_ciphertext_alterado_rechazado,
        test_metadatos_alterados_rechazado,
        test_clave_publica_incorrecta_rechazada,
        test_firma_eliminada_rechazada,
    ]

    passed = 0
    failed = 0

    print("=" * 60)
    print("  CryptoGO Secure Vault — Tests D4 (Firma Digital)")
    print("=" * 60)

    for test_fn in tests:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)

            # Preparar fixtures manualmente
            priv_e, pub_e = generate_ecies_keypair()
            alice = {"priv": priv_e, "pub": pub_e}

            priv_s, pub_s, sid_s = generate_signing_keypair()
            signer = {"priv": priv_s, "pub": pub_s, "sid": sid_s}

            priv_o, pub_o, _ = generate_signing_keypair()
            other = {"priv": priv_o, "pub": pub_o}

            plaintext_p = tmp / "documento_secreto.txt"
            plaintext_p.write_bytes(b"Contenido confidencial para prueba de firma digital D4.")

            container_p = tmp / "contenedor"
            encrypt_file_for_recipients(
                input_path            = plaintext_p,
                output_dir            = container_p,
                recipient_public_keys = {"alice": alice["pub"]},
                signing_private_key   = signer["priv"],
            )

            try:
                # Pasar fixtures según los parámetros del test
                import inspect
                params = inspect.signature(test_fn).parameters
                kwargs: dict = {}
                if "tmp_path"       in params: kwargs["tmp_path"]       = tmp
                if "valid_container" in params: kwargs["valid_container"] = container_p
                if "alice_ecies"    in params: kwargs["alice_ecies"]    = alice
                if "signer_keys"    in params: kwargs["signer_keys"]    = signer
                if "other_signer_keys" in params: kwargs["other_signer_keys"] = other

                test_fn(**kwargs)
                print(f"  ✔  {test_fn.__name__}")
                passed += 1
            except Exception:
                print(f"  ✗  {test_fn.__name__}")
                traceback.print_exc()
                failed += 1

    print("=" * 60)
    print(f"  Resultado: {passed} pasaron, {failed} fallaron")
    print("=" * 60)
    sys.exit(0 if failed == 0 else 1)
