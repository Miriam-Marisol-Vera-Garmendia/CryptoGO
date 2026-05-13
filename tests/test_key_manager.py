"""
test_key_manager.py — D6: Tests Automatizados del Sistema de Gestión de Claves
===============================================================================

Cubre los 5 casos requeridos:
  1. Contraseña correcta → acceso concedido
  2. Contraseña incorrecta → acceso denegado
  3. Keystore modificado → fallo
  4. Backup → restauración exitosa
  5. Keystore robado solo → no puede descifrar

También verifica:
  - Compatibilidad con hybrid_vault.py (D3/D4)
  - Rotación de claves
  - Inspección de metadata sin contraseña
"""

import os
import sys
import json
import tempfile
import traceback
from pathlib import Path

from cryptogo.encryption.key_manager import (
    KEY_TYPE_ECIES,
    KEY_TYPE_ED25519,
    KeyManagerAuthError,
    KeyManagerFormatError,
    backup_keystore,
    get_keystore_info,
    protect_private_key,
    recover_private_key,
    rotate_key,
)
from cryptogo.encryption.hybrid_vault import (
    decrypt_file_for_recipient,
    encrypt_file_for_recipients,
    generate_ecies_keypair,
    generate_signing_keypair,
)

DIVIDER = "─" * 60
passed = 0
failed = 0


def run_test(name: str, fn):
    global passed, failed
    print(f"\n  TEST: {name}")
    try:
        fn()
        print(f"  ✔  PASÓ")
        passed += 1
    except Exception as exc:
        print(f"  ✗  FALLÓ: {exc}")
        traceback.print_exc()
        failed += 1


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 1: Contraseña correcta → acceso concedido
# ══════════════════════════════════════════════════════════════════════════════

def test_contrasena_correcta_acceso_concedido():
    """
    Verifica que una clave privada cifrada se puede recuperar
    cuando se proporciona la contraseña correcta.
    """
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        # Generar clave ECIES
        priv_hex, pub_hex = generate_ecies_keypair()
        ks_dir = tmp / "mi_keystore_ecies"
        password = "ContraseñaSegura2025!"

        # Cifrar y guardar
        protect_private_key(
            key_material=priv_hex,
            key_type=KEY_TYPE_ECIES,
            password=password,
            keystore_dir=ks_dir,
            label="clave-ecies-alice",
        )

        # Recuperar con contraseña correcta
        recovered, key_type, metadata = recover_private_key(ks_dir, password)

        assert recovered == priv_hex, "La clave recuperada debe ser idéntica a la original."
        assert key_type == KEY_TYPE_ECIES
        assert metadata["label"] == "clave-ecies-alice"
        print(f"    key_id     : {metadata['key_id'][:16]}...")
        print(f"    created_at : {metadata['created_at']}")


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 2: Contraseña incorrecta → acceso denegado
# ══════════════════════════════════════════════════════════════════════════════

def test_contrasena_incorrecta_acceso_denegado():
    """
    Verifica que una contraseña incorrecta impide recuperar la clave.
    La excepción debe ser KeyManagerAuthError.
    """
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        priv_hex, _ = generate_ecies_keypair()
        ks_dir = tmp / "ks_test2"
        protect_private_key(
            key_material=priv_hex,
            key_type=KEY_TYPE_ECIES,
            password="ContraseñaReal",
            keystore_dir=ks_dir,
        )

        try:
            recover_private_key(ks_dir, "ContraseñaFalsa")
            raise AssertionError("Debió lanzar KeyManagerAuthError pero no lo hizo.")
        except KeyManagerAuthError as e:
            print(f"    Rechazado correctamente: {e}")

        # Verificar también con variaciones de la contraseña real
        for wrong in ["contraseñareal", "ContraseñaReal ", "ContraseñaReal1", ""]:
            try:
                recover_private_key(ks_dir, wrong)
                raise AssertionError(f"Debió rechazar la contraseña '{wrong}'")
            except KeyManagerAuthError:
                pass  # Correcto


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 3: Keystore modificado → fallo
# ══════════════════════════════════════════════════════════════════════════════

def test_keystore_modificado_falla():
    """
    Verifica que si cualquier componente del keystore es alterado,
    el sistema rechaza la recuperación de la clave.

    Demuestra integridad del keystore: la AAD vincula salt+nonce al ciphertext.
    """
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        priv_hex, _ = generate_ecies_keypair()
        password = "MiContraseña"
        ks_dir = tmp / "ks_test3"
        protect_private_key(
            key_material=priv_hex,
            key_type=KEY_TYPE_ECIES,
            password=password,
            keystore_dir=ks_dir,
        )

        # 3a: Alterar ciphertext
        enc_path = ks_dir / "encrypted_key"
        original = enc_path.read_bytes()
        tampered = bytes([original[0] ^ 0xFF]) + original[1:]
        enc_path.write_bytes(tampered)

        try:
            recover_private_key(ks_dir, password)
            raise AssertionError("Debió rechazar ciphertext alterado.")
        except KeyManagerAuthError:
            print("    [3a] Ciphertext alterado → rechazado ✓")

        # Restaurar ciphertext
        enc_path.write_bytes(original)

        # 3b: Alterar salt (cambia la derivación KDF → tag inválido)
        salt_path = ks_dir / "salt"
        original_salt = salt_path.read_bytes()
        tampered_salt = bytes([original_salt[0] ^ 0x01]) + original_salt[1:]
        salt_path.write_bytes(tampered_salt)

        try:
            recover_private_key(ks_dir, password)
            raise AssertionError("Debió rechazar salt alterado.")
        except KeyManagerAuthError:
            print("    [3b] Salt alterado → rechazado ✓")

        # Restaurar salt
        salt_path.write_bytes(original_salt)

        # 3c: Eliminar componente
        (ks_dir / "nonce").unlink()
        try:
            recover_private_key(ks_dir, password)
            raise AssertionError("Debió fallar sin componente 'nonce'.")
        except KeyManagerFormatError:
            print("    [3c] Componente faltante → rechazado ✓")


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 4: Backup → restauración exitosa
# ══════════════════════════════════════════════════════════════════════════════

def test_backup_y_restauracion():
    """
    Verifica que un keystore puede respaldarse y restaurarse correctamente.
    El backup es un directorio con los mismos archivos cifrados (sin exponer la clave).
    """
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        priv_bytes, pub_bytes, _ = generate_signing_keypair()
        password = "BackupSeguro!"
        ks_dir  = tmp / "ks_original"
        bkp_dir = tmp / "ks_backup"

        protect_private_key(
            key_material=priv_bytes,
            key_type=KEY_TYPE_ED25519,
            password=password,
            keystore_dir=ks_dir,
            label="clave-firma-bob",
        )

        # Hacer backup
        backup_keystore(ks_dir, bkp_dir)

        # Verificar que el backup contiene los mismos archivos
        for fname in ["metadata", "salt", "nonce", "encrypted_key"]:
            assert (bkp_dir / fname).exists(), f"Falta {fname} en el backup"

        # Recuperar desde el backup con la misma contraseña
        recovered, key_type, metadata = recover_private_key(bkp_dir, password)

        assert recovered == priv_bytes, "La clave restaurada desde backup debe ser idéntica."
        assert key_type == KEY_TYPE_ED25519
        assert metadata["label"] == "clave-firma-bob"

        # Simular pérdida del original y uso del backup
        import shutil
        shutil.rmtree(ks_dir)
        assert not ks_dir.exists()

        recovered2, _, _ = recover_private_key(bkp_dir, password)
        assert recovered2 == priv_bytes, "Debe recuperarse desde backup tras perder el original."
        print(f"    Backup creado y restaurado. key_type: {key_type}")


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 5: Keystore robado solo → no puede descifrar
# ══════════════════════════════════════════════════════════════════════════════

def test_keystore_robado_sin_contrasena():
    """
    Verifica que un atacante que roba el directorio keystore no puede
    recuperar la clave privada sin conocer la contraseña.

    El keystore solo contiene material cifrado — sin la contraseña,
    la clave privada es inaccesible.
    """
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        priv_hex, _ = generate_ecies_keypair()
        password = "ContraseñaMuySegura#99"
        ks_dir = tmp / "ks_test5"
        protect_private_key(
            key_material=priv_hex,
            key_type=KEY_TYPE_ECIES,
            password=password,
            keystore_dir=ks_dir,
        )

        # El "atacante" tiene el directorio completo pero no sabe la contraseña
        intentos_fallidos = 0
        for contrasena_atacante in [
            "password", "123456", "admin", "qwerty", "",
            "ContraseñaMuySegura", "contraseñamuysegura#99",
        ]:
            try:
                recover_private_key(ks_dir, contrasena_atacante)
                raise AssertionError(f"El atacante NO debe poder usar '{contrasena_atacante}'")
            except KeyManagerAuthError:
                intentos_fallidos += 1

        print(f"    {intentos_fallidos} intentos de acceso rechazados sin contraseña correcta.")

        # La clave correcta sí funciona (confirmar que el keystore es válido)
        recovered, _, _ = recover_private_key(ks_dir, password)
        assert recovered == priv_hex
        print(f"    Con contraseña correcta: acceso concedido ✓")


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 6 (BONUS): Integración con hybrid_vault — flujo completo
# ══════════════════════════════════════════════════════════════════════════════

def test_integracion_con_hybrid_vault():
    """
    Verifica el flujo completo D3+D4+D5:
      1. Generar y proteger claves con el gestor de claves (D5).
      2. Cifrar un archivo para un destinatario (D3).
      3. Recuperar la clave privada del keystore con contraseña (D5).
      4. Descifrar el archivo verificando la firma (D4).
    """
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        # ── Generar claves ───────────────────────────────────────────────────
        alice_priv_hex, alice_pub_hex = generate_ecies_keypair()
        signer_priv_bytes, signer_pub_bytes, signer_id = generate_signing_keypair()

        # ── Proteger claves con D5 ───────────────────────────────────────────
        alice_ks = tmp / "alice_keystore"
        signer_ks = tmp / "signer_keystore"

        protect_private_key(
            key_material=alice_priv_hex,
            key_type=KEY_TYPE_ECIES,
            password="alice_password_2025",
            keystore_dir=alice_ks,
            label="alice-ecies",
        )
        protect_private_key(
            key_material=signer_priv_bytes,
            key_type=KEY_TYPE_ED25519,
            password="signer_password_2025",
            keystore_dir=signer_ks,
            label="signer-ed25519",
        )

        # ── Crear archivo de prueba ──────────────────────────────────────────
        doc = tmp / "documento.pdf"
        doc.write_bytes(b"Contenido confidencial del documento PDF para D6.")

        # Recuperar clave de firma para cifrar
        signer_key_recovered, _, _ = recover_private_key(signer_ks, "signer_password_2025")

        container = tmp / "contenedor"
        encrypt_file_for_recipients(
            input_path=doc,
            output_dir=container,
            recipient_public_keys={"alice": alice_pub_hex},
            signing_private_key=signer_key_recovered,
        )

        # ── Recuperar clave privada de Alice desde keystore ──────────────────
        alice_key_recovered, _, _ = recover_private_key(alice_ks, "alice_password_2025")

        # ── Descifrar (verificando firma D4) ────────────────────────────────
        output = tmp / "descifrado.pdf"
        result_path, info = decrypt_file_for_recipient(
            container_dir=container,
            recipient_private_key_hex=alice_key_recovered,
            recipient_public_key_hex=alice_pub_hex,
            output_path=output,
            signing_public_key=signer_pub_bytes,
        )

        assert result_path.exists()
        assert result_path.read_bytes() == b"Contenido confidencial del documento PDF para D6."
        assert info["signer_id"] == signer_id
        print(f"    Flujo D3+D4+D5 completo exitoso.")
        print(f"    signer_id: {info['signer_id'][:16]}...")


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 7 (BONUS): Rotación de claves
# ══════════════════════════════════════════════════════════════════════════════

def test_rotacion_de_claves():
    """
    Verifica que la rotación genera una clave nueva diferente a la anterior,
    y que ambos keystores son accesibles con sus respectivas contraseñas.
    """
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        priv_hex, _ = generate_ecies_keypair()
        old_ks = tmp / "ks_old"
        new_ks = tmp / "ks_new"

        protect_private_key(
            key_material=priv_hex,
            key_type=KEY_TYPE_ECIES,
            password="contraseña_vieja",
            keystore_dir=old_ks,
        )

        # Rotar
        new_ks_path, new_material = rotate_key(
            old_keystore_dir=old_ks,
            old_password="contraseña_vieja",
            new_keystore_dir=new_ks,
            new_password="contraseña_nueva_2025",
        )

        # La nueva clave debe ser diferente
        assert new_material != priv_hex, "La clave rotada debe ser diferente a la original."

        # El nuevo keystore funciona con la nueva contraseña
        recovered_new, _, _ = recover_private_key(new_ks_path, "contraseña_nueva_2025")
        assert recovered_new == new_material

        # El antiguo keystore sigue funcionando (hasta que se elimine conscientemente)
        recovered_old, _, _ = recover_private_key(old_ks, "contraseña_vieja")
        assert recovered_old == priv_hex

        print(f"    Rotación exitosa. Clave nueva diferente a la anterior ✓")


# ══════════════════════════════════════════════════════════════════════════════
#  TEST 8 (BONUS): Inspección de metadata sin contraseña
# ══════════════════════════════════════════════════════════════════════════════

def test_inspeccion_sin_contrasena():
    """
    Verifica que se pueden leer los metadatos del keystore
    sin proporcionar contraseña (sin revelar la clave privada).
    """
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        priv_hex, _ = generate_ecies_keypair()
        ks_dir = tmp / "ks_inspect"
        protect_private_key(
            key_material=priv_hex,
            key_type=KEY_TYPE_ECIES,
            password="cualquier_contraseña",
            keystore_dir=ks_dir,
            label="mi-clave-ecies",
        )

        info = get_keystore_info(ks_dir)

        assert info["magic"]     == "CRYPTOGO_KEYSTORE"
        assert info["key_type"]  == KEY_TYPE_ECIES
        assert info["label"]     == "mi-clave-ecies"
        assert info["kdf"]       == "scrypt"
        assert "encrypted_key"   not in str(info)  # La clave NO está en metadata

        print(f"    Metadata visible: key_id={info['key_id'][:16]}..., label={info['label']}")


# ══════════════════════════════════════════════════════════════════════════════
#  Ejecución
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print()
    print("=" * 60)
    print("  CryptoGO Secure Vault — Tests D6 (Gestión de Claves)")
    print("=" * 60)

    tests = [
        ("1. Contraseña correcta → acceso concedido",      test_contrasena_correcta_acceso_concedido),
        ("2. Contraseña incorrecta → acceso denegado",     test_contrasena_incorrecta_acceso_denegado),
        ("3. Keystore modificado → fallo",                 test_keystore_modificado_falla),
        ("4. Backup → restauración exitosa",               test_backup_y_restauracion),
        ("5. Keystore robado solo → no puede descifrar",   test_keystore_robado_sin_contrasena),
        ("6. Integración con hybrid_vault (D3+D4+D5)",     test_integracion_con_hybrid_vault),
        ("7. Rotación de claves",                          test_rotacion_de_claves),
        ("8. Inspección de metadata sin contraseña",       test_inspeccion_sin_contrasena),
    ]

    for name, fn in tests:
        run_test(name, fn)

    print()
    print("=" * 60)
    print(f"  Resultado: {passed} pasaron, {failed} fallaron")
    print("=" * 60)
    print()
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
