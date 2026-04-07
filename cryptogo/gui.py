import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from datetime import datetime
from pathlib import Path

from ecies.utils import generate_key

from encryption.hybrid_vault import (
    encrypt_file_for_recipients,
    decrypt_file_for_recipient,
)
from encryption import HybridVaultAuthenticationError, HybridVaultFormatError

selected_file = None


# ─────────────────────────── Helpers ────────────────────────────────────────

def copy_to_clipboard(text: str):
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()


def get_recipients() -> dict[str, str]:
    """Lee los campos de recipients y devuelve {nombre: pubkey_hex}."""
    recipients = {}
    for name_entry, key_entry in recipient_rows:
        name = name_entry.get().strip()
        key = key_entry.get().strip()
        if name and key:
            recipients[name] = key
    return recipients


# ─────────────────────────── Generar par de claves ──────────────────────────

def generate_keypair():
    sk = generate_key()
    private_hex = sk.secret.hex()
    public_hex = sk.public_key.format(compressed=False).hex()

    win = tk.Toplevel(root)
    win.title("Par de claves generado")
    win.geometry("620x280")
    win.resizable(False, False)

    tk.Label(win, text="🔑 Clave Pública (comparte con quienes cifren para ti):",
             font=("Consolas", 9, "bold")).pack(anchor="w", padx=10, pady=(10, 0))
    pub_box = tk.Entry(win, width=88)
    pub_box.insert(0, public_hex)
    pub_box.config(state="readonly")
    pub_box.pack(padx=10)

    tk.Label(win, text="🔒 Clave Privada (guárdala en secreto, NO la compartas):",
             font=("Consolas", 9, "bold"), fg="red").pack(anchor="w", padx=10, pady=(10, 0))
    priv_box = tk.Entry(win, width=88, show="*")
    priv_box.insert(0, private_hex)
    priv_box.config(state="readonly")
    priv_box.pack(padx=10)

    def reveal():
        priv_box.config(show="" if priv_box.cget("show") == "*" else "*")

    def copy_priv():
        copy_to_clipboard(private_hex)
        messagebox.showinfo("Copiado", "Clave privada copiada al portapapeles.", parent=win)

    def copy_pub():
        copy_to_clipboard(public_hex)
        messagebox.showinfo("Copiado", "Clave pública copiada al portapapeles.", parent=win)

    btn_frame = tk.Frame(win)
    btn_frame.pack(pady=10)
    tk.Button(btn_frame, text="Mostrar/Ocultar privada", command=reveal).pack(side="left", padx=5)
    tk.Button(btn_frame, text="Copiar privada", command=copy_priv).pack(side="left", padx=5)
    tk.Button(btn_frame, text="Copiar pública", command=copy_pub).pack(side="left", padx=5)


# ─────────────────────────── Seleccionar archivo ────────────────────────────

def select_file():
    global selected_file
    selected_file = filedialog.askopenfilename(title="Seleccionar archivo a cifrar")
    if selected_file:
        label_file.config(text=f"Archivo: {Path(selected_file).name}")


# ─────────────────────────── Cifrar ─────────────────────────────────────────

def encrypt():
    if not selected_file:
        messagebox.showerror("Error", "Selecciona un archivo primero.")
        return

    recipients = get_recipients()

    if len(recipients) < 1:
        messagebox.showerror(
            "Error",
            "Debes agregar al menos 1 recipient con nombre y clave pública."
        )
        return

    output_dir = filedialog.askdirectory(title="Seleccionar carpeta de destino para el contenedor")
    if not output_dir:
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_stem = Path(selected_file).stem
    container_name = f"{file_stem}_{timestamp}"
    container_path = Path(output_dir) / container_name

    try:
        result_path = encrypt_file_for_recipients(selected_file, container_path, recipients)
        messagebox.showinfo(
            "Éxito",
            f"Archivo cifrado correctamente.\n\nContenedor creado en:\n{result_path}\n\n"
            f"Recipients incluidos: {', '.join(recipients.keys())}"
        )
    except FileExistsError:
        messagebox.showerror("Error", "Ya existe un contenedor 'vault_container' en esa carpeta. "
                             "Elige otra carpeta o renombra el existente.")
    except ValueError as e:
        messagebox.showerror("Error de configuración", str(e))
    except Exception as e:
        messagebox.showerror("Error inesperado", str(e))


# ─────────────────────────── Descifrar ──────────────────────────────────────

def decrypt():
    container_dir = filedialog.askdirectory(
        title="Seleccionar carpeta del contenedor (vault_container o su carpeta padre)"
    )
    if not container_dir:
        return

    container_path = Path(container_dir)

    # Auto-detectar subcarpeta contenedora si el usuario seleccionó la carpeta padre
    if not (container_path / "header").exists():
        # Buscar cualquier subcarpeta que contenga un archivo 'header'
        candidates = [p for p in container_path.iterdir() if p.is_dir() and (p / "header").exists()]
        if len(candidates) == 1:
            container_path = candidates[0]
        elif len(candidates) > 1:
            names = "\n".join(f"  • {p.name}" for p in candidates)
            messagebox.showerror(
                "Error de formato",
                f"Se encontraron varios contenedores en la carpeta.\nSelecciona directamente uno de ellos:\n{names}"
            )
            return
        else:
            messagebox.showerror(
                "Error de formato",
                f"La carpeta seleccionada no contiene un contenedor válido.\n\n"
                f"Selecciona la carpeta del contenedor (la que tiene archivos 'header', 'ciphertext', etc.).\n\n"
                f"Ruta: {container_dir}"
            )
            return

    container_dir = str(container_path)

    priv_key = entry_privkey.get().strip()
    pub_key = entry_pubkey.get().strip()

    if not priv_key:
        messagebox.showerror("Error", "Introduce tu clave privada.")
        return
    if not pub_key:
        messagebox.showerror("Error", "Introduce tu clave pública.")
        return

    output_file = filedialog.asksaveasfilename(
        title="Guardar archivo descifrado",
        defaultextension=".bin"
    )
    if not output_file:
        return

    try:
        result = decrypt_file_for_recipient(
            container_dir=container_dir,
            recipient_private_key_hex=priv_key,
            recipient_public_key_hex=pub_key,
            output_path=output_file,
        )
        messagebox.showinfo("Éxito", f"Archivo descifrado correctamente.\n\nGuardado en:\n{result}")

    except HybridVaultAuthenticationError:
        messagebox.showerror(
            "Error de autenticación",
            "Las claves no son válidas para este contenedor, o el contenedor fue alterado."
        )
    except HybridVaultFormatError as e:
        messagebox.showerror("Error de formato", f"El contenedor está dañado o es inválido:\n{e}")
    except Exception as e:
        messagebox.showerror("Error inesperado", str(e))


# ─────────────────────────── Agregar recipient ──────────────────────────────

recipient_rows: list[tuple[tk.Entry, tk.Entry]] = []
# Mapa entry -> botón ✕ para poder habilitarlo/deshabilitarlo
_remove_buttons: dict = {}


def _update_remove_buttons():
    """Deshabilita los botones ✕ cuando solo queda 1 recipient (mínimo requerido)."""
    can_remove = len(recipient_rows) > 1
    for key, btn in _remove_buttons.items():
        try:
            btn.config(state="normal" if can_remove else "disabled")
        except tk.TclError:
            pass  # el widget ya fue destruido


def add_recipient_row(name_default="", key_default=""):
    frame = tk.Frame(recipients_frame, bd=1, relief="groove")
    frame.pack(fill="x", padx=5, pady=2)

    tk.Label(frame, text="Nombre:", width=8, anchor="e").pack(side="left")
    name_entry = tk.Entry(frame, width=14)
    name_entry.insert(0, name_default)
    name_entry.pack(side="left", padx=(0, 5))

    tk.Label(frame, text="Clave pública:", width=12, anchor="e").pack(side="left")
    key_entry = tk.Entry(frame, width=45)
    key_entry.insert(0, key_default)
    key_entry.pack(side="left", padx=(0, 5))

    remove_btn = tk.Button(frame, text="✕", fg="red", width=2)
    remove_btn.pack(side="left")
    _remove_buttons[id(name_entry)] = remove_btn

    def remove():
        confirmed = messagebox.askyesno(
            "Eliminar recipient",
            "⚠️ Atención:\n\n"
            "Eliminar este recipient de la lista solo afecta los FUTUROS cifrados.\n\n"
            "Los archivos ya cifrados que incluían a este recipient seguirán siendo "
            "accesibles para él, ya que su clave está guardada dentro del vault.\n\n"
            "Para revocar el acceso, debes re-cifrar el archivo sin este recipient.\n\n"
            "¿Deseas eliminarlo de la lista de todos modos?"
        )
        if not confirmed:
            return
        recipient_rows.remove((name_entry, key_entry))
        _remove_buttons.pop(id(name_entry), None)
        frame.destroy()
        _update_remove_buttons()

    remove_btn.config(command=remove)
    recipient_rows.append((name_entry, key_entry))
    _update_remove_buttons()


# ════════════════════════════════════════════════════════════════════════════
#  Ventana principal
# ════════════════════════════════════════════════════════════════════════════

root = tk.Tk()
root.title("CryptoGO Secure Vault  —  Hybrid ECIES")
root.geometry("700x580")
root.resizable(False, False)

# Título
tk.Label(root, text="CryptoGO Secure Vault", font=("Arial", 17, "bold")).pack(pady=(12, 0))
tk.Label(root, text="Cifrado híbrido ECIES + ChaCha20-Poly1305",
         font=("Arial", 9), fg="gray").pack(pady=(0, 8))

# ── Generar claves ──────────────────────────────────────────────────────────
frame_keygen = tk.LabelFrame(root, text="Utilidades de claves", padx=8, pady=6)
frame_keygen.pack(fill="x", padx=12, pady=4)
tk.Button(frame_keygen, text="Generar par de claves ECIES", command=generate_keypair,
          bg="#2a7ae2", fg="white", font=("Arial", 9, "bold"), padx=8).pack(side="left")
tk.Label(frame_keygen, text="  Genera un nuevo par público/privado para un recipient",
         fg="gray", font=("Arial", 8)).pack(side="left")

# ── Cifrar ──────────────────────────────────────────────────────────────────
frame_enc = tk.LabelFrame(root, text="Cifrar archivo", padx=8, pady=6)
frame_enc.pack(fill="x", padx=12, pady=4)

row_file = tk.Frame(frame_enc)
row_file.pack(fill="x", pady=2)
tk.Button(row_file, text="Seleccionar archivo", command=select_file).pack(side="left")
label_file = tk.Label(row_file, text="Ningún archivo seleccionado", fg="gray")
label_file.pack(side="left", padx=10)

# Recipients
tk.Label(frame_enc, text="Recipients (mínimo 1):", anchor="w",
         font=("Arial", 9, "bold")).pack(fill="x", pady=(6, 0))

recipients_frame = tk.Frame(frame_enc)
recipients_frame.pack(fill="x")

# Una fila por defecto (se pueden agregar más con el botón)
add_recipient_row("Recipient 1")

btn_row = tk.Frame(frame_enc)
btn_row.pack(pady=4)
tk.Button(btn_row, text="+ Agregar recipient", command=add_recipient_row).pack(side="left", padx=4)
tk.Button(btn_row, text="Cifrar →", command=encrypt,
          bg="#27ae60", fg="white", font=("Arial", 9, "bold"), padx=8).pack(side="left", padx=4)

# ── Descifrar ───────────────────────────────────────────────────────────────
frame_dec = tk.LabelFrame(root, text="Descifrar contenedor", padx=8, pady=6)
frame_dec.pack(fill="x", padx=12, pady=4)

row_priv = tk.Frame(frame_dec)
row_priv.pack(fill="x", pady=2)
tk.Label(row_priv, text="Clave privada:", width=14, anchor="e").pack(side="left")
entry_privkey = tk.Entry(row_priv, width=68, show="*")
entry_privkey.pack(side="left")

row_pub = tk.Frame(frame_dec)
row_pub.pack(fill="x", pady=2)
tk.Label(row_pub, text="Clave pública:", width=14, anchor="e").pack(side="left")
entry_pubkey = tk.Entry(row_pub, width=68)
entry_pubkey.pack(side="left")

tk.Button(frame_dec, text="Descifrar →", command=decrypt,
          bg="#e67e22", fg="white", font=("Arial", 9, "bold"), padx=8).pack(pady=6)

root.mainloop()