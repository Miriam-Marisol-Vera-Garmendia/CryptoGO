import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from datetime import datetime
from pathlib import Path
import json
import os

from cryptogo.encryption.hybrid_vault import (
    encrypt_file_for_recipients,
    decrypt_file_for_recipient,
    generate_ecies_keypair,
    generate_signing_keypair,
    get_container_info,
    public_key_fingerprint,
)
from cryptogo.encryption.key_manager import (
    protect_private_key,
    recover_private_key,
    KEY_TYPE_ECIES,
    KEY_TYPE_ED25519,
    KeyManagerAuthError,
    KeyManagerFormatError,
)
from cryptogo.encryption import (
    HybridVaultAuthenticationError,
    HybridVaultFormatError,
    HybridVaultSignatureError,
)
import logging
import traceback

# ──────────────────────────────────────────────────────────────────────────────
#  Seguridad: mensaje genérico y logger local (sin exponer detalles al usuario)
# ──────────────────────────────────────────────────────────────────────────────

GENERIC_CONTAINER_ERROR = (
    "No fue posible procesar la operación.\n\n"
    "Verifica que el archivo, las llaves y el contenedor sean correctos."
)

_security_logger = logging.getLogger("cryptogo.security")
if not _security_logger.handlers:
    _log_path = Path(__file__).parent / "security.log"
    _handler  = logging.FileHandler(_log_path, encoding="utf-8")
    _handler.setFormatter(logging.Formatter(
        "%(asctime)s  %(levelname)s  %(message)s", datefmt="%Y-%m-%dT%H:%M:%S"
    ))
    _security_logger.addHandler(_handler)
    _security_logger.setLevel(logging.WARNING)


def log_security_error(context: str, exc: BaseException) -> None:
    """Registra el error completo sólo en el log local; nunca lo muestra al usuario."""
    _security_logger.warning(
        "[%s] %s: %s\n%s",
        context,
        type(exc).__name__,
        exc,
        traceback.format_exc(),
    )


# ──────────────────────────────────────────────────────────────────────────────
#  Agenda de Contactos (Directorio de Llaves Públicas)
# ──────────────────────────────────────────────────────────────────────────────

CONTACTS_FILE = Path(__file__).parent / "contactos.json"

def load_contacts() -> dict[str, dict]:
    if not CONTACTS_FILE.exists():
        return {}
    try:
        with open(CONTACTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Migrar formato antiguo (string simple) al nuevo (diccionario con dos llaves)
            for k, v in data.items():
                if isinstance(v, str):
                    data[k] = {"access": v, "signing": ""}
            return data
    except Exception:
        return {}

def save_contacts(contacts: dict[str, str]):
    with open(CONTACTS_FILE, "w", encoding="utf-8") as f:
        json.dump(contacts, f, indent=4, ensure_ascii=False)


def find_duplicate_access_key(contacts: dict, access_key: str, exclude_name: str = "") -> str | None:
    """Busca si la llave de acceso ya pertenece a otro contacto.
    Retorna el nombre del contacto duplicado, o None si no hay duplicado."""
    if not access_key:
        return None
    for name, data in contacts.items():
        if name == exclude_name:
            continue
        if data.get("access") == access_key:
            return name
    return None


# ──────────────────────────────────────────────────────────────────────────────
#  Paleta
# ──────────────────────────────────────────────────────────────────────────────

BG         = "#f5f0fa"
BG_PANEL   = "#ede8f5"
BG_INPUT   = "#ffffff"
BG_HOVER   = "#6d28d9"
ACCENT     = "#7c3aed"
ACCENT_DIM = "#be185d"
SUCCESS    = "#059669"
WARNING    = "#d97706"
DANGER     = "#be123c"
TEXT       = "#1e1030"
TEXT_D   = "#ffffff"
TEXT_DIM   = "#6b7280"
BORDER     = "#ddd6fe"

# Colores adicionales por función
CHERRY     = "#be185d"   # cereza — firma privada, clave privada
ROSE       = "#db2777"   # rosa — copiar, secundarios
VIOLET     = "#7c3aed"   # morado — generar, claves principales
INDIGO     = "#4338ca"   # índigo — inspeccionar, recuperar
TEAL       = "#0d9488"   # verde azulado — guardar protegida


# ──────────────────────────────────────────────────────────────────────────────
#  Widgets reutilizables
# ──────────────────────────────────────────────────────────────────────────────

def _darken(hex_color: str, factor: float = 0.75) -> str:
    r = int(hex_color[1:3], 16)
    g = int(hex_color[3:5], 16)
    b = int(hex_color[5:7], 16)
    return f"#{int(r*factor):02x}{int(g*factor):02x}{int(b*factor):02x}"


class StyledEntry(tk.Entry):
    def __init__(self, parent, show_char=None, width=70, **kwargs):
        kwargs.setdefault("bg", BG_INPUT)
        kwargs.setdefault("fg", TEXT)
        kwargs.setdefault("insertbackground", TEXT)
        kwargs.setdefault("relief", "flat")
        kwargs.setdefault("highlightthickness", 1)
        kwargs.setdefault("highlightbackground", BORDER)
        kwargs.setdefault("highlightcolor", ACCENT)
        kwargs.setdefault("font", ("Consolas", 9))
        kwargs.setdefault("width", width)
        if show_char:
            kwargs["show"] = show_char
        super().__init__(parent, **kwargs)


class StyledButton(tk.Button):
    def __init__(self, parent, text, command, color=ACCENT, **kwargs):
        kwargs.setdefault("font", ("Segoe UI", 9, "bold"))
        kwargs.setdefault("relief", "flat")
        kwargs.setdefault("cursor", "hand2")
        kwargs.setdefault("padx", 10)
        kwargs.setdefault("pady", 5)
        super().__init__(
            parent, text=text, command=command,
            bg=color, fg="white",
            activebackground=_darken(color), activeforeground="white",
            **kwargs,
        )
        self.bind("<Enter>", lambda e: self.config(bg=_darken(color)))
        self.bind("<Leave>", lambda e: self.config(bg=color))


def lbl(parent, text, bold=False, size=9, color=TEXT, **kwargs):
    font = ("Segoe UI", size, "bold") if bold else ("Segoe UI", size)
    return tk.Label(parent, text=text, bg=BG_PANEL, fg=color, font=font, **kwargs)


def make_section(parent, title: str) -> tk.Frame:
    outer = tk.Frame(parent, bg=BG_PANEL, highlightthickness=1,
                     highlightbackground=BORDER)
    outer.pack(fill="x", padx=14, pady=4)
    tk.Frame(outer, bg=VIOLET, height=3).pack(fill="x")
    tk.Label(outer, text=f"  {title}", bg=VIOLET, fg="white",
             font=("Segoe UI", 9, "bold"), anchor="w").pack(fill="x")
    body = tk.Frame(outer, bg=BG_PANEL, padx=12, pady=10)
    body.pack(fill="x")
    return body


def hsep(parent):
    tk.Frame(parent, height=1, bg=BORDER).pack(fill="x", padx=14, pady=3)


selected_file: str | None = None
recipient_rows: list[tuple[tk.Entry, tk.Entry]] = []
_remove_buttons: dict = {}

# Tipos de archivo permitidos para cifrado
ALLOWED_FILE_EXTENSIONS = {".pdf", ".epub", ".png", ".jpg", ".jpeg", ".xps"}
ALLOWED_FILETYPES = [
    ("Archivos permitidos", "*.pdf *.epub *.png *.jpg *.jpeg *.xps"),
    ("PDF", "*.pdf"),
    ("EPUB", "*.epub"),
    ("Imágenes", "*.png *.jpg *.jpeg"),
    ("XPS", "*.xps"),
]


def is_allowed_file(path: str | Path) -> bool:
    """Valida que el archivo tenga una extensión permitida."""
    return Path(path).suffix.lower() in ALLOWED_FILE_EXTENSIONS

def copy_to_clipboard(text: str):
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()


def set_status(msg: str, color: str = TEXT_DIM):
    status_var.set(f"  {msg}")
    status_label.config(fg=color)


def get_recipients() -> dict[str, str]:
    result = {}
    for name_e, key_e in recipient_rows:
        n, k = name_e.get().strip(), key_e.get().strip()
        if n and k:
            result[n] = k
    return result


def _resolve_container(base_dir: str) -> Path | None:
    p = Path(base_dir)
    if (p / "header").exists():
        return p
    candidates = [c for c in p.iterdir() if c.is_dir() and (c / "header").exists()]
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        names = "\n".join(f"  • {c.name}" for c in candidates)
        messagebox.showerror("Múltiples contenedores",
                             f"Selecciona directamente uno:\n{names}")
        return None
    messagebox.showerror("Error de formato",
                         f"No se encontró un contenedor válido en:\n{base_dir}")
    return None


# ──────────────────────────────────────────────────────────────────────────────
#  Ventana: Generar par de claves de acceso
# ──────────────────────────────────────────────────────────────────────────────

def open_keygen_window():
    win = tk.Toplevel(root)
    win.title("Generar par de llaves de acceso")
    win.geometry("700x390")
    win.resizable(False, False)
    win.configure(bg=BG)

    tk.Label(win, text="Generador de llaves de acceso", bg=BG, fg=TEXT,
             font=("Segoe UI", 13, "bold")).pack(pady=(16, 2))
    tk.Label(win, text="Par de llaves para proteger y recuperar archivos",
             bg=BG, fg=TEXT_DIM, font=("Segoe UI", 9)).pack()

    frame = tk.Frame(win, bg=BG_PANEL, padx=16, pady=14,
                     highlightthickness=1, highlightbackground=BORDER)
    frame.pack(fill="x", padx=20, pady=12)

    priv_hex = tk.StringVar()
    pub_hex  = tk.StringVar()

    tk.Label(frame, text="Llave pública  —  comparte con quien cifrará para ti",
             bg=BG_PANEL, fg=TEXT, font=("Segoe UI", 8, "bold")).pack(anchor="w")
    pub_entry = tk.Entry(frame, width=92, bg=BG_INPUT, fg=TEXT, relief="flat",
                         font=("Consolas", 8), highlightthickness=1,
                         highlightbackground=BORDER, state="readonly")
    pub_entry.pack(fill="x", pady=(2, 8))

    tk.Label(frame, text="Llave privada  —  NO la compartas nunca",
             bg=BG_PANEL, fg=DANGER, font=("Segoe UI", 8, "bold")).pack(anchor="w")
    priv_entry = tk.Entry(frame, width=92, bg=BG_INPUT, fg=DANGER, relief="flat",
                          font=("Consolas", 8), show="•", highlightthickness=1,
                          highlightbackground=BORDER, state="readonly")
    priv_entry.pack(fill="x", pady=(2, 4))

    fp_var = tk.StringVar(value="")
    tk.Label(frame, textvariable=fp_var, bg=BG_PANEL, fg=TEXT_DIM,
             font=("Consolas", 8)).pack(anchor="w")

    def do_generate():
        priv, pub = generate_ecies_keypair()
        priv_hex.set(priv); pub_hex.set(pub)
        for entry, val, show in [(pub_entry, pub, ""), (priv_entry, priv, "•")]:
            entry.config(state="normal"); entry.delete(0, "end")
            entry.insert(0, val); entry.config(state="readonly", show=show)
        fp_var.set(f"Huella: {public_key_fingerprint(pub)}")
        set_status("✔ Par de llaves generado.", SUCCESS)

    def toggle_priv():
        s = priv_entry.cget("show")
        priv_entry.config(state="normal", show="" if s == "•" else "•")
        priv_entry.config(state="readonly")

    def copy_pub():
        if pub_hex.get():
            copy_to_clipboard(pub_hex.get())
            messagebox.showinfo("Copiado", "Llave pública copiada.", parent=win)

    def save_pub():
        if not pub_hex.get():
            messagebox.showwarning("Sin llave", "Genera un par primero.", parent=win)
            return
        pub_path = filedialog.asksaveasfilename(
            parent=win, title="Guardar llave pública de acceso",
            defaultextension=".txt",
            filetypes=[("Texto hex", "*.txt"), ("Todos", "*.*")],
        )
        if pub_path:
            Path(pub_path).write_text(pub_hex.get(), encoding="utf-8")
            messagebox.showinfo("Guardado", f"Llave pública guardada en:\n{pub_path}", parent=win)

    def save_protected():
        if not priv_hex.get():
            messagebox.showwarning("Sin llave", "Genera un par primero.", parent=win)
            return
        pw_win = tk.Toplevel(win)
        pw_win.title("Proteger llave privada")
        pw_win.geometry("440x200")
        pw_win.configure(bg=BG)
        pw_win.resizable(False, False)
        tk.Label(pw_win, text="Contraseña para proteger la llave privada",
                 bg=BG, fg=TEXT, font=("Segoe UI", 10, "bold")).pack(pady=(16, 4))
        tk.Label(pw_win, text="Mínimo 8 caracteres.",
                 bg=BG, fg=WARNING, font=("Segoe UI", 8)).pack()
        pw_entry = StyledEntry(pw_win, show_char="•", width=52)
        pw_entry.pack(pady=8)

        def do_save():
            pw = pw_entry.get()
            if len(pw) < 8:
                messagebox.showwarning("Débil", "Mínimo 8 caracteres.", parent=pw_win)
                return
            folder = filedialog.askdirectory(
                parent=pw_win, title="Seleccionar carpeta donde guardar el keystore",
            )
            if not folder:
                return
            import os
            keystore_path = os.path.join(folder, "keystore")
            try:
                protect_private_key(
                    key_material=priv_hex.get(),
                    key_type=KEY_TYPE_ECIES,
                    password=pw,
                    keystore_dir=keystore_path,
                    label="clave-ecies",
                )
                messagebox.showinfo("Guardado", f"Keystore guardado en:\n{keystore_path}", parent=pw_win)
                set_status("✔ Llave protegida guardada.", SUCCESS)
                pw_win.destroy()
            except FileExistsError:
                messagebox.showerror("Error", "Ya existe un keystore en esa carpeta.\nElige otra ubicación.", parent=pw_win)
            except Exception as e:
                log_security_error("protect_key", e)
                messagebox.showerror("Error", "No fue posible proteger la llave.", parent=pw_win)

        StyledButton(pw_win, "🔒 Cifrar y guardar", do_save, color=TEAL).pack()

    btn_row = tk.Frame(win, bg=BG)
    btn_row.pack(pady=6)
    StyledButton(btn_row, "⚡ Generar",          do_generate,    color=VIOLET).pack(side="left", padx=3)
    StyledButton(btn_row, "👁 Ver/Ocultar",       toggle_priv,    color=INDIGO).pack(side="left", padx=3)
    StyledButton(btn_row, "📋 Copiar pública",    copy_pub,       color=ROSE).pack(side="left", padx=3)
    StyledButton(btn_row, "💾 Guardar pública", save_pub,  color=INDIGO).pack(side="left", padx=3)
    StyledButton(btn_row, "🔒 Guardar privada", save_protected, color=TEAL).pack(side="left", padx=3)


# ──────────────────────────────────────────────────────────────────────────────
#  Ventana: Generar par de claves de firma
# ──────────────────────────────────────────────────────────────────────────────

def open_signing_keygen_window():
    """
    Genera un par de claves Ed25519 para firma digital.
    Las claves se representan como hexadecimal para facilitar su copia y uso en la GUI.
    Internamente el módulo opera con bytes raw (32B privada, 32B pública).
    """
    win = tk.Toplevel(root)
    win.title("Generar llaves de firma")
    win.geometry("700x400")
    win.resizable(False, False)
    win.configure(bg=BG)

    tk.Label(win, text="Generador de llaves de firma", bg=BG, fg=TEXT,
             font=("Segoe UI", 13, "bold")).pack(pady=(16, 2))
    tk.Label(win, text="Par de llaves para firmar y verificar contenedores",
             bg=BG, fg=TEXT_DIM, font=("Segoe UI", 9)).pack()

    frame = tk.Frame(win, bg=BG_PANEL, padx=16, pady=14,
                     highlightthickness=1, highlightbackground=BORDER)
    frame.pack(fill="x", padx=20, pady=12)

    priv_hex_var = tk.StringVar()
    pub_hex_var  = tk.StringVar()

    tk.Label(frame,
             text="Llave pública de firma  —  comparte con quien verificará tu firma",
             bg=BG_PANEL, fg=TEXT, font=("Segoe UI", 8, "bold")).pack(anchor="w")
    pub_entry = tk.Entry(frame, width=92, bg=BG_INPUT, fg=TEXT, relief="flat",
                         font=("Consolas", 8), highlightthickness=1,
                         highlightbackground=BORDER, state="readonly")
    pub_entry.pack(fill="x", pady=(2, 8))

    tk.Label(frame,
             text="Llave privada de firma  —  NO la compartas nunca",
             bg=BG_PANEL, fg=DANGER, font=("Segoe UI", 8, "bold")).pack(anchor="w")
    priv_entry = tk.Entry(frame, width=92, bg=BG_INPUT, fg=DANGER, relief="flat",
                          font=("Consolas", 8), show="•", highlightthickness=1,
                          highlightbackground=BORDER, state="readonly")
    priv_entry.pack(fill="x", pady=(2, 4))

    sid_var = tk.StringVar(value="")
    tk.Label(frame, textvariable=sid_var, bg=BG_PANEL, fg=TEXT_DIM,
             font=("Consolas", 8)).pack(anchor="w")

    def do_generate():
        priv_bytes, pub_bytes, sid = generate_signing_keypair()
        priv_h = priv_bytes.hex()
        pub_h  = pub_bytes.hex()
        priv_hex_var.set(priv_h); pub_hex_var.set(pub_h)
        for entry, val, show in [(pub_entry, pub_h, ""), (priv_entry, priv_h, "•")]:
            entry.config(state="normal"); entry.delete(0, "end")
            entry.insert(0, val); entry.config(state="readonly", show=show)
        sid_var.set(f"Identificador de firma: {sid}")
        set_status("✔ Par de llaves de firma generado.", SUCCESS)

    def toggle_priv():
        s = priv_entry.cget("show")
        priv_entry.config(state="normal", show="" if s == "•" else "•")
        priv_entry.config(state="readonly")

    def copy_pub():
        if pub_hex_var.get():
            copy_to_clipboard(pub_hex_var.get())
            messagebox.showinfo("Copiado", "Llave pública copiada.", parent=win)

    def copy_priv():
        if priv_hex_var.get():
            copy_to_clipboard(priv_hex_var.get())
            messagebox.showinfo("Copiado", "Llave privada copiada.", parent=win)

    def save_pub():
        if not pub_hex_var.get():
            messagebox.showwarning("Sin llave", "Genera un par primero.", parent=win)
            return
        pub_path = filedialog.asksaveasfilename(
            parent=win, title="Guardar llave pública de firma",
            defaultextension=".txt",
            filetypes=[("Texto hex", "*.txt"), ("Todos", "*.*")],
        )
        if pub_path:
            Path(pub_path).write_text(pub_hex_var.get(), encoding="utf-8")
            messagebox.showinfo("Guardado", f"Llave pública guardada en:\n{pub_path}", parent=win)

    def save_protected():
        if not priv_hex_var.get():
            messagebox.showwarning("Sin llave", "Genera un par primero.", parent=win)
            return
        pw_win = tk.Toplevel(win)
        pw_win.title("Proteger llave privada de firma")
        pw_win.geometry("440x200")
        pw_win.configure(bg=BG)
        pw_win.resizable(False, False)
        tk.Label(pw_win, text="Contraseña para proteger la llave privada de firma",
                 bg=BG, fg=TEXT, font=("Segoe UI", 10, "bold")).pack(pady=(16, 4))
        tk.Label(pw_win, text="Mínimo 8 caracteres.",
                 bg=BG, fg=WARNING, font=("Segoe UI", 8)).pack()
        pw_entry = StyledEntry(pw_win, show_char="•", width=52)
        pw_entry.pack(pady=8)

        def do_save():
            pw = pw_entry.get()
            if len(pw) < 8:
                messagebox.showwarning("Débil", "Mínimo 8 caracteres.", parent=pw_win)
                return
            folder = filedialog.askdirectory(
                parent=pw_win, title="Seleccionar carpeta donde guardar el keystore de firma",
            )
            if not folder:
                return
            import os
            keystore_path = os.path.join(folder, "keystore_firma")
            try:
                # La llave de firma Ed25519 en key_manager espera los bytes crudos (raw)
                raw_bytes = bytes.fromhex(priv_hex_var.get())
                protect_private_key(
                    key_material=raw_bytes,
                    key_type=KEY_TYPE_ED25519,
                    password=pw,
                    keystore_dir=keystore_path,
                    label="clave-firma-ed25519",
                )
                messagebox.showinfo("Guardado", f"Keystore de firma guardado en:\n{keystore_path}", parent=pw_win)
                set_status("✔ Llave de firma protegida guardada.", SUCCESS)
                pw_win.destroy()
            except FileExistsError:
                messagebox.showerror("Error", "Ya existe un keystore en esa carpeta.\nElige otra ubicación.", parent=pw_win)
            except Exception as e:
                log_security_error("protect_signing_key", e)
                messagebox.showerror("Error", "No fue posible proteger la llave de firma.", parent=pw_win)

        StyledButton(pw_win, "🔒 Cifrar y guardar privada", do_save, color=TEAL).pack()

    btn_row = tk.Frame(win, bg=BG)
    btn_row.pack(pady=6)
    StyledButton(btn_row, "⚡ Generar",        do_generate, color=VIOLET).pack(side="left", padx=3)
    StyledButton(btn_row, "👁 Ver/Ocultar",     toggle_priv, color=INDIGO).pack(side="left", padx=3)
    StyledButton(btn_row, "📋 Copiar pública",  copy_pub,    color=ROSE).pack(side="left", padx=3)
    StyledButton(btn_row, "💾 Guardar pública", save_pub,  color=INDIGO).pack(side="left", padx=3)
    StyledButton(btn_row, "🔒 Guardar privada", save_protected, color=TEAL).pack(side="left", padx=3)


# ──────────────────────────────────────────────────────────────────────────────
#  Ventana: Recuperar clave privada desde .vkey
# ──────────────────────────────────────────────────────────────────────────────

def open_recover_key_window():
    win = tk.Toplevel(root)
    win.title("Recuperar llave privada (keystore)")
    win.geometry("580x260")
    win.configure(bg=BG)
    win.resizable(False, False)

    tk.Label(win, text="Recuperar llave privada protegida", bg=BG, fg=TEXT,
             font=("Segoe UI", 12, "bold")).pack(pady=(14, 2))

    frame = tk.Frame(win, bg=BG_PANEL, padx=14, pady=12,
                     highlightthickness=1, highlightbackground=BORDER)
    frame.pack(fill="x", padx=18, pady=8)

    folder_var = tk.StringVar(value="Ninguna carpeta seleccionada")
    tk.Label(frame, textvariable=folder_var, bg=BG_PANEL, fg=TEXT_DIM,
             font=("Consolas", 8)).pack(anchor="w", pady=(0, 4))

    key_path = {"path": None}

    def pick_folder():                          # ← ahora busca CARPETA
        p = filedialog.askdirectory(
            parent=win, title="Seleccionar carpeta keystore",
        )
        if p:
            key_path["path"] = p
            folder_var.set(p)

    StyledButton(frame, "Seleccionar carpeta keystore", pick_folder,
                 color=INDIGO).pack(anchor="w", pady=(0, 8))

    tk.Label(frame, text="Contraseña:", bg=BG_PANEL, fg=TEXT,
             font=("Segoe UI", 9)).pack(anchor="w")
    pw_entry = StyledEntry(frame, show_char="•", width=70)
    pw_entry.pack(fill="x", pady=(2, 6))

    result_var = tk.StringVar()
    tk.Entry(frame, textvariable=result_var, width=90, bg=BG_INPUT, fg=SUCCESS,
             font=("Consolas", 8), relief="flat", state="readonly",
             highlightthickness=1, highlightbackground=BORDER).pack(fill="x")

    def do_recover():
        if not key_path["path"]:
            messagebox.showwarning("Sin carpeta", "Selecciona un keystore.", parent=win)
            return
        try:
            recovered, key_type, info = recover_private_key(
                keystore_dir=key_path["path"],
                password=pw_entry.get(),
            )
            if isinstance(recovered, bytes):
                recovered = recovered.hex()
            result_var.set(recovered)
            set_status("✔ Llave recuperada.", SUCCESS)
        except KeyManagerAuthError:
            messagebox.showerror("Error", "Contraseña incorrecta.", parent=win)
        except KeyManagerFormatError as e:
            messagebox.showerror("Error", f"Keystore inválido:\n{e}", parent=win)
        except Exception as e:
            log_security_error("recover_key_unexpected", e)
            messagebox.showerror("Error", "No fue posible recuperar la llave.", parent=win)

    def copy_result():
        if result_var.get():
            copy_to_clipboard(result_var.get())
            messagebox.showinfo("Copiado", "Llave copiada.", parent=win)

    btn_row = tk.Frame(win, bg=BG)
    btn_row.pack(pady=6)
    StyledButton(btn_row, "🔓 Recuperar", do_recover,  color=VIOLET).pack(side="left", padx=4)
    StyledButton(btn_row, "📋 Copiar",    copy_result, color=ROSE).pack(side="left", padx=4)

# ──────────────────────────────────────────────────────────────────────────────
#  Ventana: Inspeccionar contenedor
# ──────────────────────────────────────────────────────────────────────────────

def open_inspect_window():
    base_dir = filedialog.askdirectory(title="Seleccionar carpeta del contenedor")
    if not base_dir:
        return
    container_path = _resolve_container(base_dir)
    if container_path is None:
        return

    try:
        info = get_container_info(container_path)
    except (HybridVaultFormatError, HybridVaultSignatureError) as e:
        log_security_error("inspect_container", e)
        messagebox.showerror("Error", GENERIC_CONTAINER_ERROR); return
    except Exception as e:
        log_security_error("inspect_unexpected", e)
        messagebox.showerror("Error", GENERIC_CONTAINER_ERROR); return

    win = tk.Toplevel(root)
    win.title("Inspección del contenedor")
    win.geometry("600x380")
    win.configure(bg=BG)
    win.resizable(False, False)

    tk.Label(win, text="Metadatos del contenedor", bg=BG, fg=TEXT,
             font=("Segoe UI", 12, "bold")).pack(pady=(14, 6))

    txt = scrolledtext.ScrolledText(
        win, bg=BG_INPUT, fg=TEXT, font=("Consolas", 9),
        relief="flat", width=76, height=17,
        highlightthickness=1, highlightbackground=BORDER,
    )
    txt.pack(padx=18, pady=4, fill="both", expand=True)

    lines = [
        f"  Archivo original   : {info['original_filename']}",
        f"  Fecha de creación  : {info['created_at']}",
        f"  Tamaño original    : {info['plaintext_size']:,} bytes",
        f"  Versión contenedor : {info['container_version']}",
        f"  Verificación       : disponible",
        f"  Identificador      : {info['signer_id']}",
        "",
        f"  Usuarios autorizados ({len(info['recipients'])}):",
    ]
    for r in info["recipients"]:
        lines.append(f"    • {r['id']}   [{r['key_id']}]")

    txt.insert("1.0", "\n".join(lines))
    txt.config(state="disabled")

# ──────────────────────────────────────────────────────────────────────────────
#  Ventana: Agenda de Contactos
# ──────────────────────────────────────────────────────────────────────────────

def open_contacts_window():
    win = tk.Toplevel(root)
    win.title("Agenda de Contactos")
    win.geometry("540x480")
    win.configure(bg=BG)
    win.resizable(False, False)

    tk.Label(win, text="Directorio de Llaves Públicas", bg=BG, fg=TEXT,
             font=("Segoe UI", 12, "bold")).pack(pady=(14, 4))
    tk.Label(win, text="Guarda aquí las llaves públicas de tus destinatarios.", bg=BG, fg=TEXT_DIM,
             font=("Segoe UI", 9)).pack()

    list_frame = tk.Frame(win, bg=BG)
    list_frame.pack(fill="both", expand=True, padx=20, pady=10)

    listbox = tk.Listbox(list_frame, font=("Segoe UI", 10), bg=BG_INPUT, fg=TEXT, relief="flat", highlightthickness=1, highlightbackground=BORDER)
    listbox.pack(side="left", fill="both", expand=True)
    scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=listbox.yview)
    scrollbar.pack(side="right", fill="y")
    listbox.config(yscrollcommand=scrollbar.set)

    def refresh_list():
        listbox.delete(0, tk.END)
        for name in load_contacts().keys():
            listbox.insert(tk.END, name)
            
    refresh_list()

    add_frame = tk.Frame(win, bg=BG_PANEL, highlightthickness=1, highlightbackground=BORDER, padx=14, pady=14)
    add_frame.pack(fill="x", padx=20, pady=10)

    tk.Label(add_frame, text="Nombre:", bg=BG_PANEL, fg=TEXT, font=("Segoe UI", 9)).grid(row=0, column=0, sticky="e", pady=2)
    name_entry = StyledEntry(add_frame, width=20)
    name_entry.grid(row=0, column=1, sticky="w", padx=8, pady=2)

    tk.Label(add_frame, text="Pública de Acceso:", bg=BG_PANEL, fg=TEXT, font=("Segoe UI", 9)).grid(row=1, column=0, sticky="e", pady=2)
    acc_key_entry = StyledEntry(add_frame, width=50)
    acc_key_entry.grid(row=1, column=1, sticky="w", padx=8, pady=2)

    tk.Label(add_frame, text="Pública de Firma:", bg=BG_PANEL, fg=TEXT, font=("Segoe UI", 9)).grid(row=2, column=0, sticky="e", pady=2)
    sign_key_entry = StyledEntry(add_frame, width=50)
    sign_key_entry.grid(row=2, column=1, sticky="w", padx=8, pady=2)

    def add_contact():
        name = name_entry.get().strip()
        acc_key = acc_key_entry.get().strip()
        sign_key = sign_key_entry.get().strip()
        if not name or (not acc_key and not sign_key):
            messagebox.showwarning("Error", "Debes ingresar un nombre y al menos una llave.", parent=win)
            return
        c = load_contacts()
        if name in c:
            if not messagebox.askyesno(
                "Contacto existente",
                f"'{name}' ya existe en la agenda.\n¿Deseas actualizar sus llaves?",
                parent=win,
            ):
                return
        # Verificar que la llave de acceso no pertenezca a otro contacto
        dup = find_duplicate_access_key(c, acc_key, exclude_name=name)
        if dup:
            messagebox.showerror("Llave duplicada",
                f"La llave pública de acceso ya está registrada para '{dup}'.\n\n"
                "Cada contacto debe tener una llave de acceso única.",
                parent=win)
            return
        c[name] = {"access": acc_key, "signing": sign_key}
        save_contacts(c)
        name_entry.delete(0, tk.END)
        acc_key_entry.delete(0, tk.END)
        sign_key_entry.delete(0, tk.END)
        refresh_list()
        set_status(f"Contacto '{name}' guardado.", SUCCESS)

    def delete_contact():
        sel = listbox.curselection()
        if not sel: return
        name = listbox.get(sel[0])
        c = load_contacts()
        if name in c:
            del c[name]
            save_contacts(c)
            refresh_list()
            set_status(f"Contacto '{name}' eliminado.", WARNING)

    def copy_key():
        sel = listbox.curselection()
        if not sel: return
        name = listbox.get(sel[0])
        c = load_contacts()
        if name in c:
            acc = c[name].get("access", "")
            if acc:
                copy_to_clipboard(acc)
                messagebox.showinfo("Copiado", f"Llave pública de acceso de '{name}' copiada.", parent=win)
            else:
                messagebox.showinfo("Vacío", f"'{name}' no tiene llave de acceso.", parent=win)

    btn_f = tk.Frame(add_frame, bg=BG_PANEL)
    btn_f.grid(row=3, column=0, columnspan=2, pady=(10,0))
    StyledButton(btn_f, "➕ Añadir a la agenda", add_contact, color=TEAL).pack()
    
    btn_f2 = tk.Frame(win, bg=BG)
    btn_f2.pack(pady=5)
    StyledButton(btn_f2, "📋 Copiar llave seleccionada", copy_key, color=INDIGO).pack(side="left", padx=5)
    StyledButton(btn_f2, "🗑️ Eliminar seleccionado", delete_contact, color=DANGER).pack(side="left", padx=5)


# ──────────────────────────────────────────────────────────────────────────────
#  Recipients
# ──────────────────────────────────────────────────────────────────────────────

def _update_remove_buttons():
    can = len(recipient_rows) > 1
    for btn in _remove_buttons.values():
        try:
            btn.config(state="normal" if can else "disabled")
        except tk.TclError:
            pass


def add_recipient_row(name_default="", key_default=""):
    frame = tk.Frame(recipients_frame, bg=BG_PANEL,
                     highlightthickness=1, highlightbackground=BORDER)
    frame.pack(fill="x", padx=4, pady=2)

    tk.Label(frame, text="Nombre:", bg=BG_PANEL, fg=TEXT_DIM,
             font=("Segoe UI", 8), width=8, anchor="e").pack(side="left")
    name_entry = StyledEntry(frame, width=14)
    name_entry.insert(0, name_default)
    name_entry.pack(side="left", padx=(2, 6))

    tk.Label(frame, text="Llave pública:", bg=BG_PANEL, fg=TEXT_DIM,
             font=("Segoe UI", 8), width=18, anchor="e").pack(side="left")
    key_entry = StyledEntry(frame, width=46)
    key_entry.insert(0, key_default)
    key_entry.pack(side="left", padx=(2, 4))

    def save_to_agenda(ne=name_entry, ke=key_entry):
        n = ne.get().strip()
        k = ke.get().strip()
        if not n or not k:
            messagebox.showwarning(
                "Datos incompletos",
                "Ingresa nombre y llave pública de acceso antes de guardar.",
            )
            return

        # Verificar si el contacto ya existe
        existing = load_contacts()
        if n in existing:
            # Ya existe: solo preguntar si desea actualizar la llave de acceso
            if messagebox.askyesno(
                "Contacto existente",
                f"'{n}' ya existe en la agenda.\n¿Deseas actualizar su llave de acceso?",
            ):
                # Verificar que la llave no pertenezca a otro contacto
                dup = find_duplicate_access_key(existing, k, exclude_name=n)
                if dup:
                    messagebox.showerror("Llave duplicada",
                        f"La llave de acceso ya está registrada para '{dup}'.\n\n"
                        "Cada contacto debe tener una llave de acceso única.")
                else:
                    existing[n]["access"] = k
                    save_contacts(existing)
                    set_status(f"✔ Llave de acceso de '{n}' actualizada.", SUCCESS)
            return

        # Contacto nuevo: abrir diálogo para pedir la llave de firma
        dlg = tk.Toplevel(root)
        dlg.title("Guardar en Agenda")
        dlg.geometry("520x260")
        dlg.configure(bg=BG)
        dlg.resizable(False, False)

        tk.Label(dlg, text="Nuevo contacto", bg=BG, fg=TEXT,
                 font=("Segoe UI", 11, "bold")).pack(pady=(14, 4))

        form = tk.Frame(dlg, bg=BG_PANEL, padx=14, pady=12,
                        highlightthickness=1, highlightbackground=BORDER)
        form.pack(fill="x", padx=18, pady=6)

        tk.Label(form, text="Nombre:", bg=BG_PANEL, fg=TEXT,
                 font=("Segoe UI", 9)).grid(row=0, column=0, sticky="e", pady=3)
        dlg_name = StyledEntry(form, width=40)
        dlg_name.insert(0, n)
        dlg_name.grid(row=0, column=1, sticky="w", padx=8, pady=3)

        tk.Label(form, text="Pública de Acceso:", bg=BG_PANEL, fg=TEXT,
                 font=("Segoe UI", 9)).grid(row=1, column=0, sticky="e", pady=3)
        dlg_access = StyledEntry(form, width=40)
        dlg_access.insert(0, k)
        dlg_access.grid(row=1, column=1, sticky="w", padx=8, pady=3)

        tk.Label(form, text="Pública de Firma:", bg=BG_PANEL, fg=TEXT,
                 font=("Segoe UI", 9)).grid(row=2, column=0, sticky="e", pady=3)
        dlg_signing = StyledEntry(form, width=40)
        dlg_signing.grid(row=2, column=1, sticky="w", padx=8, pady=3)

        def _validate_hex_key(value, expected_bytes, label):
            """Valida que un valor sea hexadecimal con la longitud correcta."""
            try:
                raw = bytes.fromhex(value)
            except ValueError:
                messagebox.showerror("Llave inválida",
                    f"La {label} no tiene formato hexadecimal válido.",
                    parent=dlg)
                return False
            if len(raw) != expected_bytes:
                messagebox.showerror("Llave inválida",
                    f"La {label} no tiene la longitud correcta.\n"
                    "Verifica que sea una llave completa y correcta.",
                    parent=dlg)
                return False
            return True

        def do_save():
            name = dlg_name.get().strip()
            acc  = dlg_access.get().strip()
            sign = dlg_signing.get().strip()
            if not name or not acc or not sign:
                messagebox.showwarning("Datos incompletos",
                    "Todos los campos son obligatorios:\n"
                    "• Nombre\n• Llave pública de acceso\n• Llave pública de firma",
                    parent=dlg)
                return
            # Validar formato y longitud de ambas llaves
            if not _validate_hex_key(acc, 65, "llave pública de acceso"):
                return
            if not _validate_hex_key(sign, 32, "llave pública de firma"):
                return
            c = load_contacts()
            # Verificar que la llave de acceso no pertenezca a otro contacto
            dup = find_duplicate_access_key(c, acc, exclude_name=name)
            if dup:
                messagebox.showerror("Llave duplicada",
                    f"La llave de acceso ya está registrada para '{dup}'.\n\n"
                    "Cada contacto debe tener una llave de acceso única.",
                    parent=dlg)
                return
            c[name] = {"access": acc, "signing": sign}
            save_contacts(c)
            set_status(f"✔ '{name}' guardado en la agenda.", SUCCESS)
            dlg.destroy()

        StyledButton(dlg, "💾 Guardar en Agenda", do_save, color=TEAL).pack(pady=10)

    save_btn = tk.Button(frame, text="💾", bg=SUCCESS, fg="white",
                         font=("Segoe UI", 8, "bold"), relief="flat",
                         cursor="hand2", width=2, padx=4,
                         command=save_to_agenda)
    save_btn.pack(side="left", padx=(4, 2))

    rm_btn = tk.Button(frame, text="✕", bg=DANGER, fg="white",
                       font=("Segoe UI", 8, "bold"), relief="flat",
                       cursor="hand2", width=2, padx=4)
    rm_btn.pack(side="left")
    _remove_buttons[id(name_entry)] = rm_btn

    def remove():
        if not messagebox.askyesno(
            "Eliminar destinatario",
            "⚠️ Eliminar este destinatario solo afecta FUTUROS cifrados.\n\n"
            "Los archivos ya cifrados siguen siendo accesibles para él.\n"
            "Para revocar acceso, re-cifra sin este destinatario.\n\n"
            "¿Deseas eliminarlo?",
        ):
            return
        recipient_rows.remove((name_entry, key_entry))
        _remove_buttons.pop(id(name_entry), None)
        frame.destroy()
        _update_remove_buttons()

    rm_btn.config(command=remove)
    recipient_rows.append((name_entry, key_entry))
    _update_remove_buttons()


# ──────────────────────────────────────────────────────────────────────────────
#  Cifrar
# ──────────────────────────────────────────────────────────────────────────────

def select_file():
    global selected_file
    path = filedialog.askopenfilename(
        title="Seleccionar archivo a cifrar",
        filetypes=ALLOWED_FILETYPES,
    )
    if path:
        if not is_allowed_file(path):
            selected_file = None
            label_file.config(text="Ningún archivo seleccionado", fg=TEXT_DIM)
            messagebox.showerror(
                "Archivo no permitido",
                "El tipo de archivo seleccionado no está permitido.\n\n"
                "Formatos aceptados: PDF, EPUB, PNG, JPG/JPEG y XPS.",
            )
            return
        selected_file = path
        label_file.config(text=Path(path).name, fg=TEXT)
        set_status(f"Archivo listo: {Path(path).name}")


def encrypt():
    if not selected_file:
        messagebox.showerror("Error", "Selecciona un archivo primero.")
        return

    if not is_allowed_file(selected_file):
        messagebox.showerror(
            "Archivo no permitido",
            "El tipo de archivo seleccionado no está permitido.\n\n"
            "Formatos aceptados: PDF, EPUB, PNG, JPG/JPEG y XPS.",
        )
        return

    recipients = get_recipients()
    if not recipients:
        messagebox.showerror("Error",
                             "Agrega al menos 1 destinatario con nombre y llave pública.")
        return

    # Leer clave privada Ed25519 del firmante (hex → bytes)
    signing_priv_hex = entry_signing_priv.get().strip()
    if not signing_priv_hex:
        messagebox.showerror("Error",
                             "Ingresa tu llave privada de firma para firmar el contenedor.")
        return
    try:
        signing_priv_bytes = bytes.fromhex(signing_priv_hex)
    except ValueError:
        messagebox.showerror("Error",
                             "La llave ingresada no es válida.")
        return
    if len(signing_priv_bytes) != 32:
        messagebox.showerror("Error", "La llave ingresada no es válida.")
        return

    output_dir = filedialog.askdirectory(title="Seleccionar carpeta de destino")
    if not output_dir:
        return

    timestamp      = datetime.now().strftime("%Y%m%d_%H%M%S")
    container_path = Path(output_dir) / f"{Path(selected_file).stem}_{timestamp}"

    set_status("Cifrando y firmando…", ACCENT)
    root.update()

    try:
        result = encrypt_file_for_recipients(
            input_path            = selected_file,
            output_dir            = container_path,
            recipient_public_keys = recipients,
            signing_private_key   = signing_priv_bytes,
        )
        set_status(f"✔ Cifrado y firmado → {result.name}", SUCCESS)
        messagebox.showinfo(
            "Cifrado y firmado exitoso",
            f"✔ Archivo cifrado y firmado correctamente.\n\n"
            f"Contenedor:\n{result}\n\n"
            f"Destinatarios: {', '.join(recipients.keys())}",
        )
    except FileExistsError as e:
        log_security_error("encrypt_output_exists", e)
        set_status("No se pudo completar la operación.", DANGER)
        messagebox.showerror("No se pudo completar", GENERIC_CONTAINER_ERROR)
    except ValueError as e:
        log_security_error("encrypt_validation", e)
        set_status("No se pudo completar la operación.", DANGER)
        messagebox.showerror("No se pudo completar", GENERIC_CONTAINER_ERROR)
    except Exception as e:
        log_security_error("encrypt_unexpected", e)
        set_status("No se pudo completar la operación.", DANGER)
        messagebox.showerror("No se pudo completar", GENERIC_CONTAINER_ERROR)


# ──────────────────────────────────────────────────────────────────────────────
#  Descifrar
# ──────────────────────────────────────────────────────────────────────────────

def decrypt():
    base_dir = filedialog.askdirectory(title="Seleccionar carpeta del contenedor")
    if not base_dir:
        return
    container_path = _resolve_container(base_dir)
    if container_path is None:
        return

    priv_key = entry_dec_priv.get().strip()
    pub_key  = entry_dec_pub.get().strip()
    signing_pub_hex = entry_dec_signing_pub.get().strip()

    if not priv_key:
        messagebox.showerror("Error", "Introduce tu llave privada."); return
    if not pub_key:
        messagebox.showerror("Error", "Introduce tu llave pública."); return
    if not signing_pub_hex:
        messagebox.showerror("Error",
                             "Introduce la llave pública de firma del remitente.\n\n"
                             "Es obligatoria para verificar la firma antes de descifrar.")
        return

    try:
        signing_pub_bytes = bytes.fromhex(signing_pub_hex)
    except ValueError:
        messagebox.showerror("Error", "La llave ingresada no es válida.")
        return
    if len(signing_pub_bytes) != 32:
        messagebox.showerror("Error", "La llave ingresada no es válida.")
        return

    # Leer el nombre original del archivo desde los metadatos del contenedor
    # para pre-rellenar el diálogo con el nombre y extensión correctos
    try:
        _info = get_container_info(container_path)
        _original_name = _info.get("original_filename") or "archivo_descifrado"
        _original_ext  = Path(_original_name).suffix or ""
        _original_stem = Path(_original_name).stem
    except Exception:
        _original_name = "archivo_descifrado"
        _original_ext  = ""
        _original_stem = "archivo_descifrado"

    output_file = filedialog.asksaveasfilename(
        title="Guardar archivo descifrado",
        initialfile=_original_name,
        defaultextension=_original_ext,
        filetypes=[
            (f"Archivo original (*{_original_ext})", f"*{_original_ext}") if _original_ext else ("Todos", "*.*"),
            ("Todos los archivos", "*.*"),
        ],
    )
    if not output_file:
        return

    set_status("Verificando y descifrando…", ACCENT)
    root.update()

    try:
        result_path, info = decrypt_file_for_recipient(
            container_dir             = str(container_path),
            recipient_private_key_hex = priv_key,
            recipient_public_key_hex  = pub_key,
            output_path               = output_file,
            signing_public_key        = signing_pub_bytes,
        )
        set_status(f"✔ Verificación y descifrado completados → {result_path.name}", SUCCESS)
        messagebox.showinfo(
            "Descifrado exitoso",
            f"✔ Firma verificada correctamente.\n"
            f"✔ Contenedor descifrado y autenticado.\n\n"
            f"Guardado en  : {result_path}\n\n"
            f"Archivo      : {info['original_filename']}\n"
            f"Creado       : {info['created_at']}\n"
            f"Identificador: {info['signer_id']}\n"
            f"Tamaño       : {info['plaintext_size']:,} bytes",
        )

    except (HybridVaultSignatureError, HybridVaultAuthenticationError, HybridVaultFormatError) as e:
        # No revelar si falló la firma, la clave, AEAD o el formato.
        # Los detalles se guardan únicamente en logs locales de seguridad.
        log_security_error("decrypt_container", e)
        set_status("No se pudo procesar el contenedor.", DANGER)
        messagebox.showerror("No se pudo procesar el contenedor", GENERIC_CONTAINER_ERROR)

    except Exception as e:
        # También evitar filtrar rutas, trazas o mensajes internos en errores inesperados.
        log_security_error("decrypt_unexpected", e)
        set_status("No se pudo procesar el contenedor.", DANGER)
        messagebox.showerror("No se pudo procesar el contenedor", GENERIC_CONTAINER_ERROR)


# ──────────────────────────────────────────────────────────────────────────────
#  Ventana principal  (con scroll para adaptarse a cualquier resolución)
# ──────────────────────────────────────────────────────────────────────────────

root = tk.Tk()
root.title("CryptoGO")
root.configure(bg=BG)

# Tamaño inicial: 90% de la pantalla disponible, máximo 800x900
_sw = root.winfo_screenwidth()
_sh = root.winfo_screenheight()
_w  = min(800, int(_sw * 0.90))
_h  = min(900, int(_sh * 0.90))
root.geometry(f"{_w}x{_h}")
root.resizable(True, True)
root.minsize(700, 500)

# ── Canvas + Scrollbar para scroll vertical ───────────────────────────────────
_canvas = tk.Canvas(root, bg=BG, highlightthickness=0)
_vscroll = tk.Scrollbar(root, orient="vertical", command=_canvas.yview)
_canvas.configure(yscrollcommand=_vscroll.set)
_vscroll.pack(side="right", fill="y")
_canvas.pack(side="left", fill="both", expand=True)

# Frame interior que contiene todo el contenido
_inner = tk.Frame(_canvas, bg=BG)
_inner_id = _canvas.create_window((0, 0), window=_inner, anchor="nw")

def _on_frame_configure(event):
    _canvas.configure(scrollregion=_canvas.bbox("all"))

def _on_canvas_configure(event):
    _canvas.itemconfig(_inner_id, width=event.width)

_inner.bind("<Configure>", _on_frame_configure)
_canvas.bind("<Configure>", _on_canvas_configure)

# Scroll con rueda del ratón
def _on_mousewheel(event):
    _canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
root.bind_all("<MouseWheel>", _on_mousewheel)

# A partir de aquí todos los widgets van dentro de _inner (no de root)
_root = _inner   # alias para no cambiar el resto del código


# ── Cabecera ──────────────────────────────────────────────────────────────────
tk.Frame(_root, bg=CHERRY, height=5).pack(fill="x")
tk.Label(_root, text="CryptoGO", bg=BG, fg=TEXT,
         font=("Segoe UI", 18, "bold")).pack(pady=(12, 0))
tk.Label(_root, text="Protección de archivos  ·  Firma digital  ·  Verificación",
         bg=BG, fg=VIOLET, font=("Segoe UI", 9)).pack(pady=(0, 8))

# ── Barra de herramientas ─────────────────────────────────────────────────────
tools_frame = tk.Frame(_root, bg=BG_PANEL, pady=6, padx=14,
                       highlightthickness=1, highlightbackground=BORDER)
tools_frame.pack(fill="x", padx=14, pady=2)

StyledButton(tools_frame, "🔑 Llaves de acceso",
             open_keygen_window, color=VIOLET).pack(side="left", padx=3)
StyledButton(tools_frame, "✍️ Llaves de firma",
             open_signing_keygen_window, color=CHERRY).pack(side="left", padx=3)
StyledButton(tools_frame, "🔓 Recuperar llave de acceso privada",
             open_recover_key_window, color=INDIGO).pack(side="left", padx=3)
StyledButton(tools_frame, "👥 Agenda",
             open_contacts_window, color=TEAL).pack(side="left", padx=3)

hsep(_root)

# ── Sección: Cifrar ───────────────────────────────────────────────────────────
enc_body = make_section(_root, "📦  CIFRAR Y FIRMAR ARCHIVO")

row_file = tk.Frame(enc_body, bg=BG_PANEL)
row_file.pack(fill="x", pady=2)
StyledButton(row_file, "Seleccionar archivo", select_file,
             color=INDIGO).pack(side="left")
label_file = tk.Label(row_file, text="Ningún archivo seleccionado",
                      bg=BG_PANEL, fg=TEXT_DIM, font=("Segoe UI", 9))
label_file.pack(side="left", padx=10)

# Clave privada Ed25519 del firmante
lbl(enc_body, "Tu llave privada de firma — para firmar el contenedor:",
    bold=True, color=DANGER).pack(anchor="w", pady=(10, 0))
entry_signing_priv = StyledEntry(enc_body, show_char="•", width=82)
entry_signing_priv.pack(fill="x", pady=(2, 2))

sign_toggle = {"show": False}
def _toggle_signing_priv():
    sign_toggle["show"] = not sign_toggle["show"]
    entry_signing_priv.config(show="" if sign_toggle["show"] else "•")
tk.Button(enc_body, text="Ver / Ocultar llave privada",
          bg=BG_HOVER, fg=TEXT_D, relief="flat", font=("Segoe UI", 8),
          cursor="hand2", command=_toggle_signing_priv).pack(anchor="w", pady=(0, 6))

# Destinatarios con llave pública ECIES
lbl(enc_body, "Destinatarios — nombre y llave pública (mínimo 1):",
    bold=True).pack(anchor="w")
recipients_frame = tk.Frame(enc_body, bg=BG_PANEL)
recipients_frame.pack(fill="x")
add_recipient_row("Destinatario 1")

btn_enc = tk.Frame(enc_body, bg=BG_PANEL)
btn_enc.pack(pady=6)

def add_from_agenda():
    contacts = load_contacts()
    if not contacts:
        messagebox.showinfo("Agenda vacía", "No tienes contactos. Ve a Herramientas -> 'Agenda' para añadir a tus destinatarios.")
        return
    
    win = tk.Toplevel(root)
    win.title("Seleccionar Contacto")
    win.geometry("300x400")
    win.configure(bg=BG)

    tk.Label(win, text="Selecciona un destinatario:", bg=BG, fg=TEXT, font=("Segoe UI", 10, "bold")).pack(pady=10)

    listbox = tk.Listbox(win, font=("Segoe UI", 10), bg=BG_INPUT, fg=TEXT, relief="flat", highlightthickness=1, highlightbackground=BORDER)
    listbox.pack(fill="both", expand=True, padx=20, pady=5)
    
    for name in contacts.keys():
        listbox.insert(tk.END, name)
        
    def on_select():
        sel = listbox.curselection()
        if sel:
            name = listbox.get(sel[0])
            add_recipient_row(name, contacts[name].get("access", ""))
            win.destroy()

    StyledButton(win, "➕ Añadir como destinatario", on_select, color=INDIGO).pack(pady=10)

StyledButton(btn_enc, "+ Agregar destinatario", add_recipient_row,
             color=INDIGO).pack(side="left", padx=4)
StyledButton(btn_enc, "📘 Cargar de Agenda", add_from_agenda,
             color=TEAL).pack(side="left", padx=4)
StyledButton(btn_enc, "🔐 Cifrar y firmar", encrypt,
             color=CHERRY).pack(side="left", padx=14)

hsep(_root)

# ── Sección: Descifrar ────────────────────────────────────────────────────────
dec_body = make_section(_root, "🔓  DESCIFRAR Y VERIFICAR FIRMA")

lbl(dec_body, "Tu llave privada de acceso:", bold=True, color=DANGER).pack(anchor="w")
entry_dec_priv = StyledEntry(dec_body, show_char="•", width=82)
entry_dec_priv.pack(fill="x", pady=(2, 8))

lbl(dec_body, "Tu llave pública de acceso:", bold=True).pack(anchor="w")
entry_dec_pub = StyledEntry(dec_body, width=82)
entry_dec_pub.pack(fill="x", pady=(2, 8))

lbl(dec_body, "Llave pública de firma del remitente — obligatoria:",
    bold=True, color=WARNING).pack(anchor="w")

sign_row = tk.Frame(dec_body, bg=BG_PANEL)
sign_row.pack(fill="x", pady=(2, 8))
entry_dec_signing_pub = StyledEntry(sign_row, width=65)
entry_dec_signing_pub.pack(side="left")

def load_sender_from_agenda():
    contacts = load_contacts()
    if not contacts:
        messagebox.showinfo("Agenda vacía", "No tienes contactos.")
        return
    win = tk.Toplevel(root)
    win.title("Seleccionar Remitente")
    win.geometry("300x400")
    win.configure(bg=BG)
    tk.Label(win, text="Selecciona el remitente:", bg=BG, fg=TEXT, font=("Segoe UI", 10, "bold")).pack(pady=10)
    listbox = tk.Listbox(win, font=("Segoe UI", 10), bg=BG_INPUT, fg=TEXT, relief="flat", highlightthickness=1, highlightbackground=BORDER)
    listbox.pack(fill="both", expand=True, padx=20, pady=5)
    for name in contacts.keys():
        listbox.insert(tk.END, name)
    def on_select():
        sel = listbox.curselection()
        if sel:
            name = listbox.get(sel[0])
            signing_key = contacts[name].get("signing", "")
            if not signing_key:
                messagebox.showwarning("Aviso", f"No tienes guardada la llave de firma de {name}.", parent=win)
                return
            entry_dec_signing_pub.config(state="normal")
            entry_dec_signing_pub.delete(0, tk.END)
            entry_dec_signing_pub.insert(0, signing_key)
            win.destroy()
    StyledButton(win, "📥 Cargar Llave de Firma", on_select, color=INDIGO).pack(pady=10)

StyledButton(sign_row, "📘 Cargar de Agenda", load_sender_from_agenda, color=TEAL).pack(side="left", padx=10)

btn_dec = tk.Frame(dec_body, bg=BG_PANEL)
btn_dec.pack(pady=4)
StyledButton(btn_dec, "🔓 Verificar firma y descifrar", decrypt, color=VIOLET).pack()

hsep(_root)

# ── Barra de estado ───────────────────────────────────────────────────────────
status_bar = tk.Frame(_root, bg=BG_PANEL, pady=5, padx=14,
                      highlightthickness=1, highlightbackground=BORDER)
status_bar.pack(fill="x", padx=14, pady=(2, 10))
status_var   = tk.StringVar(value="  Listo")
status_label = tk.Label(status_bar, textvariable=status_var, bg=BG_PANEL, fg=TEXT_DIM,
                        font=("Consolas", 8), anchor="w")
status_label.pack(fill="x")

root.mainloop()
