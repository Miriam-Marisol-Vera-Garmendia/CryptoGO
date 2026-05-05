import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from datetime import datetime
from pathlib import Path

from encryption.hybrid_vault import (
    encrypt_file_for_recipients,
    decrypt_file_for_recipient,
    generate_ecies_keypair,
    generate_signing_keypair,
    protect_private_key,
    recover_private_key,
    get_container_info,
    public_key_fingerprint,
)
from encryption import (
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
    "No fue posible procesar el contenedor.\n\n"
    "Verifica que las claves sean correctas y que el contenedor no haya sido modificado."
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
#  Ventana: Generar par de claves ECIES (para cifrado)
# ──────────────────────────────────────────────────────────────────────────────

def open_keygen_window():
    win = tk.Toplevel(root)
    win.title("Generar par de claves ECIES (cifrado)")
    win.geometry("700x390")
    win.resizable(False, False)
    win.configure(bg=BG)

    tk.Label(win, text="Generador de claves ECIES", bg=BG, fg=TEXT,
             font=("Segoe UI", 13, "bold")).pack(pady=(16, 2))
    tk.Label(win, text="Par de claves para cifrado/descifrado de archivos (secp256k1)",
             bg=BG, fg=TEXT_DIM, font=("Segoe UI", 9)).pack()

    frame = tk.Frame(win, bg=BG_PANEL, padx=16, pady=14,
                     highlightthickness=1, highlightbackground=BORDER)
    frame.pack(fill="x", padx=20, pady=12)

    priv_hex = tk.StringVar()
    pub_hex  = tk.StringVar()

    tk.Label(frame, text="Clave pública  —  comparte con quien cifrará para ti",
             bg=BG_PANEL, fg=TEXT, font=("Segoe UI", 8, "bold")).pack(anchor="w")
    pub_entry = tk.Entry(frame, width=92, bg=BG_INPUT, fg=TEXT, relief="flat",
                         font=("Consolas", 8), highlightthickness=1,
                         highlightbackground=BORDER, state="readonly")
    pub_entry.pack(fill="x", pady=(2, 8))

    tk.Label(frame, text="Clave privada  —  NO la compartas nunca",
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
        set_status("✔ Par de claves ECIES generado.", SUCCESS)

    def toggle_priv():
        s = priv_entry.cget("show")
        priv_entry.config(state="normal", show="" if s == "•" else "•")
        priv_entry.config(state="readonly")

    def copy_pub():
        if pub_hex.get():
            copy_to_clipboard(pub_hex.get())
            messagebox.showinfo("Copiado", "Clave pública copiada.", parent=win)

    def copy_priv():
        if priv_hex.get():
            copy_to_clipboard(priv_hex.get())
            messagebox.showinfo("Copiado", "Clave privada copiada.", parent=win)

    def save_protected():
        if not priv_hex.get():
            messagebox.showwarning("Sin clave", "Genera un par primero.", parent=win)
            return
        pw_win = tk.Toplevel(win)
        pw_win.title("Proteger clave privada ECIES")
        pw_win.geometry("440x200")
        pw_win.configure(bg=BG)
        pw_win.resizable(False, False)
        tk.Label(pw_win, text="Contraseña para cifrar la clave privada ECIES",
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
            try:
                protected = protect_private_key(priv_hex.get(), pw)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=pw_win); return
            path = filedialog.asksaveasfilename(
                parent=pw_win, title="Guardar .vkey",
                defaultextension=".vkey",
                filetypes=[("CryptoGO Key", "*.vkey"), ("Todos", "*.*")],
            )
            if path:
                Path(path).write_bytes(protected)
                messagebox.showinfo("Guardado", f"Guardada en:\n{path}", parent=pw_win)
                set_status("✔ Clave ECIES protegida guardada.", SUCCESS)
                pw_win.destroy()

        StyledButton(pw_win, "🔒 Cifrar y guardar", do_save, color=TEAL).pack()

    btn_row = tk.Frame(win, bg=BG)
    btn_row.pack(pady=6)
    StyledButton(btn_row, "⚡ Generar",          do_generate,    color=VIOLET).pack(side="left", padx=3)
    StyledButton(btn_row, "👁 Ver/Ocultar",       toggle_priv,    color=INDIGO).pack(side="left", padx=3)
    StyledButton(btn_row, "📋 Copiar pública",    copy_pub,       color=ROSE).pack(side="left", padx=3)
    StyledButton(btn_row, "📋 Copiar privada",    copy_priv,      color=CHERRY).pack(side="left", padx=3)
    StyledButton(btn_row, "🔒 Guardar protegida", save_protected, color=TEAL).pack(side="left", padx=3)


# ──────────────────────────────────────────────────────────────────────────────
#  Ventana: Generar par de claves Ed25519 (para firma digital)
# ──────────────────────────────────────────────────────────────────────────────

def open_signing_keygen_window():
    """
    Genera un par de claves Ed25519 para firma digital.
    Las claves se representan como hexadecimal para facilitar su copia y uso en la GUI.
    Internamente el módulo opera con bytes raw (32B privada, 32B pública).
    """
    win = tk.Toplevel(root)
    win.title("Generar claves de firma Ed25519")
    win.geometry("700x400")
    win.resizable(False, False)
    win.configure(bg=BG)

    tk.Label(win, text="Generador de claves de firma Ed25519", bg=BG, fg=TEXT,
             font=("Segoe UI", 13, "bold")).pack(pady=(16, 2))
    tk.Label(win, text="Par de claves para firmar y verificar contenedores (D4)",
             bg=BG, fg=TEXT_DIM, font=("Segoe UI", 9)).pack()

    frame = tk.Frame(win, bg=BG_PANEL, padx=16, pady=14,
                     highlightthickness=1, highlightbackground=BORDER)
    frame.pack(fill="x", padx=20, pady=12)

    priv_hex_var = tk.StringVar()
    pub_hex_var  = tk.StringVar()

    tk.Label(frame,
             text="Clave pública Ed25519 (hex)  —  comparte con quien verificará tu firma",
             bg=BG_PANEL, fg=TEXT, font=("Segoe UI", 8, "bold")).pack(anchor="w")
    pub_entry = tk.Entry(frame, width=92, bg=BG_INPUT, fg=TEXT, relief="flat",
                         font=("Consolas", 8), highlightthickness=1,
                         highlightbackground=BORDER, state="readonly")
    pub_entry.pack(fill="x", pady=(2, 8))

    tk.Label(frame,
             text="Clave privada Ed25519 (hex)  —  NO la compartas nunca",
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
        sid_var.set(f"signer_id (SHA-256 de pub): {sid}")
        set_status("✔ Par de claves Ed25519 generado.", SUCCESS)

    def toggle_priv():
        s = priv_entry.cget("show")
        priv_entry.config(state="normal", show="" if s == "•" else "•")
        priv_entry.config(state="readonly")

    def copy_pub():
        if pub_hex_var.get():
            copy_to_clipboard(pub_hex_var.get())
            messagebox.showinfo("Copiado", "Clave pública Ed25519 copiada.", parent=win)

    def copy_priv():
        if priv_hex_var.get():
            copy_to_clipboard(priv_hex_var.get())
            messagebox.showinfo("Copiado", "Clave privada Ed25519 copiada.", parent=win)

    def save_keys():
        """Guarda las claves en archivos de texto con el valor hex, igual a lo que se muestra en pantalla."""
        if not pub_hex_var.get():
            messagebox.showwarning("Sin clave", "Genera un par primero.", parent=win)
            return
        pub_path = filedialog.asksaveasfilename(
            parent=win, title="Guardar clave pública Ed25519",
            defaultextension=".txt",
            filetypes=[("Texto hex", "*.txt"), ("Todos", "*.*")],
        )
        if pub_path:
            Path(pub_path).write_text(pub_hex_var.get(), encoding="utf-8")
            messagebox.showinfo("Guardado", f"Clave pública guardada en:\n{pub_path}", parent=win)

        priv_path = filedialog.asksaveasfilename(
            parent=win, title="Guardar clave privada Ed25519",
            defaultextension=".txt",
            filetypes=[("Texto hex", "*.txt"), ("Todos", "*.*")],
        )
        if priv_path:
            Path(priv_path).write_text(priv_hex_var.get(), encoding="utf-8")
            messagebox.showinfo("Guardado", f"Clave privada guardada en:\n{priv_path}", parent=win)
            set_status("✔ Claves Ed25519 guardadas.", SUCCESS)

    btn_row = tk.Frame(win, bg=BG)
    btn_row.pack(pady=6)
    StyledButton(btn_row, "⚡ Generar",        do_generate, color=VIOLET).pack(side="left", padx=3)
    StyledButton(btn_row, "👁 Ver/Ocultar",     toggle_priv, color=INDIGO).pack(side="left", padx=3)
    StyledButton(btn_row, "📋 Copiar pública",  copy_pub,    color=ROSE).pack(side="left", padx=3)
    StyledButton(btn_row, "📋 Copiar privada",  copy_priv,   color=CHERRY).pack(side="left", padx=3)
    StyledButton(btn_row, "💾 Guardar en disco", save_keys,  color=TEAL).pack(side="left", padx=3)


# ──────────────────────────────────────────────────────────────────────────────
#  Ventana: Recuperar clave privada ECIES desde .vkey
# ──────────────────────────────────────────────────────────────────────────────

def open_recover_key_window():
    win = tk.Toplevel(root)
    win.title("Recuperar clave privada ECIES (.vkey)")
    win.geometry("580x260")
    win.configure(bg=BG)
    win.resizable(False, False)

    tk.Label(win, text="Recuperar clave privada ECIES protegida", bg=BG, fg=TEXT,
             font=("Segoe UI", 12, "bold")).pack(pady=(14, 2))

    frame = tk.Frame(win, bg=BG_PANEL, padx=14, pady=12,
                     highlightthickness=1, highlightbackground=BORDER)
    frame.pack(fill="x", padx=18, pady=8)

    file_var = tk.StringVar(value="Ningún archivo seleccionado")
    tk.Label(frame, textvariable=file_var, bg=BG_PANEL, fg=TEXT_DIM,
             font=("Consolas", 8)).pack(anchor="w", pady=(0, 4))

    key_path: dict = {"path": None}

    def pick_file():
        p = filedialog.askopenfilename(
            parent=win, title="Seleccionar .vkey",
            filetypes=[("CryptoGO Key", "*.vkey"), ("Todos", "*.*")],
        )
        if p:
            key_path["path"] = p; file_var.set(Path(p).name)

    StyledButton(frame, "Seleccionar archivo .vkey", pick_file,
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
            messagebox.showwarning("Sin archivo", "Selecciona un .vkey.", parent=win); return
        try:
            priv = recover_private_key(Path(key_path["path"]).read_bytes(), pw_entry.get())
            result_var.set(priv)
            set_status("✔ Clave ECIES recuperada.", SUCCESS)
        except HybridVaultAuthenticationError:
            messagebox.showerror("Error", "Contraseña incorrecta o archivo corrupto.", parent=win)
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=win)

    def copy_result():
        if result_var.get():
            copy_to_clipboard(result_var.get())
            messagebox.showinfo("Copiado", "Clave copiada.", parent=win)

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
        messagebox.showerror("Error", str(e)); return
    except Exception as e:
        messagebox.showerror("Error", str(e)); return

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
        f"  Algoritmo de firma : {info['signature_algorithm']}",
        f"  signer_id          : {info['signer_id']}",
        "",
        f"  Recipients ({len(info['recipients'])}):",
    ]
    for r in info["recipients"]:
        lines.append(f"    • {r['id']}   [{r['key_id']}]")

    txt.insert("1.0", "\n".join(lines))
    txt.config(state="disabled")


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

    tk.Label(frame, text="Clave pública ECIES:", bg=BG_PANEL, fg=TEXT_DIM,
             font=("Segoe UI", 8), width=18, anchor="e").pack(side="left")
    key_entry = StyledEntry(frame, width=46)
    key_entry.insert(0, key_default)
    key_entry.pack(side="left", padx=(2, 4))

    rm_btn = tk.Button(frame, text="✕", bg=DANGER, fg="white",
                       font=("Segoe UI", 8, "bold"), relief="flat",
                       cursor="hand2", width=2, padx=4)
    rm_btn.pack(side="left")
    _remove_buttons[id(name_entry)] = rm_btn

    def remove():
        if not messagebox.askyesno(
            "Eliminar recipient",
            "⚠️ Eliminar este recipient solo afecta FUTUROS cifrados.\n\n"
            "Los archivos ya cifrados siguen siendo accesibles para él.\n"
            "Para revocar acceso, re-cifra sin este recipient.\n\n"
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
    path = filedialog.askopenfilename(title="Seleccionar archivo a cifrar")
    if path:
        selected_file = path
        label_file.config(text=Path(path).name, fg=TEXT)
        set_status(f"Archivo listo: {Path(path).name}")


def encrypt():
    if not selected_file:
        messagebox.showerror("Error", "Selecciona un archivo primero.")
        return

    recipients = get_recipients()
    if not recipients:
        messagebox.showerror("Error",
                             "Agrega al menos 1 recipient con nombre y clave pública ECIES.")
        return

    # Leer clave privada Ed25519 del firmante (hex → bytes)
    signing_priv_hex = entry_signing_priv.get().strip()
    if not signing_priv_hex:
        messagebox.showerror("Error",
                             "Ingresa tu clave privada Ed25519 para firmar el contenedor.")
        return
    try:
        signing_priv_bytes = bytes.fromhex(signing_priv_hex)
    except ValueError:
        messagebox.showerror("Error",
                             "La clave privada Ed25519 no es hexadecimal válido.")
        return
    if len(signing_priv_bytes) != 32:
        messagebox.showerror("Error",
                             f"La clave privada Ed25519 debe tener 32 bytes (64 hex chars). "
                             f"Se recibieron {len(signing_priv_bytes)} bytes.")
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
            f"✔ Archivo cifrado y firmado con Ed25519.\n\n"
            f"Contenedor:\n{result}\n\n"
            f"Recipients: {', '.join(recipients.keys())}",
        )
    except FileExistsError as e:
        set_status("Error: directorio destino ya existe.", DANGER)
        messagebox.showerror("Error", str(e))
    except ValueError as e:
        set_status("Error de configuración.", DANGER)
        messagebox.showerror("Error de configuración", str(e))
    except Exception as e:
        set_status("Error inesperado.", DANGER)
        messagebox.showerror("Error inesperado", str(e))


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
        messagebox.showerror("Error", "Introduce tu clave privada ECIES."); return
    if not pub_key:
        messagebox.showerror("Error", "Introduce tu clave pública ECIES."); return
    if not signing_pub_hex:
        messagebox.showerror("Error",
                             "Introduce la clave pública Ed25519 del firmante.\n\n"
                             "Es obligatoria para verificar la firma antes de descifrar.")
        return

    try:
        signing_pub_bytes = bytes.fromhex(signing_pub_hex)
    except ValueError:
        messagebox.showerror("Error", "La clave pública Ed25519 no es hexadecimal válido.")
        return
    if len(signing_pub_bytes) != 32:
        messagebox.showerror("Error",
                             f"La clave pública Ed25519 debe tener 32 bytes (64 hex chars). "
                             f"Se recibieron {len(signing_pub_bytes)} bytes.")
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

    set_status("Verificando firma y descifrando…", ACCENT)
    root.update()

    try:
        result_path, info = decrypt_file_for_recipient(
            container_dir             = str(container_path),
            recipient_private_key_hex = priv_key,
            recipient_public_key_hex  = pub_key,
            output_path               = output_file,
            signing_public_key        = signing_pub_bytes,
        )
        set_status(f"✔ Firma verificada y descifrado completado → {result_path.name}", SUCCESS)
        messagebox.showinfo(
            "Descifrado exitoso",
            f"✔ Firma Ed25519 verificada correctamente.\n"
            f"✔ Contenedor descifrado y autenticado (AEAD).\n\n"
            f"Guardado en  : {result_path}\n\n"
            f"Archivo      : {info['original_filename']}\n"
            f"Creado       : {info['created_at']}\n"
            f"signer_id    : {info['signer_id']}\n"
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
root.title("CryptoGO Secure Vault")
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
tk.Label(_root, text="CryptoGO Secure Vault", bg=BG, fg=TEXT,
         font=("Segoe UI", 18, "bold")).pack(pady=(12, 0))
tk.Label(_root, text="ECIES  ·  ChaCha20-Poly1305  ·  Ed25519",
         bg=BG, fg=VIOLET, font=("Segoe UI", 9)).pack(pady=(0, 8))

# ── Barra de herramientas ─────────────────────────────────────────────────────
tools_frame = tk.Frame(_root, bg=BG_PANEL, pady=6, padx=14,
                       highlightthickness=1, highlightbackground=BORDER)
tools_frame.pack(fill="x", padx=14, pady=2)

StyledButton(tools_frame, "🔑 Claves ECIES",
             open_keygen_window, color=VIOLET).pack(side="left", padx=3)
StyledButton(tools_frame, "✍️ Claves de firma Ed25519",
             open_signing_keygen_window, color=CHERRY).pack(side="left", padx=3)
StyledButton(tools_frame, "🔓 Recuperar .vkey",
             open_recover_key_window, color=INDIGO).pack(side="left", padx=3)
StyledButton(tools_frame, "🔍 Inspeccionar",
             open_inspect_window, color=INDIGO).pack(side="left", padx=3)

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
lbl(enc_body, "Tu clave privada Ed25519 (hex, 64 chars)  —  para firmar el contenedor:",
    bold=True, color=DANGER).pack(anchor="w", pady=(10, 0))
entry_signing_priv = StyledEntry(enc_body, show_char="•", width=82)
entry_signing_priv.pack(fill="x", pady=(2, 2))

sign_toggle = {"show": False}
def _toggle_signing_priv():
    sign_toggle["show"] = not sign_toggle["show"]
    entry_signing_priv.config(show="" if sign_toggle["show"] else "•")
tk.Button(enc_body, text="Ver / Ocultar clave privada Ed25519",
          bg=BG_HOVER, fg=TEXT_DIM, relief="flat", font=("Segoe UI", 8),
          cursor="hand2", command=_toggle_signing_priv).pack(anchor="w", pady=(0, 6))

# Recipients con clave pública ECIES
lbl(enc_body, "Recipients — nombre y clave pública ECIES (mínimo 1):",
    bold=True).pack(anchor="w")
recipients_frame = tk.Frame(enc_body, bg=BG_PANEL)
recipients_frame.pack(fill="x")
add_recipient_row("Recipient 1")

btn_enc = tk.Frame(enc_body, bg=BG_PANEL)
btn_enc.pack(pady=6)
StyledButton(btn_enc, "+ Agregar recipient", add_recipient_row,
             color=INDIGO).pack(side="left", padx=4)
StyledButton(btn_enc, "🔐 Cifrar y firmar", encrypt,
             color=CHERRY).pack(side="left", padx=4)

hsep(_root)

# ── Sección: Descifrar ────────────────────────────────────────────────────────
dec_body = make_section(_root, "🔓  DESCIFRAR Y VERIFICAR FIRMA")

lbl(dec_body, "Tu clave privada ECIES (hex):", bold=True, color=DANGER).pack(anchor="w")
entry_dec_priv = StyledEntry(dec_body, show_char="•", width=82)
entry_dec_priv.pack(fill="x", pady=(2, 8))

lbl(dec_body, "Tu clave pública ECIES (hex):", bold=True).pack(anchor="w")
entry_dec_pub = StyledEntry(dec_body, width=82)
entry_dec_pub.pack(fill="x", pady=(2, 8))

lbl(dec_body, "Clave pública Ed25519 del firmante (hex, 64 chars)  —  obligatoria:",
    bold=True, color=WARNING).pack(anchor="w")
entry_dec_signing_pub = StyledEntry(dec_body, width=82)
entry_dec_signing_pub.pack(fill="x", pady=(2, 8))

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
