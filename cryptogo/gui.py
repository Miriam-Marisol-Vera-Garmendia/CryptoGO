import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path
import re

from encryption.file_vault import encrypt_file, decrypt_file

selected_file = None
generated_key = None


def clean_hex(text):
    """Eliminar todo lo que no sea hexadecimal"""
    return re.sub(r'[^0-9a-fA-F]', '', text)


def paste_clean(event):
    """Intercepta CTRL+V y limpia la clave pegada"""
    try:
        text = root.clipboard_get()
        text = clean_hex(text)

        entry_key.delete(0, tk.END)
        entry_key.insert(0, text)

    except:
        pass

    return "break"


def select_file():
    global selected_file
    selected_file = filedialog.askopenfilename()

    if selected_file:
        label_file.config(text=f"Archivo: {selected_file}")


def encrypt():
    global generated_key

    if not selected_file:
        messagebox.showerror("Error", "Selecciona un archivo primero")
        return

    output_dir = filedialog.askdirectory(title="Seleccionar carpeta para contenedor")

    if not output_dir:
        return

    container_path = Path(output_dir) / "vault_container"

    try:
        generated_key = encrypt_file(selected_file, container_path)

        key_hex = generated_key.hex()

        # copiar al portapapeles
        root.clipboard_clear()
        root.clipboard_append(key_hex)
        root.update()

        messagebox.showinfo(
            "Éxito",
            f"Archivo cifrado correctamente.\n\n"
            f"La clave se copió al portapapeles.\n\n"
            f"Guárdala en un lugar seguro."
        )

    except Exception as e:
        messagebox.showerror("Error", str(e))


def decrypt():
    container_dir = filedialog.askdirectory(title="Seleccionar contenedor")

    if not container_dir:
        return

    key_hex = entry_key.get()

    if not key_hex:
        messagebox.showerror("Error", "Introduce la clave")
        return

    try:
        # limpiar clave
        key_hex = clean_hex(key_hex)

        print("Clave limpia:", key_hex)
        print("Longitud:", len(key_hex))

        if len(key_hex) != 64:
            messagebox.showerror(
                "Error",
                f"La clave debe tener 64 caracteres hex.\nActualmente tiene {len(key_hex)}"
            )
            return

        file_key = bytes.fromhex(key_hex)

        output_file = filedialog.asksaveasfilename(
            title="Guardar archivo descifrado",
            defaultextension=".bin"
        )

        if not output_file:
            return

        decrypt_file(container_dir, file_key, output_file)

        messagebox.showinfo("Éxito", "Archivo descifrado correctamente")

    except ValueError:
        messagebox.showerror(
            "Error de clave",
            "La clave no es hexadecimal válida."
        )

    except Exception as e:
        messagebox.showerror("Error", str(e))


# ventana
root = tk.Tk()
root.title("CryptoGO Secure Vault")
root.geometry("500x350")

title = tk.Label(root, text="CryptoGO Secure Vault", font=("Arial", 16))
title.pack(pady=10)

btn_select = tk.Button(root, text="Seleccionar archivo", command=select_file)
btn_select.pack(pady=5)

label_file = tk.Label(root, text="Ningún archivo seleccionado")
label_file.pack(pady=5)

btn_encrypt = tk.Button(root, text="Cifrar archivo", command=encrypt)
btn_encrypt.pack(pady=10)

tk.Label(root, text="Clave para descifrar:").pack()

entry_key = tk.Entry(root, width=60)
entry_key.pack(pady=5)

# interceptar CTRL+V
entry_key.bind("<Control-v>", paste_clean)

btn_decrypt = tk.Button(root, text="Descifrar contenedor", command=decrypt)
btn_decrypt.pack(pady=10)

root.mainloop()