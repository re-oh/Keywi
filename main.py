import tkinter as tk
from tkinter import filedialog, messagebox, Menu, Toplevel
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class Application(tk.Frame):
  def __init__(self, master=None):
    super().__init__(master)
    self.pack()
    self.create_widgets()
    self.private_key = None
    self.bits = None
    self.has_public_k = False
    self.has_private_k = False
    self.has_file = False

  def create_widgets(self):
    self.master.geometry("300x400")
    self.master.title("Keywi")

    self.menu = Menu(self.master) 
  
    self.key_menu = Menu(self.menu, tearoff=0)
    self.key_menu.add_command(label="Generate new keys", command=self.generate_keys)
    self.key_menu.add_command(label="Import public key")

    self.operations_menu = Menu(self.menu, tearoff=0)
    self.operations_menu.add_command(label="Encrypt", command=self.encrypt)
    self.operations_menu.add_command(label="Decrypt", command=self.decrypt)

    self.menu.add_command(label="Open", command=self.open_file)    
    self.menu.add_cascade(label="Keys", menu=self.key_menu)
    self.menu.add_cascade(label="Operations", menu=self.operations_menu)
    self.master.config(menu=self.menu) 

    self.info_label_frame = tk.LabelFrame(text="Key & File information")
    self.info_label_frame.pack(expand=True, fill='both', anchor="nw")
    self.generate_information(parent=self.info_label_frame)

  def generate_information(self, parent):
    self.path_label = tk.Label(parent, text=f"Current File:", anchor="w")
    self.keyb_label = tk.Label(parent, text=f"Key bitsize:")
    self.priv_key_label = tk.Label(parent, text=f"Public Key:")
    self.pub_key_label = tk.Label(parent, text=f"Private Key:")

    self.path_label.pack(anchor="w")
    self.priv_key_label.pack(anchor="w")
    self.pub_key_label.pack(anchor="w")
    self.keyb_label.pack(anchor="w")

  def encrypt(self):
    if self.has_file != True:
      messagebox.showerror(title="Error", message="No file selected")
    if self.has_public_k != True:
      messagebox.showerror(title="Error", message="Cannot encrypt without public key, generate one or import one to decrypt files")
    
    self.encrypt_file(filename=self.filename, recipient_public_key=self.public_key)
    messagebox.showinfo("File Encrypted", "Finished encrypting file")
  def decrypt(self):
    if self.has_file != True:
      messagebox.showerror(title="Error", message="No file selected")
    if self.has_private_k != True:
      messagebox.showerror(title="Error", message="Cannot decrypt without private key, generate one to encrypt files")
    
    self.decrypt_file(filename=self.filename, recipient_public_key=self.private_key)
    messagebox.showinfo("File Decrypted", "Finished decrypting file")

  def update_label(self, label, newinfo):
    label["text"] = newinfo

  def open_file(self):
    self.filetypes = (
    ('text files', '*.txt'),
    ('All files', '*.*')
    )
    self.filename = filedialog.askopenfilename(
    title='Open a file',
    initialdir='/',
    filetypes=self.filetypes) 
    self.update_label(self.path_label, f"Current File: {self.filename}")
    self.has_file = True

  def generate_keys(self):
    self.kg_window = Toplevel(self.master)
    self.kg_window.geometry("200x100")
    self.kg_window.title("Generate new keys")
    self.key_bits = tk.Label(self.kg_window, text="New key size (bits)")
    self.key_bits_entry = tk.Entry(self.kg_window)
    self.submit_keys = tk.Button(self.kg_window, text="Generate", command=self.submit_new_key_gen)
    self.key_bits.pack()
    self.key_bits_entry.pack()
    self.submit_keys.pack()

  def submit_new_key_gen(self):
    self.bits = self.key_bits_entry.get()
    self.update_label(self.keyb_label, f"Key bitsize: {self.bits}")

    private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
    self.private_key = private_key
    self.public_key = private_key.public_key()

    self.update_label(self.priv_key_label,f"Private Key: RSA_PUB_{self.bits}")
    self.update_label(self.pub_key_label,f"Public Key: RSA_PRI_{self.bits}")
    self.has_private_k = True
    self.has_public_k = True
    self.kg_window.destroy()

  def import_pub_key(self):
    pass

  def encrypt_file(self, filename, recipient_public_key):
        aes_key = Fernet.generate_key()

        encrypted_aes_key = recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(filename, 'rb') as file:
            plaintext = file.read()

        f = Fernet(aes_key)
        encrypted_plaintext = f.encrypt(plaintext)

        with open(filename + '.enc', 'wb') as file:
            file.write(encrypted_aes_key)
            file.write(encrypted_plaintext)

  def decrypt_file(self, filename, recipient_private_key):

    with open(filename, 'rb') as file:

      encrypted_aes_key = file.read(recipient_private_key.key_size // 8)
      encrypted_plaintext = file.read()

      aes_key = recipient_private_key.decrypt(
        encrypted_aes_key,

        padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
        )
      )

      f = Fernet(aes_key)
      plaintext = f.decrypt(encrypted_plaintext)

      with open(filename + '.dec', 'wb') as file:
          file.write(plaintext)


if __name__ == "__main__":
  root = tk.Tk()
  app = Application(master=root)
  app.mainloop()
