import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import json
import threading

# Import existing core logic
from core import (
    ssh_tools, ssl_tools, hashing, symmetric, network_tools, 
    secret_vault, password_tools, asymmetric, encoding, 
    jwt_tools, random_tools, conversions
)
from utils import file_utils

# Set Appearance
ctk.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue", "green", "dark-blue"

class CryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("CryptoUtility - Professional GUI")
        self.geometry("1100x700")

        # Layout: 1x2 Grid (Sidebar | Main Content)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- Sidebar ---
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(13, weight=1) # Push exit button down

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="CryptoUtility", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Navigation Buttons
        self.buttons = {}
        tools = [
            "SSH Tools", "SSL/TLS", "Hashing", "Encoding", "Symmetric Enc",
            "Asymmetric Enc", "JWT Tools", "Passwords", "Random Utils",
            "Converters", "Network Tools", "Vault"
        ]
        
        for i, tool in enumerate(tools):
            btn = ctk.CTkButton(self.sidebar_frame, text=tool, command=lambda t=tool: self.select_frame(t))
            btn.grid(row=i+1, column=0, padx=20, pady=5)
            self.buttons[tool] = btn

        # --- Main Content Area ---
        self.frames = {}
        self.container = ctk.CTkFrame(self)
        self.container.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        
        # Initialize all tool frames
        self.frames["SSH Tools"] = SSHFrame(self.container)
        self.frames["SSL/TLS"] = SSLFrame(self.container)
        self.frames["Hashing"] = HashingFrame(self.container)
        self.frames["Encoding"] = EncodingFrame(self.container)
        self.frames["Symmetric Enc"] = SymmetricFrame(self.container)
        self.frames["Asymmetric Enc"] = AsymmetricFrame(self.container)
        self.frames["JWT Tools"] = JWTFrame(self.container)
        self.frames["Passwords"] = PasswordFrame(self.container)
        self.frames["Random Utils"] = RandomFrame(self.container)
        self.frames["Converters"] = ConverterFrame(self.container)
        self.frames["Network Tools"] = NetworkFrame(self.container)
        self.frames["Vault"] = VaultFrame(self.container)

        # Select first frame default
        self.select_frame("SSH Tools")

    def select_frame(self, name):
        # Reset button colors
        for btn_name, btn in self.buttons.items():
            btn.configure(fg_color=("gray75", "gray25") if btn_name != name else ("#3B8ED0", "#1F6AA5"))

        # Show selected frame
        for frame in self.frames.values():
            frame.pack_forget()
        self.frames[name].pack(fill="both", expand=True)

# =========================================================
#   BASE FRAME CLASS (Helper for common UI tasks)
# =========================================================
class BaseToolFrame(ctk.CTkFrame):
    def __init__(self, master, title):
        super().__init__(master)
        self.title_label = ctk.CTkLabel(self, text=title, font=ctk.CTkFont(size=24, weight="bold"))
        self.title_label.pack(pady=10, anchor="w")
        
        self.output_box = ctk.CTkTextbox(self, height=150)
        self.output_box.pack(side="bottom", fill="x", padx=10, pady=10)
        
        self.save_btn = ctk.CTkButton(self, text="Save Output to File", command=self.save_output, fg_color="green")
        self.save_btn.pack(side="bottom", pady=5)

    def log(self, message):
        self.output_box.delete("1.0", "end")
        self.output_box.insert("1.0", str(message))

    def save_output(self):
        content = self.output_box.get("1.0", "end").strip()
        if not content:
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if path:
            with open(path, "w") as f:
                f.write(content)
            messagebox.showinfo("Saved", f"Saved to {path}")

# =========================================================
#   TOOL FRAMES
# =========================================================

class SSHFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master, "SSH Key Generator")
        
        self.type_var = ctk.StringVar(value="rsa")
        ctk.CTkOptionMenu(self, values=["rsa", "ed25519"], variable=self.type_var).pack(pady=10)
        
        ctk.CTkButton(self, text="Select Output Folder & Generate", command=self.generate).pack(pady=10)

    def generate(self):
        folder = filedialog.askdirectory()
        if folder:
            try:
                priv, pub, content = ssh_tools.generate_ssh_key(self.type_var.get(), folder)
                self.log(f"Success!\n\nPrivate Key: {priv}\nPublic Key: {pub}\n\nPublic Content:\n{content}")
            except Exception as e:
                self.log(f"Error: {e}")

class SSLFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master, "SSL/TLS Certificate Generator")
        
        self.cn_entry = ctk.CTkEntry(self, placeholder_text="Common Name (e.g. localhost)")
        self.cn_entry.pack(pady=10, fill="x", padx=20)
        
        ctk.CTkButton(self, text="Generate Self-Signed Cert", command=self.generate).pack(pady=10)

    def generate(self):
        cn = self.cn_entry.get()
        if not cn: return
        
        path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM", "*.pem")])
        if path:
            try:
                ssl_tools.generate_self_signed_cert(cn, path)
                self.log(f"Certificate generated successfully at:\n{path}\nKey file at: {path}.key")
            except Exception as e:
                self.log(f"Error: {e}")

class HashingFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master, "Hashing Utilities")
        
        self.tabview = ctk.CTkTabview(self, height=200)
        self.tabview.pack(fill="x", padx=10)
        
        # String Tab
        tab_str = self.tabview.add("String")
        self.str_entry = ctk.CTkEntry(tab_str, placeholder_text="Enter text to hash")
        self.str_entry.pack(pady=10, fill="x")
        
        # File Tab
        tab_file = self.tabview.add("File")
        self.file_btn = ctk.CTkButton(tab_file, text="Choose File", command=self.choose_file)
        self.file_btn.pack(pady=20)
        self.selected_file = None
        
        # Algorithm Selection
        self.algo_var = ctk.StringVar(value="sha256")
        ctk.CTkOptionMenu(self, values=["md5", "sha1", "sha256", "sha512"], variable=self.algo_var).pack(pady=10)
        
        ctk.CTkButton(self, text="Calculate Hash", command=self.calc).pack(pady=10)

    def choose_file(self):
        self.selected_file = filedialog.askopenfilename()
        if self.selected_file:
            self.file_btn.configure(text=os.path.basename(self.selected_file))

    def calc(self):
        algo = self.algo_var.get()
        mode = self.tabview.get()
        
        try:
            if mode == "String":
                data = self.str_entry.get()
                res = hashing.hash_data(data.encode(), algo)
            else:
                if not self.selected_file: return
                res = hashing.hash_file(self.selected_file, algo)
            self.log(f"Algorithm: {algo.upper()}\nResult: {res}")
        except Exception as e:
            self.log(f"Error: {e}")

class EncodingFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master, "Encoding / Decoding")
        
        self.input_box = ctk.CTkTextbox(self, height=80)
        self.input_box.pack(fill="x", padx=10, pady=5)
        self.input_box.insert("1.0", "Enter input here...")
        
        self.action_var = ctk.StringVar(value="Base64 Encode")
        ctk.CTkOptionMenu(self, values=["Base64 Encode", "Base64 Decode", "Hex Encode", "Hex Decode"], variable=self.action_var).pack(pady=10)
        
        ctk.CTkButton(self, text="Process", command=self.process).pack(pady=10)

    def process(self):
        data = self.input_box.get("1.0", "end").strip()
        action = self.action_var.get()
        try:
            if action == "Base64 Encode": res = encoding.to_base64(data.encode())
            elif action == "Base64 Decode": res = encoding.from_base64(data).decode()
            elif action == "Hex Encode": res = encoding.to_hex(data.encode())
            elif action == "Hex Decode": res = encoding.from_hex(data).decode()
            self.log(res)
        except Exception as e:
            self.log(f"Error: {e}")

class SymmetricFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master, "Symmetric Encryption (Fernet)")
        
        self.key_entry = ctk.CTkEntry(self, placeholder_text="Key (Leave empty to generate new)")
        self.key_entry.pack(fill="x", padx=20, pady=5)
        
        self.msg_entry = ctk.CTkEntry(self, placeholder_text="Message / Ciphertext")
        self.msg_entry.pack(fill="x", padx=20, pady=5)
        
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=10)
        
        ctk.CTkButton(btn_frame, text="Generate Key", command=self.gen_key).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Encrypt", command=self.enc).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Decrypt", command=self.dec).pack(side="left", padx=5)

    def gen_key(self):
        key = symmetric.generate_fernet_key().decode()
        self.key_entry.delete(0, "end")
        self.key_entry.insert(0, key)
        self.log(f"New Key Generated: {key}")

    def enc(self):
        try:
            k = self.key_entry.get()
            m = self.msg_entry.get()
            res = symmetric.fernet_encrypt(k.encode(), m.encode()).decode()
            self.log(res)
        except Exception as e: self.log(e)

    def dec(self):
        try:
            k = self.key_entry.get()
            c = self.msg_entry.get()
            res = symmetric.fernet_decrypt(k.encode(), c.encode()).decode()
            self.log(res)
        except Exception as e: self.log(e)

class AsymmetricFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master, "Asymmetric (RSA)")
        ctk.CTkButton(self, text="Generate Key Pair & Save", command=self.gen).pack(pady=20)
    
    def gen(self):
        folder = filedialog.askdirectory(title="Select folder to save keys")
        if folder:
            try:
                priv, pub = asymmetric.generate_rsa_pair()
                # Pass 'pass' as default password for demo, or add input field for it
                priv_pem = asymmetric.serialize_private_key(priv, password="pass")
                pub_pem = asymmetric.serialize_public_key(pub)
                
                file_utils.write_file_bytes(os.path.join(folder, "rsa_private.pem"), priv_pem)
                file_utils.write_file_bytes(os.path.join(folder, "rsa_public.pem"), pub_pem)
                
                self.log(f"Keys saved to {folder}\n(Default password used: 'pass')")
            except Exception as e: self.log(e)

class JWTFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master, "JWT Tools")
        self.payload_box = ctk.CTkTextbox(self, height=60)
        self.payload_box.pack(fill="x", padx=20, pady=5)
        self.payload_box.insert("1.0", '{"user_id": 123}')
        
        self.secret_entry = ctk.CTkEntry(self, placeholder_text="Secret Key")
        self.secret_entry.pack(fill="x", padx=20, pady=5)
        
        self.token_entry = ctk.CTkEntry(self, placeholder_text="Paste Token Here (for Decode/Verify)")
        self.token_entry.pack(fill="x", padx=20, pady=5)
        
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(pady=10)
        ctk.CTkButton(frame, text="Create", command=self.create).pack(side="left", padx=5)
        ctk.CTkButton(frame, text="Decode (No Verify)", command=self.decode_nv).pack(side="left", padx=5)
        ctk.CTkButton(frame, text="Verify", command=self.verify).pack(side="left", padx=5)

    def create(self):
        try:
            p = self.payload_box.get("1.0", "end").strip()
            s = self.secret_entry.get()
            self.log(jwt_tools.create_jwt(p, s))
        except Exception as e: self.log(e)

    def decode_nv(self):
        try:
            t = self.token_entry.get()
            self.log(json.dumps(jwt_tools.decode_jwt_token(t, verify=False), indent=4))
        except Exception as e: self.log(e)

    def verify(self):
        try:
            t = self.token_entry.get()
            s = self.secret_entry.get()
            res = jwt_tools.decode_jwt_token(t, secret=s, verify=True)
            self.log(f"Signature Valid!\n{json.dumps(res, indent=4)}")
        except Exception as e: self.log(f"Invalid: {e}")

class PasswordFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master, "Password Tools")
        self.len_slider = ctk.CTkSlider(self, from_=8, to=64, number_of_steps=56)
        self.len_slider.pack(pady=10)
        self.len_slider.set(16)
        
        ctk.CTkButton(self, text="Generate Password", command=self.gen).pack(pady=10)
        
        self.chk_entry = ctk.CTkEntry(self, placeholder_text="Check Password Strength")
        self.chk_entry.pack(fill="x", padx=20, pady=(20, 5))
        ctk.CTkButton(self, text="Check Strength", command=self.check).pack(pady=5)

    def gen(self):
        l = int(self.len_slider.get())
        self.log(password_tools.generate_password(l))
    
    def check(self):
        res = password_tools.check_strength(self.chk_entry.get())
        self.log(f"Strength: {res['strength']}")

class RandomFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master, "Random Utilities")
        self.combo = ctk.CTkOptionMenu(self, values=["UUID", "Hex Token", "URL Token", "PIN"])
        self.combo.pack(pady=10)
        ctk.CTkButton(self, text="Generate", command=self.gen).pack(pady=10)

    def gen(self):
        v = self.combo.get()
        if v == "UUID": res = random_tools.generate_uuid()
        elif v == "Hex Token": res = random_tools.generate_token_hex()
        elif v == "URL Token": res = random_tools.generate_token_urlsafe()
        else: res = random_tools.generate_pin()
        self.log(res)

class ConverterFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master, "File Format Converter")
        self.file_path = None
        self.btn = ctk.CTkButton(self, text="Select Input File", command=self.sel)
        self.btn.pack(pady=10)
        
        self.action = ctk.CTkOptionMenu(self, values=["PEM -> DER", "DER -> PEM"])
        self.action.pack(pady=10)
        
        ctk.CTkButton(self, text="Convert & Save", command=self.convert).pack(pady=10)

    def sel(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path: self.btn.configure(text=os.path.basename(self.file_path))

    def convert(self):
        if not self.file_path: return
        act = self.action.get()
        save_ext = ".der" if "DER" in act else ".pem"
        out_path = filedialog.asksaveasfilename(defaultextension=save_ext)
        
        if out_path:
            try:
                data = file_utils.read_file_bytes(self.file_path)
                if "PEM -> DER" in act:
                    res = conversions.pem_to_der(data)
                else:
                    res = conversions.der_to_pem(data, is_private=False) # Simplified
                
                file_utils.write_file_bytes(out_path, res)
                self.log(f"Saved to {out_path}")
            except Exception as e: self.log(e)

class NetworkFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master, "Network Tools")
        self.host_entry = ctk.CTkEntry(self, placeholder_text="Host / Domain")
        self.host_entry.pack(fill="x", padx=20, pady=5)
        
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(pady=10)
        ctk.CTkButton(frame, text="Get Cert Info", command=self.cert).pack(side="left", padx=5)
        ctk.CTkButton(frame, text="Scan Port 443", command=self.scan).pack(side="left", padx=5)

    def cert(self):
        h = self.host_entry.get()
        try:
            res = network_tools.get_ssl_cert_details(h)
            self.log(str(res))
        except Exception as e: self.log(e)

    def scan(self):
        h = self.host_entry.get()
        res = network_tools.scan_port(h, 443)
        self.log(f"Port 443 on {h} is {'OPEN' if res else 'CLOSED'}")

class VaultFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master, "Secret Vault")
        
        self.pass_entry = ctk.CTkEntry(self, placeholder_text="Master Password", show="*")
        self.pass_entry.pack(fill="x", padx=20, pady=5)
        
        self.key_entry = ctk.CTkEntry(self, placeholder_text="Key Name")
        self.key_entry.pack(fill="x", padx=20, pady=5)
        
        self.val_entry = ctk.CTkEntry(self, placeholder_text="Value (for storage)")
        self.val_entry.pack(fill="x", padx=20, pady=5)
        
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(pady=10)
        ctk.CTkButton(frame, text="Store", command=self.store).pack(side="left", padx=5)
        ctk.CTkButton(frame, text="Retrieve", command=self.retr).pack(side="left", padx=5)

    def store(self):
        p, k, v = self.pass_entry.get(), self.key_entry.get(), self.val_entry.get()
        res = secret_vault.add_secret(p, k, v)
        self.log(res)

    def retr(self):
        p, k = self.pass_entry.get(), self.key_entry.get()
        res = secret_vault.get_secret(p, k)
        self.log(res)

if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()