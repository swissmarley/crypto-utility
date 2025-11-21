# 🔐 CryptoUtility

**CryptoUtility** is a professional-grade, modular Python toolkit for cryptography, security operations, and network analysis. It is designed for developers, sysadmins, and security enthusiasts to perform complex cryptographic tasks via a clean CLI or an interactive menu.

## 🚀 Features

* **SSH Tools:** Generate RSA/ED25519 keys, export fingerprints.
* **SSL/TLS:** Create self-signed certs, inspect domain certificates.
* **Hashing:** File and string hashing (SHA256, MD5, etc.).
* **Encryption:** Symmetric (Fernet/AES) and Asymmetric (RSA).
* **Password Vault:** Local, encrypted storage for secrets.
* **JWT:** Decode and verify JSON Web Tokens.
* **Network:** Port scanning and certificate fetching.
* **Encodings:** Base64, Hex, URL, Binary visualization.

## 📦 Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourname/crypto-utility.git
    cd crypto-utility
    ```

2.  **Create a Virtual Environment (Recommended):**
    ```bash
    python -m venv venv
    
    # Windows
    venv\Scripts\activate

    # Linux/Mac
    source venv/bin/activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## 🖥️ Usage

You can use the tool in two ways: **Interactive Mode** or **Command Line Mode**.

### 1. Interactive Mode (Menu System)
Simply run the script without arguments to enter the TUI (Text User Interface):

```bash
python main.py
```

Follow the on-screen prompts to navigate menus.

### **2. Command Line Mode (Scripting)**
Pass commands directly for automation.

**SSH Key Generation**:

```bash
python main.py ssh generate --type ed25519 --out ./keys
```

**Hash a File:**

```bash
python main.py hash file ./dist/app.zip
```

**Encrypt a Secret:**

```bash
python main.py enc encrypt MySecretKey "Secret Message"
```

**Scan a Port:**

```bash
python main.py net scan google.com 443
```

**SSL Certificates:**

```bash
# Generate a self-signed cert for localhost
python main.py ssl create localhost --out mycert.pem
```

**JWT Operations:**

```bash
# Create a token
python main.py jwt create '{"user":"admin"}' mysecretkey

# Decode a token (no verification)
python main.py jwt decode <token_string>
```

**Format Conversion:**

```bash
# Convert a PEM key file to DER format
python main.py convert pem2der private_key.pem
```


**Symmetric Encryption:**

```bash
# 1. Generate Key
python main.py sym genkey
# 2. Encrypt
python main.py sym encrypt <key_string> "Secret Message"
```

**Network Scanning:**

```bash
# Fetch SSL info
python main.py net cert google.com
```

## 📂 Project Structure
```
crypto_utility/
├── core/               # Implementation logic
│   ├── ssh_tools.py    # SSH Key generation
│   ├── ssl_tools.py    # Certificates & CSRs
│   ├── symmetric.py    # AES/Fernet
│   ├── vault.py        # Secret Manager
│   └── ...
├── utils/              # Helpers
│   ├── validators.py
│   ├── file_utils.py   # Safe I/O
│   └── __init__.py 
├── cli.py              # Entry point & Interactive 
├── main.py             # Execution wrapper
├── app.py              # GUI App
└── requirements.txt    # Dependencies
```

## ⚠️ Security Notice

**1. Educational vs. Production:** While this project uses production-grade libraries (`cryptography`, `argon2`), the Secret Vault stores data in a local file. If you lose your master password, data is unrecoverable.

**2. Key Management:** Always store generated private keys (`.pem`, `id_rsa`) in secure locations with restricted permissions (chmod 600).

**3. Classic Ciphers:** The `classic` module is for educational purposes only. Do not use Caesar/Vigenère for real security.

**4.Ephemeral Keys:** Keys generated to the console (interactive mode) are not saved automatically unless specified.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
