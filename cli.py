import click
import sys
import os
import json
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import print as rprint

# Import ALL core modules
from core import (
    ssh_tools, ssl_tools, hashing, symmetric, network_tools, 
    secret_vault, password_tools, asymmetric, encoding, 
    jwt_tools, random_tools, conversions
)
from utils import file_utils

console = Console()

# ==========================================
#   HELPER: OUTPUT & SAVE
# ==========================================

def output_and_save(content: str, title: str = "Result", subdir: str = "general"):
    """
    Prints content to console and offers to save it to a .txt file.
    """
    # 1. Display the result nicely
    console.print(Panel(str(content), title=title, style="green", expand=False))
    
    # 2. Offer to save
    if Confirm.ask("Save this output to a .txt file?", default=False):
        filename = Prompt.ask("Enter filename", default="output.txt")
        
        # Ensure it has .txt extension if no extension provided
        if "." not in filename:
            filename += ".txt"
            
        try:
            # Write output
            saved_path = file_utils.write_file_bytes(filename, str(content).encode('utf-8'), subdir=subdir)
            console.print(f"[dim]Saved successfully to: {saved_path}[/dim]")
        except Exception as e:
            console.print(f"[red]Failed to save: {e}[/red]")

# ==========================================
#   INTERACTIVE MENU SYSTEM
# ==========================================

def print_header():
    console.clear()
    console.print(Panel.fit(
        "[bold cyan]CryptoUtility[/bold cyan]\n"
        "[dim]Professional Security Toolkit[/dim]",
        border_style="blue", subtitle="v1.3 (Save Enabled)"
    ))

def interactive_mode():
    """The main loop for the interactive UI."""
    while True:
        print_header()
        table = Table(show_header=False, box=None)
        table.add_column("Option", style="cyan")
        table.add_column("Description")
        
        table.add_row("1. SSH Tools", "Generate Keys (RSA/ED25519)")
        table.add_row("2. SSL/TLS", "Generate Certs, CSRs")
        table.add_row("3. Hashing", "File & String Integrity")
        table.add_row("4. Encoding", "Base64, Hex, URL")
        table.add_row("5. Symmetric Enc", "AES-GCM, Fernet")
        table.add_row("6. Asymmetric Enc", "RSA Encrypt/Sign")
        table.add_row("7. JWT Tools", "Decode, Verify, Create")
        table.add_row("8. Passwords", "Generate, Vault, Check")
        table.add_row("9. Random Utils", "Tokens, UUIDs")
        table.add_row("10. Converters", "PEM <-> DER")
        table.add_row("11. Network", "Port Scan, Cert Check")
        table.add_row("0. Exit", "")

        console.print(table)
        console.print("[dim]All outputs saved to ./output/{subfolder}[/dim]")
        console.print("---------------------------------")
        
        choice = Prompt.ask("Select Module", choices=[str(i) for i in range(12)], default="0")
        
        if choice == "0": sys.exit(0)
        elif choice == "1": menu_ssh()
        elif choice == "2": menu_ssl()
        elif choice == "3": menu_hashing()
        elif choice == "4": menu_encoding()
        elif choice == "5": menu_symmetric()
        elif choice == "6": menu_asymmetric()
        elif choice == "7": menu_jwt()
        elif choice == "8": menu_password()
        elif choice == "9": menu_random()
        elif choice == "10": menu_conversions()
        elif choice == "11": menu_network()
        
        if not Confirm.ask("\nReturn to Main Menu?", default=True):
            sys.exit(0)

# --- Sub-Menus Implementation ---

def menu_ssh():
    console.print(Panel("[bold]SSH Tools[/bold]", style="blue"))
    kt = Prompt.ask("Key Type", choices=["rsa", "ed25519"], default="rsa")
    target_dir = file_utils.get_path("", subdir="ssh")
    os.makedirs(target_dir, exist_ok=True)

    try:
        priv, pub, content = ssh_tools.generate_ssh_key(kt, target_dir)
        console.print(f"[green]Keys Generated Successfully in:[/green] {target_dir}")
        # Offer to save the public key content as a separate text file (redundant but requested feature)
        output_and_save(content, title="Public Key Content", subdir="ssh")
    except Exception as e: console.print(f"[red]Error: {e}[/red]")

def menu_ssl():
    console.print(Panel("[bold]SSL/TLS Tools[/bold]", style="blue"))
    action = Prompt.ask("Action", choices=["generate_self_signed"], default="generate_self_signed")
    
    if action == "generate_self_signed":
        cn = Prompt.ask("Common Name (e.g., localhost)", default="localhost")
        fname = Prompt.ask("Output Filename", default="cert.pem")
        full_path = file_utils.get_path(fname, subdir="certs")
        
        try:
            ssl_tools.generate_self_signed_cert(cn, full_path)
            console.print(f"[green]Certificate saved:[/green] {full_path}")
            # SSL tools already save to disk, so we don't need a secondary "save to txt" for the cert itself,
            # but we can offer to save the *details* if we were inspecting it.
        except Exception as e: console.print(f"[red]Error: {e}[/red]")

def menu_hashing():
    console.print(Panel("[bold]Hashing[/bold]", style="blue"))
    mode = Prompt.ask("Source", choices=["string", "file"])
    algo = Prompt.ask("Algorithm", choices=["md5", "sha1", "sha256"], default="sha256")
    
    if mode == "string":
        txt = Prompt.ask("Input Text")
        res = hashing.hash_data(txt.encode(), algo)
        title_text = f"{algo.upper()} Hash (String)"
    else:
        path = Prompt.ask("File Path")
        res = hashing.hash_file(path, algo)
        title_text = f"{algo.upper()} Hash (File: {os.path.basename(path)})"
    
    # USE NEW SAVE FUNCTION
    output_and_save(res, title=title_text, subdir="hashing")

def menu_encoding():
    console.print(Panel("[bold]Encoding[/bold]", style="blue"))
    action = Prompt.ask("Action", choices=["b64_enc", "b64_dec", "hex_enc", "hex_dec"])
    data = Prompt.ask("Input Data")
    try:
        if action == "b64_enc": res = encoding.to_base64(data.encode())
        elif action == "b64_dec": res = encoding.from_base64(data).decode()
        elif action == "hex_enc": res = encoding.to_hex(data.encode())
        elif action == "hex_dec": res = encoding.from_hex(data).decode()
        
        # USE NEW SAVE FUNCTION
        output_and_save(res, title=f"Result ({action})", subdir="encoding")
    except Exception as e: console.print(f"[red]Error: {e}[/red]")

def menu_symmetric():
    console.print(Panel("[bold]Symmetric Encryption[/bold]", style="blue"))
    action = Prompt.ask("Action", choices=["fernet_gen", "fernet_enc", "fernet_dec"])
    
    if action == "fernet_gen":
        key = symmetric.generate_fernet_key().decode()
        output_and_save(key, title="New Fernet Key", subdir="keys")
        
    elif action == "fernet_enc":
        key = Prompt.ask("Key")
        msg = Prompt.ask("Message")
        try:
            ct = symmetric.fernet_encrypt(key.encode(), msg.encode()).decode()
            output_and_save(ct, title="Ciphertext", subdir="symmetric")
        except Exception as e: console.print(f"[red]{e}[/red]")
        
    elif action == "fernet_dec":
        key = Prompt.ask("Key")
        ct = Prompt.ask("Ciphertext")
        try:
            pt = symmetric.fernet_decrypt(key.encode(), ct.encode()).decode()
            output_and_save(pt, title="Plaintext", subdir="symmetric")
        except Exception as e: console.print(f"[red]Invalid Key or Data[/red]")

def menu_asymmetric():
    console.print(Panel("[bold]Asymmetric (RSA)[/bold]", style="blue"))
    action = Prompt.ask("Action", choices=["gen_keys", "encrypt_demo"])
    
    if action == "gen_keys":
        priv, pub = asymmetric.generate_rsa_pair()
        priv_pem = asymmetric.serialize_private_key(priv, password="pass").decode()
        pub_pem = asymmetric.serialize_public_key(pub).decode()
        
        console.print("[green]Keys Generated.[/green]")
        output_and_save(priv_pem, title="Private Key", subdir="keys")
        output_and_save(pub_pem, title="Public Key", subdir="keys")
        
    elif action == "encrypt_demo":
        # Simple demo to show saving capability
        console.print("[yellow]Generating ephemeral keys for demo...[/yellow]")
        priv, pub = asymmetric.generate_rsa_pair()
        pub_pem = asymmetric.serialize_public_key(pub)
        msg = Prompt.ask("Message to Encrypt")
        
        ct = asymmetric.rsa_encrypt(pub_pem, msg.encode())
        b64_ct = encoding.to_base64(ct) # Convert to string for display/saving
        
        output_and_save(b64_ct, title="RSA Encrypted (Base64)", subdir="asymmetric")

def menu_jwt():
    console.print(Panel("[bold]JWT Tools[/bold]", style="blue"))
    action = Prompt.ask("Action", choices=["create", "decode", "verify"])
    
    if action == "create":
        payload = Prompt.ask("Payload (JSON)", default='{"user_id": 123}')
        secret = Prompt.ask("Secret Key")
        token = jwt_tools.create_jwt(payload, secret)
        output_and_save(token, title="JWT Token", subdir="jwt")
        
    elif action == "decode":
        token = Prompt.ask("JWT Token")
        try:
            decoded = jwt_tools.decode_jwt_token(token, verify=False)
            # Convert dict to string for saving
            res_str = json.dumps(decoded, indent=4)
            output_and_save(res_str, title="Decoded Payload", subdir="jwt")
        except Exception as e: console.print(f"[red]{e}[/red]")
        
    elif action == "verify":
        token = Prompt.ask("JWT Token")
        secret = Prompt.ask("Secret Key")
        try:
            decoded = jwt_tools.decode_jwt_token(token, secret=secret, verify=True)
            res_str = json.dumps(decoded, indent=4)
            console.print("[green]Signature Valid[/green]")
            output_and_save(res_str, title="Verified Payload", subdir="jwt")
        except Exception as e: console.print(f"[red]Invalid: {e}[/red]")

def menu_password():
    console.print(Panel("[bold]Password Tools[/bold]", style="blue"))
    action = Prompt.ask("Action", choices=["generate", "check_strength", "vault"])
    
    if action == "generate":
        l = int(Prompt.ask("Length", default="16"))
        pwd = password_tools.generate_password(l)
        output_and_save(pwd, title="Generated Password", subdir="passwords")
        
    elif action == "check_strength":
        p = Prompt.ask("Password")
        res = password_tools.check_strength(p)
        output_and_save(f"Password: {p}\nStrength: {res['strength']}", title="Strength Report", subdir="passwords")
        
    elif action == "vault":
        console.print(f"[dim]Vault location: output/vault/my_secrets.vault[/dim]")
        sub = Prompt.ask("Vault Action", choices=["store", "retrieve"])
        mp = Prompt.ask("Master Password", password=True)
        k = Prompt.ask("Entry Key")
        
        if sub == "store":
            v = Prompt.ask("Value")
            r = secret_vault.add_secret(mp, k, v)
            console.print(f"[yellow]{r}[/yellow]")
        else:
            res = secret_vault.get_secret(mp, k)
            output_and_save(res, title="Decrypted Secret", subdir="vault")

def menu_random():
    console.print(Panel("[bold]Random Utilities[/bold]", style="blue"))
    action = Prompt.ask("Type", choices=["uuid", "hex_token", "url_token", "pin"])
    res = ""
    if action == "uuid": res = random_tools.generate_uuid()
    elif action == "hex_token": res = random_tools.generate_token_hex()
    elif action == "url_token": res = random_tools.generate_token_urlsafe()
    elif action == "pin": res = random_tools.generate_pin()
    
    output_and_save(res, title=f"Random {action.upper()}", subdir="random")

def menu_conversions():
    console.print(Panel("[bold]Format Conversions[/bold]", style="blue"))
    f_path = Prompt.ask("Input File Path")
    action = Prompt.ask("Convert to", choices=["pem_to_der", "der_to_pem"])
    
    try:
        data = file_utils.read_file_bytes(f_path)
        base_name = os.path.basename(f_path)
        
        if action == "pem_to_der":
            res = conversions.pem_to_der(data)
            new_name = base_name + ".der"
        else:
            res = conversions.der_to_pem(data, is_private=Confirm.ask("Is this a private key?"))
            new_name = base_name + ".pem"
        
        saved_path = file_utils.write_file_bytes(new_name, res, subdir="converted")
        console.print(f"[green]Converted file saved: {saved_path}[/green]")
        # No text save option here because these are usually binary files
    except Exception as e: console.print(f"[red]{e}[/red]")

def menu_network():
    console.print(Panel("[bold]Network Tools[/bold]", style="blue"))
    action = Prompt.ask("Action", choices=["scan_port", "cert_info"])
    host = Prompt.ask("Host")
    
    if action == "scan_port":
        port = int(Prompt.ask("Port", default="443"))
        res = network_tools.scan_port(host, port)
        status = f"Port {port} on {host} is {'OPEN' if res else 'CLOSED'}"
        output_and_save(status, title="Port Scan Result", subdir="network")
        
    else:
        try:
            cert_info = network_tools.get_ssl_cert_details(host)
            # Convert complicated dictionary to a nice string for text file
            # We filter it to make it JSON serializable or just use str()
            formatted_info = ""
            for k, v in cert_info.items():
                formatted_info += f"{k}: {v}\n"
                
            output_and_save(formatted_info, title="Certificate Details", subdir="network")
        except Exception as e: console.print(f"[red]{e}[/red]")

# ==========================================
#   CLI ARGUMENT PARSING (CLICK)
# ==========================================

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """CryptoUtility: The Professional Security Toolkit."""
    file_utils.ensure_output_dir()
    if ctx.invoked_subcommand is None:
        interactive_mode()

@cli.group()
def ssh(): """SSH Key Tools"""

@ssh.command()
@click.option('--type', default='rsa')
@click.option('--out', default=None)
def generate(type, out):
    path = out if out else file_utils.get_path("", subdir="ssh")
    os.makedirs(path, exist_ok=True)
    ssh_tools.generate_ssh_key(type, path)
    print(f"Keys generated in {path}")

@cli.group()
def ssl(): """SSL Certificate Tools"""

@ssl.command()
@click.argument('cn')
@click.option('--out', default='cert.pem')
def create(cn, out):
    full_path = file_utils.get_path(out, subdir="certs")
    ssl_tools.generate_self_signed_cert(cn, full_path)
    print(f"Certificate generated: {full_path}")

@cli.group()
def hash(): """Hashing Tools"""

@hash.command()
@click.argument('text')
def string(text): print(hashing.hash_data(text.encode()))

@hash.command()
@click.argument('file')
def file(file): print(hashing.hash_file(file))

@cli.group()
def encode(): """Encoding Tools"""

@encode.command()
@click.argument('text')
def b64(text): print(encoding.to_base64(text.encode()))

@encode.command()
@click.argument('text')
def hex(text): print(encoding.to_hex(text.encode()))

@cli.group()
def sym(): """Symmetric Encryption"""

@sym.command()
def genkey(): 
    key = symmetric.generate_fernet_key()
    print(key.decode())
    file_utils.write_file_bytes("fernet_cli.key", key, subdir="keys")

@sym.command()
@click.argument('key')
@click.argument('msg')
def encrypt(key, msg): print(symmetric.fernet_encrypt(key.encode(), msg.encode()).decode())

@cli.group()
def jwt(): """JWT Tools"""

@jwt.command()
@click.argument('payload')
@click.argument('secret')
def create(payload, secret): print(jwt_tools.create_jwt(payload, secret))

@jwt.command()
@click.argument('token')
def decode(token): print(jwt_tools.decode_jwt_token(token, verify=False))

@cli.group()
def rand(): """Random Utilities"""

@rand.command()
def uuid(): print(random_tools.generate_uuid())

@rand.command()
def token(): print(random_tools.generate_token_hex())

@cli.group()
def convert(): """Format Conversions"""

@convert.command()
@click.argument('file')
def pem2der(file):
    data = file_utils.read_file_bytes(file)
    res = conversions.pem_to_der(data)
    new_name = os.path.basename(file) + ".der"
    saved_path = file_utils.write_file_bytes(new_name, res, subdir="converted")
    print(f"Converted to DER: {saved_path}")

@cli.group()
def net(): """Network Tools"""

@net.command()
@click.argument('host')
def cert(host): print(network_tools.get_ssl_cert_details(host))

if __name__ == '__main__':
    cli()