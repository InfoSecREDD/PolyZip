#!/usr/bin/env python3
"""
PolyZip - A tool for creating polyglot files (FILE + ZIP)
Based on the work of DavidBuchanan314 (https://github.com/DavidBuchanan314/tweetable-polyglot-png)
Author: InfoSecREDD
Version: 2.1.2
"""

import zlib
import sys
import os
import glob
import json
import struct
import mimetypes
import subprocess
import importlib.util
import platform
import tempfile
import zipfile
import datetime
import base64
import secrets

ARGON2_AVAILABLE = False

def check_and_install_dependencies():
    """Always ensure we're running in our own virtual environment with all dependencies"""
    venv_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.poly_venv')

    if platform.system() == 'Windows':
        our_venv_python = os.path.join(venv_dir, 'Scripts', 'python.exe')
    else:
        our_venv_python = os.path.join(venv_dir, 'bin', 'python')

    current_python = os.path.abspath(sys.executable)
    our_python = os.path.abspath(our_venv_python)

    in_our_venv = (
        current_python == our_python or  # Exact path match
        os.path.basename(current_python) == os.path.basename(our_python) and current_python.startswith(os.path.abspath(venv_dir)) or  # Same filename in our venv dir
        (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix and os.path.abspath(sys.prefix) == os.path.abspath(venv_dir))  # sys.prefix points to our venv
    )
    
    if not in_our_venv:
        venv_exists = os.path.exists(venv_dir)
        
        if not venv_exists:
            print(f"[\033[36m*\033[0m] Setting up dedicated virtual environment...")
            print(f"[\033[36m+\033[0m] Creating virtual environment in {venv_dir}")
            try:
                subprocess.check_call([sys.executable, '-m', 'venv', venv_dir])
            except Exception as e:
                print(f"[\033[31m!\033[0m] Failed to create virtual environment: {e}")
                sys.exit(1)
            print(f"[\033[36m*\033[0m] Restarting script in virtual environment...")

        if platform.system() == 'Windows':
            venv_python = os.path.join(venv_dir, 'Scripts', 'python.exe')
        else:
            venv_python = os.path.join(venv_dir, 'bin', 'python')

        if not os.path.exists(venv_python):
            print(f"[\033[31m!\033[0m] Virtual environment Python not found at {venv_python}")
            sys.exit(1)

        os.execl(venv_python, venv_python, *sys.argv)

    required_packages = [
        {'package': 'python-magic', 'import_name': 'magic', 'optional': True},
        {'package': 'cryptography', 'import_name': 'cryptography', 'optional': False}
    ]
    
    missing_packages = []
    for package_info in required_packages:
        if importlib.util.find_spec(package_info['import_name']) is None:
            missing_packages.append(package_info['package'])
    
    if missing_packages:
        print(f"[\033[36m*\033[0m] Installing missing packages: {', '.join(missing_packages)}")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + missing_packages)
            print(f"[\033[32m✓\033[0m] Dependencies installed successfully!")
        except Exception as e:
            print(f"[\033[33m!\033[0m] pip failed: {e}, trying pip3...")
            try:
                subprocess.check_call([sys.executable, '-m', 'pip3', 'install'] + missing_packages)
                print(f"[\033[32m✓\033[0m] Dependencies installed successfully using pip3!")
            except Exception as e2:
                print(f"[\033[31m!\033[0m] Failed to install dependencies with both pip and pip3: {e2}")
                print(f"[\033[31m!\033[0m] Please install manually in the virtual environment:")
                print(f"    source {venv_dir}/bin/activate  # or {venv_dir}\\Scripts\\activate on Windows")
                print(f"    pip install {' '.join(missing_packages)}")
                sys.exit(1)
    else:
        print(f"[\033[32m✓\033[0m] Using virtual environment")

def import_cryptography():
    """Import cryptography modules after dependency checking"""
    global ARGON2_AVAILABLE, Cipher, algorithms, modes, Scrypt, hashes, default_backend, Argon2id
    
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        
        try:
            from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
            ARGON2_AVAILABLE = True
        except ImportError:
            ARGON2_AVAILABLE = False
            
    except ImportError as e:
        print(f"\033[31m[!] Error importing cryptography: {e}\033[0m")
        print(f"\033[31m[!] Please install cryptography: pip install cryptography\033[0m")
        sys.exit(1)

if __name__ == "__main__":
    check_and_install_dependencies()
    import_cryptography()

BANNER = r'''
██████╗  ██████╗ ██╗  ██╗   ██╗███████╗██╗██████╗ 
██╔══██╗██╔═══██╗██║  ╚██╗ ██╔╝╚══███╔╝██║██╔══██╗
██████╔╝██║   ██║██║   ╚████╔╝   ███╔╝ ██║██████╔╝
██╔═══╝ ██║   ██║██║    ╚██╔╝   ███╔╝  ██║██╔═══╝ 
██║     ╚██████╔╝███████╗██║   ███████╗██║██║     
╚═╝      ╚═════╝ ╚══════╝╚═╝   ╚══════╝╚═╝╚═╝     
                                                   
  [ Multi-Format Polyglot Tool - Hide Any Data ]
   ╔══════════════════════════════════════════╗
   ║  pack ≫ extract ≫ detect ≫ ghost in file ║
   ╚══════════════════════════════════════════╝
'''

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC = b"\xff\xd8\xff"
GIF_MAGIC = b"GIF8"
PDF_MAGIC = b"%PDF-"
BMP_MAGIC = b"BM"
WEBP_MAGIC = b"RIFF"
TIFF_MAGIC_LE = b"II*\x00"
TIFF_MAGIC_BE = b"MM\x00*"
WAV_MAGIC = b"RIFF"
MP3_MAGIC = b"\xFF\xFB"
MP3_MAGIC2 = b"\xFF\xF3"
MP3_MAGIC3 = b"\xFF\xFA"
MP3_MAGIC4 = b"\xFF\xF2"
FLAC_MAGIC = b"fLaC"
OGG_MAGIC = b"OggS"
AVI_MAGIC = b"RIFF"
MKV_MAGIC = b"\x1a\x45\xdf\xa3"
M4A_MAGIC = b"ftyp"
WEBM_MAGIC = b"\x1a\x45\xdf\xa3"
FLV_MAGIC = b"FLV"
ICO_MAGIC = b"\x00\x00\x01\x00"
CUR_MAGIC = b"\x00\x00\x02\x00"
ICNS_MAGIC = b"icns"
MP4_MAGIC = b"ftyp"
MZ_MAGIC = b"MZ"
ELF_MAGIC = b"\x7fELF"
MSI_MAGIC = b"\xd0\xcf\x11\xe0"
TTF_MAGIC = b"\x00\x01\x00\x00"
OTF_MAGIC = b"OTTO"
WOFF_MAGIC = b"wOFF"



def print_banner():
    colors = {
        'cyan': '\033[36m',
        'green': '\033[32m',
        'blue': '\033[34m',
        'red': '\033[31m',
        'magenta': '\033[35m',
        'yellow': '\033[33m',
        'white': '\033[37m',
        'reset': '\033[0m'
    }
    
    colored_banner = colors['cyan'] + BANNER + colors['reset']
    print(colored_banner)
    
    version_info = f"{colors['green']}[+]{colors['reset']} {colors['white']}Version 2.1.2{colors['reset']} | " + \
                   f"{colors['green']}[+]{colors['reset']} {colors['white']}Data Hidden in Plain Sight{colors['reset']}"
    print(version_info)
    print(f"{colors['green']}[+]{colors['reset']} {colors['white']}Use {colors['cyan']}detect{colors['reset']} to scan for hidden data")
    print()

def print_usage():
    colors = {
        'cyan': '\033[36m',
        'green': '\033[32m',
        'blue': '\033[34m',
        'red': '\033[31m',
        'magenta': '\033[35m',
        'yellow': '\033[33m',
        'white': '\033[37m',
        'bold': '\033[1m',
        'reset': '\033[0m'
    }
    
    print(f"\n{colors['bold']}{colors['cyan']}USAGE:{colors['reset']}")
    print(f"  {colors['white']}{sys.argv[0]}{colors['reset']} {colors['yellow']}[command]{colors['reset']} {colors['green']}[options...]{colors['reset']}")
    
    print(f"\n{colors['bold']}{colors['magenta']}COMMANDS:{colors['reset']}")
    
    # PACK command
    print(f"\n  {colors['bold']}{colors['cyan']}pack{colors['reset']} - {colors['white']}Hide files inside images/documents{colors['reset']}")
    print(f"    {colors['yellow']}Usage:{colors['reset']} {sys.argv[0]} pack {colors['green']}cover_file{colors['reset']} {colors['blue']}file1 [file2 ...]{colors['reset']} {colors['magenta']}output_file{colors['reset']} {colors['red']}[encryption]{colors['reset']}")
    print(f"    {colors['yellow']}Example:{colors['reset']} {sys.argv[0]} pack photo.png secret.txt hidden_photo.png")
    print(f"    {colors['yellow']}Encrypted:{colors['reset']} {sys.argv[0]} pack photo.png secret.txt hidden_photo.png --key=my.key")
    print(f"    {colors['yellow']}Supports:{colors['reset']} PNG, JPEG, GIF, PDF, BMP, WebP, TIFF, WAV, MP3, FLAC, OGG,")
    print(f"              AVI, MKV, WebM, FLV, ICO, CUR, ICNS, MP4, MOV, M4A, EXE, DLL, ELF, MSI, TTF, OTF, WOFF")
    
    # EXTRACT command  
    print(f"\n  {colors['bold']}{colors['cyan']}extract{colors['reset']} - {colors['white']}Extract hidden files from images/documents{colors['reset']}")
    print(f"    {colors['yellow']}Usage:{colors['reset']} {sys.argv[0]} extract {colors['green']}input_file{colors['reset']} {colors['blue']}[output_directory]{colors['reset']} {colors['red']}[encryption]{colors['reset']}")
    print(f"    {colors['yellow']}Example:{colors['reset']} {sys.argv[0]} extract hidden_photo.png extracted_files/")
    print(f"    {colors['yellow']}Encrypted:{colors['reset']} {sys.argv[0]} extract hidden_photo.png extracted_files/ --key=my.key")
    print(f"    {colors['yellow']}Note:{colors['reset']} If output directory is omitted, extracts to folder named after input file")
    
    # DETECT command
    print(f"\n  {colors['bold']}{colors['cyan']}detect{colors['reset']} - {colors['white']}Scan for hidden data in files{colors['reset']}")
    print(f"    {colors['yellow']}Usage:{colors['reset']} {sys.argv[0]} detect {colors['green']}[file]{colors['reset']}")
    print(f"    {colors['yellow']}Example:{colors['reset']} {sys.argv[0]} detect suspicious_image.png")
    print(f"    {colors['yellow']}Note:{colors['reset']} If no file specified, scans all supported files in current directory")
    
    # CHAT command
    print(f"\n  {colors['bold']}{colors['cyan']}chat{colors['reset']} - {colors['white']}Create encrypted hidden chat logs in images{colors['reset']}")
    print(f"    {colors['bold']}{colors['green']}Subcommands:{colors['reset']}")
    
    # Chat create
    print(f"\n    {colors['bold']}{colors['yellow']}create{colors['reset']} - Create new encrypted chat")
    print(f"      {colors['yellow']}Usage:{colors['reset']} {sys.argv[0]} chat create {colors['green']}cover.[any]{colors['reset']} {colors['magenta']}output.[any]{colors['reset']} {colors['blue']}[\"title\"]{colors['reset']} {colors['red']}[encryption]{colors['reset']}")
    print(f"      {colors['yellow']}Examples:{colors['reset']}")
    print(f"        {sys.argv[0]} chat create photo.jpg secret_chat.jpg \"Team Chat\" --key=team.key")
    print(f"        {sys.argv[0]} chat create document.pdf secret_chat.pdf \"Private\" --password=mypass123")
    print(f"        {sys.argv[0]} chat create image.gif secret_chat.gif  # Unencrypted")
    print(f"        {sys.argv[0]} chat create cover.png output.png \"Any file type works!\"")
    print(f"      {colors['cyan']}Supported formats:{colors['reset']} PNG, JPG, GIF, PDF, BMP, WEBP, TIFF, WAV, MP3, FLAC, OGG, AVI, MKV, WebM, FLV, ICO, MP4, MOV, EXE, and more")
    
    # Chat add
    print(f"\n    {colors['bold']}{colors['yellow']}add{colors['reset']} - Add message to existing chat")
    print(f"      {colors['yellow']}Usage:{colors['reset']} {sys.argv[0]} chat add {colors['green']}chat.[any]{colors['reset']} {colors['blue']}sender{colors['reset']} {colors['cyan']}\"message\"{colors['reset']} {colors['magenta']}[output.[any]]{colors['reset']} {colors['red']}[encryption]{colors['reset']}")
    print(f"      {colors['yellow']}Examples:{colors['reset']}")
    print(f"        {sys.argv[0]} chat add secret_chat.jpg Alice \"Hello team!\" --key=team.key")
    print(f"        {sys.argv[0]} chat add secret_chat.pdf Bob \"Secret message\" --password=mypass123")
    print(f"        {sys.argv[0]} chat add hidden_chat.gif Charlie \"Works with any file type!\"")
    
    # Chat read
    print(f"\n    {colors['bold']}{colors['yellow']}read{colors['reset']} - Display chat messages")
    print(f"      {colors['yellow']}Usage:{colors['reset']} {sys.argv[0]} chat read {colors['green']}chat.[any]{colors['reset']} {colors['blue']}[--format=terminal|json|html]{colors['reset']} {colors['red']}[encryption]{colors['reset']}")
    print(f"      {colors['yellow']}Examples:{colors['reset']}")
    print(f"        {sys.argv[0]} chat read secret_chat.jpg --key=team.key")
    print(f"        {sys.argv[0]} chat read secret_chat.pdf --format=json --password=mypass123")
    print(f"        {sys.argv[0]} chat read hidden_chat.mp4 --format=html")
    
    # Chat export
    print(f"\n    {colors['bold']}{colors['yellow']}export{colors['reset']} - Export chat to file")
    print(f"      {colors['yellow']}Usage:{colors['reset']} {sys.argv[0]} chat export {colors['green']}chat.[any]{colors['reset']} {colors['magenta']}output.[txt|json|html]{colors['reset']} {colors['red']}[encryption]{colors['reset']}")
    print(f"      {colors['yellow']}Examples:{colors['reset']}")
    print(f"        {sys.argv[0]} chat export secret_chat.jpg backup.html --key=team.key")
    print(f"        {sys.argv[0]} chat export secret_chat.pdf backup.json --password=mypass123")
    print(f"        {sys.argv[0]} chat export hidden_chat.mkv backup.txt")
    print(f"\n  {colors['bold']}{colors['red']}ENCRYPTION OPTIONS:{colors['reset']}")
    print(f"    {colors['cyan']}--key=filename.key{colors['reset']}     Use AES-256 encryption with key file (auto-generated if missing)")
    print(f"    {colors['cyan']}--password=yourpass{colors['reset']}    Use AES-256 encryption with password (Argon2id + salt)")
    print(f"    {colors['yellow']}Note:{colors['reset']} Encrypted chats are completely secure and undetectable")
    print(f"\n{colors['bold']}{colors['green']}QUICK EXAMPLES:{colors['reset']}")
    print(f"  {colors['white']}Hide files:{colors['reset']}          {sys.argv[0]} pack photo.jpg document.pdf hidden.jpg")
    print(f"  {colors['white']}Hide files encrypted:{colors['reset']}  {sys.argv[0]} pack photo.jpg secret.txt hidden.jpg --key=my.key")
    print(f"  {colors['white']}Extract files:{colors['reset']}       {sys.argv[0]} extract hidden.jpg")
    print(f"  {colors['white']}Extract encrypted:{colors['reset']}    {sys.argv[0]} extract hidden.jpg output/ --key=my.key")
    print(f"  {colors['white']}Scan for hidden data:{colors['reset']} {sys.argv[0]} detect")
    print(f"  {colors['white']}Create encrypted chat:{colors['reset']} {sys.argv[0]} chat create cover.jpg chat.jpg --key=my.key")
    print(f"  {colors['white']}Add encrypted message:{colors['reset']} {sys.argv[0]} chat add chat.pdf Alice \"Hello!\" --key=my.key")
    print(f"  {colors['white']}Read encrypted chat:{colors['reset']}   {sys.argv[0]} chat read chat.gif --key=my.key")
    print(f"  {colors['cyan']}💡 Both files AND chat work with ANY file format - images, videos, documents, executables, etc!{colors['reset']}")
    print(f"\n{colors['bold']}{colors['yellow']}SECURITY FEATURES:{colors['reset']}")
    print(f"  • {colors['green']}AES-256-GCM encryption{colors['reset']} with authenticated encryption for files & chat")
    print(f"  • {colors['green']}Perfect steganography{colors['reset']} - files appear completely normal")
    print(f"  • {colors['green']}Key file generation{colors['reset']} - automatic secure key creation")
    print(f"  • {colors['green']}Password protection{colors['reset']} - Argon2id or Scrypt with secure parameters")
    print(f"  • {colors['green']}Tamper detection{colors['reset']} - GCM authentication prevents modification")
    
    print(f"\n{colors['bold']}{colors['cyan']}💡 TIP:{colors['reset']} {colors['white']}Files with hidden data can be opened normally in any image viewer/PDF reader!{colors['reset']}")
    print()
    sys.exit(1)

if len(sys.argv) < 2:
    print_banner()
    print_usage()

def create_chat_data(title="Chat Log"):
    """Create initial chat data structure"""
    return {
        "version": "1.0",
        "title": title,
        "created": datetime.datetime.now().isoformat(),
        "participants": [],
        "messages": []
    }

def add_message_to_chat(chat_data, sender, message):
    """Add a message to the chat data"""
    timestamp = datetime.datetime.now().isoformat()

    if sender not in chat_data["participants"]:
        chat_data["participants"].append(sender)

    chat_data["messages"].append({
        "timestamp": timestamp,
        "sender": sender,
        "message": message
    })
    
    return chat_data

def generate_key():
    """Generate a new AES-256 key"""
    return secrets.token_bytes(32)

def save_key_to_file(key, filename):
    """Save AES key to file in base64 format"""
    with open(filename, 'wb') as f:
        f.write(base64.b64encode(key))
    print(f"[\033[32m+\033[0m] New encryption key saved to: {filename}")

def load_key_from_file(filename):
    """Load AES key from file"""
    try:
        with open(filename, 'rb') as f:
            return base64.b64decode(f.read())
    except Exception as e:
        raise ValueError(f"Could not load key from {filename}: {e}")

def derive_key_from_password(password, salt):
    """Derive AES key from password using Argon2id or Scrypt fallback"""
    if 'Cipher' not in globals():
        import_cryptography()
        
    if ARGON2_AVAILABLE:
        kdf = Argon2id(
            salt=salt,
            length=32,
            lanes=4,
            memory_cost=65536,
            iterations=3
        )
    else:
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**15,  # 32768
            r=8,
            p=1,
            backend=default_backend()
        )
    return kdf.derive(password.encode())

def encrypt_data(data, key):
    """Encrypt text data using AES-256-GCM"""
    if 'Cipher' not in globals():
        import_cryptography()
        
    iv = secrets.token_bytes(12)

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    encrypted_payload = iv + encryptor.tag + ciphertext
    return base64.b64encode(encrypted_payload).decode()

def decrypt_data(encrypted_data, key):
    """Decrypt text data using AES-256-GCM"""
    if 'Cipher' not in globals():
        import_cryptography()
        
    try:
        encrypted_payload = base64.b64decode(encrypted_data.encode())
        iv = encrypted_payload[:12]
        auth_tag = encrypted_payload[12:28]
        ciphertext = encrypted_payload[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()
        
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

def encrypt_file_data(data, key):
    """Encrypt binary file data using AES-256-GCM"""
    if 'Cipher' not in globals():
        import_cryptography()
        
    iv = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    encrypted_payload = iv + encryptor.tag + ciphertext
    return encrypted_payload

def decrypt_file_data(encrypted_data, key):
    """Decrypt binary file data using AES-256-GCM"""
    if 'Cipher' not in globals():
        import_cryptography()
        
    try:
        iv = encrypted_data[:12]
        auth_tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
        
    except Exception as e:
        raise ValueError(f"File decryption failed: {e}")

def parse_encryption_args(args):
    """Parse encryption arguments from command line"""
    key_file = None
    password = None
    
    for arg in args:
        if arg.startswith("--key="):
            key_file = arg.split("=", 1)[1]
        elif arg.startswith("--password="):
            password = arg.split("=", 1)[1]
    
    return key_file, password

def get_encryption_key(key_file, password, create_if_missing=False):
    """Get encryption key from file or password"""
    if key_file and password:
        raise ValueError("Cannot specify both --key and --password options")
    
    if key_file:
        if os.path.exists(key_file):
            return load_key_from_file(key_file), None 
        elif create_if_missing:
            key = generate_key()
            save_key_to_file(key, key_file)
            return key, None
        else:
            raise ValueError(f"Key file '{key_file}' not found")
    
    elif password:
        salt = secrets.token_bytes(16)
        key = derive_key_from_password(password, salt)
        return key, salt
    
    else:
        return None, None

def format_chat_terminal(chat_data):
    """Format chat data for terminal display"""
    output = []
    output.append(f"\n[\033[36m*\033[0m] \033[1m{chat_data['title']}\033[0m")
    output.append(f"[\033[36m+\033[0m] Created: {chat_data['created']}")
    output.append(f"[\033[36m+\033[0m] Participants: {', '.join(chat_data['participants'])}")
    output.append(f"[\033[36m+\033[0m] Messages: {len(chat_data['messages'])}")
    output.append("\n" + "=" * 60)
    
    for msg in chat_data["messages"]:
        timestamp = datetime.datetime.fromisoformat(msg["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        output.append(f"\n[\033[32m{timestamp}\033[0m] \033[1m{msg['sender']}\033[0m:")
        output.append(f"  {msg['message']}")
    
    output.append("\n" + "=" * 60)
    return "\n".join(output)

def format_chat_html(chat_data):
    """Format chat data as HTML"""
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{chat_data['title']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 10px; border-radius: 5px; }}
        .message {{ margin: 10px 0; padding: 10px; border-left: 3px solid #007acc; }}
        .sender {{ font-weight: bold; color: #007acc; }}
        .timestamp {{ color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{chat_data['title']}</h1>
        <p>Created: {chat_data['created']}</p>
        <p>Participants: {', '.join(chat_data['participants'])}</p>
        <p>Messages: {len(chat_data['messages'])}</p>
    </div>
"""
    
    for msg in chat_data["messages"]:
        timestamp = datetime.datetime.fromisoformat(msg["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        html += f"""
    <div class="message">
        <div class="timestamp">{timestamp}</div>
        <div class="sender">{msg['sender']}:</div>
        <div>{msg['message']}</div>
    </div>"""
    
    html += """
</body>
</html>"""
    return html

def extract_chat_from_image(image_path, encryption_key=None, password=None):
    """Extract chat data from image file with optional decryption"""
    input_type = detect_cover_file_type(image_path)
    if not input_type:
        raise ValueError(f"Unsupported image format: {image_path}")
    
    with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_zip_file:
        temp_zip_path = temp_zip_file.name
    
    try:
        with open(image_path, "rb") as f_in:
            if input_type == "png":
                png_header = f_in.read(len(PNG_MAGIC))
                if png_header != PNG_MAGIC:
                    raise ValueError(f"Not a valid PNG file: {image_path}")
                
                zip_data_start = None
                while True:
                    chunk_len_bytes = f_in.read(4)
                    if not chunk_len_bytes or len(chunk_len_bytes) < 4:
                        break
                        
                    chunk_len = int.from_bytes(chunk_len_bytes, "big")
                    chunk_type = f_in.read(4)
                    
                    if not chunk_type or len(chunk_type) < 4:
                        break
                    
                    if chunk_type == b"IDAT":
                        f_in.seek(chunk_len + 4, 1)
                        zip_data_start = f_in.tell()
                        break
                    else:
                        f_in.seek(chunk_len + 4, 1)
                
                if zip_data_start is None:
                    raise ValueError(f"Could not find chat data in {image_path}")
                
                f_in.seek(zip_data_start)
                zip_data = f_in.read()
                
            elif input_type == "jpeg":
                jpeg_data = f_in.read()
                eoi_pos = jpeg_data.rfind(b'\xFF\xD9')
                if eoi_pos == -1:
                    raise ValueError(f"Invalid JPEG file: {image_path}")
                zip_data = jpeg_data[eoi_pos+2:]
                
            elif input_type == "gif":
                gif_data = f_in.read()
                trailer_pos = gif_data.rfind(b'\x3B')
                if trailer_pos == -1:
                    raise ValueError(f"Invalid GIF file: {image_path}")
                zip_data = gif_data[trailer_pos+1:]
                
            elif input_type == "pdf":
                pdf_data = f_in.read()
                eof_pos = pdf_data.rfind(b'%%EOF')
                if eof_pos == -1:
                    raise ValueError(f"Invalid PDF file: {image_path}")
                eol_pos = pdf_data.find(b'\n', eof_pos)
                if eol_pos == -1:
                    eol_pos = pdf_data.find(b'\r', eof_pos)
                    if eol_pos == -1:
                        eol_pos = len(pdf_data)
                    else:
                        eol_pos += 1
                else:
                    eol_pos += 1
                zip_data = pdf_data[eol_pos:]
                
            else:
                data = f_in.read()
                zip_signatures = [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08']
                for sig in zip_signatures:
                    sig_pos = data.find(sig)
                    if sig_pos > 0:
                        zip_data = data[sig_pos:]
                        break
                else:
                    raise ValueError(f"Could not find chat data in {image_path}")
        
        with open(temp_zip_path, "wb") as f_out:
            f_out.write(zip_data)
        with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
            file_list = zipf.namelist()
            if 'metadata.json' in file_list and 'chat.enc' in file_list:
                metadata_json = zipf.read('metadata.json').decode('utf-8')
                metadata = json.loads(metadata_json)
                
                if not metadata.get('encrypted', False):
                    raise ValueError(f"Invalid encrypted chat format in {image_path}")
                
                if not encryption_key and not password:
                    raise ValueError(f"Chat is encrypted but no decryption key/password provided")
                if password:
                    if 'salt' not in metadata:
                        raise ValueError(f"Password-encrypted chat but no salt found in metadata")
                    salt = base64.b64decode(metadata['salt'].encode())
                    actual_key = derive_key_from_password(password, salt)
                else:
                    actual_key = encryption_key
                encrypted_json = zipf.read('chat.enc').decode('utf-8')
                chat_json = decrypt_data(encrypted_json, actual_key)
                return json.loads(chat_json)
                
            elif 'chat.json' in file_list:
                if encryption_key or password:
                    print("[\033[33m!\033[0m] Warning: Decryption key/password provided but chat is not encrypted")
                
                chat_json = zipf.read('chat.json').decode('utf-8')
                return json.loads(chat_json)
                
            else:
                raise ValueError(f"No chat data found in {image_path}")
    
    finally:
        try:
            os.unlink(temp_zip_path)
        except:
            pass

def extract_cover_from_chat_image(chat_image_path):
    """Extract original cover image from a chat image (before the embedded data)"""
    input_type = detect_cover_file_type(chat_image_path)
    if not input_type:
        raise ValueError(f"Unsupported image format: {chat_image_path}")
    
    with open(chat_image_path, "rb") as f_in:
        if input_type == "png":
            png_header = f_in.read(len(PNG_MAGIC))
            if png_header != PNG_MAGIC:
                raise ValueError(f"Not a valid PNG file: {chat_image_path}")
            cover_data = bytearray(png_header)
            
            while True:
                chunk_len_bytes = f_in.read(4)
                if not chunk_len_bytes or len(chunk_len_bytes) < 4:
                    break
                    
                chunk_len = int.from_bytes(chunk_len_bytes, "big")
                chunk_type = f_in.read(4)
                
                if not chunk_type or len(chunk_type) < 4:
                    break
                
                chunk_body = f_in.read(chunk_len)
                if len(chunk_body) < chunk_len:
                    break
                    
                chunk_csum_bytes = f_in.read(4)
                if not chunk_csum_bytes or len(chunk_csum_bytes) < 4:
                    break
                
                cover_data.extend(chunk_len_bytes)
                cover_data.extend(chunk_type)
                cover_data.extend(chunk_body)
                cover_data.extend(chunk_csum_bytes)
                if chunk_type == b"IDAT":
                    break
            
            return bytes(cover_data)
            
        elif input_type == "jpeg":
            jpeg_data = f_in.read()
            eoi_pos = jpeg_data.rfind(b'\xFF\xD9')
            if eoi_pos == -1:
                raise ValueError(f"Invalid JPEG file: {chat_image_path}")
            return jpeg_data[:eoi_pos+2]
            
        elif input_type == "gif":
            gif_data = f_in.read()
            trailer_pos = gif_data.rfind(b'\x3B')
            if trailer_pos == -1:
                raise ValueError(f"Invalid GIF file: {chat_image_path}")
            return gif_data[:trailer_pos+1]
            
        elif input_type == "pdf":
            pdf_data = f_in.read()
            eof_pos = pdf_data.rfind(b'%%EOF')
            if eof_pos == -1:
                raise ValueError(f"Invalid PDF file: {chat_image_path}")
            eol_pos = pdf_data.find(b'\n', eof_pos)
            if eol_pos == -1:
                eol_pos = pdf_data.find(b'\r', eof_pos)
                if eol_pos == -1:
                    eol_pos = len(pdf_data)
                else:
                    eol_pos += 1
            else:
                eol_pos += 1
            return pdf_data[:eol_pos]
            
        else:
            data = f_in.read()
            zip_signatures = [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08']
            for sig in zip_signatures:
                sig_pos = data.find(sig)
                if sig_pos > 0:
                    return data[:sig_pos]
            raise ValueError(f"Could not find original cover in {chat_image_path}")

def save_chat_to_image(cover_image, chat_data, output_image, encryption_key=None, salt=None):
    """Save chat data embedded in an image with optional encryption"""
    with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_zip_file:
        temp_zip_path = temp_zip_file.name
    
    try:
        with zipfile.ZipFile(temp_zip_path, 'w') as zipf:
            chat_json = json.dumps(chat_data, indent=2)
            
            if encryption_key:
                encrypted_json = encrypt_data(chat_json, encryption_key)
                metadata = {
                    "encrypted": True,
                    "version": "1.0"
                }
                if salt:
                    metadata["salt"] = base64.b64encode(salt).decode()
                zipf.writestr('chat.enc', encrypted_json)
                zipf.writestr('metadata.json', json.dumps(metadata))
            else:
                zipf.writestr('chat.json', chat_json)
        cover_type = detect_cover_file_type(cover_image)
        if not cover_type:
            raise ValueError(f"Unsupported cover image format: {cover_image}")
        
        try:
            cover_in = open(cover_image, "rb")
            content_in = open(temp_zip_path, "rb")
            output_out = open(output_image, "wb")
        except Exception as e:
            raise ValueError(f"Error opening files: {e}")

        try:
            if cover_type == "png":
                png_header = cover_in.read(len(PNG_MAGIC))
                if png_header != PNG_MAGIC:
                    raise ValueError(f"Not a valid PNG file: {cover_image}")
                
                output_out.write(png_header)
                
                content_embedded = False
                
                while True:
                    chunk_len_bytes = cover_in.read(4)
                    if not chunk_len_bytes or len(chunk_len_bytes) < 4:
                        break
                        
                    chunk_len = int.from_bytes(chunk_len_bytes, "big")
                    chunk_type = cover_in.read(4)
                    
                    if not chunk_type or len(chunk_type) < 4:
                        break
                        
                    chunk_body = cover_in.read(chunk_len)
                    if len(chunk_body) < chunk_len:
                        break
                        
                    chunk_csum_bytes = cover_in.read(4)
                    if not chunk_csum_bytes or len(chunk_csum_bytes) < 4:
                        break
                    
                    chunk_csum = int.from_bytes(chunk_csum_bytes, "big")
                    
                    if chunk_type == b"IDAT" and not content_embedded:
                        output_out.write(chunk_len.to_bytes(4, "big"))
                        output_out.write(chunk_type)
                        output_out.write(chunk_body)
                        output_out.write(chunk_csum.to_bytes(4, "big"))
                        
                        current_pos = output_out.tell()
                        start_offset = current_pos
                        
                        content_dat = bytearray(content_in.read())
                        fixup_zip(content_dat, start_offset)
                        
                        output_out.write(content_dat)
                        content_embedded = True
                        continue
                        
                    elif chunk_type == b"IDAT" and content_embedded:
                        print(f"[\033[36m+\033[0m] Skipping redundant IDAT chunk after ZIP embedding")
                        continue
                    
                    output_out.write(chunk_len.to_bytes(4, "big"))
                    output_out.write(chunk_type)
                    output_out.write(chunk_body)
                    output_out.write(chunk_csum.to_bytes(4, "big"))
                    
                    if chunk_type == b"IEND":
                        break

            elif cover_type == "jpeg":
                jpeg_data = cover_in.read()
                eoi_pos = jpeg_data.rfind(b'\xFF\xD9')
                if eoi_pos == -1:
                    raise ValueError(f"Invalid JPEG file: {cover_image}")
                
                output_out.write(jpeg_data[:eoi_pos+2])
                start_offset = eoi_pos + 2
                content_dat = bytearray(content_in.read())
                fixup_zip(content_dat, start_offset)
                output_out.write(content_dat)
                
            elif cover_type == "gif":
                gif_data = cover_in.read()
                trailer_pos = gif_data.rfind(b'\x3B')
                if trailer_pos == -1:
                    raise ValueError(f"Invalid GIF file: {cover_image}")
                
                output_out.write(gif_data[:trailer_pos+1])
                start_offset = trailer_pos + 1
                content_dat = bytearray(content_in.read())
                fixup_zip(content_dat, start_offset)
                output_out.write(content_dat)
                
            elif cover_type == "pdf":
                pdf_data = cover_in.read()
                eof_pos = pdf_data.rfind(b'%%EOF')
                if eof_pos == -1:
                    raise ValueError(f"Invalid PDF file: {cover_image}")
                
                eol_pos = pdf_data.find(b'\n', eof_pos)
                if eol_pos == -1:
                    eol_pos = pdf_data.find(b'\r', eof_pos)
                    if eol_pos == -1:
                        eol_pos = len(pdf_data)
                    else:
                        eol_pos += 1
                else:
                    eol_pos += 1
                
                output_out.write(pdf_data[:eol_pos])
                start_offset = eol_pos
                content_dat = bytearray(content_in.read())
                fixup_zip(content_dat, start_offset)
                output_out.write(content_dat)
                
            else:
                format_data = cover_in.read()
                output_out.write(format_data)
                start_offset = len(format_data)
                content_dat = bytearray(content_in.read())
                fixup_zip(content_dat, start_offset)
                output_out.write(content_dat)
        
        finally:
            cover_in.close()
            content_in.close()
            output_out.close()
    
    finally:
        try:
            os.unlink(temp_zip_path)
        except:
            pass

if len(sys.argv) == 4 and sys.argv[1] not in ["pack", "extract", "detect", "chat"]:
    sys.argv = [sys.argv[0], "pack"] + sys.argv[1:]

command = sys.argv[1]

print_banner()

def fixup_zip(data, start_offset):
    try:
        end_central_dir_offset = data.rindex(b"PK\x05\x06")
        cdent_count = int.from_bytes(data[end_central_dir_offset+10:end_central_dir_offset+10+2], "little")
        cd_range = slice(end_central_dir_offset+16, end_central_dir_offset+16+4)
        central_dir_start_offset = int.from_bytes(data[cd_range], "little")
        data[cd_range] = (central_dir_start_offset + start_offset).to_bytes(4, "little")
        for _ in range(cdent_count):
            central_dir_start_offset = data.index(b"PK\x01\x02", central_dir_start_offset)
            off_range = slice(central_dir_start_offset+42, central_dir_start_offset+42+4)
            off = int.from_bytes(data[off_range], "little")
            data[off_range] = (off + start_offset).to_bytes(4, "little")
            central_dir_start_offset += 1
        return True
    except Exception as e:
        print(f"Error fixing ZIP file: {e}")
        return False

def detect_png_file(png_path):
    if not os.path.exists(png_path):
        print(f"Error: File '{png_path}' not found")
        return False
        
    try:
        with open(png_path, "rb") as png_in:
            png_header = png_in.read(len(PNG_MAGIC))
            if png_header != PNG_MAGIC:
                print(f"Not a valid PNG file: {png_path}")
                return False
            
            idat_chunks = 0
            total_data_size = 0
            suspicious_patterns = []
            
            while True:
                chunk_len_bytes = png_in.read(4)
                if not chunk_len_bytes or len(chunk_len_bytes) < 4:
                    break
                    
                chunk_len = int.from_bytes(chunk_len_bytes, "big")
                chunk_type = png_in.read(4)
                
                if not chunk_type or len(chunk_type) < 4:
                    break
                
                chunk_position = png_in.tell() - 8
                    
                if chunk_type == b"IDAT":
                    idat_chunks += 1
                    total_data_size += chunk_len
                    
                    if idat_chunks > 1:
                        peek_data = png_in.read(16)
                        
                        if b"PK\x03\x04" in peek_data:
                            suspicious_patterns.append(f"ZIP header at offset {chunk_position + 8}")
                        elif b"\x50\x4B\x05\x06" in peek_data:
                            suspicious_patterns.append(f"ZIP end header at offset {chunk_position + 8}")
                        elif b"\x89PNG" in peek_data:
                            suspicious_patterns.append(f"PNG signature at offset {chunk_position + 8}")
                        elif b"PDF-" in peek_data:
                            suspicious_patterns.append(f"PDF header at offset {chunk_position + 8}")
                        elif b"\xFF\xD8\xFF" in peek_data:
                            suspicious_patterns.append(f"JPEG header at offset {chunk_position + 8}")
                        elif b"POLY" in peek_data:
                            suspicious_patterns.append(f"POLY multi-file header at offset {chunk_position + 8}")
                        
                        png_in.seek(chunk_position + 8)
                
                png_in.seek(chunk_len, 1)
                png_in.seek(4, 1)
                
                if chunk_type == b"IEND":
                    break
            
            is_suspicious = idat_chunks > 1 or len(suspicious_patterns) > 0
            
            print(f"\n[\033[36m*\033[0m] PNG File: \033[1m{png_path}\033[0m")
            print(f"[\033[36m+\033[0m] Total IDAT chunks: {idat_chunks}")
            
            if idat_chunks > 1:
                print(f"[\033[33m!\033[0m] Multiple IDAT chunks detected ({idat_chunks}), which could indicate embedded data")
                
            if idat_chunks > 1:
                print(f"[\033[36m+\033[0m] Total size of all IDAT chunks: {total_data_size} bytes")
                
            if suspicious_patterns:
                print("[\033[31m!\033[0m] Potential embedded content detected:")
                for pattern in suspicious_patterns:
                    print(f"  [\033[31m>\033[0m] {pattern}")
                print("[\033[31m!\033[0m] This file likely contains embedded data")
            else:
                if idat_chunks > 1:
                    print("[\033[33m!\033[0m] Multiple IDAT chunks found, but no obvious embedded file signatures detected")
                    print("[\033[33m!\033[0m] The file might still contain embedded data in an uncommon format")
                else:
                    print("[\033[32m✓\033[0m] No evidence of embedded data found")
                    
            return is_suspicious
    
    except Exception as e:
        print(f"\033[31m[!] Error analyzing {png_path}: {e}\033[0m")
        return False

def detect_file_type(data):
    signatures = {
        b'\x89PNG\r\n\x1a\n': '.png',
        b'\xff\xd8\xff': '.jpg',
        b'GIF87a': '.gif',
        b'GIF89a': '.gif',
        b'%PDF': '.pdf',
        b'PK\x03\x04': '.zip',
        b'Rar!\x1a\x07': '.rar',
        b'\x1f\x8b\x08': '.gz',
        b'BM': '.bmp',
        b'\x49\x49\x2a\x00': '.tif',
        b'\x4d\x4d\x00\x2a': '.tif',
        b'RIFF': '.wav',
        b'OggS': '.ogg',
        b'\x50\x4b\x05\x06': '.zip',
        b'\x50\x4b\x07\x08': '.zip',
        b'\x75\x73\x74\x61\x72': '.tar',
        b'7z\xbc\xaf\x27\x1c': '.7z',
        b'\x00\x01\x00\x00\x00': '.ttf',
        b'OTTO': '.otf',

        b'\x4d\x5a': '.exe',
        b'<!DOCTYPE html': '.html',
        b'<html': '.html',
        b'<?xml': '.xml',
        b'{': '.json',
        b'SQLite format': '.db',
    }
    
    is_text = True
    for i in range(min(32, len(data))):
        if i < len(data) and data[i] < 9 or (data[i] > 13 and data[i] < 32):
            is_text = False
            break
    
    if is_text:
        if data.startswith(b'#!'):
            return '.sh'
        elif data.startswith(b'<?php'):
            return '.php'
        elif data.startswith(b'import ') or data.startswith(b'from ') or b'def ' in data[:100]:
            return '.py'

        elif b'<svg' in data[:100]:
            return '.svg'
        elif b'#include' in data[:100]:
            return '.c'
        else:
            return '.txt'
    
    for signature, ext in signatures.items():
        if data.startswith(signature):
            return ext
    
    try:
        temp_fd, temp_path = tempfile.mkstemp()
        try:
            with os.fdopen(temp_fd, 'wb') as f:
                f.write(data[:min(1024, len(data))])
            
            mime_type, _ = mimetypes.guess_type(temp_path)
            if mime_type:
                extension = mimetypes.guess_extension(mime_type)
                if extension:
                    return extension
        finally:
            try:
                os.unlink(temp_path)
            except:
                pass
    except:
        pass
    
    try:
        import magic
        mime = magic.Magic(mime=True)
        mime_type = mime.from_buffer(data)
        extension = mimetypes.guess_extension(mime_type)
        if extension:
            return extension
    except (ImportError, Exception):
        pass
        
    return '.bin'

def is_likely_text_file(data, sample_size=100):
    if not data or len(data) == 0:
        return False
    
    sample = data[:min(sample_size, len(data))]
    
    binary_chars = 0
    for byte in sample:
        if (byte < 9 or (byte > 13 and byte < 32) or byte > 126):
            binary_chars += 1
    
    if len(sample) > 0 and binary_chars / len(sample) > 0.05:
        return False
    
    return True

def detect_cover_file_type(file_path):
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
            
            if header.startswith(PNG_MAGIC):
                return "png"
            elif header.startswith(JPEG_MAGIC):
                return "jpeg"
            elif header.startswith(GIF_MAGIC):
                return "gif"
            elif header.startswith(PDF_MAGIC):
                return "pdf"
            elif header.startswith(BMP_MAGIC):
                return "bmp"
            elif header.startswith(WEBP_MAGIC) and b"WEBP" in header:
                return "webp"
            elif header.startswith(TIFF_MAGIC_LE) or header.startswith(TIFF_MAGIC_BE):
                return "tiff"
            elif header.startswith(WAV_MAGIC) and b"WAVE" in header:
                return "wav"
            elif header.startswith(b"ID3") or header.startswith(MP3_MAGIC) or header.startswith(MP3_MAGIC2) or header.startswith(MP3_MAGIC3) or header.startswith(MP3_MAGIC4):
                return "mp3"
            elif header.startswith(FLAC_MAGIC):
                return "flac"
            elif header.startswith(OGG_MAGIC):
                return "ogg"
            elif header.startswith(MKV_MAGIC):
                try:
                    f.seek(0)
                    ebml_data = f.read(1024)
                    if b"webm" in ebml_data:
                        return "webm"
                    elif b"matroska" in ebml_data:
                        return "mkv"
                    else:
                        return "mkv"
                except:
                    return "mkv"
            elif header.startswith(FLV_MAGIC):
                return "flv"
            elif header.startswith(AVI_MAGIC) and b"AVI " in header:
                return "avi"
            elif header.startswith(ICO_MAGIC):
                return "ico"
            elif header.startswith(CUR_MAGIC):
                return "cur"
            elif header.startswith(ICNS_MAGIC):
                return "icns"
            elif header.startswith(ELF_MAGIC):
                return "elf"
            elif header.startswith(MSI_MAGIC):
                return "msi"
            elif header.startswith(TTF_MAGIC):
                return "ttf"
            elif header.startswith(OTF_MAGIC):
                return "otf"
            elif header.startswith(WOFF_MAGIC):
                return "woff"

            elif header.startswith(MZ_MAGIC):
                ext = os.path.splitext(file_path)[1].lower().lstrip('.')
                if ext == 'dll':
                    return "dll"
                return "exe"

            elif header[4:8] == b"ftyp":
                if len(header) >= 12:
                    brand = header[8:12]
                    if brand == b"qt  ":
                        return "mov"
                    elif brand in [b"M4A ", b"M4B ", b"mp42"]:
                        return "m4a"
                return "mp4"
            

            if len(header) >= 8:
                size = int.from_bytes(header[0:4], byteorder='big')
                if size >= 8 and size <= 1024:
                    f.seek(0)
                    box_data = f.read(size)
                    if len(box_data) >= 8 and box_data[4:8] == b"ftyp":
                        major = box_data[8:12] if len(box_data) >= 12 else None
                        if major == b"qt  ":
                            return "mov"
                        return "mp4"
            
            return None
    except Exception as e:
        return None

if command == "pack":
    if len(sys.argv) < 5:
        print(f"USAGE: {sys.argv[0]} pack cover.[png|pdf|jpg|gif|bmp|webp|tiff|wav|mp3|flac|ogg|avi|mkv|webm|flv|ico|cur|icns|mp4|mov|m4a|exe|dll|elf|msi|ttf|otf|woff] file1 [file2 file3 ...] output.[png|pdf|jpg|gif|bmp|webp|tiff|wav|mp3|flac|ogg|avi|mkv|webm|flv|ico|cur|icns|mp4|mov|m4a|exe|dll|elf|msi|ttf|otf|woff] [--key=file.key|--password=pass]")
        print(f"       # Embeds files into cover file and saves to output file")
        print(f"       # Use --key=file.key for AES-256 encryption with key file")
        print(f"       # Use --password=pass for AES-256 encryption with password")
        sys.exit(1)
    
    encryption_args = []
    regular_args = []
    for arg in sys.argv[2:]:
        if arg.startswith('--key=') or arg.startswith('--password='):
            encryption_args.append(arg)
        else:
            regular_args.append(arg)
    
    if len(regular_args) < 3:
        print(f"USAGE: {sys.argv[0]} pack cover_file file1 [file2 ...] output_file [--key=file.key|--password=pass]")
        sys.exit(1)
    
    cover_file = regular_args[0]
    output_file = regular_args[-1]
    files_to_embed = regular_args[1:-1]
    
    key_file, password = parse_encryption_args(encryption_args)
    encryption_key, salt = None, None
    
    if key_file or password:
        try:
            encryption_key, salt = get_encryption_key(key_file, password, create_if_missing=True)
            if encryption_key:
                if key_file:
                    print(f"[\033[36m+\033[0m] Using encryption with key file: {key_file}")
                else:
                    print(f"[\033[36m+\033[0m] Using encryption with password")
        except Exception as e:
            print(f"\033[31m[!] Encryption setup error: {e}\033[0m")
            sys.exit(1)
    
    if not os.path.exists(cover_file):
        print(f"\033[31m[!] Error: Cover file '{cover_file}' not found\033[0m")
        sys.exit(1)
    
    for file_path in files_to_embed:
        if not os.path.exists(file_path):
            print(f"\033[31m[!] Error: Input file '{file_path}' not found\033[0m")
            sys.exit(1)
    
    cover_type = detect_cover_file_type(cover_file)
    if not cover_type:
        print(f"\033[31m[!] Error: Cover file '{cover_file}' is not a supported format (png, jpg, gif, pdf, bmp, webp, tiff, wav, mp3, flac, ogg, avi, mkv, webm, flv, ico, cur, icns, mp4, mov, m4a, exe, dll, elf, msi, ttf, otf, woff)\033[0m")
        sys.exit(1)
    
    print(f"[\033[36m+\033[0m] Detected cover file type: {cover_type.upper()}")
    
    is_single_file = len(files_to_embed) == 1
    
    with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_zip_file:
        temp_zip_path = temp_zip_file.name
        
    try:
        with zipfile.ZipFile(temp_zip_path, 'w') as zipf:
            if encryption_key:
                # Create metadata for encrypted files
                metadata = {
                    "encrypted": True,
                    "version": "1.0",
                    "files": []
                }
                if salt:
                    metadata["salt"] = base64.b64encode(salt).decode()
                
                for file_path in files_to_embed:
                    print(f"[\033[36m+\033[0m] Encrypting and adding to ZIP: {os.path.basename(file_path)}")
                    
                    with open(file_path, 'rb') as f:
                        file_data = f.read()
                    
                    encrypted_data = encrypt_file_data(file_data, encryption_key)
                    encrypted_filename = os.path.basename(file_path) + '.enc'
                    zipf.writestr(encrypted_filename, encrypted_data)
                    
                    metadata["files"].append({
                        "original": os.path.basename(file_path),
                        "encrypted": encrypted_filename,
                        "size": len(file_data)
                    })
                
                zipf.writestr('metadata.json', json.dumps(metadata, indent=2))
                print(f"[\033[32m+\033[0m] Files encrypted with AES-256-GCM")
                
            else:
                for file_path in files_to_embed:
                    print(f"[\033[36m+\033[0m] Adding to ZIP: {os.path.basename(file_path)}")
                    zipf.write(file_path, os.path.basename(file_path))
        
        try:
            cover_in = open(cover_file, "rb")
        except Exception as e:
            print(f"\033[31m[!] Error opening cover file: {e}\033[0m")
            os.unlink(temp_zip_path)
            sys.exit(1)
            
        try:
            content_in = open(temp_zip_path, "rb")
        except Exception as e:
            cover_in.close()
            print(f"\033[31m[!] Error opening temp ZIP file: {e}\033[0m")
            os.unlink(temp_zip_path)
            sys.exit(1)
            
        try:
            output_out = open(output_file, "wb")
        except Exception as e:
            cover_in.close()
            content_in.close()
            print(f"\033[31m[!] Error creating output file: {e}\033[0m")
            os.unlink(temp_zip_path)
            sys.exit(1)

        try:
            if cover_type == "png":
                png_header = cover_in.read(len(PNG_MAGIC))
                if png_header != PNG_MAGIC:
                    raise ValueError(f"Not a valid PNG file: {cover_file}")
                
                output_out.write(png_header)
                
                content_embedded = False
                idat_count = 0
                
                while True:
                    chunk_len_bytes = cover_in.read(4)
                    if not chunk_len_bytes or len(chunk_len_bytes) < 4:
                        break
                        
                    chunk_len = int.from_bytes(chunk_len_bytes, "big")
                    chunk_type = cover_in.read(4)
                    
                    print(f"[\033[36m+\033[0m] Found chunk: {chunk_type.decode('ascii', errors='replace')} of length {chunk_len}")
                    
                    if not chunk_type or len(chunk_type) < 4:
                        break
                        
                    chunk_body = cover_in.read(chunk_len)
                    if len(chunk_body) < chunk_len:
                        print("\033[33m[!] Warning: Truncated chunk body\033[0m")
                        break
                        
                    chunk_csum_bytes = cover_in.read(4)
                    if not chunk_csum_bytes or len(chunk_csum_bytes) < 4:
                        break
                    
                    chunk_csum = int.from_bytes(chunk_csum_bytes, "big")
                    
                    if chunk_type == b"IDAT" and not content_embedded:
                        idat_count += 1
                        print(f"[\033[36m+\033[0m] Processing IDAT chunk for embedding ZIP data")
                        
                        output_out.write(chunk_len.to_bytes(4, "big"))
                        output_out.write(chunk_type)
                        output_out.write(chunk_body)
                        output_out.write(chunk_csum.to_bytes(4, "big"))
                        
                        current_pos = output_out.tell()
                        start_offset = current_pos
                        
                        content_dat = bytearray(content_in.read())
                        print(f"[\033[32m*\033[0m] ZIP data will start at offset \033[1m{hex(start_offset)}\033[0m")
                        
                        print("[\033[36m+\033[0m] Fixing up zip offsets for PNG/ZIP compatibility...")
                        success = fixup_zip(content_dat, start_offset)
                        if not success:
                            print("\033[33m[!] Warning: ZIP fix-up may not have worked correctly\033[0m")
                        
                        output_out.write(content_dat)
                        content_embedded = True
                        continue
                        
                    elif chunk_type == b"IDAT" and content_embedded:
                        print(f"[\033[36m+\033[0m] Skipping redundant IDAT chunk after ZIP embedding")
                        continue
                    
                    output_out.write(chunk_len.to_bytes(4, "big"))
                    output_out.write(chunk_type)
                    output_out.write(chunk_body)
                    output_out.write(chunk_csum.to_bytes(4, "big"))
                    
                    if chunk_type == b"IEND":
                        break

            elif cover_type == "jpeg":
                jpeg_data = cover_in.read()
                
                eoi_pos = jpeg_data.rfind(b'\xFF\xD9')
                
                if eoi_pos == -1:
                    raise ValueError(f"Invalid JPEG file: {cover_file}, no EOI marker found")
                
                output_out.write(jpeg_data[:eoi_pos+2])
                
                start_offset = eoi_pos + 2
                print(f"[\033[32m*\033[0m] ZIP data will start at offset \033[1m{hex(start_offset)}\033[0m")
                
                content_dat = bytearray(content_in.read())
                
                print("[\033[36m+\033[0m] Fixing up zip offsets for JPEG/ZIP compatibility...")
                success = fixup_zip(content_dat, start_offset)
                if not success:
                    print("\033[33m[!] Warning: ZIP fix-up may not have worked correctly\033[0m")
                
                output_out.write(content_dat)
                content_embedded = True
                
            elif cover_type == "gif":
                gif_data = cover_in.read()
                
                trailer_pos = gif_data.rfind(b'\x3B')
                
                if trailer_pos == -1:
                    raise ValueError(f"Invalid GIF file: {cover_file}, no trailer marker found")
                
                output_out.write(gif_data[:trailer_pos+1])
                
                start_offset = trailer_pos + 1
                print(f"[\033[32m*\033[0m] ZIP data will start at offset \033[1m{hex(start_offset)}\033[0m")
                
                content_dat = bytearray(content_in.read())
                
                print("[\033[36m+\033[0m] Fixing up zip offsets for GIF/ZIP compatibility...")
                success = fixup_zip(content_dat, start_offset)
                if not success:
                    print("\033[33m[!] Warning: ZIP fix-up may not have worked correctly\033[0m")
                
                output_out.write(content_dat)
                content_embedded = True
                
            elif cover_type == "pdf":
                pdf_data = cover_in.read()
                
                eof_pos = pdf_data.rfind(b'%%EOF')
                
                if eof_pos == -1:
                    raise ValueError(f"Invalid PDF file: {cover_file}, no EOF marker found")
                
                eol_pos = pdf_data.find(b'\n', eof_pos)
                if eol_pos == -1:
                    eol_pos = pdf_data.find(b'\r', eof_pos)
                    if eol_pos == -1:
                        eol_pos = len(pdf_data)
                    else:
                        eol_pos += 1
                else:
                    eol_pos += 1
                
                output_out.write(pdf_data[:eol_pos])
                
                start_offset = eol_pos
                print(f"[\033[32m*\033[0m] ZIP data will start at offset \033[1m{hex(start_offset)}\033[0m")
                
                content_dat = bytearray(content_in.read())
                
                print("[\033[36m+\033[0m] Fixing up zip offsets for PDF/ZIP compatibility...")
                success = fixup_zip(content_dat, start_offset)
                if not success:
                    print("\033[33m[!] Warning: ZIP fix-up may not have worked correctly\033[0m")
                
                output_out.write(content_dat)
                content_embedded = True
                
            elif cover_type == "bmp":
                bmp_data = cover_in.read()
                if len(bmp_data) >= 6:
                    bmp_size = int.from_bytes(bmp_data[2:6], "little")
                    zip_data = bmp_data[bmp_size:]
                else:
                    raise ValueError(f"Invalid BMP file: {cover_file}, file too small")
                
                output_out.write(bmp_data)
                
                start_offset = len(bmp_data)
                print(f"[\033[32m*\033[0m] ZIP data will start at offset \033[1m{hex(start_offset)}\033[0m")
                
                content_dat = bytearray(content_in.read())
                
                print("[\033[36m+\033[0m] Fixing up zip offsets for BMP/ZIP compatibility...")
                success = fixup_zip(content_dat, start_offset)
                if not success:
                    print("\033[33m[!] Warning: ZIP fix-up may not have worked correctly\033[0m")
                
                output_out.write(content_dat)
                content_embedded = True
                
            elif cover_type == "webp" or cover_type == "wav":
                riff_data = cover_in.read()
                if len(riff_data) < 12:
                    raise ValueError(f"Invalid {cover_type.upper()} file: {cover_file}, file too small")
                
                output_out.write(riff_data)
                
                start_offset = len(riff_data)
                print(f"[\033[32m*\033[0m] ZIP data will start at offset \033[1m{hex(start_offset)}\033[0m")
                
                content_dat = bytearray(content_in.read())
                
                print(f"[\033[36m+\033[0m] Fixing up zip offsets for {cover_type.upper()}/ZIP compatibility...")
                success = fixup_zip(content_dat, start_offset)
                if not success:
                    print("\033[33m[!] Warning: ZIP fix-up may not have worked correctly\033[0m")
                
                output_out.write(content_dat)
                content_embedded = True
                

                
            elif cover_type in ["tiff", "mp3", "flac", "ogg", "avi", "mkv", "webm", "flv", "ico", "cur", "icns", "mp4", "mov", "m4a", "exe", "dll", "elf", "msi", "ttf", "otf", "woff"]:
                format_data = cover_in.read()
                
                output_out.write(format_data)
                
                start_offset = len(format_data)
                print(f"[\033[32m*\033[0m] ZIP data will start at offset \033[1m{hex(start_offset)}\033[0m")
                
                content_dat = bytearray(content_in.read())
                
                print(f"[\033[36m+\033[0m] Fixing up zip offsets for {cover_type.upper()}/ZIP compatibility...")
                success = fixup_zip(content_dat, start_offset)
                if not success:
                    print("\033[33m[!] Warning: ZIP fix-up may not have worked correctly\033[0m")
                
                output_out.write(content_dat)
                content_embedded = True
                
            if content_embedded:
                print(f"\n[\033[32m✓\033[0m] \033[1mOperation successful\033[0m:")
                print(f"[\033[32m+\033[0m] Created dual-format {cover_type.upper()}/ZIP file: {output_file}")
                print(f"[\033[32m+\033[0m] This file can be viewed as {cover_type.upper()} or renamed to .zip and extracted")
                print(f"[\033[32m+\033[0m] Embedded {len(files_to_embed)} files")
                if encryption_key:
                    print(f"[\033[32m+\033[0m] Files are AES-256-GCM encrypted and secure")
                print()
            else:
                print(f"\033[31m[!] Error: Could not embed content in {cover_file}\033[0m")

        except Exception as e:
            print(f"\033[31m[!] Error during packing: {e}\033[0m")
        finally:
            cover_in.close()
            content_in.close()
            output_out.close()
    finally:
        try:
            os.unlink(temp_zip_path)
        except:
            pass

elif command == "extract":
    if len(sys.argv) < 3:
        print(f"USAGE: {sys.argv[0]} extract input.[png|pdf|jpg|gif|bmp|webp|tiff|wav|mp3|flac|ogg|avi|mkv|webm|flv|ico|cur|icns|mp4|mov|m4a|exe|dll|elf|msi|ttf|otf|woff] [output] [--key=file.key|--password=pass]")
        print(f"       # If output is omitted, extracts to directory named after input file")
        print(f"       # Use --key=file.key for AES-256 decryption with key file")
        print(f"       # Use --password=pass for AES-256 decryption with password")
        sys.exit(1)
    
    encryption_args = []
    regular_args = []
    for arg in sys.argv[2:]:
        if arg.startswith('--key=') or arg.startswith('--password='):
            encryption_args.append(arg)
        else:
            regular_args.append(arg)
    
    if len(regular_args) < 1:
        print(f"USAGE: {sys.argv[0]} extract input_file [output_directory] [--key=file.key|--password=pass]")
        sys.exit(1)
        
    input_file = regular_args[0]
    
    key_file, password = parse_encryption_args(encryption_args)
    encryption_key, salt = None, None
    
    if key_file or password:
        try:
            encryption_key, salt = get_encryption_key(key_file, password, create_if_missing=False)
            if encryption_key:
                if key_file:
                    print(f"[\033[36m+\033[0m] Using decryption with key file: {key_file}")
                else:
                    print(f"[\033[36m+\033[0m] Using decryption with password")
        except Exception as e:
            print(f"\033[31m[!] Decryption setup error: {e}\033[0m")
            sys.exit(1)
    
    if len(regular_args) >= 2:
        output_path = regular_args[1]
    else:
        output_path = os.path.splitext(os.path.basename(input_file))[0]
        print(f"[\033[36m+\033[0m] No output specified, extracting to directory: \033[1m{output_path}\033[0m")
        
        if not os.path.exists(output_path):
            os.makedirs(output_path, exist_ok=True)
            print(f"[\033[36m+\033[0m] Created directory: {output_path}")
    
    if not os.path.exists(input_file):
        print(f"\033[31m[!] Error: Input file '{input_file}' not found\033[0m")
        sys.exit(1)
    
    input_type = detect_cover_file_type(input_file)
    if not input_type:
        print(f"\033[31m[!] Error: Input file '{input_file}' is not a supported format (png, jpg, gif, pdf, bmp, webp, tiff, wav, mp3, flac, ogg, avi, mkv, webm, flv, ico, cur, icns, mp4, mov, m4a, exe, dll, elf, msi, ttf, otf, woff)\033[0m")
        sys.exit(1)
    
    print(f"[\033[36m+\033[0m] Detected input file type: {input_type.upper()}")
    
    with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_zip_file:
        temp_zip_path = temp_zip_file.name
    
    try:
        with open(input_file, "rb") as f_in:
            if input_type == "png":
                png_header = f_in.read(len(PNG_MAGIC))
                if png_header != PNG_MAGIC:
                    raise ValueError(f"Not a valid PNG file: {input_file}")
                
                zip_data_start = None
                
                while True:
                    chunk_len_bytes = f_in.read(4)
                    if not chunk_len_bytes or len(chunk_len_bytes) < 4:
                        break
                        
                    chunk_len = int.from_bytes(chunk_len_bytes, "big")
                    chunk_type = f_in.read(4)
                    
                    if not chunk_type or len(chunk_type) < 4:
                        break
                    
                    if chunk_type == b"IDAT":
                        f_in.seek(chunk_len + 4, 1)
                        zip_data_start = f_in.tell()
                        break
                    else:
                        f_in.seek(chunk_len + 4, 1)
                
                if zip_data_start is None:
                    raise ValueError(f"Could not find ZIP data in {input_file}")
                
                f_in.seek(zip_data_start)
                zip_data = f_in.read()
                
            elif input_type == "jpeg":
                jpeg_data = f_in.read()
                eoi_pos = jpeg_data.rfind(b'\xFF\xD9')
                if eoi_pos == -1:
                    raise ValueError(f"Invalid JPEG file: {input_file}, no EOI marker found")
                zip_data = jpeg_data[eoi_pos+2:]
                
            elif input_type == "gif":
                gif_data = f_in.read()
                trailer_pos = gif_data.rfind(b'\x3B')
                if trailer_pos == -1:
                    raise ValueError(f"Invalid GIF file: {input_file}, no trailer marker found")
                zip_data = gif_data[trailer_pos+1:]
                
            elif input_type == "pdf":
                pdf_data = f_in.read()
                eof_pos = pdf_data.rfind(b'%%EOF')
                if eof_pos == -1:
                    raise ValueError(f"Invalid PDF file: {input_file}, no EOF marker found")
                eol_pos = pdf_data.find(b'\n', eof_pos)
                if eol_pos == -1:
                    eol_pos = pdf_data.find(b'\r', eof_pos)
                    if eol_pos == -1:
                        eol_pos = len(pdf_data)
                    else:
                        eol_pos += 1
                else:
                    eol_pos += 1
                zip_data = pdf_data[eol_pos:]
                
            elif input_type == "bmp":
                bmp_data = f_in.read()
                if len(bmp_data) >= 6:
                    bmp_size = int.from_bytes(bmp_data[2:6], "little")
                    zip_data = bmp_data[bmp_size:]
                else:
                    raise ValueError(f"Invalid BMP file: {input_file}, file too small")
                
            elif input_type == "webp" or input_type == "wav":
                riff_data = f_in.read()
                if len(riff_data) >= 12:
                    riff_size = int.from_bytes(riff_data[4:8], "little") + 8
                    zip_data = riff_data[riff_size:]
                else:
                    raise ValueError(f"Invalid {input_type.upper()} file: {input_file}, file too small")
                
            elif input_type in ["tiff", "mp3", "flac", "ogg", "avi", "mkv", "webm", "flv", "ico", "cur", "icns", "mp4", "mov", "m4a", "exe", "dll", "elf", "msi", "ttf", "otf", "woff"]:
                data = f_in.read()
                zip_signatures = [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08']
                
                for sig in zip_signatures:
                    sig_pos = data.find(sig)
                    if sig_pos > 0:
                        zip_data = data[sig_pos:]
                        break
                else:
                    raise ValueError(f"Could not find ZIP data in {input_file}")
        
        with open(temp_zip_path, "wb") as f_out:
            f_out.write(zip_data)
        
        output_is_dir = os.path.isdir(output_path)
        
        if not output_is_dir:
            os.makedirs(output_path, exist_ok=True)
            output_is_dir = True
        
        try:
            with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
                file_list = zipf.namelist()
                print(f"[\033[36m+\033[0m] Found {len(file_list)} files in ZIP data")
                
                is_encrypted = 'metadata.json' in file_list
                files_to_decrypt = []
                
                if is_encrypted:
                    if not encryption_key:
                        print(f"\033[31m[!] Error: Files are encrypted but no decryption key/password provided\033[0m")
                        sys.exit(1)
                    
                    metadata_json = zipf.read('metadata.json').decode('utf-8')
                    metadata = json.loads(metadata_json)
                    
                    if not metadata.get('encrypted', False):
                        print(f"\033[31m[!] Error: Invalid encrypted file format\033[0m")
                        sys.exit(1)
                    
                    actual_key = encryption_key
                    if password and 'salt' in metadata:
                        salt = base64.b64decode(metadata['salt'].encode())
                        actual_key = derive_key_from_password(password, salt)
                    
                    print(f"[\033[36m+\033[0m] Decrypting {len(metadata['files'])} encrypted files")
                    
                    for file_info in metadata['files']:
                        encrypted_filename = file_info['encrypted']
                        original_filename = file_info['original']
                        encrypted_data = zipf.read(encrypted_filename)
                        
                        try:
                            decrypted_data = decrypt_file_data(encrypted_data, actual_key)
                        except Exception as e:
                            print(f"\033[31m[!] Failed to decrypt {original_filename}: {e}\033[0m")
                            continue
                        
                        output_file_path = os.path.join(output_path, original_filename)
                        with open(output_file_path, 'wb') as f:
                            f.write(decrypted_data)
                        
                        file_size = len(decrypted_data)
                        print(f"[\033[32m+\033[0m] Decrypted and extracted: \033[1m{original_filename}\033[0m ({file_size} bytes)")
                        
                        if file_size < 1024:
                            is_text_by_ext = output_file_path.endswith(('.txt', '.md', '.csv', '.json', '.xml', '.html', '.css', '.js', '.py', '.sh'))
                            
                            sample_data = decrypted_data[:100]
                            is_text = is_text_by_ext or is_likely_text_file(sample_data)
                            
                            if is_text:
                                try:
                                    content = decrypted_data.decode('utf-8').strip()
                                    print(f"[\033[36m*\033[0m] File content preview:")
                                    print(f"\033[33m----------------------------------------\033[0m")
                                    print(f"\033[37m{content}\033[0m")
                                    print(f"\033[33m----------------------------------------\033[0m")
                                except UnicodeDecodeError:
                                    pass
                    
                    extracted_count = len(metadata['files'])
                    print(f"\n[\033[32m✓\033[0m] \033[1mOperation successful\033[0m:")
                    print(f"[\033[32m+\033[0m] Successfully decrypted and extracted {extracted_count} files to {output_path}")
                    print(f"[\033[32m+\033[0m] Files were AES-256-GCM encrypted")
                    
                else:
                    if encryption_key:
                        print("[\033[33m!\033[0m] Warning: Decryption key/password provided but files are not encrypted")
                    
                    for file_name in file_list:
                        output_file_path = os.path.join(output_path, file_name)
                        zipf.extract(file_name, output_path)
                        
                        file_size = os.path.getsize(output_file_path)
                        print(f"[\033[32m+\033[0m] Extracted: \033[1m{file_name}\033[0m ({file_size} bytes)")
                        
                        if file_size < 1024:
                            is_text_by_ext = output_file_path.endswith(('.txt', '.md', '.csv', '.json', '.xml', '.html', '.css', '.js', '.py', '.sh'))
                            
                            with open(output_file_path, 'rb') as f:
                                sample_data = f.read(100)
                                is_text = is_text_by_ext or is_likely_text_file(sample_data)
                            
                            if is_text:
                                try:
                                    with open(output_file_path, 'r') as f:
                                        content = f.read().strip()
                                        print(f"[\033[36m*\033[0m] File content preview:")
                                        print(f"\033[33m----------------------------------------\033[0m")
                                        print(f"\033[37m{content}\033[0m")
                                        print(f"\033[33m----------------------------------------\033[0m")
                                except UnicodeDecodeError:
                                    pass
                    
                    print(f"\n[\033[32m✓\033[0m] \033[1mOperation successful\033[0m:")
                    print(f"[\033[32m+\033[0m] Successfully extracted {len(file_list)} files to {output_path}")
                
        except zipfile.BadZipFile:
            print(f"\033[31m[!] Error: Could not extract ZIP data from {input_file}. The file might be corrupted or not contain embedded ZIP data.\033[0m")
        
    except Exception as e:
        print(f"\033[31m[!] Error during extraction: {e}\033[0m")
    finally:
        try:
            os.unlink(temp_zip_path)
        except:
            pass

elif command == "detect":
    def detect_embedded_data_in_file(file_path):
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found")
            return False
            
        file_type = detect_cover_file_type(file_path)
        if not file_type:
            print(f"\033[31m[!] File '{file_path}' is not a supported format (png, jpg, gif, pdf, bmp, webp, tiff, wav, mp3, flac, ogg, avi, mkv, webm, flv, ico, cur, icns, mp4, mov, m4a, exe, dll, elf, msi, ttf, otf, woff)\033[0m")
            return False
        
        print(f"[\033[36m*\033[0m] File type: \033[1m{file_type.upper()}\033[0m")
        
        try:
            with open(file_path, "rb") as f:
                content = f.read()
                
                zip_signatures = [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08']
                
                is_suspicious = False
                for sig in zip_signatures:
                    sig_pos = content.find(sig)
                    if sig_pos > 0:
                        is_suspicious = True
                        print(f"[\033[31m!\033[0m] Found ZIP signature at offset {sig_pos}")
                
                if file_type == "png":
                    idat_count = content.count(b'IDAT')
                    if idat_count > 1:
                        print(f"[\033[33m!\033[0m] Multiple IDAT chunks detected ({idat_count}), could indicate embedded data")
                        is_suspicious = True
                
                elif file_type == "jpeg":
                    eoi_pos = content.rfind(b'\xFF\xD9')
                    if eoi_pos > 0 and eoi_pos < len(content) - 2:
                        trailing_bytes = len(content) - (eoi_pos + 2)
                        print(f"[\033[33m!\033[0m] Found {trailing_bytes} bytes after JPEG EOI marker")
                        is_suspicious = True
                
                elif file_type == "gif":
                    trailer_pos = content.rfind(b'\x3B')
                    if trailer_pos > 0 and trailer_pos < len(content) - 1:
                        trailing_bytes = len(content) - (trailer_pos + 1)
                        print(f"[\033[33m!\033[0m] Found {trailing_bytes} bytes after GIF trailer marker")
                        is_suspicious = True
                
                elif file_type == "pdf":
                    eof_pos = content.rfind(b'%%EOF')
                    if eof_pos > 0:
                        eol_pos = content.find(b'\n', eof_pos)
                        if eol_pos == -1:
                            eol_pos = content.find(b'\r', eof_pos)
                        
                        if eol_pos > 0 and eol_pos < len(content) - 1:
                            trailing_bytes = len(content) - (eol_pos + 1)
                            print(f"[\033[33m!\033[0m] Found {trailing_bytes} bytes after PDF EOF marker")
                            is_suspicious = True
                
                elif file_type == "bmp":
                    if len(content) >= 6:
                        bmp_size = int.from_bytes(content[2:6], "little")
                        trailing_data = content[bmp_size:]
                        found_sig = False
                        for sig in zip_signatures:
                            pos = trailing_data.find(sig)
                            if pos >= 0:
                                abs_pos = bmp_size + pos
                                print(f"[\033[31m!\033[0m] Found ZIP signature at offset {abs_pos}")
                                found_sig = True
                        if found_sig:
                            trailing_bytes = len(trailing_data)
                            print(f"[\033[33m!\033[0m] Found {trailing_bytes} bytes after BMP declared size")
                            is_suspicious = True
                
                elif file_type == "webp" or file_type == "wav":
                    if len(content) >= 12:
                        riff_size = int.from_bytes(content[4:8], "little") + 8
                        if len(content) > riff_size:
                            trailing_bytes = len(content) - riff_size
                            print(f"[\033[33m!\033[0m] Found {trailing_bytes} bytes after {file_type.upper()} declared size")
                            is_suspicious = True
                
                elif file_type == "tiff":
                    pass
                
                elif file_type == "mp3":
                    pass
                
                elif file_type == "flac":
                    pass
                
                if is_suspicious:
                    print("[\033[31m!\033[0m] This file likely contains embedded data")
                    
                    with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_file:
                        temp_path = temp_file.name
                    
                    try:
                        with open(temp_path, "wb") as temp:
                            if file_type == "png":
                                idat_pos = content.find(b'IDAT')
                                if idat_pos > 0:
                                    pos = idat_pos + 4
                                    chunk_len = int.from_bytes(content[idat_pos-4:idat_pos], "big")
                                    pos += chunk_len + 4
                                    temp.write(content[pos:])
                            elif file_type == "jpeg":
                                temp.write(content[eoi_pos+2:])
                            elif file_type == "gif":
                                temp.write(content[trailer_pos+1:])
                            elif file_type == "pdf":
                                temp.write(content[eol_pos+1:])
                            elif file_type == "bmp":
                                bmp_size = int.from_bytes(content[2:6], "little")
                                temp.write(content[bmp_size:])
                            elif file_type == "webp" or file_type == "wav":
                                riff_size = int.from_bytes(content[4:8], "little") + 8
                                temp.write(content[riff_size:])
                            elif file_type in ["tiff", "mp3", "flac", "avi", "ico", "cur", "mp4", "mov", "exe", "dll", "elf", "msi", "ttf", "otf", "woff", "tar", "iso", "cab", "unity", "dex", "class"]:
                                for sig in zip_signatures:
                                    sig_pos = content.find(sig)
                                    if sig_pos > 0:
                                        temp.write(content[sig_pos:])
                                        break
                        
                        try:
                            with zipfile.ZipFile(temp_path, 'r') as zipf:
                                zip_files = zipf.namelist()
                                if zip_files:
                                    print(f"[\033[32m✓\033[0m] Confirmed! Contains a valid ZIP archive with {len(zip_files)} files:")
                                    for zf in zip_files:
                                        print(f"  [\033[32m>\033[0m] {zf}")
                        except zipfile.BadZipFile:
                            print("[\033[33m!\033[0m] File contains suspicious patterns but ZIP validation failed")
                    finally:
                        try:
                            os.unlink(temp_path)
                        except:
                            pass
                    
                    return True
                else:
                    print("[\033[32m✓\033[0m] No evidence of embedded data found")
                    return False
        
        except Exception as e:
            print(f"\033[31m[!] Error analyzing {file_path}: {e}\033[0m")
            return False
    
    if len(sys.argv) == 3:
        detect_embedded_data_in_file(sys.argv[2])
    else:
        print("\033[36m[*]\033[0m Scanning current directory for files with potential embedded content...")
        
        supported_files = (glob.glob("*.png") + glob.glob("*.jpg") + glob.glob("*.jpeg") + glob.glob("*.gif") + glob.glob("*.pdf") + glob.glob("*.bmp") + glob.glob("*.webp") + glob.glob("*.tiff") + glob.glob("*.tif") + glob.glob("*.wav") + glob.glob("*.mp3") + glob.glob("*.flac") + glob.glob("*.ogg") + glob.glob("*.avi") + glob.glob("*.mkv") + glob.glob("*.webm") + glob.glob("*.flv") + glob.glob("*.ico") + glob.glob("*.cur") + glob.glob("*.icns") + glob.glob("*.mp4") + glob.glob("*.mov") + glob.glob("*.m4a") + glob.glob("*.exe") + glob.glob("*.dll") + glob.glob("*.elf") + glob.glob("*.msi") + glob.glob("*.ttf") + glob.glob("*.otf") + glob.glob("*.woff"))
        
        if not supported_files:
            print("\033[33m[!]\033[0m No supported files found in the current directory.")
            sys.exit(0)
            
        print(f"\033[36m[*]\033[0m Found {len(supported_files)} files to analyze.")
        
        suspicious_files = []
        for file_path in supported_files:
            print(f"\n[\033[36m*\033[0m] Analyzing {file_path}:")
            is_suspicious = detect_embedded_data_in_file(file_path)
            if is_suspicious:
                suspicious_files.append(file_path)
                
        print("\n\033[36m===================== Analysis Summary =====================\033[0m")
        print(f"\033[36m[*]\033[0m Total files scanned: {len(supported_files)}")
        
        if suspicious_files:
            print(f"\033[31m[!]\033[0m Suspicious files detected: {len(suspicious_files)}")
            print("\033[31m[!]\033[0m The following files likely contain embedded data:")
            for file in suspicious_files:
                print(f"    \033[31m>\033[0m \033[1m{file}\033[0m")
            print("\n\033[36m[*]\033[0m Use \033[1mextract\033[0m command to retrieve hidden content")
        else:
            print("\033[32m[✓]\033[0m No suspicious files detected in the current directory.")

elif command == "chat":
    if len(sys.argv) < 3:
        print(f"USAGE: {sys.argv[0]} chat [create|add|read|export] args...")
        print(f"        create: {sys.argv[0]} chat create cover_image.ext output_chat.ext [title] [--key=file.key|--password=pass]")
        print(f"                # Creates a new encrypted chat log hidden in an image")
        print(f"        add: {sys.argv[0]} chat add chat_image.ext sender \"message\" [output.ext] [--key=file.key|--password=pass]")
        print(f"             # Adds a message to existing encrypted chat (if no output, overwrites original)")
        print(f"        read: {sys.argv[0]} chat read chat_image.ext [--format=terminal|json|html] [--key=file.key|--password=pass]")
        print(f"              # Displays encrypted chat messages (default: terminal)")
        print(f"        export: {sys.argv[0]} chat export chat_image.ext output.[txt|json|html] [--key=file.key|--password=pass]")
        print(f"                # Exports encrypted chat to specified format")
        sys.exit(1)
    
    subcommand = sys.argv[2]
    
    if subcommand == "create":
        if len(sys.argv) < 5:
            print(f"USAGE: {sys.argv[0]} chat create cover_image.ext output_chat.ext [title] [--key=file.key|--password=pass]")
            sys.exit(1)

        cover_image = sys.argv[3]
        output_chat = sys.argv[4]

        title = "Chat Log"
        remaining_args = sys.argv[5:]
        if remaining_args and not remaining_args[0].startswith('--'):
            title = remaining_args[0]
            remaining_args = remaining_args[1:]

        key_file, password = parse_encryption_args(remaining_args)
        
        if not os.path.exists(cover_image):
            print(f"\033[31m[!] Error: Cover image '{cover_image}' not found\033[0m")
            sys.exit(1)
        
        try:

            encryption_key, salt = get_encryption_key(key_file, password, create_if_missing=True)
            
            if encryption_key:
                print(f"[\033[36m+\033[0m] Creating new encrypted chat log '{title}' hidden in {cover_image}")
                if key_file:
                    print(f"[\033[36m+\033[0m] Using key file: {key_file}")
                else:
                    print(f"[\033[36m+\033[0m] Using password-based encryption")
            else:
                print(f"[\033[36m+\033[0m] Creating new unencrypted chat log '{title}' hidden in {cover_image}")

            chat_data = create_chat_data(title)

            save_chat_to_image(cover_image, chat_data, output_chat, encryption_key, salt)
            
            print(f"[\033[32m✓\033[0m] \033[1mChat creation successful\033[0m:")
            print(f"[\033[32m+\033[0m] Created chat log: {title}")
            print(f"[\033[32m+\033[0m] Hidden chat saved to: {output_chat}")
            if encryption_key:
                print(f"[\033[32m+\033[0m] Chat is AES-256 encrypted")
            print(f"[\033[32m+\033[0m] This file can be viewed as a normal image or used for hidden chat")
            
        except Exception as e:
            print(f"\033[31m[!] Error creating chat: {e}\033[0m")
            sys.exit(1)

    elif subcommand == "add":
        if len(sys.argv) < 6:
            print(f"USAGE: {sys.argv[0]} chat add chat_image.ext sender \"message\" [output.ext] [--key=file.key|--password=pass]")
            sys.exit(1)

        chat_image = sys.argv[3]
        sender = sys.argv[4]
        message = sys.argv[5]

        remaining_args = sys.argv[6:]
        output_image = chat_image 

        if remaining_args and not remaining_args[0].startswith('--'):
            output_image = remaining_args[0]
            remaining_args = remaining_args[1:]
        key_file, password = parse_encryption_args(remaining_args)
        
        if not os.path.exists(chat_image):
            print(f"\033[31m[!] Error: Chat image '{chat_image}' not found\033[0m")
            sys.exit(1)
        
        try:

            encryption_key, salt = get_encryption_key(key_file, password, create_if_missing=False)
            
            print(f"[\033[36m+\033[0m] Adding message from {sender} to chat")

            chat_data = extract_chat_from_image(chat_image, encryption_key, password)
            chat_data = add_message_to_chat(chat_data, sender, message)
            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as temp_cover:
                temp_cover_path = temp_cover.name
                
            try:
                cover_data = extract_cover_from_chat_image(chat_image)
                with open(temp_cover_path, 'wb') as f:
                    f.write(cover_data)

                save_chat_to_image(temp_cover_path, chat_data, output_image, encryption_key, salt)
            finally:
                try:
                    os.unlink(temp_cover_path)
                except:
                    pass
            
            print(f"[\033[32m✓\033[0m] \033[1mMessage added successfully\033[0m:")
            print(f"[\033[32m+\033[0m] From: {sender}")
            print(f"[\033[32m+\033[0m] Message: {message}")
            print(f"[\033[32m+\033[0m] Total messages: {len(chat_data['messages'])}")
            if output_image != chat_image:
                print(f"[\033[32m+\033[0m] Updated chat saved to: {output_image}")
            else:
                print(f"[\033[32m+\033[0m] Chat updated in place")
                
        except Exception as e:
            print(f"\033[31m[!] Error adding message: {e}\033[0m")
            sys.exit(1)

    elif subcommand == "read":
        if len(sys.argv) < 4:
            print(f"USAGE: {sys.argv[0]} chat read chat_image.ext [--format=terminal|json|html] [--key=file.key|--password=pass]")
            sys.exit(1)
        
        chat_image = sys.argv[3]
        remaining_args = sys.argv[4:]

        format_type = "terminal"
        format_found = False
        encryption_args = []
        
        for arg in remaining_args:
            if arg.startswith("--format="):
                format_type = arg.split("=")[1]
                format_found = True
            elif arg.startswith("--key=") or arg.startswith("--password="):
                encryption_args.append(arg)
        
        if format_type not in ["terminal", "json", "html"]:
            print(f"\033[31m[!] Error: Invalid format '{format_type}'. Use terminal, json, or html\033[0m")
            sys.exit(1)

        key_file, password = parse_encryption_args(encryption_args)
        
        if not os.path.exists(chat_image):
            print(f"\033[31m[!] Error: Chat image '{chat_image}' not found\033[0m")
            sys.exit(1)
        
        try:
            encryption_key, salt = get_encryption_key(key_file, password, create_if_missing=False)
            
            print(f"[\033[36m+\033[0m] Reading chat from {chat_image}")
            chat_data = extract_chat_from_image(chat_image, encryption_key, password)
            
            if format_type == "terminal":
                print(format_chat_terminal(chat_data))
            elif format_type == "json":
                print(json.dumps(chat_data, indent=2))
            elif format_type == "html":
                print(format_chat_html(chat_data))
                
        except Exception as e:
            print(f"\033[31m[!] Error reading chat: {e}\033[0m")
            sys.exit(1)

    elif subcommand == "export":
        if len(sys.argv) < 5:
            print(f"USAGE: {sys.argv[0]} chat export chat_image.ext output.[txt|json|html] [--key=file.key|--password=pass]")
            sys.exit(1)
        
        chat_image = sys.argv[3]
        output_file = sys.argv[4]
        remaining_args = sys.argv[5:]

        key_file, password = parse_encryption_args(remaining_args)
        
        if not os.path.exists(chat_image):
            print(f"\033[31m[!] Error: Chat image '{chat_image}' not found\033[0m")
            sys.exit(1)

        output_ext = os.path.splitext(output_file)[1].lower()
        if output_ext not in ['.txt', '.json', '.html']:
            print(f"\033[31m[!] Error: Unsupported output format '{output_ext}'. Use .txt, .json, or .html\033[0m")
            sys.exit(1)
        
        try:

            encryption_key, salt = get_encryption_key(key_file, password, create_if_missing=False)
            
            print(f"[\033[36m+\033[0m] Exporting chat from {chat_image} to {output_file}")

            chat_data = extract_chat_from_image(chat_image, encryption_key, password)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                if output_ext == '.json':
                    f.write(json.dumps(chat_data, indent=2))
                elif output_ext == '.html':
                    f.write(format_chat_html(chat_data))
                elif output_ext == '.txt':
                    f.write(f"Chat Log: {chat_data['title']}\n")
                    f.write(f"Created: {chat_data['created']}\n")
                    f.write(f"Participants: {', '.join(chat_data['participants'])}\n")
                    f.write(f"Messages: {len(chat_data['messages'])}\n")
                    f.write("=" * 60 + "\n\n")
                    
                    for msg in chat_data["messages"]:
                        timestamp = datetime.datetime.fromisoformat(msg["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                        f.write(f"[{timestamp}] {msg['sender']}:\n")
                        f.write(f"  {msg['message']}\n\n")
            
            print(f"[\033[32m✓\033[0m] \033[1mChat exported successfully\033[0m:")
            print(f"[\033[32m+\033[0m] Format: {output_ext[1:].upper()}")
            print(f"[\033[32m+\033[0m] Output file: {output_file}")
            print(f"[\033[32m+\033[0m] Messages exported: {len(chat_data['messages'])}")
                
        except Exception as e:
            print(f"\033[31m[!] Error exporting chat: {e}\033[0m")
            sys.exit(1)
    
    else:
        print(f"\033[31m[!] Unknown chat subcommand: {subcommand}\033[0m")
        print(f"USAGE: {sys.argv[0]} chat [create|add|read|export] args...")
        sys.exit(1)

else:
    print(f"\033[31m[!] Unknown command: {command}\033[0m")
    print_usage() 
