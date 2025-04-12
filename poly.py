#!/usr/bin/env python3
"""
PolyZip - A tool for creating polyglot files (PNG/JPEG/GIF/PDF + ZIP)
Based on the work of DavidBuchanan314 (https://github.com/DavidBuchanan314/tweetable-polyglot-png)
Author: InfoSecREDD
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

def check_and_install_dependencies():
    required_packages = [
        {'package': 'python-magic', 'import_name': 'magic', 'optional': True}
    ]
    
    in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    venv_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.poly_venv')
    
    in_our_venv = False
    if in_venv and os.path.dirname(os.path.abspath(sys.prefix)) == os.path.dirname(os.path.abspath(venv_dir)):
        in_our_venv = True
    
    if os.path.exists(venv_dir) and not in_our_venv:
        print(f"[\033[36m*\033[0m] Virtual environment found, restarting script in venv...")
        if platform.system() == 'Windows':
            venv_python = os.path.join(venv_dir, 'Scripts', 'python.exe')
        else:
            venv_python = os.path.join(venv_dir, 'bin', 'python')
        
        if os.path.exists(venv_python):
            os.execl(venv_python, venv_python, *sys.argv)
        else:
            print(f"[\033[33m!\033[0m] Virtual environment found but Python executable not found at {venv_python}")

    missing_critical_packages = []
    missing_optional_packages = []
    
    for package_info in required_packages:
        if importlib.util.find_spec(package_info['import_name']) is None:
            if package_info.get('optional', False):
                missing_optional_packages.append(package_info['package'])
            else:
                missing_critical_packages.append(package_info['package'])
    
    if in_our_venv and (missing_critical_packages or missing_optional_packages):
        all_missing = missing_critical_packages + missing_optional_packages
        print(f"[\033[36m*\033[0m] Running in our venv but missing packages: {', '.join(all_missing)}")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + all_missing)
            print(f"[\033[32m✓\033[0m] Dependencies installed in venv!")
            return
        except Exception as e:
            print(f"[\033[31m!\033[0m] Failed to install dependencies in venv: {e}")
    
    if missing_critical_packages:
        print(f"[\033[31m!\033[0m] Critical packages are missing: {', '.join(missing_critical_packages)}")
        user_input = input(f"[\033[36m?\033[0m] Do you want to install them now? (y/n): ").strip().lower()
        if user_input != 'y':
            print(f"[\033[31m!\033[0m] Cannot continue without required packages.")
            sys.exit(1)
        install_packages(missing_critical_packages)
    
    if missing_optional_packages:
        print(f"[\033[33m!\033[0m] Optional packages are missing: {', '.join(missing_optional_packages)}")
        print(f"[\033[36m*\033[0m] The tool will use fallback methods, but some features might be limited.")
        print(f"[\033[36m?\033[0m] Would you like to install optional packages in a virtual environment for better functionality? (y/n): ", end="")
        user_input = input().strip().lower()
        if user_input == 'y':
            install_packages(missing_optional_packages)
        else:
            print(f"[\033[36m*\033[0m] You can install them manually with: pip install {' '.join(missing_optional_packages)}")

def install_packages(package_list):
    if not package_list:
        return
        
    venv_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.poly_venv')
    
    in_our_venv = False
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        if os.path.dirname(os.path.abspath(sys.prefix)) == os.path.dirname(os.path.abspath(venv_dir)):
            in_our_venv = True
    
    if not in_our_venv:
        print(f"[\033[36m+\033[0m] Creating virtual environment in {venv_dir}")
        try:
            if not os.path.exists(venv_dir):
                subprocess.check_call([sys.executable, '-m', 'venv', venv_dir])
            
            if platform.system() == 'Windows':
                venv_python = os.path.join(venv_dir, 'Scripts', 'python.exe')
            else:
                venv_python = os.path.join(venv_dir, 'bin', 'python')
            
            subprocess.check_call([venv_python, '-m', 'pip', 'install'] + package_list)
            
            print(f"[\033[32m✓\033[0m] Dependencies installed! Restarting script in virtual environment...")
            os.execl(venv_python, venv_python, *sys.argv)
        except Exception as e:
            print(f"[\033[31m!\033[0m] Failed to setup virtual environment: {e}")
            print(f"[\033[31m!\033[0m] Please install the required packages manually:")
            print(f"    pip install {' '.join(package_list)}")
            sys.exit(1)
    else:
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + package_list)
            print(f"[\033[32m✓\033[0m] Dependencies installed! Script will work with full functionality.")
        except Exception as e:
            print(f"[\033[31m!\033[0m] Failed to install dependencies: {e}")
            print(f"[\033[36m*\033[0m] The script will continue using fallback methods.")

if __name__ == "__main__":
    check_and_install_dependencies()

BANNER = r'''
██████╗  ██████╗ ██╗  ██╗   ██╗███████╗██╗██████╗ 
██╔══██╗██╔═══██╗██║  ╚██╗ ██╔╝╚══███╔╝██║██╔══██╗
██████╔╝██║   ██║██║   ╚████╔╝   ███╔╝ ██║██████╔╝
██╔═══╝ ██║   ██║██║    ╚██╔╝   ███╔╝  ██║██╔═══╝ 
██║     ╚██████╔╝███████╗██║   ███████╗██║██║     
╚═╝      ╚═════╝ ╚══════╝╚═╝   ╚══════╝╚═╝╚═╝     
                                                   
    [ PNG Steganography Tool - Hide Any Data ]
   ╔══════════════════════════════════════════╗
   ║  pack ≫ extract ≫ detect ≫ ghost in png  ║
   ╚══════════════════════════════════════════╝
'''

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC = b"\xff\xd8\xff"
GIF_MAGIC = b"GIF8"
PDF_MAGIC = b"%PDF-"

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
    
    version_info = f"{colors['green']}[+]{colors['reset']} {colors['white']}Version 1.2.0{colors['reset']} | " + \
                   f"{colors['green']}[+]{colors['reset']} {colors['white']}Data Hidden in Plain Sight{colors['reset']}"
    print(version_info)
    print(f"{colors['green']}[+]{colors['reset']} {colors['white']}Use {colors['cyan']}detect{colors['reset']} to scan for hidden data")
    print()

def print_usage():
    print(f"USAGE: {sys.argv[0]} [pack|extract|detect] args...")
    print(f"  pack: {sys.argv[0]} pack cover.[png|pdf|jpg|gif] file1 [file2 file3 ...] output.[png|pdf|jpg|gif]")
    print(f"        # Embeds files into cover file and saves to output file")
    print(f"        # The file can be viewed normally or renamed to .zip and extracted with standard tools")
    print(f"  extract: {sys.argv[0]} extract input.[png|pdf|jpg|gif] [output]")
    print(f"           # output can be a file or directory (auto-detected for multi-files)")
    print(f"           # if output is omitted, extracts to directory named after input file")
    print(f"  detect: {sys.argv[0]} detect [input.[png|pdf|jpg|gif]]  # If no file specified, scans current directory")
    sys.exit(1)

if len(sys.argv) < 2:
    print_banner()
    print_usage()

if len(sys.argv) == 4 and sys.argv[1] not in ["pack", "extract", "detect"]:
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
        b'\xca\xfe\xba\xbe': '.class',
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
        elif data.startswith(b'package ') or b'public class ' in data[:500]:
            return '.java'
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
            header = f.read(8)
            
            if header.startswith(PNG_MAGIC):
                return "png"
            elif header.startswith(JPEG_MAGIC):
                return "jpeg"
            elif header.startswith(GIF_MAGIC):
                return "gif"
            elif header.startswith(PDF_MAGIC):
                return "pdf"
            else:
                return None
    except Exception:
        return None

if command == "pack":
    if len(sys.argv) < 5:
        print(f"USAGE: {sys.argv[0]} pack cover.[png|pdf|jpg|gif] file1 [file2 file3 ...] output.[png|pdf|jpg|gif]")
        print(f"       # Embeds files into cover file and saves to output file")
        sys.exit(1)
    
    cover_file = sys.argv[2]
    output_file = sys.argv[-1]
    files_to_embed = sys.argv[3:-1]
    
    if not os.path.exists(cover_file):
        print(f"\033[31m[!] Error: Cover file '{cover_file}' not found\033[0m")
        sys.exit(1)
    
    for file_path in files_to_embed:
        if not os.path.exists(file_path):
            print(f"\033[31m[!] Error: Input file '{file_path}' not found\033[0m")
            sys.exit(1)
    
    cover_type = detect_cover_file_type(cover_file)
    if not cover_type:
        print(f"\033[31m[!] Error: Cover file '{cover_file}' is not a supported format (png, jpg, gif, pdf)\033[0m")
        sys.exit(1)
    
    print(f"[\033[36m+\033[0m] Detected cover file type: {cover_type.upper()}")
    
    is_single_file = len(files_to_embed) == 1
    
    with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_zip_file:
        temp_zip_path = temp_zip_file.name
        
    try:
        with zipfile.ZipFile(temp_zip_path, 'w') as zipf:
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
            
            if content_embedded:
                print(f"\n[\033[32m✓\033[0m] \033[1mOperation successful\033[0m:")
                print(f"[\033[32m+\033[0m] Created dual-format {cover_type.upper()}/ZIP file: {output_file}")
                print(f"[\033[32m+\033[0m] This file can be viewed as {cover_type.upper()} or renamed to .zip and extracted")
                print(f"[\033[32m+\033[0m] Embedded {len(files_to_embed)} files\n")
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
        print(f"USAGE: {sys.argv[0]} extract input.[png|pdf|jpg|gif] [output]")
        print(f"       # If output is omitted, extracts to directory named after input file")
        sys.exit(1)
        
    input_file = sys.argv[2]
    
    if len(sys.argv) >= 4:
        output_path = sys.argv[3]
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
        print(f"\033[31m[!] Error: Input file '{input_file}' is not a supported format (png, jpg, gif, pdf)\033[0m")
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
            print(f"\033[31m[!] File '{file_path}' is not a supported format (png, jpg, gif, pdf)\033[0m")
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
        
        supported_files = glob.glob("*.png") + glob.glob("*.jpg") + glob.glob("*.jpeg") + glob.glob("*.gif") + glob.glob("*.pdf")
        
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

else:
    print(f"\033[31m[!] Unknown command: {command}\033[0m")
    print_usage() 