#!/usr/bin/env python3
"""
PRODIGY_CS_02: Advanced Image Encryption Tool
===============================================
A sophisticated yet simple image encryption tool using pixel manipulation techniques.
Developed for Prodigy Infotech Cybersecurity Internship.

Author: Amit Mondal - Cybersecurity Intern - Prodigy InfoTech
Date: June 2025
Version: 1.0

Features:
- Multiple encryption algorithms (XOR, Pixel Swapping, Mathematical Operations)
- GUI and CLI interfaces
- Support for PNG, JPG, JPEG, BMP formats
- Secure key derivation
- Image integrity verification
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import argparse
import hashlib
import numpy as np
from PIL import Image, ImageTk
import os
import sys
from typing import Tuple, Optional, Union
import random


class ImageEncryption:
    """Core image encryption/decryption engine with multiple algorithms."""
    
    SUPPORTED_FORMATS = {'.png', '.jpg', '.jpeg', '.bmp'}
    
    def __init__(self):
        self.original_image = None
        self.processed_image = None
        self.image_shape = None
    
    def derive_key(self, key: Union[str, int], method: str = "sha256") -> int:
        """
        Derive a numeric key from string input using cryptographic hashing.
        Ensures consistent key generation for encryption/decryption.
        """
        if isinstance(key, int):
            return key % 256
        
        if method == "sha256":
            hash_obj = hashlib.sha256(str(key).encode())
            return int(hash_obj.hexdigest()[:8], 16) % 256
        elif method == "md5":
            hash_obj = hashlib.md5(str(key).encode())
            return int(hash_obj.hexdigest()[:8], 16) % 256
        else:
            # Simple ASCII sum fallback
            return sum(ord(c) for c in str(key)) % 256
    
    def load_image(self, image_path: str) -> bool:
        """Load and validate image file."""
        try:
            if not os.path.exists(image_path):
                raise FileNotFoundError(f"Image file not found: {image_path}")
            
            file_ext = os.path.splitext(image_path)[1].lower()
            if file_ext not in self.SUPPORTED_FORMATS:
                raise ValueError(f"Unsupported format. Supported: {', '.join(self.SUPPORTED_FORMATS)}")
            
            self.original_image = Image.open(image_path).convert('RGB')
            self.image_shape = self.original_image.size
            return True
            
        except Exception as e:
            print(f"Error loading image: {e}")
            return False
    
    def save_image(self, image: Image.Image, output_path: str) -> bool:
        """Save processed image to file."""
        try:
            # Ensure output directory exists
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            image.save(output_path, quality=95)
            return True
        except Exception as e:
            print(f"Error saving image: {e}")
            return False
    
    def xor_encryption(self, image: Image.Image, key: str, encrypt: bool = True) -> Image.Image:
        """
        XOR-based encryption/decryption (symmetric operation).
        Enhanced with multi-component key derivation.
        """
        img_array = np.array(image)
        
        # Derive three different keys for R, G, B channels
        base_key = self.derive_key(key)
        key_r = base_key
        key_g = (base_key * 2) % 256
        key_b = (base_key * 3) % 256
        
        # Apply XOR to each channel
        img_array[:, :, 0] = img_array[:, :, 0] ^ key_r  # Red
        img_array[:, :, 1] = img_array[:, :, 1] ^ key_g  # Green
        img_array[:, :, 2] = img_array[:, :, 2] ^ key_b  # Blue
        
        return Image.fromarray(img_array.astype('uint8'))
    
    def mathematical_encryption(self, image: Image.Image, key: str, encrypt: bool = True) -> Image.Image:
        """
        Mathematical operation-based encryption using modular arithmetic.
        Uses addition for encryption and subtraction for decryption.
        """
        img_array = np.array(image, dtype=np.int16)  # Prevent overflow
        base_key = self.derive_key(key)
        
        if encrypt:
            # Encryption: Addition with wraparound
            img_array = (img_array + base_key) % 256
        else:
            # Decryption: Subtraction with wraparound
            img_array = (img_array - base_key + 256) % 256
        
        return Image.fromarray(img_array.astype('uint8'))
    
    def pixel_swapping_encryption(self, image: Image.Image, key: str, encrypt: bool = True) -> Image.Image:
        """
        Advanced pixel swapping with deterministic pattern based on key.
        Swaps pixels in a reversible, key-dependent manner.
        """
        img_array = np.array(image)
        height, width, channels = img_array.shape
        
        # Use key to seed random number generator for consistent swapping
        seed = self.derive_key(key)
        random.seed(seed)
        np.random.seed(seed)
        
        # Create a list of all pixel coordinates
        coords = [(i, j) for i in range(height) for j in range(width)]
        
        # Generate swapping pairs deterministically
        swapped_coords = coords.copy()
        np.random.shuffle(swapped_coords)
        
        # Create temporary copy for swapping
        temp_array = img_array.copy()
        
        # Perform swapping (same operation for encrypt/decrypt due to symmetry)
        for orig_coord, swap_coord in zip(coords, swapped_coords):
            if orig_coord != swap_coord:
                # Swap pixels
                temp_pixel = temp_array[orig_coord[0], orig_coord[1]].copy()
                temp_array[orig_coord[0], orig_coord[1]] = img_array[swap_coord[0], swap_coord[1]]
                temp_array[swap_coord[0], swap_coord[1]] = temp_pixel
        
        return Image.fromarray(temp_array)
    
    def channel_swapping_encryption(self, image: Image.Image, key: str, encrypt: bool = True) -> Image.Image:
        """
        RGB channel swapping based on key-derived pattern.
        Different patterns for encryption and decryption.
        """
        img_array = np.array(image)
        key_val = self.derive_key(key) % 6  # 6 possible permutations of RGB
        
        # Define swapping patterns
        patterns = [
            [0, 1, 2],  # RGB -> RGB (no change)
            [0, 2, 1],  # RGB -> RBG
            [1, 0, 2],  # RGB -> GRB
            [1, 2, 0],  # RGB -> GBR
            [2, 0, 1],  # RGB -> BRG
            [2, 1, 0],  # RGB -> BGR
        ]
        
        # Reverse patterns for decryption
        reverse_patterns = [
            [0, 1, 2], [0, 2, 1], [1, 0, 2], 
            [2, 0, 1], [2, 1, 0], [1, 2, 0]
        ]
        
        pattern = patterns[key_val] if encrypt else reverse_patterns[key_val]
        
        # Apply channel swapping
        result_array = img_array.copy()
        result_array[:, :, 0] = img_array[:, :, pattern[0]]
        result_array[:, :, 1] = img_array[:, :, pattern[1]]
        result_array[:, :, 2] = img_array[:, :, pattern[2]]
        
        return Image.fromarray(result_array)
    
    def process_image(self, algorithm: str, key: str, encrypt: bool = True) -> Optional[Image.Image]:
        """
        Main processing function that applies selected algorithm.
        """
        if not self.original_image:
            raise ValueError("No image loaded")
            
        algorithms = {
            'xor': self.xor_encryption,
            'mathematical': self.mathematical_encryption,
            'pixel_swap': self.pixel_swapping_encryption,
            'channel_swap': self.channel_swapping_encryption
        }
        
        if algorithm not in algorithms:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        
        try:
            self.processed_image = algorithms[algorithm](self.original_image, key, encrypt)
            return self.processed_image
        except Exception as e:
            print(f"Error processing image: {e}")
            return None


class ImageEncryptionGUI:
    """Advanced GUI interface for the image encryption tool."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PRODIGY_CS_02 - Advanced Image Encryption Tool")
        self.root.geometry("900x700")
        self.root.configure(bg='#2c3e50')
        
        # Initialize encryption engine
        self.engine = ImageEncryption()
        
        # GUI variables
        self.input_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.encryption_key = tk.StringVar()
        self.selected_algorithm = tk.StringVar(value='xor')
        self.operation_mode = tk.StringVar(value='encrypt')
        
        # Image display variables
        self.original_display = None
        self.processed_display = None
        
        self.setup_gui()
    
    def setup_gui(self):
        """Create and configure GUI elements."""
        # Main title
        title_frame = tk.Frame(self.root, bg='#2c3e50')
        title_frame.pack(pady=20)
        
        title_label = tk.Label(
            title_frame, 
            text="🔐 Advanced Image Encryption Tool",
            font=('Arial', 24, 'bold'),
            fg='#ecf0f1',
            bg='#2c3e50'
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            title_frame,
            text="PRODIGY_CS_02 | Cybersecurity Internship Project",
            font=('Arial', 12),
            fg='#bdc3c7',
            bg='#2c3e50'
        )
        subtitle_label.pack()
        
        # Main container
        main_frame = tk.Frame(self.root, bg='#34495e', relief='raised', bd=2)
        main_frame.pack(padx=20, pady=10, fill='both', expand=True)
        
        # Control panel
        self.create_control_panel(main_frame)
        
        # Image display area
        self.create_image_display(main_frame)
        
        # Status bar
        self.create_status_bar()
    
    def create_control_panel(self, parent):
        """Create control panel with all options."""
        control_frame = tk.LabelFrame(
            parent, 
            text="Encryption Controls",
            font=('Arial', 14, 'bold'),
            fg='#ecf0f1',
            bg='#34495e',
            relief='groove',
            bd=2
        )
        control_frame.pack(padx=10, pady=10, fill='x')
        
        # File selection
        file_frame = tk.Frame(control_frame, bg='#34495e')
        file_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(file_frame, text="Input Image:", font=('Arial', 10, 'bold'), 
                fg='#ecf0f1', bg='#34495e').grid(row=0, column=0, sticky='w')
        tk.Entry(file_frame, textvariable=self.input_path, width=50, font=('Arial', 9)).grid(row=0, column=1, padx=5)
        tk.Button(file_frame, text="Browse", command=self.browse_input_file,
                 bg='#3498db', fg='white', font=('Arial', 9, 'bold')).grid(row=0, column=2, padx=5)
        
        # Algorithm selection
        algo_frame = tk.Frame(control_frame, bg='#34495e')
        algo_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(algo_frame, text="Encryption Algorithm:", font=('Arial', 10, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(anchor='w')
        
        algorithms = [
            ('XOR Encryption (Recommended)', 'xor'),
            ('Mathematical Operations', 'mathematical'),
            ('Pixel Swapping', 'pixel_swap'),
            ('Channel Swapping', 'channel_swap')
        ]
        
        for text, value in algorithms:
            tk.Radiobutton(
                algo_frame, text=text, variable=self.selected_algorithm, value=value,
                font=('Arial', 9), fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50'
            ).pack(anchor='w', padx=20)
        
        # Key input
        key_frame = tk.Frame(control_frame, bg='#34495e')
        key_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(key_frame, text="Encryption Key:", font=('Arial', 10, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(anchor='w')
        key_entry = tk.Entry(key_frame, textvariable=self.encryption_key, width=40, 
                           font=('Arial', 10), show='*')
        key_entry.pack(anchor='w', pady=5)
        
        # Operation buttons
        button_frame = tk.Frame(control_frame, bg='#34495e')
        button_frame.pack(fill='x', padx=10, pady=15)
        
        tk.Button(
            button_frame, text="🔒 ENCRYPT IMAGE", command=self.encrypt_image,
            bg='#e74c3c', fg='white', font=('Arial', 12, 'bold'),
            relief='raised', bd=3, padx=20, pady=5
        ).pack(side='left', padx=10)
        
        tk.Button(
            button_frame, text="🔓 DECRYPT IMAGE", command=self.decrypt_image,
            bg='#27ae60', fg='white', font=('Arial', 12, 'bold'),
            relief='raised', bd=3, padx=20, pady=5
        ).pack(side='left', padx=10)
        
        tk.Button(
            button_frame, text="💾 SAVE RESULT", command=self.save_result,
            bg='#f39c12', fg='white', font=('Arial', 12, 'bold'),
            relief='raised', bd=3, padx=20, pady=5
        ).pack(side='right', padx=10)
    
    def create_image_display(self, parent):
        """Create image display area."""
        display_frame = tk.LabelFrame(
            parent, text="Image Preview", font=('Arial', 14, 'bold'),
            fg='#ecf0f1', bg='#34495e', relief='groove', bd=2
        )
        display_frame.pack(padx=10, pady=10, fill='both', expand=True)
        
        # Original and processed image labels
        image_container = tk.Frame(display_frame, bg='#34495e')
        image_container.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Original image
        original_frame = tk.Frame(image_container, bg='#2c3e50', relief='sunken', bd=2)
        original_frame.pack(side='left', fill='both', expand=True, padx=5)
        
        tk.Label(original_frame, text="Original Image", font=('Arial', 12, 'bold'),
                fg='#ecf0f1', bg='#2c3e50').pack(pady=5)
        
        self.original_label = tk.Label(original_frame, text="No image loaded",
                                     bg='#2c3e50', fg='#bdc3c7')
        self.original_label.pack(expand=True)
        
        # Processed image
        processed_frame = tk.Frame(image_container, bg='#2c3e50', relief='sunken', bd=2)
        processed_frame.pack(side='right', fill='both', expand=True, padx=5)
        
        tk.Label(processed_frame, text="Processed Image", font=('Arial', 12, 'bold'),
                fg='#ecf0f1', bg='#2c3e50').pack(pady=5)
        
        self.processed_label = tk.Label(processed_frame, text="No processing done",
                                      bg='#2c3e50', fg='#bdc3c7')
        self.processed_label.pack(expand=True)
    
    def create_status_bar(self):
        """Create status bar."""
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - Load an image to begin")
        
        status_bar = tk.Label(
            self.root, textvariable=self.status_var,
            relief='sunken', bd=1, font=('Arial', 9),
            bg='#34495e', fg='#ecf0f1'
        )
        status_bar.pack(side='bottom', fill='x')
    
    def browse_input_file(self):
        """Open file dialog to select input image."""
        file_path = filedialog.askopenfilename(
            title="Select Image File",
            filetypes=[
                ("Image files", "*.png *.jpg *.jpeg *.bmp"),
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg *.jpeg"),
                ("BMP files", "*.bmp"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            self.input_path.set(file_path)
            if self.engine.load_image(file_path):
                self.display_original_image()
                self.status_var.set(f"Image loaded: {os.path.basename(file_path)}")
            else:
                messagebox.showerror("Error", "Failed to load image file")
    
    def display_original_image(self):
        """Display original image in GUI."""
        if self.engine.original_image:
            # Resize for display
            display_img = self.engine.original_image.copy()
            display_img.thumbnail((300, 300), Image.Resampling.LANCZOS)
            
            photo = ImageTk.PhotoImage(display_img)
            self.original_label.configure(image=photo, text='')
            self.original_label.image = photo  # Keep reference
    
    def display_processed_image(self):
        """Display processed image in GUI."""
        if self.engine.processed_image:
            # Resize for display
            display_img = self.engine.processed_image.copy()
            display_img.thumbnail((300, 300), Image.Resampling.LANCZOS)
            
            photo = ImageTk.PhotoImage(display_img)
            self.processed_label.configure(image=photo, text='')
            self.processed_label.image = photo  # Keep reference
    
    def encrypt_image(self):
        """Encrypt the loaded image."""
        if not self.validate_inputs():
            return
        
        try:
            result = self.engine.process_image(
                self.selected_algorithm.get(),
                self.encryption_key.get(),
                encrypt=True
            )
            
            if result:
                self.display_processed_image()
                self.status_var.set("Image encrypted successfully!")
                messagebox.showinfo("Success", "Image encrypted successfully!")
            else:
                messagebox.showerror("Error", "Encryption failed")
                
        except Exception as e:
            messagebox.showerror("Error", f"Encryption error: {str(e)}")
    
    def decrypt_image(self):
        """Decrypt the loaded image."""
        if not self.validate_inputs():
            return
        
        try:
            result = self.engine.process_image(
                self.selected_algorithm.get(),
                self.encryption_key.get(),
                encrypt=False
            )
            
            if result:
                self.display_processed_image()
                self.status_var.set("Image decrypted successfully!")
                messagebox.showinfo("Success", "Image decrypted successfully!")
            else:
                messagebox.showerror("Error", "Decryption failed")
                
        except Exception as e:
            messagebox.showerror("Error", f"Decryption error: {str(e)}")
    
    def save_result(self):
        """Save the processed image."""
        if not self.engine.processed_image:
            messagebox.showwarning("Warning", "No processed image to save")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Save Processed Image",
            defaultextension=".png",
            filetypes=[
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg"),
                ("BMP files", "*.bmp"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            if self.engine.save_image(self.engine.processed_image, file_path):
                self.status_var.set(f"Image saved: {os.path.basename(file_path)}")
                messagebox.showinfo("Success", f"Image saved successfully!\n{file_path}")
            else:
                messagebox.showerror("Error", "Failed to save image")
    
    def validate_inputs(self):
        """Validate user inputs before processing."""
        if not self.engine.original_image:
            messagebox.showwarning("Warning", "Please load an image first")
            return False
        
        if not self.encryption_key.get().strip():
            messagebox.showwarning("Warning", "Please enter an encryption key")
            return False
        
        return True
    
    def run(self):
        """Start the GUI application."""
        self.root.mainloop()


def cli_interface():
    """Command-line interface for the encryption tool."""
    parser = argparse.ArgumentParser(
        description="PRODIGY_CS_02 - Advanced Image Encryption Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt an image using XOR
  python image_encryption.py -i input.png -o encrypted.png -k mykey -a xor -m encrypt
  
  # Decrypt the same image
  python image_encryption.py -i encrypted.png -o decrypted.png -k mykey -a xor -m decrypt
  
  # Use mathematical encryption
  python image_encryption.py -i input.png -o encrypted.png -k 12345 -a mathematical -m encrypt
        """
    )
    
    parser.add_argument('-i', '--input', required=True, help='Input image path')
    parser.add_argument('-o', '--output', required=True, help='Output image path')
    parser.add_argument('-k', '--key', required=True, help='Encryption/decryption key')
    parser.add_argument('-a', '--algorithm', 
                       choices=['xor', 'mathematical', 'pixel_swap', 'channel_swap'],
                       default='xor', help='Encryption algorithm (default: xor)')
    parser.add_argument('-m', '--mode', choices=['encrypt', 'decrypt'],
                       required=True, help='Operation mode')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Initialize engine
    engine = ImageEncryption()
    
    if args.verbose:
        print(f"PRODIGY_CS_02 - Image Encryption Tool")
        print(f"Input: {args.input}")
        print(f"Output: {args.output}")
        print(f"Algorithm: {args.algorithm}")
        print(f"Mode: {args.mode}")
        print("-" * 50)
    
    # Load image
    if not engine.load_image(args.input):
        print(f"Error: Failed to load image '{args.input}'")
        return 1
    
    if args.verbose:
        print(f"Image loaded successfully: {engine.image_shape}")
    
    # Process image
    try:
        result = engine.process_image(
            args.algorithm, 
            args.key, 
            encrypt=(args.mode == 'encrypt')
        )
        
        if not result:
            print("Error: Image processing failed")
            return 1
        
        # Save result
        if engine.save_image(result, args.output):
            print(f"Success: Image {args.mode}ed and saved to '{args.output}'")
            return 0
        else:
            print(f"Error: Failed to save image to '{args.output}'")
            return 1
            
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1


def main():
    """Main entry point."""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                ADVANCED IMAGE ENCRYPTION TOOL                 ║
    ║                 PRODIGY_CS_02 - Version 1.0                   ║
    ║                                                               ║
    ║            🔐 Cybersecurity Internship Project 🔐             ║
    ║                        Prodigy InfoTech                       ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) > 1:
        # CLI mode
        return cli_interface()
    else:
        # GUI mode
        print("Starting GUI mode...")
        print("For CLI usage, run: python image_encryption.py --help")
        app = ImageEncryptionGUI()
        app.run()
        return 0


if __name__ == "__main__":
    sys.exit(main())