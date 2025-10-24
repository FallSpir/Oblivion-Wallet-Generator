import sys
import subprocess
import tkinter as tk
from tkinter import messagebox
import random
import string

def install_requirements():
    required_packages = ['eth-account', 'mnemonic', 'base58', 'ecdsa', 'PyNaCl', 'bip32utils']
    missing_packages = []
    
    for package in required_packages:
        try:
            if package == 'eth-account':
                __import__('eth_account')
            elif package == 'PyNaCl':
                __import__('nacl')
            elif package == 'bip32utils':
                __import__('bip32utils')
            else:
                __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        root = tk.Tk()
        root.withdraw()
        
        response = messagebox.askyesno(
            "Установка зависимостей",
            f"Необходимо установить библиотеки:\n{', '.join(missing_packages)}\n\nУстановить автоматически?"
        )
        
        if response:
            try:
                for package in missing_packages:
                    subprocess.check_call([
                        sys.executable, 
                        "-m", 
                        "pip", 
                        "install", 
                        package
                    ])
                messagebox.showinfo(
                    "Успех", 
                    "Зависимости успешно установлены!\nПрограмма сейчас запустится."
                )
                root.destroy()
                return True
            except Exception as e:
                messagebox.showerror(
                    "Ошибка",
                    f"Не удалось установить зависимости:\n{e}\n\nПопробуйте установить вручную:\npip install {' '.join(missing_packages)}"
                )
                root.destroy()
                return False
        else:
            messagebox.showwarning(
                "Отменено",
                f"Для работы программы необходимы библиотеки:\npip install {' '.join(missing_packages)}"
            )
            root.destroy()
            return False
    
    return True

if not install_requirements():
    sys.exit(1)

from tkinter import filedialog, ttk
from pathlib import Path
from eth_account import Account
from mnemonic import Mnemonic
import hashlib
import base58
import ecdsa
import secrets
from bip32utils import BIP32Key
import os

Account.enable_unaudited_hdwallet_features()

class WalletGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Oblivion Wallet Generator")
        self.root.geometry("650x750")
        self.root.resizable(False, False)
        
        self.bg_color = "#0a0e1a"
        self.card_color = "#1a1f35"
        self.accent_color = "#6c5ce7"
        self.accent_hover = "#5f4fd1"
        self.text_color = "#e0e0e0"
        self.text_secondary = "#8b92a8"
        self.success_color = "#00d9a3"
        self.border_color = "#2d3548"
        
        self.root.configure(bg=self.bg_color)

        desktop = Path.home() / "Desktop"
        if not desktop.exists():
            desktop = Path.home()
        
        random_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=3))
        self.default_path = str(desktop / f"wallets_{random_code}.txt")
        self.save_path = self.default_path
        self.custom_directory = None
        
        self._create_widgets()
        
    def _create_card(self, parent, **kwargs):
        frame = tk.Frame(
            parent,
            bg=self.card_color,
            relief=tk.FLAT,
            bd=0,
            **kwargs
        )
        return frame
        
    def _create_widgets(self):
        header_frame = tk.Frame(self.root, bg=self.bg_color)
        header_frame.pack(pady=(20, 15))
        
        title_canvas = tk.Canvas(
            header_frame,
            width=400,
            height=70,
            bg=self.bg_color,
            highlightthickness=0
        )
        title_canvas.pack()
        
        title_canvas.create_text(
            200, 22,
            text="OBLIVION",
            font=("Arial", 28, "bold"),
            fill=self.accent_color
        )
        
        title_canvas.create_text(
            200, 50,
            text="WALLET GENERATOR",
            font=("Arial", 10),
            fill=self.text_secondary
        )

        main_container = self._create_card(self.root)
        main_container.pack(pady=10, padx=30, fill=tk.BOTH, expand=True)

        inner_frame = tk.Frame(main_container, bg=self.card_color)
        inner_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

        type_label = tk.Label(
            inner_frame,
            text="Blockchain Network",
            font=("Arial", 10, "bold"),
            bg=self.card_color,
            fg=self.text_secondary
        )
        type_label.pack(anchor=tk.W, pady=(0, 6))
        
        type_frame = tk.Frame(inner_frame, bg=self.card_color)
        type_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.wallet_type = tk.StringVar(value="EVM")
        self.wallet_type.trace('w', self._update_radio_colors)
        
        self.type_radios = []

        crypto_symbols = [
            ("EVM", "Ξ"),      
            ("Solana", "◎"),  
            ("Bitcoin", "₿")  
        ]
        
        for idx, (wallet_type, symbol) in enumerate(crypto_symbols):
            btn_frame = tk.Frame(type_frame, bg=self.border_color, bd=1)
            btn_frame.pack(side=tk.LEFT, padx=(0, 10) if idx < 2 else 0, fill=tk.BOTH, expand=True)
            
            rb = tk.Radiobutton(
                btn_frame,
                text=f"{symbol} {wallet_type}",
                variable=self.wallet_type,
                value=wallet_type,
                font=("Arial", 11, "bold"),
                bg=self.card_color,
                fg=self.text_color,
                selectcolor="#1a1f35",
                activebackground=self.card_color,
                activeforeground=self.text_color,
                cursor="hand2",
                relief=tk.FLAT,
                bd=0,
                pady=12,
                indicatoron=True
            )
            rb.pack(fill=tk.BOTH, expand=True)
            self.type_radios.append((rb, wallet_type))

        format_label = tk.Label(
            inner_frame,
            text="Export Format",
            font=("Arial", 10, "bold"),
            bg=self.card_color,
            fg=self.text_secondary
        )
        format_label.pack(anchor=tk.W, pady=(5, 6))
        
        format_frame = tk.Frame(inner_frame, bg=self.card_color)
        format_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.file_format = tk.StringVar(value="detailed")
        self.file_format.trace('w', self._update_format_radio_colors)
        
        self.format_radios = []
        
        for idx, (format_type, icon) in enumerate([("detailed", "📋"), ("simple", "🔑")]):
            btn_frame = tk.Frame(format_frame, bg=self.border_color, bd=1)
            btn_frame.pack(side=tk.LEFT, padx=(0, 10) if idx == 0 else 0, fill=tk.BOTH, expand=True)
            
            text = "Detailed Info" if format_type == "detailed" else "Keys Only"
            
            rb = tk.Radiobutton(
                btn_frame,
                text=f"{icon} {text}",
                variable=self.file_format,
                value=format_type,
                font=("Arial", 11),
                bg=self.card_color,
                fg=self.text_color,
                selectcolor="#1a1f35",
                activebackground=self.card_color,
                activeforeground=self.text_color,
                cursor="hand2",
                relief=tk.FLAT,
                bd=0,
                pady=12,
                indicatoron=True
            )
            rb.pack(fill=tk.BOTH, expand=True)
            self.format_radios.append((rb, format_type))

        count_label = tk.Label(
            inner_frame,
            text="Wallet Quantity",
            font=("Arial", 10, "bold"),
            bg=self.card_color,
            fg=self.text_secondary
        )
        count_label.pack(anchor=tk.W, pady=(5, 6))

        quick_frame = tk.Frame(inner_frame, bg=self.card_color)
        quick_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.count_var = tk.IntVar(value=1)
        
        quick_values = [1, 5, 10, 25, 50, 100, 200, 500, 1000]
        for value in quick_values:
            btn = tk.Button(
                quick_frame,
                text=str(value),
                font=("Arial", 9),
                bg=self.border_color,
                fg=self.text_color,
                activebackground=self.accent_color,
                activeforeground="white",
                cursor="hand2",
                relief=tk.FLAT,
                bd=0,
                height=2,
                command=lambda v=value: self.count_var.set(v)
            )
            btn.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 4) if value != 1000 else 0)
        
        manual_frame = tk.Frame(inner_frame, bg=self.card_color)
        manual_frame.pack(fill=tk.X, pady=(0, 15))
        
        entry_container = tk.Frame(manual_frame, bg=self.border_color, bd=1)
        entry_container.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        self.count_entry = tk.Entry(
            entry_container,
            textvariable=self.count_var,
            font=("Arial", 13),
            bg=self.card_color,
            fg=self.text_color,
            insertbackground=self.text_color,
            relief=tk.FLAT,
            bd=0,
            justify=tk.CENTER
        )
        self.count_entry.pack(fill=tk.BOTH, padx=10, pady=10)
        
        spinbox_frame = tk.Frame(manual_frame, bg=self.card_color)
        spinbox_frame.pack(side=tk.LEFT)
        
        btn_up = tk.Button(
            spinbox_frame,
            text="▲",
            font=("Arial", 9),
            bg=self.border_color,
            fg=self.text_color,
            activebackground=self.accent_color,
            activeforeground="white",
            cursor="hand2",
            relief=tk.FLAT,
            bd=0,
            width=3,
            command=self._increment_count
        )
        btn_up.pack(pady=(0, 4))
        
        btn_down = tk.Button(
            spinbox_frame,
            text="▼",
            font=("Arial", 9),
            bg=self.border_color,
            fg=self.text_color,
            activebackground=self.accent_color,
            activeforeground="white",
            cursor="hand2",
            relief=tk.FLAT,
            bd=0,
            width=3,
            command=self._decrement_count
        )
        btn_down.pack()

        path_label = tk.Label(
            inner_frame,
            text="Save Location",
            font=("Arial", 10, "bold"),
            bg=self.card_color,
            fg=self.text_secondary
        )
        path_label.pack(anchor=tk.W, pady=(5, 6))
        
        path_container = tk.Frame(inner_frame, bg=self.border_color, bd=1)
        path_container.pack(fill=tk.X, pady=(0, 15))
        
        path_inner = tk.Frame(path_container, bg=self.card_color)
        path_inner.pack(fill=tk.X, padx=1, pady=1)
        
        self.path_label = tk.Label(
            path_inner,
            text=self.default_path,
            font=("Arial", 9),
            bg=self.card_color,
            fg=self.text_secondary,
            anchor=tk.W
        )
        self.path_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=12, pady=12)
        
        self.browse_btn = tk.Button(
            path_inner,
            text="📁",
            font=("Arial", 14),
            bg=self.card_color,
            fg=self.accent_color,
            activebackground=self.card_color,
            activeforeground=self.accent_hover,
            cursor="hand2",
            relief=tk.FLAT,
            bd=0,
            command=self._browse_path
        )
        self.browse_btn.pack(side=tk.LEFT, padx=(0, 8))

        style = ttk.Style()
        style.theme_use('clam')
        style.configure(
            "Custom.Horizontal.TProgressbar",
            troughcolor=self.border_color,
            background=self.accent_color,
            bordercolor=self.card_color,
            lightcolor=self.accent_color,
            darkcolor=self.accent_color
        )
        
        self.progress = ttk.Progressbar(
            inner_frame,
            mode='determinate',
            length=500,
            style="Custom.Horizontal.TProgressbar"
        )
        self.progress.pack(pady=(0, 15), fill=tk.X)

        self.generate_btn = tk.Button(
            inner_frame,
            text="⚡ GENERATE WALLETS",
            font=("Arial", 13, "bold"),
            bg=self.accent_color,
            fg="white",
            activebackground=self.accent_hover,
            activeforeground="white",
            cursor="hand2",
            command=self._generate_wallets,
            relief=tk.FLAT,
            bd=0,
            pady=15
        )
        self.generate_btn.pack(fill=tk.X)

        self.status_label = tk.Label(
            inner_frame,
            text="Ready to generate",
            font=("Arial", 9),
            bg=self.card_color,
            fg=self.text_secondary
        )
        self.status_label.pack(pady=(12, 0))
    
    def _update_radio_colors(self, *args):
        selected = self.wallet_type.get()
        for rb, value in self.type_radios:
            if value == selected:
                rb.config(selectcolor=self.accent_color)
            else:
                rb.config(selectcolor="#0a0e1a")
    
    def _update_format_radio_colors(self, *args):
        selected = self.file_format.get()
        for rb, value in self.format_radios:
            if value == selected:
                rb.config(selectcolor=self.accent_color)
            else:
                rb.config(selectcolor="#0a0e1a")
    
    def _increment_count(self):
        current = self.count_var.get()
        if current < 1000:
            self.count_var.set(current + 1)
    
    def _decrement_count(self):
        current = self.count_var.get()
        if current > 1:
            self.count_var.set(current - 1)
        
    def _browse_path(self):
        random_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=3))
        wallet_type = self.wallet_type.get().lower()
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"oblivion_wallets_{wallet_type}_{random_code}.txt"
        )
        if path:
            self.save_path = path
            self.custom_directory = str(Path(path).parent)
            self.path_label.config(text=path)
    
    def _generate_mnemonic(self):
        try:
            mnemo = Mnemonic("english")
            return mnemo.generate(strength=128)
        except Exception as e:
            raise Exception(f"Mnemonic generation failed: {str(e)}")
    
    def _generate_evm_wallet(self):
        try:
            private_key = secrets.token_bytes(32)
            account = Account.from_key(private_key)
            
            mnemo = Mnemonic("english")
            mnemonic_phrase = mnemo.to_mnemonic(private_key)
            
            return {
                'address': account.address,
                'private_key': account.key.hex(),
                'mnemonic': mnemonic_phrase
            }
        except Exception as e:
            raise Exception(f"EVM generation error: {str(e)}")
    
    def _generate_solana_wallet(self):
        from nacl.signing import SigningKey
        
        try:
            private_key = secrets.token_bytes(32)
            signing_key = SigningKey(private_key)
            verify_key = signing_key.verify_key
            
            public_key = base58.b58encode(bytes(verify_key)).decode('ascii')
            private_key_bytes = bytes(signing_key) + bytes(verify_key)
            private_key_str = base58.b58encode(private_key_bytes).decode('ascii')
            
            mnemo = Mnemonic("english")
            mnemonic_phrase = mnemo.to_mnemonic(private_key)
            
            return {
                'address': public_key,
                'private_key': private_key_str,
                'mnemonic': mnemonic_phrase
            }
        except Exception as e:
            raise Exception(f"Solana generation error: {str(e)}")
    
    def _generate_bitcoin_wallet(self):
        try:
            private_key = secrets.token_bytes(32)
            
            sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
            vk = sk.get_verifying_key()
            
            public_key = b'\x04' + vk.to_string()
            sha256_hash = hashlib.sha256(public_key).digest()
            ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
            
            versioned_hash = b'\x00' + ripemd160_hash
            checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]
            address = base58.b58encode(versioned_hash + checksum).decode('ascii')
            
            extended_key = b'\x80' + private_key
            checksum_wif = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
            wif_private_key = base58.b58encode(extended_key + checksum_wif).decode('ascii')
            
            mnemo = Mnemonic("english")
            mnemonic_phrase = mnemo.to_mnemonic(private_key)
            
            return {
                'address': address,
                'private_key': wif_private_key,
                'private_key_hex': private_key.hex(),
                'mnemonic': mnemonic_phrase
            }
        except Exception as e:
            raise Exception(f"Bitcoin generation error: {str(e)}")
        
    def _generate_wallets(self):
        try:
            count = self.count_var.get()
            if count < 1 or count > 1000:
                raise ValueError("Количество должно быть от 1 до 1000")
        except (ValueError, tk.TclError) as e:
            messagebox.showerror("Error", "Enter valid quantity (1-1000)")
            return
        
        wallet_type = self.wallet_type.get()
        
        self.generate_btn.config(state=tk.DISABLED)
        self.progress['value'] = 0
        self.status_label.config(text=f"Generating {wallet_type} wallets...", fg=self.text_secondary)
        self.root.update()
        
        try:
            wallets = []
            
            for i in range(count):
                try:
                    if wallet_type == "EVM":
                        wallet = self._generate_evm_wallet()
                    elif wallet_type == "Solana":
                        wallet = self._generate_solana_wallet()
                    elif wallet_type == "Bitcoin":
                        wallet = self._generate_bitcoin_wallet()
                    
                    wallets.append(wallet)
                        
                except Exception as e:
                    error_msg = f"Error generating wallet #{i+1}:\n{str(e)}"
                    messagebox.showerror("Error", error_msg)
                    break
                
                self.progress['value'] = ((i + 1) / count) * 100
                self.root.update()
           
            if wallets:
                file_format = self.file_format.get()
                self._save_to_file(wallets, wallet_type, file_format)
                
                self.status_label.config(
                    text=f"✓ Successfully generated {len(wallets)} {wallet_type} wallets",
                    fg=self.success_color
                )
                messagebox.showinfo(
                    "Success",
                    f"Generated {len(wallets)} {wallet_type} wallets!\nFile saved: {self.save_path}"
                )
                
                self._update_filename()
            
        except Exception as e:
            self.status_label.config(text="✗ Generation error", fg="#ff6b6b")
            messagebox.showerror("Error", f"Failed to create wallets:\n{e}")
        
        finally:
            self.generate_btn.config(state=tk.NORMAL)
            self.progress['value'] = 0
    
    def _save_to_file(self, wallets, wallet_type, file_format):
        with open(self.save_path, 'w', encoding='utf-8') as f:
            if file_format == "simple":
                for wallet in wallets:
                    f.write(f"{wallet['private_key']}\n")
            else:
                f.write("═" * 80 + "\n")
                f.write(f"  OBLIVION WALLET GENERATOR - {wallet_type.upper()}\n")
                f.write("═" * 80 + "\n\n")
                
                for idx, wallet in enumerate(wallets, 1):
                    f.write(f"{'─' * 80}\n")
                    f.write(f"  WALLET #{idx}\n")
                    f.write(f"{'─' * 80}\n\n")
                    f.write(f"Address:\n{wallet['address']}\n\n")
                    
                    if wallet_type == "Bitcoin" and 'private_key_hex' in wallet:
                        f.write(f"Private Key (WIF):\n{wallet['private_key']}\n\n")
                        f.write(f"Private Key (HEX):\n{wallet['private_key_hex']}\n\n")
                    else:
                        f.write(f"Private Key:\n{wallet['private_key']}\n\n")
                    
                    f.write(f"Seed Phrase (12 words):\n{wallet['mnemonic']}\n\n")
                
                f.write("═" * 80 + "\n")
                f.write(f"Total wallets created: {len(wallets)}\n")
                f.write(f"Network: {wallet_type}\n")
                f.write("═" * 80 + "\n")
                f.write("\n⚠️  IMPORTANT: Keep this file secure!\n")
                f.write("Never share your private keys or seed phrases!\n")
    
    def _update_filename(self):
        if self.custom_directory:
            save_directory = Path(self.custom_directory)
        else:
            save_directory = Path.home() / "Desktop"
            if not save_directory.exists():
                save_directory = Path.home()
        
        random_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=3))
        wallet_type = self.wallet_type.get().lower()
        self.save_path = str(save_directory / f"oblivion_wallets_{wallet_type}_{random_code}.txt")
        self.path_label.config(text=self.save_path)

if __name__ == "__main__":
    root = tk.Tk()
    app = WalletGeneratorApp(root)
    root.mainloop()