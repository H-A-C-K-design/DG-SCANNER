#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DG-SEC Scanner - Advanced Security Framework
Author: Durgesh Gaikwad
Tool Name: DG-HACKER
Version: 1.0.0
License: MIT
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import customtkinter as ctk
from PIL import Image, ImageTk
import threading
import queue
import time
import os
import sys
import json
import hashlib
from datetime import datetime
import subprocess
from pathlib import Path

# Import scanning modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from modules.file_scanner import FileScanner
from modules.url_scanner import URLScanner
from modules.ip_scanner import IPScanner
from modules.apk_scanner import APKScanner
from modules.doc_scanner import DocScanner

# Configure CustomTkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class DGSecurityScanner:
    """
    DG-HACKER Security Scanner Main Application
    Author: Durgesh Gaikwad
    """
    
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title(" DG-HACKER Security Scanner | by Durgesh Gaikwad")
        self.root.geometry("1400x900")
        
        # Set icon
        try:
            self.root.iconbitmap('assets/icon.ico')
        except:
            pass
        
        # Color Scheme - Hacker Theme
        self.colors = {
            'bg': '#0a0a0a',
            'fg': '#00ff00',
            'accent': '#ff0000',
            'secondary': '#1a1a1a',
            'warning': '#ffff00',
            'matrix': '#00cc00',
            'terminal': '#0c0c0c',
            'highlight': '#ff4500',
            'button_hover': '#2a2a2a',
            'text': '#00ff00',
            'dark_green': '#004400',
            'neon_red': '#ff073a',
            'neon_blue': '#00ffff'
        }
        
        # Initialize scanners
        self.file_scanner = FileScanner()
        self.url_scanner = URLScanner()
        self.ip_scanner = IPScanner()
        self.apk_scanner = APKScanner()
        self.doc_scanner = DocScanner()
        
        # Threading
        self.scan_queue = queue.Queue()
        self.is_scanning = False
        
        # Setup GUI
        self.setup_gui()
        self.setup_banner()
        self.animate_border()
        
        # Start queue processor
        self.process_queue()
        
    def setup_gui(self):
        """Setup the main GUI with hacker theme"""
        
        # Configure grid
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # Top Frame - Banner
        self.top_frame = ctk.CTkFrame(
            self.root, 
            fg_color=self.colors['bg'],
            border_color=self.colors['fg'],
            border_width=2
        )
        self.top_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        
        # Main Content Frame
        self.main_frame = ctk.CTkFrame(
            self.root,
            fg_color=self.colors['terminal']
        )
        self.main_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        
        # Configure main frame grid
        self.main_frame.grid_columnconfigure(1, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)
        
        # Left Panel - Controls
        self.setup_left_panel()
        
        # Right Panel - Output
        self.setup_right_panel()
        
        # Status Bar
        self.setup_status_bar()
        
    def setup_banner(self):
        """Setup the DG-HACKER banner"""
        
        banner_text = """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║                                                                          ║
    ║    ██████╗   ██████╗       ██╗  ██╗  █████╗   ██████╗ ██╗  ██╗ ███████╗ ██████╗ 
    ║    ██╔══██╗ ██╔════╝       ██║  ██║ ██╔══██╗ ██╔════╝ ██║ ██╔╝ ██╔════╝ ██╔══██╗
    ║    ██║  ██║ ██║  ███╗█████╗███████║ ███████║ ██║      █████╔╝  █████╗   ██████╔╝
    ║    ██║  ██║ ██║   ██║╚════╝██╔══██║ ██╔══██║ ██║      ██╔═██╗  ██╔══╝   ██╔══██╗
    ║    ██████╔╝ ╚██████╔╝      ██║  ██║ ██║  ██║ ╚██████╗ ██║  ██╗ ███████╗ ██║  ██║
    ║    ╚═════╝   ╚═════╝       ╚═╝  ╚═╝ ╚═╝  ╚═╝  ╚═════╝ ╚═╝  ╚═╝ ╚══════╝ ╚═╝  ╚═╝
    ║                                                                          ║
    ║               ADVANCED SECURITY SCANNER FRAMEWORK                       ║
    ║                    Author: Durgesh Gaikwad                              ║
    ╚══════════════════════════════════════════════════════════════════════════╝
        """
        
        self.banner_label = ctk.CTkLabel(
            self.top_frame,
            text=banner_text,
            font=("Courier", 8, "bold"),
            text_color=self.colors['matrix'],
            fg_color="transparent"
        )
        self.banner_label.pack(pady=5)
        
    def animate_border(self):
        """Animate the banner border"""
        colors = [self.colors['matrix'], self.colors['accent'], self.colors['neon_blue']]
        current_color = self.top_frame.cget("border_color")
        next_color = colors[(colors.index(current_color) + 1) % len(colors)] if current_color in colors else colors[0]
        self.top_frame.configure(border_color=next_color)
        self.root.after(1000, self.animate_border)
        
    def setup_left_panel(self):
        """Setup the control panel"""
        
        self.left_panel = ctk.CTkFrame(
            self.main_frame,
            fg_color=self.colors['secondary'],
            border_color=self.colors['fg'],
            border_width=1
        )
        self.left_panel.grid(row=0, column=0, sticky="ns", padx=5, pady=5)
        
        # Title
        ctk.CTkLabel(
            self.left_panel,
            text=" SCAN OPTIONS ",
            font=("Courier", 16, "bold"),
            text_color=self.colors['matrix']
        ).pack(pady=10)
        
        # Scan Type Buttons
        scan_types = [
            ("🔍 Scan File", self.scan_file, self.colors['matrix']),
            ("🌐 Scan URL", self.scan_url, self.colors['neon_blue']),
            ("📍 Scan IP", self.scan_ip, self.colors['warning']),
            ("📱 Scan APK", self.scan_apk, self.colors['neon_red']),
            ("📄 Scan Document", self.scan_document, self.colors['highlight'])
        ]
        
        self.scan_buttons = []
        for text, command, color in scan_types:
            btn = ctk.CTkButton(
                self.left_panel,
                text=text,
                command=command,
                font=("Courier", 12, "bold"),
                fg_color=self.colors['dark_green'],
                hover_color=self.colors['button_hover'],
                border_color=color,
                border_width=2,
                height=40,
                width=200
            )
            btn.pack(pady=10, padx=20)
            self.scan_buttons.append(btn)
        
        # Separator
        ctk.CTkLabel(
            self.left_panel,
            text="─" * 30,
            text_color=self.colors['fg']
        ).pack(pady=10)
        
        # Quick Actions
        ctk.CTkLabel(
            self.left_panel,
            text=" QUICK ACTIONS ",
            font=("Courier", 14, "bold"),
            text_color=self.colors['matrix']
        ).pack(pady=5)
        
        quick_actions = [
            ("📊 View Report", self.view_report),
            ("🗑️ Clear Output", self.clear_output),
            ("💾 Save Results", self.save_results),
            ("🛡️ Open Quarantine", self.open_quarantine),
            ("⚙️ Settings", self.open_settings)
        ]
        
        for text, command in quick_actions:
            btn = ctk.CTkButton(
                self.left_panel,
                text=text,
                command=command,
                font=("Courier", 10),
                fg_color="transparent",
                hover_color=self.colors['button_hover'],
                border_color=self.colors['fg'],
                border_width=1,
                height=30,
                width=180
            )
            btn.pack(pady=5, padx=20)
        
        # Progress Bar
        self.progress_var = ctk.DoubleVar()
        self.progress_bar = ctk.CTkProgressBar(
            self.left_panel,
            variable=self.progress_var,
            mode="indeterminate",
            progress_color=self.colors['matrix'],
            height=15,
            width=200
        )
        self.progress_bar.pack(pady=10)
        self.progress_bar.set(0)
        
        # Status Label
        self.status_label = ctk.CTkLabel(
            self.left_panel,
            text="[ READY ]",
            font=("Courier", 10, "bold"),
            text_color=self.colors['matrix']
        )
        self.status_label.pack(pady=5)
        
    def setup_right_panel(self):
        """Setup the output panel"""
        
        self.right_panel = ctk.CTkFrame(
            self.main_frame,
            fg_color=self.colors['terminal']
        )
        self.right_panel.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        
        # Configure right panel grid
        self.right_panel.grid_rowconfigure(0, weight=1)
        self.right_panel.grid_columnconfigure(0, weight=1)
        
        # Output Text with Terminal Look
        self.output_text = scrolledtext.ScrolledText(
            self.right_panel,
            wrap=tk.WORD,
            bg=self.colors['terminal'],
            fg=self.colors['matrix'],
            insertbackground=self.colors['matrix'],
            font=("Courier", 10),
            relief=tk.FLAT,
            borderwidth=0
        )
        self.output_text.grid(row=0, column=0, sticky="nsew")
        
        # Configure tags for colored output
        self.output_text.tag_configure("success", foreground="#00ff00")
        self.output_text.tag_configure("error", foreground="#ff0000")
        self.output_text.tag_configure("warning", foreground="#ffff00")
        self.output_text.tag_configure("info", foreground="#00ffff")
        self.output_text.tag_configure("header", foreground="#ff4500", font=("Courier", 12, "bold"))
        
        # Welcome message
        self.print_welcome()
        
    def print_welcome(self):
        """Print welcome message"""
        welcome_msg = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    DG-HACKER SECURITY SCANNER                               ║
║                    Author: Durgesh Gaikwad                                   ║
║                    Version: 1.0.0                                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

[INFO] System initialized and ready for scanning...
[INFO] All modules loaded successfully
[INFO] Select a scan option from the left panel to begin

[SECURITY FRAMEWORK STATUS]
├── File Scanner      : ACTIVE
├── URL Scanner       : ACTIVE
├── IP Scanner        : ACTIVE
├── APK Scanner       : ACTIVE
└── Document Scanner  : ACTIVE

[READY] Awaiting user input...
"""
        self.output_text.insert(tk.END, welcome_msg)
        self.output_text.see(tk.END)
        
    def setup_status_bar(self):
        """Setup status bar"""
        self.status_frame = ctk.CTkFrame(
            self.root,
            fg_color=self.colors['secondary'],
            border_color=self.colors['fg'],
            border_width=1
        )
        self.status_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=5)
        
        # System info
        self.cpu_label = ctk.CTkLabel(
            self.status_frame,
            text="CPU: 0%",
            font=("Courier", 8),
            text_color=self.colors['matrix']
        )
        self.cpu_label.pack(side=tk.LEFT, padx=10)
        
        self.mem_label = ctk.CTkLabel(
            self.status_frame,
            text="MEM: 0%",
            font=("Courier", 8),
            text_color=self.colors['matrix']
        )
        self.mem_label.pack(side=tk.LEFT, padx=10)
        
        # Author credit
        ctk.CTkLabel(
            self.status_frame,
            text="Created by Durgesh Gaikwad | DG-HACKER © 2024",
            font=("Courier", 8, "bold"),
            text_color=self.colors['accent']
        ).pack(side=tk.RIGHT, padx=10)
        
        # Time
        self.time_label = ctk.CTkLabel(
            self.status_frame,
            text="",
            font=("Courier", 8),
            text_color=self.colors['matrix']
        )
        self.time_label.pack(side=tk.RIGHT, padx=10)
        self.update_time()
        
    def update_time(self):
        """Update status bar time"""
        current_time = datetime.now().strftime("%H:%M:%S")
        self.time_label.configure(text=current_time)
        self.root.after(1000, self.update_time)
        
    def scan_file(self):
        """Handle file scanning"""
        file_path = filedialog.askopenfilename(
            title="Select File to Scan",
            filetypes=[
                ("All Files", "*.*"),
                ("Executable Files", "*.exe;*.dll;*.bin"),
                ("Script Files", "*.py;*.js;*.sh"),
                ("Archive Files", "*.zip;*.rar;*.7z")
            ]
        )
        
        if file_path:
            self.clear_output()
            self.print_output(f"[+] Starting file scan: {file_path}\n", "info")
            self.status_label.configure(text="[ SCANNING FILE ]")
            self.progress_bar.start()
            
            # Start scan in thread
            scan_thread = threading.Thread(
                target=self._scan_file_thread,
                args=(file_path,)
            )
            scan_thread.daemon = True
            scan_thread.start()
            
    def _scan_file_thread(self, file_path):
        """Thread function for file scanning"""
        try:
            results = self.file_scanner.scan(file_path)
            self.scan_queue.put(("file", results, file_path))
        except Exception as e:
            self.scan_queue.put(("error", str(e), file_path))
            
    def scan_url(self):
        """Handle URL scanning"""
        dialog = ctk.CTkInputDialog(
            text="Enter URL to scan:",
            title="URL Scanner"
        )
        url = dialog.get_input()
        
        if url:
            self.clear_output()
            self.print_output(f"[+] Starting URL scan: {url}\n", "info")
            self.status_label.configure(text="[ SCANNING URL ]")
            self.progress_bar.start()
            
            scan_thread = threading.Thread(
                target=self._scan_url_thread,
                args=(url,)
            )
            scan_thread.daemon = True
            scan_thread.start()
            
    def _scan_url_thread(self, url):
        """Thread function for URL scanning"""
        try:
            results = self.url_scanner.scan(url)
            self.scan_queue.put(("url", results, url))
        except Exception as e:
            self.scan_queue.put(("error", str(e), url))
            
    def scan_ip(self):
        """Handle IP scanning"""
        dialog = ctk.CTkInputDialog(
            text="Enter IP address to scan:",
            title="IP Scanner"
        )
        ip = dialog.get_input()
        
        if ip:
            self.clear_output()
            self.print_output(f"[+] Starting IP scan: {ip}\n", "info")
            self.status_label.configure(text="[ SCANNING IP ]")
            self.progress_bar.start()
            
            scan_thread = threading.Thread(
                target=self._scan_ip_thread,
                args=(ip,)
            )
            scan_thread.daemon = True
            scan_thread.start()
            
    def _scan_ip_thread(self, ip):
        """Thread function for IP scanning"""
        try:
            results = self.ip_scanner.scan(ip)
            self.scan_queue.put(("ip", results, ip))
        except Exception as e:
            self.scan_queue.put(("error", str(e), ip))
            
    def scan_apk(self):
        """Handle APK scanning"""
        file_path = filedialog.askopenfilename(
            title="Select APK to Scan",
            filetypes=[("APK Files", "*.apk")]
        )
        
        if file_path:
            self.clear_output()
            self.print_output(f"[+] Starting APK scan: {file_path}\n", "info")
            self.status_label.configure(text="[ SCANNING APK ]")
            self.progress_bar.start()
            
            scan_thread = threading.Thread(
                target=self._scan_apk_thread,
                args=(file_path,)
            )
            scan_thread.daemon = True
            scan_thread.start()
            
    def _scan_apk_thread(self, file_path):
        """Thread function for APK scanning"""
        try:
            results = self.apk_scanner.scan(file_path)
            self.scan_queue.put(("apk", results, file_path))
        except Exception as e:
            self.scan_queue.put(("error", str(e), file_path))
            
    def scan_document(self):
        """Handle document scanning"""
        file_path = filedialog.askopenfilename(
            title="Select Document to Scan",
            filetypes=[
                ("Document Files", "*.doc;*.docx;*.pdf;*.xls;*.xlsx"),
                ("All Files", "*.*")
            ]
        )
        
        if file_path:
            self.clear_output()
            self.print_output(f"[+] Starting document scan: {file_path}\n", "info")
            self.status_label.configure(text="[ SCANNING DOCUMENT ]")
            self.progress_bar.start()
            
            scan_thread = threading.Thread(
                target=self._scan_doc_thread,
                args=(file_path,)
            )
            scan_thread.daemon = True
            scan_thread.start()
            
    def _scan_doc_thread(self, file_path):
        """Thread function for document scanning"""
        try:
            results = self.doc_scanner.scan(file_path)
            self.scan_queue.put(("doc", results, file_path))
        except Exception as e:
            self.scan_queue.put(("error", str(e), file_path))
            
    def process_queue(self):
        """Process scan results from queue"""
        try:
            while not self.scan_queue.empty():
                scan_type, results, target = self.scan_queue.get_nowait()
                
                if scan_type == "error":
                    self.print_output(f"\n[ERROR] {results}\n", "error")
                else:
                    self.display_results(scan_type, results, target)
                
                self.progress_bar.stop()
                self.status_label.configure(text="[ READY ]")
                
        except queue.Empty:
            pass
        
        finally:
            self.root.after(100, self.process_queue)
            
    def display_results(self, scan_type, results, target):
        """Display scan results"""
        self.print_output(f"\n{'='*70}", "info")
        self.print_output(f"SCAN RESULTS - {scan_type.upper()}", "header")
        self.print_output(f"{'='*70}", "info")
        self.print_output(f"Target: {target}", "info")
        self.print_output(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "info")
        self.print_output(f"{'='*70}\n", "info")
        
        if isinstance(results, dict):
            for key, value in results.items():
                if isinstance(value, dict):
                    self.print_output(f"\n[{key}]", "header")
                    for k, v in value.items():
                        if "malware" in k.lower() or "threat" in k.lower() or "risk" in k.lower():
                            color = "error" if v else "success"
                        else:
                            color = "info"
                        self.print_output(f"  {k}: {v}", color)
                else:
                    self.print_output(f"{key}: {value}", "info")
                    
    def print_output(self, message, tag=None):
        """Print to output with optional tag"""
        self.output_text.insert(tk.END, message + "\n", tag)
        self.output_text.see(tk.END)
        self.root.update_idletasks()
        
    def clear_output(self):
        """Clear output text"""
        self.output_text.delete(1.0, tk.END)
        
    def view_report(self):
        """View latest scan report"""
        messagebox.showinfo("Reports", "Report viewer opened in browser")
        
    def save_results(self):
        """Save scan results"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[
                ("JSON Files", "*.json"),
                ("HTML Files", "*.html"),
                ("Text Files", "*.txt")
            ]
        )
        if file_path:
            content = self.output_text.get(1.0, tk.END)
            with open(file_path, 'w') as f:
                f.write(content)
            self.print_output(f"\n[+] Results saved to: {file_path}\n", "success")
            
    def open_quarantine(self):
        """Open quarantine directory"""
        quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
        os.makedirs(quarantine_dir, exist_ok=True)
        subprocess.run(['xdg-open', quarantine_dir])
        
    def open_settings(self):
        """Open settings dialog"""
        messagebox.showinfo("Settings", "Settings panel coming soon!")
        
    def run(self):
        """Run the main application"""
        self.root.mainloop()
        
    def __del__(self):
        """Cleanup"""
        pass


def main():
    """Main entry point"""
    app = DGSecurityScanner()
    app.run()

if __name__ == "__main__":
    main()