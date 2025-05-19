#!/usr/bin/python3
import hashlib
import os
import sys
import random
import string
import re
import time
import threading
from datetime import datetime
from getpass import getpass
import tkinter as tk
from tkinter import ttk, messagebox, font
from tkinter import PhotoImage
import base64
from io import BytesIO
from typing import List, Dict, Tuple, Optional, Union, Any
import math
import pyperclip
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image, ImageTk, ImageDraw, ImageFilter, ImageOps, ImageFont, ImageColor

# ============================================================================
# PASSWORD MANAGER CORE
# ============================================================================

class PasswordManager:
    """Main password manager class"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DarkLock - Secure Password Manager")
        self.root.geometry("900x700")
        
        self.path_to_database = None
        self.db_key_hash = None
        self.ciphertext = None
        self.decryption_key = None
        self.content = ""
        self.records_count = 0
        
        self.create_login_screen()
    
    def pad_db_key(self, password):
        """Pad key to multiple of 16 bytes"""
        if len(password) % 16 == 0:
            return password
        return password + ("0" * (16 - (len(password) % 16)))
    
    def check_database(self):
        """Check or create database"""
        if os.path.exists("passwords.db"):
            return "passwords.db"
        db_handle = open("passwords.db", "wb")
        default_pass = hashlib.sha256(self.pad_db_key("password123").encode()).hexdigest()
        db_handle.write(default_pass.encode())
        db_handle.close()
        messagebox.showinfo("Info", "New database created. Default password: password123")
        return "passwords.db"
    
    def decrypt_db(self):
        """Decrypt database"""
        if len(self.ciphertext.strip()) != 0:
            aes_instance = AES.new(self.decryption_key.encode(), AES.MODE_CBC, self.decryption_key[:16].encode())
            self.content = unpad(aes_instance.decrypt(self.ciphertext), AES.block_size).decode("UTF-8")
            self.records_count = len(self.content.split("|"))
        else:
            self.content = ""
            self.records_count = 0
    
    def save_db(self):
        """Save database with encryption"""
        db_handle = open(self.path_to_database, "wb")
        ciphertext = b""
        if self.records_count != 0:
            aes_instance = AES.new(self.decryption_key.encode(), AES.MODE_CBC, self.decryption_key[:16].encode())
            ciphertext = aes_instance.encrypt(pad(self.content.encode(), AES.block_size))
        db_handle.seek(0)
        db_handle.write(self.db_key_hash.encode() + ciphertext)
        db_handle.close()
    
    def is_strong_password(self, password):
        """Check password strength"""
        if len(password) < 12:
            return False, "Password must be at least 12 characters"
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r"[0-9]", password):
            return False, "Password must contain at least one digit"
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain at least one special character"
        return True, ""
    
    def create_login_screen(self):
        """Create a simple login screen with a custom background image and password input"""
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Load background image
        try:
            bg_image = Image.open("darklock.png")  # Replace with your image path
            bg_image = bg_image.resize((900, 700), Image.Resampling.LANCZOS)  # Resize to window size
            self.bg_photo = ImageTk.PhotoImage(bg_image)
            bg_label = tk.Label(self.root, image=self.bg_photo)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        except Exception as e:
            print(f"Failed to load background image: {e}")
            self.root.configure(bg="#0D1117")  # Fallback to dark background if image fails
        
        # Simple frame for login box
        frame = tk.Frame(self.root, bg="#161B22", padx=20, pady=20)
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Password entry
        password_entry = tk.Entry(frame, font=("Consolas", 12), bg="#161B22", fg="#00FF41", 
                                 insertbackground="#00FF41", show="*", width=30)
        password_entry.insert(0, "Enter database password")
        password_entry.config(fg="#555555")
        password_entry.pack(pady=10)
        
        def on_focus_in(event):
            if password_entry.get() == "Enter database password":
                password_entry.delete(0, "end")
                password_entry.config(fg="#00FF41")
        
        def on_focus_out(event):
            if not password_entry.get():
                password_entry.insert(0, "Enter database password")
                password_entry.config(fg="#555555")
        
        password_entry.bind("<FocusIn>", on_focus_in)
        password_entry.bind("<FocusOut>", on_focus_out)
        
        def try_login():
            password = password_entry.get()
            if not password or password == "Enter database password":
                messagebox.showerror("Error", "Password cannot be empty")
                return
                
            password = self.pad_db_key(password)
            try:
                db_handle = open(self.check_database(), "rb")
                self.path_to_database = "passwords.db"
                self.db_key_hash = db_handle.read(64).decode()
                self.ciphertext = db_handle.read()
                db_handle.close()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to access database: {str(e)}")
                return
                
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if password_hash == self.db_key_hash:
                self.decryption_key = password
                self.decrypt_db()
                self.create_main_screen()
            else:
                messagebox.showerror("Error", "Incorrect password")
        
        # Login button
        login_button = tk.Button(frame, text="Login", command=try_login, 
                                bg="#00FF41", fg="#0D1117", font=("Consolas", 12, "bold"), 
                                width=15, height=1)
        login_button.pack(pady=10)
        
        password_entry.bind("<Return>", lambda e: try_login())
    
    def create_main_screen(self):
        """Create main screen with table and controls"""
        for widget in self.root.winfo_children():
            widget.destroy()
            
        self.root.configure(bg="#0D1117")  # Keep simple background
        
        main_frame = tk.Frame(self.root, bg="#161B22")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        header_frame = tk.Frame(main_frame, bg="#161B22")
        header_frame.pack(fill="x")
        
        tk.Label(
            header_frame,
            text="Password Vault",
            font=("Consolas", 20, "bold"),
            fg="#00FF41",
            bg="#161B22"
        ).pack(side="left")
        
        table_frame = tk.Frame(main_frame, bg="#161B22")
        table_frame.pack(fill="both", expand=True, pady=10)
        
        columns = ("id", "username", "password", "platform", "tag", "copy")
        tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        tree.heading("id", text="ID")
        tree.heading("username", text="Username/Email")
        tree.heading("password", text="Password")
        tree.heading("platform", text="Platform")
        tree.heading("tag", text="Tag")
        tree.heading("copy", text="Copy")
        tree.column("id", width=50)
        tree.column("username", width=200)
        tree.column("password", width=200)
        tree.column("platform", width=150)
        tree.column("tag", width=100)
        tree.column("copy", width=50)
        tree.pack(fill="both", expand=True)
        
        style = ttk.Style()
        style.configure("Treeview", 
                       background="#161B22",
                       foreground="#00FF41",
                       fieldbackground="#161B22",
                       font=("Consolas", 10))
        style.configure("Treeview.Heading",
                       background="#00FF41",
                       foreground="#0D1117",
                       font=("Consolas", 12, "bold"))
        
        controls_frame = tk.Frame(main_frame, bg="#161B22")
        controls_frame.pack(fill="x", pady=10)
        
        search_entry = tk.Entry(controls_frame, font=("Consolas", 12), bg="#161B22", fg="#00FF41", 
                               insertbackground="#00FF41", width=20)
        search_entry.insert(0, "Search by username or platform")
        search_entry.config(fg="#555555")
        search_entry.pack(side="left", padx=5)
        
        def on_search_focus_in(event):
            if search_entry.get() == "Search by username or platform":
                search_entry.delete(0, "end")
                search_entry.config(fg="#00FF41")
        
        def on_search_focus_out(event):
            if not search_entry.get():
                search_entry.insert(0, "Search by username or platform")
                search_entry.config(fg="#555555")
        
        search_entry.bind("<FocusIn>", on_search_focus_in)
        search_entry.bind("<FocusOut>", on_search_focus_out)
        
        def search():
            query = search_entry.get().lower()
            self.show_credentials(tree, query)
        
        search_button = tk.Button(controls_frame, text="Search", command=search, 
                                bg="#00FF41", fg="#0D1117", font=("Consolas", 12, "bold"), 
                                width=10, height=1)
        search_button.pack(side="left", padx=5)
        
        tags = ["All", "work", "personal", "university", "other"]
        tag_var = tk.StringVar(value="All")
        tag_menu = ttk.OptionMenu(controls_frame, tag_var, "All", *tags,
                                command=lambda x: self.show_credentials(tree, tag=x if x != "All" else None))
        tag_menu.pack(side="left", padx=5)
        
        tk.Button(controls_frame, text="Add", command=self.add_credentials, 
                 bg="#00FF41", fg="#0D1117", font=("Consolas", 12, "bold"), 
                 width=10, height=1).pack(side="left", padx=5)
        
        tk.Button(controls_frame, text="Edit", command=lambda: self.edit_credentials(tree), 
                 bg="#00FF41", fg="#0D1117", font=("Consolas", 12, "bold"), 
                 width=10, height=1).pack(side="left", padx=5)
        
        tk.Button(controls_frame, text="Delete", command=lambda: self.delete_credentials(tree), 
                 bg="#00FF41", fg="#0D1117", font=("Consolas", 12, "bold"), 
                 width=10, height=1).pack(side="left", padx=5)
        
        tk.Button(controls_frame, text="Generate", command=self.generate_password, 
                 bg="#00FF41", fg="#0D1117", font=("Consolas", 12, "bold"), 
                 width=10, height=1).pack(side="left", padx=5)
        
        tk.Button(controls_frame, text="Change DB Pass", command=self.change_db_password, 
                 bg="#FFCC00", fg="#0D1117", font=("Consolas", 12, "bold"), 
                 width=15, height=1).pack(side="right", padx=5)
        
        tk.Button(controls_frame, text="Exit", command=self.root.quit, 
                 bg="#FF073A", fg="#0D1117", font=("Consolas", 12, "bold"), 
                 width=10, height=1).pack(side="right", padx=5)
        
        self.show_credentials(tree)
    
    def show_credentials(self, tree, query="", tag=None):
        """Show passwords in table"""
        for item in tree.get_children():
            tree.delete(item)
            
        if self.records_count == 0:
            messagebox.showinfo("Info", "Database is empty")
            return
            
        records = self.content.split("|")
        
        for record in records:
            fields = record.split("-")
            if len(fields) < 5:
                fields.append("")
                
            if (query == "" or query.lower() in fields[1].lower() or query.lower() in fields[3].lower()) and \
               (tag is None or fields[4] == tag):
                tree.insert("", "end", values=fields + [""])
                
        def copy_password(event):
            selected = tree.selection()
            if selected:
                password = tree.item(selected[0])["values"][2]
                pyperclip.copy(password)
                messagebox.showinfo("Success", "Password copied to clipboard")
                
        tree.bind("<Double-1>", copy_password)
    
    def add_credentials(self):
        """Add new password form"""
        window = tk.Toplevel(self.root, bg="#0D1117")
        window.title("Add Password")
        window.geometry("400x500")
        
        frame = tk.Frame(window, bg="#161B22", padx=20, pady=20)
        frame.pack(pady=20, padx=20)
        
        tk.Label(frame, text="Add New Credential", 
                font=("Consolas", 16, "bold"), fg="#00FF41", bg="#161B22").pack(pady=10)
        
        username_entry = tk.Entry(frame, font=("Consolas", 12), bg="#161B22", fg="#00FF41", 
                                 insertbackground="#00FF41", width=30)
        username_entry.insert(0, "Username/Email")
        username_entry.config(fg="#555555")
        username_entry.pack(pady=10)
        
        def on_username_focus_in(event):
            if username_entry.get() == "Username/Email":
                username_entry.delete(0, "end")
                username_entry.config(fg="#00FF41")
        
        def on_username_focus_out(event):
            if not username_entry.get():
                username_entry.insert(0, "Username/Email")
                username_entry.config(fg="#555555")
        
        username_entry.bind("<FocusIn>", on_username_focus_in)
        username_entry.bind("<FocusOut>", on_username_focus_out)
        
        password_entry = tk.Entry(frame, font=("Consolas", 12), bg="#161B22", fg="#00FF41", 
                                 insertbackground="#00FF41", show="*", width=30)
        password_entry.insert(0, "Password")
        password_entry.config(fg="#555555")
        password_entry.pack(pady=10)
        
        def on_password_focus_in(event):
            if password_entry.get() == "Password":
                password_entry.delete(0, "end")
                password_entry.config(fg="#00FF41")
        
        def on_password_focus_out(event):
            if not password_entry.get():
                password_entry.insert(0, "Password")
                password_entry.config(fg="#555555")
        
        password_entry.bind("<FocusIn>", on_password_focus_in)
        password_entry.bind("<FocusOut>", on_password_focus_out)
        
        platform_entry = tk.Entry(frame, font=("Consolas", 12), bg="#161B22", fg="#00FF41", 
                                 insertbackground="#00FF41", width=30)
        platform_entry.insert(0, "Platform")
        platform_entry.config(fg="#555555")
        platform_entry.pack(pady=10)
        
        def on_platform_focus_in(event):
            if platform_entry.get() == "Platform":
                platform_entry.delete(0, "end")
                platform_entry.config(fg="#00FF41")
        
        def on_platform_focus_out(event):
            if not platform_entry.get():
                platform_entry.insert(0, "Platform")
                platform_entry.config(fg="#555555")
        
        platform_entry.bind("<FocusIn>", on_platform_focus_in)
        platform_entry.bind("<FocusOut>", on_platform_focus_out)
        
        tags = ["work", "personal", "university", "other"]
        tag_var = tk.StringVar(value=tags[0])
        tag_menu = ttk.OptionMenu(frame, tag_var, tags[0], *tags)
        tag_menu.pack(pady=10)
        
        def save():
            username = username_entry.get()
            password = password_entry.get()
            platform = platform_entry.get()
            tag = tag_var.get()
            
            if not all([username, password, platform]) or username == "Username/Email" or password == "Password" or platform == "Platform":
                messagebox.showerror("Error", "All fields are required")
                return
                
            is_strong, error = self.is_strong_password(password)
            if not is_strong:
                messagebox.showerror("Error", error)
                return
                
            if self.records_count == 0:
                new_creds = [str(1), username, password, platform, tag]
                self.content = "-".join(new_creds)
            else:
                record_id = int(self.content.split("|")[-1].split("-")[0]) + 1
                new_creds = [str(record_id), username, password, platform, tag]
                self.content += "|" + "-".join(new_creds)
                
            self.records_count += 1
            self.save_db()
            messagebox.showinfo("Success", "Password added")
            window.destroy()
            self.show_credentials(self.root.winfo_children()[0].winfo_children()[1].winfo_children()[0])
        
        tk.Button(frame, text="Save", command=save, bg="#00FF41", fg="#0D1117", 
                 font=("Consolas", 12, "bold"), width=15, height=1).pack(pady=20)
    
    def edit_credentials(self, tree):
        """Edit password form"""
        selected = tree.selection()
        if not selected:
            messagebox.showerror("Error", "Select a password")
            return
            
        record_id = tree.item(selected)["values"][0]
        records = self.content.split("|")
        record_index = next((i for i, r in enumerate(records) if r.split("-")[0] == str(record_id)), None)
        if record_index is None:
            messagebox.showerror("Error", "Record not found")
            return
            
        record = records[record_index].split("-")
        
        window = tk.Toplevel(self.root, bg="#0D1117")
        window.title("Edit Password")
        window.geometry("400x500")
        
        frame = tk.Frame(window, bg="#161B22", padx=20, pady=20)
        frame.pack(pady=20, padx=20)
        
        tk.Label(frame, text="Edit Credential", 
                font=("Consolas", 16, "bold"), fg="#00FF41", bg="#161B22").pack(pady=10)
        
        username_entry = tk.Entry(frame, font=("Consolas", 12), bg="#161B22", fg="#00FF41", 
                                 insertbackground="#00FF41", width=30)
        username_entry.insert(0, record[1])
        username_entry.pack(pady=10)
        
        password_entry = tk.Entry(frame, font=("Consolas", 12), bg="#161B22", fg="#00FF41", 
                                 insertbackground="#00FF41", show="*", width=30)
        password_entry.insert(0, record[2])
        password_entry.pack(pady=10)
        
        platform_entry = tk.Entry(frame, font=("Consolas", 12), bg="#161B22", fg="#00FF41", 
                                 insertbackground="#00FF41", width=30)
        platform_entry.insert(0, record[3])
        platform_entry.pack(pady=10)
        
        tags = ["work", "personal", "university", "other"]
        tag_var = tk.StringVar(value=record[4] if len(record) > 4 else tags[0])
        tag_menu = ttk.OptionMenu(frame, tag_var, tag_var.get(), *tags)
        tag_menu.pack(pady=10)
        
        def save():
            username = username_entry.get()
            password = password_entry.get()
            platform = platform_entry.get()
            tag = tag_var.get()
            
            if not all([username, password, platform]):
                messagebox.showerror("Error", "All fields are required")
                return
                
            is_strong, error = self.is_strong_password(password)
            if not is_strong:
                messagebox.showerror("Error", error)
                return
                
            records[record_index] = "-".join([str(record_id), username, password, platform, tag])
            self.content = "|".join(records)
            self.save_db()
            messagebox.showinfo("Success", "Password updated")
            window.destroy()
            self.show_credentials(tree)
        
        tk.Button(frame, text="Save", command=save, bg="#00FF41", fg="#0D1117", 
                 font=("Consolas", 12, "bold"), width=15, height=1).pack(pady=20)
    
    def delete_credentials(self, tree):
        """Delete password"""
        selected = tree.selection()
        if not selected:
            messagebox.showerror("Error", "Select a password")
            return
            
        record_id = tree.item(selected)["values"][0]
        records = self.content.split("|")
        record_index = next((i for i, r in enumerate(records) if r.split("-")[0] == str(record_id)), None)
        if record_index is None:
            messagebox.showerror("Error", "Record not found")
            return
            
        if messagebox.askyesno("Confirm", "Are you sure you want to delete this password?"):
            del records[record_index]
            self.records_count -= 1
            self.content = "" if self.records_count == 0 else "|".join(records)
            self.save_db()
            messagebox.showinfo("Success", "Password deleted")
            self.show_credentials(tree)
    
    def generate_password(self):
        """Generate random password"""
        characters = string.ascii_letters + string.digits + string.punctuation
        password = "".join(random.choices(characters, k=32))
        
        window = tk.Toplevel(self.root, bg="#0D1117")
        window.title("Generated Password")
        window.geometry("400x200")
        
        frame = tk.Frame(window, bg="#161B22", padx=20, pady=20)
        frame.pack(pady=20, padx=20)
        
        tk.Label(frame, text="Generated Password", 
                font=("Consolas", 16, "bold"), fg="#00FF41", bg="#161B22").pack(pady=10)
        
        password_entry = tk.Entry(frame, font=("Consolas", 12), bg="#161B22", fg="#00FF41", 
                                 insertbackground="#00FF41", width=30)
        password_entry.insert(0, password)
        password_entry.pack(pady=10)
        
        tk.Button(frame, text="Copy & Close", command=lambda: [pyperclip.copy(password), window.destroy()], 
                 bg="#00FF41", fg="#0D1117", font=("Consolas", 12, "bold"), 
                 width=15, height=1).pack(pady=10)
    
    def change_db_password(self):
        """Change database password"""
        window = tk.Toplevel(self.root, bg="#0D1117")
        window.title("Change Database Password")
        window.geometry("400x300")
        
        frame = tk.Frame(window, bg="#161B22", padx=20, pady=20)
        frame.pack(pady=20, padx=20)
        
        tk.Label(frame, text="Change Database Password", 
                font=("Consolas", 16, "bold"), fg="#00FF41", bg="#161B22").pack(pady=10)
        
        new_password_entry = tk.Entry(frame, font=("Consolas", 12), bg="#161B22", fg="#00FF41", 
                                     insertbackground="#00FF41", show="*", width=30)
        new_password_entry.insert(0, "New Password")
        new_password_entry.config(fg="#555555")
        new_password_entry.pack(pady=10)
        
        def on_new_pass_focus_in(event):
            if new_password_entry.get() == "New Password":
                new_password_entry.delete(0, "end")
                new_password_entry.config(fg="#00FF41")
        
        def on_new_pass_focus_out(event):
            if not new_password_entry.get():
                new_password_entry.insert(0, "New Password")
                new_password_entry.config(fg="#555555")
        
        new_password_entry.bind("<FocusIn>", on_new_pass_focus_in)
        new_password_entry.bind("<FocusOut>", on_new_pass_focus_out)
        
        confirm_password_entry = tk.Entry(frame, font=("Consolas", 12), bg="#161B22", fg="#00FF41", 
                                         insertbackground="#00FF41", show="*", width=30)
        confirm_password_entry.insert(0, "Confirm Password")
        confirm_password_entry.config(fg="#555555")
        confirm_password_entry.pack(pady=10)
        
        def on_confirm_pass_focus_in(event):
            if confirm_password_entry.get() == "Confirm Password":
                confirm_password_entry.delete(0, "end")
                confirm_password_entry.config(fg="#00FF41")
        
        def on_confirm_pass_focus_out(event):
            if not confirm_password_entry.get():
                confirm_password_entry.insert(0, "Confirm Password")
                confirm_password_entry.config(fg="#555555")
        
        confirm_password_entry.bind("<FocusIn>", on_confirm_pass_focus_in)
        confirm_password_entry.bind("<FocusOut>", on_confirm_pass_focus_out)
        
        def save():
            new_password = new_password_entry.get()
            confirm_password = confirm_password_entry.get()
            
            if not new_password or not confirm_password or new_password == "New Password" or confirm_password == "Confirm Password":
                messagebox.showerror("Error", "Both fields are required")
                return
                
            if new_password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match")
                return
                
            is_strong, error = self.is_strong_password(new_password)
            if not is_strong:
                messagebox.showerror("Error", error)
                return
                
            self.decryption_key = self.pad_db_key(new_password)
            self.db_key_hash = hashlib.sha256(self.decryption_key.encode()).hexdigest()
            self.save_db()
            messagebox.showinfo("Success", "Database password changed")
            window.destroy()
        
        tk.Button(frame, text="Save", command=save, bg="#00FF41", fg="#0D1117", 
                 font=("Consolas", 12, "bold"), width=15, height=1).pack(pady=10)
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    try:
        pm = PasswordManager()
        pm.run()
    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
