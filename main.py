import json
import random
import string
import pyperclip
from tkinter import *
from tkinter import messagebox
from cryptography.fernet import Fernet

class PasswordManager:
    def __init__(self, master):
        self.master = master
        self.master.title("🔒 Password Manager Pro")
        self.master.geometry("1200x450")
        self.master.resizable(False, False)

        # --- Themes ---
        self.light_theme = {"bg": "#f0f0f0", "fg": "black", "entry_bg": "white"}
        self.dark_theme = {"bg": "#2c2c2c", "fg": "white", "entry_bg": "#4d4d4d"}
        self.current_theme = self.light_theme
        self.master.config(bg=self.current_theme["bg"])

        # --- Encryption Setup ---
        try:
            with open("secret.key", "rb") as key_file:
                self.key = key_file.read()
        except FileNotFoundError:
            self.key = Fernet.generate_key()
            with open("secret.key", "wb") as key_file:
                key_file.write(self.key)
        self.cipher = Fernet(self.key)

        # --- GUI Elements ---
        self.create_widgets()

    def create_widgets(self):
        # Frames
        self.input_frame = Frame(self.master, bg=self.current_theme["bg"])
        self.input_frame.pack(pady=30, padx=20)

        self.button_frame = Frame(self.master, bg=self.current_theme["bg"])
        self.button_frame.pack(pady=20)

        # Labels
        Label(self.input_frame, text="Website:", bg=self.current_theme["bg"], fg=self.current_theme["fg"], font=("Arial", 12)).grid(row=0, column=0, sticky=E, pady=5)
        Label(self.input_frame, text="Username/Email:", bg=self.current_theme["bg"], fg=self.current_theme["fg"], font=("Arial", 12)).grid(row=1, column=0, sticky=E, pady=5)
        Label(self.input_frame, text="Password:", bg=self.current_theme["bg"], fg=self.current_theme["fg"], font=("Arial", 12)).grid(row=2, column=0, sticky=E, pady=5)
        Label(self.input_frame, text="Strength:", bg=self.current_theme["bg"], fg=self.current_theme["fg"], font=("Arial", 12)).grid(row=3, column=0, sticky=E, pady=5)

        # Entries
        self.website_entry = Entry(self.input_frame, width=60, font=("Arial", 12), bg=self.current_theme["entry_bg"], fg=self.current_theme["fg"])
        self.website_entry.grid(row=0, column=1, pady=5, padx=5)
        self.website_entry.focus()

        self.username_entry = Entry(self.input_frame, width=60, font=("Arial", 12), bg=self.current_theme["entry_bg"], fg=self.current_theme["fg"])
        self.username_entry.grid(row=1, column=1, pady=5, padx=5)

        self.password_entry = Entry(self.input_frame, width=50, font=("Arial", 12), bg=self.current_theme["entry_bg"], fg=self.current_theme["fg"])
        self.password_entry.grid(row=2, column=1, pady=5, padx=5, sticky=W)
        self.password_entry.bind("<KeyRelease>", lambda e: self.update_strength())

        # Password Strength
        self.strength_var = StringVar()
        self.strength_label = Label(self.input_frame, textvariable=self.strength_var, bg=self.current_theme["bg"], fg=self.current_theme["fg"], font=("Arial", 10))
        self.strength_label.grid(row=3, column=1, sticky=W)

        # Buttons
        self.generate_btn = Button(self.input_frame, text="Generate", width=28, bg="#ff6666", fg="white", font=("Arial", 12, "bold"), relief=RAISED, bd=4, command=self.generate_and_fill)
        self.generate_btn.grid(row=2, column=2, padx=10, pady=5)

        self.add_btn = Button(self.button_frame, text="Add Password", width=50, bg="#4CAF50", fg="white", font=("Arial", 12, "bold"), relief=RAISED, bd=4, command=self.save_password)
        self.add_btn.grid(row=0, column=0, pady=8)

        self.search_btn = Button(self.button_frame, text="Search Password", width=50, bg="#2196F3", fg="white", font=("Arial", 12, "bold"), relief=RAISED, bd=4, command=self.search_password)
        self.search_btn.grid(row=1, column=0, pady=8)

        self.theme_btn = Button(self.button_frame, text="Toggle Theme", width=50, bg="#FFA500", fg="white", font=("Arial", 12, "bold"), relief=RAISED, bd=4, command=self.toggle_theme)
        self.theme_btn.grid(row=2, column=0, pady=8)

    # -------------------------
    # Password Functions
    # -------------------------
    def generate_password(self, length=16):
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for _ in range(length))

    def generate_and_fill(self):
        password = self.generate_password()
        self.password_entry.delete(0, END)
        self.password_entry.insert(0, password)
        pyperclip.copy(password)
        messagebox.showinfo(title="Password Generated", message="Password copied to clipboard!")
        self.update_strength()

    def update_strength(self):
        password = self.password_entry.get()
        score = 0
        if len(password) >= 8: score += 1
        if any(c.isupper() for c in password): score += 1
        if any(c.islower() for c in password): score += 1
        if any(c.isdigit() for c in password): score += 1
        if any(c in string.punctuation for c in password): score += 1
        strength_text = ["Very Weak","Weak","Moderate","Strong","Very Strong"]
        self.strength_var.set(f"{strength_text[score-1] if score>0 else 'Very Weak'}")

    def save_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not website or not username or not password:
            messagebox.showwarning("Missing Info", "Please fill all fields.")
            return
        encrypted_pass = self.cipher.encrypt(password.encode()).decode()
        new_data = {website: {"username": username, "password": encrypted_pass}}
        try:
            with open("passwords.json", "r") as file:
                data = json.load(file)
        except FileNotFoundError:
            data = {}
        data.update(new_data)
        with open("passwords.json", "w") as file:
            json.dump(data, file, indent=4)
        self.website_entry.delete(0, END)
        self.username_entry.delete(0, END)
        self.password_entry.delete(0, END)
        self.strength_var.set("")
        messagebox.showinfo("Success", f"Password for {website} saved!")

    def search_password(self):
        website = self.website_entry.get()
        try:
            with open("passwords.json", "r") as file:
                data = json.load(file)
        except FileNotFoundError:
            messagebox.showerror("Error", "No passwords saved yet.")
            return
        if website in data:
            username = data[website]["username"]
            encrypted_pass = data[website]["password"]
            decrypted_pass = self.cipher.decrypt(encrypted_pass.encode()).decode()
            messagebox.showinfo(website, f"Username: {username}\nPassword: {decrypted_pass}")
            pyperclip.copy(decrypted_pass)
        else:
            messagebox.showerror("Not Found", f"No password found for {website}")

    # -------------------------
    # Theme Toggle
    # -------------------------
    def toggle_theme(self):
        self.current_theme = self.dark_theme if self.current_theme == self.light_theme else self.light_theme
        self.master.config(bg=self.current_theme["bg"])
        for widget in self.master.winfo_children():
            if isinstance(widget, Frame):
                widget.config(bg=self.current_theme["bg"])
                for child in widget.winfo_children():
                    if isinstance(child, Label):
                        child.config(bg=self.current_theme["bg"], fg=self.current_theme["fg"])
                    if isinstance(child, Entry):
                        child.config(bg=self.current_theme["entry_bg"], fg=self.current_theme["fg"])
                    if isinstance(child, Button):
                        child.config(fg="white")
        self.update_strength()

if __name__ == "__main__":
    root = Tk()
    app = PasswordManager(root)
    root.mainloop()
