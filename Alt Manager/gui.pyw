import tkinter as tk
from tkinter import *
from tkinter import messagebox
import pyperclip
import hashlib

def hash_password(password: str) -> str:
    sha256 = hashlib.sha256()
    sha256.update(password.encode('utf-8'))
    return sha256.hexdigest()

def check_password():
    entered_password = password_entry.get()
    if hash_password(entered_password) == stored_password_hash:
        login_frame.pack_forget()
        accounts_frame.pack(pady=10)
    else:
        messagebox.showerror("Error", "Password incorrect")

def copy_credentials():
    account = account_var.get()
    if account in credentials:
        pyperclip.copy(credentials[account])
        messagebox.showinfo("Success", "Credentials copied to clipboard")
    else:
        messagebox.showerror("Error", "Account not found")

stored_password = "password"
stored_password_hash = hash_password(stored_password)

credentials = {
    'Account1': 'email / password',
    'Account2': 'email / password',
}

root = tk.Tk()
root.title("MC Alt Manager")
root.icon = PhotoImage(file='favicon.png')
root.resizable(False, False)
root.geometry('420x210')
root.config(background="#2C2F33")
root.iconphoto(True, PhotoImage(file='favicon.png'))

login_frame = tk.Frame(root)
login_frame.pack(padx=10, pady=10)
login_frame.icon = PhotoImage(file='favicon.png')

tk.Label(login_frame, text="Enter the Program Password:").pack(pady=5)
password_entry = tk.Entry(login_frame, show="*")
password_entry.pack(pady=5)
password_entry.icon = PhotoImage(file='favicon.png')
tk.Button(login_frame, text="Submit", command=check_password,   background="#99AAB5").pack(pady=10)

accounts_frame = tk.Frame(root)
accounts_frame.icon = PhotoImage(file='favicon.png')

tk.Label(accounts_frame, text="Which account do you want?").pack(pady=5)
account_var = tk.StringVar()
account_var.set(list(credentials.keys())[0])
account_var.icon = PhotoImage(file='favicon.png')

for account in credentials:
    tk.Radiobutton(accounts_frame, text=account, variable=account_var, value=account).pack(anchor=tk.W)

tk.Button(accounts_frame, text="Copy Credentials", command=copy_credentials).pack(pady=10)

accounts_frame.pack_forget()
login_frame.pack(padx=10, pady=10)

root.mainloop()
