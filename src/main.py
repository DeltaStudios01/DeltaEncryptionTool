import os, zipfile ; import base64 as bs64 ; import customtkinter as ctk
from tkinter import filedialog, messagebox as msgbox, simpledialog as dialog

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

class Base64:
    @staticmethod
    def encode(data: bytes) -> bytes:
        return bs64.b64encode(data)

    @staticmethod
    def decode(data: bytes) -> bytes:
        return bs64.b64decode(data)

class Base32:
    @staticmethod
    def encode(data: bytes) -> bytes:
        return bs64.b32encode(data)

    @staticmethod
    def decode(data: bytes) -> bytes:
        return bs64.b32decode(data)

class Base128:
    @staticmethod
    def encode(data: bytes) -> str:
        encoded = []
        data = bs64.b16encode(bs64.b85encode(data))
        for byte in data:
            high = byte >> 1
            low = byte & 0x01
            encoded.append(high)
            encoded.append(low)
        return ' '.join(map(str, encoded))

    @staticmethod
    def decode(data: str) -> bytes:
        data_list = list(map(int, data.split()))
        if len(data_list) % 2 != 0:
            raise ValueError("Input length must be even.")

        decoded = bytearray()
        for i in range(0, len(data_list), 2):
            high = data_list[i] << 1
            low = data_list[i + 1]
            decoded.append(high | low)

        decoded = bs64.b85decode(bs64.b16decode(bytes(decoded)))
        return decoded

def browse_file():
    file_path = filedialog.askopenfilename(title="Select File")
    if file_path:
        entry_filepath.delete(0, ctk.END)
        entry_filepath.insert(0, file_path)

def show_done(label):
    label.configure(text="Done!", text_color="#28A745")
    label.after(1000, lambda: label.grid_forget())
    label.after(1000, lambda: app.geometry("850x400"))

def start_encryption():
    file_path = entry_filepath.get()
    if not os.path.isfile(file_path):
        msgbox.showerror("Error", "File not found. Please select a valid file.")
        return

    file_size = os.path.getsize(file_path)
    if file_size > MAX_FILE_SIZE:
        msgbox.showerror("Error", f"File size exceeds the maximum limit of {MAX_FILE_SIZE // (1024 * 1024)} MB.")
        return

    app.geometry("850x410")
    
    please_wait_label_encrypt.configure(text="Please wait...", text_color="orange")
    please_wait_label_encrypt.grid(row=3, column=0, columnspan=3, pady=10)
    app.update()
    
    try:
        password = None
        has_password = False
        output_pw = ""

        if pw_var.get():
            password = dialog.askstring("", "Please create a password: ")
            if password:
                has_password = True
                output_pw = f"{Base32.encode(str(has_password).encode()).decode()}#{Base64.encode(Base32.encode(password.encode())).decode()}"
            else:
                has_password = False
                output_pw = f"{Base32.encode(str(has_password).encode()).decode()}#"
        else:
            has_password = False
            output_pw = f"{Base32.encode(str(has_password).encode()).decode()}#"

        with open(file_path, 'rb') as f:
            data = f.read()

        selected = selected_phase.get()
        if selected == "Phase 1":
            final = Base128.encode(data)
            phase = 1
        elif selected == "Phase 2":
            final = Base64.encode(Base128.encode(data).encode()).decode()
            phase = 2
        elif selected == "Phase 3":
            final = Base128.encode(Base64.encode(Base128.encode(data).encode()).decode())
            phase = 3
        elif selected == "Phase 4":
            final = Base32.encode(Base128.encode(Base64.encode(Base128.encode(data).encode()).decode().encode()).encode()).decode()
            phase = 4
        elif selected == "Phase 5":
            final = Base64.encode(Base32.encode(Base128.encode(Base64.encode(Base128.encode(data).encode()).decode().encode()).encode()).decode().encode()).decode()
            phase = 5

        file_name, file_extension = os.path.splitext(os.path.basename(file_path))
        encrypted_file = file_name + ".enc"

        with open(encrypted_file, 'wb') as f:
            f.write(final.encode('utf-8'))

        key_file = "key.txt"
        with open(key_file, 'w', encoding='utf-8') as f:
            f.write(' '.join(format(ord(char), '08b') for char in file_extension))
            f.write("\n" + Base32.encode(Base64.encode(str(phase).encode())).decode())
            f.write("\n" + output_pw)

        zip_file = os.path.join(os.path.dirname(file_path), file_name + ".zip")
        with zipfile.ZipFile(zip_file, 'w') as zipf:
            zipf.write(encrypted_file, os.path.basename(encrypted_file))
            zipf.write(key_file, os.path.basename(key_file))

        os.remove(encrypted_file)
        os.remove(key_file)
        os.remove(file_path)

        entry_filepath.delete("0", "end")
        pw_var.set(False)

        show_done(please_wait_label_encrypt)
        app.after(2000, show_done, please_wait_label_encrypt)
        msgbox.showinfo("Success", f"File encrypted successfully! \nYour file is now '{file_name}.zip'")

    except Exception as e:
        please_wait_label_encrypt.grid_forget()
        msgbox.showerror("Error", f"An error occurred: {e}")

def browse_enc_file():
    file_path = filedialog.askopenfilename(title="Select Encrypted File", filetypes=[("Encrypted Files", "*.enc")])
    if file_path:
        entry_enc_filepath.delete(0, ctk.END)
        entry_enc_filepath.insert(0, file_path)

def browse_key_file():
    file_path = filedialog.askopenfilename(title="Select Key File", filetypes=[("Key Files", "key.txt")])
    if file_path:
        entry_key_filepath.delete(0, ctk.END)
        entry_key_filepath.insert(0, file_path)

def start_decryption():
    enc_file_path = entry_enc_filepath.get()
    key_file_path = entry_key_filepath.get()

    if not os.path.isfile(enc_file_path):
        msgbox.showerror("Error", "Encrypted file not found. Please select a valid .enc file.")
        return
    if not os.path.isfile(key_file_path):
        msgbox.showerror("Error", "Key file not found. Please select a valid key.txt file.")
        return

    app.geometry("850x410")
    
    please_wait_label_decrypt.configure(text="Please wait...", text_color="orange")
    please_wait_label_decrypt.grid(row=2, column=0, columnspan=3, pady=10)
    app.update()
    
    try:
        with open(key_file_path, 'r', encoding='utf-8') as f:
            key_data = f.readlines()
            if len(key_data) < 3:
                raise ValueError("Key file is invalid. Missing required data.")

            file_extension = ''.join(chr(int(b, 2)) for b in key_data[0].strip().split())
            phase = int(Base64.decode(Base32.decode(key_data[1].strip().encode())).decode())

            line_3 = key_data[2].strip()
            parts = line_3.split('#')
            if len(parts) != 2:
                raise ValueError("Invalid format.")

            has_password = Base32.decode(parts[0].encode()).decode() == "True"
            encrypted_password = parts[1]

            if has_password:
                user_password = dialog.askstring("", "Please input the password:")
                if not user_password:
                    msgbox.showerror("Error", "Password is required to decrypt the file.")
                    return

                decoded_password = Base32.decode(Base64.decode(encrypted_password.encode())).decode()
                if user_password != decoded_password:
                    msgbox.showerror("Error", "Incorrect password. Decryption failed.")
                    return

        with open(enc_file_path, 'rb') as f:
            data = f.read()

        if phase == 1:
            final = Base128.decode(data.decode())
        elif phase == 2:
            final = Base128.decode(Base64.decode(data).decode())
        elif phase == 3:
            final = Base128.decode(Base64.decode(Base128.decode(data.decode())).decode())
        elif phase == 4:
            final = Base128.decode(Base64.decode(Base128.decode(Base32.decode(data).decode())).decode())
        elif phase == 5:
            final = Base128.decode(Base64.decode(Base128.decode(Base32.decode(Base64.decode(data).decode())).decode()))

        original_file_path = os.path.splitext(enc_file_path)[0] + file_extension

        with open(original_file_path, 'wb') as f:
            f.write(final)

        os.remove(enc_file_path)
        os.remove(key_file_path)

        entry_enc_filepath.delete("0", "end")
        entry_key_filepath.delete("0", "end")

        show_done(please_wait_label_decrypt)
        app.after(2000, show_done, please_wait_label_encrypt)
        msgbox.showinfo("Success", f"File decrypted successfully!\nYour file is saved as '{original_file_path}'")

    except Exception as e:
        please_wait_label_decrypt.grid_forget()
        msgbox.showerror("Error", f"An error occurred: {e}")

app = ctk.CTk()
app.title("DeltaEncryption Tool")
app.geometry("850x400")
app.resizable(False, False)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

tab_view = ctk.CTkTabview(app)
tab_view.pack(expand=True, fill="both")

encrypt_tab = tab_view.add("Encrypt")
decrypt_tab = tab_view.add("Decrypt")

header_frame_encrypt = ctk.CTkFrame(encrypt_tab)
header_frame_encrypt.pack(pady=10, fill="x")

logo_encrypt = ctk.CTkLabel(header_frame_encrypt, text="🔒 DeltaEncryption Tool - Encrypt", font=("Consolas", 20))
logo_encrypt.pack(pady=10)

frame_encrypt = ctk.CTkFrame(encrypt_tab, corner_radius=15)
frame_encrypt.pack(pady=20, padx=20, expand=True)

label_filepath = ctk.CTkLabel(frame_encrypt, text="Select File:", font=("Consolas", 15))
label_filepath.grid(row=0, column=0, padx=10, pady=10, sticky="e")

entry_filepath = ctk.CTkEntry(frame_encrypt, width=350)
entry_filepath.grid(row=0, column=1, padx=10, pady=10)

button_browse = ctk.CTkButton(frame_encrypt, text="Browse", command=browse_file, fg_color="#007BFB", hover_color="#009BFB")
button_browse.grid(row=0, column=2, padx=10, pady=10)

phases = ["Phase 1", "Phase 2", "Phase 3", "Phase 4", "Phase 5"]
selected_phase = ctk.StringVar(value="Select Phase")

phase_menu = ctk.CTkOptionMenu(encrypt_tab, values=phases, variable=selected_phase)
phase_menu.pack(pady=10)

please_wait_label_encrypt = ctk.CTkLabel(frame_encrypt, text="Please wait...", font=("Consolas", 18), text_color="orange")
please_wait_label_encrypt.grid(row=3, column=0, columnspan=3, pady=10)
please_wait_label_encrypt.grid_forget() 

action_frame_encrypt = ctk.CTkFrame(encrypt_tab, corner_radius=15)
action_frame_encrypt.pack(pady=20)

button_encrypt = ctk.CTkButton(action_frame_encrypt, text="🔐 Encrypt Now!", command=start_encryption, fg_color="#28A745", hover_color="#218838")
button_encrypt.pack(side="left", padx=10)

pw_var = ctk.BooleanVar(value=False)

pw_checkbutton = ctk.CTkCheckBox(action_frame_encrypt, text="Enable Password", variable=pw_var, checkmark_color="#FFF", hover_color="#DC3545", fg_color="#C82333")
pw_checkbutton.pack(side="left", padx=20)

header_frame_decrypt = ctk.CTkFrame(decrypt_tab)
header_frame_decrypt.pack(pady=10, fill="x")

logo_decrypt = ctk.CTkLabel(header_frame_decrypt, text="🔓 DeltaEncryption Tool - Decrypt", font=("Consolas", 20))
logo_decrypt.pack(pady=10)

frame_decrypt = ctk.CTkFrame(decrypt_tab, corner_radius=15)
frame_decrypt.pack(pady=20, padx=20, fill="x", expand=True)

label_enc_filepath = ctk.CTkLabel(frame_decrypt, text="Select Encrypted File (.enc):", font=("Consolas", 15))
label_enc_filepath.grid(row=0, column=0, padx=10, pady=10, sticky="w")

entry_enc_filepath = ctk.CTkEntry(frame_decrypt, width=350)
entry_enc_filepath.grid(row=0, column=1, padx=10, pady=10)

button_browse_enc = ctk.CTkButton(frame_decrypt, text="Browse", command=browse_enc_file, fg_color="#007BFF")
button_browse_enc.grid(row=0, column=2, padx=10, pady=10)

label_key_filepath = ctk.CTkLabel(frame_decrypt, text="Select Key File (key.txt):", font=("Consolas", 15))
label_key_filepath.grid(row=1, column=0, padx=10, pady=10, sticky="w")

entry_key_filepath = ctk.CTkEntry(frame_decrypt, width=350)
entry_key_filepath.grid(row=1, column=1, padx=10, pady=10)

button_browse_key = ctk.CTkButton(frame_decrypt, text="Browse", command=browse_key_file, fg_color="#007BFF", hover_color="#009BFB")
button_browse_key.grid(row=1, column=2, padx=10, pady=10)

please_wait_label_decrypt = ctk.CTkLabel(frame_decrypt, text="Please wait...", font=("Consolas", 18), text_color="orange")
please_wait_label_decrypt.grid(row=2, column=0, columnspan=3, pady=10)
please_wait_label_decrypt.grid_forget()

button_decrypt = ctk.CTkButton(decrypt_tab, text="🔓 Decrypt Now!", command=start_decryption, fg_color="#DC3545", hover_color="#C82333")
button_decrypt.pack(pady=20)

footer = ctk.CTkLabel(app, text="© 2024 Delta Studios | All Rights Reserved", font=("Consolas", 14))
footer.pack(side="bottom", pady=10)

#@ ------------------------------------------------------ RUN THE PROGRAM ------------------------------------------------------

app.mainloop()

# -----------------------------------------------------------------------------------------------------------------------------
#   _____  ______ _   _______          _____ _______ _    _ _____ _____ ____   _____ 
#  |  __ \|  ____| | |__   __|/\      / ____|__   __| |  | |  __ \_   _/ __ \ / ____|
#  | |  | | |__  | |    | |  /  \    | (___    | |  | |  | | |  | || || |  | | (___  
#  | |  | |  __| | |    | | / /\ \    \___ \   | |  | |  | | |  | || || |  | |\___ \ 
#  | |__| | |____| |____| |/ ____ \   ____) |  | |  | |__| | |__| || || |__| |____) |
#  |_____/|______|______|_/_/    \_\ |_____/   |_|   \____/|_____/_____\____/|_____/   Software Factory 