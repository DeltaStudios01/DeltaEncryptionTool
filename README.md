DeltaEncryption Tool
====================

DeltaEncryption Tool is a GUI-based encryption and decryption solution built using Python. It is designed to provide data security with multiple layers of encryption.

----------------------------
Features
----------------------------
- **Encryption**
  - Supports text file encryption with 5 encryption phases using a combination of Base64, Base32, and Base128.
  - Optional: Add a password for additional security.
  - Encrypted files are packed in a .zip format, including a key file (key.txt) for decryption.

- **Decryption**
  - Supports decryption of files encrypted using DeltaEncryption Tool.
  - Requires a key file (key.txt) and password (if enabled during encryption).

----------------------------
How to Install
----------------------------
1. Run `setup.exe`.
2. Follow the on-screen instructions to complete the installation.

----------------------------
How to Use
----------------------------
- **Encryption**
  1. Open the DeltaEncryption Tool.
  2. Select the text file you want to encrypt.
  3. Choose the desired encryption phase (Phase 1 - Phase 5).
  4. (Optional) Check "Enable Password" and enter a password for extra security.
  5. Click "🔐 Encrypt Now!" to start encryption.
  6. The encrypted files will be saved in a .zip format.

- **Decryption**
  1. Open the DeltaEncryption Tool.
  2. Select the encrypted file (.enc).
  3. Choose the corresponding key file (key.txt).
  4. If the file is password-protected, enter the password when prompted.
  5. Click "🔓 Decrypt Now!" to start decryption.
  6. The original file will be restored with its original extension.

----------------------------
Dependencies
----------------------------
All required dependencies are included in the installer. Simply run `setup.exe` to get started.

----------------------------
License | Open LICENSE.txt
----------------------------
© 2024 Delta Studios | All Rights Reserved
