# French OTP
French -  Outrageously Trustworthy Program
## What is this?

**French OTP** is a command-line TOTP (SHA256) manager for Windows (and partly Linux/Mac).  
It securely stores OTP secrets, protected with a password (AES-256 encryption), and can display QR codes in ASCII directly in the console or in a dedicated popup window.

## Features

- Encrypted OTP database (AES-256, password-protected)
- Supports multiple TOTP accounts (SHA256, 6 digits, 90s interval)
- Base32 secret input (compatible with Google Authenticator/FreeOTP)
- ASCII QR code rendering for easy scanning with authenticator apps
- Can open the QR code in a new (zoomed out) console window for reliable scanning
- Console menu: add, remove, view accounts and QR

## Requirements

- **OpenSSL** libraries (libssl, libcrypto)
- **qrcodegen** C library ([https://github.com/nayuki/QR-Code-generator](https://github.com/nayuki/QR-Code-generator))
- C++ compiler (Visual Studio, g++, MinGW, etc.)
- Windows console for best experience

## How to use

1. Compile the program and ensure OpenSSL and qrcodegen are linked/included.
2. Run the executable.
3. Enter your master password (or create one on first launch).
4. Use the menu to add/remove OTP accounts or display their QR codes.
5. When viewing a QR code, a dedicated console window will open for easier scanning (with a small font for maximum QR visibility).

## Notes

- The database file (`otps.bin`) is encrypted and only accessible with your password.
- ASCII QR code is displayed both in the main and popup console for compatibility.
- For Linux/Mac, console popup support may need adaptation.
