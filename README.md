# French OTP - Outrageously Trustworthy Program

A simple C++ TOTP manager for your terminal.

## What is this?

This program is a command-line TOTP (Time-based One-Time Password) manager.  
It allows you to securely store, generate, and manage OTP codes (compatible with Google Authenticator, FreeOTP, etc.) using AES encryption and a master password.  
You can display QR codes in your console for easy setup with your favorite mobile authenticator app.

## How to use

- **a** : Add a new OTP account
- **s** : Delete an account
- **m** : Show base32 secrets and generate QR codes (scan with your mobile app)
- **q** : Quit the program

Just run the executable, enter your master password (or create one on first use), and follow the on-screen instructions.

All your secrets are stored encrypted in `otps.bin`.

---
