# French OTP - Outrageously Trustworthy Program

A simple, secure, offline C++ console-based OTP (TOTP) manager.

---

## Features

- **Multi-account TOTP** (compatible with Google Authenticator, FreeOTP, Aegis…)
- **Strong encryption** for the OTP vault (AES-256-CBC + PBKDF2-HMAC-SHA256)
- **No cleartext OTP secrets** ever written to disk
- **Add/remove accounts** easily
- **Real-time OTP display** (SHA256, 6 digits, 90s time window)
- **Scannable ASCII QR code** for every account, with auto-zoom in a dedicated pop-up console
- **Local-only storage, no cloud, no tracking**
- **Works on Windows and Linux** (portable, USB-ready)

---

## Security

- **Vault is encrypted**: AES-256-CBC, key derived via PBKDF2-HMAC-SHA256
    - Salt: 16 random bytes
    - IV: 16 random bytes
    - 100,000 PBKDF2 iterations
- **Single file vault:** `otps.bin`
- **Compatible with any standard OTP app**
- **Master password required** to open the vault
- **No network dependencies or cloud sync**

### References

- [RFC 6238 (TOTP)](https://datatracker.ietf.org/doc/html/rfc6238)
- [OpenSSL Crypto](https://www.openssl.org/)
- [Nayuki QR Code Generator](https://github.com/nayuki/QR-Code-generator)
- [OWASP Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

---

## Usage

1. **Run the executable**  
   (Double-click or run `./french-otp` from your terminal)

2. **Set a master password**  
   (on first run, or if `otps.bin` does not exist)

3. **Add your OTP accounts**  
   (base32 key, e.g., `GVLVAZCC...`)

4. **Display and scan your real-time OTP codes**  
   - List view: OTP, account name, seconds left
   - QR code ASCII view, compatible with Google Auth, FreeOTP, Aegis, etc.
   - **QR code also shown in a separate pop-up console window for easy scanning**

5. **Remove/add accounts whenever you want**

---

## Example Usage

```shell
Master password: ********
== Registered accounts ==
[1] test | OTP: 489242 | 52s left

[a] Add account [s] Delete account [m] Mastercodes [q] Quit
```
- The **[m]** option shows the base32 key and lets you generate a scannable QR code for any account.
- Scan directly with your phone (all major OTP apps supported).

---

## FAQ & Resources

- [Aegis Authenticator](https://github.com/beemdevelopment/Aegis)
- [Google Authenticator](https://github.com/google/google-authenticator)
- [FreeOTP](https://freeotp.github.io/)
- [Nayuki QR Code Generator (C)](https://github.com/nayuki/QR-Code-generator)
- [Wikipedia: One-time Password](https://en.wikipedia.org/wiki/One-time_password)
- [RFC TOTP](https://datatracker.ietf.org/doc/html/rfc6238)

---
