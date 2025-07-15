#include "pch.h"
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <vector>
#include <ctime>
#include <iomanip>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <conio.h>
#include <algorithm>
#include <sstream>
#include <thread>
#include <chrono>
#include <limits>
#include <cstdlib>

extern "C" {
#include "qrcodegen.h"
}

#ifdef _WIN32
#include <windows.h>
#undef max
void clear() { system("cls"); }
void set_console_font_small()
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_FONT_INFOEX cfi = { 0 };
    cfi.cbSize = sizeof(CONSOLE_FONT_INFOEX);
    cfi.nFont = 0;
    cfi.dwFontSize.X = 4;   
    cfi.dwFontSize.Y = 8;   
    cfi.FontFamily = FF_DONTCARE;
    cfi.FontWeight = FW_NORMAL;
    wcscpy_s(cfi.FaceName, L"Consolas");
    SetCurrentConsoleFontEx(hConsole, FALSE, &cfi);
}
#else
#include <unistd.h>
void clear() { std::cout << "\033[2J\033[H"; }
#endif

#define SALT_SIZE 16
#define IV_SIZE   16
#define KEY_SIZE  32 
#define PBKDF2_ROUNDS 100000

const char* baguettes[] = {
R"(
           _   __    _   __
          ( `^` ))  ( `^` ))
          |     ||  |     ||
          |     ||  |     ||
          '-----'`  '-----'`
Not a french baguette...
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
)",
R"(
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                _                     _   
               (_)                   | |  
  ___ _ __ ___  _ ___ ___  __ _ _ __ | |_ 
 / __| '__/ _ \| / __/ __|/ _` | '_ \| __|
| (__| | | (_) | \__ \__ \ (_| | | | | |_ 
 \___|_|  \___/|_|___/___/\__,_|_| |_|\__|
                                          
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
)",
R"(
                                                          
88                                                    88  
88                                                    88  
88                                                    88  
88,dPPYba,  8b,dPPYba,  ,adPPYba, ,adPPYYba,  ,adPPYb,88  
88P'    "8a 88P'   "Y8 a8P_____88 ""     `Y8 a8"    `Y88  
88       d8 88         8PP""""""" ,adPPPPP88 8b       88  
88b,   ,a8" 88         "8b,   ,aa 88,    ,88 "8a,   ,d88  
8Y"Ybbd8"'  88          `"Ybbd8"' `"8bbdP"Y8  `"8bbdP"Y8  
)",
R"(
        ..
      ..  ..
            ..
             ..
            ..
           ..
         ..
##       ..    ####
##.............##  ##
##.............##   ##
##.............## ##
##.............###
 ##...........##
  #############
  #############
#################
)"
};

void show_baguette(int idx) {
    std::cout << baguettes[idx] << std::endl;
    std::cout << "French OTP - Outrageously Trustworthy Program\n" << std::endl;
}

void wait_enter() {
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();
}

void print_qr_ascii_nayuki(const std::string& text, int quiet = 3, int maxver = 8) {
    uint8_t qrcode[qrcodegen_BUFFER_LEN_MAX];
    uint8_t tempBuffer[qrcodegen_BUFFER_LEN_MAX];

    bool ok = qrcodegen_encodeText(
        text.c_str(), tempBuffer, qrcode,
        qrcodegen_Ecc_LOW,
        1, maxver,
        qrcodegen_Mask_AUTO, true);

    if (!ok) {
        std::cout << "Error generating QR code!\n";
        return;
    }
    int size = qrcodegen_getSize(qrcode);
    const char* BLACK = "  ";  
    const char* WHITE = "##";  

    for (int y = -quiet; y < size + quiet; ++y) {
        for (int x = -quiet; x < size + quiet; ++x) {
            bool isBlack = false;
            if (x >= 0 && x < size && y >= 0 && y < size)
                isBlack = qrcodegen_getModule(qrcode, x, y);
            std::cout << (isBlack ? BLACK : WHITE);
        }
        std::cout << "\n";
    }
}

void open_qr_in_new_console(const std::string& otpauth_uri) {
#ifdef _WIN32
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string command = "start \"QR Code\" \"" + std::string(exePath) + "\" --show-qr \"" + otpauth_uri + "\"";
    system(command.c_str());
#else

#endif
}

// --- Base32 decode ---
std::vector<uint8_t> base32_decode(const std::string& input) {
    static const std::string base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::vector<uint8_t> output;
    int buffer = 0, bitsLeft = 0;
    for (char c : input) {
        if (c == '=' || c == ' ') continue;
        c = toupper(c);
        size_t val = base32_chars.find(c);
        if (val == std::string::npos) continue;
        buffer <<= 5;
        buffer |= val;
        bitsLeft += 5;
        if (bitsLeft >= 8) {
            output.push_back((buffer >> (bitsLeft - 8)) & 0xFF);
            bitsLeft -= 8;
        }
    }
    return output;
}

// --- TOTP ---
std::string generate_totp(const std::vector<uint8_t>& key, int interval = 90, int digits = 6, int* seconds_left = nullptr) {
    std::time_t now = std::time(nullptr);
    uint64_t timestep = now / interval;
    uint8_t challenge[8];
    for (int i = 7; i >= 0; --i) {
        challenge[i] = timestep & 0xFF;
        timestep >>= 8;
    }

    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len;
    HMAC(EVP_sha256(), key.data(), key.size(), challenge, 8, result, &result_len);

    int offset = result[result_len - 1] & 0x0F;
    uint32_t code = ((result[offset] & 0x7F) << 24) |
        ((result[offset + 1] & 0xFF) << 16) |
        ((result[offset + 2] & 0xFF) << 8) |
        (result[offset + 3] & 0xFF);
    code = code % static_cast<uint32_t>(pow(10, digits));

    if (seconds_left)
        *seconds_left = interval - (now % interval);

    std::ostringstream ss;
    ss << std::setw(digits) << std::setfill('0') << code;
    return ss.str();
}

// --- AES-256-CBC Encrypt/Decrypt OTP map
bool aes_encrypt(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& ciphertext, const uint8_t* key, const uint8_t* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int len;
    int ciphertext_len;
    ciphertext.resize(plaintext.size() + 16);
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aes_decrypt(const std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& plaintext, const uint8_t* key, const uint8_t* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int len;
    int plaintext_len;
    plaintext.resize(ciphertext.size());
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    plaintext_len += len;
    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// --- Serialize/Deserialize OTPs ---
std::vector<uint8_t> serialize_otps(const std::map<std::string, std::string>& otps) {
    std::ostringstream oss;
    for (const auto& kv : otps) {
        oss << kv.first << ":" << kv.second << "\n";
    }
    std::string s = oss.str();
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::map<std::string, std::string> deserialize_otps(const std::vector<uint8_t>& data) {
    std::map<std::string, std::string> otps;
    std::istringstream iss(std::string(data.begin(), data.end()));
    std::string line;
    while (std::getline(iss, line)) {
        size_t sep = line.find(':');
        if (sep == std::string::npos) continue;
        otps[line.substr(0, sep)] = line.substr(sep + 1);
    }
    return otps;
}

// --- Password input ---
bool get_password(std::string& password) {
    std::cout << "Master password: ";
#ifdef _WIN32
    char buf[128] = { 0 };
    DWORD mode = 0;
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~(ENABLE_ECHO_INPUT));
    std::cin.getline(buf, sizeof(buf));
    SetConsoleMode(hStdin, mode);
    password = buf;
#else
    system("stty -echo");
    std::getline(std::cin, password);
    system("stty echo");
#endif
    std::cout << std::endl;
    return !password.empty();
}

bool load_otps_encrypted(const std::string& file, std::map<std::string, std::string>& otps, std::string& password) {
    std::ifstream f(file, std::ios::binary);
    if (!f) return false;
    uint8_t salt[SALT_SIZE], iv[IV_SIZE];
    f.read((char*)salt, SALT_SIZE);
    f.read((char*)iv, IV_SIZE);
    std::vector<uint8_t> ciphertext((std::istreambuf_iterator<char>(f)), {});
    f.close();
    uint8_t key[KEY_SIZE];
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(), salt, SALT_SIZE, PBKDF2_ROUNDS, EVP_sha256(), KEY_SIZE, key))
        return false;
    std::vector<uint8_t> plaintext;
    if (!aes_decrypt(ciphertext, plaintext, key, iv))
        return false;
    otps = deserialize_otps(plaintext);
    return true;
}

bool save_otps_encrypted(const std::string& file, const std::map<std::string, std::string>& otps, const std::string& password) {
    uint8_t salt[SALT_SIZE], iv[IV_SIZE];
    RAND_bytes(salt, SALT_SIZE);
    RAND_bytes(iv, IV_SIZE);
    uint8_t key[KEY_SIZE];
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(), salt, SALT_SIZE, PBKDF2_ROUNDS, EVP_sha256(), KEY_SIZE, key))
        return false;
    std::vector<uint8_t> plaintext = serialize_otps(otps);
    std::vector<uint8_t> ciphertext;
    if (!aes_encrypt(plaintext, ciphertext, key, iv))
        return false;
    std::ofstream f(file, std::ios::binary | std::ios::trunc);
    f.write((char*)salt, SALT_SIZE);
    f.write((char*)iv, IV_SIZE);
    f.write((char*)ciphertext.data(), ciphertext.size());
    f.close();
    return true;
}

// --- UI
void show_accounts(const std::map<std::string, std::string>& otps, int interval) {
    std::cout << "== Registered accounts ==" << std::endl;
    int i = 1;
    for (const auto& kv : otps) {
        std::vector<uint8_t> key = base32_decode(kv.second);
        int seconds_left = 0;
        std::string otp = "INVALID KEY";
        if (!key.empty()) {
            otp = generate_totp(key, interval, 6, &seconds_left);
        }
        std::cout << "[" << i << "] " << std::setw(20) << std::left << kv.first
            << " | OTP: " << otp << " | " << seconds_left << "s left";
        if (key.empty())
            std::cout << "  [KEY INVALID]";
        std::cout << std::endl;
        i++;
    }
    if (otps.empty())
        std::cout << "(No account registered)" << std::endl;
}

void add_account(std::map<std::string, std::string>& otps) {
    std::string name, key;
    std::cout << "Account name: ";
    std::getline(std::cin, name);
    std::cout << "OTP key (base32, ex: GVLVAZCC...): ";
    std::getline(std::cin, key);
    key.erase(std::remove_if(key.begin(), key.end(), ::isspace), key.end());
    std::transform(key.begin(), key.end(), key.begin(), ::toupper);
    std::cout << "Registered key (base32): " << key << std::endl;
    otps[name] = key;
    std::cout << "Saved! Press enter to continue...";
    wait_enter();
}

void delete_account(std::map<std::string, std::string>& otps) {
    if (otps.empty()) {
        std::cout << "No account to delete. Press enter to continue...";
        wait_enter();
        return;
    }
    std::cout << "Enter account number to delete (or 0 to cancel): ";
    int num = 0;
    std::cin >> num;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    if (num <= 0 || num > static_cast<int>(otps.size())) return;
    auto it = otps.begin();
    std::advance(it, num - 1);
    std::string account = it->first;
    otps.erase(it);
    std::cout << "Account '" << account << "' deleted. Press enter to continue...";
    wait_enter();
}

void show_mastercodes(const std::map<std::string, std::string>& otps) {
    std::cout << "\n== Mastercodes (base32) ==" << std::endl;
    int i = 1;
    std::vector<std::string> accounts;
    for (const auto& kv : otps) {
        std::cout << "[" << i << "] " << std::setw(20) << std::left << kv.first
            << " | Mastercode: " << kv.second << std::endl;
        accounts.push_back(kv.first);
        i++;
    }
    if (otps.empty())
        std::cout << "(No account registered)" << std::endl;

    std::cout << "[q] Show QR code for an account" << std::endl;
    std::cout << "Press enter to continue...";
    char c = std::cin.get();
    if (c == 'q' || c == 'Q') {
        std::cout << "\nEnter the account number to show QR code: ";
        int n = 0;
        std::cin >> n;
        std::cin.ignore(1000, '\n');
        if (n > 0 && n <= (int)accounts.size()) {
            std::string acct = accounts[n - 1];
            auto it = otps.find(acct);
            if (it != otps.end()) {
                std::ostringstream oss;
                oss << "otpauth://totp/"
                    << acct
                    << "?secret=" << it->second
                    << "&algorithm=SHA256&digits=6&period=90";
                std::cout << "\nScan this with your TOTP app (Google Auth, FreeOTP, etc):\n";
                print_qr_ascii_nayuki(oss.str());
                open_qr_in_new_console(oss.str());
                std::cout << "\n(Le QR est aussi affiché dans une nouvelle fenêtre console !)\n";
            }
        }
        std::cout << "Press enter to continue...";
        std::cin.get();
    }
    else {
        if (c != '\n') std::cin.ignore(1000, '\n');
    }
}

// -------------- MAIN --------------
int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
#endif

    // Si lancé avec "--show-qr <uri>", mode QR solo (nouvelle console)
    if (argc >= 3 && std::string(argv[1]) == "--show-qr") {
        clear();
#ifdef _WIN32
        set_console_font_small();
#endif
        print_qr_ascii_nayuki(argv[2], 3, 10); 
        std::cout << "\nAppuyez sur une touche pour fermer la fenêtre QR...";
        std::cin.get();
        return 0;
    }

    std::srand((unsigned int)std::time(nullptr));
    int idx_baguette = std::rand() % (sizeof(baguettes) / sizeof(baguettes[0]));

    const std::string storage_file = "otps.bin";
    const int interval = 90;
    std::map<std::string, std::string> otps;
    std::string password;

    get_password(password);

    bool loaded = load_otps_encrypted(storage_file, otps, password);
    if (!loaded) {
        std::ifstream f(storage_file, std::ios::binary);
        if (f.good() && f.peek() != std::ifstream::traits_type::eof()) {
            std::cout << "\nWrong password or corrupted OTP base!" << std::endl;
            wait_enter();
            return 1;
        }
        else {
            std::cout << "New file, OTP base initialized." << std::endl;
        }
    }

    bool running = true;
    while (running) {
        for (int tick = 0; tick < interval; ++tick) {
            clear();
            show_baguette(idx_baguette);
            show_accounts(otps, interval);
            std::cout << "\n[a] Add account  [s] Delete account  [m] Mastercodes  [q] Quit" << std::endl;
            std::cout << "(Press corresponding key at any time...)" << std::endl;
#ifdef _WIN32
            if (_kbhit()) {
                char c = _getch();
                if (c == 'a' || c == 'A') {
                    clear();
                    show_baguette(idx_baguette);
                    add_account(otps);
                    save_otps_encrypted(storage_file, otps, password);
                    break;
                }
                else if (c == 's' || c == 'S') {
                    clear();
                    show_baguette(idx_baguette);
                    show_accounts(otps, interval);
                    delete_account(otps);
                    save_otps_encrypted(storage_file, otps, password);
                    break;
                }
                else if (c == 'm' || c == 'M') {
                    clear();
                    show_baguette(idx_baguette);
                    show_mastercodes(otps);
                    break;
                }
                else if (c == 'q' || c == 'Q') {
                    running = false;
                    break;
                }
            }
#else
#endif
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    clear();
    std::cout << "Bye!" << std::endl;
    return 0;
}
