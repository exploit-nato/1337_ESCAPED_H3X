#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>

class EncryptableString {
private:
    std::string data{},
                salt{}; // ***Keep salt separate from the data***
    // I would do more, and structure it differently, if I was trying to be cryptographically sound. I'd also obfuscate the source more.
    char getSuccessor(char ch, const std::string &salt) const {
        int shift = static_cast<int>(salt[0]); // Taking the ASCII value of the first character of the salt
        if (isalnum(ch)) {
            if (isalpha(ch)) {
                if (isupper(ch))
                    return 'A' + (ch - 'A' + shift) % 0x1A; // 26
                else
                    return 'a' + (ch - 'a' + shift) % 0x1A;
            } else if (isdigit(ch))
                return '0' + (ch - '0' + shift) % 0xA; // 10
        } return ch; // Return the character unchanged if it's not alphanumeric
    }

    char getPredecessor(char ch, const std::string &salt) const {
        int shift = static_cast<int>(salt[0]); // Taking the ASCII value of the first character of the salt
        if (isalnum(ch)) {
            if (isalpha(ch)) {
                if (isupper(ch))
                    return 'Z' - ('Z' - ch + shift) % 0x1A;
                else
                    return 'z' - ('z' - ch + shift) % 0x1A;
            } else if (isdigit(ch))
                return '9' - ('9' - ch + shift) % 0xA;
        } return ch; // Return the character unchanged if it's not alphanumeric
    }

public:
    EncryptableString(const std::string &str) : data(str) {}

    void encrypt(const std::string &salt) {
        for (char &ch : data) ch = getSuccessor(ch, salt);
    }

    void decode(const std::string &salt) {
        for (char &ch : data) ch = getPredecessor(ch, salt);
    }
    // Typically [\x33\x58\x50\x4c\x30\x31\x37\x5f\x4e\x34\x54\x30] is normal escaped hex, just adding some Sp00kin3ss to it.
    std::string encodeToEscapedHex() const {
        std::stringstream ss{};
        for (const char &ch : data)
            ss << "\\x00" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ch);
        return ss.str();
    }

    static std::string decodeFromEscapedHex(const std::string &escapedHexString) {
        std::string decoded{};
        std::stringstream ss(escapedHexString);
        std::string hexSequence{};
        while (getline(ss, hexSequence, '\\')) {
            if (!hexSequence.empty() && hexSequence.substr(0, 1) == "x" && hexSequence.length() > 3) {
                hexSequence = hexSequence.substr(1); // Remove the 'x' from the sequence
                unsigned int value{};
                std::stringstream hexSS(hexSequence);
                hexSS >> std::hex >> value;
                decoded += static_cast<char>(value);
            } else decoded += hexSequence;
        } return decoded;
    }

    std::string getData() const { return data; }

    void clearData() {
        if (!data.empty()) {
            std::fill(data.begin(), data.end(), '\0');
            data.resize(0);
        }
    }

    void clearSalt() {
        if (!salt.empty()) {
            std::fill(salt.begin(), salt.end(), '\0');
            salt.resize(0);
        }
    }
};
// You could build a simple chat client, that encrypts and decrypts these hexes real time - so in a pcap, it wouldn't show plaintext.
int main(void) {
    std::string salt = "3XPL017_N4T0";
    //std::cout << "Enter a salt for encryption: ";
    //std::getline(std::cin, salt);

    std::string input{}; // Feel Free To Write Any-Sized Sentence!
    std::cout << "Enter a string to encrypt: ";
    std::getline(std::cin, input);

    EncryptableString encrypted(input);
    encrypted.encrypt(salt);
    std::string escapedHex = encrypted.encodeToEscapedHex();
    encrypted.clearData(); // Clear sensitive data.
    std::cout << "(Escaped Hex) The encrypted string:\n\n" << escapedHex << "\n-----------------" << std::endl;
    // Decoding.
    EncryptableString decoded = EncryptableString::decodeFromEscapedHex(escapedHex);
    decoded.decode(salt);
    std::cout << "Decoded and decrypted string:\n" << decoded.getData() << std::endl;
    decoded.clearData(); // Clear sensitive data.
    decoded.clearSalt();
    return 0;
}
// [PoC]: To Prove It Works, And Doesn't Just Encrypt/Decrypt Normally, use this to check:
// https://codepen.io/kamakalolii/pen/RKNoMr
