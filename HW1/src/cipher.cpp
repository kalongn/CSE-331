#include "cipher.h"

VigenereCipher::VigenereCipher() {
    for (int i = 0; i < VigenereCipher::SIZE; i++) {
        for (int j = 0; j < VigenereCipher::SIZE; j++) {
            lookup_table[i][j] = 'A' + ((i + j) % VigenereCipher::SIZE);
        }
    }
}

}

void VigenereCipher::encode(std::string plain_text, std::string key) {

}

void VigenereCipher::decode(std::string cipher_text, std::string key) {

}

void VigenereCipher::break_cipher(std::string cipher_text, int key_length) {

}