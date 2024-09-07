#include "cipher.h"

VigenereCipher::VigenereCipher() {
    for (int i = 0; i < VigenereCipher::SIZE; i++) {
        for (int j = 0; j < VigenereCipher::SIZE; j++) {
            lookup_table[i][j] = 'A' + ((i + j) % VigenereCipher::SIZE);
        }
    }
}

std::string VigenereCipher::key_to_key_stream(int length, std::string key) {
    if (length < key.size()) {
        key = key.substr(0, length);
        return key;
    }
    int repeat_all = length / key.size();
    std::string result;
    while (repeat_all > 0) {
        result += key;
        repeat_all--;
    }
    int repeat_char = length % key.size();
    for (int i = 0; i < repeat_char; i++) {
        result += key.at(i);
    }
    return result;
}

void VigenereCipher::encode(std::string plain_text, std::string key) {

}

void VigenereCipher::decode(std::string cipher_text, std::string key) {

}

void VigenereCipher::break_cipher(std::string cipher_text, int key_length) {

}