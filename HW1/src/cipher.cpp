#include "cipher.h"

VigenereCipher::VigenereCipher() {
    for (int i = 0; i < VigenereCipher::SIZE; i++) {
        for (int j = 0; j < VigenereCipher::SIZE; j++) {
            lookup_table[i][j] = 'A' + ((i + j) % VigenereCipher::SIZE);
        }
    }
}

std::string VigenereCipher::encode(std::string plain_text, std::string key) {
    const int plain_text_length = plain_text.size();
    const int key_length = key.size();

    std::string result;
    int index_of_key = 0;
    for (int i = 0; i < plain_text_length; i++) {
        char current_character = plain_text.at(i);
        if (isalpha(current_character)) {
            char current_key_character = key.at(index_of_key);
            if (islower(current_character) > 0) {
                result += tolower(lookup_table[toupper(current_character) - 'A'][current_key_character - 'A']);
            } else {
                result += lookup_table[current_character - 'A'][current_key_character - 'A'];
            }
            index_of_key = (index_of_key + 1) % key_length;
        } else {
            result += current_character;
        }
    }
    return result;
}

std::string VigenereCipher::decode(std::string cipher_text, std::string key) {

}

std::string VigenereCipher::break_cipher(std::string cipher_text, int key_length) {

}