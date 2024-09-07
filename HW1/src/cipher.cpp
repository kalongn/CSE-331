#include "cipher.h"

VigenereCipher::VigenereCipher() {}

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
                result.push_back(tolower(((toupper(current_character) + current_key_character) % ALPHABET_SIZE) + 'A'));
            } else {
                result.push_back(((current_character + current_key_character) % ALPHABET_SIZE) + 'A');
            }
            index_of_key = (index_of_key + 1) % key_length;
        } else {
            result.push_back(current_character);
        }
    }
    return result;
}

std::string VigenereCipher::decode(std::string cipher_text, std::string key) {
    const int cipher_text_length = cipher_text.size();
    const int key_length = key.size();

    std::string result;
    int index_of_key = 0;
    for (int i = 0; i < cipher_text_length; i++) {
        char current_character = cipher_text.at(i);
        if (isalpha(current_character)) {
            char current_key_character = key.at(index_of_key);
            if (islower(current_character) > 0) {
                result.push_back(tolower(((toupper(current_character) - current_key_character + ALPHABET_SIZE) % ALPHABET_SIZE) + 'A'));
            } else {
                result.push_back(((current_character - current_key_character + ALPHABET_SIZE) % ALPHABET_SIZE) + 'A');
            }
            index_of_key = (index_of_key + 1) % key_length;
        } else {
            result.push_back(current_character);
        }
    }
    return result;
}

std::string VigenereCipher::break_cipher(std::string cipher_text, int key_length) {

}