#include "cipher.h"

VigenereCipher::VigenereCipher() {}

std::string VigenereCipher::simplify_text(const std::string &input) {
    int n = input.size();
    std::string result;
    for (auto i = 0; i < n; i++) {
        char current_character = input.at(i);
        if (isalpha(current_character)) {
            result.push_back(tolower(current_character));
        }
    }
    return result;
}

std::vector<std::string> VigenereCipher::split_text(const std::string &input, int split_length) {
    int substrings_count = input.length() / split_length;
    std::vector<std::string> result;
    for (auto i = 0; i < substrings_count; i++) {
        result.push_back(input.substr(i * split_length, split_length));
    }
    if (input.length() % split_length != 0) {
        result.push_back(input.substr(split_length * substrings_count));
    }
    return result;
}


std::string VigenereCipher::encode(const std::string &plain_text, const std::string &key) {
    const int plain_text_length = plain_text.size();
    const int key_length = key.size();

    std::string result;
    int index_of_key = 0;
    for (auto i = 0; i < plain_text_length; i++) {
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

std::string VigenereCipher::decode(const std::string &cipher_text, const std::string &key) {
    const int cipher_text_length = cipher_text.size();
    const int key_length = key.size();

    std::string result;
    int index_of_key = 0;
    for (auto i = 0; i < cipher_text_length; i++) {
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

std::string VigenereCipher::break_cipher(const std::string &cipher_text, int key_length) {
    std::string simple_text = simplify_text(cipher_text);
    std::map<char, int> freq;
    const int simple_text_length = simple_text.size();
    for (auto i = 0; i < simple_text_length; i++) {
        char current_character = simple_text.at(i);
        if (isalpha(current_character)) {
            freq[tolower(current_character)]++;
        }
    }
    if (key_length == 0) {
        // need to iterate each key length (brute force)
        return "";
    }
    std::vector<std::string> splitted = split_text(simple_text, key_length);

    return "";
}