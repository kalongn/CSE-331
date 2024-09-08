#include "cipher.h"

VigenereCipher::VigenereCipher() {}

std::string VigenereCipher::simplify_text(const std::string &input) {
    int n = input.size();
    std::string result;
    for (auto i = 0; i < n; i++) {
        char current_character = input.at(i);
        if (isalpha(current_character)) {
            result.push_back(toupper(current_character));
        }
    }
    return result;
}

std::vector<std::string> VigenereCipher::split_columns(const std::string &cipher_text, int key_length) {
    std::vector<std::string> result(key_length);
    for (size_t i = 0; i < cipher_text.length(); i++) {
        result[i % key_length] += cipher_text[i];
    }
    return result;
}


std::string VigenereCipher::caesar_shift(const std::string &column, int shift) {
    std::string result;
    for (char c : column) {
        result.push_back((c - shift - 'A' + 26) % 26 + 'A');
    }
    return result;
}

std::map<char, double> VigenereCipher::find_relative_frequency(const std::string &decoded_column) {
    std::map<char, int> freq;
    int length_of_text = decoded_column.size();
    for (char c : decoded_column) {
        freq[c]++;
    }
    std::map<char, double> result;
    for (auto &pair : freq) {
        result[pair.first] = 1.0 * pair.second / length_of_text;
    }
    return result;
}

double VigenereCipher::chi_squared_test(const std::map<char, double> &relative_frequency) {
    double result = 0.0;
    for (auto &pair : ENGLISH_LETTER_FREQ) {
        char exp_char = pair.first;
        double obs_freq = relative_frequency.count(exp_char) > 0 ? relative_frequency.at(exp_char) : 0.0;
        double exp_freq = pair.second;
        result += pow(obs_freq - exp_freq, 2) / exp_freq;
    }
    return result;
}


char VigenereCipher::find_key(const std::string &column) {
    double min_chi_squared = MAXFLOAT;
    char best_shift = 0;
    for (auto shift = 0; shift < ALPHABET_SIZE; shift++) {
        std::map<char, double> rel_freq = find_relative_frequency(caesar_shift(column, shift));
        double chi_square = chi_squared_test(rel_freq);
        if (chi_square < min_chi_squared) {
            min_chi_squared = chi_square;
            best_shift = shift;
        }
    }
    return best_shift + 'A';
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
    if (key_length == 0) {
        // need to iterate each key length (brute force)
        return "";
    }
    std::vector<std::string> columns = split_columns(simple_text, key_length);
    std::string predict_key;
    for (auto const &column : columns) {
        predict_key.push_back(find_key(column));
    }
    return decode(cipher_text, predict_key);
}