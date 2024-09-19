#include "cipher.h"
using namespace std;

VigenereCipher::VigenereCipher() {}

string VigenereCipher::simplify_text(const string &input) {
    int n = input.size();
    string result;
    for (auto i = 0; i < n; i++) {
        char current_character = input.at(i);
        if (isalpha(current_character)) {
            result.push_back(toupper(current_character));
        }
    }
    return result;
}

vector<string> VigenereCipher::split_columns(const string &cipher_text, int key_length) {
    vector<string> result(key_length);
    for (size_t i = 0; i < cipher_text.length(); i++) {
        result[i % key_length] += cipher_text[i];
    }
    return result;
}


string VigenereCipher::caesar_shift(const string &column, int shift) {
    string result;
    for (char c : column) {
        result.push_back((c - shift - 'A' + 26) % 26 + 'A');
    }
    return result;
}

map<char, double> VigenereCipher::find_relative_frequency(const string &decoded_column) {
    map<char, int> freq;
    int length_of_text = decoded_column.size();
    for (char c : decoded_column) {
        freq[c]++;
    }
    map<char, double> result;
    for (auto &pair : freq) {
        result[pair.first] = 1.0 * pair.second / length_of_text;
    }
    return result;
}

double VigenereCipher::chi_squared_test(const map<char, double> &relative_frequency) {
    double result = 0.0;
    for (auto &pair : ENGLISH_LETTER_FREQ) {
        char exp_char = pair.first;
        double obs_freq = relative_frequency.count(exp_char) > 0 ? relative_frequency.at(exp_char) : 0.0;
        double exp_freq = pair.second;
        result += pow(obs_freq - exp_freq, 2) / exp_freq;
    }
    return result;
}


char VigenereCipher::find_key(const string &column) {
    double min_chi_squared = MAXFLOAT;
    char best_shift = 0;
    for (auto shift = 0; shift < ALPHABET_SIZE; shift++) {
        map<char, double> rel_freq = find_relative_frequency(caesar_shift(column, shift));
        double chi_square = chi_squared_test(rel_freq);
        if (chi_square < min_chi_squared) {
            min_chi_squared = chi_square;
            best_shift = shift;
        }
    }
    return best_shift + 'A';
}

double VigenereCipher::calculate_index_of_coincidence(const string &column) {
    vector<int> freq(ALPHABET_SIZE, 0);
    for (char c : column) {
        freq[toupper(c) - 'A']++;
    }

    double result = 0.0;
    for (auto count : freq) {
        result += count * (count - 1);
    }
    result /= column.size() * (column.size() - 1.0) / ALPHABET_SIZE;
    return result;
}

string VigenereCipher::find_repeat_pattern(const string &input) {
    int n = input.length();

    for (int length = 1; length <= n / 2; length++) {
        if (n % length == 0) {
            string pattern = input.substr(0, length);
            bool is_reapting = true;
            for (int i = length; i < n; i += length) {
                if (input.substr(i, length) != pattern) {
                    is_reapting = false;
                    break;
                }
            }
            if (is_reapting) {
                return pattern;
            }
        }
    }
    return input;
}


string VigenereCipher::encode(const string &plain_text, const string &key) {
    const int plain_text_length = plain_text.size();
    const int key_length = key.size();

    string result;
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

string VigenereCipher::decode(const string &cipher_text, const string &key) {
    const int cipher_text_length = cipher_text.size();
    const int key_length = key.size();

    string result;
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

string VigenereCipher::break_cipher(const string &cipher_text, int key_length) {
    if (cipher_text == "") {
        return cipher_text;
    }
    string simple_text = simplify_text(cipher_text);
    if (key_length == 0) {
        key_length = 1;
        while (true) {
            vector<string> columns = split_columns(simple_text, key_length);
            double aggregate_IC = 0.0;
            for (size_t i = 0; i < columns.size(); i++) {
                aggregate_IC += calculate_index_of_coincidence(columns.at(i));
            }
            aggregate_IC /= key_length;
            if (isnan(aggregate_IC)) {
                cout << "Cannot break the cipher text. \nReason: cannot identify the key length using index of coincidence.\n";
                return "";
            }
            if (aggregate_IC >= ENGLISH_INDEX_COINCIDENCE_LB) {
                break;
            }
            key_length++;
        }
    }

    string predict_key, output;
    vector<string> columns = split_columns(simple_text, key_length);
    for (auto const &column : columns) {
        predict_key.push_back(find_key(column));
    }
    predict_key = find_repeat_pattern(predict_key);
    output = decode(cipher_text, predict_key);
    return predict_key + '\n' + output;
}