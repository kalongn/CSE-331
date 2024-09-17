#pragma once
#ifndef CIPHER_H
#define CIPHER_H

#include <iostream>
#include <string>
#include <utility>
#include <vector>
#include <map>

class VigenereCipher {
private:
    const static int ALPHABET_SIZE = 26;
    const double ENGLISH_INDEX_COINCIDENCE = 1.73;
    const double ENGLISH_INDEX_COINCIDENCE_LB = ENGLISH_INDEX_COINCIDENCE - ENGLISH_INDEX_COINCIDENCE * 0.1;
    const std::map<char, double> ENGLISH_LETTER_FREQ = {
        {'A', 0.082}, {'B', 0.015}, {'C', 0.028}, {'D', 0.043}, {'E', 0.127},
        {'F', 0.022}, {'G', 0.02}, {'H', 0.061}, {'I', 0.07}, {'J', 0.0015},
        {'K', 0.0077}, {'L', 0.04}, {'M', 0.024}, {'N', 0.067}, {'O', 0.075},
        {'P', 0.019}, {'Q', 0.00095}, {'R', 0.06}, {'S', 0.063}, {'T', 0.091},
        {'U', 0.028}, {'V', 0.0098}, {'W', 0.024}, {'X', 0.0015}, {'Y', 0.02},
        {'Z', 0.00074}
    };

    /**
     * @brief Return the simplify string that only consist of alphabet characters.
     *
     * @param input
     *      The input string you want to simplify.
     * @return std::string
     *      the simplify string
     */
    std::string simplify_text(const std::string &input);

    /**
     * @brief Split text by columns such that every ith character of the key_length is in the same string.
     *
     * @param cipher_text
     *      The input should be a ciper text.
     * @param key_length
     *      The length of the key.
     * @return std::vector<std::string>
     *      The vector of columns of strings.
     */
    std::vector<std::string> split_columns(const std::string &cipher_text, int key_length);

    /**
     * @brief Solving a monotonic shift aka caesar_shift.
     *
     * @param column
     *      The column of the cipher text provided.
     * @param shift
     *      The shift we need to shift these letters by.
     * @return std::string
     *      return the column after shifted.
     */
    std::string caesar_shift(const std::string &column, int shift);

    /**
     * @brief Return the relative frequency of the characters of the decoded column.
     *
     * @param decoded_column
     *      The column text after passing into a caesar_shift.
     * @return std::map<char, double>
     *      The relative frequency in a map.
     */
    std::map<char, double> find_relative_frequency(const std::string &decoded_column);

    /**
     * @brief Return the double value of a chi squared test.
     *
     * @details The chi square test is comparing the english language distribution (found on the internet) to the one
     *          after we shifted and trying to find the best match via the chi squared goodness of fit test.
     *
     * @param relative_frequency
     *      The actual relative frequency of the english alphabet character.
     * @return double
     *      The chi squared value we obtain from this fitness test.
     */
    double chi_squared_test(const std::map<char, double> &relative_frequency);

    /**
     * @brief Find the most appropriate character for the specific column of cipher text.
     *
     * @param column
     *      The indiviual column of the ciphertext.
     * @return char
     *      The character that this column is shifted by.
     */
    char find_key(const std::string &column);

    /**
     * @brief Calculate the index of coincidence of a column.
     *
     * @param column
     *      The indiviual column of the ciphertext.
     * @return double
     *      The value of the index of coincidence
     */
    double calculate_index_of_coincidence(const std::string &column);


public:

    /**
     * @brief Construct a new Vigenere Cipher object.
     *
     */
    VigenereCipher();

    /**
     * @brief Encode a plain text with the key given and print out the cipher text.
     *
     * @param plain_text
     *      The input plain text that needs to be encode.
     * @param key
     *      The key that this input plain text will encode with.
     *
     * @return std::string
     *      The encoded cipher text.
     */
    std::string encode(const std::string &plain_text, const std::string &key);

    /**
     * @brief Decode a cipher text with the key given and print out the plain text.
     *
     * @param cipher_text
     *      The input cipher text that needs to be decode.
     * @param key
     *      The key that this input cipher text will decode with.
     *
     * @return std::string
     *      The decoded cipher text.
     */
    std::string decode(const std::string &cipher_text, const std::string &key);

    /**
     * @brief Break a cipher text into plain text doing frequency analysis and print out the plain text.
     *
     * @param cipher_text
     *      The input cipher text that needs to be break.
     * @param key_length
     *      The optional parameter of providing the length of the key, default to 0 means no key length provided.
     *
     * @return std::string
     *      The brute force decoded cipher text.
     */
    std::string break_cipher(const std::string &cipher_text, int key_length = 0);
};

#endif