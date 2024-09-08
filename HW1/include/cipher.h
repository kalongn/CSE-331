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
     * @brief Return the a vector of splitted strings each having split_length.
     * 
     * @details The last one may not have the exact same size by within the range of [1, split_length].
     * 
     * @param input 
     *      The input string you want to be splitted.
     * @param split_length 
     *      The amount of character in each split string.
     * @return std::vector<std::string> 
     *      The vector of string with each split string as elements.
     */
    std::vector<std::string> split_text(const std::string &input, int split_length);

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