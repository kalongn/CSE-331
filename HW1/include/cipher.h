#pragma once
#ifndef CIPHER_H
#define CIPHER_H

#include <iostream>
#include <string>
#include <utility>
#include <map>

class VigenereCipher {
private:
    char lookup_table[26][26];

public:
    // 26 letters in the english alphabet
    const static int SIZE = 26;

    /**
     * @brief Construct a new Vigenere Cipher object which created the lookup_table.
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
    std::string encode(std::string plain_text, std::string key);

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
    std::string decode(std::string cipher_text, std::string key);

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
    std::string break_cipher(std::string cipher_text, int key_length = 0);
};

#endif