#pragma once
#ifndef CRACKER_H
#define CRACKER_H

#include <string>
#include <utility>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <sstream>

#include <openssl/evp.h>

using namespace std;
class PasswordCracker {
private:
    const static int SALT_LENGTH = 4;
    const static int MAX_BRUTE_LENGTH = 4;
    const string VALID_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const int VALID_CHARS_LENGTH = VALID_CHARS.length();

    ifstream input_file;
    ofstream output_file;

    vector<vector<string>> data; // stored the stuff read from input csv file to here

    vector<string> common_password; // stored all the common password from csv file in rsrc

    unordered_map<string, string> hashed_to_password; // essentially the rainbow table
    std::mutex mutex;

    /**
     * @brief Compute the MD5 hashes for for the input string, and return a string of the hash.
     *
     * @param input
     *      The input string.
     * @return std::string
     *      The hashed output string.
     */
    string compute_MD5(const string &input);

    /**
     * @brief Read the input csv file given the path.
     *
     * @details Each line will be stored in data vector.
     *
     * @param path
     *      The relative path during execution to the file.
     * @return int
     *      0 == execute successfully, 1 == file cannot open.
     */
    int read_csv_file(const string &path);

    /**
     * @brief Read the rsrc common_passwords.csv file.
     *
     * @details
     *      Assume file under rsrc/common_passwords.csv exist.
     *
     * @return int
     *      0 == execute successfully, 1 == file cannot open.
     */
    int read_common_password_file();

    /**
     * @brief Generate string up to certain length with all combination.
     * @details This is a recursive methods.
     *
     * @param current
     *      the current String of where it is, to start the recurions use "" as input.
     * @param storage
     *      The vector you want to stored all the generation possible.
     */
    void generate_string(string current, vector<string> &storage);

    /**
     * @brief This is a thread function which allow us to divide all the 10,000 common password into smaller chunk for
     *      faster time computing all the MD5 hash by bruteforce.
     *
     * @param begin
     *      the index of the common_password we want to start with.
     * @param end
     *      the index of the common_password we want to stop at.
     */
    void worker_task_cp_rbtb(int begin, int end);

public:
    /**
     * @brief Construct a new Password Cracker object.
     *
     */
    PasswordCracker();

    /**
     * @brief Attempt to brute force for all unsalted hashed password with <= 4 letter in length.
     * @details Task 1 Code. This function will also write an output file to output/task1.csv
     *
     * @param path
     *      The relative path to the file of password we are reading from.
     */
    void brute_force(const string &path);

    /**
     * @brief Attempt to brute force for all unsalted hashed password that're in the 10,000 most common
     *      password.
     * @details Task 3 Code. This function will also write an output file to  output/task3.csv
     *
     * @param path
     *      The relative path to the file of password we're reading from.
     */
    void common_password_rbtb(const string &path);

};

#endif