#pragma once
#ifndef CRACKER_H
#define CRACKER_H

#include <string>
#include <vector>
#include <unordered_set>
#include <map>
#include <unordered_map>

#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>

#include <iomanip>
#include <iostream>
#include <fstream>
#include <sstream>

#include <utility>
#include <algorithm>
#include <openssl/evp.h>

using namespace std;
class PasswordCracker {
private:
    const static int SALT_LENGTH = 4;
    const static int MAX_BRUTE_LENGTH = 4;
    const string VALID_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const string VALID_NUM_CHARS = "0123456789";
    const int VALID_CHARS_LENGTH = VALID_CHARS.length();

    ifstream input_file;
    ofstream output_file;

    vector<vector<string>> data; // stored the stuff read from input csv file to here

    vector<string> common_password; // stored all the common password from csv file in rsrc

    unordered_map<string, string> hashed_to_password; // essentially the rainbow table
    std::mutex mutex;
    std::mutex print_mutex;

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
     * @param string_set
     *      the string set of character you want to use.
     * @param storage
     *      The vector you want to stored all the generation possible.
     */
    void generate_string(const string &current, const string &string_set, vector<string> &storage);

    /**
     * @brief Generate all the variation to uppercase a string.
     *
     * @param original_string
     *      The original string (the input original string).
     * @param current_string
     *      This is for the recursive call to know the previous call string.
     * @param index
     *      This is also for recursive call to indicate which index of the original string we're at.
     * @param storage
     *      The set is a storage to put all the results in.
     */
    void generate_uppercase(const string &original_string, string current_string, size_t index, unordered_set<string> &storage);

    /**
     * @brief Generate all the character swap possible for a string.
     * @details
     *      e -> 3,
     *      o -> 0,
     *      t -> 7
     *
     * @param original_string
     *      The original string (the input original string).
     * @param storage
     *      The set is a storage to put all the results in.
     */
    void generate_swap(const string &original_string, unordered_set<string> &storage);

    /**
     * @brief This is a thread function which allow us to divide all the 10,000 common password into smaller chunk for
     *      faster time computing all the MD5 hash by bruteforce.
     *
     * @param begin
     *      the index of the common_password we want to start with.
     * @param end
     *      the index of the common_password we want to stop at.
     */
    void worker_task_cp_rbtb(const int &begin, const int &end);

    /**
     * @brief Read from data vector to determine all the unique salt present in the file
     * @details a short cut instead of generating the large rainbow table if we know what salts are present
     *
     * @param storage
     *      The unordered_set you want to stored all the generation possible.
     */
    void obtain_salt(unordered_set<string> &storage);

    /**
     * @brief This is a thread function which allow us to divide all the 10,000 common password into smaller chunk for
     *      faster time computing all the MD5 hash.
     *
     * @param begin
     *      the index of the common_password we want to start with.
     * @param end
     *      the index of the common_password we want to stop at.
     * @param all_salts
     *      All the salts we've seen from input.
     */
    void worker_task_salt_cp_rbtb(const int &begin, const int &end, const unordered_set<string> &all_salts);

    void worker_task_salt_transform(const int &begin, const int &end,
        const unordered_set<string> &all_salts,
        const vector<string> &all_4_digits,
        const unordered_map<string, vector<int>> &target_index_map,
        vector<string> &target_hashes,
        atomic_int &successes
    );


public:
    /**
     * @brief Construct a new Password Cracker object.
     *
     */
    PasswordCracker();

    /**
     * @brief Attempt to brute force for all unsalted hashed password with <= 4 letter in length.
     * @details Task 1 Code. This function will also write an output file to task1.csv
     *
     * @param path
     *      The relative path to the file of password we are reading from.
     */
    void brute_force(const string &path);

    /**
     * @brief Attempt to brute force for all unsalted hashed password that're in the 10,000 most common
     *      password.
     * @details Task 2 Code. This function will also write an ouput file to task2.csv
     * @param path
     *      The relative path to the file of password we're reading from.
     *
     */
    void common_password_bf(const string &path);

    /**
     * @brief Attempt to use a rainbow table for all unsalted hashed password that're in the 10,000 most common
     *      password.
     * @details Task 3 Code. This function will also write an output file to task3.csv
     *
     * @param path
     *      The relative path to the file of password we're reading from.
     */
    void common_password_rbtb(const string &path);

    /**
     * @brief Attempt to use a rainbow table for detected salt hashed password that're in the 10,000 most common
     *      password.
     * @details Task 4 Code. This function will also write an output file to task4.csv
     *
     * @param path
     *      The relative path to the file of password we're reading from.
     */
    void common_password_salt_rbtb(const string &path);

    /**
     * @brief Attempt to crack a salted data base with transformation applied to the password 10,000 list.
     * @details Task 5 code. This function will also write an output file to task5.csv
     *
     * @param path
     *      The relative path to the file of password we're reading from.
     */
    void common_password_salt_transform(const string &path);

};

#endif