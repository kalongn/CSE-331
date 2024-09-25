#include "cracker.h"
using namespace std;

PasswordCracker::PasswordCracker() {};

string PasswordCracker::compute_MD5(const string &input) {
    EVP_MD_CTX *mdctx;
    unsigned char *md5_digest;
    unsigned int md5_digest_len = EVP_MD_size(EVP_md5());

    // MD5_Init
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);

    // MD5_Update
    EVP_DigestUpdate(mdctx, input.c_str(), input.length());

    // MD5_Final
    md5_digest = (unsigned char *)OPENSSL_malloc(md5_digest_len);
    EVP_DigestFinal_ex(mdctx, md5_digest, &md5_digest_len);
    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < md5_digest_len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md5_digest[i]);
    }
    OPENSSL_free(md5_digest);
    return ss.str();
}

int PasswordCracker::read_csv_file(const string &path) {
    input_file.open(path);
    if (!input_file.is_open()) {
        cerr << "Error opening input file" << endl;
        return 1;
    }
    string line;

    while (getline(input_file, line)) {
        vector<std::string> row;
        stringstream ss(line);
        string cell;

        while (getline(ss, cell, ',')) {
            row.push_back(cell);
        }

        data.push_back(row);
    }
    input_file.close();
    return 0;
}

void PasswordCracker::generate_string_bf(string current) {
    if (current.length() > 0) {
        string hashed = compute_MD5(current);
        {
            unique_lock<std::mutex> lock(mutex);
            hashed_to_password[hashed] = current;
        }
    }
    if (current.length() == MAX_BRUTE_LENGTH) {
        return;
    }
    for (char c : VALID_CHARS) {
        generate_string_bf(current + c);
    }
}

void PasswordCracker::worker_task_bf(int begin, int end) {
    for (int i = begin; i < end; ++i) {
        generate_string_bf(string(1, VALID_CHARS[i]));
    }
}

void PasswordCracker::brute_force(const string &path) {
    if (read_csv_file(path)) {
        return;
    }

    auto start_time = chrono::high_resolution_clock::now();

    vector<thread> threads;

    threads.emplace_back(bind(&PasswordCracker::worker_task_bf, this, 0, 16));
    threads.emplace_back(bind(&PasswordCracker::worker_task_bf, this, 16, 32));
    threads.emplace_back(bind(&PasswordCracker::worker_task_bf, this, 32, 48));
    threads.emplace_back(bind(&PasswordCracker::worker_task_bf, this, 48, VALID_CHARS_LENGTH));

    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    output_file.open("output/task1.csv");
    if (!output_file.is_open()) {
        cerr << "Error opening output file" << endl;
        return;
    }

    int success = 0;
    for (auto line : data) {
        string hashed_password = line.at(1);
        if (hashed_to_password.count(hashed_password)) {
            output_file << line.at(0).c_str() << ' ' << hashed_to_password[hashed_password].c_str() << '\n';
            ++success;
        } else {
            output_file << "FAILED\n";
        }
    }
    auto current_time = chrono::high_resolution_clock::now();
    output_file << "TOTALTIME [" << chrono::duration_cast<chrono::seconds>(current_time - start_time).count() << "]\n";
    output_file << "SUCCESSRATE [" << setprecision(2) << fixed << (double)success / data.size() * 100 << "%]" << endl;
    output_file.close();
}