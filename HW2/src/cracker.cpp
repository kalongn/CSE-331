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

int PasswordCracker::read_common_password_file() {
    input_file.open("./rsrc/common_passwords.csv");
    if (!input_file.is_open()) {
        cerr << "Error opening input file" << endl;
        return 1;
    }
    string line;
    while (getline(input_file, line)) {
        common_password.push_back(line);
    }
    input_file.close();
    return 0;
}

void PasswordCracker::generate_string(const string &current, const string &string_set, vector<string> &storage) {
    if (current.length() > 0) {
        storage.push_back(current);
    }
    if (current.length() == MAX_BRUTE_LENGTH) {
        return;
    }
    for (char c : string_set) {
        generate_string(current + c, string_set, storage);
    }
}

void PasswordCracker::generate_uppercase(const string &original_string, string current_string, size_t index, unordered_set<string> &storage) {
    if (index == original_string.size()) {
        storage.insert(current_string);
        return;
    }
    current_string.push_back(tolower(original_string[index]));
    generate_uppercase(original_string, current_string, index + 1, storage);

    if (isalpha(original_string[index])) {
        current_string.back() = toupper(original_string[index]);
        generate_uppercase(original_string, current_string, index + 1, storage);
    }
}

void PasswordCracker::generate_swap(const string &original_string, unordered_set<string> &storage) {
    // Lambda function to do the recursion as needs to update the uppercase now too, manual coding all ways
    // like before will be too much works.
    function<void(string &, int)> generate_combinations = [&](string &current_string, int index) {
        if ((size_t)index == current_string.length()) {
            storage.insert(current_string);
            return;
        }
        // no sub
        generate_combinations(current_string, index + 1);

        char original_char = current_string[index];
        if (original_char == 'e' || original_char == 'E') {
            current_string[index] = '3';
            generate_combinations(current_string, index + 1);
        } else if (original_char == 'o' || original_char == 'O') {
            current_string[index] = '0';
            generate_combinations(current_string, index + 1);
        } else if (original_char == 't' || original_char == 'T') {
            current_string[index] = '7';
            generate_combinations(current_string, index + 1);
        }
        current_string[index] = original_char;
        };
    string dup = original_string;
    generate_combinations(dup, 0);
}

void PasswordCracker::worker_task_cp_rbtb(const int &begin, const int &end) {
    for (int i = begin; i < end; ++i) {
        string hashed = compute_MD5(common_password.at(i));
        {
            unique_lock<std::mutex> lock(mutex);
            hashed_to_password[hashed] = common_password.at(i);
        }
    }
}

void PasswordCracker::obtain_salt(unordered_set<string> &storage) {
    for (auto line : data) {
        storage.insert(line.at(2));
    }
}

void PasswordCracker::worker_task_salt_cp_rbtb(const int &begin, const int &end, const unordered_set<string> &all_salts) {
    for (int i = begin; i < end; ++i) {
        for (auto salt : all_salts) {
            string hashed = compute_MD5(common_password.at(i) + salt);
            {
                unique_lock<std::mutex> lock(mutex);
                hashed_to_password[hashed] = common_password.at(i);
            }
        }
    }
}

void PasswordCracker::worker_task_salt_transform(const int &begin, const int &end,
    const unordered_set<string> &all_salts,
    const vector<string> &all_4_digits,
    const unordered_map<string, vector<int>> &target_index_map,
    vector<string> &target_hashes,
    atomic_int &success
) {
    for (int i = begin; i < end; ++i) {
        {
            unique_lock<std::mutex> lock(print_mutex);
            cout << this_thread::get_id() << ", Checking all transformation of \"" << common_password.at(i) << "\"" << endl;
            cout.flush();
        }
        unordered_set<string> transformed_set;
        generate_uppercase(common_password.at(i), "", 0, transformed_set);
        for (auto str : transformed_set) {
            generate_swap(str, transformed_set);
        }
        for (auto str : transformed_set) {
            for (auto digits : all_4_digits) {
                for (auto salt : all_salts) {
                    string hash = compute_MD5(str + digits + salt);
                    if (target_index_map.count(hash)) {
                        {
                            unique_lock<std::mutex> lock(mutex);
                            for (auto i : target_index_map.at(hash)) {
                                if (target_hashes[i] == "") {
                                    target_hashes[i] = str + digits;
                                    ++success;
                                }
                            }
                        }
                    }
                    if ((size_t)success == target_hashes.size()) {
                        goto end;
                    }
                }
            }
        }
    }
end:;
}

void PasswordCracker::brute_force(const string &path) {
    auto start_time = chrono::high_resolution_clock::now();
    if (read_csv_file(path)) {
        return;
    }
    output_file.open("task1.csv");
    if (!output_file.is_open()) {
        cerr << "Error opening output file" << endl;
        return;
    }
    vector<string> all_4_chars;
    generate_string("", VALID_CHARS, all_4_chars);

    vector<string> all_hashes(data.size());
    unordered_map<string, vector<int>> index_map(data.size());

    for (size_t i = 0; i < data.size(); ++i) {
        index_map[data[i][1]].push_back(i);
    }

    int success = 0;
    for (auto str : all_4_chars) {
        string hash = compute_MD5(str);
        if (index_map.count(hash)) {
            for (auto i : index_map[hash]) {
                all_hashes[i] = str;
                ++success;
            }
            if ((size_t)success == all_hashes.size()) {
                break;
            }
        }
    }

    for (size_t i = 0; i < data.size(); ++i) {
        if (all_hashes[i] == "") {
            output_file << "FAILED\n";
        } else {
            output_file << data[i][0].c_str() << ',' << all_hashes[i].c_str() << '\n';
        }
    }
    auto current_time = chrono::high_resolution_clock::now();
    output_file << "TOTALTIME [" << chrono::duration_cast<chrono::seconds>(current_time - start_time).count() << "]\n";
    output_file << "SUCCESSRATE [" << setprecision(2) << fixed << (double)success / data.size() * 100 << "%]" << endl;
    output_file.close();
}

void PasswordCracker::common_password_bf(const string &path) {
    auto start_time = chrono::high_resolution_clock::now();
    if (read_csv_file(path)) {
        return;
    }
    if (read_common_password_file()) {
        return;
    }

    output_file.open("task2.csv");
    if (!output_file.is_open()) {
        cerr << "Error opening output file" << endl;
        return;
    }

    vector<string> all_hashes(data.size());
    unordered_map<string, vector<int>> index_map(data.size());

    for (size_t i = 0; i < data.size(); ++i) {
        index_map[data[i][1]].push_back(i);
    }

    int success = 0;
    for (auto common : common_password) {
        string hash = compute_MD5(common);
        if (index_map.count(hash)) {
            for (auto i : index_map[hash]) {
                all_hashes[i] = common;
                ++success;
            }
            if ((size_t)success == all_hashes.size()) {
                break;
            }
        }
    }

    for (size_t i = 0; i < data.size(); ++i) {
        if (all_hashes[i] == "") {
            output_file << "FAILED\n";
        } else {
            output_file << data[i][0].c_str() << ',' << all_hashes[i].c_str() << '\n';
        }
    }

    auto current_time = chrono::high_resolution_clock::now();
    output_file << "TOTALTIME [" << chrono::duration_cast<chrono::seconds>(current_time - start_time).count() << "]\n";
    output_file << "SUCCESSRATE [" << setprecision(2) << fixed << (double)success / data.size() * 100 << "%]" << endl;
    hashed_to_password.clear();
    output_file.close();
}

void PasswordCracker::common_password_rbtb(const string &path) {
    auto start_time = chrono::high_resolution_clock::now();
    if (read_csv_file(path)) {
        return;
    }
    if (read_common_password_file()) {
        return;
    }
    vector<thread> threads;
    threads.emplace_back(bind(&PasswordCracker::worker_task_cp_rbtb, this, 0, 2500));
    threads.emplace_back(bind(&PasswordCracker::worker_task_cp_rbtb, this, 2500, 5000));
    threads.emplace_back(bind(&PasswordCracker::worker_task_cp_rbtb, this, 5000, 7500));
    threads.emplace_back(bind(&PasswordCracker::worker_task_cp_rbtb, this, 7500, 10000));

    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    output_file.open("task3.csv");
    if (!output_file.is_open()) {
        cerr << "Error opening output file" << endl;
        return;
    }

    int success = 0;
    for (auto line : data) {
        string hashed_password = line.at(1);
        if (hashed_to_password.count(hashed_password)) {
            output_file << line.at(0).c_str() << ',' << hashed_to_password[hashed_password].c_str() << '\n';
            ++success;
        } else {
            output_file << "FAILED\n";
        }
    }
    auto current_time = chrono::high_resolution_clock::now();
    output_file << "TOTALTIME [" << chrono::duration_cast<chrono::seconds>(current_time - start_time).count() << "]\n";
    output_file << "SUCCESSRATE [" << setprecision(2) << fixed << (double)success / data.size() * 100 << "%]" << endl;
    hashed_to_password.clear();
    output_file.close();
}

void PasswordCracker::common_password_salt_rbtb(const string &path) {
    auto start_time = chrono::high_resolution_clock::now();
    if (read_csv_file(path)) {
        return;
    }
    if (read_common_password_file()) {
        return;
    }
    unordered_set<string> all_salts;
    obtain_salt(all_salts);

    vector<thread> threads;
    threads.emplace_back(bind(&PasswordCracker::worker_task_salt_cp_rbtb, this, 0, 2500, all_salts));
    threads.emplace_back(bind(&PasswordCracker::worker_task_salt_cp_rbtb, this, 2500, 5000, all_salts));
    threads.emplace_back(bind(&PasswordCracker::worker_task_salt_cp_rbtb, this, 5000, 7500, all_salts));
    threads.emplace_back(bind(&PasswordCracker::worker_task_salt_cp_rbtb, this, 7500, 10000, all_salts));

    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    output_file.open("task4.csv");
    if (!output_file.is_open()) {
        cerr << "Error opening output file" << endl;
        return;
    }

    int success = 0;
    for (auto line : data) {
        string hashed_password = line.at(1);
        if (hashed_to_password.count(hashed_password)) {
            output_file << line.at(0).c_str() << ',' << hashed_to_password[hashed_password].c_str() << '\n';
            ++success;
        } else {
            output_file << "FAILED\n";
        }
    }
    auto current_time = chrono::high_resolution_clock::now();
    output_file << "TOTALTIME [" << chrono::duration_cast<chrono::seconds>(current_time - start_time).count() << "]\n";
    output_file << "SUCCESSRATE [" << setprecision(2) << fixed << (double)success / data.size() * 100 << "%]" << endl;
    hashed_to_password.clear();
    output_file.close();
}

void PasswordCracker::common_password_salt_transform(const string &path) {
    auto start_time = chrono::high_resolution_clock::now();
    if (read_csv_file(path)) {
        return;
    }
    if (read_common_password_file()) {
        return;
    }
    unordered_set<string> all_salts;
    obtain_salt(all_salts);
    vector<string> all_4_digits;
    generate_string("", VALID_NUM_CHARS, all_4_digits);
    all_4_digits.push_back("");

    vector<thread> threads;
    threads.emplace_back(bind(&PasswordCracker::worker_task_salt_cp_rbtb, this, 0, 2500, all_salts));
    threads.emplace_back(bind(&PasswordCracker::worker_task_salt_cp_rbtb, this, 2500, 5000, all_salts));
    threads.emplace_back(bind(&PasswordCracker::worker_task_salt_cp_rbtb, this, 5000, 7500, all_salts));
    threads.emplace_back(bind(&PasswordCracker::worker_task_salt_cp_rbtb, this, 7500, 10000, all_salts));

    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    threads.clear();

    output_file.open("task5.csv");
    if (!output_file.is_open()) {
        cerr << "Error opening output file" << endl;
        return;
    }

    vector<string> all_hashes(data.size());
    unordered_map<string, vector<int>> index_map(data.size());

    for (size_t i = 0; i < data.size(); ++i) {
        index_map[data[i][1]].push_back(i);
    }

    atomic<int> success(0);
    for (auto hash_pass : hashed_to_password) {
        string hash = hash_pass.first;
        if (index_map.count(hash)) {
            for (auto i : index_map[hash]) {
                all_hashes[i] = hash_pass.second;
                ++success;
            }
            if ((size_t)success == all_hashes.size()) {
                goto output;
            }
        }
    }

    threads.emplace_back(bind(
        &PasswordCracker::worker_task_salt_transform,
        this,
        0,
        2500,
        all_salts,
        all_4_digits,
        index_map,
        ref(all_hashes),
        ref(success)
    ));
    threads.emplace_back(bind(
        &PasswordCracker::worker_task_salt_transform,
        this,
        2500,
        5000,
        all_salts,
        all_4_digits,
        index_map,
        ref(all_hashes),
        ref(success)
    ));
    threads.emplace_back(bind(
        &PasswordCracker::worker_task_salt_transform,
        this,
        5000,
        7500,
        all_salts,
        all_4_digits,
        index_map,
        ref(all_hashes),
        ref(success)
    ));
    threads.emplace_back(bind(
        &PasswordCracker::worker_task_salt_transform,
        this,
        7500,
        10000,
        all_salts,
        all_4_digits,
        index_map,
        ref(all_hashes),
        ref(success)
    ));

    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

output:;
    for (size_t i = 0; i < data.size(); ++i) {
        if (all_hashes[i] == "") {
            output_file << "FAILED\n";
        } else {
            output_file << data[i][0].c_str() << ',' << all_hashes[i].c_str() << '\n';
        }
    }

    auto current_time = chrono::high_resolution_clock::now();
    output_file << "TOTALTIME [" << chrono::duration_cast<chrono::seconds>(current_time - start_time).count() << "]\n";
    output_file << "SUCCESSRATE [" << setprecision(2) << fixed << (double)success / data.size() * 100 << "%]" << endl;
    hashed_to_password.clear();
    output_file.close();
}
