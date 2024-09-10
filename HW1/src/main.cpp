#include "cipher.h"
using namespace std;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        cout << "1: enode \n 2: decode \n 3: break with length \n 4: break with brute force";
        return 1;
    }
    VigenereCipher cipher;
    string plain_text, cipher_text, key, key_length;

    switch (argv[1][0]) {
    case '1':
        getline(cin, plain_text);
        getline(cin, key);
        cout << cipher.encode(plain_text, key);
        break;
    case '2':
        getline(cin, cipher_text);
        getline(cin, key);
        cout << cipher.decode(cipher_text, key);
        break;
    case '3':
        getline(cin, cipher_text);
        getline(cin, key_length);
        int key_length_int;
        try {
            key_length_int = stoi(key_length);
        } catch (const std::exception &e) {
            std::cerr << e.what() << '\n';
            return 1;
        }
        cout << cipher.break_cipher(cipher_text, key_length_int);
        break;
    case '4':
        getline(cin, cipher_text);
        cout << cipher.break_cipher(cipher_text, 0);
        break;
    default:
        cout << "Not a Valid Option.\n";
        return 1;
    }
    return 0;



//     string output1 = cipher.encode("Hello world123!", "SECURITY");
//     cout << output1 << '\n';
//     string output2 = cipher.encode("hell-o wor ld!", "SECURITY");
//     cout << output2 << '\n';
//     output1 = cipher.decode(output1, "SECURITY");
//     cout << output1 << '\n';
//     output2 = cipher.decode(output2, "SECURITY");
//     cout << output2 << '\n';
//     cipher.encode("Hello world 123! Hello world 123!", "SECURITY");
//     cipher.encode("Hello !!", "SECURITY");

//     const string test = "Abstract—We evaluate two decades of proposals to replace \
// text passwords for general - purpose user authentication on the \
// web using a broad set of twenty - five usability, deployability \
// and security benefits that an ideal scheme might provide. \
// The scope of proposals we survey is also extensive, including \
// password management software, federated login protocols, \
// graphical password schemes, cognitive authentication schemes, \
// one - time passwords, hardware tokens, phone - aided schemes \
// and biometrics.Our comprehensive approach leads to key \
// insights about the difficulty of replacing passwords.Not only \
// does no known scheme come close to providing all desired \
// benefits: none even retains the full set of benefits that legacy \
// passwords already provide.In particular, there is a wide range \
// from schemes offering minor security benefits beyond legacy \
// passwords, to those offering significant security benefits in \
// return for being more costly to deploy or more difficult to use. \
// We conclude that many academic proposals have failed to gain \
// traction because researchers rarely consider a sufficiently wide \
// range of real - world constraints.Beyond our analysis of current \
// schemes, our framework provides an evaluation methodology \
// and benchmark for future web authentication proposals.";


//     string key = "TESTINGHAHEHIMERICLOLLMFAO";
//     string encode1 = cipher.encode(test, key);
//     string decode1 = cipher.break_cipher(encode1);
//     cout << decode1;
}