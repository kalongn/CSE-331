#include "cracker.h"
using namespace std;

int main(int argc, char *argv[]) {
    if (argc != 3) {
        cout << "1: brute_force \n2: dictionary attack \n3: rainbow table \n4: rainbow table with salt \n 5: transform, followed with the path to file" << endl;
        return 1;
    }
    PasswordCracker hehe;
    switch (argv[1][0]) {
    case '1':
        hehe.brute_force(argv[2]);
        break;
    case '2':
        hehe.common_password_bf(argv[2]);
        break;
    case '3':
        hehe.common_password_rbtb(argv[2]);
        break;
    case '4':
        hehe.common_password_salt_rbtb(argv[2]);
        break;
    case '5':
        hehe.common_password_salt_transform(argv[2]);
        break;
    default:
        cout << "Not a Valid Option.\n";
        return 1;
    }
    return 0;
}