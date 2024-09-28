#include "cracker.h"
using namespace std;

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    PasswordCracker hehe;
    // hehe.brute_force("./input/task1.csv");
    // hehe.common_password_bf("./input/task2.csv");
    // hehe.common_password_rbtb("./input/task3.csv");
    // hehe.common_password_salt_rbtb("./input/task4.csv");
    hehe.common_password_salt_transform("./input/task5.csv");
    return 0;
}