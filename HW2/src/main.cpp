#include "cracker.h"
using namespace std;

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    PasswordCracker hehe;
    hehe.brute_force("./input/task1.csv");
    return 0;
}