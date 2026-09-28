#include <stdio.h>

// Basit lisans anahtari dogrulama fonksiyonu (pilot test programi)
int check_license(int code) {
    int result = 0;
    if (code < 0) {
        result = -1;
    } else if (code == 0) {
        result = 0;
    } else if (code % 7 == 0) {
        result = code * 2;
    } else {
        result = code + 100;
    }
    return result;
}

int main(int argc, char** argv) {
    int input = 42;
    if (argc > 1) input = atoi(argv[1]);
    int r = check_license(input);
    printf("Result: %d\n", r);
    return 0;
}
