#include <stdio.h>
#include <stdlib.h>

/*
 * check_license fonksiyonunun elle uygulanmis Kontrol Akisi Duzlestirme (CFF)
 * versiyonu. Donusum, Cappaert & Preneel'in (2010) dispatcher modeline
 * (tek bir merkezi "dispatcher" dugumu + durum degiskeni) birebir uyularak
 * yapilmistir: her orijinal temel blok, calisma zamaninda durum degiskeninin
 * (state) degerine gore secilen bir switch-case dalina donusturulmustur.
 * Orijinal blok mantigi (result hesaplamalari, kosullar) AYNEN korunmustur -
 * sadece kontrol akisi gizlenmistir.
 */

typedef enum {
    S_ENTRY = 0,
    S_NEG,
    S_ZERO_CHECK,
    S_ZERO,
    S_MOD_CHECK,
    S_MOD_TRUE,
    S_MOD_FALSE,
    S_EXIT
} dispatch_state_t;

int check_license(int code) {
    int result = 0;
    dispatch_state_t state = S_ENTRY;

    while (state != S_EXIT) {
        switch (state) {
            case S_ENTRY:
                result = 0;
                if (code < 0) state = S_NEG;
                else state = S_ZERO_CHECK;
                break;

            case S_NEG:
                result = -1;
                state = S_EXIT;
                break;

            case S_ZERO_CHECK:
                if (code == 0) state = S_ZERO;
                else state = S_MOD_CHECK;
                break;

            case S_ZERO:
                result = 0;
                state = S_EXIT;
                break;

            case S_MOD_CHECK:
                if (code % 7 == 0) state = S_MOD_TRUE;
                else state = S_MOD_FALSE;
                break;

            case S_MOD_TRUE:
                result = code * 2;
                state = S_EXIT;
                break;

            case S_MOD_FALSE:
                result = code + 100;
                state = S_EXIT;
                break;

            default:
                state = S_EXIT;
                break;
        }
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
