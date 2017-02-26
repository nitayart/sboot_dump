#include <ctype.h>

#define HEXDUMP_COLS (16)

void hexdump_log(void *mem, unsigned int len) {
    unsigned int i, j;
    char buffer[256] = {0};
    char str[80] = {0};

    printf("[*] Dumping %08x bytes at address %llx:\n", len, (unsigned long long) mem);

    for (i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++) {
        if(i % HEXDUMP_COLS == 0) {
            sprintf(str, "[*] 0x%016llx (+0x%04x): ", (unsigned long long) (i + mem), i);
            strcat(buffer, str);
        }

        if(i < len) {
            sprintf(str, "%02x ", 0xFF & ((char*)mem)[i]);
            strcat(buffer, str);
        } else {
            sprintf(str, "   ");
            strcat(buffer, str);
        }

        if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1)) {
            for(j = i - (HEXDUMP_COLS - 1); j <= i; j++) {
                if(j >= len) {
                    sprintf(str, " ");
                    strcat(buffer, str);

                } else if (isprint (((char*) mem)[j])) {
                    sprintf(str, "%c", 0xFF & ((char*)mem)[j]);
                    strcat(buffer,str);
                } else {
                    sprintf(str, ".");
                    strcat(buffer,str);
                }
            }

            printf("%s\n", buffer);
            memset(&buffer[0], 0, sizeof(buffer));
        }
    }
}

void hexdump_log_base(void *mem, unsigned int len, unsigned int base) {
    unsigned int i, j;
    char buffer[256] = {0};
    char str[80] = {0};

    printf("[*] Dumping %08x bytes at address %llx:\n", len, (unsigned long long) mem);

    for (i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++) {
        if(i % HEXDUMP_COLS == 0) {
            sprintf(str, "[*] 0x%08x (+0x%04x): ", (unsigned int) (i + base), i);
            strcat(buffer, str);
        }

        if(i < len) {
            sprintf(str, "%02x ", 0xFF & ((char*)mem)[i]);
            strcat(buffer, str);
        } else {
            sprintf(str, "   ");
            strcat(buffer, str);
        }

        if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1)) {
            for(j = i - (HEXDUMP_COLS - 1); j <= i; j++) {
                if(j >= len) {
                    sprintf(str, " ");
                    strcat(buffer, str);

                } else if (isprint (((char*) mem)[j])) {
                    sprintf(str, "%c", 0xFF & ((char*)mem)[j]);
                    strcat(buffer,str);
                } else {
                    sprintf(str, ".");
                    strcat(buffer,str);
                }
            }

            printf("%s\n", buffer);
            memset(&buffer[0], 0, sizeof(buffer));
        }
    }
}
