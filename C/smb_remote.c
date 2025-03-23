#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAXBUF 4096

void check_dependencies() {
    if (system("which smbclient > /dev/null") != 0) {
        fprintf(stderr, "[-] smbclient not found\n");
        exit(EXIT_FAILURE);
    }
}

void remote_enumeration(const char *target, const char *auth) {
    char cmd[MAXBUF];
    
    // Share enumeration
    snprintf(cmd, MAXBUF, "smbclient -L %s %s", target, auth);
    printf("[+] Shares:\n");
    system(cmd);
    
    // User enumeration
    snprintf(cmd, MAXBUF, "rpcclient -W WORKGROUP -c 'enumdomusers' %s %s", target, auth);
    printf("\n[+] Users:\n");
    system(cmd);
}

int main() {
    check_dependencies();
    
    char target[256];
    printf("[!] Enter target IP/hostname: ");
    fgets(target, sizeof(target), stdin);
    target[strcspn(target, "\n")] = 0;
    
    char auth[MAXBUF] = "-N";
    char auth_choice;
    printf("[!] Authenticate? (y/N): ");
    scanf("%c", &auth_choice);
    
    if (auth_choice == 'y' || auth_choice == 'Y') {
        char username[256], password[256];
        printf("Username: ");
        scanf("%s", username);
        printf("Password: ");
        system("stty -echo");
        scanf("%s", password);
        system("stty echo");
        snprintf(auth, MAXBUF, "-U %s%%%s", username, password);
    }
    
    printf("\n[+] Starting remote enumeration...\n");
    remote_enumeration(target, auth);
    
    return EXIT_SUCCESS;
}
