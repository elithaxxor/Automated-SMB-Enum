#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CMD 1024
#define MAX_INPUT 256

// ANSI Color Codes
#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define CYAN "\033[36m"
#define RESET "\033[0m"

char target[MAX_INPUT];
char username[MAX_INPUT];
char password[MAX_INPUT];
int authenticated = 0;

void print_menu() {
    printf("\n%s=== SMB Enumeration Toolkit ===%s\n", CYAN, RESET);
    printf("%s[1]%s Impacket (Python SMB library)\n", YELLOW, RESET);
    printf("%s[2]%s CrackMapExec (Network scanner)\n", YELLOW, RESET);
    printf("%s[3]%s Enum4linux (Perl enumerator)\n", YELLOW, RESET);
    printf("%s[4]%s Nmap (SMB scripts)\n", YELLOW, RESET);
    printf("%s[5]%s Smbmap (Share permissions)\n", YELLOW, RESET);
    printf("%s[6]%s Metasploit (Exploit framework)\n", YELLOW, RESET);
    printf("%s[7]%s Rpcclient (RPC commands)\n", YELLOW, RESET);
    printf("%s[8]%s SMBClient (CLI tool)\n", YELLOW, RESET);
    printf("%s[9]%s Responder (Poisoning tool)\n", YELLOW, RESET);
    printf("%s[10]%s BloodHound (AD visualizer)\n", YELLOW, RESET);
    printf("%s[11]%s HAIL MARY (Run all tools)\n", RED, RESET);
    printf("%s[12]%s Exit\n", GREEN, RESET);
    printf("%s===============================%s\n", CYAN, RESET);
}

void check_dependency(const char *cmd) {
    char check[MAX_CMD];
    snprintf(check, MAX_CMD, "which %s > /dev/null", cmd);
    if (system(check) != 0) {
        printf("%s[-] %s not installed!%s\n", RED, cmd, RESET);
        exit(EXIT_FAILURE);
    }
}

void run_cmd(const char *description, const char *cmd) {
    printf("\n%s[+]%s %s\n", GREEN, RESET, description);
    printf("%s[!]%s Executing: %s%s%s\n", YELLOW, RESET, CYAN, cmd, RESET);
    system(cmd);
}

void impacket() {
    check_dependency("python3");
    char cmd[MAX_CMD];
    snprintf(cmd, MAX_CMD, 
        "python3 -c 'from impacket.smbconnection import SMBConnection; "
        "conn = SMBConnection(\"%s\", \"%s\"); "
        "conn.login(\"%s\", \"%s\"); "
        "print(conn.listShares())'", 
        target, target, username, password
    );
    run_cmd("Running Impacket SMB enumeration", cmd);
}

void crackmapexec() {
    check_dependency("crackmapexec");
    char cmd[MAX_CMD];
    snprintf(cmd, MAX_CMD, "crackmapexec smb %s -u %s -p %s --shares", 
             target, username, password);
    run_cmd("Running CrackMapExec", cmd);
}

void enum4linux() {
    check_dependency("enum4linux");
    char cmd[MAX_CMD];
    snprintf(cmd, MAX_CMD, "enum4linux -a %s", target);
    run_cmd("Running Enum4linux", cmd);
}

void nmap() {
    check_dependency("nmap");
    char cmd[MAX_CMD];
    snprintf(cmd, MAX_CMD, "nmap --script smb-enum-shares,smb-enum-users -p 445 %s", target);
    run_cmd("Running Nmap SMB scripts", cmd);
}

void smbmap() {
    check_dependency("smbmap");
    char cmd[MAX_CMD];
    snprintf(cmd, MAX_CMD, "smbmap -H %s -u %s -p %s", target, username, password);
    run_cmd("Running Smbmap", cmd);
}

void metasploit() {
    check_dependency("msfconsole");
    printf("%s[!]%s Open Metasploit and run:\n", YELLOW, RESET);
    printf("use auxiliary/scanner/smb/smb_version\n");
    printf("set RHOSTS %s\n", target);
    printf("run\n");
}

void hail_mary() {
    printf("\n%s=== HAIL MARY ACTIVATED ===%s\n", RED, RESET);
    impacket();
    crackmapexec();
    enum4linux();
    nmap();
    smbmap();
    metasploit();
    printf("%s=== HAIL MARY COMPLETE ===%s\n", RED, RESET);
}

int main() {
    // Get target input
    printf("%s[!]%s Enter target IP/hostname: ", YELLOW, RESET);
    fgets(target, MAX_INPUT, stdin);
    target[strcspn(target, "\n")] = 0;

    // Get credentials
    printf("%s[!]%s Authenticate? (y/N): ", YELLOW, RESET);
    int c = getchar();
    if (c == 'y' || c == 'Y') {
        getchar(); // Consume newline
        printf("Username: ");
        fgets(username, MAX_INPUT, stdin);
        username[strcspn(username, "\n")] = 0;
        
        printf("Password: ");
        system("stty -echo");
        fgets(password, MAX_INPUT, stdin);
        password[strcspn(password, "\n")] = 0;
        system("stty echo");
        authenticated = 1;
    }

    // Main loop
    int choice;
    do {
        print_menu();
        printf("%s[!]%s Select option: ", YELLOW, RESET);
        scanf("%d", &choice);
        getchar(); // Consume newline

        if (!authenticated && choice != 12) {
            strcpy(username, "");
            strcpy(password, "");
        }

        switch(choice) {
            case 1: impacket(); break;
            case 2: crackmapexec(); break;
            case 3: enum4linux(); break;
            case 4: nmap(); break;
            case 5: smbmap(); break;
            case 6: metasploit(); break;
            case 11: hail_mary(); break;
            case 12: printf("%s[+]%s Exiting...\n", GREEN, RESET); break;
            default: printf("%s[-]%s Invalid choice!\n", RED, RESET);
        }
    } while(choice != 12);

    return 0;
}
