#!/usr/bin/env python3
import subprocess
import sys
import logging
from getpass import getpass
from colorama import Fore, Style, init

init(autoreset=True)

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler('/var/log/smb_remote.log'),
            logging.StreamHandler()
        ]
    )

def check_dependencies():
    try:
        subprocess.run(['smbclient', '-V'], check=True, stdout=subprocess.DEVNULL)
    except FileNotFoundError:
        logging.error(f"{Fore.RED}[-]{Style.RESET_ALL} smbclient not found")
        sys.exit(1)

def remote_enumeration(target, username=None, password=None):
    auth = f"-U {username}%{password}" if username else "-N"
    
    commands = [
        f"smbclient -L {target} {auth}",
        f"rpcclient -W WORKGROUP -c 'enumdomusers' {target} {auth}",
        f"enum4linux -a {target}"
    ]
    
    results = {}
    for cmd in commands:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                results[cmd.split()[0]] = result.stdout
            else:
                logging.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Command failed: {cmd}")
        except Exception as e:
            logging.error(f"{Fore.RED}[-]{Style.RESET_ALL} Error executing {cmd}: {str(e)}")
    
    return results

def parse_enumeration(results):
    users = set()
    shares = set()
    
    # Parse smbclient output
    if 'smbclient' in results:
        for line in results['smbclient'].splitlines():
            if "Disk" in line:
                share = line.split()[0]
                shares.add(share)
    
    # Parse rpcclient output
    if 'rpcclient' in results:
        for line in results['rpcclient'].splitlines():
            if "[" in line and "]" in line:
                user = line.split("[")[1].split("]")[0]
                users.add(user)
    
    return {
        "users": sorted(users),
        "shares": sorted(shares)
    }

def main():
    setup_logging()
    check_dependencies()
    
    target = input(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Enter target IP/hostname: ")
    auth = input(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Authenticate? (y/N): ").lower()
    
    username = password = None
    if auth == 'y':
        username = input("Username: ")
        password = getpass("Password: ")
    
    logging.info(f"{Fore.GREEN}[+]{Style.RESET_ALL} Starting remote enumeration...")
    results = remote_enumeration(target, username, password)
    parsed = parse_enumeration(results)
    
    print(f"\n{Fore.CYAN}=== Enumeration Results ===")
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Users:")
    for user in parsed['users']:
        print(f" - {user}")
    
    print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Shares:")
    for share in parsed['shares']:
        print(f" - {share}")

if __name__ == "__main__":
    main()
