import subprocess
import os
import threading
import logging
from time import sleep

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("smb_enum.log"),
        logging.StreamHandler()
    ]
)

RESULTS_DIR = "smb_results"
os.makedirs(RESULTS_DIR, exist_ok=True)

INTENSITY_LEVELS = {
    "1": {
        "name": "Basic Enumeration",
        "tools": ["enum4linux", "nbtscan"],
        "vuln_scan": False,
        "description": "Minimum network impact, basic share/user enumeration"
    },
    "2": {
        "name": "Standard Analysis",
        "tools": ["smbmap", "rpcclient", "nmap_vuln"],
        "vuln_scan": True,
        "vuln_intensity": "medium",
        "description": "Authenticated checks + vulnerability scanning"
    },
    "3": {
        "name": "Advanced Exploitation",
        "tools": ["crackmapexec", "impacket", "manspider", "nmap_vuln"],
        "vuln_scan": True,
        "vuln_intensity": "aggressive",
        "description": "Full enumeration + aggressive vulnerability scanning"
    },
    "4": {
        "name": "Kerberos Focus",
        "tools": ["keimpx", "smbclient.py", "getTGT"],
        "description": "Domain-joined system analysis"
    }
}

def is_tool_installed(tool):
    try:
        subprocess.check_output(["which", tool])
        return True
    except subprocess.CalledProcessError:
        return False

def install_tool(tool):
    install_commands = {
        "enum4linux": "sudo apt install enum4linux -y",
        "smbmap": "pip3 install smbmap",
        "crackmapexec": "pip3 install crackmapexec",
        "impacket": "pip3 install impacket",
        "manspider": "pip3 install manspider",
        "keimpx": "git clone https://github.com/forcepoint/keimpx && cd keimpx && pip3 install .",
        "nbtscan": "sudo apt install nbtscan -y",
        "nmap": "sudo apt install nmap -y"
    }
    
    if tool in install_commands:
        logging.info(f"Installing {tool}...")
        os.system(install_commands[tool])
    else:
        logging.error(f"No install recipe for {tool}")

def run_cmd(command, output_file=None):
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True
        )
        if output_file:
            with open(output_file, "w") as f:
                f.write(result.stdout)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {e.output}")
        return None

def nmap_vuln_scan(target, intensity):
    scripts = [
        "smb-vuln-ms17-010",
        "smb-vuln-ms08-067",
        "smb-vuln-cve2009-3103"
    ]
    cmd = ["nmap", "-p445,139", f"--script={','.join(scripts)}"]
    
    if intensity == "aggressive":
        cmd += ["-T4", "-A", "--version-all"]
    else:
        cmd += ["-T3"]
    
    cmd.append(target)
    output = os.path.join(RESULTS_DIR, f"nmap_vuln_{target}.txt")
    return run_cmd(cmd, output)

def run_tool(tool, target, username=None, password=None):
    tool_commands = {
        "enum4linux": ["enum4linux", "-A", target],
        "smbmap": ["smbmap", "-H", target] + (["-u", username, "-p", password] if username else []),
        "crackmapexec": ["crackmapexec", "smb", target] + (["-u", username, "-p", password] if username else []),
        "nbtscan": ["nbtscan", target],
        "manspider": ["manspider", target] + (["-u", username, "-p", password] if username else []),
        "rpcclient": ["rpcclient", "-U%", target]
    }
    
    if tool not in tool_commands:
        logging.error(f"Unsupported tool: {tool}")
        return
    
    output = os.path.join(RESULTS_DIR, f"{tool}_{target}.txt")
    run_cmd(tool_commands[tool], output)

def validate_environment(intensity):
    for tool in INTENSITY_LEVELS[intensity]["tools"]:
        if tool != "nmap_vuln" and not is_tool_installed(tool):
            logging.warning(f"{tool} not found, attempting install...")
            install_tool(tool)
            sleep(2)  # Allow time for installation
            if not is_tool_installed(tool):
                logging.error(f"Critical dependency missing: {tool}")
                return False
    return True

def execute_intensity(target, intensity, username=None, password=None):
    logging.info(f"\n{'='*40}\nStarting {INTENSITY_LEVELS[intensity]['name']}\n{'='*40}")
    
    threads = []
    for tool in INTENSITY_LEVELS[intensity]["tools"]:
        if tool == "nmap_vuln":
            t = threading.Thread(
                target=nmap_vuln_scan,
                args=(target, INTENSITY_LEVELS[intensity].get("vuln_intensity", "medium"))
            )
        else:
            t = threading.Thread(
                target=run_tool,
                args=(tool, target),
                kwargs={"username": username, "password": password}
            )
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()

def main_menu():
    print("\nSMB Enumeration Toolkit")
    print("=======================")
    for num, config in INTENSITY_LEVELS.items():
        print(f"{num}. {config['name']}: {config['description']}")
    print("q. Quit")
    
    while True:
        choice = input("\nSelect intensity level: ").lower()
        if choice in INTENSITY_LEVELS or choice == "q":
            return choice
        print("Invalid selection")

def main():
    target = input("Enter target IP/CIDR: ")
    username = input("Username (optional): ") or None
    password = input("Password (optional): ") or None
    
    while True:
        choice = main_menu()
        if choice == "q":
            break
            
        if not validate_environment(choice):
            logging.error("Prerequisites not met for selected level")
            continue
            
        execute_intensity(target, choice, username, password)
        logging.info(f"\n{INTENSITY_LEVELS[choice]['name']} complete!\nResults in {RESULTS_DIR}/")

if __name__ == "__main__":
    main()
