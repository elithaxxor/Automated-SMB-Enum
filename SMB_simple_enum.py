import subprocess
import os
import logging
from smb.SMBConnection import SMBConnection

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

def is_tool_installed(tool):
    """Check if a tool is installed."""
    try:
        subprocess.check_output(["which", tool])
        return True
    except subprocess.CalledProcessError:
        return False

def install_tool(tool):
    """Install missing tools."""
    install_commands = {
        "enum4linux": "sudo apt install enum4linux -y",
        "smbmap": "pip3 install smbmap",
        "crackmapexec": "pip3 install crackmapexec",
        "impacket": "pip3 install impacket",
        "nbtscan": "sudo apt install nbtscan -y",
        "nmap": "sudo apt install nmap -y"
    }
    
    if tool in install_commands:
        logging.info(f"Installing {tool}...")
        os.system(install_commands[tool])
    else:
        logging.error(f"No installation recipe for {tool}")

def run_cmd(command, output_file=None):
    """Run a shell command and save its output."""
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

def nmap_smb_scan(target_ip):
    """Run Nmap SMB enumeration scripts."""
    scripts = [
        "smb-enum-shares.nse",
        "smb-enum-users.nse",
        "smb-vuln-ms17-010"
    ]
    cmd = ["nmap", "-p445,139", f"--script={','.join(scripts)}", target_ip]
    output_file = os.path.join(RESULTS_DIR, f"nmap_smb_{target_ip}.txt")
    return run_cmd(cmd, output_file)

def smbmap_scan(target_ip, username=None, password=None):
    """Run SMBMap to enumerate shares and permissions."""
    cmd = ["smbmap", "-H", target_ip]
    if username and password:
        cmd += ["-u", username, "-p", password]
    output_file = os.path.join(RESULTS_DIR, f"smbmap_{target_ip}.txt")
    return run_cmd(cmd, output_file)

def enum4linux_scan(target_ip):
    """Run Enum4Linux for detailed enumeration."""
    cmd = ["enum4linux", target_ip]
    output_file = os.path.join(RESULTS_DIR, f"enum4linux_{target_ip}.txt")
    return run_cmd(cmd, output_file)

def pysmb_scan(target_ip, username=None, password=None):
    """Use PySMB to list shares on the target."""
    conn = SMBConnection(username or "", password or "", "my_machine", target_ip, use_ntlm_v2=True)
    try:
        conn.connect(target_ip, 139)
        shares = conn.listShares()
        output_file = os.path.join(RESULTS_DIR, f"pysmb_{target_ip}.txt")
        with open(output_file, "w") as f:
            for share in shares:
                f.write(f"Share: {share.name}, Comment: {share.comments}\n")
                logging.info(f"Share: {share.name}, Comment: {share.comments}")
        conn.close()
    except Exception as e:
        logging.error(f"PySMB scan failed: {e}")

def validate_environment():
    """Ensure required tools are installed."""
    tools = ["enum4linux", "smbmap", "crackmapexec", "impacket", "nmap"]
    for tool in tools:
        if not is_tool_installed(tool):
            logging.warning(f"{tool} not found. Attempting to install...")
            install_tool(tool)
            if not is_tool_installed(tool):
                logging.error(f"Failed to install {tool}. Exiting.")
                return False
    return True

def main():
    """Main function to orchestrate SMB enumeration."""
    target_ip = input("Enter the target IP address: ")
    
    # Optional credentials for authenticated scans
    username = input("Enter username (leave blank for guest): ") or None
    password = input("Enter password (leave blank for none): ") or None
    
    # Validate environment
    if not validate_environment():
        return
    
    # Run scans
    logging.info("Starting SMB enumeration...")
    
    # Nmap scan
    nmap_smb_scan(target_ip)
    
    # Enum4Linux scan
    enum4linux_scan(target_ip)
    
    # SMBMap scan
    smbmap_scan(target_ip, username=username, password=password)
    
    # PySMB scan
    pysmb_scan(target_ip, username=username, password=password)
    
    logging.info(f"Enumeration complete. Results saved in {RESULTS_DIR}/")

if __name__ == "__main__":
    main()
