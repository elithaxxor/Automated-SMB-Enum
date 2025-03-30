import argparse
import subprocess
import os
import logging
import json
from smb.SMBConnection import SMBConnection
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import yaml

# Configuration loader
def load_config(config_file="config.yaml"):
    with open(config_file, "r") as f:
        return yaml.safe_load(f)

class SMBEnumerator:
    def __init__(self, target_ip, username=None, password=None, config=None):
        self.target_ip = target_ip
        self.username = username
        self.password = password
        self.results_dir = "smb_results"
        os.makedirs(self.results_dir, exist_ok=True)

        # Configuration
        self.config = config or {}
        self.scan_timeout = self.config.get("scan_timeout", 60)

        # Logging setup
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("smb_enum.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def is_tool_installed(self, tool):
        """Check if a tool is installed."""
        try:
            subprocess.check_output(["which", tool])
            return True
        except subprocess.CalledProcessError:
            return False

    def install_tool(self, tool):
        """Install missing tools."""
        install_commands = self.config.get("tools_install_commands", {})
        if tool in install_commands:
            self.logger.info(f"Installing {tool}...")
            os.system(install_commands[tool])
        else:
            self.logger.error(f"No installation recipe for {tool}")

    def run_cmd(self, command, output_file=None):
        """Run a shell command with timeout and save its output."""
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=True,
                timeout=self.scan_timeout
            )
            if output_file:
                with open(output_file, "w") as f:
                    f.write(result.stdout)
            return result.stdout
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timed out: {' '.join(command)}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {e.output}")
        return None

    # Nmap SMB Enumeration
    def nmap_smb_scan(self):
        scripts = ["smb-enum-shares.nse", "smb-enum-users.nse", "smb-vuln-ms17-010"]
        cmd = ["nmap", "-p139,445", f"--script={','.join(scripts)}", self.target_ip]
        output_file = os.path.join(self.results_dir, f"nmap_smb_{self.target_ip}.txt")
        return self.run_cmd(cmd, output_file)

    # Enum4Linux Scan
    def enum4linux_scan(self):
        cmd = ["enum4linux", self.target_ip]
        output_file = os.path.join(self.results_dir, f"enum4linux_{self.target_ip}.txt")
        return self.run_cmd(cmd, output_file)

    # SMBMap Scan
    def smbmap_scan(self):
        cmd = ["smbmap", "-H", self.target_ip]
        if self.username and self.password:
            cmd += ["-u", self.username, "-p", self.password]
        output_file = os.path.join(self.results_dir, f"smbmap_{self.target_ip}.txt")
        return self.run_cmd(cmd, output_file)

    # PySMB Scan
    def pysmb_scan(self):
        conn = SMBConnection(
            self.username or "", 
            self.password or "", 
            "my_machine", 
            self.target_ip, 
            use_ntlm_v2=True
        )
        
        try:
            conn.connect(self.target_ip, 139)
            shares = conn.listShares()
            output_file = os.path.join(self.results_dir, f"pysmb_{self.target_ip}.txt")
            
            with open(output_file, "w") as f:
                for share in shares:
                    f.write(f"Share: {share.name}, Comment: {share.comments}\n")
                    self.logger.info(f"Share: {share.name}, Comment: {share.comments}")
                    
            conn.close()
            
        except Exception as e:
            self.logger.error(f"PySMB scan failed: {e}")

    # CrackMapExec Scan
    def crackmapexec_scan(self):
        cmd = ["crackmapexec", "smb", self.target_ip]
        if self.username and self.password:
            cmd += ["-u", self.username, "-p", self.password]
        output_file = os.path.join(self.results_dir, f"cme_{self.target_ip}.txt")
        return self.run_cmd(cmd, output_file)

    # Impacket SecretsDump
    def impacket_secretsdump(self):
        cmd = ["secretsdump.py", f"{self.username or 'guest'}:{self.password or ''}@{self.target_ip}"]
        output_file = os.path.join(self.results_dir, f"impacket_secretsdump_{self.target_ip}.txt")
        return self.run_cmd(cmd, output_file)

    # Responder (Start Capturing Traffic)
    def start_responder(self):
        cmd = ["responder", "-I", "eth0", "-rdwv"]
        output_file = os.path.join(self.results_dir, "responder_log.txt")
        return self.run_cmd(cmd, output_file)

    # Validate Environment
    def validate_environment(self):
        tools = self.config.get("tools", [])
        for tool in tools:
            if not self.is_tool_installed(tool):
                self.logger.warning(f"{tool} not found. Attempting to install...")
                self.install_tool(tool)
                
                if not self.is_tool_installed(tool):
                    self.logger.error(f"Failed to install {tool}. Exiting.")
                    return False
                
        return True

    def aggregate_results(self):
        summary_file = os.path.join(self.results_dir, f"summary_{self.target_ip}.json")
        results = {f"result_file_{i}": f"tool_{i}.txt" for i in range(5)}  
        # Placeholder
        with open(summary_file, "w") as f:
            json.dump(results, f, indent=2)

    def run_all_scans_async(self):
        scans = [
            self.nmap_smb_scan,
            self.enum4linux_scan,
            self.smbmap_scan,
            self.crackmapexec_scan,
            self.impacket_secretsdump,
        ]
        with ProcessPoolExecutor() as executor:
            executor.map(lambda scan: scan(), scans)
        self.pysmb_scan()
        self.aggregate_results()

def parse_args():
    parser = argparse.ArgumentParser(description="SMB Enumeration Tool")
    parser.add_argument("-t", "--targets", nargs="+", required=True, help="Target IP address(es)")
    parser.add_argument("-u", "--username", type=str, help="Username for authentication")
    parser.add_argument("-p", "--password", type=str, help="Password for authentication")
    parser.add_argument("--config", type=str, default="config.yaml", help="Path to configuration file")
    return parser.parse_args()

def main():
    args = parse_args()
    config = load_config(args.config)
    for target in args.targets:
        enumerator = SMBEnumerator(target_ip=target, username=args.username, password=args.password, config=config)
        if enumerator.validate_environment():
            enumerator.run_all_scans_async()

if __name__ == "__main__":
    main()
import argparse
import subprocess
import os
import logging
import json
from smb.SMBConnection import SMBConnection
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import yaml

# Configuration loader
def load_config(config_file="config.yaml"):
    with open(config_file, "r") as f:
        return yaml.safe_load(f)

class SMBEnumerator:
    def __init__(self, target_ip, username=None, password=None, config=None):
        self.target_ip = target_ip
        self.username = username
        self.password = password
        self.results_dir = "smb_results"
        os.makedirs(self.results_dir, exist_ok=True)

        # Configuration
        self.config = config or {}
        self.scan_timeout = self.config.get("scan_timeout", 60)

        # Logging setup
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("smb_enum.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def is_tool_installed(self, tool):
        """Check if a tool is installed."""
        try:
            subprocess.check_output(["which", tool])
            return True
        except subprocess.CalledProcessError:
            return False

    def install_tool(self, tool):
        """Install missing tools."""
        install_commands = self.config.get("tools_install_commands", {})
        if tool in install_commands:
            self.logger.info(f"Installing {tool}...")
            os.system(install_commands[tool])
        else:
            self.logger.error(f"No installation recipe for {tool}")

    def run_cmd(self, command, output_file=None):
        """Run a shell command with timeout and save its output."""
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=True,
                timeout=self.scan_timeout
            )
            if output_file:
                with open(output_file, "w") as f:
                    f.write(result.stdout)
            return result.stdout
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timed out: {' '.join(command)}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {e.output}")
        return None

    # Nmap SMB Enumeration
    def nmap_smb_scan(self):
        scripts = ["smb-enum-shares.nse", "smb-enum-users.nse", "smb-vuln-ms17-010"]
        cmd = ["nmap", "-p139,445", f"--script={','.join(scripts)}", self.target_ip]
        output_file = os.path.join(self.results_dir, f"nmap_smb_{self.target_ip}.txt")
        return self.run_cmd(cmd, output_file)

    # Enum4Linux Scan
    def enum4linux_scan(self):
        cmd = ["enum4linux", self.target_ip]
        output_file = os.path.join(self.results_dir, f"enum4linux_{self.target_ip}.txt")
        return self.run_cmd(cmd, output_file)

    # SMBMap Scan
    def smbmap_scan(self):
        cmd = ["smbmap", "-H", self.target_ip]
        if self.username and self.password:
            cmd += ["-u", self.username, "-p", self.password]
        output_file = os.path.join(self.results_dir, f"smbmap_{self.target_ip}.txt")
        return self.run_cmd(cmd, output_file)

    # PySMB Scan
    def pysmb_scan(self):
        conn = SMBConnection(
            self.username or "", 
            self.password or "", 
            "my_machine", 
            self.target_ip, 
            use_ntlm_v2=True
        )
        
        try:
            conn.connect(self.target_ip, 139)
            shares = conn.listShares()
            output_file = os.path.join(self.results_dir, f"pysmb_{self.target_ip}.txt")
            
            with open(output_file, "w") as f:
                for share in shares:
                    f.write(f"Share: {share.name}, Comment: {share.comments}\n")
                    self.logger.info(f"Share: {share.name}, Comment: {share.comments}")
                    
            conn.close()
            
        except Exception as e:
            self.logger.error(f"PySMB scan failed: {e}")

    # CrackMapExec Scan
    def crackmapexec_scan(self):
        cmd = ["crackmapexec", "smb", self.target_ip]
        if self.username and self.password:
            cmd += ["-u", self.username, "-p", self.password]
        output_file = os.path.join(self.results_dir, f"cme_{self.target_ip}.txt")
        return self.run_cmd(cmd, output_file)

    # Impacket SecretsDump
    def impacket_secretsdump(self):
        cmd = ["secretsdump.py", f"{self.username or 'guest'}:{self.password or ''}@{self.target_ip}"]
        output_file = os.path.join(self.results_dir, f"impacket_secretsdump_{self.target_ip}.txt")
        return self.run_cmd(cmd, output_file)

    # Responder (Start Capturing Traffic)
    def start_responder(self):
        cmd = ["responder", "-I", "eth0", "-rdwv"]
        output_file = os.path.join(self.results_dir, "responder_log.txt")
        return self.run_cmd(cmd, output_file)

    # Validate Environment
    def validate_environment(self):
        tools = self.config.get("tools", [])
        for tool in tools:
            if not self.is_tool_installed(tool):
                self.logger.warning(f"{tool} not found. Attempting to install...")
                self.install_tool(tool)
                
                if not self.is_tool_installed(tool):
                    self.logger.error(f"Failed to install {tool}. Exiting.")
                    return False
                
        return True

    def aggregate_results(self):
        summary_file = os.path.join(self.results_dir, f"summary_{self.target_ip}.json")
        results = {f"result_file_{i}": f"tool_{i}.txt" for i in range(5)}  
        # Placeholder
        with open(summary_file, "w") as f:
            json.dump(results, f, indent=2)

    def run_all_scans_async(self):
        scans = [
            self.nmap_smb_scan,
            self.enum4linux_scan,
            self.smbmap_scan,
            self.crackmapexec_scan,
            self.impacket_secretsdump,
        ]
        with ProcessPoolExecutor() as executor:
            executor.map(lambda scan: scan(), scans)
        self.pysmb_scan()
        self.aggregate_results()

def parse_args():
    parser = argparse.ArgumentParser(description="SMB Enumeration Tool")
    parser.add_argument("-t", "--targets", nargs="+", required=True, help="Target IP address(es)")
    parser.add_argument("-u", "--username", type=str, help="Username for authentication")
    parser.add_argument("-p", "--password", type=str, help="Password for authentication")
    parser.add_argument("--config", type=str, default="config.yaml", help="Path to configuration file")
    return parser.parse_args()

def main():
    args = parse_args()
    config = load_config(args.config)
    for target in args.targets:
        enumerator = SMBEnumerator(target_ip=target, username=args.username, password=args.password, config=config)
        if enumerator.validate_environment():
            enumerator.run_all_scans_async()

if __name__ == "__main__":
    main()
