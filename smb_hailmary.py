import asyncio
import argparse
import subprocess
import os
import logging
import json
import random
import yaml
import aiofiles
from datetime import datetime
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from contextlib import asynccontextmanager
from smb.SMBConnection import SMBConnection
from typing import List, Dict, Any, Optional, Set, Union, Tuple


# ----- Configuration Classes -----

class ScannerConfig:
    """Base configuration class for scanners"""
    def __init__(self, config_dict: Dict = None):
        self.config_dict = config_dict or {}
        
    def get(self, key, default=None):
        return self.config_dict.get(key, default)
        
    @classmethod
    async def from_yaml(cls, file_path: str):
        """Load configuration from YAML file"""
        try:
            async with aiofiles.open(file_path, "r") as f:
                content = await f.read()
                config_dict = yaml.safe_load(content)
                return cls(config_dict)
        except Exception as e:
            logging.error(f"Failed to load config from {file_path}: {e}")
            return cls({})


class SMBScannerConfig(ScannerConfig):
    """Specific configuration for SMB scanners"""
    
    @property
    def scan_timeout(self) -> int:
        return self.get("scan_timeout", 60)
        
    @property
    def tools(self) -> List[str]:
        return self.get("tools", ["nmap", "enum4linux", "smbmap", "crackmapexec", "secretsdump.py"])
        
    @property
    def network_interface(self) -> str:
        return self.get("network_interface", "eth0")
        
    @property
    def install_commands(self) -> Dict[str, str]:
        return self.get("tools_install_commands", {})


# ----- Credential Management -----

class Credential:
    """Simple credential model class"""
    def __init__(self, username: str = "", password: str = ""):
        self.username = username
        self.password = password
        
    def __str__(self):
        return f"{self.username}:{self.password}"
        
    def __repr__(self):
        return f"Credential(username='{self.username}', password='***')"
        
    def as_dict(self):
        return {"username": self.username, "password": self.password}


class CredentialManager:
    """Manages credentials for authentication"""
    def __init__(self, default_credential: Optional[Credential] = None, cred_file: Optional[str] = None):
        self.credentials: List[Credential] = []
        
        if default_credential and (default_credential.username or default_credential.password):
            self.credentials.append(default_credential)
            
        if cred_file:
            self._load_credentials_from_file(cred_file)
            
        # Add default/anonymous credentials if none specified
        if not self.credentials:
            self.credentials.append(Credential("", ""))
            self.credentials.append(Credential("guest", ""))
            
    def _load_credentials_from_file(self, cred_file: str):
        """Load credentials from a file"""
        try:
            with open(cred_file, 'r') as f:
                for line in f:
                    if ':' in line:
                        username, password = line.strip().split(':', 1)
                        self.credentials.append(Credential(username, password))
        except Exception as e:
            logging.error(f"Failed to load credentials from {cred_file}: {e}")
            
    def get_credentials(self) -> List[Credential]:
        """Get all credentials"""
        return self.credentials


# ----- Result Classes -----

class ScanResult:
    """Base class for scan results"""
    def __init__(self, target: str, scanner_name: str, success: bool = True, message: str = None):
        self.target = target
        self.scanner_name = scanner_name
        self.success = success
        self.message = message
        self.timestamp = datetime.now().isoformat()
        
    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "scanner": self.scanner_name,
            "success": self.success,
            "message": self.message,
            "timestamp": self.timestamp
        }


class CommandScanResult(ScanResult):
    """Result from a command-based scan"""
    def __init__(self, target: str, scanner_name: str, command: List[str], 
                 output: str = None, output_file: str = None, **kwargs):
        super().__init__(target, scanner_name, **kwargs)
        self.command = command
        self.output = output
        self.output_file = output_file
        
    def to_dict(self) -> Dict:
        result = super().to_dict()
        result.update({
            "command": " ".join(self.command),
            "output_file": self.output_file
        })
        return result


class ShareInfo:
    """Information about an SMB share"""
    def __init__(self, name: str, comment: str = "", share_type: str = None):
        self.name = name
        self.comment = comment
        self.type = share_type
        self.files: List[str] = []
        self.access_error: Optional[str] = None
        
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "comment": self.comment,
            "type": self.type,
            "files": self.files[:10] if self.files else [],  # Limit to first 10 files
            "access_error": self.access_error
        }


class SMBInfo:
    """Information about SMB server"""
    def __init__(self):
        self.os_info: Dict[str, str] = {}
        self.protocols: List[str] = []
        self.dialect: Optional[str] = None
        self.shares: List[ShareInfo] = []
        self.users: Set[str] = set()
        self.groups: Set[str] = set()
        self.vulnerabilities: List[str] = []
        
    def to_dict(self) -> Dict:
        return {
            "os_info": self.os_info,
            "protocols": self.protocols,
            "dialect": self.dialect,
            "shares": [share.to_dict() for share in self.shares],
            "users": list(self.users),
            "groups": list(self.groups),
            "vulnerabilities": self.vulnerabilities
        }


class AggregatedResult:
    """Aggregated results from multiple scanners"""
    def __init__(self, target: str):
        self.target = target
        self.scan_results: Dict[str, ScanResult] = {}
        self.smb_info = SMBInfo()
        self.timestamp = datetime.now().isoformat()
        
    def add_result(self, result: ScanResult):
        """Add a scan result"""
        self.scan_results[result.scanner_name] = result
        
    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "smb_info": self.smb_info.to_dict(),
            "scan_results": {name: result.to_dict() for name, result in self.scan_results.items()}
        }
        
    async def save_to_file(self, file_path: str):
        """Save results to file"""
        async with aiofiles.open(file_path, "w") as f:
            await f.write(json.dumps(self.to_dict(), indent=2))


# ----- Command Executor -----

class CommandExecutor:
    """Executes shell commands asynchronously"""
    def __init__(self, timeout: int = 60):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        
    async def execute(self, command: List[str], output_file: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """Execute a command and optionally save output to file"""
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )
            
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
                stdout_text = stdout.decode() if stdout else None
                
                if output_file and stdout_text:
                    async with aiofiles.open(output_file, "w") as f:
                        await f.write(stdout_text)
                
                success = proc.returncode == 0
                return success, stdout_text
                
            except asyncio.TimeoutError:
                proc.terminate()
                self.logger.error(f"Command timed out: {' '.join(command)}")
                return False, None
                
        except Exception as e:
            self.logger.error(f"Command execution failed: {str(e)}")
            return False, None


# ----- Environment Validator -----

class EnvironmentValidator:
    """Validates and sets up the operating environment"""
    def __init__(self, config: SMBScannerConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.executor = CommandExecutor(timeout=30)
        
    async def is_tool_installed(self, tool: str) -> bool:
        """Check if a tool is installed"""
        success, _ = await self.executor.execute(["which", tool])
        return success
        
    async def install_tool(self, tool: str) -> bool:
        """Attempt to install a missing tool"""
        install_commands = self.config.install_commands
        if tool not in install_commands:
            self.logger.error(f"No installation recipe for {tool}")
            return False
            
        install_cmd = install_commands[tool]
        self.logger.info(f"Installing {tool} using command: {install_cmd}")
        
        success, _ = await self.executor.execute(["bash", "-c", install_cmd])
        if not success:
            self.logger.error(f"Failed to install {tool}")
            return False
            
        return await self.is_tool_installed(tool)
        
    async def validate(self) -> bool:
        """Validate the environment"""
        missing_tools = []
        
        for tool in self.config.tools:
            if not await self.is_tool_installed(tool):
                self.logger.warning(f"{tool} not found. Attempting to install...")
                if not await self.install_tool(tool):
                    missing_tools.append(tool)
        
        if missing_tools:
            self.logger.error(f"Missing required tools: {', '.join(missing_tools)}")
            return False
            
        return True


# ----- Base Scanner -----

class BaseScanner(ABC):
    """Abstract base class for all scanners"""
    def __init__(self, target: str, config: SMBScannerConfig, 
                 credential: Optional[Credential] = None, 
                 results_dir: str = "smb_results"):
        self.target = target
        self.config = config
        self.credential = credential
        self.results_dir = results_dir
        self.logger = logging.getLogger(self.__class__.__name__)
        self.executor = CommandExecutor(timeout=config.scan_timeout)
        
        os.makedirs(results_dir, exist_ok=True)
        
    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner name"""
        pass
        
    @abstractmethod
    async def scan(self) -> ScanResult:
        """Perform the scan"""
        pass
        
    def get_output_file(self, suffix: str = "") -> str:
        """Get output file path"""
        filename = f"{self.name}{suffix}_{self.target}.txt"
        return os.path.join(self.results_dir, filename)


# ----- Concrete Scanner Implementations -----

class NmapScanner(BaseScanner):
    """Nmap SMB scanner implementation"""
    @property
    def name(self) -> str:
        return "nmap"
        
    async def scan(self, options: Optional[str] = None) -> CommandScanResult:
        """Run Nmap SMB scan"""
        scripts = ["smb-enum-shares.nse", "smb-enum-users.nse", "smb-vuln-ms17-010.nse",
                  "smb-protocols.nse", "smb-security-mode.nse"]
        
        cmd = ["nmap", "-p139,445"]
        
        if options:
            cmd.extend(options.split())
            
        cmd.extend([f"--script={','.join(scripts)}", self.target])
        
        output_file = self.get_output_file()
        success, output = await self.executor.execute(cmd, output_file)
        
        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="Completed successfully" if success else "Scan failed"
        )
        
    async def parse_results(self, output_file: str) -> SMBInfo:
        """Parse Nmap results"""
        info = SMBInfo()
        
        try:
            async with aiofiles.open(output_file, "r") as f:
                content = await f.read()
                
                # Extract shares
                if "smb-enum-shares" in content:
                    share_lines = content.split("smb-enum-shares:")[1].split("smb-enum-users")[0]
                    for line in share_lines.split("\n"):
                        if "\\\\" in line and "\\\\IPC$" not in line:
                            share_name = line.split("\\\\")[1].strip()
                            info.shares.append(ShareInfo(name=share_name))
                
                # Extract users
                if "smb-enum-users" in content:
                    user_lines = content.split("smb-enum-users:")[1].split("smb-vuln")[0]
                    for line in user_lines.split("\n"):
                        if "user:" in line:
                            user_name = line.split("user:")[1].strip()
                            info.users.add(user_name)
                
                # Extract vulnerabilities
                if "smb-vuln" in content:
                    vuln_lines = content.split("smb-vuln")[1:]
                    for vuln_section in vuln_lines:
                        vuln_name = vuln_section.split(":")[0].strip()
                        if "VULNERABLE" in vuln_section:
                            info.vulnerabilities.append(vuln_name)
                
                # Extract SMB protocol info
                if "smb-protocols" in content:
                    proto_lines = content.split("smb-protocols:")[1].split("smb-security-mode")[0]
                    for line in proto_lines.split("\n"):
                        if "SMBv" in line:
                            info.protocols.append(line.strip())
                
        except Exception as e:
            self.logger.error(f"Error parsing Nmap results: {e}")
            
        return info


class Enum4LinuxScanner(BaseScanner):
    """Enum4Linux scanner implementation"""
    @property
    def name(self) -> str:
        return "enum4linux"
        
    async def scan(self) -> CommandScanResult:
        """Run Enum4Linux scan"""
        cmd = ["enum4linux", "-a", self.target]
        
        if self.credential:
            cmd.extend(["-u", self.credential.username, "-p", self.credential.password])
            
        output_file = self.get_output_file()
        success, output = await self.executor.execute(cmd, output_file)
        
        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="Completed successfully" if success else "Scan failed"
        )
        
    async def parse_results(self, output_file: str) -> SMBInfo:
        """Parse enum4linux results"""
        info = SMBInfo()
        
        try:
            async with aiofiles.open(output_file, "r") as f:
                content = await f.read()
                
                # Extract shares
                if "Share Enumeration" in content:
                    share_lines = content.split("Share Enumeration")[1].split("Password Policy")[0]
                    for line in share_lines.split("\n"):
                        if "Sharename" in line and "Type" in line:
                            continue
                        if "---" in line:
                            continue
                        parts = line.split()
                        if len(parts) >= 2:
                            share_name = parts[0].strip()
                            if share_name and share_name != "":
                                info.shares.append(ShareInfo(name=share_name))
                
                # Extract users
                if "user:[" in content:
                    user_lines = [line for line in content.split("\n") if "user:[" in line]
                    for line in user_lines:
                        user_name = line.split("user:[")[1].split("]")[0].strip()
                        info.users.add(user_name)
                
                # Extract groups
                if "group:[" in content:
                    group_lines = [line for line in content.split("\n") if "group:[" in line]
                    for line in group_lines:
                        group_name = line.split("group:[")[1].split("]")[0].strip()
                        info.groups.add(group_name)
                
                # Extract OS info
                if "OS=" in content:
                    os_line = [line for line in content.split("\n") if "OS=" in line]
                    if os_line:
                        info.os_info["os"] = os_line[0].split("OS=")[1].strip()
                
                if "Server=" in content:
                    server_line = [line for line in content.split("\n") if "Server=" in line]
                    if server_line:
                        info.os_info["server"] = server_line[0].split("Server=")[1].strip()
                
        except Exception as e:
            self.logger.error(f"Error parsing enum4linux results: {e}")
            
        return info


class SMBMapScanner(BaseScanner):
    """SMBMap scanner implementation"""
    @property
    def name(self) -> str:
        return "smbmap"
        
    async def scan(self) -> CommandScanResult:
        """Run SMBMap scan"""
        cmd = ["smbmap", "-H", self.target]
        
        if self.credential:
            cmd.extend(["-u", self.credential.username, "-p", self.credential.password])
            
        output_file = self.get_output_file()
        success, output = await self.executor.execute(cmd, output_file)
        
        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="Completed successfully" if success else "Scan failed"
        )
        
    async def parse_results(self, output_file: str) -> SMBInfo:
        """Parse SMBMap results"""
        info = SMBInfo()
        
        try:
            async with aiofiles.open(output_file, "r") as f:
                content = await f.read()
                
                for line in content.split("\n"):
                    if line.strip() and not line.startswith("[+]") and not line.startswith("[-]"):
                        parts = [p.strip() for p in line.split() if p.strip()]
                        if len(parts) >= 3:
                            share_name = parts[0]
                            permissions = parts[1]
                            comment = " ".join(parts[2:])
                            
                            share = ShareInfo(name=share_name, comment=comment)
                            info.shares.append(share)
                
        except Exception as e:
            self.logger.error(f"Error parsing SMBMap results: {e}")
            
        return info


class PySMBScanner(BaseScanner):
    """PySMB direct API scanner implementation"""
    @property
    def name(self) -> str:
        return "pysmb"
        
    @asynccontextmanager
    async def smb_connection(self, dialect=None):
        """Context manager for SMB connections"""
        username = self.credential.username if self.credential else ""
        password = self.credential.password if self.credential else ""
        
        conn = SMBConnection(
            username, 
            password, 
            "my_machine", 
            self.target, 
            use_ntlm_v2=True
        )
        
        if dialect:
            conn.preferred_dialect = dialect
            
        connected = False
        try:
            # Try both SMB ports
            for port in [445, 139]:
                try:
                    connected = conn.connect(self.target, port)
                    if connected:
                        break
                except Exception as e:
                    self.logger.debug(f"Failed to connect on port {port}: {e}")
                    
            if connected:
                yield conn
            else:
                self.logger.error(f"Failed to connect to {self.target}")
                yield None
        finally:
            if connected:
                try:
                    conn.close()
                except Exception as e:
                    self.logger.error(f"Error closing connection: {e}")
        
    async def scan(self) -> ScanResult:
        """Run PySMB scan"""
        output_file = self.get_output_file()
        success = False
        results = []
        
        # Try different SMB dialects
        for dialect in ["SMB2", "SMB3", None]:  # None = default/auto-negotiate
            try:
                async with self.smb_connection(dialect=dialect) as conn:
                    if not conn:
                        continue
                    
                    shares = conn.listShares()
                    dialect_output_file = self.get_output_file(f"_{dialect or 'default'}")
                    
                    share_info = []
                    for share in shares:
                        share_data = ShareInfo(
                            name=share.name,
                            comment=share.comments,
                            share_type=str(share.type)
                        )
                        
                        # Try to list files in share
                        try:
                            files = conn.listPath(share.name, '/')
                            share_data.files = [f.filename for f in files if f.filename not in ['.', '..']][:10]
                        except Exception as e:
                            share_data.access_error = str(e)
                        
                        share_info.append(share_data)
                    
                    # Write results to file
                    async with aiofiles.open(dialect_output_file, "w") as f:
                        for share in share_info:
                            await f.write(f"Share: {share.name}, Comment: {share.comment}, Type: {share.type}\n")
                            if share.files:
                                await f.write(f"  Files: {', '.join(share.files)}\n")
                            elif share.access_error:
                                await f.write(f"  Error listing files: {share.access_error}\n")
                    
                    results.append({
                        "dialect": dialect or "default",
                        "shares": [s.to_dict() for s in share_info]
                    })
                    
                    success = True
                    self.logger.info(f"Successfully enumerated shares with dialect {dialect or 'default'}")
                    break  # If successful, don't try other dialects
                    
            except Exception as e:
                self.logger.error(f"PySMB scan failed with dialect {dialect or 'default'}: {e}")
        
        # Write combined results
        if results:
            async with aiofiles.open(output_file, "w") as f:
                await f.write(json.dumps(results, indent=2))
        
        return ScanResult(
            target=self.target,
            scanner_name=self.name,
            success=success,
            message="Successfully enumerated shares" if success else "Failed to enumerate shares"
        )
        
    async def get_smb_info(self) -> SMBInfo:
        """Get SMB information directly from PySMB scanning"""
        info = SMBInfo()
        
        try:
            # Try different SMB dialects
            for dialect in ["SMB2", "SMB3", None]:  # None = default/auto-negotiate
                async with self.smb_connection(dialect=dialect) as conn:
                    if not conn:
                        continue
                    
                    # Got a connection, save the working dialect
                    info.dialect = dialect or "default"
                    
                    # List shares
                    shares = conn.listShares()
                    for share in shares:
                        share_info = ShareInfo(
                            name=share.name,
                            comment=share.comments,
                            share_type=str(share.type)
                        )
                        
                        # Try to list files in share
                        try:
                            files = conn.listPath(share.name, '/')
                            share_info.files = [f.filename for f in files if f.filename not in ['.', '..']][:10]
                        except Exception as e:
                            share_info.access_error = str(e)
                            
                        info.shares.append(share_info)
                    
                    break  # If we get here, we succeeded, so stop trying dialects
        except Exception as e:
            self.logger.error(f"Error getting SMB info via PySMB: {e}")
            
        return info


class CrackMapExecScanner(BaseScanner):
    """CrackMapExec scanner implementation"""
    @property
    def name(self) -> str:
        return "crackmapexec"
        
    async def scan(self) -> CommandScanResult:
        """Run CrackMapExec scan"""
        cmd = ["crackmapexec", "smb", self.target]
        
        if self.credential:
            cmd.extend(["-u", self.credential.username, "-p", self.credential.password])
            
        output_file = self.get_output_file()
        success, output = await self.executor.execute(cmd, output_file)
        
        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="Completed successfully" if success else "Scan failed"
        )


class ImpacketSecretsDumpScanner(BaseScanner):
    """Impacket SecretsDump scanner implementation"""
    @property
    def name(self) -> str:
        return "secretsdump"
        
    async def scan(self) -> CommandScanResult:
        """Run Impacket SecretsDump scan"""
        if not self.credential:
            return CommandScanResult(
                target=self.target,
                scanner_name=self.name,
                command=[],
                success=False,
                message="No credentials provided for SecretsDump scan"
            )
            
        username = self.credential.username or "guest"
        password = self.credential.password or ""
        
        cmd = ["secretsdump.py", f"{username}:{password}@{self.target}"]
        output_file = self.get_output_file()
        success, output = await self.executor.execute(cmd, output_file)
        
        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="Completed successfully" if success else "Scan failed"
        )


# ----- Scan Strategies -----

class ScanStrategy(ABC):
    """Abstract base class for scan strategies"""
    def __init__(self, target: str, config: SMBScannerConfig, results_dir: str = "smb_results"):
        self.target = target
        self.config = config
        self.results_dir = results_dir
        self.logger = logging.getLogger(self.__class__.__name__)
        
    @abstractmethod
    async def execute(self, credential: Optional[Credential] = None) -> AggregatedResult:
        """Execute the scanning strategy"""
        pass


class ComprehensiveScanStrategy(ScanStrategy):
    """Runs all available scans"""
    async def execute(self, credential: Optional[Credential] = None) -> AggregatedResult:
        """Execute all scanners"""
        self.logger.info(f"Starting comprehensive scan of {self.target}")
        
        # Create scanners
        scanners = [
            NmapScanner(self.target, self.config, credential, self.results_dir),
            Enum4LinuxScanner(self.target, self.config, credential, self.results_dir),
            SMBMapScanner(self.target, self.config, credential, self.results_dir),
            PySMBScanner(self.target, self.config, credential, self.results_dir),
            CrackMapExecScanner(self.target, self.config, credential, self.results_dir),
        ]
        
        # Add ImpacketSecretsDump if we have credentials
        if credential and credential.username:
            scanners.append(ImpacketSecretsDumpScanner(self.target, self.config, credential, self.results_dir))
        
        # Run all scanners
        results = AggregatedResult(self.target)
        
        for scanner in scanners:
            try:
                self.logger.info(f"Running {scanner.name} scanner")
                scan_result = await scanner.scan()
                results.add_result(scan_result)
                
                # Try to parse results for SMB info
                if hasattr(scanner, "parse_results") and scan_result.success:
                    # Add information from this scanner
                    try:
                        scanner_info = await scanner.parse_results(scan_result.output_file)
                        
                        # Merge scanner_info into results.smb_info
                        results.smb_info.shares.extend(scanner_info.shares)
                        results.smb_info.users.update(scanner_info.users)
                        results.smb_info.groups.update(scanner_info.groups)
                        results.smb_info.vulnerabilities.extend(scanner_info.vulnerabilities)
                        
                        if scanner_info.os_info:
                            results.smb_info.os_info.update(scanner_info.os_info)
                            
                        if scanner_info.protocols:
                            results.smb_info.protocols.extend(scanner_info.protocols)
                            
                        if scanner_info.dialect:
                            results.smb_info.dialect = scanner_info.dialect
                    except Exception as e:
                        self.logger.error(f"Error parsing results from {scanner.name}: {e}")
                
            except Exception as e:
                self.logger.error(f"Error running {scanner.name} scanner: {e}")
                results.add_result(ScanResult(
                    target=self.target,
                    scanner_name=scanner.name,
                    success=False,
                    message=f"Scan failed with error: {str(e)}"
                ))
        
        # Save aggregated results
        report_file = os.path.join(self.results_dir, f"report_{self.target}.json")
        await results.save_to_file(report_file)
        self.logger.info(f"Comprehensive scan complete, report saved to {report_file}")
        
        return results


class IntelligentScanStrategy(ScanStrategy):
    """Intelligently selects and runs scans based on initial findings"""
    async def quick_port_scan(self) -> List[int]:
        """Quick check if SMB ports are open"""
        executor = CommandExecutor(timeout=5)
        open_ports = []
        
        for port in [445, 139]:
            cmd = ["nc", "-z", "-w", "1", self.target, str(port)]
            success, _ = await executor.execute(cmd)
            if success:
                open_ports.append(port)
                
        return open_ports
    
    async def execute(self, credential: Optional[Credential] = None) -> AggregatedResult:
        """Execute intelligent scanning strategy"""
        self.logger.info(f"Starting intelligent scan of {self.target}")
        results = AggregatedResult(self.target)
        
        # Step 1: Check if SMB ports are open
        ports_open = await self.quick_port_scan()
        if not ports_open:
            self.logger.info(f"No SMB ports open on {self.target}")
            results.add_result(ScanResult(
                target=self.target,
                scanner_name="port_scan",
                success=True,
                message="No SMB ports open"
            ))
            return results
            
        self.logger.info(f"SMB ports open on {self.target}: {ports_open}")
        
        # Step 2: Run initial recon with Nmap
        nmap_scanner = NmapScanner(self.target, self.config, credential, self.results_dir)
        nmap_result = await nmap_scanner.scan()
        results.add_result(nmap_result)
        
        # Step 3: Parse Nmap results
        if nmap_result.success:
            nmap_info = await nmap_scanner.parse_results(nmap_result.output_file)
            
            # Merge nmap_info into results.smb_info
            results.smb_info.shares.extend(nmap_info.shares)
            results.smb_info.users.update(nmap_info.users)
            results.smb_info.vulnerabilities.extend(nmap_info.vulnerabilities)
            results.smb_info.protocols.extend(nmap_info.protocols)
            
            # Step 4: Based on findings, run additional scans
            
            # If vulnerabilities were found, do detailed vulnerability scans
            if nmap_info.vulnerabilities:
                self.logger.info(f"Vulnerabilities found: {nmap_info.vulnerabilities}, running detailed scans")
                # Run special vulnerability scans here
                vuln_scanner = NmapScanner(self.target, self.config, credential, self.results_dir)
                vuln_result = await vuln_scanner.scan("--script=smb-vuln*")
                results.add_result(vuln_result)
            
            # If authentication info provided, try authenticated scans
            authenticated_scanners = []
            if credential and credential.username:
                self.logger.info(f"Running authenticated scans as {credential.username}")
                authenticated_scanners = [
                    SMBMapScanner(self.target, self.config, credential, self.results_dir),
                    CrackMapExecScanner(self.target, self.config, credential, self.results_dir),
                    PySMBScanner(self.target, self.config, credential, self.results_dir),
                    ImpacketSecretsDumpScanner(self.target, self.config, credential, self.results_dir)
                ]
            else:
                # Run some basic enumeration tools
                self.logger.info("Running unauthenticated scans")
                authenticated_scanners = [
                    Enum4LinuxScanner(self.target, self.config, credential, self.results_dir),
                    SMBMapScanner(self.target, self.config, credential, self.results_dir)
                ]
                
            # Run selected scanners
            for scanner in authenticated_scanners:
                try:
                    self.logger.info(f"Running {scanner.name} scanner")
                    scan_result = await scanner.scan()
                    results.add_result(scan_result)
                    
                    # Try to parse results for SMB info
                    if hasattr(scanner, "parse_results") and scan_result.success:
                        try:
                            scanner_info = await scanner.parse_results(scan_result.output_file)
                            
                            # Merge scanner_info into results.smb_info
                            results.smb_info.shares.extend(scanner_info.shares)
                            results.smb_info.users.update(scanner_info.users)
                            results.smb_info.groups.update(scanner_info.groups)
                            results.smb_info.vulnerabilities.extend(scanner_info.vulnerabilities)
                            
                            if scanner_info.os_info:
                                results.smb_info.os_info.update(scanner_info.os_info)
                                
                            if scanner_info.protocols:
                                results.smb_info.protocols.extend(scanner_info.protocols)
                                
                            if scanner_info.dialect:
                                results.smb_info.dialect = scanner_info.dialect
                        except Exception as e:
                            self.logger.error(f"Error parsing results from {scanner.name}: {e}")
                    
                except Exception as e:
                    self.logger.error(f"Error running {scanner.name} scanner: {e}")
                    results.add_result(ScanResult(
                        target=self.target,
                        scanner_name=scanner.name,
                        success=False,
                        message=f"Scan failed with error: {str(e)}"
                    ))
        
        # Save aggregated results
        report_file = os.path.join(self.results_dir, f"report_{self.target}.json")
        await results.save_to_file(report_file)
        self.logger.info(f"Intelligent scan complete, report saved to {report_file}")
        
        return results


class StealthyScanStrategy(ScanStrategy):
    """Runs scans in a stealthier way with delays and slower timing"""
    async def execute(self, credential: Optional[Credential] = None) -> AggregatedResult:
        """Execute stealthy scanning strategy"""
        self.logger.info(f"Starting stealthy scan of {self.target}")
        results = AggregatedResult(self.target)
        
        # Create scanners with intentional delays between them
        scanners = [
            NmapScanner(self.target, self.config, credential, self.results_dir),
            Enum4LinuxScanner(self.target, self.config, credential, self.results_dir),
            SMBMapScanner(self.target, self.config, credential, self.results_dir)
        ]
        
        # Run scanners with delays
        for scanner in scanners:
            try:
                # Random delay before scan
                delay = random.uniform(3, 10)
                self.logger.info(f"Waiting {delay:.2f} seconds before running {scanner.name}")
                await asyncio.sleep(delay)
                
                self.logger.info(f"Running {scanner.name} scanner stealthily")
                
                # Use more stealth options for specific scanners
                if scanner.name == "nmap":
                    scan_result = await scanner.scan("-T2")  # Slower timing
                else:
                    scan_result = await scanner.scan()
                    
                results.add_result(scan_result)
                
                # Try to parse results for SMB info
                if hasattr(scanner, "parse_results") and scan_result.success:
                    try:
                        scanner_info = await scanner.parse_results(scan_result.output_file)
                        
                        # Merge scanner_info into results.smb_info
                        results.smb_info.shares.extend(scanner_info.shares)
                        results.smb_info.users.update(scanner_info.users)
                        results.smb_info.groups.update(scanner_info.groups)
                        results.smb_info.vulnerabilities.extend(scanner_info.vulnerabilities)
                        
                        if scanner_info.os_info:
                            results.smb_info.os_info.update(scanner_info.os_info)
                            
                        if scanner_info.protocols:
                            results.smb_info.protocols.extend(scanner_info.protocols)
                            
                        if scanner_info.dialect:
                            results.smb_info.dialect = scanner_info.dialect
                    except Exception as e:
                        self.logger.error(f"Error parsing results from {scanner.name}: {e}")
                
            except Exception as e:
                self.logger.error(f"Error running {scanner.name} scanner: {e}")
                results.add_result(ScanResult(
                    target=self.target,
                    scanner_name=scanner.name,
                    success=False,
                    message=f"Scan failed with error: {str(e)}"
                ))
        
        # Save aggregated results
        report_file = os.path.join(self.results_dir, f"report_{self.target}.json")
        await results.save_to_file(report_file)
        self.logger.info(f"Stealthy scan complete, report saved to {report_file}")
        
        return results


# ----- Facade Class for SMB Enumeration -----

class SMBEnumerator:
    """Main facade class for SMB enumeration"""
    def __init__(self, targets: List[str], config: SMBScannerConfig = None, 
                 username: str = None, password: str = None, 
                 cred_file: str = None, results_dir: str = "smb_results"):
        self.targets = targets
        self.config = config or SMBScannerConfig({})
        self.results_dir = results_dir
        self.logger = logging.getLogger(__name__)
        
        # Set up credential manager
        default_credential = Credential(username, password) if username or password else None
        self.cred_manager = CredentialManager(default_credential, cred_file)
        
        # Create results directory
        os.makedirs(results_dir, exist_ok=True)
        
    async def validate_environment(self) -> bool:
        """Validate the environment"""
        validator = EnvironmentValidator(self.config)
        return await validator.validate()
        
    async def scan_target(self, target: str, strategy_name: str = "intelligent") -> AggregatedResult:
        """Scan a single target"""
        self.logger.info(f"Starting scan of {target} using {strategy_name} strategy")
        
        # Create the appropriate strategy
        if strategy_name == "comprehensive":
            strategy = ComprehensiveScanStrategy(target, self.config, self.results_dir)
        elif strategy_name == "stealthy":
            strategy = StealthyScanStrategy(target, self.config, self.results_dir)
        else:  # Default to intelligent
            strategy = IntelligentScanStrategy(target, self.config, self.results_dir)
        
        # Try authentication with different credentials
        credential = None
        for cred in self.cred_manager.get_credentials():
            self.logger.info(f"Trying credential: {cred.username}")
            
            # Test SMB connection with this credential
            pysmb_scanner = PySMBScanner(target, self.config, cred, self.results_dir)
            try:
                async with pysmb_scanner.smb_connection() as conn:
                    if conn:
                        self.logger.info(f"Authentication successful with {cred.username}")
                        credential = cred
                        break
            except Exception:
                pass
        
        # Execute the strategy with the best credential (or None if none worked)
        return await strategy.execute(credential)
        
    async def run(self, strategy_name: str = "intelligent") -> Dict[str, AggregatedResult]:
        """Run the scan on all targets"""
        if not await self.validate_environment():
            self.logger.error("Environment validation failed")
            return {}
            
        results = {}
        for target in self.targets:
            try:
                result = await self.scan_target(target, strategy_name)
                results[target] = result
            except Exception as e:
                self.logger.error(f"Error scanning {target}: {e}")
                
        return results


# ----- Report Generator -----

class ReportGenerator:
    """Generates reports from scan results"""
    def __init__(self, results_dir: str = "smb_results"):
        self.results_dir = results_dir
        self.logger = logging.getLogger(__name__)
        
    async def generate_summary(self, results: Dict[str, AggregatedResult]) -> str:
        """Generate a summary of scan results"""
        summary = "== Scan Summary ==\n\n"
        
        for target, result in results.items():
            summary += f"Target: {target}\n"
            
            shares = len(result.smb_info.shares)
            users = len(result.smb_info.users)
            vulns = len(result.smb_info.vulnerabilities)
            
            summary += f"  Shares: {shares}, Users: {users}, Vulnerabilities: {vulns}\n"
            
            if vulns > 0:
                summary += f"  Vulnerabilities found: {', '.join(result.smb_info.vulnerabilities)}\n"
                
            summary += f"  Detailed report: {self.results_dir}/report_{target}.json\n\n"
            
        return summary
        
    async def print_summary(self, results: Dict[str, AggregatedResult]):
        """Print summary to console"""
        summary = await self.generate_summary(results)
        print(summary)
        
    async def generate_full_report(self, results: Dict[str, AggregatedResult]) -> str:
        """Generate a full report of scan results"""
        report = "================================\n"
        report += "SMB Enumeration - Full Report\n"
        report += f"Date: {datetime.now().isoformat()}\n"
        report += "================================\n\n"
        
        for target, result in results.items():
            report += f"Target: {target}\n"
            report += "--------------------------------\n\n"
            
            # OS Info
            if result.smb_info.os_info:
                report += "OS Information:\n"
                for k, v in result.smb_info.os_info.items():
                    report += f"  {k}: {v}\n"
                report += "\n"
                
            # SMB Protocol Info
            if result.smb_info.protocols:
                report += "SMB Protocols:\n"
                for protocol in result.smb_info.protocols:
                    report += f"  {protocol}\n"
                report += "\n"
                
            # Shares
            if result.smb_info.shares:
                report += "Shares:\n"
                for share in result.smb_info.shares:
                    report += f"  Name: {share.name}\n"
                    if share.comment:
                        report += f"    Comment: {share.comment}\n"
                    if share.type:
                        report += f"    Type: {share.type}\n"
                    if share.files:
                        report += f"    Files: {', '.join(share.files[:5])}"
                        if len(share.files) > 5:
                            report += f" (+{len(share.files) - 5} more)"
                        report += "\n"
                    report += "\n"
                
            # Users
            if result.smb_info.users:
                report += "Users:\n"
                for user in sorted(result.smb_info.users):
                    report += f"  {user}\n"
                report += "\n"
                
            # Groups
            if result.smb_info.groups:
                report += "Groups:\n"
                for group in sorted(result.smb_info.groups):
                    report += f"  {group}\n"
                report += "\n"
                
            # Vulnerabilities
            if result.smb_info.vulnerabilities:
                report += "Vulnerabilities:\n"
                for vuln in result.smb_info.vulnerabilities:
                    report += f"  {vuln}\n"
                report += "\n"
                
            report += "\n"
            
        return report
        
    async def save_full_report(self, results: Dict[str, AggregatedResult], output_file: str = None):
        """Save full report to file"""
        if not output_file:
            output_file = os.path.join(self.results_dir, f"full_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            
        report = await self.generate_full_report(results)
        
        async with aiofiles.open(output_file, "w") as f:
            await f.write(report)
            
        self.logger.info(f"Full report saved to {output_file}")
        

# ----- Command Line Interface -----

async def main_async():
    """Main async entry point"""
    parser = argparse.ArgumentParser(description="Object-Oriented SMB Enumeration Tool")
    parser.add_argument("-t", "--targets", nargs="+", required=True, help="Target IP address(es)")
    parser.add_argument("-u", "--username", type=str, help="Username for authentication")
    parser.add_argument("-p", "--password", type=str, help="Password for authentication")
    parser.add_argument("--config", type=str, default="config.yaml", help="Path to configuration file")
    parser.add_argument("--cred-file", type=str, help="File containing credentials (username:password format)")
    parser.add_argument("--strategy", type=str, choices=["intelligent", "comprehensive", "stealthy"], 
                       default="intelligent", help="Scanning strategy to use")
    parser.add_argument("--results-dir", type=str, default="smb_results", help="Directory to store results")
    args = parser.parse_args()
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("smb_enum.log"),
            logging.StreamHandler()
        ]
    )
    
    # Load config
    config = await SMBScannerConfig.from_yaml(args.config)
    
    # Create the SMB enumerator
    enumerator = SMBEnumerator(
        targets=args.targets,
        config=config,
        username=args.username,
        password=args.password,
        cred_file=args.cred_file,
        results_dir=args.results_dir
    )
    
    # Run the scan
    results = await enumerator.run(args.strategy)
    
    # Generate and print report
    report_generator = ReportGenerator(args.results_dir)
    await report_generator.print_summary(results)
    await report_generator.save_full_report(results)


def main():
    """Entry point for the script"""
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
