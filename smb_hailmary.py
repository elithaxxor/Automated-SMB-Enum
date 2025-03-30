import asyncio
import subprocess
import os
import logging
import enum
from typing import List, Dict, Optional, Set, Union, Tuple

# ---- Nmap Preference Enums ----

class StealthLevel(enum.Enum):
    VERY_STEALTHY = 0
    STEALTHY = 1
    BALANCED = 2
    AGGRESSIVE = 3
    VERY_AGGRESSIVE = 4
    
    def __str__(self):
        return self.name.replace("_", " ").title()


class ScanSpeed(enum.Enum):
    PARANOID = 0  # T0
    SNEAKY = 1    # T1
    POLITE = 2    # T2
    NORMAL = 3    # T3
    AGGRESSIVE = 4  # T4
    INSANE = 5    # T5
    
    def __str__(self):
        return self.name.title()
    
    @property
    def timing_option(self):
        return f"-T{self.value}"


# ---- Enhanced Nmap Functionality ----

class NmapPreferences:
    """Class to hold Nmap scanning preferences"""
    
    def __init__(self, 
                 stealth_level: StealthLevel = StealthLevel.BALANCED,
                 scan_speed: ScanSpeed = ScanSpeed.NORMAL,
                 service_detection: bool = True,
                 os_detection: bool = False,
                 script_scan: bool = True):
        self.stealth_level = stealth_level
        self.scan_speed = scan_speed
        self.service_detection = service_detection
        self.os_detection = os_detection
        self.script_scan = script_scan
        
    def get_timing_options(self) -> List[str]:
        """Get timing options for Nmap based on preferences"""
        return [self.scan_speed.timing_option]
    
    def get_smb_scripts(self) -> List[str]:
        """Get appropriate SMB scripts based on stealth level"""
        # Basic scripts always included
        basic_scripts = ["smb-protocols", "smb-security-mode"]
        
        # Enum scripts - slightly more noisy
        enum_scripts = ["smb-enum-shares", "smb-enum-users", "smb-enum-sessions"]
        
        # System info scripts - more information but potentially more noisy
        info_scripts = ["smb-os-discovery", "smb-system-info"]
        
        # Vulnerability scripts - noisy and potentially detected by security systems
        vuln_scripts = ["smb-vuln-ms17-010", "smb-vuln-cve-2017-7494", 
                      "smb-double-pulsar-backdoor"]
        
        # Advanced vulnerability scripts - very noisy and potentially disruptive
        advanced_vuln_scripts = ["smb-brute", "smb-vuln*"]
        
        if self.stealth_level == StealthLevel.VERY_STEALTHY:
            return basic_scripts
        elif self.stealth_level == StealthLevel.STEALTHY:
            return basic_scripts + enum_scripts
        elif self.stealth_level == StealthLevel.BALANCED:
            return basic_scripts + enum_scripts + info_scripts
        elif self.stealth_level == StealthLevel.AGGRESSIVE:
            return basic_scripts + enum_scripts + info_scripts + vuln_scripts
        else:  # VERY_AGGRESSIVE
            return basic_scripts + enum_scripts + info_scripts + vuln_scripts + advanced_vuln_scripts
    
    def get_scan_options(self) -> List[str]:
        """Get scan options based on preferences"""
        options = []
        
        # Add timing options
        options.extend(self.get_timing_options())
        
        # Add service detection if enabled
        if self.service_detection:
            options.append("-sV")
        
        # Add OS detection if enabled
        if self.os_detection:
            options.append("-O")
        
        # Adjust scan options based on stealth level
        if self.stealth_level == StealthLevel.VERY_STEALTHY:
            options.extend(["-sS", "--max-retries", "1", "--min-rate", "10"])
        elif self.stealth_level == StealthLevel.STEALTHY:
            options.extend(["-sS", "--max-retries", "2", "--min-rate", "50"])
        elif self.stealth_level == StealthLevel.BALANCED:
            # Default Nmap options are good for balanced
            pass
        elif self.stealth_level == StealthLevel.AGGRESSIVE:
            options.extend(["--min-rate", "300", "--max-retries", "3"])
        else:  # VERY_AGGRESSIVE
            options.extend(["--min-rate", "1000", "--max-retries", "2"])
        
        return options


class EnhancedNmapScanner(BaseScanner):
    """Enhanced Nmap scanner with flexible configuration options"""
    
    def __init__(self, target: str, config: ScannerConfig, 
                 credential: Optional[Credential] = None, 
                 results_dir: str = "smb_results",
                 preferences: Optional[NmapPreferences] = None):
        super().__init__(target, config, credential, results_dir)
        self.preferences = preferences or NmapPreferences()
        
    @property
    def name(self) -> str:
        return "enhanced_nmap"
        
    async def scan(self, additional_options: Optional[str] = None) -> CommandScanResult:
        """Run enhanced Nmap scan with configured preferences"""
        # Start with basic command
        cmd = ["nmap", "-p139,445"]
        
        # Add options from preferences
        cmd.extend(self.preferences.get_scan_options())
        
        # Add script scan if enabled
        if self.preferences.script_scan:
            scripts = self.preferences.get_smb_scripts()
            if scripts:
                cmd.extend([f"--script={','.join(scripts)}"])
        
        # Add any additional options
        if additional_options:
            cmd.extend(additional_options.split())
            
        # Add the target
        cmd.append(self.target)
        
        # Run the scan
        self.logger.info(f"Running enhanced Nmap scan with {len(cmd)} options")
        output_file = self.get_output_file()
        success, output = await self.executor.execute(cmd, output_file)
        
        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="Enhanced Nmap scan completed successfully" if success else "Enhanced Nmap scan failed"
        )
    
    async def parse_results(self, output_file: str) -> SMBInfo:
        """Parse enhanced Nmap results"""
        # This would be the same as the original NmapScanner's parse_results method
        # Reusing the parsing logic from the original implementation
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
                            
                # Extract OS info
                if "OS details:" in content:
                    os_line = content.split("OS details:")[1].split("\n")[0].strip()
                    info.os_info["os_details"] = os_line
                
        except Exception as e:
            self.logger.error(f"Error parsing enhanced Nmap results: {e}")
            
        return info


# ---- Vulnerability Scanning ----

class VulnerabilityScanner(BaseScanner):
    """Scanner for finding vulnerabilities using Nmap and Metasploit"""
    
    def __init__(self, target: str, config: ScannerConfig, 
                 credential: Optional[Credential] = None, 
                 results_dir: str = "smb_results",
                 use_metasploit: bool = True,
                 aggressive: bool = False):
        super().__init__(target, config, credential, results_dir)
        self.use_metasploit = use_metasploit
        self.aggressive = aggressive
        
    @property
    def name(self) -> str:
        return "vuln_scanner"
    
    async def nmap_vuln_scan(self) -> CommandScanResult:
        """Run Nmap vulnerability scan"""
        # Configure an aggressive Nmap scan for vulnerabilities
        preferences = NmapPreferences(
            stealth_level=StealthLevel.VERY_AGGRESSIVE if self.aggressive else StealthLevel.AGGRESSIVE,
            scan_speed=ScanSpeed.AGGRESSIVE,
            service_detection=True,
            os_detection=True,
            script_scan=True
        )
        
        # Create and run enhanced Nmap scanner
        nmap_scanner = EnhancedNmapScanner(
            self.target, 
            self.config, 
            self.credential, 
            self.results_dir,
            preferences
        )
        
        # Add specific vulnerability scripts
        additional_options = "--script=vuln,exploit,auth,brute"
        
        self.logger.info("Starting Nmap vulnerability scan")
        return await nmap_scanner.scan(additional_options)
    
    async def metasploit_vuln_scan(self) -> CommandScanResult:
        """Run Metasploit vulnerability scan"""
        # Create a resource file for Metasploit
        resource_file = os.path.join(self.results_dir, f"msf_scan_{self.target}.rc")
        output_file = self.get_output_file("_metasploit")
        
        # Build Metasploit commands
        msf_commands = [
            "workspace -a smb_enum",
            f"db_nmap -p 139,445 --script=smb-vuln* {self.target}",
            "use auxiliary/scanner/smb/smb_version",
            f"set RHOSTS {self.target}",
            "run",
            "use auxiliary/scanner/smb/smb_enumshares",
            f"set RHOSTS {self.target}"
        ]
        
        # Add credential info if available
        if self.credential and self.credential.username:
            msf_commands.extend([
                f"set SMBUser {self.credential.username}",
                f"set SMBPass {self.credential.password}"
            ])
        
        msf_commands.append("run")
        
        # Add more aggressive scans if requested
        if self.aggressive:
            msf_commands.extend([
                "use auxiliary/scanner/smb/smb_login",
                f"set RHOSTS {self.target}",
                "set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt",
                "set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt",
                "set VERBOSE false",
                "run",
                "use auxiliary/scanner/smb/pipe_auditor",
                f"set RHOSTS {self.target}",
                "run",
                "use auxiliary/scanner/smb/smb2",
                f"set RHOSTS {self.target}",
                "run"
            ])
        
        # Add EternalBlue check
        msf_commands.extend([
            "use auxiliary/scanner/smb/ms17_010",
            f"set RHOSTS {self.target}",
            "run"
        ])
        
        # Generate report
        msf_commands.extend([
            "vulns",
            "services",
            "exit"
        ])
        
        # Write resource file
        async with aiofiles.open(resource_file, "w") as f:
            await f.write("\n".join(msf_commands))
        
        # Run Metasploit with resource file
        cmd = ["msfconsole", "-q", "-r", resource_file]
        success, output = await self.executor.execute(cmd, output_file, timeout=300)  # 5 minute timeout
        
        return CommandScanResult(
            target=self.target,
            scanner_name=f"{self.name}_metasploit",
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="Metasploit vulnerability scan completed" if success else "Metasploit vulnerability scan failed"
        )
    
    async def scan(self) -> List[CommandScanResult]:
        """Run vulnerability scans with both Nmap and Metasploit"""
        self.logger.info(f"Starting vulnerability scan of {self.target}")
        results = []
        
        # Run Nmap vulnerability scan
        nmap_result = await self.nmap_vuln_scan()
        results.append(nmap_result)
        
        # If requested, also run Metasploit scan
        if self.use_metasploit:
            try:
                msf_result = await self.metasploit_vuln_scan()
                results.append(msf_result)
            except Exception as e:
                self.logger.error(f"Error running Metasploit scan: {e}")
                results.append(CommandScanResult(
                    target=self.target,
                    scanner_name=f"{self.name}_metasploit",
                    command=["msfconsole"],
                    success=False,
                    message=f"Metasploit vulnerability scan failed: {str(e)}"
                ))
        
        # Process and combine results
        await self.process_vulnerability_results(results)
        
        return results
    
    async def process_vulnerability_results(self, scan_results: List[CommandScanResult]):
        """Process and aggregate vulnerability results"""
        vulnerabilities = []
        
        # Process Nmap results
        nmap_result = next((r for r in scan_results if r.scanner_name == self.name), None)
        if nmap_result and nmap_result.success and nmap_result.output_file:
            nmap_vulns = await self.parse_nmap_vulnerabilities(nmap_result.output_file)
            vulnerabilities.extend(nmap_vulns)
        
        # Process Metasploit results
        msf_result = next((r for r in scan_results if r.scanner_name == f"{self.name}_metasploit"), None)
        if msf_result and msf_result.success and msf_result.output_file:
            msf_vulns = await self.parse_metasploit_vulnerabilities(msf_result.output_file)
            vulnerabilities.extend(msf_vulns)
        
        # Write combined vulnerability report
        report_file = self.get_output_file("_vulnerability_report")
        async with aiofiles.open(report_file, "w") as f:
            await f.write(f"Vulnerability Scan Report for {self.target}\n")
            await f.write("=" * 50 + "\n\n")
            
            if vulnerabilities:
                await f.write(f"Found {len(vulnerabilities)} potential vulnerabilities:\n\n")
                
                for i, vuln in enumerate(vulnerabilities, 1):
                    await f.write(f"{i}. {vuln['name']}\n")
                    if 'description' in vuln:
                        await f.write(f"   Description: {vuln['description']}\n")
                    if 'severity' in vuln:
                        await f.write(f"   Severity: {vuln['severity']}\n")
                    if 'cve' in vuln:
                        await f.write(f"   CVE: {vuln['cve']}\n")
                    await f.write("\n")
            else:
                await f.write("No vulnerabilities detected in the scan.\n")
        
        self.logger.info(f"Vulnerability report generated at {report_file}")
    
    async def parse_nmap_vulnerabilities(self, output_file: str) -> List[Dict]:
        """Parse Nmap output for vulnerabilities"""
        vulnerabilities = []
        
        try:
            async with aiofiles.open(output_file, "r") as f:
                content = await f.read()
                
                # Look for vulnerability scripts output
                if "VULNERABLE" in content:
                    # Split by vulnerability script sections
                    sections = []
                    for script in ["smb-vuln", "vulners", "ssl-", "http-vuln"]:
                        if script in content:
                            sections.extend(content.split(script)[1:])
                    
                    for section in sections:
                        if "VULNERABLE" in section:
                            # Extract CVE if present
                            cve = None
                            cve_match = re.search(r'(CVE-\d{4}-\d+)', section)
                            if cve_match:
                                cve = cve_match.group(1)
                            
                            # Extract name
                            name_line = section.strip().split('\n')[0]
                            name = name_line.split(':')[0].strip()
                            
                            # Extract description
                            description = "Vulnerability detected by Nmap"
                            desc_match = re.search(r'\|[_\s]+(.*?)\n', section)
                            if desc_match:
                                description = desc_match.group(1).strip()
                            
                            vulnerabilities.append({
                                'name': name,
                                'description': description,
                                'cve': cve,
                                'severity': 'HIGH' if "VULNERABLE" in section else 'MEDIUM',
                                'source': 'nmap'
                            })
        except Exception as e:
            self.logger.error(f"Error parsing Nmap vulnerability results: {e}")
        
        return vulnerabilities
    
    async def parse_metasploit_vulnerabilities(self, output_file: str) -> List[Dict]:
        """Parse Metasploit output for vulnerabilities"""
        vulnerabilities = []
        
        try:
            async with aiofiles.open(output_file, "r") as f:
                content = await f.read()
                
                # Extract vulnerabilities from Metasploit output
                if "msf" in content:
                    # Look for vulnerability scanner outputs
                    ms17_010 = re.search(r'MS17-010.*?vulnerable', content, re.IGNORECASE)
                    if ms17_010:
                        vulnerabilities.append({
                            'name': 'MS17-010 EternalBlue',
                            'description': 'SMB Remote Code Execution Vulnerability',
                            'cve': 'CVE-2017-0144',
                            'severity': 'CRITICAL',
                            'source': 'metasploit'
                        })
                    
                    # Look for other vulnerabilities reported
                    vuln_sections = re.findall(r'(\[\+\].*?vulnerable.*?)$', content, re.MULTILINE)
                    for section in vuln_sections:
                        vulnerabilities.append({
                            'name': section.strip(),
                            'description': 'Vulnerability detected by Metasploit',
                            'severity': 'HIGH',
                            'source': 'metasploit'
                        })
                    
                    # Extract from vulns table if present
                    if "Vulnerabilities" in content and "=" * 10 in content:
                        vuln_table = content.split("Vulnerabilities")[1].split("=" * 10)[0]
                        vuln_lines = [line.strip() for line in vuln_table.split('\n') if line.strip()]
                        
                        for line in vuln_lines:
                            if len(line.split()) >= 3:
                                parts = line.split()
                                vulnerabilities.append({
                                    'name': ' '.join(parts[2:]),
                                    'severity': parts[1].upper() if parts[1].upper() in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] else 'MEDIUM',
                                    'source': 'metasploit'
                                })
        
        except Exception as e:
            self.logger.error(f"Error parsing Metasploit vulnerability results: {e}")
        
        return vulnerabilities


# ---- Command Line Interface for Vulnerability Scanning ----

class VulnerabilityScanStrategy(ScanStrategy):
    """Strategy for vulnerability scanning"""
    
    def __init__(self, target: str, config: SMBScannerConfig, results_dir: str = "smb_results",
                 use_metasploit: bool = True, aggressive: bool = False):
        super().__init__(target, config, results_dir)
        self.use_metasploit = use_metasploit
        self.aggressive = aggressive
        
    async def execute(self, credential: Optional[Credential] = None) -> AggregatedResult:
        """Execute the vulnerability scanning strategy"""
        self.logger.info(f"Starting vulnerability scan of {self.target}")
        results = AggregatedResult(self.target)
        
        # Create and run vulnerability scanner
        vuln_scanner = VulnerabilityScanner(
            self.target,
            self.config,
            credential,
            self.results_dir,
            self.use_metasploit,
            self.aggressive
        )
        
        try:
            scan_results = await vuln_scanner.scan()
            
            # Add all scan results to aggregated results
            for result in scan_results:
                results.add_result(result)
            
            # Check if there's vulnerability information to add
            for result in scan_results:
                if result.scanner_name == vuln_scanner.name and result.success:
                    try:
                        # Parse Nmap vulnerability results
                        nmap_vulns = await vuln_scanner.parse_nmap_vulnerabilities(result.output_file)
                        
                        # Add vulnerabilities to SMB info
                        for vuln in nmap_vulns:
                            results.smb_info.vulnerabilities.append(vuln['name'])
                            
                    except Exception as e:
                        self.logger.error(f"Error processing Nmap vulnerability results: {e}")
            
            # Save the vulnerability report
            report_file = os.path.join(self.results_dir, f"vuln_report_{self.target}.json")
            await results.save_to_file(report_file)
            self.logger.info(f"Vulnerability scan complete, report saved to {report_file}")
            
        except Exception as e:
            self.logger.error(f"Error during vulnerability scan: {e}")
            results.add_result(ScanResult(
                target=self.target,
                scanner_name="vulnerability_scan",
                success=False,
                message=f"Scan failed with error: {str(e)}"
            ))
            
        return results


# ---- Updated CLI Arguments ----

async def main_async():
    """Main async entry point with extended functionality"""
    parser = argparse.ArgumentParser(description="Enhanced SMB Enumeration Tool with Vulnerability Scanning")
    parser.add_argument("-t", "--targets", nargs="+", required=True, help="Target IP address(es)")
    parser.add_argument("-u", "--username", type=str, help="Username for authentication")
    parser.add_argument("-p", "--password", type=str, help="Password for authentication")
    parser.add_argument("--config", type=str, default="config.yaml", help="Path to configuration file")
    parser.add_argument("--cred-file", type=str, help="File containing credentials (username:password format)")
    parser.add_argument("--results-dir", type=str, default="smb_results", help="Directory to store results")
    
    # Add scan strategy options
    strategy_group = parser.add_argument_group("Scan Strategy")
    strategy_group.add_argument("--strategy", type=str, 
                               choices=["intelligent", "comprehensive", "stealthy", "vulnerability"], 
                               default="intelligent", help="Scanning strategy to use")
    
    # Add Nmap scan preferences
    nmap_group = parser.add_argument_group("Nmap Scan Preferences")
    nmap_group.add_argument("--stealth-level", type=str, 
                           choices=["very_stealthy", "stealthy", "balanced", "aggressive", "very_aggressive"],
                           default="balanced", help="Stealth level for scans")
    nmap_group.add_argument("--scan-speed", type=str,
                           choices=["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"],
                           default="normal", help="Scan speed")
    nmap_group.add_argument("--service-detection", action="store_true", default=True,
                          help="Enable service detection (-sV)")
    nmap_group.add_argument("--os-detection", action="store_true", default=False,
                          help="Enable OS detection (-O)")
    
    # Add vulnerability scanning options
    vuln_group = parser.add_argument_group("Vulnerability Scanning")
    vuln_group.add_argument("--vuln-scan", action="store_true", help="Perform vulnerability scanning")
    vuln_group.add_argument("--use-metasploit", action="store_true", default=True,
                          help="Use Metasploit for vulnerability scanning")
    vuln_group.add_argument("--aggressive-vuln", action="store_true", default=False,
                          help="Use aggressive vulnerability scanning techniques")
    
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
    
    # Convert string arguments to enums
    stealth_level = StealthLevel[args.stealth_level.upper()]
    scan_speed = ScanSpeed[args.scan_speed.upper()]
    
    # Create Nmap preferences
    nmap_preferences = NmapPreferences(
        stealth_level=stealth_level,
        scan_speed=scan_speed,
        service_detection=args.service_detection,
        os_detection=args.os_detection,
        script_scan=True
    )
    
    # Create the SMB enumerator
    enumerator = SMBEnumerator(
        targets=args.targets,
        config=config,
        username=args.username,
        password=args.password,
        cred_file=args.cred_file,
        results_dir=args.results_dir
    )
    
    # Handle vulnerability scanning
    if args.vuln_scan or args.strategy == "vulnerability":
        logging.info("Performing vulnerability scan")
        
        # Create a vulnerability scan strategy for each target
        results = {}
        for target in args.targets:
            vuln_strategy = VulnerabilityScanStrategy(
                target=target,
                config=config,
                results_dir=args.results_dir,
                use_metasploit=args.use_metasploit,
                aggressive=args.aggressive_vuln
            )
            
            # Validate environment
            if await enumerator.validate_environment():
                # Create credential
                credential = None
                if args.username or args.password:
                    credential = Credential(args.username, args.password)
                
                # Execute vulnerability scan
                result = await vuln_strategy.execute(credential)
                results[target] = result
            else:
                logging.error("Environment validation failed")
                break
        
        # Generate report
        if results:
            report_generator = ReportGenerator(args.results_dir)
            await report_generator.print_summary(results)
            report_file = os.path.join(args.results_dir, "vulnerability_report.txt")
            await report_generator.save_full_report(results, report_file)
            logging.info(f"Vulnerability report saved to {report_file}")
    else:
        # Normal scan with enhanced Nmap options
        logging.info(f"Running {args.strategy} scan with {stealth_level} stealth level and {scan_speed} speed")
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
