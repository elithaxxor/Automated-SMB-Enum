import subprocess

def run_smb_enum_shares(target_ip, username=None, password=None, domain=None):
    base_command = ["nmap", "-p445", "--script", "smb-enum-shares.nse"]
    script_args = []
    
    if username:
        script_args.append(f"smbusername={username}")
    if password:
        script_args.append(f"smbpassword={password}")
    if domain:
        script_args.append(f"smbdomain={domain}")
    
    if script_args:
        base_command.append(f"--script-args={','.join(script_args)}")
    
    base_command.append(target_ip)
    
    result = subprocess.run(base_command, stdout=subprocess.PIPE, text=True)
    print(result.stdout)

run_smb_enum_shares("192.168.1.100", username="admin", password="securepass", domain="WORKGROUP")
