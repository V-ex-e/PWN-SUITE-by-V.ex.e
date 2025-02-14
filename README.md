<ins>**Payload-creation-tool-
**</ins>
<sup>Update v1.4 10/9/2024</sup>

<sup> view in safety = https://www.youtube.com/watch?v=--srcJ9uV_U </sup>

 view online = https://drive.google.com/file/d/15GVtdcF5nQoM3-4qVxpG9ggdorQwjL9u/view?usp=sharing 

view my full youtube = https://www.youtube.com/@lil_ToT-XFZ1/videos

NOW WITH NEW OPTIONS 

<ins>![new options](https://github.com/user-attachments/assets/1cd25316-550e-4820-8d22-6d03228a043f)</ins>

<details>

<summary>Tips for collapsed sections</summary>

### How to start the script

```ruby
##IN THE BASH TERMINAL WITHIN THE SCRIPTS FOLDER
chmod +x ./pwn-suite.sh
###TO RUN THE SCRIPT
bash
Copy code
./pwn-suite.sh

## Feel free to customize and expand the script to suit your needs!
You can add text within a collapsed section.

##to write in it
nano pwn-suite.sh
##or use following to view into it
cat pwn-suite.sh
```

</details>

<ins>**Update v1.3 10/9/2024**</ins>

- whole array of new funcitonality
```ruby
echo "18) Create RAT"
echo "19) Generate Wi-Fi password sniffer"
echo "20) Generate simple SQL injection script"
echo "21) Create credential harvester"
echo "22) Start anonsurf"
echo "23) Start metasploit_framework"
echo "24) Start airgeddon "
echo "25) Start wireshark "
echo "26) DEAMON MANAGER by V.ex.e"
echo "27) Start listening for zombies"
```
**- new trojan**
    FULL WRAPPER FOR CUSTOM EXEs
   XOR Encryption:

    The script employs a simple XOR encryption method to obfuscate the IP address and port in the payload, making it less readable in the compiled executable.
    Dynamic Input Handling:
  
    :User-supplied IP and port values are dynamically integrated into the payload, which avoids hardcoding sensitive information.
    Payload Packing:
  
    The use of UPX (if available) to pack the trojan executable further reduces its size and makes static analysis more challenging.
**- deamon manager**
    Anonymous SSH Server Setup:
  
    The script installs and configures SSH on a specified port (default is 2222) and creates a non-root user for secure access.
    It configures Tor to route traffic anonymously, ensuring enhanced privacy.
    Connection Management:
    
    It allows users to listen for incoming SSH connections using netcat.
    The script maintains a dynamic array of connected clients, enabling the user to:
    View connected clients.
    Send commands to specific clients.
    Disconnect clients.
    Add new clients dynamically by inputting their addresses.

<ins>![new options2](https://github.com/user-attachments/assets/90bc55ac-5eb3-4b51-bf0c-143dec1f6459)</ins>
<details>

<summary Full feature list <3 </summary>

### Option description
./pwn-suite.sh - README
This Bash script provides a variety of payload generation tools with advanced obfuscation techniques. It integrates multiple features such as reverse shells, keyloggers, and obfuscated DLL/EXE payloads, all designed to bypass detection mechanisms. Below is a list of the functionalities and the corresponding obfuscation techniques used.

Features & Obfuscation Methods
1. Manual Obfuscated DLL Generation
Function: generate_obfuscated_dll()
Obfuscation: Randomized class and function names, with dynamic variable obfuscation for added complexity.
2. DLL Generation using msfvenom with Encoding
Function: generate_dll_with_msfvenom()
Obfuscation: Payload encoding via x86/shikata_ga_nai and Base64 encoding.
3. Encrypted EXE Loader
Function: create_encrypted_loader()
Obfuscation: AES-256 encryption for the payload and a self-decrypting PowerShell loader.
4. Ncat Reverse Shell with Persistence
Function: create_ncat_reverse_shell()
Obfuscation: Randomized sleep intervals for stealth and persistent reconnection attempts.
5. PowerShell Reverse Shell with Advanced Obfuscation
Function: create_powershell_reverse_shell()
Obfuscation: PowerShell command obfuscation using Base64 encoding with IEX injection.
6. Batch Reverse Shell with Dynamic Variable Names
Function: create_batch_reverse_shell()
Obfuscation: Dynamic environment variable usage and randomized sleep periods.
7. Python Reverse Shell with Dynamic Encoding
Function: create_python_reverse_shell()
Obfuscation: Base64-encoded Python commands for payload obfuscation.
8. Advanced Keylogger
Function: generate_keylogger()
Obfuscation: Keystrokes are encoded using Base64 before being logged for minimal detection.
9. Trojan Executable with Obfuscation
Function: generate_trojan_executable()
Obfuscation: Simple wrapper around a benign executable to hide the payload.
Updated v1.3 = Full wrapper around a benign executable to hide the payload. Fully obfuscated Payload generation and wrapping around custom EXE
11. Phishing Page with Embedded JavaScript
Function: create_phishing_page()
Obfuscation: The phishing page dynamically redirects users to a malicious URL after credentials are captured.
12. Windows Service Payload with Encrypted Storage
Function: generate_windows_service_payload()
Obfuscation: Windows service created with AES-256 encrypted payload storage.
13. USB Exploitation Payload with Autorun
Function: create_usb_exploitation_payload()
Obfuscation: Embedded autorun functionality for automatic execution from USB.
14. Reverse HTTPS Payload with Obfuscation
Function: generate_reverse_https_payload()
Obfuscation: Payload obfuscated via Base64 encoding and HTTPS communication.
15. Persistence via Windows Registry
Function: create_persistence_payload()
Obfuscation: Payload persistence achieved through Windows Registry modification.
16. Fake Update Payload
Function: generate_fake_update_payload()
Obfuscation: Simulated system update, meant to distract the user while malicious actions are performed.
17. Process Injection Payload
Function: create_process_injection_payload()
Obfuscation: Injects a DLL into a target process with manual error handling for stealth.
18. Stealthy Network Scanning Payload
Function: generate_network_scanning_payload()
Obfuscation: Uses nmap stealth scanning to avoid detection while scanning the network.
Additional Notes
Rainbow Art: The script displays a colorful Kali dragon logo at the beginning using dynamic ANSI color codes for a cool visual effect.
Dependency Checks: The script automatically checks and installs dependencies like gcc, mingw-w64, and msfvenom to ensure smooth operation on different systems.
Setup Instructions
Clone this repository.
bash
Copy code
git clone https://github.com/V-ex-e/PWN-SUITE-by-V.ex.e/
cd payload-generator

Make the script executable.
bash
Copy code
chmod +x ./pwn-suite.sh
Run the script.
bash
Copy code
./pwn-suite.sh
Feel free to customize and expand the script to suit your needs!
You can add text within a collapsed section.


</details>
<ins>![new options3](https://github.com/user-attachments/assets/90a39fba-db2e-4b3a-9008-3a83682abf98)</ins>

**- listenr**
    simple ncat listener
    listens for defined or cached LHost and Target Port Host

First Build  >>>>> v1.2 10/05/2024 = in Directory >>>>> "pwn-suite"

![pwn](https://github.com/user-attachments/assets/85bd6181-07cb-4614-b08a-bf6a14961205)





