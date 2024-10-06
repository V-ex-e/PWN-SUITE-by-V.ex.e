Payload-creation-tool-
Full Version >>>>> v1.2 10/05/2024 = in Directory >>>>> "pwn-suite"

view in safety = https://www.youtube.com/watch?v=--srcJ9uV_U

view online = https://drive.google.com/file/d/15GVtdcF5nQoM3-4qVxpG9ggdorQwjL9u/view?usp=sharing

view my full youtube = https://www.youtube.com/@lil_ToT-XFZ1/videos


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
10. Phishing Page with Embedded JavaScript
Function: create_phishing_page()
Obfuscation: The phishing page dynamically redirects users to a malicious URL after credentials are captured.
11. Windows Service Payload with Encrypted Storage
Function: generate_windows_service_payload()
Obfuscation: Windows service created with AES-256 encrypted payload storage.
12. USB Exploitation Payload with Autorun
Function: create_usb_exploitation_payload()
Obfuscation: Embedded autorun functionality for automatic execution from USB.
13. Reverse HTTPS Payload with Obfuscation
Function: generate_reverse_https_payload()
Obfuscation: Payload obfuscated via Base64 encoding and HTTPS communication.
14. Persistence via Windows Registry
Function: create_persistence_payload()
Obfuscation: Payload persistence achieved through Windows Registry modification.
15. Fake Update Payload
Function: generate_fake_update_payload()
Obfuscation: Simulated system update, meant to distract the user while malicious actions are performed.
16. Process Injection Payload
Function: create_process_injection_payload()
Obfuscation: Injects a DLL into a target process with manual error handling for stealth.
17. Stealthy Network Scanning Payload
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
