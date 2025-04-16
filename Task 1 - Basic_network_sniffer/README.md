### Basic Network Sniffer in Windows (Python)

This guide outlines the steps to create a basic network sniffer on a Windows system using Python and the Scapy library.

---

### Prerequisites

--> Python: Ensure Python is installed on your system.
    To check if Python is installed, open a command prompt and run:
    ```bash
        python --version

--> Scapy: Install the Scapy library.
    Open a command prompt and run:
    ```bash
        pip install scapy

--> Npcap: Npcap is required for packet sniffing on Windows.
    Download Npcap from: https://nmap.org/npcap/

    During the Npcap installation, make sure to enable the "WinPcap API compatibility mode" option. This is crucial for Scapy to function correctly.        

---

### Instructions
1. Identify Network Interface:
    Open a command prompt.
    Run the following command to list your network interfaces:
    ```bash
        ipconfig

    Identify the interface you want to sniff (e.g., "Ethernet" or "Wi-Fi").  Note the name, as you might need it in a more advanced script. For basic sniffing, Scapy often auto-detects.   

2. Create the Python Script:

    Create a new file named 
    basic_network_sniffer.py 
    and save the code.

3. Run the Script:

    Open a command prompt.
    Execute the script using Python:
    ```bash
        python basic_network_sniffer.py
