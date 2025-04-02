Build a Basic Network Sniffer in Windows 11 (Python)

Step 1: Install Python and Required Library
Make sure Python is installed. You can check by running:
->> python --version

Now, install the scapy library:
->> pip install scapy



Step 2: Install Npcap (Required for Packet Sniffing)
->> Download Npcap from nmap.org/npcap

Install it with "WinPcap API Compatibility Mode" enabled.



Step 3: Type "cmd" on windows search and open it. Then type the following command to check the network interface:

->> ipconfig

network interface example - Ethernet, Wi-Fi, etc.



Step 4: Run the following Python script to sniff the network traffic.