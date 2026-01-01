# Network-Traffic-Parsing-and-Analysis-Using-Python
A very simple project that aims to analyze network traffic packet by packet using Python code consisting of four scripts (IDS, Main, IOCs, and Config) to make traffic analysis easier and save time and effort.
* The IDS code monitors network traffic, either live traffic or from an external PCAP file, and generates alerts if it detects any known malicious IP addresses or ports listed in the IOCs code.
* The IOCs code contains known malicious IP addresses, ports, and byte sizes commonly associated with attacks, which are used by the IDS code for detection and prevention.
* The Main code is responsible for running the project and reporting errors when they occur, such as an incorrect network interface name, a missing file, or invalid packets.
* The Config code is used to call the other scripts using parameters. It allows selecting either live traffic (represented by 1) or an external file (represented by 0).
* The "network traffic file" is captured using the Wireshark program and then analyzed by the Python scripts.
