





# Indicators of Compromise


MALICIOUS_IPS = {
    "192.168.1.100",
    "10.0.0.66"
}

SUSPICIOUS_PORTS = {
    4444,   # Metasploit ==> vere important
    1337,   # Backdoor
    6667,   # IRC botnets
    31337,   # Trojan port ==> attack
    3306,    # mysql
    3389,    # os windows ==> ransomware attack
    8080,    # An alternative port for http
    8443    # An alternative port for https
}

SUSPICIOUS_PROTOCOLS = {
    "ICMP"
}
# oversized packet
MAX_PACKET_SIZE = 1500 # bytes
