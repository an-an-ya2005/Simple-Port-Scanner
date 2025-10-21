# services.py
"""
Service detection module for port scanner
"""

# Common port to service mappings
COMMON_PORTS = {
    # TCP Services
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    115: "SFTP",
    119: "NNTP",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP (Submission)",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1433: "MS SQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    27017: "MongoDB",
    
    # UDP Services
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    123: "NTP",
    161: "SNMP",
    500: "IKE (VPN)",
    514: "Syslog",
    520: "RIP",
    1194: "OpenVPN",
    1900: "SSDP (UPnP)",
    5353: "mDNS",
}

def detect_service(port: int, protocol: str = "tcp") -> str:
    """
    Detect service based on port number and protocol
    
    Args:
        port: Port number
        protocol: Protocol (tcp or udp)
        
    Returns:
        Service name or "Unknown"
    """
    # Handle overlapping port numbers between TCP and UDP
    if protocol.lower() == "udp" and port in [53, 123, 161]:
        return f"{COMMON_PORTS.get(port, 'Unknown')} (UDP)"
    elif protocol.lower() == "tcp":
        return COMMON_PORTS.get(port, "Unknown")
    else:
        return "Unknown"

def get_service_description(service_name: str) -> str:
    """
    Get a brief description of a service
    
    Args:
        service_name: Name of the service
        
    Returns:
        Brief description of the service
    """
    descriptions = {
        "FTP": "File Transfer Protocol - Used for transferring files",
        "SSH": "Secure Shell - Encrypted remote login and command execution",
        "Telnet": "Unencrypted remote login service (insecure)",
        "SMTP": "Simple Mail Transfer Protocol - Email sending",
        "DNS": "Domain Name System - Translates domain names to IP addresses",
        "HTTP": "Hypertext Transfer Protocol - Web browsing",
        "POP3": "Post Office Protocol v3 - Email retrieval",
        "SFTP": "Secure File Transfer Protocol",
        "NNTP": "Network News Transfer Protocol",
        "NTP": "Network Time Protocol - Time synchronization",
        "IMAP": "Internet Message Access Protocol - Email retrieval",
        "SNMP": "Simple Network Management Protocol - Network device management",
        "IRC": "Internet Relay Chat",
        "HTTPS": "HTTP Secure - Encrypted web browsing",
        "SMB": "Server Message Block - File sharing",
        "SMTPS": "SMTP Secure - Encrypted email sending",
        "SMTP (Submission)": "Email submission port",
        "IMAPS": "IMAP Secure - Encrypted email retrieval",
        "POP3S": "POP3 Secure - Encrypted email retrieval",
        "SOCKS Proxy": "SOCKS protocol proxy server",
        "MS SQL": "Microsoft SQL Server database",
        "Oracle DB": "Oracle database",
        "MySQL": "MySQL database",
        "RDP": "Remote Desktop Protocol - Remote desktop access",
        "PostgreSQL": "PostgreSQL database",
        "VNC": "Virtual Network Computing - Remote desktop access",
        "Redis": "Redis in-memory data structure store",
        "HTTP Proxy": "HTTP proxy server",
        "HTTPS Alt": "Alternative HTTPS port",
        "MongoDB": "MongoDB database",
        "DHCP Server": "Dynamic Host Configuration Protocol server",
        "DHCP Client": "Dynamic Host Configuration Protocol client",
        "TFTP": "Trivial File Transfer Protocol",
        "IKE (VPN)": "Internet Key Exchange - VPN negotiation",
        "Syslog": "System logging service",
        "RIP": "Routing Information Protocol",
        "OpenVPN": "OpenVPN service",
        "SSDP (UPnP)": "Simple Service Discovery Protocol - UPnP discovery",
        "mDNS": "Multicast DNS - Local network service discovery",
    }
    
    return descriptions.get(service_name, "No description available")