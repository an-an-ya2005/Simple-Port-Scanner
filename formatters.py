# formatters.py
"""
Output formatters for port scanner results
"""
import json
import csv
from io import StringIO
from typing import List, Dict, Any

def to_json(results: List) -> str:
    """
    Convert scan results to JSON format
    
    Args:
        results: List of PortScanResult objects
        
    Returns:
        JSON string
    """
    output = []
    for r in results:
        output.append({
            "port": r.port,
            "protocol": r.protocol,
            "open": r.open,
            "service": r.service,
            "banner": r.banner,
            "error": r.error,
            "duration": round(r.duration, 3)
        })
    return json.dumps(output, indent=2)

def to_csv(results: List) -> str:
    """
    Convert scan results to CSV format
    
    Args:
        results: List of PortScanResult objects
        
    Returns:
        CSV string
    """
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(["port", "protocol", "status", "service", "banner", "error", "duration"])
    
    # Write data
    for r in results:
        status = "open" if r.open else "closed"
        writer.writerow([
            r.port,
            r.protocol,
            status,
            r.service or "",
            r.banner or "",
            r.error or "",
            round(r.duration, 3)
        ])
    
    return output.getvalue()

def to_text(results: List) -> str:
    """
    Convert scan results to plain text format
    
    Args:
        results: List of PortScanResult objects
        
    Returns:
        Formatted text string
    """
    lines = []
    for r in results:
        if r.open:
            service_info = f" ({r.service})" if r.service and r.service != "Unknown" else ""
            banner_text = f" | banner: {r.banner}" if r.banner else ""
            lines.append(f"[OPEN]  Port {r.port}/{r.protocol.upper()}{service_info}{banner_text}")
        else:
            lines.append(f"[CLOSED] Port {r.port}/{r.protocol.upper()}")
    return "\n".join(lines)