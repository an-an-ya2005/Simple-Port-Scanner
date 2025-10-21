# scanner.py
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Literal
import time
import random
from services import detect_service

DEFAULT_TIMEOUT = 1.0

class PortScanResult:
    def __init__(self, port: int, open: bool, protocol: str = "tcp", banner: Optional[str] = None, 
                 error: Optional[str] = None, duration: float = 0.0, service: Optional[str] = None):
        self.port = port
        self.open = open
        self.protocol = protocol
        self.banner = banner
        self.error = error
        self.duration = duration
        self.service = service

    def __repr__(self):
        return f"PortScanResult(port={self.port}, protocol={self.protocol}, open={self.open}, service={self.service}, banner={self.banner}, error={self.error}, duration={self.duration:.3f})"


def try_connect(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT, do_banner: bool = False, 
               protocol: str = "tcp") -> PortScanResult:
    start = time.time()
    
    if protocol.lower() == "tcp":
        return try_tcp_connect(ip, port, timeout, do_banner, start)
    elif protocol.lower() == "udp":
        return try_udp_connect(ip, port, timeout, start)
    else:
        return PortScanResult(port=port, open=False, protocol=protocol, 
                             error=f"Unsupported protocol: {protocol}", 
                             duration=time.time() - start)

def try_tcp_connect(ip: str, port: int, timeout: float, do_banner: bool, start_time: float) -> PortScanResult:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        err = s.connect_ex((ip, port))
        if err == 0:
            banner = None
            if do_banner:
                try:
                    s.settimeout(0.5)
                    data = s.recv(1024)
                    if isinstance(data, bytes):
                        banner = data.decode(errors="ignore").strip()
                except Exception:
                    banner = None
            service = detect_service(port, "tcp")
            s.close()
            return PortScanResult(port=port, open=True, protocol="tcp", banner=banner, 
                                 service=service, duration=time.time() - start_time)
        else:
            s.close()
            return PortScanResult(port=port, open=False, protocol="tcp", duration=time.time() - start_time)
    except socket.gaierror as e:
        s.close()
        return PortScanResult(port=port, open=False, protocol="tcp", error=f"DNS error: {e}", duration=time.time() - start_time)
    except socket.timeout:
        s.close()
        return PortScanResult(port=port, open=False, protocol="tcp", error="timeout", duration=time.time() - start_time)
    except Exception as e:
        s.close()
        return PortScanResult(port=port, open=False, protocol="tcp", error=str(e), duration=time.time() - start_time)

def try_udp_connect(ip: str, port: int, timeout: float, start_time: float) -> PortScanResult:
    """
    UDP port scanning is trickier than TCP because UDP is connectionless.
    This function sends a UDP packet and checks for ICMP port unreachable responses.
    If no error is received, the port is considered potentially open.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    
    # Create a random payload
    payload = random.randbytes(32)
    
    try:
        s.sendto(payload, (ip, port))
        # Try to receive data (this will usually timeout if port is open)
        try:
            s.recvfrom(1024)
            # If we get here, we received a response
            service = detect_service(port, "udp")
            s.close()
            return PortScanResult(port=port, open=True, protocol="udp", 
                                 service=service, duration=time.time() - start_time)
        except socket.timeout:
            # Timeout can indicate an open port (no ICMP error returned)
            service = detect_service(port, "udp")
            s.close()
            return PortScanResult(port=port, open=True, protocol="udp", 
                                 service=service, duration=time.time() - start_time)
        except ConnectionRefusedError:
            # Explicitly closed
            s.close()
            return PortScanResult(port=port, open=False, protocol="udp", 
                                 duration=time.time() - start_time)
    except socket.gaierror as e:
        s.close()
        return PortScanResult(port=port, open=False, protocol="udp", 
                             error=f"DNS error: {e}", duration=time.time() - start_time)
    except Exception as e:
        s.close()
        return PortScanResult(port=port, open=False, protocol="udp", 
                             error=str(e), duration=time.time() - start_time)


def scan_ports(ip: str, ports: List[int], timeout: float = DEFAULT_TIMEOUT, workers: int = 100, 
             do_banner: bool = False, protocol: str = "tcp", show_progress: bool = True) -> List[PortScanResult]:
    results = []
    max_workers = max(1, min(workers, len(ports)))
    total_ports = len(ports)
    completed = 0
    
    with ThreadPoolExecutor(max_workers=max_workers) as exe:
        futures = {exe.submit(try_connect, ip, p, timeout, do_banner, protocol): p for p in ports}
        
        for future in as_completed(futures):
            try:
                res = future.result()
            except Exception as e:
                res = PortScanResult(port=futures[future], open=False, protocol=protocol, error=str(e))
            
            results.append(res)
            
            # Update progress bar
            if show_progress:
                completed += 1
                progress = int(50 * completed / total_ports)
                bar = '█' * progress + '░' * (50 - progress)
                percent = int(100 * completed / total_ports)
                print(f"\r[{bar}] {percent}% ({completed}/{total_ports}) ports scanned", end='', flush=True)
        
        # Finish progress bar with newline
        if show_progress and total_ports > 0:
            print()
    
    results.sort(key=lambda r: r.port)
    return results


def ports_from_range(start: int, end: int) -> List[int]:
    if start <= 0:
        start = 1
    if end > 65535:
        end = 65535
    return list(range(start, end + 1))
