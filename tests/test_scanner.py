# tests/test_scanner.py
import socket
import threading
import time
from scanner import scan_ports

def _start_test_server(bind_ip="127.0.0.1", bind_port=0, reply=b"Hello\r\n"):
    stop_event = threading.Event()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_ip, bind_port))
    sock.listen(1)
    port = sock.getsockname()[1]

    def handler():
        while not stop_event.is_set():
            try:
                sock.settimeout(0.5)
                conn, addr = sock.accept()
                with conn:
                    conn.sendall(reply)
            except socket.timeout:
                continue
            except OSError:
                break
        try:
            sock.close()
        except Exception:
            pass

    thread = threading.Thread(target=handler, daemon=True)
    thread.start()
    return thread, port, stop_event

def test_scan_local_open_port():
    thread, port, ev = _start_test_server()
    time.sleep(0.1)
    results = scan_ports("127.0.0.1", [port], timeout=1.0, workers=1, do_banner=True)
    ev.set()
    thread.join(0.5)
    assert len(results) == 1
    assert results[0].open is True
    assert results[0].banner is not None

def test_scan_closed_port():
    closed_port = 54321
    results = scan_ports("127.0.0.1", [closed_port], timeout=0.5, workers=1, do_banner=False)
    assert len(results) == 1
    assert results[0].open is False
