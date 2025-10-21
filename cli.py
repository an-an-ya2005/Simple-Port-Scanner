# cli.py
import argparse
import sys
from scanner import scan_ports, ports_from_range
from utils import resolve_host
from formatters import to_json, to_csv, to_text

def main():
    parser = argparse.ArgumentParser(description="Basic concurrent TCP port scanner")
    parser.add_argument("--host", "-t", required=True, help="Target host (IP or hostname)")
    parser.add_argument("--start-port", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end-port", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--threads", type=int, default=100, help="Number of concurrent worker threads (default: 100)")
    parser.add_argument("--banner", action="store_true", help="Attempt simple banner grabbing on open ports")
    parser.add_argument("--protocol", choices=["tcp", "udp"], default="tcp", help="Protocol to scan (tcp or udp, default: tcp)")
    parser.add_argument("--output", choices=["text", "json", "csv"], default="text", help="Output format (text, json, or csv, default: text)")
    parser.add_argument("--output-file", help="Write output to file instead of stdout")
    parser.add_argument("--no-progress", action="store_true", help="Disable progress bar")
    args = parser.parse_args()

    try:
        host, ip = resolve_host(args.host)
    except Exception as e:
        print(f"Error resolving host: {e}")
        return

    print(f"Scanning host: {host} ({ip}) ports {args.start_port}-{args.end_port} with {args.protocol.upper()} protocol, timeout {args.timeout}s using {args.threads} threads")
    ports = ports_from_range(args.start_port, args.end_port)
    results = scan_ports(ip=ip, ports=ports, timeout=args.timeout, workers=args.threads, 
                        do_banner=args.banner, protocol=args.protocol, show_progress=not args.no_progress)

    # Format the output based on the selected format
    if args.output == "json":
        output = to_json(results)
    elif args.output == "csv":
        output = to_csv(results)
    else:  # text format
        open_ports = [r for r in results if r.open]
        if open_ports:
            output = f"\nOpen ports found:\n" + to_text(open_ports)
        else:
            output = f"\nNo open {args.protocol.upper()} ports found in the given range."
    
    # Write to file or print to stdout
    if args.output_file:
        try:
            with open(args.output_file, 'w') as f:
                f.write(output)
            print(f"Results written to {args.output_file}")
        except Exception as e:
            print(f"Error writing to file: {e}")
    else:
        print(output)

if __name__ == "__main__":
    main()
