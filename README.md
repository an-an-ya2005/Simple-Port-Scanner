# Basic Port Scanner

A fast, concurrent port scanner with TCP and UDP support, service detection, and multiple output formats.

## Features

- **TCP and UDP Scanning**: Scan for open ports using either TCP or UDP protocols
- **Service Detection**: Automatically identify common services running on open ports
- **Banner Grabbing**: Attempt to retrieve service banners from open ports
- **Concurrent Scanning**: Multi-threaded design for fast scanning
- **Progress Bar**: Visual feedback during scanning
- **Multiple Output Formats**: Results in plain text, JSON, or CSV
- **File Output**: Save results to a file

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/basic-port-scanner.git
   cd basic-port-scanner
   ```

2. Create a virtual environment and activate it:
   ```
   python -m venv venv
   # On Windows
   venv\Scripts\activate
   # On Linux/Mac
   source venv/bin/activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

Basic usage:
```
python cli.py --host example.com
```

This will scan the first 1024 ports using TCP protocol.
