# Volatility 3 Linux GUI

A professional PyQt6-based graphical interface for Volatility 3 designed for Linux memory forensics, malware analysis, incident response, and DFIR investigations.

## Features

### Plugin Execution
- One-click Volatility 3 plugin execution
- Automatic kernel banner detection
- Real-time output streaming
- Background execution without GUI freezing
- Stop running plugins safely

### Symbol Management
- Automatic Linux symbol detection
- Symbol download assistance
- Quick-fix workflow for missing symbols
- Automatic plugin retry after symbol installation

### Memory Analysis
Supported memory image formats:

- `.lime`
- `.mem`
- `.raw`
- `.img`
- `.bin`
- `.data`

### Reporting
- Export results to TXT
- Export results to PDF
- Investigation report generation

## Project Structure

```text
VOL/
├── app.py
├── get_symbols.py
├── symbol_downloader.py
└── README.md
```

## Requirements

- Python 3.10+
- PyQt6
- ReportLab
- Volatility 3

## Installation

```bash
git clone https://github.com/yourusername/volatility3-linux-gui.git
cd volatility3-linux-gui

pip install PyQt6 reportlab volatility3
```

## Running

```bash
python3 app.py
```

## Workflow

1. Launch the application.
2. Load a memory image.
3. Select a Volatility plugin.
4. Run the plugin.
5. Review results.
6. Export findings to TXT or PDF.

## Available Plugin Categories

### Processes
- linux.pslist
- linux.psaux
- linux.pstree
- linux.pslist_cache
- linux.pidhashtable
- linux.psxview
- linux.lsof

### Process Memory
- linux.memmap
- linux.proc_maps
- linux.dump_map
- linux.bash

### Kernel Memory
- linux.lsmod
- linux.moddump
- linux.tmpfs

### Rootkit Detection
- linux.check_afinfo
- linux.check_tty
- linux.keyboard_notifier
- linux.check_creds
- linux.check_fop
- linux.check_idt
- linux.check_syscall
- linux.check_modules

### Networking
- linux.arp
- linux.ifconfig
- linux.route_cache
- linux.netstat
- linux.pkt_queues
- linux.sk_buff_cache

## Troubleshooting

### Missing Symbols

Use the built-in symbol tools:

- Quick Fix Symbols
- Download Symbols
- Generate Symbols

### Volatility Not Found

Install manually:

```bash
pip install volatility3
```

or

```bash
git clone https://github.com/volatilityfoundation/volatility3.git
```

## Use Cases

- Linux Memory Forensics
- Malware Analysis
- Digital Forensics
- Incident Response
- Threat Hunting
- DFIR Training Labs

## License

For educational, research, and forensic investigation purposes.

## Acknowledgments

- Volatility 3
- PyQt6
- ReportLab
