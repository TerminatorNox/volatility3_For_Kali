#!/usr/bin/env python3
"""
Helper script to obtain/generate kernel symbols for Volatility3.
Detected kernel: 6.19.14+kali-amd64 from memory image
"""

import os
import sys
import subprocess
from pathlib import Path

HOME = str(Path.home())
VOL_PATHS = [
    os.path.join(HOME, "volatility3"),
    "/opt/volatility3",
    "/usr/share/volatility3"
]

def find_volatility():
    """Find volatility3 installation directory."""
    for path in VOL_PATHS:
        if os.path.exists(os.path.join(path, "vol.py")):
            return path
    return None

def main():
    vol_dir = find_volatility()
    if not vol_dir:
        print("[!] Volatility3 not found. Install it first.")
        return False
    
    symbols_dir = os.path.join(vol_dir, "volatility3", "symbols", "linux")
    os.makedirs(symbols_dir, exist_ok=True)
    
    print(f"[*] Volatility3 found at: {vol_dir}")
    print(f"[*] Symbols directory: {symbols_dir}")
    print(f"[*] Detected kernel: 6.19.14+kali-amd64")
    print()
    
    print("=" * 70)
    print("OPTION 1: Download Pre-built Kali Symbols (Recommended)")
    print("=" * 70)
    print("""
Kali Linux maintains symbol packs. Run:
    
    cd {symbols_dir}
    wget https://mirrors.kali.org/volatility-symbols/linux/kali-6.19.14-1kali1-x86_64.zip
    unzip kali-6.19.14-1kali1-x86_64.zip

If the above URL doesn't work, check:
    https://mirrors.kali.org/kalilinux/ for symbol files
""".format(symbols_dir=symbols_dir))
    
    print()
    print("=" * 70)
    print("OPTION 2: Generate Symbols Using volatility3 (Advanced)")
    print("=" * 70)
    print("""
If running on the same Kali 6.19.14 kernel:
    
    cd {vol_dir}
    python3 volatility3/framework/symbols/linux/linux.py construct [flags]

Details: https://github.com/volatilityfoundation/volatility3/blob/master/doc/source/getting-started-linux.md
""".format(vol_dir=vol_dir))
    
    print()
    print("=" * 70)
    print("OPTION 3: Build Symbols with dwarf2json (Most Flexible)")
    print("=" * 70)
    print("""
If you have vmlinux (kernel binary with DWARF debug info):

    1. Install dwarf2json:
       go get -u github.com/volatilityfoundation/dwarf2json

    2. Generate symbols:
       /path/to/dwarf2json linux -s /boot/vmlinux-6.19.14-1+kali1 > output.json

    3. Place in Volatility:
       cp output.json {symbols_dir}/

References:
    https://github.com/volatilityfoundation/dwarf2json
    https://github.com/volatilityfoundation/volatility3/issues
""".format(symbols_dir=symbols_dir))
    
    print()
    print("=" * 70)
    print("VERIFICATION")
    print("=" * 70)
    print(f"""
After adding symbols, verify by running:

    cd {vol_dir}
    python3 vol.py -f /path/to/memory.lime linux.pslist

You should see process listing output instead of "Unsatisfied requirement" error.
""".format(vol_dir=vol_dir))

if __name__ == "__main__":
    main()
