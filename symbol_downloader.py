#!/usr/bin/env python3
"""
Automated symbol downloader for Volatility3.
Attempts to download pre-built Kali Linux kernel symbols.
"""

import os
import subprocess
import re
from pathlib import Path

def extract_kernel_version(banner_output):
    """
    Extract kernel version from banners.Banners output.
    Expected format: "Linux version 6.19.14+kali-amd64 ..."
    """
    lines = banner_output if isinstance(banner_output, list) else banner_output.split('\n')
    for line in lines:
        match = re.search(r'Linux version ([\d\.\+\-a-z]+)', line)
        if match:
            return match.group(1)
    return None

def find_volatility_dir():
    """Find volatility3 installation directory."""
    home = str(Path.home())
    paths = [
        os.path.join(home, "volatility3"),
        "/opt/volatility3",
        "/usr/share/volatility3"
    ]
    for path in paths:
        if os.path.exists(os.path.join(path, "vol.py")):
            return path
    return None

def download_kali_symbols(kernel_version, vol_dir):
    """
    Download Kali Linux symbols for given kernel version.
    Returns True if successful, False otherwise.
    """
    if not vol_dir:
        return False, "Volatility3 directory not found"
    
    symbols_dir = os.path.join(vol_dir, "volatility3", "symbols", "linux")
    os.makedirs(symbols_dir, exist_ok=True)
    
    # Parse kernel version to construct symbol filename
    # 6.19.14+kali-amd64 -> kali-6.19.14-1kali1-x86_64
    # Extract base version
    match = re.match(r'([\d\.]+)\+kali-amd64', kernel_version)
    if not match:
        return False, f"Could not parse kernel version: {kernel_version}"
    
    base_version = match.group(1)
    
    # Try common Kali symbol filenames
    symbol_urls = [
        f"https://mirrors.kali.org/volatility-symbols/linux/kali-{base_version}-1kali1-x86_64.zip",
        f"https://mirrors.kali.org/volatility-symbols/linux/kali-{base_version}-x86_64.zip",
        f"https://mirrors.kali.org/volatility-symbols/linux/Linux-{base_version}-x86_64.zip",
    ]
    
    for url in symbol_urls:
        try:
            zip_file = os.path.join(symbols_dir, os.path.basename(url))
            
            # Download
            result = subprocess.run(
                ["wget", "-q", "-O", zip_file, url],
                timeout=30,
                capture_output=True
            )
            
            if result.returncode == 0 and os.path.exists(zip_file):
                # Unzip
                subprocess.run(
                    ["unzip", "-q", "-o", zip_file, "-d", symbols_dir],
                    timeout=30,
                    capture_output=True
                )
                os.remove(zip_file)
                return True, f"Downloaded and extracted symbols from {url}"
        except Exception as e:
            continue
    
    return False, "Could not download Kali symbols. Try manual download from https://mirrors.kali.org/"

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        kernel = sys.argv[1]
        vol_dir = find_volatility_dir()
        success, msg = download_kali_symbols(kernel, vol_dir)
        print(msg)
        sys.exit(0 if success else 1)
