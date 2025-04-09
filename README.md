# Sandbox Detection Script

This Python script attempts to detect if it's running inside a virtual machine or sandboxed environment using various heuristics.

## Features

- Checks for suspicious usernames  
- Verifies presence of key environment variables  
- Detects known virtual machine MAC address prefixes  
- Looks for VM-related files or guest tools  
- Detects low CPU core count (≤ 2 cores)  
- Detects low RAM (under 4GB)  
- Detects virtualization vendors (e.g., VMware, VirtualBox)  

## Requirements

- Python 3.6 or higher  
- `psutil` package  

## Installation

```bash
pip install -r requirements.txt
```

## Using

```bash
python SANDBOX-DETECTION.PY
```

## Donate
BTC:

bc1qs2pasdn0d2tn0vw0ngtd45wv3cv6axzgrga6s5
