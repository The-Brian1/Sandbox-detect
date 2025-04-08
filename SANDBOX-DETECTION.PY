import os
import platform
import socket
import subprocess
import psutil
import winreg
import uuid
import time

def check_registry_keys():
    suspicious_keys = [
        r"HARDWARE\ACPI\DSDT\VBOX__",
        r"HARDWARE\ACPI\FADT\VBOX__",
        r"HARDWARE\ACPI\RSDT\VBOX__",
        r"SOFTWARE\Oracle\VirtualBox Guest Additions",
        r"SYSTEM\ControlSet001\Services\VBoxGuest",
        r"SYSTEM\ControlSet001\Services\VBoxService",
        r"SOFTWARE\VMware, Inc.\VMware Tools"
    ]
    for key in suspicious_keys:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key):
                return True
        except:
            continue
    return False

def check_cpu_count():
    return os.cpu_count() <= 2

def check_ram():
    total_gb = psutil.virtual_memory().total / (1024 ** 3)
    return total_gb <= 4

def check_bios_manufacturer():
    try:
        output = subprocess.check_output("wmic bios get manufacturer", shell=True).decode()
        vm_indicators = ["vbox", "virtual", "vmware", "qemu", "xen"]
        for indicator in vm_indicators:
            if indicator in output.lower():
                return True
    except:
        pass
    return False

def check_motherboard():
    try:
        output = subprocess.check_output("wmic baseboard get manufacturer", shell=True).decode()
        if any(x in output.lower() for x in ["vmware", "virtual", "vbox"]):
            return True
    except:
        pass
    return False

def check_mac_address():
    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2*6, 8)][::-1])
    vm_mac_prefixes = ['00:05:69', '00:0C:29', '00:1C:14', '00:50:56']  # VMware MAC'leri
    return any(mac.startswith(prefix.lower()) for prefix in vm_mac_prefixes)

def check_uptime():
    uptime = time.time() - psutil.boot_time()
    return uptime < 600  

def sandbox_detected():
    if any([
        check_registry_keys(),
        check_cpu_count(),
        check_ram(),
        check_bios_manufacturer(),
        check_motherboard(),
        check_mac_address(),
        check_uptime()
    ]):
        return True
    return False

if __name__ == "__main__":
    if sandbox_detected():
        print("SANDBOX DETECTED!")
    else:
        print("REAL COMPUTER!")
