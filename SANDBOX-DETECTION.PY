import os
import platform
import subprocess
import uuid
import psutil

def check_username():
    user = os.getenv("USERNAME") or os.getenv("USER")
    suspicious = ["user", "test", "sandbox", "malware", "analyst"]
    return user.lower() in suspicious if user else False

def check_env_vars():
    required = ["APPDATA", "PROGRAMFILES", "SYSTEMROOT", "TEMP"]
    return any(os.getenv(var) is None for var in required)

def check_mac_address():
    mac = hex(uuid.getnode())
    vm_macs = ["00:05:69", "00:0C:29", "00:1C:14", "00:50:56", "08:00:27"]
    return any(mac.replace("0x", "").lower().startswith(m.replace(":", "").lower()) for m in vm_macs)

def check_vm_files():
    paths = [
        "C:\\Program Files\\VMware\\VMware Tools",
        "C:\\Program Files\\Oracle\\VirtualBox Guest Additions",
        "/usr/bin/VBoxControl",
        "/usr/bin/qemu-ga"
    ]
    return any(os.path.exists(path) for path in paths)

def check_cpu_cores():
    return psutil.cpu_count(logical=True) <= 2

def check_ram():
    ram_gb = psutil.virtual_memory().total / (1024 ** 3)
    return ram_gb < 4  # Less than 4GB is suspicious

def check_system_manufacturer():
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("wmic computersystem get manufacturer", shell=True)
            if any(x in output.decode().lower() for x in ["vmware", "virtualbox", "qemu", "kvm", "xen"]):
                return True
    except Exception:
        pass
    return False

def is_sandbox():
    detections = {
        "Suspicious username": check_username(),
        "Missing environment variable": check_env_vars(),
        "VM MAC address": check_mac_address(),
        "VM-related files found": check_vm_files(),
        "Low CPU core count": check_cpu_cores(),
        "Low RAM": check_ram(),
        "Virtualization manufacturer detected": check_system_manufacturer(),
    }

    detected = [key for key, value in detections.items() if value]
    if len(detected) >= 3:
        print("[!] Sandbox detected:")
        for d in detected:
            print(f" - {d}")
        return True
    else:
        print("[+] No sandbox detected.")
        return False

if __name__ == "__main__":
    is_sandbox()
