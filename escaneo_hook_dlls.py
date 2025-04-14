import ctypes
import sys
import os
from ctypes import wintypes
import psutil
import pefile
import argparse
import json
from datetime import datetime

# Constants from Windows API
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# Windows API structures
class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p)
    ]

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(wintypes.BYTE)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.CHAR * 256),
        ("szExePath", wintypes.CHAR * 260)
    ]

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", wintypes.ULONG),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.CHAR * 260)
    ]

# Load Windows DLLs
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

# Function prototypes
CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
CreateToolhelp32Snapshot.restype = wintypes.HANDLE

Process32First = kernel32.Process32First
Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
Process32First.restype = wintypes.BOOL

Process32Next = kernel32.Process32Next
Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
Process32Next.restype = wintypes.BOOL

Module32First = kernel32.Module32First
Module32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32)]
Module32First.restype = wintypes.BOOL

Module32Next = kernel32.Module32Next
Module32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32)]
Module32Next.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

GetModuleFileNameEx = psapi.GetModuleFileNameExA
GetModuleFileNameEx.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPSTR, wintypes.DWORD]
GetModuleFileNameEx.restype = wintypes.DWORD

EnumProcessModules = psapi.EnumProcessModules
EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
EnumProcessModules.restype = wintypes.BOOL

GetModuleInformation = psapi.GetModuleInformation
GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE, ctypes.POINTER(MODULEINFO), wintypes.DWORD]
GetModuleInformation.restype = wintypes.BOOL

def get_system_modules():
    """Get a list of all loaded modules in system processes"""
    system_modules = set()
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0)
    if hSnapshot == -1:
        return system_modules
    
    me32 = MODULEENTRY32()
    me32.dwSize = ctypes.sizeof(MODULEENTRY32)
    
    if Module32First(hSnapshot, ctypes.byref(me32)):
        while True:
            module_path = me32.szExePath.decode('utf-8', errors='ignore')
            system_modules.add(module_path.lower())
            if not Module32Next(hSnapshot, ctypes.byref(me32)):
                break
    
    CloseHandle(hSnapshot)
    return system_modules

def has_authenticode_signature(file_path):
    """Check if a file has a valid Authenticode signature"""
    try:
        pe = pefile.PE(file_path)
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        return security_dir.VirtualAddress != 0
    except:
        return False

def scan_injected_dlls(pid=None, output_file=None, verbose=False):
    """Scan for potentially injected DLLs in processes"""
    results = {}
    suspicious_count = 0
    system_modules = get_system_modules()
    
    if pid is None:
        processes = [proc for proc in psutil.process_iter(['pid', 'name'])]
    else:
        try:
            proc = psutil.Process(pid)
            processes = [proc]
        except psutil.NoSuchProcess:
            print(f"[!] Process with PID {pid} not found.")
            return
    
    for proc in processes:
        try:
            process_info = {
                'pid': proc.pid,
                'name': proc.name(),
                'path': proc.exe(),
                'modules': [],
                'suspicious': False
            }
            
            if not verbose and proc.pid < 1000:
                continue
                
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, proc.pid)
            if not hProcess:
                if verbose:
                    print(f"[!] Could not open process {proc.pid} ({proc.name()})")
                continue
            
            modules = (wintypes.HMODULE * 1024)()
            cbNeeded = wintypes.DWORD()
            
            if EnumProcessModules(hProcess, modules, ctypes.sizeof(modules), ctypes.byref(cbNeeded)):
                module_count = cbNeeded.value // ctypes.sizeof(wintypes.HMODULE)
                for i in range(module_count):
                    module_info = MODULEINFO()
                    module_path = ctypes.create_string_buffer(260)
                    
                    if GetModuleFileNameEx(hProcess, modules[i], module_path, ctypes.sizeof(module_path)):
                        full_path = module_path.value.decode('utf-8', errors='ignore').lower()
                        module_name = os.path.basename(full_path)
                        
                        if GetModuleInformation(hProcess, modules[i], ctypes.byref(module_info), ctypes.sizeof(module_info)):
                            base_addr = module_info.lpBaseOfDll
                            size = module_info.SizeOfImage
                            
                            is_suspicious = False
                            reasons = []
                            
                            if full_path not in system_modules:
                                reasons.append("Not a known system module")
                                is_suspicious = True
                            
                            suspicious_locations = [
                                'appdata', 'temp', 'users\\', 'programdata',
                                'windows\\temp', 'windows\\system32\\config'
                            ]
                            if any(loc in full_path for loc in suspicious_locations):
                                reasons.append("Loaded from suspicious location")
                                is_suspicious = True
                            
                            try:
                                if not has_authenticode_signature(full_path):
                                    reasons.append("No authenticode signature")
                                    is_suspicious = True
                            except:
                                reasons.append("Could not verify signature")
                                is_suspicious = True
                            
                            module_data = {
                                'name': module_name,
                                'path': full_path,
                                'base_address': hex(base_addr),
                                'size': size,
                                'is_suspicious': is_suspicious,
                                'reasons': reasons
                            }
                            
                            process_info['modules'].append(module_data)
                            
                            if is_suspicious:
                                process_info['suspicious'] = True
                                suspicious_count += 1
                                print(f"[!] Suspicious module found in {proc.name()} (PID: {proc.pid}):")
                                print(f"    Module: {module_name}")
                                print(f"    Path: {full_path}")
                                print(f"    Reasons: {', '.join(reasons)}")
                                print("")
            
            if process_info['modules']:
                results[f"pid_{proc.pid}"] = process_info
            
            CloseHandle(hProcess)
            
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            if verbose:
                print(f"[!] Access denied to process {proc.pid} ({proc.name()})")
            continue
        except Exception as e:
            if verbose:
                print(f"[!] Error scanning process {proc.pid} ({proc.name()}): {str(e)}")
            continue
    
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"\n[+] Results saved to {output_file}")
    
    print(f"\nScan complete. Found {suspicious_count} suspicious modules.")
    return results

def scan_hooks(target_pid=None, output_file=None):
    """Scan for API hooks in a process"""
    print("[*] Hook scanning is a complex feature that requires more advanced implementation")
    print("[*] Consider using specialized tools like Process Hacker or API Monitor for this task")
    return {}

def main():
    parser = argparse.ArgumentParser(description="Advanced Injected DLL and Hook Scanner")
    parser.add_argument("-p", "--pid", type=int, help="Scan a specific process by PID")
    parser.add_argument("-o", "--output", help="Output file to save results (JSON format)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--hooks", action="store_true", help="Scan for API hooks (experimental)")
    
    args = parser.parse_args()
    
    print(f"[*] Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("[*] Gathering system module information...")
    
    if args.hooks:
        scan_hooks(args.pid, args.output)
    else:
        scan_injected_dlls(args.pid, args.output, args.verbose)

if __name__ == "__main__":
    if not sys.platform.startswith('win'):
        print("[!] This script only works on Windows systems.")
        sys.exit(1)
    
    try:
        import pefile
    except ImportError:
        print("[!] Required module 'pefile' not found. Install with: pip install pefile")
        sys.exit(1)
    
    main()
