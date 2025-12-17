/*
 * amiinavm - virtual machine detection for windows
 * https://github.com/Tymbark7372/amiinavm
 * 
 * made by Tymbark7372
 * MIT License
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <intrin.h>

#pragma comment(lib, "iphlpapi.lib")

int detections = 0;
int hyperv_host = 0;

void check_cpuid() {
    int cpuinfo[4] = {0};
    char vendor[13] = {0};
    
    __cpuid(cpuinfo, 1);
    int hypervisor_bit = cpuinfo[2] & (1 << 31);
    
    if (hypervisor_bit) {
        printf("[+] CPUID: hypervisor bit is set\n");
        detections++;
        
        __cpuid(cpuinfo, 0x40000000);
        memcpy(vendor, &cpuinfo[1], 4);
        memcpy(vendor + 4, &cpuinfo[2], 4);
        memcpy(vendor + 8, &cpuinfo[3], 4);
        
        if (strlen(vendor) > 0) {
            printf("[+] CPUID: hypervisor vendor = %s\n", vendor);
            
            if (strstr(vendor, "VMware")) printf("    -> VMware detected\n");
            else if (strstr(vendor, "VBox")) printf("    -> VirtualBox detected\n");
            else if (strstr(vendor, "Microsoft Hv")) {
                printf("    -> Hyper-V detected (could be host with Hyper-V enabled)\n");
                hyperv_host = 1;
            }
            else if (strstr(vendor, "KVMKVMKVM")) printf("    -> KVM detected\n");
            else if (strstr(vendor, "Xen")) printf("    -> Xen detected\n");
            else if (strstr(vendor, "prl hyperv")) printf("    -> Parallels detected\n");
            else printf("    -> unknown hypervisor\n");
        }
    } else {
        printf("[-] CPUID: hypervisor bit not set\n");
    }
}

void check_cpuid_timing() {
    unsigned __int64 start, end;
    int cpuinfo[4];
    unsigned __int64 total = 0;
    
    for (int i = 0; i < 10; i++) {
        start = __rdtsc();
        __cpuid(cpuinfo, 0);
        end = __rdtsc();
        total += (end - start);
    }
    
    unsigned __int64 avg = total / 10;
    printf("    CPUID avg cycles: %llu\n", avg);
    
    if (avg > 500) {
        printf("[+] Timing: CPUID took >500 cycles (suspicious)\n");
        detections++;
    } else {
        printf("[-] Timing: CPUID timing normal\n");
    }
}

void check_registry() {
    struct { const char* key; const char* desc; } keys[] = {
        {"SOFTWARE\\VMware, Inc.\\VMware Tools", "VMware Tools"},
        {"SOFTWARE\\Oracle\\VirtualBox Guest Additions", "VirtualBox GA"},
        {"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters", "Hyper-V Guest"},
        {"HARDWARE\\ACPI\\DSDT\\VBOX__", "VBox ACPI"},
        {"HARDWARE\\ACPI\\FADT\\VBOX__", "VBox ACPI"},
        {"HARDWARE\\ACPI\\RSDT\\VBOX__", "VBox ACPI"},
        {"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", "VBoxGuest"},
        {"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse", "VBoxMouse"},
        {"SYSTEM\\CurrentControlSet\\Services\\VBoxService", "VBoxService"},
        {"SYSTEM\\CurrentControlSet\\Services\\VBoxSF", "VBoxSF"},
        {"SYSTEM\\CurrentControlSet\\Services\\vmci", "VMware vmci"},
        {"SYSTEM\\CurrentControlSet\\Services\\vmhgfs", "VMware vmhgfs"},
        {"SYSTEM\\CurrentControlSet\\Services\\vmmouse", "VMware vmmouse"},
        {"SYSTEM\\CurrentControlSet\\Services\\vmrawdsk", "VMware vmrawdsk"},
        {"SYSTEM\\CurrentControlSet\\Services\\vmusbmouse", "VMware vmusbmouse"},
        {"SOFTWARE\\Wine", "Wine"},
        {"SYSTEM\\CurrentControlSet\\Services\\vioscsi", "VirtIO SCSI"},
        {"SYSTEM\\CurrentControlSet\\Services\\viostor", "VirtIO Storage"},
        {"SYSTEM\\CurrentControlSet\\Services\\balloon", "QEMU Balloon"},
        {NULL, NULL}
    };
    
    HKEY hkey;
    int found = 0;
    for (int i = 0; keys[i].key != NULL; i++) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keys[i].key, 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
            printf("[+] Registry: %s - FOUND\n", keys[i].desc);
            RegCloseKey(hkey);
            detections++;
            found++;
        }
    }
    if (found == 0) printf("[-] Registry: no VM keys found\n");
}

void check_processes() {
    const char* vmprocesses[] = {
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe", "vmacthlp.exe",
        "VBoxService.exe", "VBoxTray.exe",
        "qemu-ga.exe", "vdagent.exe", "vdservice.exe",
        "prl_tools.exe", "prl_cc.exe",
        "xenservice.exe",
        "joeboxcontrol.exe", "joeboxserver.exe",
        NULL
    };
    
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    
    int found = 0;
    if (Process32First(snap, &pe)) {
        do {
            for (int i = 0; vmprocesses[i] != NULL; i++) {
                if (_stricmp(pe.szExeFile, vmprocesses[i]) == 0) {
                    printf("[+] Process: %s - RUNNING\n", vmprocesses[i]);
                    detections++;
                    found++;
                }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    if (found == 0) printf("[-] Process: no VM processes found\n");
}

void check_mac() {
    struct { const char* prefix; const char* desc; } vmmacs[] = {
        {"00:0C:29", "VMware"}, {"00:50:56", "VMware"}, {"00:05:69", "VMware"},
        {"08:00:27", "VirtualBox"},
        {"52:54:00", "QEMU/KVM"},
        {"00:1C:42", "Parallels"},
        {"00:16:3E", "Xen"},
        {"00:15:5D", "Hyper-V"},
        {"00:21:F6", "Virtual Iron"},
        {NULL, NULL}
    };
    
    IP_ADAPTER_INFO adapters[16];
    DWORD buflen = sizeof(adapters);
    
    if (GetAdaptersInfo(adapters, &buflen) != ERROR_SUCCESS) return;
    
    PIP_ADAPTER_INFO adapter = adapters;
    int found = 0;
    
    while (adapter) {
        char prefix[10];
        snprintf(prefix, sizeof(prefix), "%02X:%02X:%02X",
            adapter->Address[0], adapter->Address[1], adapter->Address[2]);
        
        for (int i = 0; vmmacs[i].prefix != NULL; i++) {
            if (_stricmp(prefix, vmmacs[i].prefix) == 0) {
                printf("[+] MAC: %s prefix - %s\n", vmmacs[i].prefix, vmmacs[i].desc);
                detections++;
                found++;
                break;
            }
        }
        adapter = adapter->Next;
    }
    if (found == 0) printf("[-] MAC: no VM prefixes found\n");
}

void check_files() {
    const char* vmfiles[] = {
        "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
        "C:\\Windows\\System32\\drivers\\vmmouse.sys",
        "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
        "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
        "C:\\Windows\\System32\\drivers\\VBoxSF.sys",
        "C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
        "C:\\Windows\\System32\\drivers\\vioscsi.sys",
        "C:\\Windows\\System32\\drivers\\viostor.sys",
        "C:\\Windows\\System32\\drivers\\prleth.sys",
        "C:\\Windows\\System32\\drivers\\prlfs.sys",
        "C:\\Program Files\\VMware\\VMware Tools",
        "C:\\Program Files\\Oracle\\VirtualBox Guest Additions",
        "C:\\Program Files\\Parallels\\Parallels Tools",
        NULL
    };
    
    int found = 0;
    for (int i = 0; vmfiles[i] != NULL; i++) {
        DWORD attr = GetFileAttributesA(vmfiles[i]);
        if (attr != INVALID_FILE_ATTRIBUTES) {
            printf("[+] File: %s - FOUND\n", vmfiles[i]);
            detections++;
            found++;
        }
    }
    if (found == 0) printf("[-] File: no VM files found\n");
}

void check_devices() {
    const char* vmdevices[] = {
        "\\\\.\\VBoxMiniRdrDN", "\\\\.\\VBoxGuest", "\\\\.\\VBoxTrayIPC",
        "\\\\.\\HGFS", "\\\\.\\vmci",
        "\\\\.\\pipe\\VBoxMiniRdDN", "\\\\.\\pipe\\VBoxTrayIPC",
        NULL
    };
    
    int found = 0;
    for (int i = 0; vmdevices[i] != NULL; i++) {
        HANDLE h = CreateFileA(vmdevices[i], GENERIC_READ, FILE_SHARE_READ, 
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            printf("[+] Device: %s - FOUND\n", vmdevices[i]);
            CloseHandle(h);
            detections++;
            found++;
        }
    }
    if (found == 0) printf("[-] Device: no VM devices found\n");
}

void check_hardware() {
    HKEY hkey;
    char buffer[256];
    DWORD bufsize;
    
    const char* vm_strings[] = {
        "VMware", "VirtualBox", "VBOX", "Virtual", "QEMU", 
        "innotek", "Xen", "Parallels", "KVM", "Bochs", NULL
    };
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        
        const char* values[] = {"SystemManufacturer", "SystemProductName", "BIOSVendor", "BaseBoardManufacturer", NULL};
        
        for (int v = 0; values[v] != NULL; v++) {
            bufsize = sizeof(buffer);
            if (RegQueryValueExA(hkey, values[v], NULL, NULL, (LPBYTE)buffer, &bufsize) == ERROR_SUCCESS) {
                printf("    %s: %s", values[v], buffer);
                for (int i = 0; vm_strings[i] != NULL; i++) {
                    if (strstr(buffer, vm_strings[i])) {
                        printf(" [VM]\n");
                        detections++;
                        goto next_value;
                    }
                }
                printf("\n");
                next_value:;
            }
        }
        RegCloseKey(hkey);
    }
}

void check_disk() {
    HKEY hkey;
    char buffer[512];
    DWORD bufsize;
    
    const char* disk_strings[] = {
        "VBOX", "VMWARE", "VIRTUAL", "QEMU", "HARDDISK", NULL
    };
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        
        bufsize = sizeof(buffer);
        if (RegQueryValueExA(hkey, "0", NULL, NULL, (LPBYTE)buffer, &bufsize) == ERROR_SUCCESS) {
            printf("    Disk 0: %s", buffer);
            
            _strupr(buffer);
            int found = 0;
            for (int i = 0; disk_strings[i] != NULL; i++) {
                if (strstr(buffer, disk_strings[i]) && strstr(buffer, "VBOX")) {
                    printf(" [VM]\n");
                    detections++;
                    found = 1;
                    break;
                }
            }
            if (strstr(buffer, "VMWARE") || strstr(buffer, "QEMU") || strstr(buffer, "VIRTUAL HD")) {
                printf(" [VM]\n");
                detections++;
            } else if (!found) {
                printf("\n");
            }
        }
        RegCloseKey(hkey);
    }
}

void check_video() {
    HKEY hkey;
    char buffer[256];
    DWORD bufsize;
    
    const char* video_strings[] = {
        "VMware", "VBox", "VirtualBox", "QEMU", "Parallels", "Hyper-V", NULL
    };
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
        0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        
        bufsize = sizeof(buffer);
        if (RegQueryValueExA(hkey, "DriverDesc", NULL, NULL, (LPBYTE)buffer, &bufsize) == ERROR_SUCCESS) {
            printf("    Video adapter: %s", buffer);
            for (int i = 0; video_strings[i] != NULL; i++) {
                if (strstr(buffer, video_strings[i])) {
                    printf(" [VM]\n");
                    detections++;
                    RegCloseKey(hkey);
                    return;
                }
            }
            printf("\n");
        }
        RegCloseKey(hkey);
    } else {
        printf("[-] Video: couldn't query\n");
    }
}

void check_smbios() {
    HKEY hkey;
    char buffer[256];
    DWORD bufsize;
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\SystemInformation", 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        
        const char* values[] = {"SystemManufacturer", "SystemProductName", NULL};
        
        for (int v = 0; values[v] != NULL; v++) {
            bufsize = sizeof(buffer);
            if (RegQueryValueExA(hkey, values[v], NULL, NULL, (LPBYTE)buffer, &bufsize) == ERROR_SUCCESS) {
                printf("    %s: %s", values[v], buffer);
                if (strstr(buffer, "VMware") || strstr(buffer, "VirtualBox") ||
                    strstr(buffer, "Virtual") || strstr(buffer, "QEMU") ||
                    strstr(buffer, "innotek") || strstr(buffer, "Xen")) {
                    printf(" [VM]\n");
                    detections++;
                } else {
                    printf("\n");
                }
            }
        }
        RegCloseKey(hkey);
    }
}

void check_wmi_strings() {
    HKEY hkey;
    char buffer[256];
    DWORD bufsize;
    
    // check computer system product via registry (alternative to WMI)
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\HardwareConfig\\Current", 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        
        bufsize = sizeof(buffer);
        if (RegQueryValueExA(hkey, "SystemFamily", NULL, NULL, (LPBYTE)buffer, &bufsize) == ERROR_SUCCESS) {
            printf("    SystemFamily: %s", buffer);
            if (strstr(buffer, "Virtual")) {
                printf(" [VM]\n");
                detections++;
            } else {
                printf("\n");
            }
        }
        RegCloseKey(hkey);
    }
}

void check_rdtsc() {
    unsigned __int64 t1, t2, t3;
    
    t1 = __rdtsc();
    t2 = __rdtsc();
    t3 = __rdtsc();
    
    unsigned __int64 delta1 = t2 - t1;
    unsigned __int64 delta2 = t3 - t2;
    
    printf("    RDTSC delta1: %llu, delta2: %llu\n", delta1, delta2);
    
    if (delta1 > 1000 || delta2 > 1000) {
        printf("[+] RDTSC: high latency detected (VM likely)\n");
        detections++;
    } else {
        printf("[-] RDTSC: timing normal\n");
    }
}

void check_env() {
    const char* vars[] = {"VIRTUAL_ENV", "VBOX_MSI_INSTALL", NULL};
    
    int found = 0;
    for (int i = 0; vars[i] != NULL; i++) {
        char* val = getenv(vars[i]);
        if (val != NULL) {
            printf("[+] Env: %s = %s\n", vars[i], val);
            detections++;
            found++;
        }
    }
    if (found == 0) printf("[-] Env: no VM environment variables\n");
}

int main() {
    printf("=====================================================\n");
    printf("           amiinavm - VM detection tool              \n");
    printf("=====================================================\n\n");
    
    printf("[*] CPUID CHECK\n");
    printf("-----------------------------------------------------\n");
    check_cpuid();
    printf("\n");
    
    printf("[*] TIMING CHECK (CPUID)\n");
    printf("-----------------------------------------------------\n");
    check_cpuid_timing();
    printf("\n");
    
    printf("[*] RDTSC CHECK\n");
    printf("-----------------------------------------------------\n");
    check_rdtsc();
    printf("\n");
    
    printf("[*] REGISTRY CHECK\n");
    printf("-----------------------------------------------------\n");
    check_registry();
    printf("\n");
    
    printf("[*] PROCESS CHECK\n");
    printf("-----------------------------------------------------\n");
    check_processes();
    printf("\n");
    
    printf("[*] MAC ADDRESS CHECK\n");
    printf("-----------------------------------------------------\n");
    check_mac();
    printf("\n");
    
    printf("[*] FILE CHECK\n");
    printf("-----------------------------------------------------\n");
    check_files();
    printf("\n");
    
    printf("[*] DEVICE CHECK\n");
    printf("-----------------------------------------------------\n");
    check_devices();
    printf("\n");
    
    printf("[*] HARDWARE/BIOS CHECK\n");
    printf("-----------------------------------------------------\n");
    check_hardware();
    printf("\n");
    
    printf("[*] DISK CHECK\n");
    printf("-----------------------------------------------------\n");
    check_disk();
    printf("\n");
    
    printf("[*] VIDEO ADAPTER CHECK\n");
    printf("-----------------------------------------------------\n");
    check_video();
    printf("\n");
    
    printf("[*] SMBIOS CHECK\n");
    printf("-----------------------------------------------------\n");
    check_smbios();
    printf("\n");
    
    printf("[*] WMI STRINGS CHECK\n");
    printf("-----------------------------------------------------\n");
    check_wmi_strings();
    printf("\n");
    
    printf("[*] ENVIRONMENT CHECK\n");
    printf("-----------------------------------------------------\n");
    check_env();
    printf("\n");
    
    printf("=====================================================\n");
    printf("  TOTAL DETECTIONS: %d\n", detections);
    printf("=====================================================\n");
    
    if (detections == 0) {
        printf("  [+] RESULT: BARE METAL\n");
        printf("      no VM indicators found\n");
    } else if (hyperv_host && detections == 1) {
        printf("  [~] RESULT: HYPER-V HOST\n");
        printf("      Hyper-V enabled but not in a VM\n");
        printf("      (WSL2/Docker/Sandbox causes this)\n");
    } else if (detections <= 2) {
        printf("  [?] RESULT: SUSPICIOUS\n");
        printf("      few indicators, could be false positive\n");
    } else if (detections <= 4) {
        printf("  [!] RESULT: PROBABLY VM\n");
        printf("      multiple indicators found\n");
    } else {
        printf("  [!!] RESULT: VM DETECTED\n");
        printf("      strong evidence of virtualization\n");
    }
    printf("=====================================================\n");
    
    printf("\npress enter to exit...");
    getchar();
    
    return detections > 0 ? 1 : 0;
}
