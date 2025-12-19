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
#pragma comment(lib, "advapi32.lib")

#define COLOR_DEFAULT 7
#define COLOR_TITLE 11
#define COLOR_SUCCESS 10
#define COLOR_INFO 14
#define COLOR_ERROR 12
#define COLOR_ACCENT 12
#define COLOR_DIM 8

HANDLE hConsole;

void set_color(int color) {
    SetConsoleTextAttribute(hConsole, color);
}

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

static int delete_registry_key_recursive(HKEY hkey_parent, const char* subkey) {
    HKEY hkey;
    LONG result = RegOpenKeyExA(hkey_parent, subkey, 0, KEY_READ | KEY_WRITE, &hkey);
    if (result != ERROR_SUCCESS) {
        return result;
    }
    
    char name[256];
    DWORD name_size;
    FILETIME ft;
    
    while (1) {
        name_size = sizeof(name);
        result = RegEnumKeyExA(hkey, 0, name, &name_size, NULL, NULL, NULL, &ft);
        if (result == ERROR_NO_MORE_ITEMS) break;
        if (result != ERROR_SUCCESS) {
            RegCloseKey(hkey);
            return result;
        }
        delete_registry_key_recursive(hkey, name);
    }
    
    RegCloseKey(hkey);
    return RegDeleteKeyExA(hkey_parent, subkey, KEY_WOW64_64KEY, 0);
}

static int hide_registry_keys(void) {
    struct { const char* key; const char* desc; } keys[] = {
        {"SOFTWARE\\VMware, Inc.\\VMware Tools", "VMware Tools"},
        {"SOFTWARE\\Oracle\\VirtualBox Guest Additions", "VirtualBox GA"},
        {"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters", "Hyper-V Guest"},
        {"HARDWARE\\ACPI\\DSDT\\VBOX__", "VBox ACPI DSDT"},
        {"HARDWARE\\ACPI\\FADT\\VBOX__", "VBox ACPI FADT"},
        {"HARDWARE\\ACPI\\RSDT\\VBOX__", "VBox ACPI RSDT"},
        {"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", "VBoxGuest Service"},
        {"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse", "VBoxMouse Service"},
        {"SYSTEM\\CurrentControlSet\\Services\\VBoxService", "VBoxService Service"},
        {"SYSTEM\\CurrentControlSet\\Services\\VBoxSF", "VBoxSF Service"},
        {"SYSTEM\\CurrentControlSet\\Services\\VBoxVideo", "VBoxVideo Service"},
        {"SYSTEM\\CurrentControlSet\\Services\\vmci", "VMware vmci Service"},
        {"SYSTEM\\CurrentControlSet\\Services\\vmhgfs", "VMware vmhgfs Service"},
        {"SYSTEM\\CurrentControlSet\\Services\\vmmouse", "VMware vmmouse Service"},
        {"SYSTEM\\CurrentControlSet\\Services\\vmrawdsk", "VMware vmrawdsk Service"},
        {"SYSTEM\\CurrentControlSet\\Services\\vmusbmouse", "VMware vmusbmouse Service"},
        {"SOFTWARE\\Wine", "Wine"},
        {"SYSTEM\\CurrentControlSet\\Services\\vioscsi", "VirtIO SCSI Service"},
        {"SYSTEM\\CurrentControlSet\\Services\\viostor", "VirtIO Storage Service"},
        {"SYSTEM\\CurrentControlSet\\Services\\balloon", "QEMU Balloon Service"},
        {"SYSTEM\\CurrentControlSet\\Services\\VBoxUSBMon", "VBoxUSBMon Service"},
        {"SYSTEM\\CurrentControlSet\\Services\\VBoxUSB", "VBoxUSB Service"},
        {"SYSTEM\\CurrentControlSet\\Services\\prl_eth", "Parallels Ethernet Service"},
        {"SYSTEM\\CurrentControlSet\\Services\\prl_fs", "Parallels Filesystem Service"},
        {"SYSTEM\\CurrentControlSet\\Services\\prl_mouf", "Parallels Mouse Service"},
        {"SYSTEM\\CurrentControlSet\\Services\\prl_pv", "Parallels Paravirtual Service"},
        {"SYSTEM\\CurrentControlSet\\Services\\prl_time", "Parallels Time Service"},
        {"SYSTEM\\CurrentControlSet\\Services\\prl_vid", "Parallels Video Service"},
        {NULL, NULL}
    };
    
    HKEY hkey;
    LONG result;
    int hidden = 0;
    
    for (int i = 0; keys[i].key != NULL; i++) {
        result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keys[i].key, 0, KEY_READ, &hkey);
        if (result == ERROR_SUCCESS) {
            RegCloseKey(hkey);
            
            char* parent_key = _strdup(keys[i].key);
            char* last_backslash = strrchr(parent_key, '\\');
            if (last_backslash) {
                *last_backslash = '\0';
                const char* subkey = last_backslash + 1;
                
                result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, parent_key, 0, KEY_WRITE, &hkey);
                if (result == ERROR_SUCCESS) {
                    result = delete_registry_key_recursive(hkey, subkey);
                    if (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND) {
                        set_color(COLOR_SUCCESS);
                        printf("  [+] Hidden: ");
                        set_color(COLOR_DEFAULT);
                        printf("%s\n", keys[i].desc);
                        hidden++;
                    }
                    RegCloseKey(hkey);
                }
            }
            free(parent_key);
        }
    }
    
    return hidden;
}

static int hide_hardware_strings(void) {
    struct { const char* key; const char* value; const char* fake_value; } strings[] = {
        {"HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemManufacturer", "System manufacturer"},
        {"HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemProductName", "System Product Name"},
        {"HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVendor", "American Megatrends Inc."},
        {"HARDWARE\\DESCRIPTION\\System\\BIOS", "BaseBoardManufacturer", "ASUSTeK COMPUTER INC."},
        {"HARDWARE\\DESCRIPTION\\System\\BIOS", "BaseBoardProduct", "PRIME B450M-A"},
        {"SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemManufacturer", "System manufacturer"},
        {"SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemProductName", "System Product Name"},
        {"SYSTEM\\HardwareConfig\\Current", "SystemFamily", "Desktop"},
        {NULL, NULL, NULL}
    };
    
    HKEY hkey;
    LONG result;
    int modified = 0;
    
    for (int i = 0; strings[i].key != NULL; i++) {
        result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, strings[i].key, 0, KEY_READ | KEY_WRITE, &hkey);
        if (result == ERROR_SUCCESS) {
            char buffer[256];
            DWORD bufsize = sizeof(buffer);
            
            if (RegQueryValueExA(hkey, strings[i].value, NULL, NULL, (LPBYTE)buffer, &bufsize) == ERROR_SUCCESS) {
                if (strstr(buffer, "VMware") || strstr(buffer, "VirtualBox") || 
                    strstr(buffer, "VBOX") || strstr(buffer, "Virtual") || 
                    strstr(buffer, "QEMU") || strstr(buffer, "innotek") || 
                    strstr(buffer, "Xen") || strstr(buffer, "Parallels") ||
                    strstr(buffer, "KVM") || strstr(buffer, "Bochs")) {
                    
                    result = RegSetValueExA(hkey, strings[i].value, 0, REG_SZ, 
                        (BYTE*)strings[i].fake_value, strlen(strings[i].fake_value) + 1);
                    
                    if (result == ERROR_SUCCESS) {
                        set_color(COLOR_SUCCESS);
                        printf("  [+] Modified: ");
                        set_color(COLOR_DEFAULT);
                        printf("%s\\%s -> ", strings[i].key, strings[i].value);
                        set_color(COLOR_INFO);
                        printf("%s\n", strings[i].fake_value);
                        set_color(COLOR_DEFAULT);
                        modified++;
                    }
                }
            }
            RegCloseKey(hkey);
        }
    }
    
    return modified;
}

static int hide_disk_video_strings(void) {
    HKEY hkey;
    char buffer[512];
    DWORD bufsize;
    LONG result;
    int modified = 0;
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", 0, KEY_READ | KEY_WRITE, &hkey) == ERROR_SUCCESS) {
        
        bufsize = sizeof(buffer);
        if (RegQueryValueExA(hkey, "0", NULL, NULL, (LPBYTE)buffer, &bufsize) == ERROR_SUCCESS) {
            _strupr(buffer);
            if (strstr(buffer, "VBOX") || strstr(buffer, "VMWARE") || 
                strstr(buffer, "QEMU") || strstr(buffer, "VIRTUAL HD")) {
                
                const char* fake = "IDE\\DiskGeneric";
                result = RegSetValueExA(hkey, "0", 0, REG_SZ, (BYTE*)fake, strlen(fake) + 1);
                if (result == ERROR_SUCCESS) {
                    set_color(COLOR_SUCCESS);
                    printf("  [+] Modified: Disk 0 -> ");
                    set_color(COLOR_INFO);
                    printf("%s\n", fake);
                    set_color(COLOR_DEFAULT);
                    modified++;
                }
            }
        }
        RegCloseKey(hkey);
    }
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
        0, KEY_READ | KEY_WRITE, &hkey) == ERROR_SUCCESS) {
        
        bufsize = sizeof(buffer);
        if (RegQueryValueExA(hkey, "DriverDesc", NULL, NULL, (LPBYTE)buffer, &bufsize) == ERROR_SUCCESS) {
            if (strstr(buffer, "VMware") || strstr(buffer, "VBox") || 
                strstr(buffer, "VirtualBox") || strstr(buffer, "QEMU") ||
                strstr(buffer, "Parallels") || strstr(buffer, "Hyper-V")) {
                
                const char* fake = "NVIDIA GeForce GTX 1060";
                result = RegSetValueExA(hkey, "DriverDesc", 0, REG_SZ, (BYTE*)fake, strlen(fake) + 1);
                if (result == ERROR_SUCCESS) {
                    set_color(COLOR_SUCCESS);
                    printf("  [+] Modified: Video adapter -> ");
                    set_color(COLOR_INFO);
                    printf("%s\n", fake);
                    set_color(COLOR_DEFAULT);
                    modified++;
                }
            }
        }
        RegCloseKey(hkey);
    }
    
    return modified;
}

static int hide_env_vars(void) {
    const char* vars[] = {"VIRTUAL_ENV", "VBOX_MSI_INSTALL", NULL};
    int hidden = 0;
    
    for (int i = 0; vars[i] != NULL; i++) {
        if (getenv(vars[i]) != NULL) {
            if (SetEnvironmentVariableA(vars[i], NULL)) {
                set_color(COLOR_SUCCESS);
                printf("  [+] Removed env var: ");
                set_color(COLOR_DEFAULT);
                printf("%s\n", vars[i]);
                hidden++;
            }
        }
    }
    
    return hidden;
}

static void hide_indicators(void) {
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    
    BOOL is_admin = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            is_admin = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }
    
    if (!is_admin) {
        set_color(COLOR_ERROR);
        printf("  [!] ERROR: Not running as administrator!\n");
        set_color(COLOR_DEFAULT);
        printf("  [!] This tool requires admin privileges to modify registry.\n");
        return;
    }
    
    set_color(COLOR_INFO);
    printf("\n  [*] Starting VM indicator hiding...\n\n");
    set_color(COLOR_DEFAULT);
    
    int total_hidden = 0;
    
    set_color(COLOR_INFO);
    printf("  [*] Hiding registry keys...\n");
    set_color(COLOR_DEFAULT);
    total_hidden += hide_registry_keys();
    printf("\n");
    
    set_color(COLOR_INFO);
    printf("  [*] Modifying hardware strings...\n");
    set_color(COLOR_DEFAULT);
    total_hidden += hide_hardware_strings();
    printf("\n");
    
    set_color(COLOR_INFO);
    printf("  [*] Modifying disk/video strings...\n");
    set_color(COLOR_DEFAULT);
    total_hidden += hide_disk_video_strings();
    printf("\n");
    
    set_color(COLOR_INFO);
    printf("  [*] Removing environment variables...\n");
    set_color(COLOR_DEFAULT);
    total_hidden += hide_env_vars();
    printf("\n");
    
    set_color(COLOR_DIM);
    printf("  +-----------------------------------------------+\n");
    set_color(COLOR_DEFAULT);
    printf("  |  ");
    set_color(COLOR_SUCCESS);
    printf("TOTAL HIDDEN:");
    set_color(COLOR_ACCENT);
    printf(" %-3d", total_hidden);
    set_color(COLOR_DEFAULT);
    printf(" indicators                    |\n");
    set_color(COLOR_DIM);
    printf("  +-----------------------------------------------+\n");
    set_color(COLOR_DEFAULT);
    
    printf("\n  [*] Note: Some changes require reboot to take effect.\n");
}

static void print_banner(void) {
    set_color(COLOR_DIM);
    printf("\n  +===================================================+\n");
    set_color(COLOR_TITLE);
    printf("  |");
    set_color(COLOR_ACCENT);
    printf("       amiinavm ");
    set_color(COLOR_DEFAULT);
    printf("- VM detection tool            ");
    set_color(COLOR_TITLE);
    printf("|\n");
    set_color(COLOR_TITLE);
    printf("  |           made by ");
    set_color(COLOR_ACCENT);
    printf("Tymbark7372");
    set_color(COLOR_TITLE);
    printf("            |\n");
    set_color(COLOR_DIM);
    printf("  +===================================================+\n");
    set_color(COLOR_DEFAULT);
    printf("\n");
}

static void run_detection(void) {
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
}

static void interactive_menu(void) {
    char input[32];
    
    print_banner();
    
    set_color(COLOR_DEFAULT);
    printf("  what do you want to do?\n\n");
    set_color(COLOR_INFO);
    printf("  [1] ");
    set_color(COLOR_DEFAULT);
    printf("detect VM indicators\n");
    set_color(COLOR_INFO);
    printf("  [2] ");
    set_color(COLOR_DEFAULT);
    printf("hide VM indicators (requires admin)\n");
    set_color(COLOR_INFO);
    printf("  [3] ");
    set_color(COLOR_DEFAULT);
    printf("exit\n\n");
    set_color(COLOR_DEFAULT);
    printf("  choice ");
    set_color(COLOR_DIM);
    printf("(1-3)");
    set_color(COLOR_DEFAULT);
    printf(": ");
    set_color(COLOR_ACCENT);
    fgets(input, sizeof(input), stdin);
    set_color(COLOR_DEFAULT);
    
    int choice = atoi(input);
    
    if (choice == 1) {
        run_detection();
        printf("\npress enter to exit...");
        getchar();
    } else if (choice == 2) {
        set_color(COLOR_ERROR);
        printf("\n  [!] WARNING: This tool modifies system registry!\n");
        set_color(COLOR_DEFAULT);
        printf("  [!] Run as administrator. Some changes may break\n");
        printf("      VM guest tools functionality.\n");
        printf("\n");
        hide_indicators();
        printf("\n  Press enter to exit...");
        getchar();
    }
}

int main(int argc, char* argv[]) {
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    
    int hide_mode = 0;
    int detect_mode = 0;
    
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--hide") == 0) {
                hide_mode = 1;
                break;
            } else if (strcmp(argv[i], "--detect") == 0) {
                detect_mode = 1;
                break;
            } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
                printf("amiinavm - VM detection tool\n");
                printf("usage: amiinavm.exe [option]\n");
                printf("  --detect  detect VM indicators (default)\n");
                printf("  --hide    hide VM indicators (requires admin)\n");
                printf("  --help    show this help\n");
                printf("\n");
                printf("  if no option is provided, interactive menu will appear\n");
                return 0;
            }
        }
    }
    
    if (hide_mode) {
        set_color(COLOR_DIM);
        printf("\n  +===================================================+\n");
        set_color(COLOR_TITLE);
        printf("  |");
        set_color(COLOR_ACCENT);
        printf("       amiinavm ");
        set_color(COLOR_DEFAULT);
        printf("- hide VM indicators        ");
        set_color(COLOR_TITLE);
        printf("|\n");
        set_color(COLOR_TITLE);
        printf("  |           made by ");
        set_color(COLOR_ACCENT);
        printf("Tymbark7372");
        set_color(COLOR_TITLE);
        printf("            |\n");
        set_color(COLOR_DIM);
        printf("  +===================================================+\n");
        set_color(COLOR_DEFAULT);
        printf("\n");
        set_color(COLOR_ERROR);
        printf("  [!] WARNING: This tool modifies system registry!\n");
        set_color(COLOR_DEFAULT);
        printf("  [!] Run as administrator. Some changes may break\n");
        printf("      VM guest tools functionality.\n");
        printf("\n");
        
        hide_indicators();
        printf("\n  Press enter to exit...");
        getchar();
        return 0;
    }
    
    if (detect_mode) {
        run_detection();
        return detections > 0 ? 1 : 0;
    }
    
    interactive_menu();
    return 0;
}
