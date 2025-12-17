# amiinavm

detect if you're running inside a virtual machine

## what it detects

- VMware
- VirtualBox
- Hyper-V
- KVM/QEMU
- Xen
- Parallels
- Wine
- Various sandboxes

## detection methods

| method | what it checks |
|--------|---------------|
| CPUID | hypervisor bit + vendor string |
| CPUID Timing | measures cycles for CPUID execution |
| RDTSC | timestamp counter timing anomalies |
| Registry | VM guest tools, services, ACPI tables |
| Processes | vmtoolsd, VBoxTray, qemu-ga, etc |
| MAC Address | known VM vendor prefixes |
| Files | VM drivers and install paths |
| Devices | VM-specific device handles |
| Hardware/BIOS | manufacturer and product strings |
| Disk | virtual disk model names |
| Video | VM graphics adapter names |
| SMBIOS | firmware strings |
| WMI Strings | system family and product info |
| Environment | VM-related environment variables |

## result levels

| detections | result |
|------------|--------|
| 0 | **BARE METAL** - no VM indicators |
| 1 (only Hyper-V CPUID) | **HYPER-V HOST** - Hyper-V enabled but not in VM |
| 1-2 | **SUSPICIOUS** - few indicators, could be false positive |
| 3-4 | **PROBABLY VM** - multiple indicators found |
| 5+ | **VM DETECTED** - strong evidence of virtualization |

## building

requires visual studio / msvc

```batch
build.bat
```

or manually:
```batch
cl /O2 amiinavm.c /Fe:amiinavm.exe /link iphlpapi.lib advapi32.lib
```

## running

```batch
amiinavm.exe
```

exit code is 1 if VM detected, 0 if bare metal

## example output

**on bare metal with Hyper-V enabled (WSL2/Docker):**
```
TOTAL DETECTIONS: 1
[~] RESULT: HYPER-V HOST
    Hyper-V enabled but not in a VM
    (WSL2/Docker/Sandbox causes this)
```

**in a VMware VM:**
```
TOTAL DETECTIONS: 12
[!!] RESULT: VM DETECTED
     strong evidence of virtualization
```

**on clean bare metal:**
```
TOTAL DETECTIONS: 0
[+] RESULT: BARE METAL
    no VM indicators found
```

## notes

- some checks may have false positives (timing can vary)
- hyper-v being enabled on windows makes CPUID report a hypervisor even on bare metal
- sandbox environments (Windows Sandbox, etc) will be detected as VMs
- **having VM software installed** (VMware Workstation, VirtualBox, etc.) on your host machine will trigger detections due to virtual network adapters, drivers, and services - this doesn't mean you're in a VM, just that you have VM software installed

## license

MIT License - see LICENSE file.

made by [Tymbark7372](https://github.com/Tymbark7372)
