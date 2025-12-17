@echo off
cl /nologo /O2 amiinavm.c /Fe:amiinavm.exe /link /subsystem:console iphlpapi.lib advapi32.lib

