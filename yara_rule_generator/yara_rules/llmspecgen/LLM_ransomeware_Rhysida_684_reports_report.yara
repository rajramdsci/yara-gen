```yara
/*
YARA Rule Set - f6f74e05e24dd2e4e60e.exe
Generated from design specification: f6f74e05e24dd2e4e60e.exe_yara_design.pdf
All rules strictly adhere to YARA 3.6.0 syntax.
Rules are maximized into focused, single-indicator detections.
*/

import "pe"

/* ========================================= */
/* GROUP: USES_WINDOWS_UTILITIES - Command Execution */
/* ========================================= */

rule f6f74e05_UsesWindowsUtilities_VssadminFullCommand
{
    meta:
        filename = "f6f74e05e24dd2e4e60e.exe_yara_design.pdf"
        description = "Detects full vssadmin shadow deletion command string"
        category = "USES_WINDOWS_UTILITIES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "vssadmin.exe Delete Shadows /All /Quiet" ascii
    condition:
        uint16(0) == 0x5A4D and $s1
}

rule f6f74e05_UsesWindowsUtilities_VssadminFullCommand_Wide
{
    meta:
        filename = "f6f74e05e24dd2e4e60e.exe_yara_design.pdf"
        description = "Detects full vssadmin shadow deletion command string (wide)"
        category = "USES_WINDOWS_UTILITIES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "vssadmin.exe Delete Shadows /All /Quiet" wide
    condition:
        uint16(0) == 0x5A4D and $s1
}

rule f6f74e05_UsesWindowsUtilities_VssadminPartial
{
    meta:
        filename = "f6f74e05e24dd2e4e60e.exe_yara_design.pdf"
        description = "Detects partial vssadmin shadow deletion command"
        category = "USES_WINDOWS_UTILITIES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "vssadmin.exe Delete Shadows" ascii
    condition:
        uint16(0) == 0x5A4D and $s1
}

rule f6f74e05_UsesWindowsUtilities_WevtutilCommand
{
    meta:
        filename = "f6f74e05e24dd2e4e60e.exe_yara_design.pdf"
        description = "Detects wevtutil log clearing command string"
        category = "USES_WINDOWS_UTILITIES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "wevtutil.exe cl" ascii
    condition:
        uint16(0) == 0x5A4D and $s1
}

rule f6f74e05_UsesWindowsUtilities_WevtutilCommand_Wide
{
    meta:
        filename = "f6f74e05e24dd2e4e60e.exe_yara_design.pdf"
        description = "Detects wevtutil log clearing command string (wide)"
        category = "USES_WINDOWS_UTILITIES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "wevtutil.exe cl" wide
    condition:
        uint16(0) == 0x5A4D and $s1
}

/* ========================================= */
/* GROUP: DELETES_SHADOW_COPIES - Ransomware Behavior */
/* ========================================= */

rule f6f74e05_DeletesShadowCopies_VssadminExact
{
    meta:
        filename = "f6f74e05e24dd2e4e60e.exe_yara_design.pdf"
        description = "Detects classic ransomware shadow copy deletion via vssadmin"
        category = "DELETES_SHADOW_COPIES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "vssadmin.exe Delete Shadows" ascii
    condition:
        uint16(0) == 0x5A4D and $s1
}

rule f6f74e05_DeletesShadowCopies_VssadminFullQuiet
{
    meta:
        filename = "f6f74e05e24dd2e4e60e.exe_yara_design.pdf"
        description = "Detects full quiet vssadmin shadow deletion string"
        category = "DELETES_SHADOW_COPIES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "vssadmin.exe Delete Shadows /All /Quiet" ascii
    condition:
        uint16(0) == 0x5A4D and $s1
}

/* ========================================= */
/* GROUP: CLEARS_LOGS - Stealth */
/* ========================================= */

rule f6f74e05_ClearsLogs_Wevtutil
{
    meta:
        filename = "f6f74e05e24dd2e4e60e.exe_yara_design.pdf"
        description = "Detects log clearing via wevtutil.exe"
        category = "CLEARS_LOGS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "wevtutil.exe cl" ascii
    condition:
        uint16(0) == 0x5A4D and $s1
}

rule f6f74e05_ClearsLogs_Wevtutil_Wide
{
    meta:
        filename = "f6f74e05e24dd2e4e60e.exe_yara_design.pdf"
        description = "Detects log clearing via wevtutil.exe (wide)"
        category = "CLEARS_LOGS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "wevtutil.exe cl" wide
    condition:
        uint16(0) == 0x5A4D and $s1
}

/* ========================================= */
/* GROUP: PROCMEM_YARA - Memory Artifacts */
/* ========================================= */

rule f6f74e05_ProcMemYara_RansomwareIndicator
{
    meta:
        filename = "f6f74e05e24dd2e4e60e.exe_yara_design.pdf"
        description = "Detects ransomware indicator string from process memory"
        category = "PROCMEM_YARA"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "INDICATOR_SUSPICIOUS_GENRansomware" ascii
    condition:
        uint16(0) == 0x5A4D and $s1
}

rule f6f74e05_ProcMemYara_RansomwareIndicator_Wide
{
    meta:
        filename = "f6f74e05e24dd2e4e60e.exe_yara_design.pdf"
        description = "Detects ransomware indicator string from process memory (wide)"
        category = "PROCMEM_YARA"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "INDICATOR_SUSPICIOUS_GENRansomware" wide
    condition:
        uint16(0) == 0x5A4D and $s1
}

rule f6f74e05_ProcMemYara_ClearWinLogsIndicator
{
    meta:
        filename = "f6f74e05e24dd2e4e60e.exe_yara_design.pdf"
        description = "Detects log clearing indicator string from process memory"
        category = "PROCMEM_YARA"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "INDICATOR_SUSPICIOUS_ClearWinLogs" ascii
    condition:
        uint16(0) == 0x5A4D and $s1
}

rule f6f74e05_ProcMemYara_ClearWinLogsIndicator_Wide
{
    meta:
        filename = "f6f74e05e24dd2e4e60e.exe_yara_design.pdf"
        description = "Detects log clearing indicator string from process memory (wide)"
        category = "PROCMEM_YARA"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "INDICATOR_SUSPICIOUS_ClearWinLogs" wide
    condition:
        uint16(0) == 0x5A4D and $s1
}

/* ========================================= */
/* GROUP: COMBINED BEHAVIOR - High Confidence */
/* ========================================= */

rule f6f74e05_RansomwareBehavior_VssadminAndWevtutil
{
    meta:
        filename = "f6f74e05e24dd2e4e60e.exe_yara_design.pdf"
        description = "Detects both shadow deletion and log clearing commands"
        category = "DELETES_SHADOW_COPIES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "vssadmin.exe Delete Shadows" ascii
        $s2 = "wevtutil.exe cl" ascii
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule f6f74e05_Stealth_RansomwareIndicators
{
    meta:
        filename = "f6f74e05e24dd2e4e60e.exe_yara_design.pdf"
        description = "Detects both ransomware and log clearing memory indicators"
        category = "PROCMEM_YARA"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "INDICATOR_SUSPICIOUS_GENRansomware" ascii
        $s2 = "INDICATOR_SUSPICIOUS_ClearWinLogs" ascii
    condition:
        uint16(0) == 0x5A4D and all of them
}
```