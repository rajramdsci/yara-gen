```yara
/*
YARA Rule Set for wipers_Breakwin_1270
Generated for: wipers_Breakwin_1270_reports_report_yara_design.pdf
Strictly YARA 3.6.0 compatible
Focus: Wiper malware Breakwin behavioral, payload, and configuration indicators
*/

import "pe"
import "math"

/* ==================== CAPE Payloads ==================== */

rule Breakwin_CAPE_Payload_Generic
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects generic CAPE payload activity"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "Breakwin" ascii wide
        $s2 = "wiper_payload" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_CAPE_Payload_Config
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects CAPE payload configuration strings"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "config.json" ascii wide
        $s2 = "payload_id" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_CAPE_Payload_Unpacked
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects unpacked payload indicators from CAPE"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "unpacked_stage" ascii wide
        $s2 = "main_wiper" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ==================== Signatures ==================== */

rule Breakwin_Signatures_Behavioral_0
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects signature category 0 behavioral triggers"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "sig_trigger_0" ascii wide
        $s2 = "behavior_match" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Signatures_Destructive
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects destructive operation signatures"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "format_volume" ascii wide
        $s2 = "overwrite_mbr" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ==================== Debug Logs ==================== */

rule Breakwin_Debug_Log_Errors
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects debug log error strings"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "debug_log" ascii wide
        $s2 = "error_code" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Debug_Log_AntiAnalysis
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects anti-analysis debug messages"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "sandbox_detected" ascii wide
        $s2 = "vm_check" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ==================== URL Analysis ==================== */

rule Breakwin_URL_C2_Communication
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects C2 URLs from URL analysis"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "http://breakwin" ascii wide
        $s2 = "/command" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_URL_Exfiltration
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects exfiltration URLs"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "exfil.breakwin" ascii wide
        $s2 = "/upload" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ==================== Additional Focused Rules ==================== */

rule Breakwin_Wiper_Drive_Overwrite
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects drive overwrite patterns"
        category = "WIPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "\\\\.\\PhysicalDrive" ascii wide
        $s2 = "CreateFileA" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and all of them
}

rule Breakwin_Wiper_File_Destruction
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects file destruction routines"
        category = "WIPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "DeleteFileW" ascii
        $s2 = "SetFilePointer" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Wiper_RansomNote
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects ransom note strings"
        category = "WIPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "Your files have been destroyed" ascii wide
        $s2 = "Breakwin" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Packer_HighEntropy
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects high entropy sections typical of packers"
        category = "PACKER"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and
        math.entropy(0, filesize) > 7.0
}

rule Breakwin_Registry_Persistence
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects registry persistence strings"
        category = "PERSISTENCE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "CurrentVersion\\Run" ascii wide
        $s2 = "Breakwin" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Service_Installation
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects service creation indicators"
        category = "PERSISTENCE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "CreateServiceA" ascii
        $s2 = "BreakwinSvc" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Process_Injection
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects process injection strings"
        category = "INJECTION"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "VirtualAllocEx" ascii
        $s2 = "WriteProcessMemory" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and all of them
}

rule Breakwin_AntiVM_Strings
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects common anti-VM strings"
        category = "ANTI_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "VMware" ascii wide
        $s2 = "VBox" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_CommandLine_Arguments
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects command line argument handling"
        category = "EXECUTION"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "/wipe" ascii wide
        $s2 = "-destroy" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}
```