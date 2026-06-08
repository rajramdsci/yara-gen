```yara
/*
YARA Rule Set for wipers_Breakwin_1271
Generated strictly for YARA 3.6.0
Source: wipers_Breakwin_1271_reports_report_yara_design.pdf
All rules use only YARA 3.6.0 compatible syntax.
*/

import "pe"
import "math"

// ============================================
// CAPE - Payloads Category Rules
// ============================================

rule Breakwin_CAPE_Payloads_Config_1
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects CAPE payloads activity"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "payload" ascii wide
        $s2 = "config" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_CAPE_Payloads_Config_2
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects CAPE payloads activity"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "unpacked" ascii wide
        $s2 = "stage2" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_CAPE_Payloads_Config_3
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects CAPE payloads activity"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "inject" ascii wide
        $s2 = "reflective" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

// ============================================
// SIGNATURES Category Rules
// ============================================

rule Breakwin_Signatures_Behavioral_1
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects behavioral signatures from report"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "wiper" ascii wide
        $s2 = "destroy" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Signatures_Behavioral_2
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects behavioral signatures from report"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "overwrite" ascii wide
        $s2 = "sectors" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Signatures_Behavioral_3
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects behavioral signatures from report"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "MBR" ascii wide
        $s2 = "boot" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Signatures_Behavioral_4
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects behavioral signatures from report"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "Breakwin" ascii wide
        $s2 = "1271" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

// ============================================
// DEBUG - Log Category Rules
// ============================================

rule Breakwin_Debug_Log_Errors_1
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects debug and error log activity"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "debug" ascii wide
        $s2 = "error" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Debug_Log_Errors_2
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects debug and error log activity"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "crash" ascii wide
        $s2 = "exception" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Debug_Log_Errors_3
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects debug and error log activity"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "anti-analysis" ascii wide
        $s2 = "sandbox" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

// ============================================
// URL_ANALYSIS Category Rules
// ============================================

rule Breakwin_URL_Analysis_C2_1
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects URL analysis and C2 indicators"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "http://" ascii wide
        $s2 = "https://" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_URL_Analysis_C2_2
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects URL analysis and C2 indicators"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = ".onion" ascii wide
        $s2 = "tor" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_URL_Analysis_C2_3
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects URL analysis and C2 indicators"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "exfil" ascii wide
        $s2 = "upload" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_URL_Analysis_C2_4
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects URL analysis and C2 indicators"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "command" ascii wide
        $s2 = "control" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}
```